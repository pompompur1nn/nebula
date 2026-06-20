use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> =
    std::result::Result<T, PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError>;
pub type PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_ASSET_FEE_CREDIT_ROUTER_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-low-fee-pq-confidential-multi-asset-fee-credit-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_ASSET_FEE_CREDIT_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-fee-credit-route-attestation-v1";
pub const CONFIDENTIAL_COMMITMENT_SUITE: &str = "ringct-style-multi-asset-fee-credit-commitment-v1";
pub const SPONSOR_COMMITMENT_SUITE: &str = "pq-sponsor-credit-commitment-root-v1";
pub const SETTLEMENT_VOUCHER_SUITE: &str = "low-fee-confidential-settlement-voucher-root-v1";
pub const REBATE_DISTRIBUTION_SUITE: &str = "multi-asset-fee-credit-rebate-distribution-root-v1";
pub const REDACTION_BUDGET_SUITE: &str = "confidential-router-redaction-budget-root-v1";
pub const THROTTLE_SUITE: &str = "fee-credit-router-anti-abuse-throttle-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-low-fee-pq-fee-credit-router-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_946_240;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_720_480;
pub const DEVNET_EPOCH: u64 = 3_108;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 8_192;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_POOL_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_THROTTLE_WINDOW_BLOCKS: u64 = 64;
pub const DEFAULT_REDACTION_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_ROUTER_MARGIN_BPS: u64 = 2;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_REBATE_TARGET_BPS: u64 = 5;
pub const DEFAULT_ABUSE_ESCROW_MICRO_UNITS: u64 = 500_000_000;
pub const DEFAULT_MIN_POOL_LIQUIDITY_MICRO_UNITS: u64 = 10_000_000_000;
pub const DEFAULT_ROUTE_MAX_HOPS: usize = 6;
pub const DEFAULT_BATCH_MAX_ROUTES: usize = 4_096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError {
    pub code: String,
    pub message: String,
}

impl PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError {}

fn err(
    code: impl Into<String>,
    message: impl Into<String>,
) -> PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError {
    PrivateL2LowFeePqConfidentialMultiAssetFeeCreditRouterRuntimeError::new(code, message)
}

fn require(condition: bool, code: &str, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(err(code, message))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeAssetKind {
    WrappedMonero,
    ConfidentialToken,
    StablePrivateToken,
    AppFeeCredit,
    RebateCoupon,
    SponsorCredit,
    SettlementVoucher,
    VaultShare,
}

impl FeeAssetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WrappedMonero => "wrapped_monero",
            Self::ConfidentialToken => "confidential_token",
            Self::StablePrivateToken => "stable_private_token",
            Self::AppFeeCredit => "app_fee_credit",
            Self::RebateCoupon => "rebate_coupon",
            Self::SponsorCredit => "sponsor_credit",
            Self::SettlementVoucher => "settlement_voucher",
            Self::VaultShare => "vault_share",
        }
    }

    pub fn can_settle_fees(self) -> bool {
        matches!(
            self,
            Self::WrappedMonero
                | Self::ConfidentialToken
                | Self::StablePrivateToken
                | Self::AppFeeCredit
                | Self::SponsorCredit
                | Self::SettlementVoucher
        )
    }

    pub fn is_credit_like(self) -> bool {
        matches!(
            self,
            Self::AppFeeCredit | Self::RebateCoupon | Self::SponsorCredit | Self::SettlementVoucher
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Proposed,
    Open,
    Rebalancing,
    Throttled,
    Settling,
    Settled,
    Paused,
    Slashed,
    Retired,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Rebalancing => "rebalancing",
            Self::Throttled => "throttled",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_routes(self) -> bool {
        matches!(self, Self::Proposed | Self::Open | Self::Rebalancing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Quoted,
    Attested,
    Sponsored,
    Reserved,
    Settling,
    Settled,
    Rebated,
    Redacted,
    Rejected,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Attested => "attested",
            Self::Sponsored => "sponsored",
            Self::Reserved => "reserved",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Redacted => "redacted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Quoted | Self::Attested | Self::Sponsored)
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rebated | Self::Redacted | Self::Rejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Offered,
    Bonded,
    Matched,
    Exhausted,
    Settling,
    Settled,
    Slashed,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Bonded => "bonded",
            Self::Matched => "matched",
            Self::Exhausted => "exhausted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn matchable(self) -> bool {
        matches!(self, Self::Offered | Self::Bonded | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Draft,
    Issued,
    Anchored,
    Redeemed,
    Rebated,
    Challenged,
    Revoked,
    Expired,
}

impl VoucherStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Issued => "issued",
            Self::Anchored => "anchored",
            Self::Redeemed => "redeemed",
            Self::Rebated => "rebated",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn redeemable(self) -> bool {
        matches!(self, Self::Issued | Self::Anchored)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleStatus {
    Observing,
    Armed,
    CoolingDown,
    Quarantined,
    Released,
    Escalated,
}

impl ThrottleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observing => "observing",
            Self::Armed => "armed",
            Self::CoolingDown => "cooling_down",
            Self::Quarantined => "quarantined",
            Self::Released => "released",
            Self::Escalated => "escalated",
        }
    }

    pub fn blocks_new_routes(self) -> bool {
        matches!(self, Self::Quarantined | Self::Escalated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    RouteHints,
    SponsorGraph,
    LiquidityAmounts,
    AccountCohorts,
    VoucherMetadata,
    OperatorTelemetry,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouteHints => "route_hints",
            Self::SponsorGraph => "sponsor_graph",
            Self::LiquidityAmounts => "liquidity_amounts",
            Self::AccountCohorts => "account_cohorts",
            Self::VoucherMetadata => "voucher_metadata",
            Self::OperatorTelemetry => "operator_telemetry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorHealth {
    Nominal,
    Degraded,
    Throttled,
    Quarantined,
    SlashingReview,
}

impl OperatorHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Degraded => "degraded",
            Self::Throttled => "throttled",
            Self::Quarantined => "quarantined",
            Self::SlashingReview => "slashing_review",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub route_ttl_blocks: u64,
    pub pool_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub throttle_window_blocks: u64,
    pub redaction_epoch_blocks: u64,
    pub max_user_fee_bps: u64,
    pub router_margin_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub rebate_target_bps: u64,
    pub abuse_escrow_micro_units: u64,
    pub min_pool_liquidity_micro_units: u64,
    pub route_max_hops: usize,
    pub batch_max_routes: usize,
    pub accepted_assets: BTreeSet<String>,
    pub operator_committee_root: String,
    pub sponsor_allowlist_root: String,
    pub emergency_pause_root: String,
}

impl Config {
    pub fn devnet() -> Self {
        let mut accepted_assets = BTreeSet::new();
        accepted_assets.insert("wxmr-devnet".to_string());
        accepted_assets.insert("pdusd-devnet".to_string());
        accepted_assets.insert("fee-credit-devnet".to_string());
        accepted_assets.insert("sponsor-credit-devnet".to_string());
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_height: DEVNET_L2_HEIGHT,
            monero_height: DEVNET_MONERO_HEIGHT,
            epoch: DEVNET_EPOCH,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            pool_ttl_blocks: DEFAULT_POOL_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            throttle_window_blocks: DEFAULT_THROTTLE_WINDOW_BLOCKS,
            redaction_epoch_blocks: DEFAULT_REDACTION_EPOCH_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            router_margin_bps: DEFAULT_ROUTER_MARGIN_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            rebate_target_bps: DEFAULT_REBATE_TARGET_BPS,
            abuse_escrow_micro_units: DEFAULT_ABUSE_ESCROW_MICRO_UNITS,
            min_pool_liquidity_micro_units: DEFAULT_MIN_POOL_LIQUIDITY_MICRO_UNITS,
            route_max_hops: DEFAULT_ROUTE_MAX_HOPS,
            batch_max_routes: DEFAULT_BATCH_MAX_ROUTES,
            accepted_assets,
            operator_committee_root: root_from_values("devnet-operator-committee", &[]),
            sponsor_allowlist_root: root_from_values("devnet-sponsor-allowlist", &[]),
            emergency_pause_root: root_from_values("devnet-emergency-pauses", &[]),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require(
            self.chain_id == CHAIN_ID,
            "config.chain",
            "config chain id does not match crate chain id",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "config.pq_security",
            "pq security below policy",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "config.privacy",
            "minimum privacy set must be nonzero",
        )?;
        require(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "config.privacy_target",
            "target privacy set below minimum privacy set",
        )?;
        require(
            self.max_user_fee_bps <= MAX_BPS,
            "config.max_fee",
            "max user fee bps outside range",
        )?;
        require(
            self.router_margin_bps <= self.max_user_fee_bps,
            "config.margin",
            "router margin above max user fee",
        )?;
        require(
            self.rebate_target_bps <= self.max_user_fee_bps,
            "config.rebate",
            "rebate target above max user fee",
        )?;
        require(
            self.sponsor_reserve_bps <= MAX_BPS,
            "config.sponsor_reserve",
            "sponsor reserve bps outside range",
        )?;
        require(
            self.route_max_hops > 0,
            "config.route_hops",
            "route max hops must be nonzero",
        )?;
        require(
            self.batch_max_routes > 0,
            "config.batch",
            "batch max routes must be nonzero",
        )?;
        require(
            !self.accepted_assets.is_empty(),
            "config.assets",
            "accepted asset set cannot be empty",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub fee_credit_pools: u64,
    pub multi_asset_routes: u64,
    pub route_hops: u64,
    pub sponsor_commitments: u64,
    pub pq_routing_attestations: u64,
    pub settlement_vouchers: u64,
    pub anti_abuse_throttles: u64,
    pub rebate_distributions: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub settled_routes: u64,
    pub redacted_routes: u64,
    pub slashed_sponsors: u64,
    pub total_user_fee_micro_units: u64,
    pub total_sponsor_credit_micro_units: u64,
    pub total_rebate_micro_units: u64,
    pub total_voucher_micro_units: u64,
}

impl Counters {
    pub fn absorb_pool(&mut self, pool: &FeeCreditPool) {
        self.fee_credit_pools += 1;
        self.total_sponsor_credit_micro_units = self
            .total_sponsor_credit_micro_units
            .saturating_add(pool.available_credit_micro_units);
    }

    pub fn absorb_route(&mut self, route: &MultiAssetRoute) {
        self.multi_asset_routes += 1;
        self.route_hops = self.route_hops.saturating_add(route.hops.len() as u64);
        self.total_user_fee_micro_units = self
            .total_user_fee_micro_units
            .saturating_add(route.max_user_fee_micro_units);
        if route.status == RouteStatus::Settled || route.status == RouteStatus::Rebated {
            self.settled_routes += 1;
        }
        if route.status == RouteStatus::Redacted {
            self.redacted_routes += 1;
        }
    }

    pub fn absorb_sponsor(&mut self, sponsor: &SponsorCommitment) {
        self.sponsor_commitments += 1;
        self.total_sponsor_credit_micro_units = self
            .total_sponsor_credit_micro_units
            .saturating_add(sponsor.committed_credit_micro_units);
        if sponsor.status == SponsorStatus::Slashed {
            self.slashed_sponsors += 1;
        }
    }

    pub fn absorb_voucher(&mut self, voucher: &SettlementVoucher) {
        self.settlement_vouchers += 1;
        self.total_voucher_micro_units = self
            .total_voucher_micro_units
            .saturating_add(voucher.settlement_amount_micro_units);
    }

    pub fn absorb_rebate(&mut self, rebate: &RebateDistribution) {
        self.rebate_distributions += 1;
        self.total_rebate_micro_units = self
            .total_rebate_micro_units
            .saturating_add(rebate.total_rebate_micro_units);
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub fee_credit_pools_root: String,
    pub multi_asset_routes_root: String,
    pub route_hops_root: String,
    pub sponsor_commitments_root: String,
    pub pq_routing_attestations_root: String,
    pub settlement_vouchers_root: String,
    pub anti_abuse_throttles_root: String,
    pub rebate_distributions_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = root_from_values("empty", &[]);
        Self {
            fee_credit_pools_root: empty.clone(),
            multi_asset_routes_root: empty.clone(),
            route_hops_root: empty.clone(),
            sponsor_commitments_root: empty.clone(),
            pq_routing_attestations_root: empty.clone(),
            settlement_vouchers_root: empty.clone(),
            anti_abuse_throttles_root: empty.clone(),
            rebate_distributions_root: empty.clone(),
            redaction_budgets_root: empty.clone(),
            operator_summaries_root: empty.clone(),
            public_record_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeCreditPool {
    pub pool_id: String,
    pub asset_id: String,
    pub asset_kind: FeeAssetKind,
    pub status: PoolStatus,
    pub pool_commitment: String,
    pub liquidity_root: String,
    pub route_policy_root: String,
    pub sponsor_set_root: String,
    pub available_credit_micro_units: u64,
    pub reserved_credit_micro_units: u64,
    pub min_route_credit_micro_units: u64,
    pub max_route_credit_micro_units: u64,
    pub fee_ceiling_bps: u64,
    pub reserve_bps: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub operator_id: String,
}

impl FeeCreditPool {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.asset_id),
            "pool.asset",
            format!("asset {} is not accepted", self.asset_id),
        )?;
        require(
            self.asset_kind.can_settle_fees(),
            "pool.asset_kind",
            "asset kind cannot settle fees",
        )?;
        require(
            self.available_credit_micro_units >= config.min_pool_liquidity_micro_units,
            "pool.liquidity",
            "pool available credit below configured minimum",
        )?;
        require(
            self.max_route_credit_micro_units >= self.min_route_credit_micro_units,
            "pool.route_range",
            "pool max route credit below min route credit",
        )?;
        require(
            self.reserved_credit_micro_units <= self.available_credit_micro_units,
            "pool.reserve",
            "reserved credit exceeds available credit",
        )?;
        require(
            self.fee_ceiling_bps <= config.max_user_fee_bps,
            "pool.fee_ceiling",
            "pool fee ceiling exceeds max user fee",
        )?;
        require(
            self.reserve_bps <= MAX_BPS,
            "pool.reserve_bps",
            "pool reserve bps outside range",
        )?;
        require(
            self.expires_at_l2_height > self.opened_at_l2_height,
            "pool.expiry",
            "pool expiry must be after open height",
        )?;
        require(
            !self.operator_id.is_empty(),
            "pool.operator",
            "pool operator id cannot be empty",
        )?;
        Ok(())
    }

    pub fn remaining_credit_micro_units(&self) -> u64 {
        self.available_credit_micro_units
            .saturating_sub(self.reserved_credit_micro_units)
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "asset_kind": self.asset_kind.as_str(),
            "expires_at_l2_height": self.expires_at_l2_height,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "liquidity_root": self.liquidity_root,
            "operator_id": self.operator_id,
            "pool_commitment": self.pool_commitment,
            "pool_id": self.pool_id,
            "remaining_credit_micro_units": self.remaining_credit_micro_units(),
            "route_policy_root": self.route_policy_root,
            "sponsor_set_root": self.sponsor_set_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteHop {
    pub hop_id: String,
    pub pool_id: String,
    pub from_asset_id: String,
    pub to_asset_id: String,
    pub conversion_commitment: String,
    pub encrypted_amount_commitment: String,
    pub max_spread_bps: u64,
    pub router_fee_bps: u64,
    pub privacy_set_size: u64,
    pub decoy_set_root: String,
}

impl RouteHop {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.from_asset_id),
            "hop.from_asset",
            format!("from asset {} is not accepted", self.from_asset_id),
        )?;
        require(
            config.accepted_assets.contains(&self.to_asset_id),
            "hop.to_asset",
            format!("to asset {} is not accepted", self.to_asset_id),
        )?;
        require(
            self.max_spread_bps <= MAX_BPS,
            "hop.spread",
            "hop max spread bps outside range",
        )?;
        require(
            self.router_fee_bps <= config.router_margin_bps,
            "hop.router_fee",
            "hop router fee exceeds configured margin",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "hop.privacy",
            "hop privacy set below minimum",
        )?;
        require(
            !self.pool_id.is_empty(),
            "hop.pool",
            "hop pool id cannot be empty",
        )?;
        Ok(())
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "conversion_commitment": self.conversion_commitment,
            "decoy_set_root": self.decoy_set_root,
            "from_asset_id": self.from_asset_id,
            "hop_id": self.hop_id,
            "max_spread_bps": self.max_spread_bps,
            "pool_id": self.pool_id,
            "privacy_set_size": self.privacy_set_size,
            "router_fee_bps": self.router_fee_bps,
            "to_asset_id": self.to_asset_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MultiAssetRoute {
    pub route_id: String,
    pub payer_cohort_root: String,
    pub destination_cohort_root: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub fee_credit_asset_id: String,
    pub status: RouteStatus,
    pub route_commitment: String,
    pub encrypted_route_note: String,
    pub hops: Vec<RouteHop>,
    pub sponsor_commitment_id: Option<String>,
    pub attestation_id: Option<String>,
    pub voucher_id: Option<String>,
    pub max_user_fee_micro_units: u64,
    pub sponsor_credit_micro_units: u64,
    pub expected_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub quoted_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub nullifier_root: String,
}

impl MultiAssetRoute {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.input_asset_id),
            "route.input_asset",
            "route input asset is not accepted",
        )?;
        require(
            config.accepted_assets.contains(&self.output_asset_id),
            "route.output_asset",
            "route output asset is not accepted",
        )?;
        require(
            config.accepted_assets.contains(&self.fee_credit_asset_id),
            "route.fee_credit_asset",
            "route fee credit asset is not accepted",
        )?;
        require(
            !self.hops.is_empty(),
            "route.hops",
            "route requires at least one hop",
        )?;
        require(
            self.hops.len() <= config.route_max_hops,
            "route.hop_limit",
            "route exceeds max hop count",
        )?;
        require(
            self.max_user_fee_micro_units > 0,
            "route.user_fee",
            "route max user fee must be nonzero",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "route.privacy",
            "route privacy set below minimum",
        )?;
        require(
            self.expires_at_l2_height > self.quoted_at_l2_height,
            "route.expiry",
            "route expiry must be after quote height",
        )?;
        for hop in &self.hops {
            hop.validate(config)?;
        }
        Ok(())
    }

    pub fn total_router_fee_bps(&self) -> u64 {
        self.hops
            .iter()
            .fold(0_u64, |acc, hop| acc.saturating_add(hop.router_fee_bps))
    }

    pub fn hop_ids(&self) -> Vec<String> {
        self.hops.iter().map(|hop| hop.hop_id.clone()).collect()
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "destination_cohort_root": self.destination_cohort_root,
            "expected_rebate_micro_units": self.expected_rebate_micro_units,
            "expires_at_l2_height": self.expires_at_l2_height,
            "fee_credit_asset_id": self.fee_credit_asset_id,
            "hop_ids": self.hop_ids(),
            "input_asset_id": self.input_asset_id,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "nullifier_root": self.nullifier_root,
            "output_asset_id": self.output_asset_id,
            "payer_cohort_root": self.payer_cohort_root,
            "privacy_set_size": self.privacy_set_size,
            "quoted_at_l2_height": self.quoted_at_l2_height,
            "route_commitment": self.route_commitment,
            "route_id": self.route_id,
            "sponsor_commitment_id": self.sponsor_commitment_id,
            "sponsor_credit_micro_units": self.sponsor_credit_micro_units,
            "status": self.status.as_str(),
            "total_router_fee_bps": self.total_router_fee_bps(),
            "voucher_id": self.voucher_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorCommitment {
    pub sponsor_commitment_id: String,
    pub sponsor_id: String,
    pub pool_id: String,
    pub asset_id: String,
    pub status: SponsorStatus,
    pub sponsor_commitment: String,
    pub credential_root: String,
    pub rate_card_root: String,
    pub committed_credit_micro_units: u64,
    pub reserved_credit_micro_units: u64,
    pub max_fee_bps: u64,
    pub reserve_bps: u64,
    pub pq_key_commitment: String,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl SponsorCommitment {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.asset_id),
            "sponsor.asset",
            "sponsor asset is not accepted",
        )?;
        require(
            self.committed_credit_micro_units > 0,
            "sponsor.credit",
            "committed sponsor credit must be nonzero",
        )?;
        require(
            self.reserved_credit_micro_units <= self.committed_credit_micro_units,
            "sponsor.reserve",
            "reserved sponsor credit exceeds commitment",
        )?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "sponsor.max_fee",
            "sponsor max fee exceeds configured max",
        )?;
        require(
            self.reserve_bps >= config.sponsor_reserve_bps,
            "sponsor.reserve_bps",
            "sponsor reserve bps below policy",
        )?;
        require(
            self.expires_at_l2_height > self.opened_at_l2_height,
            "sponsor.expiry",
            "sponsor expiry must be after open height",
        )?;
        Ok(())
    }

    pub fn free_credit_micro_units(&self) -> u64 {
        self.committed_credit_micro_units
            .saturating_sub(self.reserved_credit_micro_units)
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "credential_root": self.credential_root,
            "expires_at_l2_height": self.expires_at_l2_height,
            "free_credit_micro_units": self.free_credit_micro_units(),
            "max_fee_bps": self.max_fee_bps,
            "pool_id": self.pool_id,
            "pq_key_commitment": self.pq_key_commitment,
            "rate_card_root": self.rate_card_root,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsor_commitment_id": self.sponsor_commitment_id,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqRoutingAttestation {
    pub attestation_id: String,
    pub route_id: String,
    pub attestor_id: String,
    pub attestation_root: String,
    pub pq_signature_commitment: String,
    pub transcript_root: String,
    pub path_privacy_root: String,
    pub min_pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub route_fee_bps: u64,
    pub issued_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl PqRoutingAttestation {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.min_pq_security_bits >= config.min_pq_security_bits,
            "attestation.pq",
            "attestation pq security below config",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "attestation.privacy",
            "attestation privacy set below minimum",
        )?;
        require(
            self.route_fee_bps <= config.max_user_fee_bps,
            "attestation.fee",
            "attested route fee exceeds config",
        )?;
        require(
            self.expires_at_l2_height > self.issued_at_l2_height,
            "attestation.expiry",
            "attestation expiry must be after issue height",
        )?;
        Ok(())
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "attestation_root": self.attestation_root,
            "attestor_id": self.attestor_id,
            "expires_at_l2_height": self.expires_at_l2_height,
            "issued_at_l2_height": self.issued_at_l2_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "path_privacy_root": self.path_privacy_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_commitment": self.pq_signature_commitment,
            "route_fee_bps": self.route_fee_bps,
            "route_id": self.route_id,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementVoucher {
    pub voucher_id: String,
    pub route_id: String,
    pub sponsor_commitment_id: Option<String>,
    pub asset_id: String,
    pub status: VoucherStatus,
    pub voucher_commitment: String,
    pub settlement_root: String,
    pub redemption_nullifier_root: String,
    pub settlement_amount_micro_units: u64,
    pub user_fee_micro_units: u64,
    pub sponsor_paid_micro_units: u64,
    pub rebate_due_micro_units: u64,
    pub issued_at_l2_height: u64,
    pub redeemable_after_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl SettlementVoucher {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.asset_id),
            "voucher.asset",
            "voucher asset is not accepted",
        )?;
        require(
            self.settlement_amount_micro_units > 0,
            "voucher.amount",
            "voucher settlement amount must be nonzero",
        )?;
        require(
            self.user_fee_micro_units <= self.settlement_amount_micro_units,
            "voucher.user_fee",
            "voucher user fee exceeds settlement amount",
        )?;
        require(
            self.sponsor_paid_micro_units <= self.settlement_amount_micro_units,
            "voucher.sponsor_paid",
            "voucher sponsor paid exceeds settlement amount",
        )?;
        require(
            self.redeemable_after_l2_height >= self.issued_at_l2_height,
            "voucher.redeemable_after",
            "voucher redeemable height before issue height",
        )?;
        require(
            self.expires_at_l2_height > self.issued_at_l2_height,
            "voucher.expiry",
            "voucher expiry must be after issue height",
        )?;
        Ok(())
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "expires_at_l2_height": self.expires_at_l2_height,
            "issued_at_l2_height": self.issued_at_l2_height,
            "rebate_due_micro_units": self.rebate_due_micro_units,
            "redeemable_after_l2_height": self.redeemable_after_l2_height,
            "redemption_nullifier_root": self.redemption_nullifier_root,
            "route_id": self.route_id,
            "settlement_amount_micro_units": self.settlement_amount_micro_units,
            "settlement_root": self.settlement_root,
            "sponsor_commitment_id": self.sponsor_commitment_id,
            "sponsor_paid_micro_units": self.sponsor_paid_micro_units,
            "status": self.status.as_str(),
            "user_fee_micro_units": self.user_fee_micro_units,
            "voucher_commitment": self.voucher_commitment,
            "voucher_id": self.voucher_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AntiAbuseThrottle {
    pub throttle_id: String,
    pub subject_commitment: String,
    pub route_id: Option<String>,
    pub pool_id: Option<String>,
    pub status: ThrottleStatus,
    pub reason_code: String,
    pub nullifier_root: String,
    pub evidence_root: String,
    pub window_start_l2_height: u64,
    pub window_end_l2_height: u64,
    pub observed_route_count: u64,
    pub allowed_route_count: u64,
    pub escrow_micro_units: u64,
}

impl AntiAbuseThrottle {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.window_end_l2_height > self.window_start_l2_height,
            "throttle.window",
            "throttle window end must be after start",
        )?;
        require(
            self.allowed_route_count > 0,
            "throttle.allowance",
            "allowed route count must be nonzero",
        )?;
        require(
            self.escrow_micro_units >= config.abuse_escrow_micro_units,
            "throttle.escrow",
            "abuse escrow below configured minimum",
        )?;
        require(
            !self.subject_commitment.is_empty(),
            "throttle.subject",
            "throttle subject commitment cannot be empty",
        )?;
        Ok(())
    }

    pub fn over_limit(&self) -> bool {
        self.observed_route_count > self.allowed_route_count
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "allowed_route_count": self.allowed_route_count,
            "escrow_micro_units": self.escrow_micro_units,
            "evidence_root": self.evidence_root,
            "nullifier_root": self.nullifier_root,
            "observed_route_count": self.observed_route_count,
            "over_limit": self.over_limit(),
            "pool_id": self.pool_id,
            "reason_code": self.reason_code,
            "route_id": self.route_id,
            "status": self.status.as_str(),
            "subject_commitment": self.subject_commitment,
            "throttle_id": self.throttle_id,
            "window_end_l2_height": self.window_end_l2_height,
            "window_start_l2_height": self.window_start_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateDistribution {
    pub rebate_id: String,
    pub voucher_id: String,
    pub route_id: String,
    pub asset_id: String,
    pub rebate_commitment: String,
    pub recipient_set_root: String,
    pub distribution_proof_root: String,
    pub total_rebate_micro_units: u64,
    pub sponsor_rebate_micro_units: u64,
    pub user_rebate_micro_units: u64,
    pub operator_rebate_micro_units: u64,
    pub distributed_at_l2_height: u64,
}

impl RebateDistribution {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            config.accepted_assets.contains(&self.asset_id),
            "rebate.asset",
            "rebate asset is not accepted",
        )?;
        let parts = self
            .sponsor_rebate_micro_units
            .saturating_add(self.user_rebate_micro_units)
            .saturating_add(self.operator_rebate_micro_units);
        require(
            parts == self.total_rebate_micro_units,
            "rebate.sum",
            "rebate parts do not sum to total",
        )?;
        require(
            self.total_rebate_micro_units > 0,
            "rebate.total",
            "rebate total must be nonzero",
        )?;
        Ok(())
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "distributed_at_l2_height": self.distributed_at_l2_height,
            "distribution_proof_root": self.distribution_proof_root,
            "operator_rebate_micro_units": self.operator_rebate_micro_units,
            "rebate_commitment": self.rebate_commitment,
            "rebate_id": self.rebate_id,
            "recipient_set_root": self.recipient_set_root,
            "route_id": self.route_id,
            "sponsor_rebate_micro_units": self.sponsor_rebate_micro_units,
            "total_rebate_micro_units": self.total_rebate_micro_units,
            "user_rebate_micro_units": self.user_rebate_micro_units,
            "voucher_id": self.voucher_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub class: RedactionClass,
    pub subject_root: String,
    pub redaction_policy_root: String,
    pub budget_commitment: String,
    pub epoch: u64,
    pub max_redactions: u64,
    pub used_redactions: u64,
    pub max_public_fields: u64,
    pub remaining_public_fields: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
}

impl RedactionBudget {
    pub fn validate(&self) -> Result<()> {
        require(
            self.used_redactions <= self.max_redactions,
            "redaction.used",
            "used redactions exceed max redactions",
        )?;
        require(
            self.remaining_public_fields <= self.max_public_fields,
            "redaction.fields",
            "remaining public fields exceeds max public fields",
        )?;
        require(
            self.expires_at_l2_height > self.opened_at_l2_height,
            "redaction.expiry",
            "redaction budget expiry must be after open height",
        )?;
        Ok(())
    }

    pub fn remaining_redactions(&self) -> u64 {
        self.max_redactions.saturating_sub(self.used_redactions)
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "budget_commitment": self.budget_commitment,
            "budget_id": self.budget_id,
            "class": self.class.as_str(),
            "epoch": self.epoch,
            "expires_at_l2_height": self.expires_at_l2_height,
            "max_public_fields": self.max_public_fields,
            "opened_at_l2_height": self.opened_at_l2_height,
            "redaction_policy_root": self.redaction_policy_root,
            "remaining_public_fields": self.remaining_public_fields,
            "remaining_redactions": self.remaining_redactions(),
            "subject_root": self.subject_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub health: OperatorHealth,
    pub operated_pool_root: String,
    pub route_summary_root: String,
    pub voucher_summary_root: String,
    pub throttle_summary_root: String,
    pub rebate_summary_root: String,
    pub summary_commitment: String,
    pub routes_served: u64,
    pub routes_settled: u64,
    pub vouchers_issued: u64,
    pub throttles_triggered: u64,
    pub rebates_distributed_micro_units: u64,
    pub average_fee_bps: u64,
    pub summarized_at_l2_height: u64,
}

impl OperatorSummary {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require(
            self.routes_settled <= self.routes_served,
            "operator.routes",
            "settled routes exceed served routes",
        )?;
        require(
            self.average_fee_bps <= config.max_user_fee_bps,
            "operator.fee",
            "operator average fee exceeds configured max user fee",
        )?;
        require(
            !self.operator_id.is_empty(),
            "operator.id",
            "operator id cannot be empty",
        )?;
        Ok(())
    }

    pub fn public_leaf(&self) -> Value {
        json!({
            "average_fee_bps": self.average_fee_bps,
            "health": self.health.as_str(),
            "operated_pool_root": self.operated_pool_root,
            "operator_id": self.operator_id,
            "rebate_summary_root": self.rebate_summary_root,
            "rebates_distributed_micro_units": self.rebates_distributed_micro_units,
            "route_summary_root": self.route_summary_root,
            "routes_served": self.routes_served,
            "routes_settled": self.routes_settled,
            "summarized_at_l2_height": self.summarized_at_l2_height,
            "summary_commitment": self.summary_commitment,
            "throttle_summary_root": self.throttle_summary_root,
            "throttles_triggered": self.throttles_triggered,
            "voucher_summary_root": self.voucher_summary_root,
            "vouchers_issued": self.vouchers_issued,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub fee_credit_pools: BTreeMap<String, FeeCreditPool>,
    pub multi_asset_routes: BTreeMap<String, MultiAssetRoute>,
    pub sponsor_commitments: BTreeMap<String, SponsorCommitment>,
    pub pq_routing_attestations: BTreeMap<String, PqRoutingAttestation>,
    pub settlement_vouchers: BTreeMap<String, SettlementVoucher>,
    pub anti_abuse_throttles: BTreeMap<String, AntiAbuseThrottle>,
    pub rebate_distributions: BTreeMap<String, RebateDistribution>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub route_index_by_pool: BTreeMap<String, BTreeSet<String>>,
    pub route_index_by_sponsor: BTreeMap<String, BTreeSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            fee_credit_pools: BTreeMap::new(),
            multi_asset_routes: BTreeMap::new(),
            sponsor_commitments: BTreeMap::new(),
            pq_routing_attestations: BTreeMap::new(),
            settlement_vouchers: BTreeMap::new(),
            anti_abuse_throttles: BTreeMap::new(),
            rebate_distributions: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            route_index_by_pool: BTreeMap::new(),
            route_index_by_sponsor: BTreeMap::new(),
        };
        state.recompute();
        Ok(state)
    }

    pub fn devnet() -> Self {
        demo_state().expect("devnet runtime fixture must validate")
    }

    pub fn public_record(&self) -> Value {
        public_record(self)
    }

    pub fn state_root(&self) -> String {
        state_root(self)
    }

    pub fn insert_fee_credit_pool(&mut self, pool: FeeCreditPool) -> Result<()> {
        pool.validate(&self.config)?;
        require(
            !self.fee_credit_pools.contains_key(&pool.pool_id),
            "pool.duplicate",
            format!("duplicate pool {}", pool.pool_id),
        )?;
        self.fee_credit_pools.insert(pool.pool_id.clone(), pool);
        self.recompute();
        Ok(())
    }

    pub fn insert_sponsor_commitment(&mut self, sponsor: SponsorCommitment) -> Result<()> {
        sponsor.validate(&self.config)?;
        require(
            self.fee_credit_pools.contains_key(&sponsor.pool_id),
            "sponsor.pool",
            format!("unknown sponsor pool {}", sponsor.pool_id),
        )?;
        require(
            !self
                .sponsor_commitments
                .contains_key(&sponsor.sponsor_commitment_id),
            "sponsor.duplicate",
            format!(
                "duplicate sponsor commitment {}",
                sponsor.sponsor_commitment_id
            ),
        )?;
        self.sponsor_commitments
            .insert(sponsor.sponsor_commitment_id.clone(), sponsor);
        self.recompute();
        Ok(())
    }

    pub fn insert_route(&mut self, route: MultiAssetRoute) -> Result<()> {
        route.validate(&self.config)?;
        require(
            !self.multi_asset_routes.contains_key(&route.route_id),
            "route.duplicate",
            format!("duplicate route {}", route.route_id),
        )?;
        for hop in &route.hops {
            let pool = self
                .fee_credit_pools
                .get(&hop.pool_id)
                .ok_or_else(|| err("route.pool", format!("unknown route pool {}", hop.pool_id)))?;
            require(
                pool.status.accepts_routes(),
                "route.pool_status",
                format!("pool {} does not accept routes", pool.pool_id),
            )?;
        }
        if let Some(sponsor_id) = &route.sponsor_commitment_id {
            let sponsor = self.sponsor_commitments.get(sponsor_id).ok_or_else(|| {
                err(
                    "route.sponsor",
                    format!("unknown sponsor commitment {sponsor_id}"),
                )
            })?;
            require(
                sponsor.status.matchable(),
                "route.sponsor_status",
                format!("sponsor commitment {sponsor_id} is not matchable"),
            )?;
        }
        self.multi_asset_routes
            .insert(route.route_id.clone(), route.clone());
        for hop in &route.hops {
            self.route_index_by_pool
                .entry(hop.pool_id.clone())
                .or_default()
                .insert(route.route_id.clone());
        }
        if let Some(sponsor_id) = &route.sponsor_commitment_id {
            self.route_index_by_sponsor
                .entry(sponsor_id.clone())
                .or_default()
                .insert(route.route_id.clone());
        }
        self.recompute();
        Ok(())
    }

    pub fn insert_pq_routing_attestation(
        &mut self,
        attestation: PqRoutingAttestation,
    ) -> Result<()> {
        attestation.validate(&self.config)?;
        require(
            self.multi_asset_routes.contains_key(&attestation.route_id),
            "attestation.route",
            format!("unknown attested route {}", attestation.route_id),
        )?;
        require(
            !self
                .pq_routing_attestations
                .contains_key(&attestation.attestation_id),
            "attestation.duplicate",
            format!("duplicate attestation {}", attestation.attestation_id),
        )?;
        self.pq_routing_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute();
        Ok(())
    }

    pub fn insert_settlement_voucher(&mut self, voucher: SettlementVoucher) -> Result<()> {
        voucher.validate(&self.config)?;
        require(
            self.multi_asset_routes.contains_key(&voucher.route_id),
            "voucher.route",
            format!("unknown voucher route {}", voucher.route_id),
        )?;
        if let Some(sponsor_id) = &voucher.sponsor_commitment_id {
            require(
                self.sponsor_commitments.contains_key(sponsor_id),
                "voucher.sponsor",
                format!("unknown voucher sponsor {}", sponsor_id),
            )?;
        }
        require(
            !self.settlement_vouchers.contains_key(&voucher.voucher_id),
            "voucher.duplicate",
            format!("duplicate voucher {}", voucher.voucher_id),
        )?;
        self.settlement_vouchers
            .insert(voucher.voucher_id.clone(), voucher);
        self.recompute();
        Ok(())
    }

    pub fn insert_anti_abuse_throttle(&mut self, throttle: AntiAbuseThrottle) -> Result<()> {
        throttle.validate(&self.config)?;
        if let Some(route_id) = &throttle.route_id {
            require(
                self.multi_asset_routes.contains_key(route_id),
                "throttle.route",
                format!("unknown throttle route {}", route_id),
            )?;
        }
        if let Some(pool_id) = &throttle.pool_id {
            require(
                self.fee_credit_pools.contains_key(pool_id),
                "throttle.pool",
                format!("unknown throttle pool {}", pool_id),
            )?;
        }
        require(
            !self
                .anti_abuse_throttles
                .contains_key(&throttle.throttle_id),
            "throttle.duplicate",
            format!("duplicate throttle {}", throttle.throttle_id),
        )?;
        self.anti_abuse_throttles
            .insert(throttle.throttle_id.clone(), throttle);
        self.recompute();
        Ok(())
    }

    pub fn insert_rebate_distribution(&mut self, rebate: RebateDistribution) -> Result<()> {
        rebate.validate(&self.config)?;
        require(
            self.multi_asset_routes.contains_key(&rebate.route_id),
            "rebate.route",
            format!("unknown rebate route {}", rebate.route_id),
        )?;
        require(
            self.settlement_vouchers.contains_key(&rebate.voucher_id),
            "rebate.voucher",
            format!("unknown rebate voucher {}", rebate.voucher_id),
        )?;
        require(
            !self.rebate_distributions.contains_key(&rebate.rebate_id),
            "rebate.duplicate",
            format!("duplicate rebate {}", rebate.rebate_id),
        )?;
        self.rebate_distributions
            .insert(rebate.rebate_id.clone(), rebate);
        self.recompute();
        Ok(())
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        budget.validate()?;
        require(
            !self.redaction_budgets.contains_key(&budget.budget_id),
            "redaction.duplicate",
            format!("duplicate redaction budget {}", budget.budget_id),
        )?;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.recompute();
        Ok(())
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        summary.validate(&self.config)?;
        require(
            !self.operator_summaries.contains_key(&summary.operator_id),
            "operator.duplicate",
            format!("duplicate operator summary {}", summary.operator_id),
        )?;
        self.operator_summaries
            .insert(summary.operator_id.clone(), summary);
        self.recompute();
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "state.protocol",
            "protocol version mismatch",
        )?;
        for pool in self.fee_credit_pools.values() {
            pool.validate(&self.config)?;
        }
        for sponsor in self.sponsor_commitments.values() {
            sponsor.validate(&self.config)?;
        }
        for route in self.multi_asset_routes.values() {
            route.validate(&self.config)?;
        }
        for attestation in self.pq_routing_attestations.values() {
            attestation.validate(&self.config)?;
        }
        for voucher in self.settlement_vouchers.values() {
            voucher.validate(&self.config)?;
        }
        for throttle in self.anti_abuse_throttles.values() {
            throttle.validate(&self.config)?;
        }
        for rebate in self.rebate_distributions.values() {
            rebate.validate(&self.config)?;
        }
        for budget in self.redaction_budgets.values() {
            budget.validate()?;
        }
        for summary in self.operator_summaries.values() {
            summary.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn recompute(&mut self) {
        self.rebuild_indexes();
        self.counters = self.derive_counters();
        self.roots = self.derive_roots();
    }

    fn rebuild_indexes(&mut self) {
        self.route_index_by_pool.clear();
        self.route_index_by_sponsor.clear();
        for route in self.multi_asset_routes.values() {
            for hop in &route.hops {
                self.route_index_by_pool
                    .entry(hop.pool_id.clone())
                    .or_default()
                    .insert(route.route_id.clone());
            }
            if let Some(sponsor_id) = &route.sponsor_commitment_id {
                self.route_index_by_sponsor
                    .entry(sponsor_id.clone())
                    .or_default()
                    .insert(route.route_id.clone());
            }
        }
    }

    fn derive_counters(&self) -> Counters {
        let mut counters = Counters::default();
        for pool in self.fee_credit_pools.values() {
            counters.absorb_pool(pool);
        }
        for sponsor in self.sponsor_commitments.values() {
            counters.absorb_sponsor(sponsor);
        }
        for route in self.multi_asset_routes.values() {
            counters.absorb_route(route);
        }
        counters.pq_routing_attestations = self.pq_routing_attestations.len() as u64;
        for voucher in self.settlement_vouchers.values() {
            counters.absorb_voucher(voucher);
        }
        counters.anti_abuse_throttles = self.anti_abuse_throttles.len() as u64;
        for rebate in self.rebate_distributions.values() {
            counters.absorb_rebate(rebate);
        }
        counters.redaction_budgets = self.redaction_budgets.len() as u64;
        counters.operator_summaries = self.operator_summaries.len() as u64;
        counters
    }

    fn derive_roots(&self) -> Roots {
        let fee_credit_pools_root = root_from_values(
            "fee-credit-pools",
            &self
                .fee_credit_pools
                .values()
                .map(FeeCreditPool::public_leaf)
                .collect::<Vec<_>>(),
        );
        let multi_asset_routes_root = root_from_values(
            "multi-asset-routes",
            &self
                .multi_asset_routes
                .values()
                .map(MultiAssetRoute::public_leaf)
                .collect::<Vec<_>>(),
        );
        let route_hops_root = root_from_values("route-hops", &self.route_hop_leaves());
        let sponsor_commitments_root = root_from_values(
            "sponsor-commitments",
            &self
                .sponsor_commitments
                .values()
                .map(SponsorCommitment::public_leaf)
                .collect::<Vec<_>>(),
        );
        let pq_routing_attestations_root = root_from_values(
            "pq-routing-attestations",
            &self
                .pq_routing_attestations
                .values()
                .map(PqRoutingAttestation::public_leaf)
                .collect::<Vec<_>>(),
        );
        let settlement_vouchers_root = root_from_values(
            "settlement-vouchers",
            &self
                .settlement_vouchers
                .values()
                .map(SettlementVoucher::public_leaf)
                .collect::<Vec<_>>(),
        );
        let anti_abuse_throttles_root = root_from_values(
            "anti-abuse-throttles",
            &self
                .anti_abuse_throttles
                .values()
                .map(AntiAbuseThrottle::public_leaf)
                .collect::<Vec<_>>(),
        );
        let rebate_distributions_root = root_from_values(
            "rebate-distributions",
            &self
                .rebate_distributions
                .values()
                .map(RebateDistribution::public_leaf)
                .collect::<Vec<_>>(),
        );
        let redaction_budgets_root = root_from_values(
            "redaction-budgets",
            &self
                .redaction_budgets
                .values()
                .map(RedactionBudget::public_leaf)
                .collect::<Vec<_>>(),
        );
        let operator_summaries_root = root_from_values(
            "operator-summaries",
            &self
                .operator_summaries
                .values()
                .map(OperatorSummary::public_leaf)
                .collect::<Vec<_>>(),
        );
        let public_record_root = domain_hash(
            PUBLIC_RECORD_SUITE,
            &[
                HashPart::Str(&fee_credit_pools_root),
                HashPart::Str(&multi_asset_routes_root),
                HashPart::Str(&sponsor_commitments_root),
                HashPart::Str(&pq_routing_attestations_root),
                HashPart::Str(&settlement_vouchers_root),
                HashPart::Str(&anti_abuse_throttles_root),
                HashPart::Str(&rebate_distributions_root),
                HashPart::Str(&redaction_budgets_root),
                HashPart::Str(&operator_summaries_root),
            ],
            32,
        );
        let state_root = domain_hash(
            "private-l2-low-fee-pq-confidential-multi-asset-fee-credit-router-state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(SCHEMA_VERSION),
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.config.l2_height),
                HashPart::U64(self.config.epoch),
                HashPart::Str(&public_record_root),
                HashPart::Json(&json!(self.counters)),
            ],
            32,
        );
        Roots {
            fee_credit_pools_root,
            multi_asset_routes_root,
            route_hops_root,
            sponsor_commitments_root,
            pq_routing_attestations_root,
            settlement_vouchers_root,
            anti_abuse_throttles_root,
            rebate_distributions_root,
            redaction_budgets_root,
            operator_summaries_root,
            public_record_root,
            state_root,
        }
    }

    fn route_hop_leaves(&self) -> Vec<Value> {
        let mut leaves = Vec::new();
        for route in self.multi_asset_routes.values() {
            for hop in &route.hops {
                leaves.push(json!({
                    "hop": hop.public_leaf(),
                    "route_id": route.route_id,
                }));
            }
        }
        leaves
    }

    pub fn public_pool_ids(&self) -> Vec<String> {
        self.fee_credit_pools.keys().cloned().collect()
    }

    pub fn public_route_ids(&self) -> Vec<String> {
        self.multi_asset_routes.keys().cloned().collect()
    }

    pub fn route_ids_for_pool(&self, pool_id: &str) -> Vec<String> {
        self.route_index_by_pool
            .get(pool_id)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn route_ids_for_sponsor(&self, sponsor_id: &str) -> Vec<String> {
        self.route_index_by_sponsor
            .get(sponsor_id)
            .map(|ids| ids.iter().cloned().collect())
            .unwrap_or_default()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    json!({
        "accepted_assets": state.config.accepted_assets,
        "chain_id": state.config.chain_id,
        "config": {
            "abuse_escrow_micro_units": state.config.abuse_escrow_micro_units,
            "batch_max_routes": state.config.batch_max_routes,
            "epoch": state.config.epoch,
            "l2_height": state.config.l2_height,
            "max_user_fee_bps": state.config.max_user_fee_bps,
            "min_pool_liquidity_micro_units": state.config.min_pool_liquidity_micro_units,
            "min_pq_security_bits": state.config.min_pq_security_bits,
            "min_privacy_set_size": state.config.min_privacy_set_size,
            "monero_height": state.config.monero_height,
            "rebate_target_bps": state.config.rebate_target_bps,
            "redaction_epoch_blocks": state.config.redaction_epoch_blocks,
            "route_max_hops": state.config.route_max_hops,
            "route_ttl_blocks": state.config.route_ttl_blocks,
            "router_margin_bps": state.config.router_margin_bps,
            "sponsor_reserve_bps": state.config.sponsor_reserve_bps,
            "target_privacy_set_size": state.config.target_privacy_set_size,
            "throttle_window_blocks": state.config.throttle_window_blocks,
            "voucher_ttl_blocks": state.config.voucher_ttl_blocks,
        },
        "counters": state.counters,
        "hash_suite": state.hash_suite,
        "protocol_version": state.protocol_version,
        "pq_attestation_suite": state.pq_attestation_suite,
        "roots": state.roots,
        "schema_version": state.schema_version,
    })
}

pub fn state_root(state: &State) -> String {
    state.roots.state_root.clone()
}

fn root_from_values(domain: &str, values: &[Value]) -> String {
    merkle_root(
        &format!("private-l2-low-fee-pq-confidential-multi-asset-fee-credit-router:{domain}"),
        values,
    )
}

fn commitment(domain: &str, id: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private-l2-low-fee-pq-confidential-multi-asset-fee-credit-router:{domain}"),
        &[HashPart::Str(id), HashPart::U64(parts.len() as u64)],
        32,
    )
}

fn demo_state() -> Result<State> {
    let config = Config::devnet();
    let mut state = State::new(config.clone())?;
    state.insert_fee_credit_pool(devnet_pool(
        "pool-wxmr-fast-credit",
        "wxmr-devnet",
        FeeAssetKind::WrappedMonero,
        PoolStatus::Open,
        85_000_000_000,
        7_000_000_000,
        "operator-alpha",
    ))?;
    state.insert_fee_credit_pool(devnet_pool(
        "pool-pdusd-stable-credit",
        "pdusd-devnet",
        FeeAssetKind::StablePrivateToken,
        PoolStatus::Rebalancing,
        120_000_000_000,
        9_500_000_000,
        "operator-beta",
    ))?;
    state.insert_fee_credit_pool(devnet_pool(
        "pool-sponsor-credit",
        "sponsor-credit-devnet",
        FeeAssetKind::SponsorCredit,
        PoolStatus::Open,
        65_000_000_000,
        5_200_000_000,
        "operator-alpha",
    ))?;
    state.insert_sponsor_commitment(devnet_sponsor(
        "sponsor-commitment-alpha-001",
        "sponsor-alpha",
        "pool-sponsor-credit",
        "sponsor-credit-devnet",
        42_000_000_000,
        6_000_000_000,
    ))?;
    state.insert_sponsor_commitment(devnet_sponsor(
        "sponsor-commitment-beta-001",
        "sponsor-beta",
        "pool-pdusd-stable-credit",
        "pdusd-devnet",
        38_000_000_000,
        4_400_000_000,
    ))?;
    let route_alpha = devnet_route(
        "route-credit-wxmr-pdusd-001",
        "wxmr-devnet",
        "pdusd-devnet",
        "fee-credit-devnet",
        Some("sponsor-commitment-alpha-001"),
        vec![
            devnet_hop(
                "hop-route-001-a",
                "pool-wxmr-fast-credit",
                "wxmr-devnet",
                "fee-credit-devnet",
                2,
            ),
            devnet_hop(
                "hop-route-001-b",
                "pool-sponsor-credit",
                "fee-credit-devnet",
                "pdusd-devnet",
                1,
            ),
        ],
        RouteStatus::Settled,
        1_200_000,
        820_000,
        95_000,
    );
    let route_beta = devnet_route(
        "route-credit-pdusd-wxmr-002",
        "pdusd-devnet",
        "wxmr-devnet",
        "sponsor-credit-devnet",
        Some("sponsor-commitment-beta-001"),
        vec![
            devnet_hop(
                "hop-route-002-a",
                "pool-pdusd-stable-credit",
                "pdusd-devnet",
                "sponsor-credit-devnet",
                1,
            ),
            devnet_hop(
                "hop-route-002-b",
                "pool-wxmr-fast-credit",
                "sponsor-credit-devnet",
                "wxmr-devnet",
                2,
            ),
        ],
        RouteStatus::Rebated,
        1_550_000,
        1_010_000,
        120_000,
    );
    state.insert_route(route_alpha)?;
    state.insert_route(route_beta)?;
    state.insert_pq_routing_attestation(devnet_attestation(
        "attestation-route-001",
        "route-credit-wxmr-pdusd-001",
        "attestor-ml-dsa-alpha",
        6,
    ))?;
    state.insert_pq_routing_attestation(devnet_attestation(
        "attestation-route-002",
        "route-credit-pdusd-wxmr-002",
        "attestor-ml-dsa-beta",
        7,
    ))?;
    state.insert_settlement_voucher(devnet_voucher(
        "voucher-route-001",
        "route-credit-wxmr-pdusd-001",
        Some("sponsor-commitment-alpha-001"),
        "pdusd-devnet",
        VoucherStatus::Redeemed,
        1_200_000,
        380_000,
        820_000,
        95_000,
    ))?;
    state.insert_settlement_voucher(devnet_voucher(
        "voucher-route-002",
        "route-credit-pdusd-wxmr-002",
        Some("sponsor-commitment-beta-001"),
        "wxmr-devnet",
        VoucherStatus::Rebated,
        1_550_000,
        540_000,
        1_010_000,
        120_000,
    ))?;
    state.insert_anti_abuse_throttle(devnet_throttle(
        "throttle-route-burst-alpha",
        Some("route-credit-wxmr-pdusd-001"),
        Some("pool-sponsor-credit"),
        ThrottleStatus::CoolingDown,
        18,
        24,
    ))?;
    state.insert_anti_abuse_throttle(devnet_throttle(
        "throttle-pool-beta-quarantine-watch",
        None,
        Some("pool-pdusd-stable-credit"),
        ThrottleStatus::Armed,
        31,
        32,
    ))?;
    state.insert_rebate_distribution(devnet_rebate(
        "rebate-route-001",
        "voucher-route-001",
        "route-credit-wxmr-pdusd-001",
        "pdusd-devnet",
        95_000,
    ))?;
    state.insert_rebate_distribution(devnet_rebate(
        "rebate-route-002",
        "voucher-route-002",
        "route-credit-pdusd-wxmr-002",
        "wxmr-devnet",
        120_000,
    ))?;
    state.insert_redaction_budget(devnet_redaction_budget(
        "redaction-route-hints-epoch-3108",
        RedactionClass::RouteHints,
        24,
        5,
    ))?;
    state.insert_redaction_budget(devnet_redaction_budget(
        "redaction-sponsor-graph-epoch-3108",
        RedactionClass::SponsorGraph,
        12,
        2,
    ))?;
    state.insert_operator_summary(devnet_operator_summary(
        "operator-alpha",
        OperatorHealth::Nominal,
        1,
        1,
        95_000,
        3,
    ))?;
    state.insert_operator_summary(devnet_operator_summary(
        "operator-beta",
        OperatorHealth::Degraded,
        1,
        1,
        120_000,
        4,
    ))?;
    state.validate()?;
    Ok(state)
}

fn devnet_pool(
    pool_id: &str,
    asset_id: &str,
    asset_kind: FeeAssetKind,
    status: PoolStatus,
    available_credit_micro_units: u64,
    reserved_credit_micro_units: u64,
    operator_id: &str,
) -> FeeCreditPool {
    FeeCreditPool {
        pool_id: pool_id.to_string(),
        asset_id: asset_id.to_string(),
        asset_kind,
        status,
        pool_commitment: commitment(
            CONFIDENTIAL_COMMITMENT_SUITE,
            pool_id,
            &[HashPart::Str(asset_id)],
        ),
        liquidity_root: root_from_values("pool-liquidity", &[json!({ "pool_id": pool_id })]),
        route_policy_root: root_from_values("pool-route-policy", &[json!({ "pool_id": pool_id })]),
        sponsor_set_root: root_from_values("pool-sponsors", &[json!({ "pool_id": pool_id })]),
        available_credit_micro_units,
        reserved_credit_micro_units,
        min_route_credit_micro_units: 10_000,
        max_route_credit_micro_units: 8_000_000,
        fee_ceiling_bps: DEFAULT_MAX_USER_FEE_BPS,
        reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
        opened_at_l2_height: DEVNET_L2_HEIGHT,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_POOL_TTL_BLOCKS,
        operator_id: operator_id.to_string(),
    }
}

fn devnet_hop(
    hop_id: &str,
    pool_id: &str,
    from_asset_id: &str,
    to_asset_id: &str,
    router_fee_bps: u64,
) -> RouteHop {
    RouteHop {
        hop_id: hop_id.to_string(),
        pool_id: pool_id.to_string(),
        from_asset_id: from_asset_id.to_string(),
        to_asset_id: to_asset_id.to_string(),
        conversion_commitment: commitment(
            "devnet-hop-conversion",
            hop_id,
            &[HashPart::Str(from_asset_id), HashPart::Str(to_asset_id)],
        ),
        encrypted_amount_commitment: commitment(
            "devnet-hop-amount",
            hop_id,
            &[HashPart::Str(pool_id)],
        ),
        max_spread_bps: 4,
        router_fee_bps,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        decoy_set_root: root_from_values("devnet-hop-decoys", &[json!({ "hop_id": hop_id })]),
    }
}

fn devnet_route(
    route_id: &str,
    input_asset_id: &str,
    output_asset_id: &str,
    fee_credit_asset_id: &str,
    sponsor_commitment_id: Option<&str>,
    hops: Vec<RouteHop>,
    status: RouteStatus,
    max_user_fee_micro_units: u64,
    sponsor_credit_micro_units: u64,
    expected_rebate_micro_units: u64,
) -> MultiAssetRoute {
    MultiAssetRoute {
        route_id: route_id.to_string(),
        payer_cohort_root: root_from_values(
            "devnet-payer-cohort",
            &[json!({ "route_id": route_id })],
        ),
        destination_cohort_root: root_from_values(
            "devnet-destination-cohort",
            &[json!({ "route_id": route_id })],
        ),
        input_asset_id: input_asset_id.to_string(),
        output_asset_id: output_asset_id.to_string(),
        fee_credit_asset_id: fee_credit_asset_id.to_string(),
        status,
        route_commitment: commitment(
            "devnet-route",
            route_id,
            &[
                HashPart::Str(input_asset_id),
                HashPart::Str(output_asset_id),
            ],
        ),
        encrypted_route_note: commitment(
            "devnet-route-note",
            route_id,
            &[HashPart::Str(fee_credit_asset_id)],
        ),
        hops,
        sponsor_commitment_id: sponsor_commitment_id.map(str::to_string),
        attestation_id: None,
        voucher_id: None,
        max_user_fee_micro_units,
        sponsor_credit_micro_units,
        expected_rebate_micro_units,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        quoted_at_l2_height: DEVNET_L2_HEIGHT,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_ROUTE_TTL_BLOCKS,
        nullifier_root: root_from_values(
            "devnet-route-nullifiers",
            &[json!({ "route_id": route_id })],
        ),
    }
}

fn devnet_sponsor(
    sponsor_commitment_id: &str,
    sponsor_id: &str,
    pool_id: &str,
    asset_id: &str,
    committed_credit_micro_units: u64,
    reserved_credit_micro_units: u64,
) -> SponsorCommitment {
    SponsorCommitment {
        sponsor_commitment_id: sponsor_commitment_id.to_string(),
        sponsor_id: sponsor_id.to_string(),
        pool_id: pool_id.to_string(),
        asset_id: asset_id.to_string(),
        status: SponsorStatus::Matched,
        sponsor_commitment: commitment(
            SPONSOR_COMMITMENT_SUITE,
            sponsor_commitment_id,
            &[HashPart::Str(sponsor_id), HashPart::Str(pool_id)],
        ),
        credential_root: root_from_values(
            "devnet-sponsor-credentials",
            &[json!({ "sponsor_id": sponsor_id })],
        ),
        rate_card_root: root_from_values(
            "devnet-sponsor-rate-card",
            &[json!({ "asset_id": asset_id })],
        ),
        committed_credit_micro_units,
        reserved_credit_micro_units,
        max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
        reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
        pq_key_commitment: commitment(
            "devnet-sponsor-pq-key",
            sponsor_id,
            &[HashPart::Str(asset_id)],
        ),
        opened_at_l2_height: DEVNET_L2_HEIGHT,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_SPONSOR_TTL_BLOCKS,
    }
}

fn devnet_attestation(
    attestation_id: &str,
    route_id: &str,
    attestor_id: &str,
    route_fee_bps: u64,
) -> PqRoutingAttestation {
    PqRoutingAttestation {
        attestation_id: attestation_id.to_string(),
        route_id: route_id.to_string(),
        attestor_id: attestor_id.to_string(),
        attestation_root: root_from_values(
            "devnet-route-attestation",
            &[json!({ "attestation_id": attestation_id, "route_id": route_id })],
        ),
        pq_signature_commitment: commitment(
            PQ_ATTESTATION_SUITE,
            attestation_id,
            &[HashPart::Str(attestor_id)],
        ),
        transcript_root: root_from_values(
            "devnet-attestation-transcript",
            &[json!({ "route_id": route_id })],
        ),
        path_privacy_root: root_from_values(
            "devnet-attestation-privacy",
            &[json!({ "route_id": route_id })],
        ),
        min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        route_fee_bps,
        issued_at_l2_height: DEVNET_L2_HEIGHT + 1,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_ROUTE_TTL_BLOCKS,
    }
}

fn devnet_voucher(
    voucher_id: &str,
    route_id: &str,
    sponsor_commitment_id: Option<&str>,
    asset_id: &str,
    status: VoucherStatus,
    settlement_amount_micro_units: u64,
    user_fee_micro_units: u64,
    sponsor_paid_micro_units: u64,
    rebate_due_micro_units: u64,
) -> SettlementVoucher {
    SettlementVoucher {
        voucher_id: voucher_id.to_string(),
        route_id: route_id.to_string(),
        sponsor_commitment_id: sponsor_commitment_id.map(str::to_string),
        asset_id: asset_id.to_string(),
        status,
        voucher_commitment: commitment(
            SETTLEMENT_VOUCHER_SUITE,
            voucher_id,
            &[HashPart::Str(route_id)],
        ),
        settlement_root: root_from_values(
            "devnet-voucher-settlement",
            &[json!({ "voucher_id": voucher_id })],
        ),
        redemption_nullifier_root: root_from_values(
            "devnet-voucher-redemption-nullifier",
            &[json!({ "voucher_id": voucher_id })],
        ),
        settlement_amount_micro_units,
        user_fee_micro_units,
        sponsor_paid_micro_units,
        rebate_due_micro_units,
        issued_at_l2_height: DEVNET_L2_HEIGHT + 2,
        redeemable_after_l2_height: DEVNET_L2_HEIGHT + 4,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_VOUCHER_TTL_BLOCKS,
    }
}

fn devnet_throttle(
    throttle_id: &str,
    route_id: Option<&str>,
    pool_id: Option<&str>,
    status: ThrottleStatus,
    observed_route_count: u64,
    allowed_route_count: u64,
) -> AntiAbuseThrottle {
    AntiAbuseThrottle {
        throttle_id: throttle_id.to_string(),
        subject_commitment: commitment("devnet-throttle-subject", throttle_id, &[]),
        route_id: route_id.map(str::to_string),
        pool_id: pool_id.map(str::to_string),
        status,
        reason_code: "burst_fee_credit_reservation".to_string(),
        nullifier_root: root_from_values(
            "devnet-throttle-nullifiers",
            &[json!({ "throttle_id": throttle_id })],
        ),
        evidence_root: root_from_values(
            "devnet-throttle-evidence",
            &[json!({ "throttle_id": throttle_id })],
        ),
        window_start_l2_height: DEVNET_L2_HEIGHT,
        window_end_l2_height: DEVNET_L2_HEIGHT + DEFAULT_THROTTLE_WINDOW_BLOCKS,
        observed_route_count,
        allowed_route_count,
        escrow_micro_units: DEFAULT_ABUSE_ESCROW_MICRO_UNITS,
    }
}

fn devnet_rebate(
    rebate_id: &str,
    voucher_id: &str,
    route_id: &str,
    asset_id: &str,
    total_rebate_micro_units: u64,
) -> RebateDistribution {
    let sponsor_rebate_micro_units = total_rebate_micro_units / 4;
    let operator_rebate_micro_units = total_rebate_micro_units / 10;
    let user_rebate_micro_units = total_rebate_micro_units
        .saturating_sub(sponsor_rebate_micro_units)
        .saturating_sub(operator_rebate_micro_units);
    RebateDistribution {
        rebate_id: rebate_id.to_string(),
        voucher_id: voucher_id.to_string(),
        route_id: route_id.to_string(),
        asset_id: asset_id.to_string(),
        rebate_commitment: commitment(
            REBATE_DISTRIBUTION_SUITE,
            rebate_id,
            &[HashPart::Str(voucher_id)],
        ),
        recipient_set_root: root_from_values(
            "devnet-rebate-recipients",
            &[json!({ "rebate_id": rebate_id })],
        ),
        distribution_proof_root: root_from_values(
            "devnet-rebate-distribution-proof",
            &[json!({ "rebate_id": rebate_id })],
        ),
        total_rebate_micro_units,
        sponsor_rebate_micro_units,
        user_rebate_micro_units,
        operator_rebate_micro_units,
        distributed_at_l2_height: DEVNET_L2_HEIGHT + 8,
    }
}

fn devnet_redaction_budget(
    budget_id: &str,
    class: RedactionClass,
    max_redactions: u64,
    used_redactions: u64,
) -> RedactionBudget {
    RedactionBudget {
        budget_id: budget_id.to_string(),
        class,
        subject_root: root_from_values(
            "devnet-redaction-subjects",
            &[json!({ "budget_id": budget_id })],
        ),
        redaction_policy_root: root_from_values(
            "devnet-redaction-policy",
            &[json!({ "class": class.as_str() })],
        ),
        budget_commitment: commitment(
            REDACTION_BUDGET_SUITE,
            budget_id,
            &[HashPart::Str(class.as_str())],
        ),
        epoch: DEVNET_EPOCH,
        max_redactions,
        used_redactions,
        max_public_fields: 64,
        remaining_public_fields: 48,
        opened_at_l2_height: DEVNET_L2_HEIGHT,
        expires_at_l2_height: DEVNET_L2_HEIGHT + DEFAULT_REDACTION_EPOCH_BLOCKS,
    }
}

fn devnet_operator_summary(
    operator_id: &str,
    health: OperatorHealth,
    routes_served: u64,
    vouchers_issued: u64,
    rebates_distributed_micro_units: u64,
    average_fee_bps: u64,
) -> OperatorSummary {
    OperatorSummary {
        operator_id: operator_id.to_string(),
        health,
        operated_pool_root: root_from_values(
            "devnet-operator-pools",
            &[json!({ "operator_id": operator_id })],
        ),
        route_summary_root: root_from_values(
            "devnet-operator-routes",
            &[json!({ "operator_id": operator_id })],
        ),
        voucher_summary_root: root_from_values(
            "devnet-operator-vouchers",
            &[json!({ "operator_id": operator_id })],
        ),
        throttle_summary_root: root_from_values(
            "devnet-operator-throttles",
            &[json!({ "operator_id": operator_id })],
        ),
        rebate_summary_root: root_from_values(
            "devnet-operator-rebates",
            &[json!({ "operator_id": operator_id })],
        ),
        summary_commitment: commitment("devnet-operator-summary", operator_id, &[]),
        routes_served,
        routes_settled: routes_served,
        vouchers_issued,
        throttles_triggered: 1,
        rebates_distributed_micro_units,
        average_fee_bps,
        summarized_at_l2_height: DEVNET_L2_HEIGHT + 12,
    }
}
