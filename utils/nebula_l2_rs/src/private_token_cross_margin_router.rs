use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenCrossMarginRouterResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-private-token-cross-margin-router-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_COLLATERAL_COMMITMENT_SCHEME: &str =
    "shake256-shielded-token-collateral-bucket-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_ACCOUNT_COMMITMENT_SCHEME: &str =
    "shake256-private-cross-margin-account-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_ROUTE_COMMITMENT_SCHEME: &str =
    "zk-private-defi-route-intent-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PQ_ORACLE_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-oracle-route-attestation-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_REBALANCE_LANE_SCHEME: &str =
    "low-fee-shielded-cross-margin-rebalance-lane-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_RISK_CAP_SCHEME: &str =
    "bucketed-private-defi-risk-cap-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-private-token-cross-margin-settlement-receipt-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-private-token-cross-margin-router-public-record-v1";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_HEIGHT: u64 = 384;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_COLLATERAL_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_GOVERNANCE_ASSET_ID: &str = "dnero-devnet";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_ORACLE_FEED_ID: &str =
    "feed-private-token-cross-margin-devnet";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_LOW_FEE_LANE: &str =
    "devnet-private-token-cross-margin-low-fee";
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PRICE_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_INDEX_SCALE: u64 = 1_000_000_000_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 36;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_BUCKET_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 24;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_880;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_800;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_150;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_LIQUIDATION_PENALTY_BPS: u64 = 650;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_REBATE_BPS: u64 = 7_500;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 35;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_CORRELATION_BPS: u64 = 5_500;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_VENUE_SHARE_BPS: u64 = 4_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_SMALL_REBALANCE_NOTIONAL_UNITS: u64 =
    25_000_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_SPONSORED_FEE_UNITS: u64 = 6_000;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ACCOUNTS: usize = 262_144;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_BUCKETS: usize = 524_288;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ROUTES: usize = 1_048_576;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_REBALANCE_LANES: usize = 65_536;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_RISK_CAPS: usize = 262_144;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginVenueKind {
    Lending,
    Perpetual,
    EuropeanOption,
    AmericanOption,
    Amm,
    Vault,
    StableSwap,
    Insurance,
    SmartContract,
    Custom(String),
}

impl MarginVenueKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Lending => "lending".to_string(),
            Self::Perpetual => "perpetual".to_string(),
            Self::EuropeanOption => "european_option".to_string(),
            Self::AmericanOption => "american_option".to_string(),
            Self::Amm => "amm".to_string(),
            Self::Vault => "vault".to_string(),
            Self::StableSwap => "stable_swap".to_string(),
            Self::Insurance => "insurance".to_string(),
            Self::SmartContract => "smart_contract".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn consumes_margin(&self) -> bool {
        !matches!(self, Self::Insurance | Self::Vault)
    }

    pub fn derivatives_weight_bps(&self) -> u64 {
        match self {
            Self::Perpetual => 11_000,
            Self::EuropeanOption | Self::AmericanOption => 12_500,
            Self::Lending => 9_000,
            Self::Amm | Self::StableSwap => 7_500,
            Self::Vault => 6_500,
            Self::Insurance => 4_000,
            Self::SmartContract => 10_000,
            Self::Custom(_) => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossMarginAccountStatus {
    Pending,
    Active,
    RebalanceOnly,
    MarginCall,
    LiquidationGuarded,
    Frozen,
    Settling,
    Closed,
}

impl CrossMarginAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::RebalanceOnly => "rebalance_only",
            Self::MarginCall => "margin_call",
            Self::LiquidationGuarded => "liquidation_guarded",
            Self::Frozen => "frozen",
            Self::Settling => "settling",
            Self::Closed => "closed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Active
                | Self::RebalanceOnly
                | Self::MarginCall
                | Self::LiquidationGuarded
                | Self::Frozen
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollateralBucketStatus {
    Draft,
    Open,
    RebalanceLocked,
    OracleLocked,
    LiquidationLocked,
    Settling,
    Settled,
    Frozen,
    Expired,
}

impl CollateralBucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::RebalanceLocked => "rebalance_locked",
            Self::OracleLocked => "oracle_locked",
            Self::LiquidationLocked => "liquidation_locked",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Frozen => "frozen",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_routes(self) -> bool {
        matches!(self, Self::Open | Self::RebalanceLocked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntentStatus {
    Pending,
    OraclePending,
    Attested,
    Queued,
    Rebalancing,
    Executed,
    Settled,
    Cancelled,
    Expired,
    Rejected,
}

impl RouteIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::OraclePending => "oracle_pending",
            Self::Attested => "attested",
            Self::Queued => "queued",
            Self::Rebalancing => "rebalancing",
            Self::Executed => "executed",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::OraclePending | Self::Attested | Self::Queued | Self::Rebalancing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSide {
    AddCollateral,
    RemoveCollateral,
    Borrow,
    Repay,
    Long,
    Short,
    BuyOption,
    SellOption,
    SwapExactIn,
    SwapExactOut,
    Hedge,
    Settle,
}

impl RouteSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AddCollateral => "add_collateral",
            Self::RemoveCollateral => "remove_collateral",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::Long => "long",
            Self::Short => "short",
            Self::BuyOption => "buy_option",
            Self::SellOption => "sell_option",
            Self::SwapExactIn => "swap_exact_in",
            Self::SwapExactOut => "swap_exact_out",
            Self::Hedge => "hedge",
            Self::Settle => "settle",
        }
    }

    pub fn increases_risk(self) -> bool {
        matches!(
            self,
            Self::RemoveCollateral
                | Self::Borrow
                | Self::Long
                | Self::Short
                | Self::SellOption
                | Self::SwapExactOut
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Draft,
    Posted,
    QuorumReached,
    Challenged,
    Finalized,
    Expired,
    Revoked,
}

impl OracleAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Posted => "posted",
            Self::QuorumReached => "quorum_reached",
            Self::Challenged => "challenged",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::QuorumReached | Self::Finalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceLaneStatus {
    Draft,
    Active,
    Congested,
    Paused,
    Draining,
    Retired,
}

impl RebalanceLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Congested => "congested",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Active | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCapStatus {
    Draft,
    Active,
    Tightened,
    Breached,
    Grace,
    Paused,
    Retired,
}

impl RiskCapStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Tightened => "tightened",
            Self::Breached => "breached",
            Self::Grace => "grace",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn enforceable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Tightened | Self::Breached | Self::Grace
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Pending,
    Posted,
    Proved,
    Finalized,
    Disputed,
    Reversed,
    Expired,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Posted => "posted",
            Self::Proved => "proved",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenCrossMarginRouterConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub collateral_commitment_scheme: String,
    pub account_commitment_scheme: String,
    pub route_commitment_scheme: String,
    pub pq_oracle_attestation_scheme: String,
    pub rebalance_lane_scheme: String,
    pub risk_cap_scheme: String,
    pub settlement_receipt_scheme: String,
    pub public_record_scheme: String,
    pub price_scale: u64,
    pub index_scale: u64,
    pub epoch_blocks: u64,
    pub route_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebalance_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub rebalance_rebate_bps: u64,
    pub max_route_fee_bps: u64,
    pub max_correlation_bps: u64,
    pub max_venue_share_bps: u64,
    pub small_rebalance_notional_units: u64,
    pub max_sponsored_fee_units: u64,
    pub default_low_fee_lane: String,
    pub supported_venue_kinds: BTreeSet<MarginVenueKind>,
}

impl PrivateTokenCrossMarginRouterConfig {
    pub fn devnet() -> Self {
        let mut supported_venue_kinds = BTreeSet::new();
        supported_venue_kinds.insert(MarginVenueKind::Lending);
        supported_venue_kinds.insert(MarginVenueKind::Perpetual);
        supported_venue_kinds.insert(MarginVenueKind::EuropeanOption);
        supported_venue_kinds.insert(MarginVenueKind::AmericanOption);
        supported_venue_kinds.insert(MarginVenueKind::Amm);
        supported_venue_kinds.insert(MarginVenueKind::StableSwap);
        supported_venue_kinds.insert(MarginVenueKind::SmartContract);

        Self {
            protocol_version: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_HASH_SUITE.to_string(),
            collateral_commitment_scheme:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_COLLATERAL_COMMITMENT_SCHEME.to_string(),
            account_commitment_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_ACCOUNT_COMMITMENT_SCHEME
                .to_string(),
            route_commitment_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_ROUTE_COMMITMENT_SCHEME
                .to_string(),
            pq_oracle_attestation_scheme:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PQ_ORACLE_ATTESTATION_SCHEME.to_string(),
            rebalance_lane_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_REBALANCE_LANE_SCHEME
                .to_string(),
            risk_cap_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_RISK_CAP_SCHEME.to_string(),
            settlement_receipt_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_SETTLEMENT_RECEIPT_SCHEME
                .to_string(),
            public_record_scheme: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PUBLIC_RECORD_SCHEME
                .to_string(),
            price_scale: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PRICE_SCALE,
            index_scale: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_INDEX_SCALE,
            epoch_blocks: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_EPOCH_BLOCKS,
            route_ttl_blocks: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            bucket_ttl_blocks: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_BUCKET_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebalance_ttl_blocks: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_RECEIPT_TTL_BLOCKS,
            min_pq_security_bits: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            initial_margin_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_LIQUIDATION_PENALTY_BPS,
            rebalance_rebate_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_REBATE_BPS,
            max_route_fee_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_ROUTE_FEE_BPS,
            max_correlation_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_CORRELATION_BPS,
            max_venue_share_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_VENUE_SHARE_BPS,
            small_rebalance_notional_units:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_SMALL_REBALANCE_NOTIONAL_UNITS,
            max_sponsored_fee_units:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_SPONSORED_FEE_UNITS,
            default_low_fee_lane: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_LOW_FEE_LANE.to_string(),
            supported_venue_kinds,
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<()> {
        non_empty("protocol_version", &self.protocol_version)?;
        validate_positive("schema_version", self.schema_version)?;
        non_empty("chain_id", &self.chain_id)?;
        non_empty("hash_suite", &self.hash_suite)?;
        non_empty(
            "collateral_commitment_scheme",
            &self.collateral_commitment_scheme,
        )?;
        non_empty("account_commitment_scheme", &self.account_commitment_scheme)?;
        non_empty("route_commitment_scheme", &self.route_commitment_scheme)?;
        non_empty(
            "pq_oracle_attestation_scheme",
            &self.pq_oracle_attestation_scheme,
        )?;
        non_empty("rebalance_lane_scheme", &self.rebalance_lane_scheme)?;
        non_empty("risk_cap_scheme", &self.risk_cap_scheme)?;
        non_empty("settlement_receipt_scheme", &self.settlement_receipt_scheme)?;
        non_empty("public_record_scheme", &self.public_record_scheme)?;
        validate_positive("price_scale", self.price_scale)?;
        validate_positive("index_scale", self.index_scale)?;
        validate_positive("epoch_blocks", self.epoch_blocks)?;
        validate_positive("route_ttl_blocks", self.route_ttl_blocks)?;
        validate_positive("bucket_ttl_blocks", self.bucket_ttl_blocks)?;
        validate_positive("attestation_ttl_blocks", self.attestation_ttl_blocks)?;
        validate_positive("rebalance_ttl_blocks", self.rebalance_ttl_blocks)?;
        validate_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        validate_positive("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_bps("initial_margin_bps", self.initial_margin_bps)?;
        validate_bps("maintenance_margin_bps", self.maintenance_margin_bps)?;
        validate_bps("liquidation_penalty_bps", self.liquidation_penalty_bps)?;
        validate_bps("rebalance_rebate_bps", self.rebalance_rebate_bps)?;
        validate_bps("max_route_fee_bps", self.max_route_fee_bps)?;
        validate_bps("max_correlation_bps", self.max_correlation_bps)?;
        validate_bps("max_venue_share_bps", self.max_venue_share_bps)?;
        validate_positive(
            "small_rebalance_notional_units",
            self.small_rebalance_notional_units,
        )?;
        validate_positive("max_sponsored_fee_units", self.max_sponsored_fee_units)?;
        non_empty("default_low_fee_lane", &self.default_low_fee_lane)?;
        if self.initial_margin_bps <= self.maintenance_margin_bps {
            return Err("initial_margin_bps must exceed maintenance_margin_bps".to_string());
        }
        if self.supported_venue_kinds.is_empty() {
            return Err("supported_venue_kinds must not be empty".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "collateral_commitment_scheme": self.collateral_commitment_scheme,
            "account_commitment_scheme": self.account_commitment_scheme,
            "route_commitment_scheme": self.route_commitment_scheme,
            "pq_oracle_attestation_scheme": self.pq_oracle_attestation_scheme,
            "rebalance_lane_scheme": self.rebalance_lane_scheme,
            "risk_cap_scheme": self.risk_cap_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "public_record_scheme": self.public_record_scheme,
            "price_scale": self.price_scale,
            "index_scale": self.index_scale,
            "epoch_blocks": self.epoch_blocks,
            "route_ttl_blocks": self.route_ttl_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "rebalance_ttl_blocks": self.rebalance_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "rebalance_rebate_bps": self.rebalance_rebate_bps,
            "max_route_fee_bps": self.max_route_fee_bps,
            "max_correlation_bps": self.max_correlation_bps,
            "max_venue_share_bps": self.max_venue_share_bps,
            "small_rebalance_notional_units": self.small_rebalance_notional_units,
            "max_sponsored_fee_units": self.max_sponsored_fee_units,
            "default_low_fee_lane": self.default_low_fee_lane,
            "supported_venue_kinds": self.supported_venue_kinds
                .iter()
                .map(MarginVenueKind::as_str)
                .collect::<Vec<_>>(),
        })
    }

    pub fn commitment_root(&self) -> String {
        router_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossMarginAccount {
    pub account_id: String,
    pub owner_commitment: String,
    pub account_nullifier: String,
    pub status: CrossMarginAccountStatus,
    pub collateral_bucket_ids: BTreeSet<String>,
    pub active_route_ids: BTreeSet<String>,
    pub risk_cap_ids: BTreeSet<String>,
    pub encrypted_account_state: Value,
    pub balance_upper_bound_units: u64,
    pub debt_upper_bound_units: u64,
    pub exposure_upper_bound_units: u64,
    pub risk_score_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivateCrossMarginAccount {
    pub fn devnet(account_id: &str, owner_label: &str, height: u64) -> Self {
        let owner_commitment = router_id("ACCOUNT-OWNER", &[account_id, owner_label]);
        let account_nullifier = router_id("ACCOUNT-NULLIFIER", &[account_id, owner_label]);
        Self {
            account_id: account_id.to_string(),
            owner_commitment,
            account_nullifier,
            status: CrossMarginAccountStatus::Active,
            collateral_bucket_ids: BTreeSet::new(),
            active_route_ids: BTreeSet::new(),
            risk_cap_ids: BTreeSet::new(),
            encrypted_account_state: json!({
                "ciphertext": router_id("DEVNET-ACCOUNT-CIPHERTEXT", &[account_id]),
                "scheme": PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_ACCOUNT_COMMITMENT_SCHEME,
            }),
            balance_upper_bound_units: 250_000_000_000,
            debt_upper_bound_units: 85_000_000_000,
            exposure_upper_bound_units: 420_000_000_000,
            risk_score_bps: 2_750,
            min_privacy_set_size: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            opened_at_height: height,
            updated_at_height: height,
            expires_at_height: height + 21_600,
            metadata: json!({
                "label": owner_label,
                "purpose": "devnet_private_token_cross_margin",
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("account_id", &self.account_id)?;
        non_empty("owner_commitment", &self.owner_commitment)?;
        non_empty("account_nullifier", &self.account_nullifier)?;
        validate_public_payload("encrypted_account_state", &self.encrypted_account_state)?;
        validate_positive("balance_upper_bound_units", self.balance_upper_bound_units)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_bps("risk_score_bps", self.risk_score_bps)?;
        validate_window(self.opened_at_height, self.expires_at_height, "account")?;
        if self.updated_at_height < self.opened_at_height {
            return Err("updated_at_height must not be before opened_at_height".to_string());
        }
        if self.debt_upper_bound_units
            > self.balance_upper_bound_units + self.exposure_upper_bound_units
        {
            return Err("debt_upper_bound_units exceeds covered upper bounds".to_string());
        }
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.commitment_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "account_nullifier": self.account_nullifier,
            "status": self.status.as_str(),
            "collateral_bucket_ids": self.collateral_bucket_ids.iter().cloned().collect::<Vec<_>>(),
            "active_route_ids": self.active_route_ids.iter().cloned().collect::<Vec<_>>(),
            "risk_cap_ids": self.risk_cap_ids.iter().cloned().collect::<Vec<_>>(),
            "encrypted_account_state": self.encrypted_account_state,
            "balance_upper_bound_units": self.balance_upper_bound_units,
            "debt_upper_bound_units": self.debt_upper_bound_units,
            "exposure_upper_bound_units": self.exposure_upper_bound_units,
            "risk_score_bps": self.risk_score_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment_root(&self) -> String {
        router_payload_root("ACCOUNT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedCollateralBucket {
    pub bucket_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub status: CollateralBucketStatus,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub encrypted_balance: Value,
    pub value_upper_bound_units: u64,
    pub borrow_power_bps: u64,
    pub haircut_bps: u64,
    pub concentration_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl ShieldedCollateralBucket {
    pub fn devnet(bucket_id: &str, account_id: &str, asset_id: &str, height: u64) -> Self {
        Self {
            bucket_id: bucket_id.to_string(),
            account_id: account_id.to_string(),
            asset_id: asset_id.to_string(),
            status: CollateralBucketStatus::Open,
            commitment_root: router_id("COLLATERAL-COMMITMENT", &[bucket_id, asset_id]),
            nullifier_root: router_id("COLLATERAL-NULLIFIER", &[bucket_id, account_id]),
            encrypted_balance: json!({
                "ciphertext": router_id("DEVNET-BUCKET-BALANCE", &[bucket_id, asset_id]),
                "asset_id": asset_id,
            }),
            value_upper_bound_units: 150_000_000_000,
            borrow_power_bps: 7_500,
            haircut_bps: 800,
            concentration_bps: 2_500,
            min_privacy_set_size: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            opened_at_height: height,
            expires_at_height: height + PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_BUCKET_TTL_BLOCKS,
            metadata: json!({
                "shielded_bucket": true,
                "bucket_class": "cross_margin_collateral",
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("bucket_id", &self.bucket_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("asset_id", &self.asset_id)?;
        non_empty("commitment_root", &self.commitment_root)?;
        non_empty("nullifier_root", &self.nullifier_root)?;
        validate_public_payload("encrypted_balance", &self.encrypted_balance)?;
        validate_positive("value_upper_bound_units", self.value_upper_bound_units)?;
        validate_bps("borrow_power_bps", self.borrow_power_bps)?;
        validate_bps("haircut_bps", self.haircut_bps)?;
        validate_bps("concentration_bps", self.concentration_bps)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        validate_window(
            self.opened_at_height,
            self.expires_at_height,
            "collateral bucket",
        )?;
        if self.borrow_power_bps + self.haircut_bps > PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_BPS {
            return Err("borrow_power_bps plus haircut_bps exceeds max bps".to_string());
        }
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.bucket_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "encrypted_balance": self.encrypted_balance,
            "value_upper_bound_units": self.value_upper_bound_units,
            "borrow_power_bps": self.borrow_power_bps,
            "haircut_bps": self.haircut_bps,
            "concentration_bps": self.concentration_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn bucket_root(&self) -> String {
        router_payload_root("COLLATERAL-BUCKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiRouteIntent {
    pub route_id: String,
    pub account_id: String,
    pub source_bucket_id: String,
    pub target_bucket_id: Option<String>,
    pub venue_id: String,
    pub venue_kind: MarginVenueKind,
    pub side: RouteSide,
    pub status: RouteIntentStatus,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub notional_upper_bound_units: u64,
    pub max_fee_bps: u64,
    pub max_slippage_bps: u64,
    pub risk_weight_bps: u64,
    pub route_privacy_set_size: u64,
    pub low_fee_lane_id: Option<String>,
    pub pq_oracle_attestation_id: Option<String>,
    pub encrypted_route_payload: Value,
    pub constraint_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivateDefiRouteIntent {
    pub fn devnet(
        route_id: &str,
        account_id: &str,
        source_bucket_id: &str,
        venue_id: &str,
        venue_kind: MarginVenueKind,
        side: RouteSide,
        height: u64,
    ) -> Self {
        Self {
            route_id: route_id.to_string(),
            account_id: account_id.to_string(),
            source_bucket_id: source_bucket_id.to_string(),
            target_bucket_id: None,
            venue_id: venue_id.to_string(),
            venue_kind,
            side,
            status: RouteIntentStatus::Attested,
            input_asset_id: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_COLLATERAL_ASSET_ID
                .to_string(),
            output_asset_id: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_STABLE_ASSET_ID.to_string(),
            notional_upper_bound_units: 20_000_000_000,
            max_fee_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_ROUTE_FEE_BPS,
            max_slippage_bps: 80,
            risk_weight_bps: 9_500,
            route_privacy_set_size: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE
                + 64,
            low_fee_lane_id: Some(
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_LOW_FEE_LANE.to_string(),
            ),
            pq_oracle_attestation_id: Some("devnet-pq-oracle-attestation-0".to_string()),
            encrypted_route_payload: json!({
                "ciphertext": router_id("DEVNET-ROUTE-PAYLOAD", &[route_id, venue_id]),
                "side": side.as_str(),
            }),
            constraint_commitment: router_id("ROUTE-CONSTRAINT", &[route_id, account_id]),
            created_at_height: height,
            expires_at_height: height + PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            metadata: json!({
                "route_class": "cross_margin_private_defi",
                "venue_id": venue_id,
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("route_id", &self.route_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("source_bucket_id", &self.source_bucket_id)?;
        non_empty("venue_id", &self.venue_id)?;
        non_empty("input_asset_id", &self.input_asset_id)?;
        non_empty("output_asset_id", &self.output_asset_id)?;
        validate_positive(
            "notional_upper_bound_units",
            self.notional_upper_bound_units,
        )?;
        validate_bps("max_fee_bps", self.max_fee_bps)?;
        validate_bps("max_slippage_bps", self.max_slippage_bps)?;
        validate_bps_floor("risk_weight_bps", self.risk_weight_bps)?;
        validate_positive("route_privacy_set_size", self.route_privacy_set_size)?;
        validate_public_payload("encrypted_route_payload", &self.encrypted_route_payload)?;
        non_empty("constraint_commitment", &self.constraint_commitment)?;
        validate_window(
            self.created_at_height,
            self.expires_at_height,
            "route intent",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.route_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "account_id": self.account_id,
            "source_bucket_id": self.source_bucket_id,
            "target_bucket_id": self.target_bucket_id,
            "venue_id": self.venue_id,
            "venue_kind": self.venue_kind.as_str(),
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "notional_upper_bound_units": self.notional_upper_bound_units,
            "max_fee_bps": self.max_fee_bps,
            "max_slippage_bps": self.max_slippage_bps,
            "risk_weight_bps": self.risk_weight_bps,
            "route_privacy_set_size": self.route_privacy_set_size,
            "low_fee_lane_id": self.low_fee_lane_id,
            "pq_oracle_attestation_id": self.pq_oracle_attestation_id,
            "encrypted_route_payload": self.encrypted_route_payload,
            "constraint_commitment": self.constraint_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn route_root(&self) -> String {
        router_payload_root("ROUTE-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub feed_id: String,
    pub committee_id: String,
    pub route_ids: BTreeSet<String>,
    pub status: OracleAttestationStatus,
    pub price_root: String,
    pub volatility_root: String,
    pub liquidity_root: String,
    pub correlation_root: String,
    pub signature_root: String,
    pub threshold: u64,
    pub signer_count: u64,
    pub min_pq_security_bits: u16,
    pub confidence_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PqOracleAttestation {
    pub fn devnet(attestation_id: &str, route_id: &str, height: u64) -> Self {
        let mut route_ids = BTreeSet::new();
        route_ids.insert(route_id.to_string());
        Self {
            attestation_id: attestation_id.to_string(),
            feed_id: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_ORACLE_FEED_ID.to_string(),
            committee_id: "devnet-pq-oracle-committee".to_string(),
            route_ids,
            status: OracleAttestationStatus::QuorumReached,
            price_root: router_id("ORACLE-PRICE", &[attestation_id]),
            volatility_root: router_id("ORACLE-VOL", &[attestation_id]),
            liquidity_root: router_id("ORACLE-LIQUIDITY", &[attestation_id]),
            correlation_root: router_id("ORACLE-CORRELATION", &[attestation_id]),
            signature_root: router_id("ORACLE-PQ-SIGNATURE", &[attestation_id]),
            threshold: 5,
            signer_count: 7,
            min_pq_security_bits: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PQ_SECURITY_BITS,
            confidence_bps: 9_850,
            observed_at_height: height,
            expires_at_height: height
                + PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_ATTESTATION_TTL_BLOCKS,
            metadata: json!({
                "scheme": PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PQ_ORACLE_ATTESTATION_SCHEME,
                "oracle_mesh": "devnet",
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("attestation_id", &self.attestation_id)?;
        non_empty("feed_id", &self.feed_id)?;
        non_empty("committee_id", &self.committee_id)?;
        if self.route_ids.is_empty() {
            return Err("route_ids must not be empty".to_string());
        }
        non_empty("price_root", &self.price_root)?;
        non_empty("volatility_root", &self.volatility_root)?;
        non_empty("liquidity_root", &self.liquidity_root)?;
        non_empty("correlation_root", &self.correlation_root)?;
        non_empty("signature_root", &self.signature_root)?;
        validate_positive("threshold", self.threshold)?;
        validate_positive("signer_count", self.signer_count)?;
        if self.signer_count < self.threshold {
            return Err("signer_count must be at least threshold".to_string());
        }
        validate_positive("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        validate_bps("confidence_bps", self.confidence_bps)?;
        validate_window(
            self.observed_at_height,
            self.expires_at_height,
            "pq oracle attestation",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.attestation_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "feed_id": self.feed_id,
            "committee_id": self.committee_id,
            "route_ids": self.route_ids.iter().cloned().collect::<Vec<_>>(),
            "status": self.status.as_str(),
            "price_root": self.price_root,
            "volatility_root": self.volatility_root,
            "liquidity_root": self.liquidity_root,
            "correlation_root": self.correlation_root,
            "signature_root": self.signature_root,
            "threshold": self.threshold,
            "signer_count": self.signer_count,
            "min_pq_security_bits": self.min_pq_security_bits,
            "confidence_bps": self.confidence_bps,
            "observed_at_height": self.observed_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn attestation_root(&self) -> String {
        router_payload_root("PQ-ORACLE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRebalanceLane {
    pub lane_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub status: RebalanceLaneStatus,
    pub accepted_venue_kinds: BTreeSet<MarginVenueKind>,
    pub max_notional_units: u64,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub pending_route_count: u64,
    pub lane_commitment_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl LowFeeRebalanceLane {
    pub fn devnet(lane_id: &str, height: u64) -> Self {
        let mut accepted_venue_kinds = BTreeSet::new();
        accepted_venue_kinds.insert(MarginVenueKind::Lending);
        accepted_venue_kinds.insert(MarginVenueKind::Perpetual);
        accepted_venue_kinds.insert(MarginVenueKind::Amm);
        accepted_venue_kinds.insert(MarginVenueKind::StableSwap);
        Self {
            lane_id: lane_id.to_string(),
            sponsor_commitment: router_id("REBALANCE-SPONSOR", &[lane_id]),
            fee_asset_id: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            status: RebalanceLaneStatus::Active,
            accepted_venue_kinds,
            max_notional_units:
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_SMALL_REBALANCE_NOTIONAL_UNITS,
            max_fee_units: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_SPONSORED_FEE_UNITS,
            rebate_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_REBATE_BPS,
            min_privacy_set_size: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            pending_route_count: 0,
            lane_commitment_root: router_id("REBALANCE-LANE", &[lane_id]),
            opened_at_height: height,
            expires_at_height: height
                + PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_REBALANCE_TTL_BLOCKS,
            metadata: json!({
                "lane_class": "low_fee_private_rebalance",
                "sponsored": true,
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("lane_id", &self.lane_id)?;
        non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        non_empty("fee_asset_id", &self.fee_asset_id)?;
        if self.accepted_venue_kinds.is_empty() {
            return Err("accepted_venue_kinds must not be empty".to_string());
        }
        validate_positive("max_notional_units", self.max_notional_units)?;
        validate_positive("max_fee_units", self.max_fee_units)?;
        validate_bps("rebate_bps", self.rebate_bps)?;
        validate_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        non_empty("lane_commitment_root", &self.lane_commitment_root)?;
        validate_window(
            self.opened_at_height,
            self.expires_at_height,
            "rebalance lane",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.lane_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "status": self.status.as_str(),
            "accepted_venue_kinds": self.accepted_venue_kinds
                .iter()
                .map(MarginVenueKind::as_str)
                .collect::<Vec<_>>(),
            "max_notional_units": self.max_notional_units,
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pending_route_count": self.pending_route_count,
            "lane_commitment_root": self.lane_commitment_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn lane_root(&self) -> String {
        router_payload_root("LOW-FEE-REBALANCE-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateRiskCap {
    pub cap_id: String,
    pub account_id: Option<String>,
    pub asset_id: Option<String>,
    pub venue_id: Option<String>,
    pub venue_kind: Option<MarginVenueKind>,
    pub status: RiskCapStatus,
    pub max_debt_units: u64,
    pub max_exposure_units: u64,
    pub max_delta_bps: u64,
    pub max_gamma_bps: u64,
    pub max_venue_share_bps: u64,
    pub max_correlation_bps: u64,
    pub min_health_bps: u64,
    pub privacy_budget_units: u64,
    pub cap_commitment_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivateRiskCap {
    pub fn devnet(
        cap_id: &str,
        account_id: Option<&str>,
        venue_id: Option<&str>,
        height: u64,
    ) -> Self {
        Self {
            cap_id: cap_id.to_string(),
            account_id: account_id.map(str::to_string),
            asset_id: Some(
                PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_COLLATERAL_ASSET_ID.to_string(),
            ),
            venue_id: venue_id.map(str::to_string),
            venue_kind: Some(MarginVenueKind::Perpetual),
            status: RiskCapStatus::Active,
            max_debt_units: 90_000_000_000,
            max_exposure_units: 350_000_000_000,
            max_delta_bps: 6_000,
            max_gamma_bps: 2_000,
            max_venue_share_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_VENUE_SHARE_BPS,
            max_correlation_bps: PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_MAX_CORRELATION_BPS,
            min_health_bps: 12_500,
            privacy_budget_units: 1_000_000,
            cap_commitment_root: router_id("RISK-CAP", &[cap_id]),
            opened_at_height: height,
            expires_at_height: height + 21_600,
            metadata: json!({
                "risk_model": "private_cross_margin_var_bucketed",
                "enforced": true,
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("cap_id", &self.cap_id)?;
        validate_positive("max_debt_units", self.max_debt_units)?;
        validate_positive("max_exposure_units", self.max_exposure_units)?;
        validate_bps("max_delta_bps", self.max_delta_bps)?;
        validate_bps("max_gamma_bps", self.max_gamma_bps)?;
        validate_bps("max_venue_share_bps", self.max_venue_share_bps)?;
        validate_bps("max_correlation_bps", self.max_correlation_bps)?;
        validate_bps_floor("min_health_bps", self.min_health_bps)?;
        validate_positive("privacy_budget_units", self.privacy_budget_units)?;
        non_empty("cap_commitment_root", &self.cap_commitment_root)?;
        validate_window(self.opened_at_height, self.expires_at_height, "risk cap")?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.cap_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "venue_id": self.venue_id,
            "venue_kind": self.venue_kind.as_ref().map(MarginVenueKind::as_str),
            "status": self.status.as_str(),
            "max_debt_units": self.max_debt_units,
            "max_exposure_units": self.max_exposure_units,
            "max_delta_bps": self.max_delta_bps,
            "max_gamma_bps": self.max_gamma_bps,
            "max_venue_share_bps": self.max_venue_share_bps,
            "max_correlation_bps": self.max_correlation_bps,
            "min_health_bps": self.min_health_bps,
            "privacy_budget_units": self.privacy_budget_units,
            "cap_commitment_root": self.cap_commitment_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn cap_root(&self) -> String {
        router_payload_root("RISK-CAP", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSettlementReceipt {
    pub receipt_id: String,
    pub route_id: String,
    pub account_id: String,
    pub source_bucket_id: String,
    pub target_bucket_id: Option<String>,
    pub status: SettlementReceiptStatus,
    pub settlement_root: String,
    pub fee_receipt_root: String,
    pub proof_root: String,
    pub oracle_attestation_id: Option<String>,
    pub low_fee_lane_id: Option<String>,
    pub settled_notional_units: u64,
    pub charged_fee_units: u64,
    pub rebate_units: u64,
    pub health_after_bps: u64,
    pub privacy_set_size: u64,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: Value,
}

impl PrivateSettlementReceipt {
    pub fn devnet(receipt_id: &str, route: &PrivateDefiRouteIntent, height: u64) -> Self {
        Self {
            receipt_id: receipt_id.to_string(),
            route_id: route.route_id.clone(),
            account_id: route.account_id.clone(),
            source_bucket_id: route.source_bucket_id.clone(),
            target_bucket_id: route.target_bucket_id.clone(),
            status: SettlementReceiptStatus::Proved,
            settlement_root: router_id("SETTLEMENT", &[receipt_id, &route.route_id]),
            fee_receipt_root: router_id("SETTLEMENT-FEE", &[receipt_id]),
            proof_root: router_id("SETTLEMENT-PROOF", &[receipt_id]),
            oracle_attestation_id: route.pq_oracle_attestation_id.clone(),
            low_fee_lane_id: route.low_fee_lane_id.clone(),
            settled_notional_units: route.notional_upper_bound_units / 2,
            charged_fee_units: 2_500,
            rebate_units: 1_875,
            health_after_bps: 18_500,
            privacy_set_size: route.route_privacy_set_size + 16,
            emitted_at_height: height,
            expires_at_height: height
                + PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEFAULT_RECEIPT_TTL_BLOCKS,
            metadata: json!({
                "receipt_scheme": PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_SETTLEMENT_RECEIPT_SCHEME,
                "finality": "devnet_proved",
            }),
        }
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("receipt_id", &self.receipt_id)?;
        non_empty("route_id", &self.route_id)?;
        non_empty("account_id", &self.account_id)?;
        non_empty("source_bucket_id", &self.source_bucket_id)?;
        non_empty("settlement_root", &self.settlement_root)?;
        non_empty("fee_receipt_root", &self.fee_receipt_root)?;
        non_empty("proof_root", &self.proof_root)?;
        validate_positive("settled_notional_units", self.settled_notional_units)?;
        validate_bps_floor("health_after_bps", self.health_after_bps)?;
        validate_positive("privacy_set_size", self.privacy_set_size)?;
        validate_window(
            self.emitted_at_height,
            self.expires_at_height,
            "settlement receipt",
        )?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.receipt_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "route_id": self.route_id,
            "account_id": self.account_id,
            "source_bucket_id": self.source_bucket_id,
            "target_bucket_id": self.target_bucket_id,
            "status": self.status.as_str(),
            "settlement_root": self.settlement_root,
            "fee_receipt_root": self.fee_receipt_root,
            "proof_root": self.proof_root,
            "oracle_attestation_id": self.oracle_attestation_id,
            "low_fee_lane_id": self.low_fee_lane_id,
            "settled_notional_units": self.settled_notional_units,
            "charged_fee_units": self.charged_fee_units,
            "rebate_units": self.rebate_units,
            "health_after_bps": self.health_after_bps,
            "privacy_set_size": self.privacy_set_size,
            "emitted_at_height": self.emitted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn receipt_root(&self) -> String {
        router_payload_root("SETTLEMENT-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenCrossMarginPublicRecord {
    pub record_id: String,
    pub sequence: u64,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub metadata: Value,
}

impl PrivateTokenCrossMarginPublicRecord {
    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("record_id", &self.record_id)?;
        non_empty("record_kind", &self.record_kind)?;
        non_empty("subject_id", &self.subject_id)?;
        non_empty("payload_root", &self.payload_root)?;
        validate_positive("emitted_at_height", self.emitted_at_height)?;
        validate_public_payload("metadata", &self.metadata)?;
        Ok(self.record_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_cross_margin_public_record",
            "public_record_scheme": PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_PUBLIC_RECORD_SCHEME,
            "record_id": self.record_id,
            "sequence": self.sequence,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn record_root(&self) -> String {
        router_payload_root("PUBLIC-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenCrossMarginRouterRoots {
    pub config_root: String,
    pub account_root: String,
    pub collateral_bucket_root: String,
    pub route_intent_root: String,
    pub pq_oracle_attestation_root: String,
    pub low_fee_rebalance_lane_root: String,
    pub risk_cap_root: String,
    pub settlement_receipt_root: String,
    pub public_record_root: String,
}

impl PrivateTokenCrossMarginRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "account_root": self.account_root,
            "collateral_bucket_root": self.collateral_bucket_root,
            "route_intent_root": self.route_intent_root,
            "pq_oracle_attestation_root": self.pq_oracle_attestation_root,
            "low_fee_rebalance_lane_root": self.low_fee_rebalance_lane_root,
            "risk_cap_root": self.risk_cap_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        private_token_cross_margin_router_state_root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenCrossMarginRouterCounters {
    pub account_count: u64,
    pub collateral_bucket_count: u64,
    pub route_intent_count: u64,
    pub active_route_count: u64,
    pub pq_oracle_attestation_count: u64,
    pub low_fee_rebalance_lane_count: u64,
    pub risk_cap_count: u64,
    pub settlement_receipt_count: u64,
    pub public_record_count: u64,
}

impl PrivateTokenCrossMarginRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "account_count": self.account_count,
            "collateral_bucket_count": self.collateral_bucket_count,
            "route_intent_count": self.route_intent_count,
            "active_route_count": self.active_route_count,
            "pq_oracle_attestation_count": self.pq_oracle_attestation_count,
            "low_fee_rebalance_lane_count": self.low_fee_rebalance_lane_count,
            "risk_cap_count": self.risk_cap_count,
            "settlement_receipt_count": self.settlement_receipt_count,
            "public_record_count": self.public_record_count,
        })
    }

    pub fn counters_root(&self) -> String {
        router_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenCrossMarginRouterState {
    pub config: PrivateTokenCrossMarginRouterConfig,
    pub height: u64,
    pub accounts: BTreeMap<String, PrivateCrossMarginAccount>,
    pub collateral_buckets: BTreeMap<String, ShieldedCollateralBucket>,
    pub route_intents: BTreeMap<String, PrivateDefiRouteIntent>,
    pub pq_oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub low_fee_rebalance_lanes: BTreeMap<String, LowFeeRebalanceLane>,
    pub risk_caps: BTreeMap<String, PrivateRiskCap>,
    pub settlement_receipts: BTreeMap<String, PrivateSettlementReceipt>,
    pub public_records: BTreeMap<String, PrivateTokenCrossMarginPublicRecord>,
}

impl PrivateTokenCrossMarginRouterState {
    pub fn new(
        config: PrivateTokenCrossMarginRouterConfig,
    ) -> PrivateTokenCrossMarginRouterResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height: 1,
            accounts: BTreeMap::new(),
            collateral_buckets: BTreeMap::new(),
            route_intents: BTreeMap::new(),
            pq_oracle_attestations: BTreeMap::new(),
            low_fee_rebalance_lanes: BTreeMap::new(),
            risk_caps: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> PrivateTokenCrossMarginRouterResult<Self> {
        let mut state = Self::new(PrivateTokenCrossMarginRouterConfig::devnet())?;
        state.set_height(PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_HEIGHT)?;

        let account = PrivateCrossMarginAccount::devnet(
            "devnet-cross-margin-account-0",
            "alice",
            state.height,
        );
        state.register_account(account)?;

        let bucket = ShieldedCollateralBucket::devnet(
            "devnet-collateral-bucket-0",
            "devnet-cross-margin-account-0",
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_COLLATERAL_ASSET_ID,
            state.height,
        );
        state.register_collateral_bucket(bucket)?;

        let lane = LowFeeRebalanceLane::devnet(
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_DEVNET_LOW_FEE_LANE,
            state.height,
        );
        state.register_low_fee_rebalance_lane(lane)?;

        let cap = PrivateRiskCap::devnet(
            "devnet-risk-cap-0",
            Some("devnet-cross-margin-account-0"),
            Some("devnet-perp-venue-0"),
            state.height,
        );
        state.register_risk_cap(cap)?;

        let route = PrivateDefiRouteIntent::devnet(
            "devnet-route-intent-0",
            "devnet-cross-margin-account-0",
            "devnet-collateral-bucket-0",
            "devnet-perp-venue-0",
            MarginVenueKind::Perpetual,
            RouteSide::Hedge,
            state.height,
        );
        state.register_route_intent(route.clone())?;

        let attestation = PqOracleAttestation::devnet(
            "devnet-pq-oracle-attestation-0",
            &route.route_id,
            state.height,
        );
        state.register_pq_oracle_attestation(attestation)?;

        let receipt = PrivateSettlementReceipt::devnet(
            "devnet-settlement-receipt-0",
            &route,
            state.height + 1,
        );
        state.register_settlement_receipt(receipt)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateTokenCrossMarginRouterResult<()> {
        validate_positive("height", height)?;
        if height < self.height {
            return Err("height must not decrease".to_string());
        }
        self.height = height;
        Ok(())
    }

    pub fn register_account(
        &mut self,
        mut account: PrivateCrossMarginAccount,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = account.validate()?;
        if self.accounts.contains_key(&account.account_id) {
            return Err(format!("account {} already exists", account.account_id));
        }
        account.updated_at_height = self.height;
        let account_id = account.account_id.clone();
        self.add_public_record("account", &account_id, &root, account.public_record())?;
        self.accounts.insert(account_id, account);
        Ok(root)
    }

    pub fn register_collateral_bucket(
        &mut self,
        bucket: ShieldedCollateralBucket,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = bucket.validate()?;
        if self.collateral_buckets.contains_key(&bucket.bucket_id) {
            return Err(format!(
                "collateral bucket {} already exists",
                bucket.bucket_id
            ));
        }
        if !self.accounts.contains_key(&bucket.account_id) {
            return Err(format!("account {} missing for bucket", bucket.account_id));
        }
        let bucket_id = bucket.bucket_id.clone();
        let account_id = bucket.account_id.clone();
        self.add_public_record(
            "collateral_bucket",
            &bucket_id,
            &root,
            bucket.public_record(),
        )?;
        self.collateral_buckets.insert(bucket_id.clone(), bucket);
        if let Some(account) = self.accounts.get_mut(&account_id) {
            account.collateral_bucket_ids.insert(bucket_id);
            account.updated_at_height = self.height;
        }
        Ok(root)
    }

    pub fn register_route_intent(
        &mut self,
        route: PrivateDefiRouteIntent,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = route.validate()?;
        if self.route_intents.contains_key(&route.route_id) {
            return Err(format!("route {} already exists", route.route_id));
        }
        self.validate_route_links(&route)?;
        let route_id = route.route_id.clone();
        let account_id = route.account_id.clone();
        if route.status.active() {
            if let Some(account) = self.accounts.get_mut(&account_id) {
                account.active_route_ids.insert(route_id.clone());
                account.updated_at_height = self.height;
            }
            if let Some(lane_id) = &route.low_fee_lane_id {
                if let Some(lane) = self.low_fee_rebalance_lanes.get_mut(lane_id) {
                    lane.pending_route_count = lane.pending_route_count.saturating_add(1);
                }
            }
        }
        self.add_public_record("route_intent", &route_id, &root, route.public_record())?;
        self.route_intents.insert(route_id, route);
        Ok(root)
    }

    pub fn register_pq_oracle_attestation(
        &mut self,
        attestation: PqOracleAttestation,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = attestation.validate()?;
        if self
            .pq_oracle_attestations
            .contains_key(&attestation.attestation_id)
        {
            return Err(format!(
                "pq oracle attestation {} already exists",
                attestation.attestation_id
            ));
        }
        for route_id in &attestation.route_ids {
            if !self.route_intents.contains_key(route_id) {
                return Err(format!("route {} missing for oracle attestation", route_id));
            }
        }
        let attestation_id = attestation.attestation_id.clone();
        self.add_public_record(
            "pq_oracle_attestation",
            &attestation_id,
            &root,
            attestation.public_record(),
        )?;
        self.pq_oracle_attestations
            .insert(attestation_id, attestation);
        Ok(root)
    }

    pub fn register_low_fee_rebalance_lane(
        &mut self,
        lane: LowFeeRebalanceLane,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = lane.validate()?;
        if self.low_fee_rebalance_lanes.contains_key(&lane.lane_id) {
            return Err(format!("rebalance lane {} already exists", lane.lane_id));
        }
        let lane_id = lane.lane_id.clone();
        self.add_public_record(
            "low_fee_rebalance_lane",
            &lane_id,
            &root,
            lane.public_record(),
        )?;
        self.low_fee_rebalance_lanes.insert(lane_id, lane);
        Ok(root)
    }

    pub fn register_risk_cap(
        &mut self,
        cap: PrivateRiskCap,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = cap.validate()?;
        if self.risk_caps.contains_key(&cap.cap_id) {
            return Err(format!("risk cap {} already exists", cap.cap_id));
        }
        if let Some(account_id) = &cap.account_id {
            if !self.accounts.contains_key(account_id) {
                return Err(format!("account {} missing for risk cap", account_id));
            }
        }
        let cap_id = cap.cap_id.clone();
        let account_id = cap.account_id.clone();
        self.add_public_record("risk_cap", &cap_id, &root, cap.public_record())?;
        self.risk_caps.insert(cap_id.clone(), cap);
        if let Some(account_id) = account_id {
            if let Some(account) = self.accounts.get_mut(&account_id) {
                account.risk_cap_ids.insert(cap_id);
                account.updated_at_height = self.height;
            }
        }
        Ok(root)
    }

    pub fn register_settlement_receipt(
        &mut self,
        receipt: PrivateSettlementReceipt,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        let root = receipt.validate()?;
        if self.settlement_receipts.contains_key(&receipt.receipt_id) {
            return Err(format!(
                "settlement receipt {} already exists",
                receipt.receipt_id
            ));
        }
        if !self.route_intents.contains_key(&receipt.route_id) {
            return Err(format!(
                "route {} missing for settlement receipt",
                receipt.route_id
            ));
        }
        let receipt_id = receipt.receipt_id.clone();
        self.add_public_record(
            "settlement_receipt",
            &receipt_id,
            &root,
            receipt.public_record(),
        )?;
        self.settlement_receipts.insert(receipt_id, receipt);
        Ok(root)
    }

    pub fn roots(&self) -> PrivateTokenCrossMarginRouterRoots {
        PrivateTokenCrossMarginRouterRoots {
            config_root: self.config.commitment_root(),
            account_root: router_collection_root("ACCOUNTS", &map_records(&self.accounts)),
            collateral_bucket_root: router_collection_root(
                "COLLATERAL-BUCKETS",
                &map_records(&self.collateral_buckets),
            ),
            route_intent_root: router_collection_root(
                "ROUTE-INTENTS",
                &map_records(&self.route_intents),
            ),
            pq_oracle_attestation_root: router_collection_root(
                "PQ-ORACLE-ATTESTATIONS",
                &map_records(&self.pq_oracle_attestations),
            ),
            low_fee_rebalance_lane_root: router_collection_root(
                "LOW-FEE-REBALANCE-LANES",
                &map_records(&self.low_fee_rebalance_lanes),
            ),
            risk_cap_root: router_collection_root("RISK-CAPS", &map_records(&self.risk_caps)),
            settlement_receipt_root: router_collection_root(
                "SETTLEMENT-RECEIPTS",
                &map_records(&self.settlement_receipts),
            ),
            public_record_root: router_collection_root(
                "PUBLIC-RECORDS",
                &map_records(&self.public_records),
            ),
        }
    }

    pub fn counters(&self) -> PrivateTokenCrossMarginRouterCounters {
        PrivateTokenCrossMarginRouterCounters {
            account_count: self.accounts.len() as u64,
            collateral_bucket_count: self.collateral_buckets.len() as u64,
            route_intent_count: self.route_intents.len() as u64,
            active_route_count: self
                .route_intents
                .values()
                .filter(|route| route.status.active())
                .count() as u64,
            pq_oracle_attestation_count: self.pq_oracle_attestations.len() as u64,
            low_fee_rebalance_lane_count: self.low_fee_rebalance_lanes.len() as u64,
            risk_cap_count: self.risk_caps.len() as u64,
            settlement_receipt_count: self.settlement_receipts.len() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "state_root": roots.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        private_token_cross_margin_router_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateTokenCrossMarginRouterResult<String> {
        self.config.validate()?;
        validate_positive("height", self.height)?;
        self.validate_collection_limits()?;

        for account in self.accounts.values() {
            account.validate()?;
        }
        for bucket in self.collateral_buckets.values() {
            bucket.validate()?;
            if !self.accounts.contains_key(&bucket.account_id) {
                return Err(format!(
                    "bucket {} references missing account",
                    bucket.bucket_id
                ));
            }
        }
        for route in self.route_intents.values() {
            route.validate()?;
            self.validate_route_links(route)?;
        }
        for attestation in self.pq_oracle_attestations.values() {
            attestation.validate()?;
            for route_id in &attestation.route_ids {
                if !self.route_intents.contains_key(route_id) {
                    return Err(format!(
                        "attestation {} references missing route {}",
                        attestation.attestation_id, route_id
                    ));
                }
            }
        }
        for lane in self.low_fee_rebalance_lanes.values() {
            lane.validate()?;
        }
        for cap in self.risk_caps.values() {
            cap.validate()?;
            if let Some(account_id) = &cap.account_id {
                if !self.accounts.contains_key(account_id) {
                    return Err(format!(
                        "risk cap {} references missing account",
                        cap.cap_id
                    ));
                }
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.route_intents.contains_key(&receipt.route_id) {
                return Err(format!(
                    "receipt {} references missing route {}",
                    receipt.receipt_id, receipt.route_id
                ));
            }
        }
        for (record_id, record) in &self.public_records {
            if record_id != &record.record_id {
                return Err(format!("public record key mismatch for {}", record_id));
            }
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn validate_collection_limits(&self) -> PrivateTokenCrossMarginRouterResult<()> {
        validate_max_len(
            "accounts",
            self.accounts.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ACCOUNTS,
        )?;
        validate_max_len(
            "collateral_buckets",
            self.collateral_buckets.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_BUCKETS,
        )?;
        validate_max_len(
            "route_intents",
            self.route_intents.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ROUTES,
        )?;
        validate_max_len(
            "pq_oracle_attestations",
            self.pq_oracle_attestations.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_ATTESTATIONS,
        )?;
        validate_max_len(
            "low_fee_rebalance_lanes",
            self.low_fee_rebalance_lanes.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_REBALANCE_LANES,
        )?;
        validate_max_len(
            "risk_caps",
            self.risk_caps.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_RISK_CAPS,
        )?;
        validate_max_len(
            "settlement_receipts",
            self.settlement_receipts.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_RECEIPTS,
        )?;
        validate_max_len(
            "public_records",
            self.public_records.len(),
            PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_PUBLIC_RECORDS,
        )?;
        Ok(())
    }

    fn validate_route_links(
        &self,
        route: &PrivateDefiRouteIntent,
    ) -> PrivateTokenCrossMarginRouterResult<()> {
        if !self.accounts.contains_key(&route.account_id) {
            return Err(format!(
                "route {} references missing account",
                route.route_id
            ));
        }
        let source_bucket = self
            .collateral_buckets
            .get(&route.source_bucket_id)
            .ok_or_else(|| format!("route {} references missing source bucket", route.route_id))?;
        if source_bucket.account_id != route.account_id {
            return Err(format!(
                "route {} source bucket account mismatch",
                route.route_id
            ));
        }
        if let Some(target_bucket_id) = &route.target_bucket_id {
            let target_bucket = self
                .collateral_buckets
                .get(target_bucket_id)
                .ok_or_else(|| {
                    format!("route {} references missing target bucket", route.route_id)
                })?;
            if target_bucket.account_id != route.account_id {
                return Err(format!(
                    "route {} target bucket account mismatch",
                    route.route_id
                ));
            }
        }
        if let Some(lane_id) = &route.low_fee_lane_id {
            let lane = self.low_fee_rebalance_lanes.get(lane_id).ok_or_else(|| {
                format!("route {} references missing low fee lane", route.route_id)
            })?;
            if !lane.accepted_venue_kinds.contains(&route.venue_kind) {
                return Err(format!(
                    "route {} venue kind not accepted by low fee lane {}",
                    route.route_id, lane_id
                ));
            }
            if route.notional_upper_bound_units > lane.max_notional_units {
                return Err(format!(
                    "route {} exceeds low fee lane notional",
                    route.route_id
                ));
            }
        }
        if let Some(attestation_id) = &route.pq_oracle_attestation_id {
            if let Some(attestation) = self.pq_oracle_attestations.get(attestation_id) {
                if !attestation.route_ids.contains(&route.route_id) {
                    return Err(format!(
                        "route {} not covered by attestation {}",
                        route.route_id, attestation_id
                    ));
                }
            }
        }
        Ok(())
    }

    fn add_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
        payload_root: &str,
        payload: Value,
    ) -> PrivateTokenCrossMarginRouterResult<String> {
        non_empty("record_kind", record_kind)?;
        non_empty("subject_id", subject_id)?;
        non_empty("payload_root", payload_root)?;
        validate_public_payload("public record payload", &payload)?;
        let sequence = self.public_records.len() as u64;
        let record_id = router_public_record_id(record_kind, subject_id, payload_root, sequence);
        let record = PrivateTokenCrossMarginPublicRecord {
            record_id: record_id.clone(),
            sequence,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root.to_string(),
            emitted_at_height: self.height,
            metadata: json!({
                "payload": payload,
                "height": self.height,
            }),
        };
        record.validate()?;
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }
}

pub fn private_token_cross_margin_router_state_root_from_record(record: &Value) -> String {
    router_payload_root("STATE", record)
}

fn router_id(domain: &str, values: &[&str]) -> String {
    let parts = values
        .iter()
        .map(|value| HashPart::Str(value))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-TOKEN-CROSS-MARGIN-ROUTER:{domain}"),
        &parts,
        32,
    )
}

fn router_payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-TOKEN-CROSS-MARGIN-ROUTER:{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

fn router_collection_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-TOKEN-CROSS-MARGIN-ROUTER:{domain}"),
        records,
    )
}

fn router_public_record_id(
    record_kind: &str,
    subject_id: &str,
    payload_root: &str,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CROSS-MARGIN-ROUTER:PUBLIC-RECORD-ID",
        &[
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn non_empty(field: &str, value: &str) -> PrivateTokenCrossMarginRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn validate_positive(field: &str, value: u64) -> PrivateTokenCrossMarginRouterResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn validate_bps(field: &str, value: u64) -> PrivateTokenCrossMarginRouterResult<()> {
    if value > PRIVATE_TOKEN_CROSS_MARGIN_ROUTER_MAX_BPS {
        return Err(format!("{field} exceeds max basis points"));
    }
    Ok(())
}

fn validate_bps_floor(field: &str, value: u64) -> PrivateTokenCrossMarginRouterResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive bps"));
    }
    Ok(())
}

fn validate_window(start: u64, end: u64, label: &str) -> PrivateTokenCrossMarginRouterResult<()> {
    validate_positive(&format!("{label}.start"), start)?;
    if end <= start {
        return Err(format!("{label} expiry must be after start"));
    }
    Ok(())
}

fn validate_public_payload(field: &str, value: &Value) -> PrivateTokenCrossMarginRouterResult<()> {
    if value.is_null() {
        return Err(format!("{field} must not be null"));
    }
    let encoded = serde_json::to_vec(value).map_err(|err| format!("{field} is not JSON: {err}"))?;
    if encoded.len() > 16 * 1024 {
        return Err(format!("{field} exceeds 16KiB public payload limit"));
    }
    Ok(())
}

fn validate_max_len(
    field: &str,
    len: usize,
    max: usize,
) -> PrivateTokenCrossMarginRouterResult<()> {
    if len > max {
        return Err(format!("{field} exceeds max length {max}"));
    }
    Ok(())
}

trait RouterPublicRecord {
    fn as_public_record_value(&self) -> Value;
}

impl RouterPublicRecord for PrivateCrossMarginAccount {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for ShieldedCollateralBucket {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for PrivateDefiRouteIntent {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for PqOracleAttestation {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for LowFeeRebalanceLane {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for PrivateRiskCap {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for PrivateSettlementReceipt {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl RouterPublicRecord for PrivateTokenCrossMarginPublicRecord {
    fn as_public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn map_records<T: RouterPublicRecord>(values: &BTreeMap<String, T>) -> Vec<Value> {
    values
        .values()
        .map(RouterPublicRecord::as_public_record_value)
        .collect()
}
