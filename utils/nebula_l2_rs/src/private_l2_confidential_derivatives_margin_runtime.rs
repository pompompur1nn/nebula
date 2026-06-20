use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2ConfidentialDerivativesMarginRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-derivatives-margin-runtime-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PQ_AUTH_SCHEME: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-derivatives-margin-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_ACCOUNT_SCHEME: &str =
    "monero-private-l2-confidential-margin-account-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_ORDER_SCHEME: &str =
    "monero-private-l2-confidential-derivatives-order-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_RISK_SCHEME: &str =
    "monero-private-l2-confidential-margin-risk-attestation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_BATCH_SCHEME: &str =
    "monero-private-l2-confidential-perp-margin-batch-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_LIQUIDATION_SCHEME: &str =
    "monero-private-l2-confidential-margin-liquidation-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_RECEIPT_SCHEME: &str =
    "roots-only-confidential-derivatives-settlement-receipt-v1";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEVNET_HEIGHT: u64 = 212_000;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_LOW_FEE_LANE: &str =
    "devnet-private-l2-derivatives-margin-low-fee";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID: &str =
    "asset:wxmr";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_QUOTE_ASSET_ID: &str =
    "asset:private-dusd";
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_ACCOUNTS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_OPEN_ORDERS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS: usize =
    1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_BATCH_ORDERS: usize =
    8_192;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_LIQUIDATIONS: usize =
    262_144;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    4_096;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 20;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_RATE_BPS: u64 =
    1_200;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS: u64 =
    1_500;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS: u64 =
    750;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_LIQUIDATION_PENALTY_BPS: u64 =
    500;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 =
    12;
pub const PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeMarketKind {
    PerpetualFuture,
    DatedFuture,
    PrivateOption,
    SyntheticSpot,
    FundingOnly,
}

impl DerivativeMarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerpetualFuture => "perpetual_future",
            Self::DatedFuture => "dated_future",
            Self::PrivateOption => "private_option",
            Self::SyntheticSpot => "synthetic_spot",
            Self::FundingOnly => "funding_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginMode {
    Isolated,
    Cross,
    Portfolio,
}

impl MarginMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Isolated => "isolated",
            Self::Cross => "cross",
            Self::Portfolio => "portfolio",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Open,
    ReduceOnly,
    LiquidationOnly,
    Suspended,
    Closed,
}

impl AccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ReduceOnly => "reduce_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::ReduceOnly)
    }

    pub fn accepts_liquidation(self) -> bool {
        matches!(self, Self::Open | Self::ReduceOnly | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    Long,
    Short,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Long => "long",
            Self::Short => "short",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Open,
    Increase,
    Reduce,
    Close,
    FundingUpdate,
    CollateralRebalance,
}

impl OrderKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Increase => "increase",
            Self::Reduce => "reduce",
            Self::Close => "close",
            Self::FundingUpdate => "funding_update",
            Self::CollateralRebalance => "collateral_rebalance",
        }
    }

    pub fn can_run_on_reduce_only_account(self) -> bool {
        matches!(
            self,
            Self::Reduce | Self::Close | Self::FundingUpdate | Self::CollateralRebalance
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Pending,
    RiskAttested,
    Batched,
    Settled,
    Rejected,
    Expired,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RiskAttested => "risk_attested",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending | Self::RiskAttested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    Liquidatable,
    Rejected,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::Rejected => "rejected",
        }
    }

    pub fn allows_batching(self) -> bool {
        matches!(self, Self::Healthy | Self::Watch | Self::ReduceOnly)
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(self, Self::Liquidatable | Self::ReduceOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarginBatchStatus {
    Open,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl MarginBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Pending,
    SettlementReady,
    Settled,
    Disputed,
    Rejected,
}

impl LiquidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptKind {
    MarginBatchSettled,
    LiquidationSettled,
    FundingSettled,
}

impl SettlementReceiptKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarginBatchSettled => "margin_batch_settled",
            Self::LiquidationSettled => "liquidation_settled",
            Self::FundingSettled => "funding_settled",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub low_fee_lane: String,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub hash_suite: String,
    pub pq_authorization_scheme: String,
    pub account_scheme: String,
    pub order_scheme: String,
    pub risk_scheme: String,
    pub batch_scheme: String,
    pub liquidation_scheme: String,
    pub receipt_scheme: String,
    pub max_accounts: usize,
    pub max_open_orders: usize,
    pub max_risk_attestations: usize,
    pub max_batch_orders: usize,
    pub max_liquidations: usize,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_funding_rate_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub liquidation_penalty_bps: u64,
    pub settlement_ttl_blocks: u64,
    pub require_low_fee_sponsor: bool,
    pub require_oracle_bound: bool,
    pub require_roots_only_public_state: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_L2_NETWORK
                .to_string(),
            low_fee_lane: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_LOW_FEE_LANE
                .to_string(),
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_COLLATERAL_ASSET_ID
                    .to_string(),
            quote_asset_id:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_QUOTE_ASSET_ID
                    .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_HASH_SUITE.to_string(),
            pq_authorization_scheme:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PQ_AUTH_SCHEME.to_string(),
            account_scheme: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_ACCOUNT_SCHEME
                .to_string(),
            order_scheme: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_ORDER_SCHEME
                .to_string(),
            risk_scheme: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_RISK_SCHEME.to_string(),
            batch_scheme: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_BATCH_SCHEME
                .to_string(),
            liquidation_scheme:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_LIQUIDATION_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            max_accounts: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_ACCOUNTS,
            max_open_orders:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_OPEN_ORDERS,
            max_risk_attestations:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_RISK_ATTESTATIONS,
            max_batch_orders:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_BATCH_ORDERS,
            max_liquidations:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_LIQUIDATIONS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_funding_rate_bps:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAX_FUNDING_RATE_BPS,
            initial_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_MAINTENANCE_MARGIN_BPS,
            liquidation_penalty_bps:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_LIQUIDATION_PENALTY_BPS,
            settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            require_low_fee_sponsor: true,
            require_oracle_bound: true,
            require_roots_only_public_state: true,
        }
    }

    pub fn validate(&self) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        if self.max_accounts == 0
            || self.max_open_orders == 0
            || self.max_risk_attestations == 0
            || self.max_batch_orders == 0
            || self.max_liquidations == 0
        {
            return Err("confidential derivatives capacities must be positive".to_string());
        }
        if self.max_batch_orders > self.max_open_orders {
            return Err("confidential derivatives batch size exceeds order capacity".to_string());
        }
        if self.min_privacy_set_size == 0
            || self.min_batch_privacy_set_size < self.min_privacy_set_size
        {
            return Err("confidential derivatives privacy set policy is invalid".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("confidential derivatives PQ security floor is too low".to_string());
        }
        if self.max_user_fee_bps > PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_MAX_BPS {
            return Err("confidential derivatives fee cap exceeds BPS range".to_string());
        }
        if self.max_funding_rate_bps > PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_MAX_BPS {
            return Err("confidential derivatives funding cap exceeds BPS range".to_string());
        }
        if self.maintenance_margin_bps == 0
            || self.initial_margin_bps < self.maintenance_margin_bps
            || self.initial_margin_bps > PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_MAX_BPS
        {
            return Err("confidential derivatives margin policy is invalid".to_string());
        }
        if self.liquidation_penalty_bps > self.maintenance_margin_bps {
            return Err(
                "confidential derivatives liquidation penalty exceeds maintenance margin"
                    .to_string(),
            );
        }
        if self.settlement_ttl_blocks == 0 {
            return Err("confidential derivatives settlement TTL must be positive".to_string());
        }
        required("chain_id", &self.chain_id)?;
        required("monero_network", &self.monero_network)?;
        required("l2_network", &self.l2_network)?;
        required("low_fee_lane", &self.low_fee_lane)?;
        required("collateral_asset_id", &self.collateral_asset_id)?;
        required("quote_asset_id", &self.quote_asset_id)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "low_fee_lane": self.low_fee_lane,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "hash_suite": self.hash_suite,
            "pq_authorization_scheme": self.pq_authorization_scheme,
            "account_scheme": self.account_scheme,
            "order_scheme": self.order_scheme,
            "risk_scheme": self.risk_scheme,
            "batch_scheme": self.batch_scheme,
            "liquidation_scheme": self.liquidation_scheme,
            "receipt_scheme": self.receipt_scheme,
            "max_accounts": self.max_accounts,
            "max_open_orders": self.max_open_orders,
            "max_risk_attestations": self.max_risk_attestations,
            "max_batch_orders": self.max_batch_orders,
            "max_liquidations": self.max_liquidations,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_funding_rate_bps": self.max_funding_rate_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "liquidation_penalty_bps": self.liquidation_penalty_bps,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "require_low_fee_sponsor": self.require_low_fee_sponsor,
            "require_oracle_bound": self.require_oracle_bound,
            "require_roots_only_public_state": self.require_roots_only_public_state,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub margin_account_counter: u64,
    pub position_order_counter: u64,
    pub risk_attestation_counter: u64,
    pub margin_batch_counter: u64,
    pub settlement_receipt_counter: u64,
    pub liquidation_counter: u64,
    pub consumed_nullifier_counter: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "margin_account_counter": self.margin_account_counter,
            "position_order_counter": self.position_order_counter,
            "risk_attestation_counter": self.risk_attestation_counter,
            "margin_batch_counter": self.margin_batch_counter,
            "settlement_receipt_counter": self.settlement_receipt_counter,
            "liquidation_counter": self.liquidation_counter,
            "consumed_nullifier_counter": self.consumed_nullifier_counter,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenMarginAccountRequest {
    pub account_owner_commitment: String,
    pub market_kind: DerivativeMarketKind,
    pub margin_mode: MarginMode,
    pub collateral_note_root: String,
    pub collateral_lock_root: String,
    pub account_policy_root: String,
    pub leverage_limit_root: String,
    pub oracle_set_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
}

impl OpenMarginAccountRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        required("account_owner_commitment", &self.account_owner_commitment)?;
        required("collateral_note_root", &self.collateral_note_root)?;
        required("collateral_lock_root", &self.collateral_lock_root)?;
        required("account_policy_root", &self.account_policy_root)?;
        required("leverage_limit_root", &self.leverage_limit_root)?;
        required("oracle_set_root", &self.oracle_set_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("nullifier", &self.nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        if config.require_oracle_bound {
            required("oracle_set_root", &self.oracle_set_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("margin account open fee exceeds configured cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_owner_commitment": self.account_owner_commitment,
            "market_kind": self.market_kind.as_str(),
            "margin_mode": self.margin_mode.as_str(),
            "collateral_note_root": self.collateral_note_root,
            "collateral_lock_root": self.collateral_lock_root,
            "account_policy_root": self.account_policy_root,
            "leverage_limit_root": self.leverage_limit_root,
            "oracle_set_root": self.oracle_set_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostPositionOrderRequest {
    pub margin_account_id: String,
    pub market_kind: DerivativeMarketKind,
    pub side: PositionSide,
    pub order_kind: OrderKind,
    pub account_commitment: String,
    pub position_note_root: String,
    pub collateral_delta_root: String,
    pub notional_commitment_root: String,
    pub price_limit_root: String,
    pub funding_index_root: String,
    pub oracle_price_root: String,
    pub risk_read_root: String,
    pub state_write_hint_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub posted_at_height: u64,
}

impl PostPositionOrderRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        required("margin_account_id", &self.margin_account_id)?;
        required("account_commitment", &self.account_commitment)?;
        required("position_note_root", &self.position_note_root)?;
        required("collateral_delta_root", &self.collateral_delta_root)?;
        required("notional_commitment_root", &self.notional_commitment_root)?;
        required("price_limit_root", &self.price_limit_root)?;
        required("funding_index_root", &self.funding_index_root)?;
        required("risk_read_root", &self.risk_read_root)?;
        required("state_write_hint_root", &self.state_write_hint_root)?;
        required("pq_authorization_root", &self.pq_authorization_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("replay_fence_root", &self.replay_fence_root)?;
        required("nullifier", &self.nullifier)?;
        if config.require_oracle_bound {
            required("oracle_price_root", &self.oracle_price_root)?;
        }
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("position order fee exceeds configured cap".to_string());
        }
        if self.expires_at_height <= self.posted_at_height {
            return Err("position order expiry must be after posted height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "margin_account_id": self.margin_account_id,
            "market_kind": self.market_kind.as_str(),
            "side": self.side.as_str(),
            "order_kind": self.order_kind.as_str(),
            "account_commitment": self.account_commitment,
            "position_note_root": self.position_note_root,
            "collateral_delta_root": self.collateral_delta_root,
            "notional_commitment_root": self.notional_commitment_root,
            "price_limit_root": self.price_limit_root,
            "funding_index_root": self.funding_index_root,
            "oracle_price_root": self.oracle_price_root,
            "risk_read_root": self.risk_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestRiskRequest {
    pub position_order_id: String,
    pub margin_account_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub margin_health_bps: u64,
    pub initial_margin_requirement_bps: u64,
    pub maintenance_margin_requirement_bps: u64,
    pub funding_rate_bps: u64,
    pub oracle_price_root: String,
    pub risk_model_root: String,
    pub account_state_root_before: String,
    pub account_state_root_after: String,
    pub liquidation_hint_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub attestation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl AttestRiskRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        required("position_order_id", &self.position_order_id)?;
        required("margin_account_id", &self.margin_account_id)?;
        required("attestor_commitment", &self.attestor_commitment)?;
        required("oracle_price_root", &self.oracle_price_root)?;
        required("risk_model_root", &self.risk_model_root)?;
        required("account_state_root_before", &self.account_state_root_before)?;
        required("account_state_root_after", &self.account_state_root_after)?;
        required("pq_attestation_root", &self.pq_attestation_root)?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("attestation_nullifier", &self.attestation_nullifier)?;
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.initial_margin_requirement_bps < self.maintenance_margin_requirement_bps {
            return Err("risk attestation initial margin is below maintenance margin".to_string());
        }
        if self.maintenance_margin_requirement_bps < config.maintenance_margin_bps {
            return Err("risk attestation maintenance margin below runtime floor".to_string());
        }
        if self.funding_rate_bps > config.max_funding_rate_bps {
            return Err("risk attestation funding rate exceeds cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "position_order_id": self.position_order_id,
            "margin_account_id": self.margin_account_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "margin_health_bps": self.margin_health_bps,
            "initial_margin_requirement_bps": self.initial_margin_requirement_bps,
            "maintenance_margin_requirement_bps": self.maintenance_margin_requirement_bps,
            "funding_rate_bps": self.funding_rate_bps,
            "oracle_price_root": self.oracle_price_root,
            "risk_model_root": self.risk_model_root,
            "account_state_root_before": self.account_state_root_before,
            "account_state_root_after": self.account_state_root_after,
            "liquidation_hint_root": self.liquidation_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "attestation_nullifier": self.attestation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildMarginBatchRequest {
    pub order_ids: Vec<String>,
    pub batch_builder_commitment: String,
    pub matching_engine_root: String,
    pub netting_root: String,
    pub account_delta_root: String,
    pub funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_proof_root: String,
    pub batch_nullifier: String,
    pub min_batch_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub built_at_height: u64,
}

impl BuildMarginBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        if self.order_ids.is_empty() {
            return Err("margin batch must include at least one order".to_string());
        }
        if self.order_ids.len() > config.max_batch_orders {
            return Err("margin batch exceeds configured order capacity".to_string());
        }
        required("batch_builder_commitment", &self.batch_builder_commitment)?;
        required("matching_engine_root", &self.matching_engine_root)?;
        required("netting_root", &self.netting_root)?;
        required("account_delta_root", &self.account_delta_root)?;
        required("funding_delta_root", &self.funding_delta_root)?;
        required("oracle_snapshot_root", &self.oracle_snapshot_root)?;
        required(
            "recursive_batch_proof_root",
            &self.recursive_batch_proof_root,
        )?;
        required(
            "pq_batch_authorization_root",
            &self.pq_batch_authorization_root,
        )?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("batch_nullifier", &self.batch_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.min_batch_privacy_set_size,
            self.pq_security_bits,
            config.min_batch_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("margin batch fee exceeds configured cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "order_ids": self.order_ids,
            "batch_builder_commitment": self.batch_builder_commitment,
            "matching_engine_root": self.matching_engine_root,
            "netting_root": self.netting_root,
            "account_delta_root": self.account_delta_root,
            "funding_delta_root": self.funding_delta_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "batch_nullifier": self.batch_nullifier,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "built_at_height": self.built_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettleMarginBatchRequest {
    pub margin_batch_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_order_root: String,
    pub rejected_order_root: String,
    pub account_delta_root: String,
    pub output_note_root: String,
    pub funding_payment_root: String,
    pub fee_receipt_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleMarginBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        required("margin_batch_id", &self.margin_batch_id)?;
        required("settlement_tx_root", &self.settlement_tx_root)?;
        required("settlement_proof_root", &self.settlement_proof_root)?;
        required("included_order_root", &self.included_order_root)?;
        required("rejected_order_root", &self.rejected_order_root)?;
        required("account_delta_root", &self.account_delta_root)?;
        required("output_note_root", &self.output_note_root)?;
        required("funding_payment_root", &self.funding_payment_root)?;
        required("fee_receipt_root", &self.fee_receipt_root)?;
        required("pq_settlement_root", &self.pq_settlement_root)?;
        required("state_root_after", &self.state_root_after)?;
        if config.require_low_fee_sponsor {
            required(
                "low_fee_sponsor_receipt_root",
                &self.low_fee_sponsor_receipt_root,
            )?;
        }
        if self.settled_fee_bps > config.max_user_fee_bps {
            return Err("margin batch settlement fee exceeds configured cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "margin_batch_id": self.margin_batch_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "included_order_root": self.included_order_root,
            "rejected_order_root": self.rejected_order_root,
            "account_delta_root": self.account_delta_root,
            "output_note_root": self.output_note_root,
            "funding_payment_root": self.funding_payment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidateUnhealthyPositionRequest {
    pub margin_account_id: String,
    pub position_order_id: String,
    pub risk_attestation_id: String,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_notional_root: String,
    pub insurance_fund_delta_root: String,
    pub auction_clearing_root: String,
    pub liquidation_proof_root: String,
    pub oracle_snapshot_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_liquidation_authorization_root: String,
    pub privacy_proof_root: String,
    pub liquidation_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub liquidated_at_height: u64,
}

impl LiquidateUnhealthyPositionRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        required("margin_account_id", &self.margin_account_id)?;
        required("position_order_id", &self.position_order_id)?;
        required("risk_attestation_id", &self.risk_attestation_id)?;
        required("liquidator_commitment", &self.liquidator_commitment)?;
        required("seized_collateral_root", &self.seized_collateral_root)?;
        required("repaid_notional_root", &self.repaid_notional_root)?;
        required("insurance_fund_delta_root", &self.insurance_fund_delta_root)?;
        required("auction_clearing_root", &self.auction_clearing_root)?;
        required("liquidation_proof_root", &self.liquidation_proof_root)?;
        required("oracle_snapshot_root", &self.oracle_snapshot_root)?;
        required(
            "pq_liquidation_authorization_root",
            &self.pq_liquidation_authorization_root,
        )?;
        required("privacy_proof_root", &self.privacy_proof_root)?;
        required("liquidation_nullifier", &self.liquidation_nullifier)?;
        if config.require_low_fee_sponsor {
            required("low_fee_sponsor_root", &self.low_fee_sponsor_root)?;
        }
        validate_privacy_and_pq(
            self.privacy_set_size,
            self.pq_security_bits,
            config.min_privacy_set_size,
            config.min_pq_security_bits,
        )?;
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("liquidation fee exceeds configured cap".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "margin_account_id": self.margin_account_id,
            "position_order_id": self.position_order_id,
            "risk_attestation_id": self.risk_attestation_id,
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_notional_root": self.repaid_notional_root,
            "insurance_fund_delta_root": self.insurance_fund_delta_root,
            "auction_clearing_root": self.auction_clearing_root,
            "liquidation_proof_root": self.liquidation_proof_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_liquidation_authorization_root": self.pq_liquidation_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "liquidation_nullifier": self.liquidation_nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "liquidated_at_height": self.liquidated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginAccount {
    pub margin_account_id: String,
    pub account_owner_commitment: String,
    pub market_kind: DerivativeMarketKind,
    pub margin_mode: MarginMode,
    pub status: AccountStatus,
    pub collateral_note_root: String,
    pub collateral_lock_root: String,
    pub account_policy_root: String,
    pub leverage_limit_root: String,
    pub oracle_set_root: String,
    pub latest_account_state_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub order_ids: Vec<String>,
    pub liquidation_ids: Vec<String>,
}

impl MarginAccount {
    pub fn public_record(&self) -> Value {
        json!({
            "margin_account_id": self.margin_account_id,
            "account_owner_commitment": self.account_owner_commitment,
            "market_kind": self.market_kind.as_str(),
            "margin_mode": self.margin_mode.as_str(),
            "status": self.status.as_str(),
            "collateral_note_root": self.collateral_note_root,
            "collateral_lock_root": self.collateral_lock_root,
            "account_policy_root": self.account_policy_root,
            "leverage_limit_root": self.leverage_limit_root,
            "oracle_set_root": self.oracle_set_root,
            "latest_account_state_root": self.latest_account_state_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "opened_at_height": self.opened_at_height,
            "order_ids": self.order_ids,
            "liquidation_ids": self.liquidation_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionOrder {
    pub position_order_id: String,
    pub margin_account_id: String,
    pub market_kind: DerivativeMarketKind,
    pub side: PositionSide,
    pub order_kind: OrderKind,
    pub status: OrderStatus,
    pub account_commitment: String,
    pub position_note_root: String,
    pub collateral_delta_root: String,
    pub notional_commitment_root: String,
    pub price_limit_root: String,
    pub funding_index_root: String,
    pub oracle_price_root: String,
    pub risk_read_root: String,
    pub state_write_hint_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
    pub posted_at_height: u64,
    pub risk_attestation_ids: Vec<String>,
}

impl PositionOrder {
    pub fn public_record(&self) -> Value {
        json!({
            "position_order_id": self.position_order_id,
            "margin_account_id": self.margin_account_id,
            "market_kind": self.market_kind.as_str(),
            "side": self.side.as_str(),
            "order_kind": self.order_kind.as_str(),
            "status": self.status.as_str(),
            "account_commitment": self.account_commitment,
            "position_note_root": self.position_note_root,
            "collateral_delta_root": self.collateral_delta_root,
            "notional_commitment_root": self.notional_commitment_root,
            "price_limit_root": self.price_limit_root,
            "funding_index_root": self.funding_index_root,
            "oracle_price_root": self.oracle_price_root,
            "risk_read_root": self.risk_read_root,
            "state_write_hint_root": self.state_write_hint_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
            "posted_at_height": self.posted_at_height,
            "risk_attestation_ids": self.risk_attestation_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAttestationRecord {
    pub risk_attestation_id: String,
    pub position_order_id: String,
    pub margin_account_id: String,
    pub attestor_commitment: String,
    pub verdict: RiskVerdict,
    pub margin_health_bps: u64,
    pub initial_margin_requirement_bps: u64,
    pub maintenance_margin_requirement_bps: u64,
    pub funding_rate_bps: u64,
    pub oracle_price_root: String,
    pub risk_model_root: String,
    pub account_state_root_before: String,
    pub account_state_root_after: String,
    pub liquidation_hint_root: String,
    pub pq_attestation_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
}

impl RiskAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_attestation_id": self.risk_attestation_id,
            "position_order_id": self.position_order_id,
            "margin_account_id": self.margin_account_id,
            "attestor_commitment": self.attestor_commitment,
            "verdict": self.verdict.as_str(),
            "margin_health_bps": self.margin_health_bps,
            "initial_margin_requirement_bps": self.initial_margin_requirement_bps,
            "maintenance_margin_requirement_bps": self.maintenance_margin_requirement_bps,
            "funding_rate_bps": self.funding_rate_bps,
            "oracle_price_root": self.oracle_price_root,
            "risk_model_root": self.risk_model_root,
            "account_state_root_before": self.account_state_root_before,
            "account_state_root_after": self.account_state_root_after,
            "liquidation_hint_root": self.liquidation_hint_root,
            "pq_attestation_root": self.pq_attestation_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginBatch {
    pub margin_batch_id: String,
    pub order_ids: Vec<String>,
    pub batch_builder_commitment: String,
    pub matching_engine_root: String,
    pub netting_root: String,
    pub account_delta_root: String,
    pub funding_delta_root: String,
    pub oracle_snapshot_root: String,
    pub recursive_batch_proof_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_batch_authorization_root: String,
    pub privacy_proof_root: String,
    pub min_batch_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: MarginBatchStatus,
    pub built_at_height: u64,
    pub settlement_deadline_height: u64,
}

impl MarginBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "margin_batch_id": self.margin_batch_id,
            "order_ids": self.order_ids,
            "batch_builder_commitment": self.batch_builder_commitment,
            "matching_engine_root": self.matching_engine_root,
            "netting_root": self.netting_root,
            "account_delta_root": self.account_delta_root,
            "funding_delta_root": self.funding_delta_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "recursive_batch_proof_root": self.recursive_batch_proof_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "settlement_deadline_height": self.settlement_deadline_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarginSettlementReceipt {
    pub settlement_receipt_id: String,
    pub receipt_kind: SettlementReceiptKind,
    pub subject_id: String,
    pub settlement_tx_root: String,
    pub settlement_proof_root: String,
    pub included_order_root: String,
    pub rejected_order_root: String,
    pub account_delta_root: String,
    pub output_note_root: String,
    pub funding_payment_root: String,
    pub fee_receipt_root: String,
    pub low_fee_sponsor_receipt_root: String,
    pub pq_settlement_root: String,
    pub state_root_after: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl MarginSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_receipt_id": self.settlement_receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "settlement_tx_root": self.settlement_tx_root,
            "settlement_proof_root": self.settlement_proof_root,
            "included_order_root": self.included_order_root,
            "rejected_order_root": self.rejected_order_root,
            "account_delta_root": self.account_delta_root,
            "output_note_root": self.output_note_root,
            "funding_payment_root": self.funding_payment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "low_fee_sponsor_receipt_root": self.low_fee_sponsor_receipt_root,
            "pq_settlement_root": self.pq_settlement_root,
            "state_root_after": self.state_root_after,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationRecord {
    pub liquidation_id: String,
    pub margin_account_id: String,
    pub position_order_id: String,
    pub risk_attestation_id: String,
    pub liquidator_commitment: String,
    pub seized_collateral_root: String,
    pub repaid_notional_root: String,
    pub insurance_fund_delta_root: String,
    pub auction_clearing_root: String,
    pub liquidation_proof_root: String,
    pub oracle_snapshot_root: String,
    pub low_fee_sponsor_root: String,
    pub pq_liquidation_authorization_root: String,
    pub privacy_proof_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub status: LiquidationStatus,
    pub liquidated_at_height: u64,
}

impl LiquidationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_id": self.liquidation_id,
            "margin_account_id": self.margin_account_id,
            "position_order_id": self.position_order_id,
            "risk_attestation_id": self.risk_attestation_id,
            "liquidator_commitment": self.liquidator_commitment,
            "seized_collateral_root": self.seized_collateral_root,
            "repaid_notional_root": self.repaid_notional_root,
            "insurance_fund_delta_root": self.insurance_fund_delta_root,
            "auction_clearing_root": self.auction_clearing_root,
            "liquidation_proof_root": self.liquidation_proof_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "low_fee_sponsor_root": self.low_fee_sponsor_root,
            "pq_liquidation_authorization_root": self.pq_liquidation_authorization_root,
            "privacy_proof_root": self.privacy_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_fee_bps": self.max_fee_bps,
            "status": self.status.as_str(),
            "liquidated_at_height": self.liquidated_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub margin_account_root: String,
    pub position_order_root: String,
    pub risk_attestation_root: String,
    pub margin_batch_root: String,
    pub settlement_receipt_root: String,
    pub liquidation_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "margin_account_root": self.margin_account_root,
            "position_order_root": self.position_order_root,
            "risk_attestation_root": self.risk_attestation_root,
            "margin_batch_root": self.margin_batch_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "liquidation_root": self.liquidation_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub margin_accounts: BTreeMap<String, MarginAccount>,
    pub position_orders: BTreeMap<String, PositionOrder>,
    pub risk_attestations: BTreeMap<String, RiskAttestationRecord>,
    pub margin_batches: BTreeMap<String, MarginBatch>,
    pub settlement_receipts: BTreeMap<String, MarginSettlementReceipt>,
    pub liquidations: BTreeMap<String, LiquidationRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            current_height: PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_DEVNET_HEIGHT,
            counters: Counters::default(),
            margin_accounts: BTreeMap::new(),
            position_orders: BTreeMap::new(),
            risk_attestations: BTreeMap::new(),
            margin_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            liquidations: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn open_margin_account(
        &mut self,
        request: OpenMarginAccountRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<MarginAccount> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.margin_accounts.len() >= self.config.max_accounts {
            return Err("confidential derivatives margin account capacity exhausted".to_string());
        }
        self.consume_nullifier(&request.nullifier)?;
        self.counters.margin_account_counter =
            self.counters.margin_account_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.opened_at_height);
        let margin_account_id = margin_account_id(&request, self.counters.margin_account_counter);
        let latest_account_state_root = payload_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-ACCOUNT-OPEN-STATE",
            &request.public_record(),
        );
        let account = MarginAccount {
            margin_account_id: margin_account_id.clone(),
            account_owner_commitment: request.account_owner_commitment,
            market_kind: request.market_kind,
            margin_mode: request.margin_mode,
            status: AccountStatus::Open,
            collateral_note_root: request.collateral_note_root,
            collateral_lock_root: request.collateral_lock_root,
            account_policy_root: request.account_policy_root,
            leverage_limit_root: request.leverage_limit_root,
            oracle_set_root: request.oracle_set_root,
            latest_account_state_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            opened_at_height: request.opened_at_height,
            order_ids: Vec::new(),
            liquidation_ids: Vec::new(),
        };
        self.margin_accounts
            .insert(margin_account_id, account.clone());
        Ok(account)
    }

    pub fn post_position_order(
        &mut self,
        request: PostPositionOrderRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<PositionOrder> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.position_orders.len() >= self.config.max_open_orders {
            return Err("confidential derivatives open order capacity exhausted".to_string());
        }
        let account = self
            .margin_accounts
            .get(&request.margin_account_id)
            .ok_or_else(|| "margin account not found".to_string())?;
        if !account.status.accepts_orders() {
            return Err("margin account does not accept orders".to_string());
        }
        if account.status == AccountStatus::ReduceOnly
            && !request.order_kind.can_run_on_reduce_only_account()
        {
            return Err("reduce-only margin account cannot increase exposure".to_string());
        }
        if account.market_kind != request.market_kind {
            return Err("position order market kind does not match account".to_string());
        }
        self.consume_nullifier(&request.nullifier)?;
        self.counters.position_order_counter =
            self.counters.position_order_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.posted_at_height);
        let position_order_id = position_order_id(&request, self.counters.position_order_counter);
        let order = PositionOrder {
            position_order_id: position_order_id.clone(),
            margin_account_id: request.margin_account_id.clone(),
            market_kind: request.market_kind,
            side: request.side,
            order_kind: request.order_kind,
            status: OrderStatus::Pending,
            account_commitment: request.account_commitment,
            position_note_root: request.position_note_root,
            collateral_delta_root: request.collateral_delta_root,
            notional_commitment_root: request.notional_commitment_root,
            price_limit_root: request.price_limit_root,
            funding_index_root: request.funding_index_root,
            oracle_price_root: request.oracle_price_root,
            risk_read_root: request.risk_read_root,
            state_write_hint_root: request.state_write_hint_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_authorization_root: request.pq_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            expires_at_height: request.expires_at_height,
            posted_at_height: request.posted_at_height,
            risk_attestation_ids: Vec::new(),
        };
        if let Some(account) = self.margin_accounts.get_mut(&request.margin_account_id) {
            account.order_ids.push(position_order_id.clone());
        }
        self.position_orders
            .insert(position_order_id, order.clone());
        Ok(order)
    }

    pub fn attest_risk(
        &mut self,
        request: AttestRiskRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<RiskAttestationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.risk_attestations.len() >= self.config.max_risk_attestations {
            return Err("confidential derivatives risk attestation capacity exhausted".to_string());
        }
        let order = self
            .position_orders
            .get(&request.position_order_id)
            .ok_or_else(|| "position order not found".to_string())?;
        if order.margin_account_id != request.margin_account_id {
            return Err("risk attestation margin account mismatch".to_string());
        }
        if !order.status.batchable() {
            return Err("position order is not risk-attestable".to_string());
        }
        if order.expires_at_height <= request.attested_at_height {
            return Err("position order expired before risk attestation".to_string());
        }
        self.consume_nullifier(&request.attestation_nullifier)?;
        self.counters.risk_attestation_counter =
            self.counters.risk_attestation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.attested_at_height);
        let risk_attestation_id =
            risk_attestation_id(&request, self.counters.risk_attestation_counter);
        if let Some(order) = self.position_orders.get_mut(&request.position_order_id) {
            order.status = if request.verdict == RiskVerdict::Rejected {
                OrderStatus::Rejected
            } else {
                OrderStatus::RiskAttested
            };
            order.risk_attestation_ids.push(risk_attestation_id.clone());
        }
        if let Some(account) = self.margin_accounts.get_mut(&request.margin_account_id) {
            account.latest_account_state_root = request.account_state_root_after.clone();
            account.status = match request.verdict {
                RiskVerdict::Healthy | RiskVerdict::Watch => AccountStatus::Open,
                RiskVerdict::ReduceOnly => AccountStatus::ReduceOnly,
                RiskVerdict::Liquidatable => AccountStatus::LiquidationOnly,
                RiskVerdict::Rejected => account.status,
            };
        }
        let attestation = RiskAttestationRecord {
            risk_attestation_id: risk_attestation_id.clone(),
            position_order_id: request.position_order_id,
            margin_account_id: request.margin_account_id,
            attestor_commitment: request.attestor_commitment,
            verdict: request.verdict,
            margin_health_bps: request.margin_health_bps,
            initial_margin_requirement_bps: request.initial_margin_requirement_bps,
            maintenance_margin_requirement_bps: request.maintenance_margin_requirement_bps,
            funding_rate_bps: request.funding_rate_bps,
            oracle_price_root: request.oracle_price_root,
            risk_model_root: request.risk_model_root,
            account_state_root_before: request.account_state_root_before,
            account_state_root_after: request.account_state_root_after,
            liquidation_hint_root: request.liquidation_hint_root,
            pq_attestation_root: request.pq_attestation_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
        };
        self.risk_attestations
            .insert(risk_attestation_id, attestation.clone());
        Ok(attestation)
    }

    pub fn build_margin_batch(
        &mut self,
        request: BuildMarginBatchRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<MarginBatch> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let mut seen = BTreeSet::new();
        for order_id in &request.order_ids {
            if !seen.insert(order_id.clone()) {
                return Err("margin batch contains duplicate order".to_string());
            }
            let order = self
                .position_orders
                .get(order_id)
                .ok_or_else(|| format!("position order {order_id} not found"))?;
            if !order.status.batchable() {
                return Err("position order is not batchable".to_string());
            }
            if order.expires_at_height <= request.built_at_height {
                return Err("position order expired before batch build".to_string());
            }
            if order.status == OrderStatus::RiskAttested {
                let latest_risk_id = order
                    .risk_attestation_ids
                    .last()
                    .ok_or_else(|| "risk-attested order missing attestation id".to_string())?;
                let latest_risk = self
                    .risk_attestations
                    .get(latest_risk_id)
                    .ok_or_else(|| "risk-attested order missing attestation record".to_string())?;
                if !latest_risk.verdict.allows_batching() {
                    return Err("latest risk verdict does not allow batching".to_string());
                }
            }
        }
        self.consume_nullifier(&request.batch_nullifier)?;
        self.counters.margin_batch_counter = self.counters.margin_batch_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.built_at_height);
        let margin_batch_id = margin_batch_id(&request, self.counters.margin_batch_counter);
        for order_id in &request.order_ids {
            if let Some(order) = self.position_orders.get_mut(order_id) {
                order.status = OrderStatus::Batched;
            }
        }
        let batch = MarginBatch {
            margin_batch_id: margin_batch_id.clone(),
            order_ids: request.order_ids,
            batch_builder_commitment: request.batch_builder_commitment,
            matching_engine_root: request.matching_engine_root,
            netting_root: request.netting_root,
            account_delta_root: request.account_delta_root,
            funding_delta_root: request.funding_delta_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            recursive_batch_proof_root: request.recursive_batch_proof_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_batch_authorization_root: request.pq_batch_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            min_batch_privacy_set_size: request.min_batch_privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: MarginBatchStatus::SettlementReady,
            built_at_height: request.built_at_height,
            settlement_deadline_height: request
                .built_at_height
                .saturating_add(self.config.settlement_ttl_blocks),
        };
        self.margin_batches.insert(margin_batch_id, batch.clone());
        Ok(batch)
    }

    pub fn settle_margin_batch(
        &mut self,
        request: SettleMarginBatchRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<MarginSettlementReceipt> {
        self.config.validate()?;
        request.validate(&self.config)?;
        let batch = self
            .margin_batches
            .get(&request.margin_batch_id)
            .ok_or_else(|| "margin batch not found".to_string())?
            .clone();
        if !batch.status.can_settle() {
            return Err("margin batch cannot settle".to_string());
        }
        if request.settled_at_height > batch.settlement_deadline_height {
            return Err("margin batch settlement deadline elapsed".to_string());
        }
        self.counters.settlement_receipt_counter =
            self.counters.settlement_receipt_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.settled_at_height);
        let settlement_receipt_id =
            margin_settlement_receipt_id(&request, self.counters.settlement_receipt_counter);
        for order_id in &batch.order_ids {
            if let Some(order) = self.position_orders.get_mut(order_id) {
                order.status = OrderStatus::Settled;
                if let Some(account) = self.margin_accounts.get_mut(&order.margin_account_id) {
                    account.latest_account_state_root = request.account_delta_root.clone();
                    if account.status == AccountStatus::ReduceOnly {
                        account.status = AccountStatus::Open;
                    }
                }
            }
        }
        if let Some(stored_batch) = self.margin_batches.get_mut(&request.margin_batch_id) {
            stored_batch.status = MarginBatchStatus::Settled;
        }
        let receipt = MarginSettlementReceipt {
            settlement_receipt_id: settlement_receipt_id.clone(),
            receipt_kind: SettlementReceiptKind::MarginBatchSettled,
            subject_id: request.margin_batch_id,
            settlement_tx_root: request.settlement_tx_root,
            settlement_proof_root: request.settlement_proof_root,
            included_order_root: request.included_order_root,
            rejected_order_root: request.rejected_order_root,
            account_delta_root: request.account_delta_root,
            output_note_root: request.output_note_root,
            funding_payment_root: request.funding_payment_root,
            fee_receipt_root: request.fee_receipt_root,
            low_fee_sponsor_receipt_root: request.low_fee_sponsor_receipt_root,
            pq_settlement_root: request.pq_settlement_root,
            state_root_after: request.state_root_after,
            settled_fee_bps: request.settled_fee_bps,
            settled_at_height: request.settled_at_height,
        };
        self.settlement_receipts
            .insert(settlement_receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn liquidate_unhealthy_position(
        &mut self,
        request: LiquidateUnhealthyPositionRequest,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<LiquidationRecord> {
        self.config.validate()?;
        request.validate(&self.config)?;
        if self.liquidations.len() >= self.config.max_liquidations {
            return Err("confidential derivatives liquidation capacity exhausted".to_string());
        }
        let account = self
            .margin_accounts
            .get(&request.margin_account_id)
            .ok_or_else(|| "margin account not found".to_string())?;
        if !account.status.accepts_liquidation() {
            return Err("margin account does not accept liquidations".to_string());
        }
        let order = self
            .position_orders
            .get(&request.position_order_id)
            .ok_or_else(|| "position order not found".to_string())?;
        if order.margin_account_id != request.margin_account_id {
            return Err("liquidation order/account mismatch".to_string());
        }
        let risk = self
            .risk_attestations
            .get(&request.risk_attestation_id)
            .ok_or_else(|| "risk attestation not found".to_string())?;
        if risk.position_order_id != request.position_order_id {
            return Err("liquidation risk/order mismatch".to_string());
        }
        if !risk.verdict.allows_liquidation() {
            return Err("risk verdict does not allow liquidation".to_string());
        }
        self.consume_nullifier(&request.liquidation_nullifier)?;
        self.counters.liquidation_counter = self.counters.liquidation_counter.saturating_add(1);
        self.current_height = self.current_height.max(request.liquidated_at_height);
        let liquidation_id = liquidation_id(&request, self.counters.liquidation_counter);
        if let Some(account) = self.margin_accounts.get_mut(&request.margin_account_id) {
            account.status = AccountStatus::LiquidationOnly;
            account.latest_account_state_root = request.seized_collateral_root.clone();
            account.liquidation_ids.push(liquidation_id.clone());
        }
        if let Some(order) = self.position_orders.get_mut(&request.position_order_id) {
            order.status = OrderStatus::Settled;
        }
        let liquidation = LiquidationRecord {
            liquidation_id: liquidation_id.clone(),
            margin_account_id: request.margin_account_id,
            position_order_id: request.position_order_id,
            risk_attestation_id: request.risk_attestation_id,
            liquidator_commitment: request.liquidator_commitment,
            seized_collateral_root: request.seized_collateral_root,
            repaid_notional_root: request.repaid_notional_root,
            insurance_fund_delta_root: request.insurance_fund_delta_root,
            auction_clearing_root: request.auction_clearing_root,
            liquidation_proof_root: request.liquidation_proof_root,
            oracle_snapshot_root: request.oracle_snapshot_root,
            low_fee_sponsor_root: request.low_fee_sponsor_root,
            pq_liquidation_authorization_root: request.pq_liquidation_authorization_root,
            privacy_proof_root: request.privacy_proof_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_fee_bps: request.max_fee_bps,
            status: LiquidationStatus::SettlementReady,
            liquidated_at_height: request.liquidated_at_height,
        };
        self.liquidations
            .insert(liquidation_id, liquidation.clone());
        Ok(liquidation)
    }

    pub fn roots(&self) -> Roots {
        let margin_account_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-ACCOUNTS",
            &self
                .margin_accounts
                .values()
                .map(MarginAccount::public_record)
                .collect::<Vec<_>>(),
        );
        let position_order_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-POSITION-ORDERS",
            &self
                .position_orders
                .values()
                .map(PositionOrder::public_record)
                .collect::<Vec<_>>(),
        );
        let risk_attestation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-RISK-ATTESTATIONS",
            &self
                .risk_attestations
                .values()
                .map(RiskAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let margin_batch_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-BATCHES",
            &self
                .margin_batches
                .values()
                .map(MarginBatch::public_record)
                .collect::<Vec<_>>(),
        );
        let settlement_receipt_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-SETTLEMENT-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(MarginSettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidation_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-LIQUIDATIONS",
            &self
                .liquidations
                .values()
                .map(LiquidationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!(nullifier))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-STATE",
            &json!({
                "chain_id": self.config.chain_id,
                "protocol_version": self.config.protocol_version,
                "current_height": self.current_height,
                "margin_account_root": margin_account_root,
                "position_order_root": position_order_root,
                "risk_attestation_root": risk_attestation_root,
                "margin_batch_root": margin_batch_root,
                "settlement_receipt_root": settlement_receipt_root,
                "liquidation_root": liquidation_root,
                "nullifier_root": nullifier_root,
                "counters": self.counters.public_record(),
            }),
        );
        Roots {
            margin_account_root,
            position_order_root,
            risk_attestation_root,
            margin_batch_root,
            settlement_receipt_root,
            liquidation_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.config.chain_id,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "margin_account_ids": self.margin_accounts.keys().cloned().collect::<Vec<_>>(),
            "position_order_ids": self.position_orders.keys().cloned().collect::<Vec<_>>(),
            "risk_attestation_ids": self.risk_attestations.keys().cloned().collect::<Vec<_>>(),
            "margin_batch_ids": self.margin_batches.keys().cloned().collect::<Vec<_>>(),
            "settlement_receipt_ids": self.settlement_receipts.keys().cloned().collect::<Vec<_>>(),
            "liquidation_ids": self.liquidations.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn consume_nullifier(
        &mut self,
        nullifier: &str,
    ) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
        let nullifier_hash = payload_id(
            "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-NULLIFIER-ID",
            &[HashPart::Str(nullifier)],
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("confidential derivatives nullifier replay detected".to_string());
        }
        self.counters.consumed_nullifier_counter =
            self.counters.consumed_nullifier_counter.saturating_add(1);
        Ok(())
    }
}

pub fn margin_account_id(request: &OpenMarginAccountRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-ACCOUNT-ID",
        &json!({
            "counter": counter,
            "account_owner_commitment": request.account_owner_commitment,
            "market_kind": request.market_kind.as_str(),
            "margin_mode": request.margin_mode.as_str(),
            "collateral_note_root": request.collateral_note_root,
            "collateral_lock_root": request.collateral_lock_root,
            "nullifier": request.nullifier,
            "opened_at_height": request.opened_at_height,
        }),
    )
}

pub fn position_order_id(request: &PostPositionOrderRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-POSITION-ORDER-ID",
        &json!({
            "counter": counter,
            "margin_account_id": request.margin_account_id,
            "market_kind": request.market_kind.as_str(),
            "side": request.side.as_str(),
            "order_kind": request.order_kind.as_str(),
            "position_note_root": request.position_note_root,
            "notional_commitment_root": request.notional_commitment_root,
            "nullifier": request.nullifier,
            "posted_at_height": request.posted_at_height,
        }),
    )
}

pub fn risk_attestation_id(request: &AttestRiskRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-RISK-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "position_order_id": request.position_order_id,
            "margin_account_id": request.margin_account_id,
            "attestor_commitment": request.attestor_commitment,
            "verdict": request.verdict.as_str(),
            "margin_health_bps": request.margin_health_bps,
            "oracle_price_root": request.oracle_price_root,
            "risk_model_root": request.risk_model_root,
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        }),
    )
}

pub fn margin_batch_id(request: &BuildMarginBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-BATCH-ID",
        &json!({
            "counter": counter,
            "order_ids": request.order_ids,
            "batch_builder_commitment": request.batch_builder_commitment,
            "matching_engine_root": request.matching_engine_root,
            "netting_root": request.netting_root,
            "recursive_batch_proof_root": request.recursive_batch_proof_root,
            "batch_nullifier": request.batch_nullifier,
            "built_at_height": request.built_at_height,
        }),
    )
}

pub fn margin_settlement_receipt_id(request: &SettleMarginBatchRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-MARGIN-SETTLEMENT-RECEIPT-ID",
        &json!({
            "counter": counter,
            "margin_batch_id": request.margin_batch_id,
            "settlement_tx_root": request.settlement_tx_root,
            "settlement_proof_root": request.settlement_proof_root,
            "state_root_after": request.state_root_after,
            "settled_at_height": request.settled_at_height,
        }),
    )
}

pub fn liquidation_id(request: &LiquidateUnhealthyPositionRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-CONFIDENTIAL-DERIVATIVES-LIQUIDATION-ID",
        &json!({
            "counter": counter,
            "margin_account_id": request.margin_account_id,
            "position_order_id": request.position_order_id,
            "risk_attestation_id": request.risk_attestation_id,
            "liquidator_commitment": request.liquidator_commitment,
            "seized_collateral_root": request.seized_collateral_root,
            "liquidation_nullifier": request.liquidation_nullifier,
            "liquidated_at_height": request.liquidated_at_height,
        }),
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn payload_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!(
            "{}:{}:{}",
            PRIVATE_L2_CONFIDENTIAL_DERIVATIVES_MARGIN_RUNTIME_PROTOCOL_VERSION, CHAIN_ID, domain
        ),
        parts,
        32,
    )
}

fn required(field: &str, value: &str) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "confidential derivatives field {field} is required"
        ));
    }
    Ok(())
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    min_privacy_set_size: u64,
    min_pq_security_bits: u16,
) -> PrivateL2ConfidentialDerivativesMarginRuntimeResult<()> {
    if privacy_set_size < min_privacy_set_size {
        return Err("confidential derivatives privacy set below minimum".to_string());
    }
    if pq_security_bits < min_pq_security_bits {
        return Err("confidential derivatives PQ security bits below minimum".to_string());
    }
    Ok(())
}
