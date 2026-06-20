use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-confidential-token-fee-derivatives-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_HEIGHT: u64 = 631_200;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_COLLATERAL_ASSET_ID: &str =
    "dusd-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PQ_RFQ_SCHEME: &str =
    "ml-kem-1024-sealed-confidential-token-fee-derivative-rfq-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PQ_QUOTE_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87-liquidity-provider-fee-derivative-quote-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_ORACLE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-token-fee-oracle-attestation-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_SETTLEMENT_SCHEME: &str =
    "zk-pq-confidential-token-fee-derivative-settlement-batch-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-confidential-token-fee-derivative-nullifier-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_RECEIPT_SCHEME: &str =
    "confidential-token-fee-derivative-receipt-rebate-root-v1";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_REPLAY_DOMAIN: &str =
    "private-l2-confidential-token-fee-derivatives-devnet";
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_RQF_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_EXPIRY_BLOCKS: u64 = 720;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 =
    36;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    32_768;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_MIN_MARGIN_BPS: u64 = 1_250;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_TARGET_MARGIN_BPS: u64 =
    2_250;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_LP_SPREAD_BPS: u64 = 18;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_OPTION_PREMIUM_BPS: u64 =
    35;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_REBATE_BPS: u64 = 8;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_INSTRUMENTS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_POSITIONS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RFQS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_QUOTES: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_SETTLEMENTS: usize = 262_144;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RESERVATIONS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_REBATES: usize = 524_288;
pub const PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_FENCES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenFeeMarket {
    ConfidentialSwap,
    PrivateAmm,
    LendingPool,
    PerpDex,
    SponsorRelay,
    MarketMakerInventory,
}

impl TokenFeeMarket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialSwap => "confidential_swap",
            Self::PrivateAmm => "private_amm",
            Self::LendingPool => "lending_pool",
            Self::PerpDex => "perp_dex",
            Self::SponsorRelay => "sponsor_relay",
            Self::MarketMakerInventory => "market_maker_inventory",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeKind {
    FeeFuture,
    FeeCallOption,
    FeePutOption,
    FeeCollar,
    VarianceSwap,
    SponsorRebateForward,
}

impl DerivativeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeFuture => "fee_future",
            Self::FeeCallOption => "fee_call_option",
            Self::FeePutOption => "fee_put_option",
            Self::FeeCollar => "fee_collar",
            Self::VarianceSwap => "variance_swap",
            Self::SponsorRebateForward => "sponsor_rebate_forward",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongFee,
    ShortFee,
    LongVolatility,
    ShortVolatility,
    SponsorRebate,
    LpInventoryHedge,
}

impl PositionSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongFee => "long_fee",
            Self::ShortFee => "short_fee",
            Self::LongVolatility => "long_volatility",
            Self::ShortVolatility => "short_volatility",
            Self::SponsorRebate => "sponsor_rebate",
            Self::LpInventoryHedge => "lp_inventory_hedge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentStatus {
    Draft,
    Listed,
    Trading,
    Halted,
    Expired,
    Settled,
    Cancelled,
}

impl InstrumentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Listed => "listed",
            Self::Trading => "trading",
            Self::Halted => "halted",
            Self::Expired => "expired",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Open,
    MarginReserved,
    PartiallySettled,
    Settled,
    Liquidating,
    Liquidated,
    Cancelled,
}

impl PositionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::MarginReserved => "margin_reserved",
            Self::PartiallySettled => "partially_settled",
            Self::Settled => "settled",
            Self::Liquidating => "liquidating",
            Self::Liquidated => "liquidated",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RfqStatus {
    Sealed,
    Routed,
    Quoted,
    Accepted,
    Expired,
    Cancelled,
}

impl RfqStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Routed => "routed",
            Self::Quoted => "quoted",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Firm,
    Accepted,
    Rejected,
    Expired,
    Revoked,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Firm => "firm",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    OracleAttested,
    SponsorReserved,
    Netting,
    Settled,
    Disputed,
    Cancelled,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::OracleAttested => "oracle_attested",
            Self::SponsorReserved => "sponsor_reserved",
            Self::Netting => "netting",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    FeeIndex,
    Volatility,
    ReserveCoverage,
    Settlement,
    RebateBudget,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeIndex => "fee_index",
            Self::Volatility => "volatility",
            Self::ReserveCoverage => "reserve_coverage",
            Self::Settlement => "settlement",
            Self::RebateBudget => "rebate_budget",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    QuoteReplay,
    RfqReplay,
    ReceiptReplay,
    SettlementReplay,
    OracleReplay,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::QuoteReplay => "quote_replay",
            Self::RfqReplay => "rfq_replay",
            Self::ReceiptReplay => "receipt_replay",
            Self::SettlementReplay => "settlement_replay",
            Self::OracleReplay => "oracle_replay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub collateral_asset_id: String,
    pub hash_suite: String,
    pub pq_rfq_scheme: String,
    pub pq_quote_scheme: String,
    pub pq_oracle_scheme: String,
    pub settlement_scheme: String,
    pub receipt_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub default_rfq_ttl_blocks: u64,
    pub default_quote_ttl_blocks: u64,
    pub default_expiry_blocks: u64,
    pub default_settlement_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_pq_security_bits: u16,
    pub min_margin_bps: u64,
    pub target_margin_bps: u64,
    pub default_lp_spread_bps: u64,
    pub default_option_premium_bps: u64,
    pub default_rebate_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            fee_asset_id: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            collateral_asset_id:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_COLLATERAL_ASSET_ID
                    .to_string(),
            hash_suite: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_HASH_SUITE.to_string(),
            pq_rfq_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PQ_RFQ_SCHEME
                .to_string(),
            pq_quote_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_PQ_QUOTE_SCHEME
                .to_string(),
            pq_oracle_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_ORACLE_SCHEME
                .to_string(),
            settlement_scheme:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_SETTLEMENT_SCHEME.to_string(),
            receipt_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            nullifier_scheme: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_REPLAY_DOMAIN
                .to_string(),
            default_rfq_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_RQF_TTL_BLOCKS,
            default_quote_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            default_expiry_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_EXPIRY_BLOCKS,
            default_settlement_ttl_blocks:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_pq_security_bits:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_MIN_MARGIN_BPS,
            target_margin_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_TARGET_MARGIN_BPS,
            default_lp_spread_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_LP_SPREAD_BPS,
            default_option_premium_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_OPTION_PREMIUM_BPS,
            default_rebate_bps:
                PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEFAULT_REBATE_BPS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "collateral_asset_id": self.collateral_asset_id,
            "hash_suite": self.hash_suite,
            "pq_rfq_scheme": self.pq_rfq_scheme,
            "pq_quote_scheme": self.pq_quote_scheme,
            "pq_oracle_scheme": self.pq_oracle_scheme,
            "settlement_scheme": self.settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "default_rfq_ttl_blocks": self.default_rfq_ttl_blocks,
            "default_quote_ttl_blocks": self.default_quote_ttl_blocks,
            "default_expiry_blocks": self.default_expiry_blocks,
            "default_settlement_ttl_blocks": self.default_settlement_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_margin_bps": self.min_margin_bps,
            "target_margin_bps": self.target_margin_bps,
            "default_lp_spread_bps": self.default_lp_spread_bps,
            "default_option_premium_bps": self.default_option_premium_bps,
            "default_rebate_bps": self.default_rebate_bps,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
        if self.chain_id != CHAIN_ID {
            return Err("config chain_id does not match runtime CHAIN_ID".to_string());
        }
        require_non_empty("monero network", &self.monero_network)?;
        require_non_empty("l2 network", &self.l2_network)?;
        require_non_empty("fee asset id", &self.fee_asset_id)?;
        require_non_empty("collateral asset id", &self.collateral_asset_id)?;
        require_positive("default rfq ttl", self.default_rfq_ttl_blocks)?;
        require_positive("default quote ttl", self.default_quote_ttl_blocks)?;
        require_positive("default expiry blocks", self.default_expiry_blocks)?;
        require_positive("default settlement ttl", self.default_settlement_ttl_blocks)?;
        require_bps("min margin bps", self.min_margin_bps)?;
        require_bps("target margin bps", self.target_margin_bps)?;
        require_bps("default lp spread bps", self.default_lp_spread_bps)?;
        require_bps(
            "default option premium bps",
            self.default_option_premium_bps,
        )?;
        require_bps("default rebate bps", self.default_rebate_bps)?;
        if self.target_margin_bps < self.min_margin_bps {
            return Err("target margin bps cannot be below min margin bps".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeDerivativeInstrument {
    pub instrument_id: String,
    pub kind: DerivativeKind,
    pub market: TokenFeeMarket,
    pub status: InstrumentStatus,
    pub fee_index_root: String,
    pub strike_fee_micro_units: u64,
    pub cap_fee_micro_units: u64,
    pub floor_fee_micro_units: u64,
    pub notional_token_amount_units: u64,
    pub contract_size_units: u64,
    pub collateral_asset_id: String,
    pub quote_asset_id: String,
    pub margin_bps: u64,
    pub premium_bps: u64,
    pub listed_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_window_start_height: u64,
    pub settlement_window_end_height: u64,
    pub privacy_set_size: u64,
    pub metadata_root: String,
}

impl FeeDerivativeInstrument {
    pub fn public_record(&self) -> Value {
        json!({
            "instrument_id": self.instrument_id,
            "kind": self.kind.as_str(),
            "market": self.market.as_str(),
            "status": self.status.as_str(),
            "fee_index_root": self.fee_index_root,
            "strike_fee_micro_units": self.strike_fee_micro_units,
            "cap_fee_micro_units": self.cap_fee_micro_units,
            "floor_fee_micro_units": self.floor_fee_micro_units,
            "notional_token_amount_units": self.notional_token_amount_units,
            "contract_size_units": self.contract_size_units,
            "collateral_asset_id": self.collateral_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "margin_bps": self.margin_bps,
            "premium_bps": self.premium_bps,
            "listed_at_height": self.listed_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_window_start_height": self.settlement_window_start_height,
            "settlement_window_end_height": self.settlement_window_end_height,
            "privacy_set_size": self.privacy_set_size,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn payload_root(&self) -> String {
        payload_root(
            "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-INSTRUMENT",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("instrument id", &self.instrument_id)?;
        require_non_empty("fee index root", &self.fee_index_root)?;
        require_non_empty("collateral asset id", &self.collateral_asset_id)?;
        require_non_empty("quote asset id", &self.quote_asset_id)?;
        require_positive("notional token amount", self.notional_token_amount_units)?;
        require_positive("contract size", self.contract_size_units)?;
        require_bps("margin bps", self.margin_bps)?;
        require_bps("premium bps", self.premium_bps)?;
        if self.expires_at_height <= self.listed_at_height {
            return Err("instrument expiry must be after listing height".to_string());
        }
        if self.settlement_window_end_height < self.settlement_window_start_height {
            return Err("instrument settlement window is inverted".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("instrument privacy set below configured minimum".to_string());
        }
        Ok(self.instrument_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HedgePosition {
    pub position_id: String,
    pub instrument_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub entry_quote_id: String,
    pub entry_fee_micro_units: u64,
    pub quantity_contracts: u64,
    pub notional_token_amount_units: u64,
    pub margin_commitment_root: String,
    pub collateral_locked_units: u64,
    pub realized_pnl_units: i128,
    pub unrealized_pnl_units: i128,
    pub rebate_reservation_id: String,
    pub opened_at_height: u64,
    pub last_mark_height: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl HedgePosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "instrument_id": self.instrument_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "entry_quote_id": self.entry_quote_id,
            "entry_fee_micro_units": self.entry_fee_micro_units,
            "quantity_contracts": self.quantity_contracts,
            "notional_token_amount_units": self.notional_token_amount_units,
            "margin_commitment_root": self.margin_commitment_root,
            "collateral_locked_units": self.collateral_locked_units,
            "realized_pnl_units": self.realized_pnl_units.to_string(),
            "unrealized_pnl_units": self.unrealized_pnl_units.to_string(),
            "rebate_reservation_id": self.rebate_reservation_id,
            "opened_at_height": self.opened_at_height,
            "last_mark_height": self.last_mark_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("position id", &self.position_id)?;
        require_non_empty("instrument id", &self.instrument_id)?;
        require_non_empty("owner commitment", &self.owner_commitment)?;
        require_non_empty("margin commitment root", &self.margin_commitment_root)?;
        require_positive("quantity contracts", self.quantity_contracts)?;
        require_positive("position notional", self.notional_token_amount_units)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("position expiry must be after open height".to_string());
        }
        Ok(self.position_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRfq {
    pub rfq_id: String,
    pub requester_commitment: String,
    pub instrument_id: String,
    pub side: PositionSide,
    pub status: RfqStatus,
    pub sealed_terms_root: String,
    pub kem_ciphertext_hash: String,
    pub response_key_commitment: String,
    pub max_fee_micro_units: u64,
    pub min_quantity_contracts: u64,
    pub max_quantity_contracts: u64,
    pub privacy_set_size: u64,
    pub route_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
}

impl EncryptedRfq {
    pub fn public_record(&self) -> Value {
        json!({
            "rfq_id": self.rfq_id,
            "requester_commitment": self.requester_commitment,
            "instrument_id": self.instrument_id,
            "side": self.side.as_str(),
            "status": self.status.as_str(),
            "sealed_terms_root": self.sealed_terms_root,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "response_key_commitment": self.response_key_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "min_quantity_contracts": self.min_quantity_contracts,
            "max_quantity_contracts": self.max_quantity_contracts,
            "privacy_set_size": self.privacy_set_size,
            "route_root": self.route_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("rfq id", &self.rfq_id)?;
        require_non_empty("requester commitment", &self.requester_commitment)?;
        require_non_empty("instrument id", &self.instrument_id)?;
        require_non_empty("sealed terms root", &self.sealed_terms_root)?;
        require_non_empty("kem ciphertext hash", &self.kem_ciphertext_hash)?;
        require_positive("rfq max quantity", self.max_quantity_contracts)?;
        if self.min_quantity_contracts > self.max_quantity_contracts {
            return Err("rfq min quantity exceeds max quantity".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("rfq expiry must be after creation height".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("rfq privacy set below configured minimum".to_string());
        }
        Ok(self.rfq_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityProviderQuote {
    pub quote_id: String,
    pub rfq_id: String,
    pub instrument_id: String,
    pub lp_commitment: String,
    pub status: QuoteStatus,
    pub bid_fee_micro_units: u64,
    pub ask_fee_micro_units: u64,
    pub quantity_contracts: u64,
    pub premium_units: u64,
    pub margin_requirement_units: u64,
    pub quote_envelope_root: String,
    pub pq_signature_root: String,
    pub inventory_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidityProviderQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "rfq_id": self.rfq_id,
            "instrument_id": self.instrument_id,
            "lp_commitment": self.lp_commitment,
            "status": self.status.as_str(),
            "bid_fee_micro_units": self.bid_fee_micro_units,
            "ask_fee_micro_units": self.ask_fee_micro_units,
            "quantity_contracts": self.quantity_contracts,
            "premium_units": self.premium_units,
            "margin_requirement_units": self.margin_requirement_units,
            "quote_envelope_root": self.quote_envelope_root,
            "pq_signature_root": self.pq_signature_root,
            "inventory_root": self.inventory_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("quote id", &self.quote_id)?;
        require_non_empty("rfq id", &self.rfq_id)?;
        require_non_empty("instrument id", &self.instrument_id)?;
        require_non_empty("lp commitment", &self.lp_commitment)?;
        require_positive("quote quantity", self.quantity_contracts)?;
        if self.ask_fee_micro_units < self.bid_fee_micro_units {
            return Err("quote ask fee cannot be below bid fee".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("quote expiry must be after creation height".to_string());
        }
        Ok(self.quote_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub kind: AttestationKind,
    pub oracle_committee_id: String,
    pub subject_id: String,
    pub subject_root: String,
    pub fee_index_micro_units: u64,
    pub realized_volatility_bps: u64,
    pub implied_volatility_bps: u64,
    pub reserve_coverage_bps: u64,
    pub observation_start_height: u64,
    pub observation_end_height: u64,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
    pub transcript_root: String,
    pub pq_signature_root: String,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "oracle_committee_id": self.oracle_committee_id,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "fee_index_micro_units": self.fee_index_micro_units,
            "realized_volatility_bps": self.realized_volatility_bps,
            "implied_volatility_bps": self.implied_volatility_bps,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "observation_start_height": self.observation_start_height,
            "observation_end_height": self.observation_end_height,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
            "transcript_root": self.transcript_root,
            "pq_signature_root": self.pq_signature_root,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("attestation id", &self.attestation_id)?;
        require_non_empty("oracle committee id", &self.oracle_committee_id)?;
        require_non_empty("subject id", &self.subject_id)?;
        require_non_empty("subject root", &self.subject_root)?;
        require_non_empty("pq signature root", &self.pq_signature_root)?;
        require_bps("reserve coverage bps", self.reserve_coverage_bps)?;
        if self.observation_end_height < self.observation_start_height {
            return Err("oracle observation window is inverted".to_string());
        }
        if self.expires_at_height <= self.signed_at_height {
            return Err("oracle attestation expiry must be after signature height".to_string());
        }
        Ok(self.attestation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub settlement_id: String,
    pub status: SettlementStatus,
    pub instrument_root: String,
    pub position_root: String,
    pub quote_root: String,
    pub oracle_attestation_root: String,
    pub sponsor_reservation_root: String,
    pub netting_root: String,
    pub payout_root: String,
    pub rebate_root: String,
    pub fee_index_micro_units: u64,
    pub mark_fee_micro_units: u64,
    pub total_notional_units: u64,
    pub total_payout_units: u64,
    pub proposed_at_height: u64,
    pub settles_at_height: u64,
    pub expires_at_height: u64,
    pub settlement_proof_root: String,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "status": self.status.as_str(),
            "instrument_root": self.instrument_root,
            "position_root": self.position_root,
            "quote_root": self.quote_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "netting_root": self.netting_root,
            "payout_root": self.payout_root,
            "rebate_root": self.rebate_root,
            "fee_index_micro_units": self.fee_index_micro_units,
            "mark_fee_micro_units": self.mark_fee_micro_units,
            "total_notional_units": self.total_notional_units,
            "total_payout_units": self.total_payout_units,
            "proposed_at_height": self.proposed_at_height,
            "settles_at_height": self.settles_at_height,
            "expires_at_height": self.expires_at_height,
            "settlement_proof_root": self.settlement_proof_root,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("settlement id", &self.settlement_id)?;
        require_non_empty("instrument root", &self.instrument_root)?;
        require_non_empty("position root", &self.position_root)?;
        require_non_empty("oracle attestation root", &self.oracle_attestation_root)?;
        if self.settles_at_height < self.proposed_at_height {
            return Err("settlement height cannot precede proposal height".to_string());
        }
        if self.expires_at_height <= self.proposed_at_height {
            return Err("settlement expiry must be after proposal height".to_string());
        }
        Ok(self.settlement_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub settlement_id: String,
    pub instrument_id: String,
    pub budget_root: String,
    pub reserved_units: u64,
    pub rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub spent_units: u64,
    pub status: SettlementStatus,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "settlement_id": self.settlement_id,
            "instrument_id": self.instrument_id,
            "budget_root": self.budget_root,
            "reserved_units": self.reserved_units,
            "rebate_bps": self.rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "spent_units": self.spent_units,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("reservation id", &self.reservation_id)?;
        require_non_empty("sponsor commitment", &self.sponsor_commitment)?;
        require_non_empty("settlement id", &self.settlement_id)?;
        require_positive("reserved units", self.reserved_units)?;
        require_bps("rebate bps", self.rebate_bps)?;
        if self.spent_units > self.reserved_units {
            return Err("sponsor reservation spent units exceed reserved units".to_string());
        }
        if self.min_privacy_set_size < config.min_privacy_set_size {
            return Err("sponsor reservation privacy set below configured minimum".to_string());
        }
        Ok(self.reservation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivativeReceipt {
    pub receipt_id: String,
    pub settlement_id: String,
    pub position_id: String,
    pub owner_commitment: String,
    pub gross_payout_units: u64,
    pub net_payout_units: u64,
    pub fee_paid_units: u64,
    pub rebate_id: String,
    pub payout_commitment_root: String,
    pub nullifier_root: String,
    pub issued_at_height: u64,
    pub receipt_proof_root: String,
}

impl DerivativeReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_id": self.settlement_id,
            "position_id": self.position_id,
            "owner_commitment": self.owner_commitment,
            "gross_payout_units": self.gross_payout_units,
            "net_payout_units": self.net_payout_units,
            "fee_paid_units": self.fee_paid_units,
            "rebate_id": self.rebate_id,
            "payout_commitment_root": self.payout_commitment_root,
            "nullifier_root": self.nullifier_root,
            "issued_at_height": self.issued_at_height,
            "receipt_proof_root": self.receipt_proof_root,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("receipt id", &self.receipt_id)?;
        require_non_empty("settlement id", &self.settlement_id)?;
        require_non_empty("position id", &self.position_id)?;
        require_non_empty("owner commitment", &self.owner_commitment)?;
        require_non_empty("payout commitment root", &self.payout_commitment_root)?;
        require_non_empty("nullifier root", &self.nullifier_root)?;
        if self.net_payout_units > self.gross_payout_units {
            return Err("receipt net payout exceeds gross payout".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub reservation_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub gross_fee_units: u64,
    pub rebate_units: u64,
    pub rebate_bps: u64,
    pub claim_commitment_root: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub claimed: bool,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "gross_fee_units": self.gross_fee_units,
            "rebate_units": self.rebate_units,
            "rebate_bps": self.rebate_bps,
            "claim_commitment_root": self.claim_commitment_root,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "claimed": self.claimed,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("rebate id", &self.rebate_id)?;
        require_non_empty("reservation id", &self.reservation_id)?;
        require_non_empty("receipt id", &self.receipt_id)?;
        require_non_empty("beneficiary commitment", &self.beneficiary_commitment)?;
        require_bps("rebate bps", self.rebate_bps)?;
        if self.rebate_units > self.gross_fee_units {
            return Err("rebate units exceed gross fee units".to_string());
        }
        if self.expires_at_height <= self.issued_at_height {
            return Err("rebate expiry must be after issue height".to_string());
        }
        Ok(self.rebate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub nullifier_root: String,
    pub commitment_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "nullifier_root": self.nullifier_root,
            "commitment_root": self.commitment_root,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "inserted_at_height": self.inserted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("fence id", &self.fence_id)?;
        require_non_empty("subject id", &self.subject_id)?;
        require_non_empty("nullifier root", &self.nullifier_root)?;
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("privacy fence set below configured minimum".to_string());
        }
        if self.expires_at_height <= self.inserted_at_height {
            return Err("privacy fence expiry must be after insert height".to_string());
        }
        Ok(self.fence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolatilityMetric {
    pub metric_id: String,
    pub market: TokenFeeMarket,
    pub fee_index_root: String,
    pub sample_count: u64,
    pub mean_fee_micro_units: u64,
    pub median_fee_micro_units: u64,
    pub realized_volatility_bps: u64,
    pub implied_volatility_bps: u64,
    pub stress_volatility_bps: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub oracle_attestation_id: String,
}

impl VolatilityMetric {
    pub fn public_record(&self) -> Value {
        json!({
            "metric_id": self.metric_id,
            "market": self.market.as_str(),
            "fee_index_root": self.fee_index_root,
            "sample_count": self.sample_count,
            "mean_fee_micro_units": self.mean_fee_micro_units,
            "median_fee_micro_units": self.median_fee_micro_units,
            "realized_volatility_bps": self.realized_volatility_bps,
            "implied_volatility_bps": self.implied_volatility_bps,
            "stress_volatility_bps": self.stress_volatility_bps,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "oracle_attestation_id": self.oracle_attestation_id,
        })
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        require_non_empty("metric id", &self.metric_id)?;
        require_non_empty("fee index root", &self.fee_index_root)?;
        require_positive("sample count", self.sample_count)?;
        if self.window_end_height < self.window_start_height {
            return Err("volatility metric window is inverted".to_string());
        }
        Ok(self.metric_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub instruments: u64,
    pub open_instruments: u64,
    pub positions: u64,
    pub open_positions: u64,
    pub rfqs: u64,
    pub active_rfqs: u64,
    pub quotes: u64,
    pub firm_quotes: u64,
    pub attestations: u64,
    pub settlements: u64,
    pub sponsor_reservations: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub fences: u64,
    pub volatility_metrics: u64,
    pub events: u64,
    pub total_notional_units: u128,
    pub total_margin_locked_units: u128,
    pub total_payout_units: u128,
    pub total_rebate_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "instruments": self.instruments,
            "open_instruments": self.open_instruments,
            "positions": self.positions,
            "open_positions": self.open_positions,
            "rfqs": self.rfqs,
            "active_rfqs": self.active_rfqs,
            "quotes": self.quotes,
            "firm_quotes": self.firm_quotes,
            "attestations": self.attestations,
            "settlements": self.settlements,
            "sponsor_reservations": self.sponsor_reservations,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "fences": self.fences,
            "volatility_metrics": self.volatility_metrics,
            "events": self.events,
            "total_notional_units": self.total_notional_units.to_string(),
            "total_margin_locked_units": self.total_margin_locked_units.to_string(),
            "total_payout_units": self.total_payout_units.to_string(),
            "total_rebate_units": self.total_rebate_units.to_string(),
        })
    }

    pub fn counters_root(&self) -> String {
        payload_root(
            "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub instrument_root: String,
    pub position_root: String,
    pub rfq_root: String,
    pub quote_root: String,
    pub oracle_attestation_root: String,
    pub settlement_root: String,
    pub sponsor_reservation_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub privacy_fence_root: String,
    pub volatility_metric_root: String,
    pub event_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "instrument_root": self.instrument_root,
            "position_root": self.position_root,
            "rfq_root": self.rfq_root,
            "quote_root": self.quote_root,
            "oracle_attestation_root": self.oracle_attestation_root,
            "settlement_root": self.settlement_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "privacy_fence_root": self.privacy_fence_root,
            "volatility_metric_root": self.volatility_metric_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn roots_root(&self) -> String {
        payload_root(
            "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub instruments: BTreeMap<String, FeeDerivativeInstrument>,
    pub positions: BTreeMap<String, HedgePosition>,
    pub encrypted_rfqs: BTreeMap<String, EncryptedRfq>,
    pub lp_quotes: BTreeMap<String, LiquidityProviderQuote>,
    pub oracle_attestations: BTreeMap<String, PqOracleAttestation>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub receipts: BTreeMap<String, DerivativeReceipt>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub volatility_metrics: BTreeMap<String, VolatilityMetric>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl State {
    pub fn empty(config: Config, height: u64) -> Self {
        Self {
            config,
            height,
            instruments: BTreeMap::new(),
            positions: BTreeMap::new(),
            encrypted_rfqs: BTreeMap::new(),
            lp_quotes: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            volatility_metrics: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let config = Config::default();
        let height = PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_DEVNET_HEIGHT;
        let mut state = Self::empty(config.clone(), height);

        let fee_index_root = string_root("DEVNET-FEE-INDEX", "monero-l2-private-token-p50");
        let future_id = token_fee_derivative_instrument_id(
            DerivativeKind::FeeFuture,
            TokenFeeMarket::PrivateAmm,
            &fee_index_root,
            420,
            50_000_000_000,
            height,
            height + 720,
        );
        let option_id = token_fee_derivative_instrument_id(
            DerivativeKind::FeeCallOption,
            TokenFeeMarket::SponsorRelay,
            &fee_index_root,
            680,
            25_000_000_000,
            height,
            height + 360,
        );
        let future = FeeDerivativeInstrument {
            instrument_id: future_id.clone(),
            kind: DerivativeKind::FeeFuture,
            market: TokenFeeMarket::PrivateAmm,
            status: InstrumentStatus::Trading,
            fee_index_root: fee_index_root.clone(),
            strike_fee_micro_units: 420,
            cap_fee_micro_units: 900,
            floor_fee_micro_units: 120,
            notional_token_amount_units: 50_000_000_000,
            contract_size_units: 1_000_000_000,
            collateral_asset_id: config.collateral_asset_id.clone(),
            quote_asset_id: config.fee_asset_id.clone(),
            margin_bps: config.target_margin_bps,
            premium_bps: 0,
            listed_at_height: height - 10,
            expires_at_height: height + 720,
            settlement_window_start_height: height + 700,
            settlement_window_end_height: height + 740,
            privacy_set_size: 65_536,
            metadata_root: string_root("DEVNET-INSTRUMENT-METADATA", "weekly-l2-exit-fee-future"),
        };
        let option = FeeDerivativeInstrument {
            instrument_id: option_id.clone(),
            kind: DerivativeKind::FeeCallOption,
            market: TokenFeeMarket::SponsorRelay,
            status: InstrumentStatus::Trading,
            fee_index_root: fee_index_root.clone(),
            strike_fee_micro_units: 680,
            cap_fee_micro_units: 1_400,
            floor_fee_micro_units: 0,
            notional_token_amount_units: 25_000_000_000,
            contract_size_units: 500_000_000,
            collateral_asset_id: config.collateral_asset_id.clone(),
            quote_asset_id: config.fee_asset_id.clone(),
            margin_bps: config.target_margin_bps + 250,
            premium_bps: config.default_option_premium_bps,
            listed_at_height: height - 6,
            expires_at_height: height + 360,
            settlement_window_start_height: height + 350,
            settlement_window_end_height: height + 384,
            privacy_set_size: 65_536,
            metadata_root: string_root("DEVNET-INSTRUMENT-METADATA", "emergency-exit-fee-call"),
        };
        state.instruments.insert(future_id.clone(), future);
        state.instruments.insert(option_id.clone(), option);

        let rfq_id = encrypted_rfq_id(
            "devnet-hedger-commitment",
            &future_id,
            PositionSide::LongFee,
            48,
            height - 3,
        );
        let quote_id = liquidity_provider_quote_id(
            &rfq_id,
            &future_id,
            "devnet-lp-alpha-commitment",
            410,
            430,
            height - 2,
        );
        let position_id = hedge_position_id(
            &future_id,
            "devnet-hedger-commitment",
            PositionSide::LongFee,
            &quote_id,
            height - 1,
        );
        let settlement_id = settlement_batch_id(
            &future_id,
            &position_id,
            &quote_id,
            &fee_index_root,
            height + 720,
        );
        let reservation_id = sponsor_reservation_id(
            "devnet-sponsor-commitment",
            &settlement_id,
            &future_id,
            9_000_000,
            height,
        );
        let attestation_id = pq_oracle_attestation_id(
            AttestationKind::FeeIndex,
            "devnet-oracle-committee",
            &future_id,
            &fee_index_root,
            height,
        );
        let receipt_id = derivative_receipt_id(&settlement_id, &position_id, 3_800_000, height);
        let rebate_id = fee_rebate_id(&reservation_id, &receipt_id, "devnet-hedger-commitment", 8);
        let metric_id = volatility_metric_id(
            TokenFeeMarket::PrivateAmm,
            &fee_index_root,
            height - 144,
            height,
        );
        let rfq = EncryptedRfq {
            rfq_id: rfq_id.clone(),
            requester_commitment: "devnet-hedger-commitment".to_string(),
            instrument_id: future_id.clone(),
            side: PositionSide::LongFee,
            status: RfqStatus::Quoted,
            sealed_terms_root: string_root("DEVNET-RFQ-TERMS", "hedge-48-contracts-private"),
            kem_ciphertext_hash: string_root("DEVNET-KEM", "rfq-ciphertext"),
            response_key_commitment: string_root("DEVNET-RESPONSE-KEY", "hedger-response-key"),
            max_fee_micro_units: 450,
            min_quantity_contracts: 24,
            max_quantity_contracts: 48,
            privacy_set_size: 65_536,
            route_root: string_root("DEVNET-ROUTE", "lp-alpha+lp-beta"),
            created_at_height: height - 3,
            expires_at_height: height + config.default_rfq_ttl_blocks,
            nullifier_root: string_root("DEVNET-NULLIFIER", "rfq-nullifier"),
        };
        let quote = LiquidityProviderQuote {
            quote_id: quote_id.clone(),
            rfq_id: rfq_id.clone(),
            instrument_id: future_id.clone(),
            lp_commitment: "devnet-lp-alpha-commitment".to_string(),
            status: QuoteStatus::Accepted,
            bid_fee_micro_units: 410,
            ask_fee_micro_units: 430,
            quantity_contracts: 48,
            premium_units: 0,
            margin_requirement_units: 10_800_000,
            quote_envelope_root: string_root("DEVNET-QUOTE-ENVELOPE", "firm-quote-alpha"),
            pq_signature_root: string_root("DEVNET-PQ-SIGNATURE", "quote-alpha-signature"),
            inventory_root: string_root("DEVNET-INVENTORY", "alpha-short-fee-room"),
            created_at_height: height - 2,
            expires_at_height: height + config.default_quote_ttl_blocks,
        };
        let position = HedgePosition {
            position_id: position_id.clone(),
            instrument_id: future_id.clone(),
            owner_commitment: "devnet-hedger-commitment".to_string(),
            side: PositionSide::LongFee,
            status: PositionStatus::MarginReserved,
            entry_quote_id: quote_id.clone(),
            entry_fee_micro_units: 430,
            quantity_contracts: 48,
            notional_token_amount_units: 48_000_000_000,
            margin_commitment_root: string_root("DEVNET-MARGIN", "hedger-margin-note"),
            collateral_locked_units: 10_800_000,
            realized_pnl_units: 0,
            unrealized_pnl_units: 760_000,
            rebate_reservation_id: reservation_id.clone(),
            opened_at_height: height - 1,
            last_mark_height: height,
            expires_at_height: height + 720,
            nullifier_root: string_root("DEVNET-NULLIFIER", "position-nullifier"),
        };
        let attestation = PqOracleAttestation {
            attestation_id: attestation_id.clone(),
            kind: AttestationKind::FeeIndex,
            oracle_committee_id: "devnet-oracle-committee".to_string(),
            subject_id: future_id.clone(),
            subject_root: string_root("DEVNET-ORACLE-SUBJECT", &future_id),
            fee_index_micro_units: 446,
            realized_volatility_bps: 1_120,
            implied_volatility_bps: 1_380,
            reserve_coverage_bps: 9_800,
            observation_start_height: height - 144,
            observation_end_height: height,
            signed_at_height: height,
            expires_at_height: height + 48,
            transcript_root: string_root("DEVNET-ORACLE-TRANSCRIPT", "fee-index-p50-window"),
            pq_signature_root: string_root("DEVNET-PQ-SIGNATURE", "oracle-fee-index-signature"),
        };
        let settlement = SettlementBatch {
            settlement_id: settlement_id.clone(),
            status: SettlementStatus::OracleAttested,
            instrument_root: future_id.clone(),
            position_root: position_id.clone(),
            quote_root: quote_id.clone(),
            oracle_attestation_root: attestation_id.clone(),
            sponsor_reservation_root: reservation_id.clone(),
            netting_root: string_root("DEVNET-NETTING", "future-netting-batch"),
            payout_root: string_root("DEVNET-PAYOUT", "future-payouts"),
            rebate_root: rebate_id.clone(),
            fee_index_micro_units: 446,
            mark_fee_micro_units: 446,
            total_notional_units: 48_000_000_000,
            total_payout_units: 3_800_000,
            proposed_at_height: height,
            settles_at_height: height + 720,
            expires_at_height: height + 756,
            settlement_proof_root: string_root("DEVNET-SETTLEMENT-PROOF", "future-settlement-zk"),
        };
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: "devnet-sponsor-commitment".to_string(),
            settlement_id: settlement_id.clone(),
            instrument_id: future_id.clone(),
            budget_root: string_root("DEVNET-SPONSOR-BUDGET", "rebate-budget-alpha"),
            reserved_units: 9_000_000,
            rebate_bps: config.default_rebate_bps,
            min_privacy_set_size: 65_536,
            opened_at_height: height,
            expires_at_height: height + 756,
            spent_units: 304_000,
            status: SettlementStatus::SponsorReserved,
        };
        let receipt = DerivativeReceipt {
            receipt_id: receipt_id.clone(),
            settlement_id: settlement_id.clone(),
            position_id: position_id.clone(),
            owner_commitment: "devnet-hedger-commitment".to_string(),
            gross_payout_units: 3_800_000,
            net_payout_units: 3_496_000,
            fee_paid_units: 304_000,
            rebate_id: rebate_id.clone(),
            payout_commitment_root: string_root("DEVNET-PAYOUT-COMMITMENT", "hedger-payout-note"),
            nullifier_root: string_root("DEVNET-NULLIFIER", "receipt-nullifier"),
            issued_at_height: height,
            receipt_proof_root: string_root("DEVNET-RECEIPT-PROOF", "receipt-proof"),
        };
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            reservation_id: reservation_id.clone(),
            receipt_id: receipt_id.clone(),
            beneficiary_commitment: "devnet-hedger-commitment".to_string(),
            gross_fee_units: 304_000,
            rebate_units: 243,
            rebate_bps: config.default_rebate_bps,
            claim_commitment_root: string_root("DEVNET-REBATE-CLAIM", "hedger-rebate-claim"),
            issued_at_height: height,
            expires_at_height: height + 1_440,
            claimed: false,
        };
        let metric = VolatilityMetric {
            metric_id: metric_id.clone(),
            market: TokenFeeMarket::PrivateAmm,
            fee_index_root: fee_index_root.clone(),
            sample_count: 144,
            mean_fee_micro_units: 432,
            median_fee_micro_units: 426,
            realized_volatility_bps: 1_120,
            implied_volatility_bps: 1_380,
            stress_volatility_bps: 2_500,
            window_start_height: height - 144,
            window_end_height: height,
            oracle_attestation_id: attestation_id.clone(),
        };
        state.encrypted_rfqs.insert(rfq_id.clone(), rfq);
        state.lp_quotes.insert(quote_id.clone(), quote);
        state.positions.insert(position_id.clone(), position);
        state
            .oracle_attestations
            .insert(attestation_id.clone(), attestation);
        state
            .settlement_batches
            .insert(settlement_id.clone(), settlement);
        state
            .sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        state.receipts.insert(receipt_id.clone(), receipt);
        state.rebates.insert(rebate_id.clone(), rebate);
        state.volatility_metrics.insert(metric_id.clone(), metric);

        for (sequence, (event_kind, subject_id, subject_root)) in [
            (
                "instrument_listed",
                future_id.clone(),
                state.instruments[&future_id].payload_root(),
            ),
            (
                "instrument_listed",
                option_id.clone(),
                state.instruments[&option_id].payload_root(),
            ),
            (
                "rfq_quoted",
                rfq_id.clone(),
                payload_root("RFQ", &state.encrypted_rfqs[&rfq_id].public_record()),
            ),
            (
                "quote_accepted",
                quote_id.clone(),
                payload_root("QUOTE", &state.lp_quotes[&quote_id].public_record()),
            ),
            (
                "position_opened",
                position_id.clone(),
                payload_root("POSITION", &state.positions[&position_id].public_record()),
            ),
            (
                "oracle_attested",
                attestation_id.clone(),
                payload_root(
                    "ATTESTATION",
                    &state.oracle_attestations[&attestation_id].public_record(),
                ),
            ),
            (
                "settlement_proposed",
                settlement_id.clone(),
                payload_root(
                    "SETTLEMENT",
                    &state.settlement_batches[&settlement_id].public_record(),
                ),
            ),
            (
                "rebate_reserved",
                reservation_id.clone(),
                payload_root(
                    "SPONSOR-RESERVATION",
                    &state.sponsor_reservations[&reservation_id].public_record(),
                ),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let event_id = runtime_event_id(event_kind, &subject_id, height, sequence as u64);
            state.events.insert(
                event_id.clone(),
                RuntimeEvent {
                    event_id,
                    event_kind: event_kind.to_string(),
                    subject_id,
                    subject_root,
                    height,
                    sequence: sequence as u64,
                },
            );
        }

        for (kind, subject_id, nullifier_root) in [
            (
                FenceKind::RfqReplay,
                rfq_id.clone(),
                state.encrypted_rfqs[&rfq_id].nullifier_root.clone(),
            ),
            (
                FenceKind::QuoteReplay,
                quote_id.clone(),
                string_root("DEVNET-NULLIFIER", "quote-nullifier"),
            ),
            (
                FenceKind::Nullifier,
                position_id.clone(),
                state.positions[&position_id].nullifier_root.clone(),
            ),
            (
                FenceKind::ReceiptReplay,
                receipt_id.clone(),
                state.receipts[&receipt_id].nullifier_root.clone(),
            ),
            (
                FenceKind::SettlementReplay,
                settlement_id.clone(),
                string_root("DEVNET-NULLIFIER", "settlement-nullifier"),
            ),
            (
                FenceKind::OracleReplay,
                attestation_id.clone(),
                string_root("DEVNET-NULLIFIER", "oracle-nullifier"),
            ),
        ] {
            let fence_id = privacy_fence_id(kind, &subject_id, &nullifier_root, height);
            state.privacy_fences.insert(
                fence_id.clone(),
                PrivacyFence {
                    fence_id,
                    kind,
                    subject_id,
                    nullifier_root,
                    commitment_root: string_root("DEVNET-FENCE-COMMITMENT", kind.as_str()),
                    replay_domain: config.replay_domain.clone(),
                    privacy_set_size: 65_536,
                    inserted_at_height: height,
                    expires_at_height: height + 1_440,
                },
            );
        }

        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            instruments: self.instruments.len() as u64,
            open_instruments: self
                .instruments
                .values()
                .filter(|instrument| {
                    matches!(
                        instrument.status,
                        InstrumentStatus::Listed | InstrumentStatus::Trading
                    )
                })
                .count() as u64,
            positions: self.positions.len() as u64,
            open_positions: self
                .positions
                .values()
                .filter(|position| {
                    matches!(
                        position.status,
                        PositionStatus::Open
                            | PositionStatus::MarginReserved
                            | PositionStatus::PartiallySettled
                    )
                })
                .count() as u64,
            rfqs: self.encrypted_rfqs.len() as u64,
            active_rfqs: self
                .encrypted_rfqs
                .values()
                .filter(|rfq| {
                    matches!(
                        rfq.status,
                        RfqStatus::Sealed | RfqStatus::Routed | RfqStatus::Quoted
                    )
                })
                .count() as u64,
            quotes: self.lp_quotes.len() as u64,
            firm_quotes: self
                .lp_quotes
                .values()
                .filter(|quote| matches!(quote.status, QuoteStatus::Firm | QuoteStatus::Accepted))
                .count() as u64,
            attestations: self.oracle_attestations.len() as u64,
            settlements: self.settlement_batches.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            receipts: self.receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            fences: self.privacy_fences.len() as u64,
            volatility_metrics: self.volatility_metrics.len() as u64,
            events: self.events.len() as u64,
            total_notional_units: self
                .positions
                .values()
                .map(|position| position.notional_token_amount_units as u128)
                .sum(),
            total_margin_locked_units: self
                .positions
                .values()
                .map(|position| position.collateral_locked_units as u128)
                .sum(),
            total_payout_units: self
                .receipts
                .values()
                .map(|receipt| receipt.net_payout_units as u128)
                .sum(),
            total_rebate_units: self
                .rebates
                .values()
                .map(|rebate| rebate.rebate_units as u128)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        Roots {
            config_root: payload_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-CONFIG",
                &self.config.public_record(),
            ),
            instrument_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-INSTRUMENTS",
                self.instruments
                    .iter()
                    .map(|(id, instrument)| (id.clone(), instrument.public_record()))
                    .collect(),
            ),
            position_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-POSITIONS",
                self.positions
                    .iter()
                    .map(|(id, position)| (id.clone(), position.public_record()))
                    .collect(),
            ),
            rfq_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-RFQS",
                self.encrypted_rfqs
                    .iter()
                    .map(|(id, rfq)| (id.clone(), rfq.public_record()))
                    .collect(),
            ),
            quote_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-QUOTES",
                self.lp_quotes
                    .iter()
                    .map(|(id, quote)| (id.clone(), quote.public_record()))
                    .collect(),
            ),
            oracle_attestation_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-ORACLE-ATTESTATIONS",
                self.oracle_attestations
                    .iter()
                    .map(|(id, attestation)| (id.clone(), attestation.public_record()))
                    .collect(),
            ),
            settlement_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-SETTLEMENTS",
                self.settlement_batches
                    .iter()
                    .map(|(id, settlement)| (id.clone(), settlement.public_record()))
                    .collect(),
            ),
            sponsor_reservation_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-SPONSOR-RESERVATIONS",
                self.sponsor_reservations
                    .iter()
                    .map(|(id, reservation)| (id.clone(), reservation.public_record()))
                    .collect(),
            ),
            receipt_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-RECEIPTS",
                self.receipts
                    .iter()
                    .map(|(id, receipt)| (id.clone(), receipt.public_record()))
                    .collect(),
            ),
            rebate_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-REBATES",
                self.rebates
                    .iter()
                    .map(|(id, rebate)| (id.clone(), rebate.public_record()))
                    .collect(),
            ),
            privacy_fence_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-PRIVACY-FENCES",
                self.privacy_fences
                    .iter()
                    .map(|(id, fence)| (id.clone(), fence.public_record()))
                    .collect(),
            ),
            volatility_metric_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-VOLATILITY-METRICS",
                self.volatility_metrics
                    .iter()
                    .map(|(id, metric)| (id.clone(), metric.public_record()))
                    .collect(),
            ),
            event_root: keyed_record_root(
                "CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-EVENTS",
                self.events
                    .iter()
                    .map(|(id, event)| (id.clone(), event.public_record()))
                    .collect(),
            ),
            counters_root: counters.counters_root(),
        }
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
            "sample_markets": {
                "active_instruments": self.instruments.keys().cloned().collect::<Vec<_>>(),
                "active_rfqs": self.encrypted_rfqs.keys().cloned().collect::<Vec<_>>(),
                "firm_quotes": self.lp_quotes.keys().cloned().collect::<Vec<_>>(),
            },
        })
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "confidential_token_fee_derivatives_state_root",
            self.state_root(),
        )
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn validate(&self) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<String> {
        self.config.validate()?;
        require_len(
            "instruments",
            self.instruments.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_INSTRUMENTS,
        )?;
        require_len(
            "positions",
            self.positions.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_POSITIONS,
        )?;
        require_len(
            "rfqs",
            self.encrypted_rfqs.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RFQS,
        )?;
        require_len(
            "quotes",
            self.lp_quotes.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_QUOTES,
        )?;
        require_len(
            "oracle attestations",
            self.oracle_attestations.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_ATTESTATIONS,
        )?;
        require_len(
            "settlements",
            self.settlement_batches.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_SETTLEMENTS,
        )?;
        require_len(
            "sponsor reservations",
            self.sponsor_reservations.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RESERVATIONS,
        )?;
        require_len(
            "receipts",
            self.receipts.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_RECEIPTS,
        )?;
        require_len(
            "rebates",
            self.rebates.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_REBATES,
        )?;
        require_len(
            "privacy fences",
            self.privacy_fences.len(),
            PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_FENCES,
        )?;

        let instrument_ids = self
            .instruments
            .values()
            .map(|instrument| instrument.validate(&self.config))
            .collect::<PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<Vec<_>>>()?;
        ensure_unique_strings(&instrument_ids, "instrument id")?;
        let instrument_set = instrument_ids.iter().cloned().collect::<BTreeSet<_>>();

        let position_ids =
            self.positions
                .values()
                .map(HedgePosition::validate)
                .collect::<PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<Vec<_>>>()?;
        ensure_unique_strings(&position_ids, "position id")?;
        let position_set = position_ids.iter().cloned().collect::<BTreeSet<_>>();

        let rfq_ids = self
            .encrypted_rfqs
            .values()
            .map(|rfq| rfq.validate(&self.config))
            .collect::<PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<Vec<_>>>()?;
        ensure_unique_strings(&rfq_ids, "rfq id")?;
        let rfq_set = rfq_ids.iter().cloned().collect::<BTreeSet<_>>();

        let quote_ids = self
            .lp_quotes
            .values()
            .map(LiquidityProviderQuote::validate)
            .collect::<PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<Vec<_>>>()?;
        ensure_unique_strings(&quote_ids, "quote id")?;
        let quote_set = quote_ids.iter().cloned().collect::<BTreeSet<_>>();

        for position in self.positions.values() {
            if !instrument_set.contains(&position.instrument_id) {
                return Err("position references missing instrument".to_string());
            }
            if !quote_set.contains(&position.entry_quote_id) && !position.entry_quote_id.is_empty()
            {
                return Err("position references missing entry quote".to_string());
            }
        }
        for rfq in self.encrypted_rfqs.values() {
            if !instrument_set.contains(&rfq.instrument_id) {
                return Err("rfq references missing instrument".to_string());
            }
        }
        for quote in self.lp_quotes.values() {
            if !rfq_set.contains(&quote.rfq_id) {
                return Err("quote references missing rfq".to_string());
            }
            if !instrument_set.contains(&quote.instrument_id) {
                return Err("quote references missing instrument".to_string());
            }
        }
        for attestation in self.oracle_attestations.values() {
            attestation.validate()?;
        }
        for settlement in self.settlement_batches.values() {
            settlement.validate()?;
        }
        for reservation in self.sponsor_reservations.values() {
            reservation.validate(&self.config)?;
            if !instrument_set.contains(&reservation.instrument_id) {
                return Err("sponsor reservation references missing instrument".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !position_set.contains(&receipt.position_id) {
                return Err("receipt references missing position".to_string());
            }
        }
        for rebate in self.rebates.values() {
            rebate.validate()?;
        }
        for fence in self.privacy_fences.values() {
            fence.validate(&self.config)?;
        }
        for metric in self.volatility_metrics.values() {
            metric.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-STATE", record)
}

pub fn public_record_root(record: &Value) -> String {
    payload_root("CONFIDENTIAL-TOKEN-FEE-DERIVATIVES-PUBLIC-RECORD", record)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn token_fee_derivative_instrument_id(
    kind: DerivativeKind,
    market: TokenFeeMarket,
    fee_index_root: &str,
    strike_fee_micro_units: u64,
    notional_token_amount_units: u64,
    listed_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-INSTRUMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(market.as_str()),
            HashPart::Str(fee_index_root),
            HashPart::Int(strike_fee_micro_units as i128),
            HashPart::Int(notional_token_amount_units as i128),
            HashPart::Int(listed_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn hedge_position_id(
    instrument_id: &str,
    owner_commitment: &str,
    side: PositionSide,
    entry_quote_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-HEDGE-POSITION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(instrument_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(side.as_str()),
            HashPart::Str(entry_quote_id),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn encrypted_rfq_id(
    requester_commitment: &str,
    instrument_id: &str,
    side: PositionSide,
    max_quantity_contracts: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-ENCRYPTED-RFQ-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(requester_commitment),
            HashPart::Str(instrument_id),
            HashPart::Str(side.as_str()),
            HashPart::Int(max_quantity_contracts as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn liquidity_provider_quote_id(
    rfq_id: &str,
    instrument_id: &str,
    lp_commitment: &str,
    bid_fee_micro_units: u64,
    ask_fee_micro_units: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-LP-QUOTE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(rfq_id),
            HashPart::Str(instrument_id),
            HashPart::Str(lp_commitment),
            HashPart::Int(bid_fee_micro_units as i128),
            HashPart::Int(ask_fee_micro_units as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn pq_oracle_attestation_id(
    kind: AttestationKind,
    oracle_committee_id: &str,
    subject_id: &str,
    subject_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-PQ-ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(oracle_committee_id),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn settlement_batch_id(
    instrument_id: &str,
    position_id: &str,
    quote_id: &str,
    oracle_root: &str,
    settles_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-SETTLEMENT-BATCH-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(instrument_id),
            HashPart::Str(position_id),
            HashPart::Str(quote_id),
            HashPart::Str(oracle_root),
            HashPart::Int(settles_at_height as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_commitment: &str,
    settlement_id: &str,
    instrument_id: &str,
    reserved_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-SPONSOR-RESERVATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(settlement_id),
            HashPart::Str(instrument_id),
            HashPart::Int(reserved_units as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn derivative_receipt_id(
    settlement_id: &str,
    position_id: &str,
    net_payout_units: u64,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-RECEIPT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(settlement_id),
            HashPart::Str(position_id),
            HashPart::Int(net_payout_units as i128),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn fee_rebate_id(
    reservation_id: &str,
    receipt_id: &str,
    beneficiary_commitment: &str,
    rebate_bps: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-REBATE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(reservation_id),
            HashPart::Str(receipt_id),
            HashPart::Str(beneficiary_commitment),
            HashPart::Int(rebate_bps as i128),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    nullifier_root: &str,
    inserted_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
            HashPart::Int(inserted_at_height as i128),
        ],
        32,
    )
}

pub fn volatility_metric_id(
    market: TokenFeeMarket,
    fee_index_root: &str,
    window_start_height: u64,
    window_end_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-VOLATILITY-METRIC-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market.as_str()),
            HashPart::Str(fee_index_root),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
        ],
        32,
    )
}

pub fn runtime_event_id(event_kind: &str, subject_id: &str, height: u64, sequence: u64) -> String {
    domain_hash(
        "CONFIDENTIAL-TOKEN-FEE-DERIVATIVE-RUNTIME-EVENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Int(height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(
    label: &str,
    value: u64,
) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(
    label: &str,
    value: u64,
) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
    if value > PRIVATE_L2_CONFIDENTIAL_TOKEN_FEE_DERIVATIVES_RUNTIME_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn require_len(
    label: &str,
    value: usize,
    max: usize,
) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
    if value > max {
        Err(format!("{label} exceeds runtime maximum"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(
    values: &[String],
    label: &str,
) -> PrivateL2ConfidentialTokenFeeDerivativesRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
