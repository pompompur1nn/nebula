use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialFeeDerivativeHedgingRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-fee-derivative-hedging-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_DERIVATIVE_HEDGING_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-confidential-fee-derivative-roll-auth-v1";
pub const PQ_SEALING_SCHEME: &str =
    "ml-kem-1024+xwing-sealed-confidential-fee-derivative-position-v1";
pub const CLEARING_PROOF_SCHEME: &str = "zk-pq-private-low-fee-derivative-clearing-batch-proof-v1";
pub const SETTLEMENT_RECEIPT_SCHEME: &str =
    "zk-pq-private-low-fee-derivative-settlement-receipt-v1";
pub const SPONSOR_POOL_HEDGE_SCHEME: &str =
    "roots-only-private-sponsor-pool-fee-hedge-commitment-v1";
pub const PROOF_MARKET_VOLATILITY_SCHEME: &str =
    "confidential-proof-market-volatility-surface-root-v1";
pub const DA_BLOB_PRICE_HEDGE_SCHEME: &str = "private-da-blob-price-hedge-root-v1";
pub const BRIDGE_EXIT_FEE_SMOOTHING_SCHEME: &str =
    "private-bridge-exit-fee-smoothing-ladder-root-v1";
pub const MULTI_ASSET_NETTING_SCHEME: &str = "confidential-multi-asset-fee-netting-root-v1";
pub const USER_CAP_ENFORCEMENT_SCHEME: &str = "private-user-fee-cap-enforcement-root-v1";
pub const PRIVATE_CLEARING_BATCH_SCHEME: &str =
    "private-confidential-fee-derivative-clearing-batch-root-v1";
pub const PQ_ROLL_ATTESTATION_SCHEME: &str =
    "pq-authenticated-confidential-fee-hedge-roll-attestation-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-ringct-style-fee-derivative-privacy-fence-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_888_640;
pub const DEVNET_EPOCH: u64 = 2_623;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MARKET_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ROLL_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_CLEARING_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 10;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_CLEARING_FEE_BPS: u64 = 2;
pub const DEFAULT_PROTOCOL_REBATE_BPS: u64 = 6;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_750;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_250;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_400;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 850;
pub const DEFAULT_DA_BLOB_HAIRCUT_BPS: u64 = 500;
pub const DEFAULT_PROOF_VOL_HAIRCUT_BPS: u64 = 650;
pub const DEFAULT_EXIT_SMOOTHING_BPS: u64 = 900;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 40_000;
pub const DEFAULT_MAX_MARKETS: usize = 262_144;
pub const DEFAULT_MAX_POSITIONS: usize = 2_097_152;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 131_072;
pub const DEFAULT_MAX_VOL_SURFACES: usize = 262_144;
pub const DEFAULT_MAX_DA_HEDGES: usize = 524_288;
pub const DEFAULT_MAX_EXIT_LADDERS: usize = 262_144;
pub const DEFAULT_MAX_NETTING_ROUNDS: usize = 524_288;
pub const DEFAULT_MAX_CAPS: usize = 1_048_576;
pub const DEFAULT_MAX_ROLLS: usize = 1_048_576;
pub const DEFAULT_MAX_CLEARING_BATCHES: usize = 524_288;
pub const DEFAULT_MAX_RECEIPTS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 524_288;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRiskKind {
    RollupGas,
    ProofMarket,
    DaBlob,
    BridgeExit,
    ContractCall,
    TokenMint,
    TokenSwap,
    SmartAccountSession,
    WithdrawalBatch,
    SponsorRelay,
}

impl FeeRiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupGas => "rollup_gas",
            Self::ProofMarket => "proof_market",
            Self::DaBlob => "da_blob",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::TokenMint => "token_mint",
            Self::TokenSwap => "token_swap",
            Self::SmartAccountSession => "smart_account_session",
            Self::WithdrawalBatch => "withdrawal_batch",
            Self::SponsorRelay => "sponsor_relay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    FeeFuture,
    FeeCall,
    FeePut,
    FeeCollar,
    SponsorPoolForward,
    ProofVolatilitySwap,
    DaBlobPriceFuture,
    BridgeExitSmoothingNote,
    MultiAssetNettingClaim,
    UserCapProtection,
}

impl InstrumentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeeFuture => "fee_future",
            Self::FeeCall => "fee_call",
            Self::FeePut => "fee_put",
            Self::FeeCollar => "fee_collar",
            Self::SponsorPoolForward => "sponsor_pool_forward",
            Self::ProofVolatilitySwap => "proof_volatility_swap",
            Self::DaBlobPriceFuture => "da_blob_price_future",
            Self::BridgeExitSmoothingNote => "bridge_exit_smoothing_note",
            Self::MultiAssetNettingClaim => "multi_asset_netting_claim",
            Self::UserCapProtection => "user_cap_protection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HedgeSide {
    PayFixedFee,
    ReceiveFixedFee,
    BuyCap,
    SellCap,
    BuyFloor,
    SellFloor,
    SponsorShortFee,
    UserLongFee,
    LongVolatility,
    ShortVolatility,
}

impl HedgeSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayFixedFee => "pay_fixed_fee",
            Self::ReceiveFixedFee => "receive_fixed_fee",
            Self::BuyCap => "buy_cap",
            Self::SellCap => "sell_cap",
            Self::BuyFloor => "buy_floor",
            Self::SellFloor => "sell_floor",
            Self::SponsorShortFee => "sponsor_short_fee",
            Self::UserLongFee => "user_long_fee",
            Self::LongVolatility => "long_volatility",
            Self::ShortVolatility => "short_volatility",
        }
    }

    pub fn signed_notional(self, notional: u64) -> i128 {
        match self {
            Self::PayFixedFee
            | Self::BuyCap
            | Self::BuyFloor
            | Self::UserLongFee
            | Self::LongVolatility => notional as i128,
            Self::ReceiveFixedFee
            | Self::SellCap
            | Self::SellFloor
            | Self::SponsorShortFee
            | Self::ShortVolatility => -(notional as i128),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Open,
    Hedging,
    Netting,
    Clearing,
    Settling,
    Settled,
    Paused,
    Expired,
    Slashed,
}

impl MarketStatus {
    pub fn accepts_positions(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Open | Self::Hedging | Self::Netting
        )
    }

    pub fn can_clear(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Hedging | Self::Netting | Self::Clearing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Submitted,
    Admitted,
    Matched,
    Rolled,
    Netting,
    Clearing,
    Settled,
    CapClamped,
    Rejected,
    Expired,
}

impl PositionStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Admitted | Self::Matched | Self::Rolled | Self::Netting
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Draft,
    Active,
    Hedging,
    Reserving,
    Settling,
    Settled,
    Paused,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Admitting,
    Netting,
    Clearing,
    Settling,
    Receipted,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Final,
    Rebatable,
    CapAdjusted,
    Disputed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapMode {
    HardReject,
    ClampToCap,
    SponsorOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollIntent {
    ExtendMaturity,
    ReduceNotional,
    IncreaseMargin,
    ChangeStrike,
    MoveToSponsorPool,
    CloseAndReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub clearing_proof_scheme: String,
    pub settlement_receipt_scheme: String,
    pub epoch_blocks: u64,
    pub market_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub roll_ttl_blocks: u64,
    pub clearing_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub clearing_fee_bps: u64,
    pub protocol_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub da_blob_haircut_bps: u64,
    pub proof_vol_haircut_bps: u64,
    pub exit_smoothing_bps: u64,
    pub max_leverage_bps: u64,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_sponsor_pools: usize,
    pub max_vol_surfaces: usize,
    pub max_da_hedges: usize,
    pub max_exit_ladders: usize,
    pub max_netting_rounds: usize,
    pub max_caps: usize,
    pub max_rolls: usize,
    pub max_clearing_batches: usize,
    pub max_receipts: usize,
    pub max_privacy_fences: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            clearing_proof_scheme: CLEARING_PROOF_SCHEME.to_string(),
            settlement_receipt_scheme: SETTLEMENT_RECEIPT_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            market_ttl_blocks: DEFAULT_MARKET_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            roll_ttl_blocks: DEFAULT_ROLL_TTL_BLOCKS,
            clearing_ttl_blocks: DEFAULT_CLEARING_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            clearing_fee_bps: DEFAULT_CLEARING_FEE_BPS,
            protocol_rebate_bps: DEFAULT_PROTOCOL_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            da_blob_haircut_bps: DEFAULT_DA_BLOB_HAIRCUT_BPS,
            proof_vol_haircut_bps: DEFAULT_PROOF_VOL_HAIRCUT_BPS,
            exit_smoothing_bps: DEFAULT_EXIT_SMOOTHING_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_vol_surfaces: DEFAULT_MAX_VOL_SURFACES,
            max_da_hedges: DEFAULT_MAX_DA_HEDGES,
            max_exit_ladders: DEFAULT_MAX_EXIT_LADDERS,
            max_netting_rounds: DEFAULT_MAX_NETTING_ROUNDS,
            max_caps: DEFAULT_MAX_CAPS,
            max_rolls: DEFAULT_MAX_ROLLS,
            max_clearing_batches: DEFAULT_MAX_CLEARING_BATCHES,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_sealing_scheme": self.pq_sealing_scheme,
            "clearing_proof_scheme": self.clearing_proof_scheme,
            "settlement_receipt_scheme": self.settlement_receipt_scheme,
            "epoch_blocks": self.epoch_blocks,
            "market_ttl_blocks": self.market_ttl_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "roll_ttl_blocks": self.roll_ttl_blocks,
            "clearing_ttl_blocks": self.clearing_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "clearing_fee_bps": self.clearing_fee_bps,
            "protocol_rebate_bps": self.protocol_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "da_blob_haircut_bps": self.da_blob_haircut_bps,
            "proof_vol_haircut_bps": self.proof_vol_haircut_bps,
            "exit_smoothing_bps": self.exit_smoothing_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_markets": self.max_markets,
            "max_positions": self.max_positions,
            "max_sponsor_pools": self.max_sponsor_pools,
            "max_vol_surfaces": self.max_vol_surfaces,
            "max_da_hedges": self.max_da_hedges,
            "max_exit_ladders": self.max_exit_ladders,
            "max_netting_rounds": self.max_netting_rounds,
            "max_caps": self.max_caps,
            "max_rolls": self.max_rolls,
            "max_clearing_batches": self.max_clearing_batches,
            "max_receipts": self.max_receipts,
            "max_privacy_fences": self.max_privacy_fences
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub markets: u64,
    pub positions: u64,
    pub sponsor_pools: u64,
    pub proof_vol_surfaces: u64,
    pub da_blob_hedges: u64,
    pub exit_smoothing_ladders: u64,
    pub netting_rounds: u64,
    pub user_caps: u64,
    pub pq_rolls: u64,
    pub clearing_batches: u64,
    pub settlement_receipts: u64,
    pub privacy_fences: u64,
    pub rejected_requests: u64,
    pub cap_adjustments: u64,
    pub total_notional: u128,
    pub total_margin: u128,
    pub total_settled: u128,
    pub total_rebates: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets": self.markets,
            "positions": self.positions,
            "sponsor_pools": self.sponsor_pools,
            "proof_vol_surfaces": self.proof_vol_surfaces,
            "da_blob_hedges": self.da_blob_hedges,
            "exit_smoothing_ladders": self.exit_smoothing_ladders,
            "netting_rounds": self.netting_rounds,
            "user_caps": self.user_caps,
            "pq_rolls": self.pq_rolls,
            "clearing_batches": self.clearing_batches,
            "settlement_receipts": self.settlement_receipts,
            "privacy_fences": self.privacy_fences,
            "rejected_requests": self.rejected_requests,
            "cap_adjustments": self.cap_adjustments,
            "total_notional": self.total_notional.to_string(),
            "total_margin": self.total_margin.to_string(),
            "total_settled": self.total_settled.to_string(),
            "total_rebates": self.total_rebates.to_string()
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub markets_root: String,
    pub positions_root: String,
    pub sponsor_pools_root: String,
    pub proof_vol_surfaces_root: String,
    pub da_blob_hedges_root: String,
    pub exit_ladders_root: String,
    pub netting_rounds_root: String,
    pub user_caps_root: String,
    pub pq_rolls_root: String,
    pub clearing_batches_root: String,
    pub receipts_root: String,
    pub privacy_fences_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "markets_root": self.markets_root,
            "positions_root": self.positions_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "proof_vol_surfaces_root": self.proof_vol_surfaces_root,
            "da_blob_hedges_root": self.da_blob_hedges_root,
            "exit_ladders_root": self.exit_ladders_root,
            "netting_rounds_root": self.netting_rounds_root,
            "user_caps_root": self.user_caps_root,
            "pq_rolls_root": self.pq_rolls_root,
            "clearing_batches_root": self.clearing_batches_root,
            "receipts_root": self.receipts_root,
            "privacy_fences_root": self.privacy_fences_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeMarketRequest {
    pub market_id: String,
    pub risk_kind: FeeRiskKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub maturity_height: u64,
    pub strike_micro_fee: u64,
    pub oracle_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_notional: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeMarketRecord {
    pub market_id: String,
    pub risk_kind: FeeRiskKind,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub open_height: u64,
    pub maturity_height: u64,
    pub strike_micro_fee: u64,
    pub oracle_commitment: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_notional: u64,
    pub open_notional: u64,
    pub matched_notional: u64,
    pub cleared_notional: u64,
    pub status: MarketStatus,
    pub market_root: String,
}

impl FeeMarketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "risk_kind": self.risk_kind.as_str(),
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "open_height": self.open_height,
            "maturity_height": self.maturity_height,
            "strike_micro_fee": self.strike_micro_fee,
            "oracle_commitment": self.oracle_commitment,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "max_notional": self.max_notional,
            "open_notional": self.open_notional,
            "matched_notional": self.matched_notional,
            "cleared_notional": self.cleared_notional,
            "status": format!("{:?}", self.status),
            "market_root": self.market_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HedgePositionRequest {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub instrument: InstrumentKind,
    pub side: HedgeSide,
    pub notional: u64,
    pub premium: u64,
    pub margin: u64,
    pub user_fee_cap_micro: u64,
    pub cap_mode: CapMode,
    pub nullifier: String,
    pub sealed_terms_root: String,
    pub pq_auth_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HedgePositionRecord {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub instrument: InstrumentKind,
    pub side: HedgeSide,
    pub notional: u64,
    pub premium: u64,
    pub margin: u64,
    pub user_fee_cap_micro: u64,
    pub effective_fee_cap_micro: u64,
    pub cap_mode: CapMode,
    pub nullifier: String,
    pub sealed_terms_root: String,
    pub pq_auth_root: String,
    pub admitted_height: u64,
    pub status: PositionStatus,
    pub settlement_delta: i128,
    pub position_root: String,
}

impl HedgePositionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "instrument": self.instrument.as_str(),
            "side": self.side.as_str(),
            "notional": self.notional,
            "premium": self.premium,
            "margin": self.margin,
            "user_fee_cap_micro": self.user_fee_cap_micro,
            "effective_fee_cap_micro": self.effective_fee_cap_micro,
            "cap_mode": format!("{:?}", self.cap_mode),
            "nullifier": self.nullifier,
            "sealed_terms_root": self.sealed_terms_root,
            "pq_auth_root": self.pq_auth_root,
            "admitted_height": self.admitted_height,
            "status": format!("{:?}", self.status),
            "settlement_delta": self.settlement_delta.to_string(),
            "position_root": self.position_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorPoolRequest {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub reserve_amount: u64,
    pub cover_bps: u64,
    pub max_fee_cap_micro: u64,
    pub hedged_market_ids: Vec<String>,
    pub sealed_policy_root: String,
    pub pq_auth_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorPoolRecord {
    pub pool_id: String,
    pub sponsor_commitment: String,
    pub asset_id: String,
    pub reserve_amount: u64,
    pub allocated_amount: u64,
    pub cover_bps: u64,
    pub max_fee_cap_micro: u64,
    pub hedged_market_ids: Vec<String>,
    pub sealed_policy_root: String,
    pub pq_auth_root: String,
    pub status: PoolStatus,
    pub pool_root: String,
}

impl SponsorPoolRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "sponsor_commitment": self.sponsor_commitment,
            "asset_id": self.asset_id,
            "reserve_amount": self.reserve_amount,
            "allocated_amount": self.allocated_amount,
            "cover_bps": self.cover_bps,
            "max_fee_cap_micro": self.max_fee_cap_micro,
            "hedged_market_ids": self.hedged_market_ids,
            "sealed_policy_root": self.sealed_policy_root,
            "pq_auth_root": self.pq_auth_root,
            "status": format!("{:?}", self.status),
            "pool_root": self.pool_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMarketVolatilityRequest {
    pub surface_id: String,
    pub market_id: String,
    pub prover_class: String,
    pub base_vol_bps: u64,
    pub stress_vol_bps: u64,
    pub depth_commitment: String,
    pub proof_latency_commitment: String,
    pub pq_oracle_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMarketVolatilityRecord {
    pub surface_id: String,
    pub market_id: String,
    pub prover_class: String,
    pub base_vol_bps: u64,
    pub stress_vol_bps: u64,
    pub haircut_bps: u64,
    pub depth_commitment: String,
    pub proof_latency_commitment: String,
    pub pq_oracle_root: String,
    pub surface_root: String,
}

impl ProofMarketVolatilityRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "surface_id": self.surface_id,
            "market_id": self.market_id,
            "prover_class": self.prover_class,
            "base_vol_bps": self.base_vol_bps,
            "stress_vol_bps": self.stress_vol_bps,
            "haircut_bps": self.haircut_bps,
            "depth_commitment": self.depth_commitment,
            "proof_latency_commitment": self.proof_latency_commitment,
            "pq_oracle_root": self.pq_oracle_root,
            "surface_root": self.surface_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaBlobPriceHedgeRequest {
    pub hedge_id: String,
    pub market_id: String,
    pub blob_lane: String,
    pub blob_count: u64,
    pub fixed_blob_price_micro: u64,
    pub max_blob_price_micro: u64,
    pub da_commitment_root: String,
    pub pq_auth_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaBlobPriceHedgeRecord {
    pub hedge_id: String,
    pub market_id: String,
    pub blob_lane: String,
    pub blob_count: u64,
    pub fixed_blob_price_micro: u64,
    pub max_blob_price_micro: u64,
    pub haircut_bps: u64,
    pub da_commitment_root: String,
    pub pq_auth_root: String,
    pub hedge_root: String,
}

impl DaBlobPriceHedgeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "hedge_id": self.hedge_id,
            "market_id": self.market_id,
            "blob_lane": self.blob_lane,
            "blob_count": self.blob_count,
            "fixed_blob_price_micro": self.fixed_blob_price_micro,
            "max_blob_price_micro": self.max_blob_price_micro,
            "haircut_bps": self.haircut_bps,
            "da_commitment_root": self.da_commitment_root,
            "pq_auth_root": self.pq_auth_root,
            "hedge_root": self.hedge_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeExitFeeSmoothingRequest {
    pub ladder_id: String,
    pub market_id: String,
    pub bridge_domain: String,
    pub target_exit_fee_micro: u64,
    pub smoothing_bps: u64,
    pub tranche_count: u64,
    pub exit_queue_commitment: String,
    pub sponsor_pool_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeExitFeeSmoothingRecord {
    pub ladder_id: String,
    pub market_id: String,
    pub bridge_domain: String,
    pub target_exit_fee_micro: u64,
    pub smoothing_bps: u64,
    pub tranche_count: u64,
    pub exit_queue_commitment: String,
    pub sponsor_pool_id: String,
    pub ladder_root: String,
}

impl BridgeExitFeeSmoothingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "ladder_id": self.ladder_id,
            "market_id": self.market_id,
            "bridge_domain": self.bridge_domain,
            "target_exit_fee_micro": self.target_exit_fee_micro,
            "smoothing_bps": self.smoothing_bps,
            "tranche_count": self.tranche_count,
            "exit_queue_commitment": self.exit_queue_commitment,
            "sponsor_pool_id": self.sponsor_pool_id,
            "ladder_root": self.ladder_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiAssetNettingRequest {
    pub round_id: String,
    pub market_id: String,
    pub asset_exposures: BTreeMap<String, i128>,
    pub conversion_roots: BTreeMap<String, String>,
    pub participant_commitments: Vec<String>,
    pub sealed_netting_proof_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiAssetNettingRecord {
    pub round_id: String,
    pub market_id: String,
    pub asset_exposures: BTreeMap<String, i128>,
    pub conversion_roots: BTreeMap<String, String>,
    pub participant_commitments: Vec<String>,
    pub gross_abs_exposure: u128,
    pub net_abs_exposure: u128,
    pub participant_count: u64,
    pub sealed_netting_proof_root: String,
    pub netting_root: String,
}

impl MultiAssetNettingRecord {
    pub fn public_record(&self) -> Value {
        let exposures: BTreeMap<String, String> = self
            .asset_exposures
            .iter()
            .map(|(asset, amount)| (asset.clone(), amount.to_string()))
            .collect();
        json!({
            "round_id": self.round_id,
            "market_id": self.market_id,
            "asset_exposures": exposures,
            "conversion_roots": self.conversion_roots,
            "participant_commitments": self.participant_commitments,
            "gross_abs_exposure": self.gross_abs_exposure.to_string(),
            "net_abs_exposure": self.net_abs_exposure.to_string(),
            "participant_count": self.participant_count,
            "sealed_netting_proof_root": self.sealed_netting_proof_root,
            "netting_root": self.netting_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserCapRequest {
    pub cap_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub max_fee_micro: u64,
    pub epoch: u64,
    pub sponsor_pool_id: String,
    pub cap_nullifier: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserCapRecord {
    pub cap_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub max_fee_micro: u64,
    pub used_fee_micro: u64,
    pub overflow_sponsored_micro: u64,
    pub epoch: u64,
    pub sponsor_pool_id: String,
    pub cap_nullifier: String,
    pub cap_root: String,
}

impl UserCapRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "max_fee_micro": self.max_fee_micro,
            "used_fee_micro": self.used_fee_micro,
            "overflow_sponsored_micro": self.overflow_sponsored_micro,
            "epoch": self.epoch,
            "sponsor_pool_id": self.sponsor_pool_id,
            "cap_nullifier": self.cap_nullifier,
            "cap_root": self.cap_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAuthenticatedRollRequest {
    pub roll_id: String,
    pub old_position_id: String,
    pub new_position_id: String,
    pub intent: RollIntent,
    pub new_maturity_height: u64,
    pub new_notional: u64,
    pub new_strike_micro_fee: u64,
    pub roll_fee_micro: u64,
    pub pq_signature_root: String,
    pub previous_position_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAuthenticatedRollRecord {
    pub roll_id: String,
    pub old_position_id: String,
    pub new_position_id: String,
    pub intent: RollIntent,
    pub new_maturity_height: u64,
    pub new_notional: u64,
    pub new_strike_micro_fee: u64,
    pub roll_fee_micro: u64,
    pub pq_signature_root: String,
    pub previous_position_root: String,
    pub accepted_height: u64,
    pub roll_root: String,
}

impl PqAuthenticatedRollRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "roll_id": self.roll_id,
            "old_position_id": self.old_position_id,
            "new_position_id": self.new_position_id,
            "intent": format!("{:?}", self.intent),
            "new_maturity_height": self.new_maturity_height,
            "new_notional": self.new_notional,
            "new_strike_micro_fee": self.new_strike_micro_fee,
            "roll_fee_micro": self.roll_fee_micro,
            "pq_signature_root": self.pq_signature_root,
            "previous_position_root": self.previous_position_root,
            "accepted_height": self.accepted_height,
            "roll_root": self.roll_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateClearingBatchRequest {
    pub batch_id: String,
    pub market_id: String,
    pub position_ids: Vec<String>,
    pub netting_round_id: String,
    pub clearing_price_micro: u64,
    pub realized_fee_micro: u64,
    pub sealed_batch_proof_root: String,
    pub operator_pq_auth_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateClearingBatchRecord {
    pub batch_id: String,
    pub market_id: String,
    pub position_ids: Vec<String>,
    pub netting_round_id: String,
    pub clearing_price_micro: u64,
    pub realized_fee_micro: u64,
    pub gross_notional: u64,
    pub net_delta: i128,
    pub rebate_pool_micro: u64,
    pub clearing_fee_micro: u64,
    pub sealed_batch_proof_root: String,
    pub operator_pq_auth_root: String,
    pub status: BatchStatus,
    pub batch_root: String,
}

impl PrivateClearingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "market_id": self.market_id,
            "position_ids": self.position_ids,
            "netting_round_id": self.netting_round_id,
            "clearing_price_micro": self.clearing_price_micro,
            "realized_fee_micro": self.realized_fee_micro,
            "gross_notional": self.gross_notional,
            "net_delta": self.net_delta.to_string(),
            "rebate_pool_micro": self.rebate_pool_micro,
            "clearing_fee_micro": self.clearing_fee_micro,
            "sealed_batch_proof_root": self.sealed_batch_proof_root,
            "operator_pq_auth_root": self.operator_pq_auth_root,
            "status": format!("{:?}", self.status),
            "batch_root": self.batch_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceiptRequest {
    pub receipt_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub position_id: String,
    pub asset_id: String,
    pub settled_amount_micro: i128,
    pub rebate_micro: u64,
    pub cap_adjustment_micro: u64,
    pub nullifier: String,
    pub inclusion_proof_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceiptRecord {
    pub receipt_id: String,
    pub batch_id: String,
    pub beneficiary_commitment: String,
    pub position_id: String,
    pub asset_id: String,
    pub settled_amount_micro: i128,
    pub rebate_micro: u64,
    pub cap_adjustment_micro: u64,
    pub nullifier: String,
    pub inclusion_proof_root: String,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

impl SettlementReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "batch_id": self.batch_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "position_id": self.position_id,
            "asset_id": self.asset_id,
            "settled_amount_micro": self.settled_amount_micro.to_string(),
            "rebate_micro": self.rebate_micro,
            "cap_adjustment_micro": self.cap_adjustment_micro,
            "nullifier": self.nullifier,
            "inclusion_proof_root": self.inclusion_proof_root,
            "status": format!("{:?}", self.status),
            "receipt_root": self.receipt_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub nullifier: String,
    pub domain: String,
    pub min_decoys: u64,
    pub privacy_set_size: u64,
    pub pq_auth_root: String,
    pub fence_root: String,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "nullifier": self.nullifier,
            "domain": self.domain,
            "min_decoys": self.min_decoys,
            "privacy_set_size": self.privacy_set_size,
            "pq_auth_root": self.pq_auth_root,
            "fence_root": self.fence_root
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub network: String,
    pub monero_network: String,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub markets: BTreeMap<String, FeeMarketRecord>,
    pub positions: BTreeMap<String, HedgePositionRecord>,
    pub sponsor_pools: BTreeMap<String, SponsorPoolRecord>,
    pub proof_vol_surfaces: BTreeMap<String, ProofMarketVolatilityRecord>,
    pub da_blob_hedges: BTreeMap<String, DaBlobPriceHedgeRecord>,
    pub exit_ladders: BTreeMap<String, BridgeExitFeeSmoothingRecord>,
    pub netting_rounds: BTreeMap<String, MultiAssetNettingRecord>,
    pub user_caps: BTreeMap<String, UserCapRecord>,
    pub pq_rolls: BTreeMap<String, PqAuthenticatedRollRecord>,
    pub clearing_batches: BTreeMap<String, PrivateClearingBatchRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceiptRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        network: impl Into<String>,
        monero_network: impl Into<String>,
    ) -> Self {
        Self {
            config,
            network: network.into(),
            monero_network: monero_network.into(),
            height: 0,
            epoch: 0,
            counters: Counters::default(),
            markets: BTreeMap::new(),
            positions: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            proof_vol_surfaces: BTreeMap::new(),
            da_blob_hedges: BTreeMap::new(),
            exit_ladders: BTreeMap::new(),
            netting_rounds: BTreeMap::new(),
            user_caps: BTreeMap::new(),
            pq_rolls: BTreeMap::new(),
            clearing_batches: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_L2_NETWORK, DEVNET_MONERO_NETWORK);
        state.height = DEVNET_HEIGHT;
        state.epoch = DEVNET_EPOCH;
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let market = FeeMarketRequest {
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            risk_kind: FeeRiskKind::ProofMarket,
            base_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            maturity_height: DEVNET_HEIGHT + 720,
            strike_micro_fee: 42,
            oracle_commitment: "oracle:devnet:proof-fee-surface".to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_notional: 5_000_000,
        };
        let _ = state.open_market(market);
        let pool = SponsorPoolRequest {
            pool_id: "sponsor-pool-devnet-low-fee".to_string(),
            sponsor_commitment: "commitment:sponsor:devnet".to_string(),
            asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            reserve_amount: 2_000_000,
            cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            max_fee_cap_micro: 80,
            hedged_market_ids: vec!["fee-market-devnet-proof-da-exit".to_string()],
            sealed_policy_root: "sealed:sponsor-policy:devnet".to_string(),
            pq_auth_root: "pq:sponsor:auth:devnet".to_string(),
        };
        let _ = state.register_sponsor_pool(pool);
        let cap = UserCapRequest {
            cap_id: "cap-user-devnet-001".to_string(),
            owner_commitment: "commitment:user:001".to_string(),
            asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            max_fee_micro: 96,
            epoch: DEVNET_EPOCH,
            sponsor_pool_id: "sponsor-pool-devnet-low-fee".to_string(),
            cap_nullifier: "nullifier:cap:001".to_string(),
        };
        let _ = state.register_user_cap(cap);
        let position = HedgePositionRequest {
            position_id: "position-devnet-user-cap-proof-fee".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            owner_commitment: "commitment:user:001".to_string(),
            instrument: InstrumentKind::FeeCall,
            side: HedgeSide::BuyCap,
            notional: 250_000,
            premium: 480,
            margin: 40_000,
            user_fee_cap_micro: 96,
            cap_mode: CapMode::SponsorOverflow,
            nullifier: "nullifier:position:001".to_string(),
            sealed_terms_root: "sealed:position:terms:001".to_string(),
            pq_auth_root: "pq:position:auth:001".to_string(),
        };
        let _ = state.submit_position(position);
        let vol = ProofMarketVolatilityRequest {
            surface_id: "proof-vol-surface-devnet".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            prover_class: "recursive-pq-proof".to_string(),
            base_vol_bps: 1_200,
            stress_vol_bps: 2_600,
            depth_commitment: "depth:proof-market:devnet".to_string(),
            proof_latency_commitment: "latency:proof-market:devnet".to_string(),
            pq_oracle_root: "pq:oracle:proof-vol:devnet".to_string(),
        };
        let _ = state.record_proof_market_volatility(vol);
        let da = DaBlobPriceHedgeRequest {
            hedge_id: "da-blob-hedge-devnet".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            blob_lane: "celestia-devnet-private-lane".to_string(),
            blob_count: 12,
            fixed_blob_price_micro: 18,
            max_blob_price_micro: 30,
            da_commitment_root: "da:commitment:devnet".to_string(),
            pq_auth_root: "pq:da-hedge:devnet".to_string(),
        };
        let _ = state.record_da_blob_price_hedge(da);
        let ladder = BridgeExitFeeSmoothingRequest {
            ladder_id: "exit-ladder-devnet".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            bridge_domain: "monero-exit-devnet".to_string(),
            target_exit_fee_micro: 44,
            smoothing_bps: DEFAULT_EXIT_SMOOTHING_BPS,
            tranche_count: 8,
            exit_queue_commitment: "exit-queue:devnet".to_string(),
            sponsor_pool_id: "sponsor-pool-devnet-low-fee".to_string(),
        };
        let _ = state.record_bridge_exit_fee_smoothing(ladder);
        let mut exposures = BTreeMap::new();
        exposures.insert(DEVNET_QUOTE_ASSET_ID.to_string(), 120_000);
        exposures.insert(DEVNET_FEE_ASSET_ID.to_string(), -80_000);
        let mut conversions = BTreeMap::new();
        conversions.insert(
            DEVNET_QUOTE_ASSET_ID.to_string(),
            "oracle:quote:devnet".to_string(),
        );
        conversions.insert(
            DEVNET_FEE_ASSET_ID.to_string(),
            "oracle:fee:devnet".to_string(),
        );
        let netting = MultiAssetNettingRequest {
            round_id: "netting-round-devnet".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            asset_exposures: exposures,
            conversion_roots: conversions,
            participant_commitments: vec!["commitment:user:001".to_string()],
            sealed_netting_proof_root: "sealed:netting:devnet".to_string(),
        };
        let _ = state.record_multi_asset_netting(netting);
        let batch = PrivateClearingBatchRequest {
            batch_id: "clearing-batch-devnet".to_string(),
            market_id: "fee-market-devnet-proof-da-exit".to_string(),
            position_ids: vec!["position-devnet-user-cap-proof-fee".to_string()],
            netting_round_id: "netting-round-devnet".to_string(),
            clearing_price_micro: 52,
            realized_fee_micro: 62,
            sealed_batch_proof_root: "sealed:clearing:devnet".to_string(),
            operator_pq_auth_root: "pq:operator:clearing:devnet".to_string(),
        };
        let _ = state.clear_private_batch(batch);
        let receipt = SettlementReceiptRequest {
            receipt_id: "receipt-devnet-user-001".to_string(),
            batch_id: "clearing-batch-devnet".to_string(),
            beneficiary_commitment: "commitment:user:001".to_string(),
            position_id: "position-devnet-user-cap-proof-fee".to_string(),
            asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            settled_amount_micro: 2_500,
            rebate_micro: 15,
            cap_adjustment_micro: 0,
            nullifier: "nullifier:receipt:001".to_string(),
            inclusion_proof_root: "inclusion:receipt:001".to_string(),
        };
        let _ = state.issue_settlement_receipt(receipt);
        state
    }

    pub fn open_market(&mut self, request: FeeMarketRequest) -> Result<String> {
        ensure!(!request.market_id.is_empty(), "market id is required");
        ensure!(
            !self.markets.contains_key(&request.market_id),
            "market {} already exists",
            request.market_id
        );
        ensure!(
            self.markets.len() < self.config.max_markets,
            "market limit reached"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below minimum"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits below minimum"
        );
        ensure!(
            request.maturity_height > self.height,
            "maturity must be in the future"
        );
        let mut record = FeeMarketRecord {
            market_id: request.market_id.clone(),
            risk_kind: request.risk_kind,
            base_asset_id: request.base_asset_id,
            quote_asset_id: request.quote_asset_id,
            open_height: self.height,
            maturity_height: request.maturity_height,
            strike_micro_fee: request.strike_micro_fee,
            oracle_commitment: request.oracle_commitment,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            max_notional: request.max_notional,
            open_notional: 0,
            matched_notional: 0,
            cleared_notional: 0,
            status: MarketStatus::Open,
            market_root: String::new(),
        };
        record.market_root = record_root("FEE-MARKET", &record.public_record());
        self.markets.insert(record.market_id.clone(), record);
        self.counters.markets = self.counters.markets.saturating_add(1);
        Ok(self.state_root())
    }

    pub fn submit_position(&mut self, request: HedgePositionRequest) -> Result<String> {
        ensure!(!request.position_id.is_empty(), "position id is required");
        ensure!(
            !self.positions.contains_key(&request.position_id),
            "position {} already exists",
            request.position_id
        );
        ensure!(
            self.positions.len() < self.config.max_positions,
            "position limit reached"
        );
        ensure!(
            !self.spent_nullifiers.contains(&request.nullifier),
            "position nullifier already spent"
        );
        let market = self
            .markets
            .get_mut(&request.market_id)
            .ok_or_else(|| format!("market {} missing", request.market_id))?;
        ensure!(
            market.status.accepts_positions(),
            "market does not accept positions"
        );
        ensure!(
            market.open_notional.saturating_add(request.notional) <= market.max_notional,
            "market notional limit exceeded"
        );
        let required_margin = bps(request.notional, self.config.initial_margin_bps);
        ensure!(
            request.margin >= required_margin,
            "initial margin below configured minimum"
        );
        let mut effective_cap = request.user_fee_cap_micro;
        let mut status = PositionStatus::Admitted;
        if request.user_fee_cap_micro > self.config.base_fee_micro_units
            && request.user_fee_cap_micro > market.strike_micro_fee.saturating_mul(2)
        {
            match request.cap_mode {
                CapMode::HardReject => {
                    self.counters.rejected_requests =
                        self.counters.rejected_requests.saturating_add(1);
                    return Err("user fee cap exceeds conservative low-fee envelope".to_string());
                }
                CapMode::ClampToCap => {
                    effective_cap = market.strike_micro_fee.saturating_mul(2);
                    status = PositionStatus::CapClamped;
                    self.counters.cap_adjustments = self.counters.cap_adjustments.saturating_add(1);
                }
                CapMode::SponsorOverflow => {
                    effective_cap = request.user_fee_cap_micro;
                }
            }
        }
        let mut record = HedgePositionRecord {
            position_id: request.position_id.clone(),
            market_id: request.market_id.clone(),
            owner_commitment: request.owner_commitment,
            instrument: request.instrument,
            side: request.side,
            notional: request.notional,
            premium: request.premium,
            margin: request.margin,
            user_fee_cap_micro: request.user_fee_cap_micro,
            effective_fee_cap_micro: effective_cap,
            cap_mode: request.cap_mode,
            nullifier: request.nullifier.clone(),
            sealed_terms_root: request.sealed_terms_root,
            pq_auth_root: request.pq_auth_root,
            admitted_height: self.height,
            status,
            settlement_delta: 0,
            position_root: String::new(),
        };
        record.position_root = record_root("HEDGE-POSITION", &record.public_record());
        market.open_notional = market.open_notional.saturating_add(record.notional);
        market.matched_notional = market.matched_notional.saturating_add(record.notional);
        self.spent_nullifiers.insert(request.nullifier);
        self.counters.positions = self.counters.positions.saturating_add(1);
        self.counters.total_notional = self
            .counters
            .total_notional
            .saturating_add(record.notional as u128);
        self.counters.total_margin = self
            .counters
            .total_margin
            .saturating_add(record.margin as u128);
        self.positions.insert(record.position_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn register_sponsor_pool(&mut self, request: SponsorPoolRequest) -> Result<String> {
        ensure!(!request.pool_id.is_empty(), "pool id is required");
        ensure!(
            !self.sponsor_pools.contains_key(&request.pool_id),
            "sponsor pool already exists"
        );
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool limit reached"
        );
        ensure!(request.cover_bps <= MAX_BPS, "cover bps exceeds max");
        let reserve_floor = bps(request.reserve_amount, self.config.sponsor_reserve_bps);
        ensure!(
            request.reserve_amount >= reserve_floor,
            "reserve is below sponsor reserve floor"
        );
        let mut record = SponsorPoolRecord {
            pool_id: request.pool_id,
            sponsor_commitment: request.sponsor_commitment,
            asset_id: request.asset_id,
            reserve_amount: request.reserve_amount,
            allocated_amount: 0,
            cover_bps: request.cover_bps,
            max_fee_cap_micro: request.max_fee_cap_micro,
            hedged_market_ids: request.hedged_market_ids,
            sealed_policy_root: request.sealed_policy_root,
            pq_auth_root: request.pq_auth_root,
            status: PoolStatus::Active,
            pool_root: String::new(),
        };
        record.pool_root = record_root("SPONSOR-POOL", &record.public_record());
        self.counters.sponsor_pools = self.counters.sponsor_pools.saturating_add(1);
        self.sponsor_pools.insert(record.pool_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn record_proof_market_volatility(
        &mut self,
        request: ProofMarketVolatilityRequest,
    ) -> Result<String> {
        ensure!(
            self.proof_vol_surfaces.len() < self.config.max_vol_surfaces,
            "vol surface limit reached"
        );
        ensure!(
            self.markets.contains_key(&request.market_id),
            "market missing"
        );
        ensure!(
            request.stress_vol_bps >= request.base_vol_bps,
            "stress vol below base vol"
        );
        let mut record = ProofMarketVolatilityRecord {
            surface_id: request.surface_id,
            market_id: request.market_id,
            prover_class: request.prover_class,
            base_vol_bps: request.base_vol_bps,
            stress_vol_bps: request.stress_vol_bps,
            haircut_bps: self.config.proof_vol_haircut_bps,
            depth_commitment: request.depth_commitment,
            proof_latency_commitment: request.proof_latency_commitment,
            pq_oracle_root: request.pq_oracle_root,
            surface_root: String::new(),
        };
        record.surface_root = record_root("PROOF-MARKET-VOLATILITY", &record.public_record());
        self.counters.proof_vol_surfaces = self.counters.proof_vol_surfaces.saturating_add(1);
        self.proof_vol_surfaces
            .insert(record.surface_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn record_da_blob_price_hedge(
        &mut self,
        request: DaBlobPriceHedgeRequest,
    ) -> Result<String> {
        ensure!(
            self.da_blob_hedges.len() < self.config.max_da_hedges,
            "da hedge limit reached"
        );
        ensure!(
            self.markets.contains_key(&request.market_id),
            "market missing"
        );
        ensure!(
            request.max_blob_price_micro >= request.fixed_blob_price_micro,
            "max blob price below fixed"
        );
        let mut record = DaBlobPriceHedgeRecord {
            hedge_id: request.hedge_id,
            market_id: request.market_id,
            blob_lane: request.blob_lane,
            blob_count: request.blob_count,
            fixed_blob_price_micro: request.fixed_blob_price_micro,
            max_blob_price_micro: request.max_blob_price_micro,
            haircut_bps: self.config.da_blob_haircut_bps,
            da_commitment_root: request.da_commitment_root,
            pq_auth_root: request.pq_auth_root,
            hedge_root: String::new(),
        };
        record.hedge_root = record_root("DA-BLOB-PRICE-HEDGE", &record.public_record());
        self.counters.da_blob_hedges = self.counters.da_blob_hedges.saturating_add(1);
        self.da_blob_hedges.insert(record.hedge_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn record_bridge_exit_fee_smoothing(
        &mut self,
        request: BridgeExitFeeSmoothingRequest,
    ) -> Result<String> {
        ensure!(
            self.exit_ladders.len() < self.config.max_exit_ladders,
            "exit ladder limit reached"
        );
        ensure!(
            self.markets.contains_key(&request.market_id),
            "market missing"
        );
        ensure!(
            self.sponsor_pools.contains_key(&request.sponsor_pool_id),
            "sponsor pool missing"
        );
        ensure!(
            request.smoothing_bps <= MAX_BPS,
            "smoothing bps exceeds max"
        );
        let mut record = BridgeExitFeeSmoothingRecord {
            ladder_id: request.ladder_id,
            market_id: request.market_id,
            bridge_domain: request.bridge_domain,
            target_exit_fee_micro: request.target_exit_fee_micro,
            smoothing_bps: request.smoothing_bps,
            tranche_count: request.tranche_count,
            exit_queue_commitment: request.exit_queue_commitment,
            sponsor_pool_id: request.sponsor_pool_id,
            ladder_root: String::new(),
        };
        record.ladder_root = record_root("BRIDGE-EXIT-FEE-SMOOTHING", &record.public_record());
        self.counters.exit_smoothing_ladders =
            self.counters.exit_smoothing_ladders.saturating_add(1);
        self.exit_ladders.insert(record.ladder_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn record_multi_asset_netting(
        &mut self,
        request: MultiAssetNettingRequest,
    ) -> Result<String> {
        ensure!(
            self.netting_rounds.len() < self.config.max_netting_rounds,
            "netting round limit reached"
        );
        ensure!(
            self.markets.contains_key(&request.market_id),
            "market missing"
        );
        ensure!(
            !request.asset_exposures.is_empty(),
            "asset exposures required"
        );
        let gross_abs_exposure = request
            .asset_exposures
            .values()
            .fold(0u128, |acc, amount| acc.saturating_add(abs_i128(*amount)));
        let net_sum = request
            .asset_exposures
            .values()
            .fold(0i128, |acc, amount| acc.saturating_add(*amount));
        let mut record = MultiAssetNettingRecord {
            round_id: request.round_id,
            market_id: request.market_id,
            asset_exposures: request.asset_exposures,
            conversion_roots: request.conversion_roots,
            participant_count: request.participant_commitments.len() as u64,
            participant_commitments: request.participant_commitments,
            gross_abs_exposure,
            net_abs_exposure: abs_i128(net_sum),
            sealed_netting_proof_root: request.sealed_netting_proof_root,
            netting_root: String::new(),
        };
        record.netting_root = record_root("MULTI-ASSET-NETTING", &record.public_record());
        self.counters.netting_rounds = self.counters.netting_rounds.saturating_add(1);
        self.netting_rounds.insert(record.round_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn register_user_cap(&mut self, request: UserCapRequest) -> Result<String> {
        ensure!(
            self.user_caps.len() < self.config.max_caps,
            "user cap limit reached"
        );
        ensure!(
            !self.user_caps.contains_key(&request.cap_id),
            "cap already exists"
        );
        ensure!(
            !self.spent_nullifiers.contains(&request.cap_nullifier),
            "cap nullifier already spent"
        );
        let mut record = UserCapRecord {
            cap_id: request.cap_id,
            owner_commitment: request.owner_commitment,
            asset_id: request.asset_id,
            max_fee_micro: request.max_fee_micro,
            used_fee_micro: 0,
            overflow_sponsored_micro: 0,
            epoch: request.epoch,
            sponsor_pool_id: request.sponsor_pool_id,
            cap_nullifier: request.cap_nullifier.clone(),
            cap_root: String::new(),
        };
        record.cap_root = record_root("USER-CAP", &record.public_record());
        self.spent_nullifiers.insert(request.cap_nullifier);
        self.counters.user_caps = self.counters.user_caps.saturating_add(1);
        self.user_caps.insert(record.cap_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn enforce_user_cap(&mut self, cap_id: &str, fee_micro: u64) -> Result<u64> {
        let cap = self
            .user_caps
            .get_mut(cap_id)
            .ok_or_else(|| format!("cap {} missing", cap_id))?;
        let next_used = cap.used_fee_micro.saturating_add(fee_micro);
        if next_used <= cap.max_fee_micro {
            cap.used_fee_micro = next_used;
            cap.cap_root = record_root("USER-CAP", &cap.public_record());
            return Ok(0);
        }
        let overflow = next_used.saturating_sub(cap.max_fee_micro);
        cap.used_fee_micro = cap.max_fee_micro;
        cap.overflow_sponsored_micro = cap.overflow_sponsored_micro.saturating_add(overflow);
        cap.cap_root = record_root("USER-CAP", &cap.public_record());
        self.counters.cap_adjustments = self.counters.cap_adjustments.saturating_add(1);
        Ok(overflow)
    }

    pub fn authenticate_hedge_roll(
        &mut self,
        request: PqAuthenticatedRollRequest,
    ) -> Result<String> {
        ensure!(
            self.pq_rolls.len() < self.config.max_rolls,
            "pq roll limit reached"
        );
        ensure!(
            !self.pq_rolls.contains_key(&request.roll_id),
            "roll already exists"
        );
        let old = self
            .positions
            .get_mut(&request.old_position_id)
            .ok_or_else(|| format!("old position {} missing", request.old_position_id))?;
        ensure!(old.status.active(), "old position is not rollable");
        ensure!(
            old.position_root == request.previous_position_root,
            "previous position root mismatch"
        );
        old.status = PositionStatus::Rolled;
        old.position_root = record_root("HEDGE-POSITION", &old.public_record());
        let mut record = PqAuthenticatedRollRecord {
            roll_id: request.roll_id,
            old_position_id: request.old_position_id,
            new_position_id: request.new_position_id,
            intent: request.intent,
            new_maturity_height: request.new_maturity_height,
            new_notional: request.new_notional,
            new_strike_micro_fee: request.new_strike_micro_fee,
            roll_fee_micro: request.roll_fee_micro,
            pq_signature_root: request.pq_signature_root,
            previous_position_root: request.previous_position_root,
            accepted_height: self.height,
            roll_root: String::new(),
        };
        record.roll_root = record_root("PQ-AUTHENTICATED-ROLL", &record.public_record());
        self.counters.pq_rolls = self.counters.pq_rolls.saturating_add(1);
        self.pq_rolls.insert(record.roll_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn clear_private_batch(&mut self, request: PrivateClearingBatchRequest) -> Result<String> {
        ensure!(
            self.clearing_batches.len() < self.config.max_clearing_batches,
            "clearing batch limit reached"
        );
        ensure!(
            !self.clearing_batches.contains_key(&request.batch_id),
            "clearing batch exists"
        );
        ensure!(
            self.netting_rounds.contains_key(&request.netting_round_id),
            "netting round missing"
        );
        let market = self
            .markets
            .get_mut(&request.market_id)
            .ok_or_else(|| format!("market {} missing", request.market_id))?;
        ensure!(market.status.can_clear(), "market cannot clear");
        let mut gross_notional = 0u64;
        let mut net_delta = 0i128;
        for position_id in &request.position_ids {
            let position = self
                .positions
                .get_mut(position_id)
                .ok_or_else(|| format!("position {} missing", position_id))?;
            ensure!(
                position.market_id == request.market_id,
                "position market mismatch"
            );
            gross_notional = gross_notional.saturating_add(position.notional);
            let delta = position.side.signed_notional(
                request
                    .realized_fee_micro
                    .saturating_sub(request.clearing_price_micro),
            );
            position.settlement_delta = delta;
            position.status = PositionStatus::Clearing;
            position.position_root = record_root("HEDGE-POSITION", &position.public_record());
            net_delta = net_delta.saturating_add(delta);
        }
        let clearing_fee_micro = bps(gross_notional, self.config.clearing_fee_bps);
        let rebate_pool_micro = bps(gross_notional, self.config.protocol_rebate_bps);
        market.cleared_notional = market.cleared_notional.saturating_add(gross_notional);
        market.status = MarketStatus::Clearing;
        market.market_root = record_root("FEE-MARKET", &market.public_record());
        let mut record = PrivateClearingBatchRecord {
            batch_id: request.batch_id,
            market_id: request.market_id,
            position_ids: request.position_ids,
            netting_round_id: request.netting_round_id,
            clearing_price_micro: request.clearing_price_micro,
            realized_fee_micro: request.realized_fee_micro,
            gross_notional,
            net_delta,
            rebate_pool_micro,
            clearing_fee_micro,
            sealed_batch_proof_root: request.sealed_batch_proof_root,
            operator_pq_auth_root: request.operator_pq_auth_root,
            status: BatchStatus::Settling,
            batch_root: String::new(),
        };
        record.batch_root = record_root("PRIVATE-CLEARING-BATCH", &record.public_record());
        self.counters.clearing_batches = self.counters.clearing_batches.saturating_add(1);
        self.counters.total_rebates = self
            .counters
            .total_rebates
            .saturating_add(rebate_pool_micro as u128);
        self.clearing_batches
            .insert(record.batch_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn issue_settlement_receipt(
        &mut self,
        request: SettlementReceiptRequest,
    ) -> Result<String> {
        ensure!(
            self.settlement_receipts.len() < self.config.max_receipts,
            "receipt limit reached"
        );
        ensure!(
            !self.settlement_receipts.contains_key(&request.receipt_id),
            "receipt exists"
        );
        ensure!(
            !self.spent_nullifiers.contains(&request.nullifier),
            "receipt nullifier spent"
        );
        let batch = self
            .clearing_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| format!("batch {} missing", request.batch_id))?;
        ensure!(
            batch.position_ids.contains(&request.position_id),
            "position not in batch"
        );
        let position = self
            .positions
            .get_mut(&request.position_id)
            .ok_or_else(|| format!("position {} missing", request.position_id))?;
        position.status = PositionStatus::Settled;
        position.position_root = record_root("HEDGE-POSITION", &position.public_record());
        batch.status = BatchStatus::Receipted;
        batch.batch_root = record_root("PRIVATE-CLEARING-BATCH", &batch.public_record());
        let status = if request.cap_adjustment_micro > 0 {
            ReceiptStatus::CapAdjusted
        } else if request.rebate_micro > 0 {
            ReceiptStatus::Rebatable
        } else {
            ReceiptStatus::Final
        };
        let mut record = SettlementReceiptRecord {
            receipt_id: request.receipt_id,
            batch_id: request.batch_id,
            beneficiary_commitment: request.beneficiary_commitment,
            position_id: request.position_id,
            asset_id: request.asset_id,
            settled_amount_micro: request.settled_amount_micro,
            rebate_micro: request.rebate_micro,
            cap_adjustment_micro: request.cap_adjustment_micro,
            nullifier: request.nullifier.clone(),
            inclusion_proof_root: request.inclusion_proof_root,
            status,
            receipt_root: String::new(),
        };
        record.receipt_root = record_root("SETTLEMENT-RECEIPT", &record.public_record());
        self.spent_nullifiers.insert(request.nullifier);
        self.counters.settlement_receipts = self.counters.settlement_receipts.saturating_add(1);
        self.counters.total_settled = self
            .counters
            .total_settled
            .saturating_add(abs_i128(record.settled_amount_micro));
        self.settlement_receipts
            .insert(record.receipt_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn insert_privacy_fence(
        &mut self,
        fence_id: impl Into<String>,
        nullifier: impl Into<String>,
        domain: impl Into<String>,
        pq_auth_root: impl Into<String>,
    ) -> Result<String> {
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences,
            "privacy fence limit reached"
        );
        let nullifier = nullifier.into();
        ensure!(
            !self.spent_nullifiers.contains(&nullifier),
            "privacy fence nullifier spent"
        );
        let mut record = PrivacyFenceRecord {
            fence_id: fence_id.into(),
            nullifier: nullifier.clone(),
            domain: domain.into(),
            min_decoys: self.config.min_decoy_set_size,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_auth_root: pq_auth_root.into(),
            fence_root: String::new(),
        };
        record.fence_root = record_root("PRIVACY-FENCE", &record.public_record());
        self.spent_nullifiers.insert(nullifier);
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.privacy_fences.insert(record.fence_id.clone(), record);
        Ok(self.state_root())
    }

    pub fn roots(&self) -> Roots {
        let config_root = record_root("CONFIG", &self.config.public_record());
        let markets_root = map_root(
            "MARKETS",
            self.markets.values().map(|r| r.public_record()).collect(),
        );
        let positions_root = map_root(
            "POSITIONS",
            self.positions.values().map(|r| r.public_record()).collect(),
        );
        let sponsor_pools_root = map_root(
            "SPONSOR-POOLS",
            self.sponsor_pools
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let proof_vol_surfaces_root = map_root(
            "PROOF-VOL-SURFACES",
            self.proof_vol_surfaces
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let da_blob_hedges_root = map_root(
            "DA-BLOB-HEDGES",
            self.da_blob_hedges
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let exit_ladders_root = map_root(
            "EXIT-LADDERS",
            self.exit_ladders
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let netting_rounds_root = map_root(
            "NETTING-ROUNDS",
            self.netting_rounds
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let user_caps_root = map_root(
            "USER-CAPS",
            self.user_caps.values().map(|r| r.public_record()).collect(),
        );
        let pq_rolls_root = map_root(
            "PQ-ROLLS",
            self.pq_rolls.values().map(|r| r.public_record()).collect(),
        );
        let clearing_batches_root = map_root(
            "CLEARING-BATCHES",
            self.clearing_batches
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let receipts_root = map_root(
            "SETTLEMENT-RECEIPTS",
            self.settlement_receipts
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let privacy_fences_root = map_root(
            "PRIVACY-FENCES",
            self.privacy_fences
                .values()
                .map(|r| r.public_record())
                .collect(),
        );
        let counters_root = record_root("COUNTERS", &self.counters.public_record());
        let state_root = record_root(
            "STATE-WITHOUT-SELF-ROOT",
            &json!({
                "config_root": config_root,
                "markets_root": markets_root,
                "positions_root": positions_root,
                "sponsor_pools_root": sponsor_pools_root,
                "proof_vol_surfaces_root": proof_vol_surfaces_root,
                "da_blob_hedges_root": da_blob_hedges_root,
                "exit_ladders_root": exit_ladders_root,
                "netting_rounds_root": netting_rounds_root,
                "user_caps_root": user_caps_root,
                "pq_rolls_root": pq_rolls_root,
                "clearing_batches_root": clearing_batches_root,
                "receipts_root": receipts_root,
                "privacy_fences_root": privacy_fences_root,
                "counters_root": counters_root,
                "height": self.height,
                "epoch": self.epoch,
                "network": self.network,
                "monero_network": self.monero_network
            }),
        );
        Roots {
            config_root,
            markets_root,
            positions_root,
            sponsor_pools_root,
            proof_vol_surfaces_root,
            da_blob_hedges_root,
            exit_ladders_root,
            netting_rounds_root,
            user_caps_root,
            pq_rolls_root,
            clearing_batches_root,
            receipts_root,
            privacy_fences_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "module_protocol_version": PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_FEE_DERIVATIVE_HEDGING_RUNTIME_PROTOCOL_VERSION,
            "network": self.network,
            "monero_network": self.monero_network,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "state_root": self.state_root()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    State::demo().public_record()
}

pub fn state_root() -> String {
    State::demo().state_root()
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-DERIVATIVE-HEDGING-{}",
            domain
        ),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_public_record(record: &Value) -> String {
    record_root("PUBLIC-RECORD", record)
}

fn map_root(domain: &str, records: Vec<Value>) -> String {
    let leaves: Vec<Value> = records
        .iter()
        .map(|record| Value::String(record_root(domain, record)))
        .collect();
    merkle_root(
        &format!(
            "PRIVATE-L2-LOW-FEE-PQ-CONFIDENTIAL-FEE-DERIVATIVE-HEDGING-{}",
            domain
        ),
        &leaves,
    )
}

fn bps(amount: u64, rate_bps: u64) -> u64 {
    let value = (amount as u128).saturating_mul(rate_bps as u128) / (MAX_BPS as u128);
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

fn abs_i128(value: i128) -> u128 {
    if value < 0 {
        value.saturating_neg() as u128
    } else {
        value as u128
    }
}
