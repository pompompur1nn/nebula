use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-pq-confidential-rollup-fee-futures-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ROLLUP_FEE_FUTURES_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str = "ml-dsa-87+slh-dsa-shake-256f-low-fee-rollup-fee-futures-auth-v1";
pub const PQ_SEALING_SCHEME: &str =
    "ml-kem-1024+xwing-sealed-confidential-rollup-fee-futures-position-v1";
pub const FEE_FUTURES_PROTOCOL: &str = "monero-l2-pq-confidential-rollup-fee-futures-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_ROLLUP_FEE_FUTURES_RUNTIME_PROTOCOL: &str =
    FEE_FUTURES_PROTOCOL;
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-rollup-fee-rate-oracle-attestation-root-v1";
pub const ENCRYPTED_HEDGE_SCHEME: &str = "ringct-style-sealed-fee-futures-hedge-position-v1";
pub const SETTLEMENT_BAND_SCHEME: &str = "low-fee-private-settlement-band-root-v1";
pub const SPONSOR_POOL_SCHEME: &str = "low-fee-private-fee-futures-sponsor-pool-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "roots-only-private-rollup-fee-futures-rebate-coupon-v1";
pub const ROUTE_RECEIPT_SCHEME: &str = "pq-private-rollup-fee-futures-route-receipt-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-l2-fee-futures-privacy-fence-v1";
pub const CHALLENGE_SCHEME: &str = "private-rollup-fee-futures-liquidation-challenge-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str =
    "pq-private-fee-futures-sponsor-oracle-router-slasher-v1";
pub const DEVNET_HEIGHT: u64 = 1_744_320;
pub const DEVNET_EPOCH: u64 = 2_423;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_MARKET_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_POSITION_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_CHALLENGE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ROUTE_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_REBATE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MIN_FENCE_NULLIFIER_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 10;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 7;
pub const DEFAULT_MAKER_FEE_BPS: u64 = 1;
pub const DEFAULT_TAKER_FEE_BPS: u64 = 2;
pub const DEFAULT_ORACLE_FEE_BPS: u64 = 1;
pub const DEFAULT_ROUTER_FEE_BPS: u64 = 2;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_500;
pub const DEFAULT_REBATE_BPS: u64 = 5;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_LIQUIDATION_BPS: u64 = 9_250;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 750;
pub const DEFAULT_MAX_LEVERAGE_BPS: u64 = 50_000;
pub const DEFAULT_MAX_MARKETS: usize = 1_048_576;
pub const DEFAULT_MAX_POSITIONS: usize = 8_388_608;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_SETTLEMENT_BANDS: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 524_288;
pub const DEFAULT_MAX_REBATE_COUPONS: usize = 4_194_304;
pub const DEFAULT_MAX_ROUTE_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_LIQUIDATIONS: usize = 1_048_576;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    RollupGas,
    DataAvailability,
    ProverTime,
    SequencerTip,
    BridgeExit,
    BatchInclusion,
    PrivateTransfer,
    ContractCall,
    SponsorRelay,
    OracleUpdate,
}

impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RollupGas => "rollup_gas",
            Self::DataAvailability => "data_availability",
            Self::ProverTime => "prover_time",
            Self::SequencerTip => "sequencer_tip",
            Self::BridgeExit => "bridge_exit",
            Self::BatchInclusion => "batch_inclusion",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::SponsorRelay => "sponsor_relay",
            Self::OracleUpdate => "oracle_update",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketStatus {
    Proposed,
    Open,
    Auctioning,
    Hedging,
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
            Self::Proposed | Self::Open | Self::Auctioning | Self::Hedging
        )
    }

    pub fn can_settle(self) -> bool {
        matches!(self, Self::Open | Self::Hedging | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionSide {
    LongFee,
    ShortFee,
    SponsorCovered,
    RebateClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionStatus {
    Submitted,
    Admitted,
    Hedged,
    Settling,
    Settled,
    Rebated,
    Liquidating,
    Liquidated,
    Challenged,
    Rejected,
    Expired,
}

impl PositionStatus {
    pub fn hedgeable(self) -> bool {
        matches!(self, Self::Submitted | Self::Admitted | Self::Hedged)
    }

    pub fn can_liquidate(self) -> bool {
        matches!(self, Self::Admitted | Self::Hedged | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Submitted,
    Quorum,
    Usable,
    Superseded,
    Disputed,
    Expired,
    Slashed,
}

impl OracleStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Quorum | Self::Usable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBandStatus {
    Draft,
    Active,
    Settling,
    Settled,
    Disputed,
    Expired,
}

impl SettlementBandStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Proposed,
    Active,
    Settling,
    Exhausted,
    Paused,
    Slashed,
    Retired,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Routed,
    Redeemed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Proposed,
    Active,
    Sealed,
    Expired,
    Slashed,
}

impl FenceStatus {
    pub fn open(self) -> bool {
        matches!(self, Self::Proposed | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Open,
    Matched,
    Settled,
    Challenged,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingTarget {
    OracleCommittee,
    SponsorPool,
    Router,
    Liquidator,
    MarketMaker,
    SettlementOperator,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub fee_futures_protocol: String,
    pub epoch_blocks: u64,
    pub market_ttl_blocks: u64,
    pub position_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub route_receipt_finality_blocks: u64,
    pub rebate_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_fence_nullifier_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub oracle_fee_bps: u64,
    pub router_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub liquidation_bps: u64,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub max_leverage_bps: u64,
    pub max_markets: usize,
    pub max_positions: usize,
    pub max_oracle_attestations: usize,
    pub max_settlement_bands: usize,
    pub max_sponsor_pools: usize,
    pub max_rebate_coupons: usize,
    pub max_route_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_liquidations: usize,
    pub max_challenges: usize,
    pub max_slashes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            fee_futures_protocol: FEE_FUTURES_PROTOCOL.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            market_ttl_blocks: DEFAULT_MARKET_TTL_BLOCKS,
            position_ttl_blocks: DEFAULT_POSITION_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_ttl_blocks: DEFAULT_CHALLENGE_TTL_BLOCKS,
            route_receipt_finality_blocks: DEFAULT_ROUTE_RECEIPT_FINALITY_BLOCKS,
            rebate_window_blocks: DEFAULT_REBATE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_fence_nullifier_set_size: DEFAULT_MIN_FENCE_NULLIFIER_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            maker_fee_bps: DEFAULT_MAKER_FEE_BPS,
            taker_fee_bps: DEFAULT_TAKER_FEE_BPS,
            oracle_fee_bps: DEFAULT_ORACLE_FEE_BPS,
            router_fee_bps: DEFAULT_ROUTER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            liquidation_bps: DEFAULT_LIQUIDATION_BPS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            max_leverage_bps: DEFAULT_MAX_LEVERAGE_BPS,
            max_markets: DEFAULT_MAX_MARKETS,
            max_positions: DEFAULT_MAX_POSITIONS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_settlement_bands: DEFAULT_MAX_SETTLEMENT_BANDS,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_rebate_coupons: DEFAULT_MAX_REBATE_COUPONS,
            max_route_receipts: DEFAULT_MAX_ROUTE_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_liquidations: DEFAULT_MAX_LIQUIDATIONS,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_slashes: DEFAULT_MAX_SLASHES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch"
        );
        ensure!(self.chain_id == CHAIN_ID, "chain id mismatch");
        ensure!(self.hash_suite == HASH_SUITE, "hash suite mismatch");
        ensure!(
            self.min_pq_security_bits >= 256,
            "pq security below 256 bits"
        );
        ensure!(
            self.min_privacy_set_size <= self.target_privacy_set_size,
            "privacy set target below minimum"
        );
        ensure!(
            self.min_decoy_set_size <= self.target_privacy_set_size,
            "decoy set exceeds privacy target"
        );
        ensure!(self.max_user_fee_bps <= MAX_BPS, "max user fee bps invalid");
        ensure!(
            self.maker_fee_bps <= self.max_user_fee_bps,
            "maker fee too high"
        );
        ensure!(
            self.taker_fee_bps <= self.max_user_fee_bps,
            "taker fee too high"
        );
        ensure!(
            self.oracle_fee_bps <= self.max_user_fee_bps,
            "oracle fee too high"
        );
        ensure!(
            self.router_fee_bps <= self.max_user_fee_bps,
            "router fee too high"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps invalid"
        );
        ensure!(
            self.sponsor_reserve_bps <= MAX_BPS,
            "sponsor reserve bps invalid"
        );
        ensure!(self.rebate_bps <= MAX_BPS, "rebate bps invalid");
        ensure!(self.slash_bps <= MAX_BPS, "slash bps invalid");
        ensure!(self.liquidation_bps <= MAX_BPS, "liquidation bps invalid");
        ensure!(
            self.maintenance_margin_bps <= self.initial_margin_bps,
            "maintenance margin exceeds initial margin"
        );
        ensure!(self.max_leverage_bps >= MAX_BPS, "max leverage below 1x");
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_auth_scheme": self.pq_auth_scheme,
            "pq_sealing_scheme": self.pq_sealing_scheme,
            "fee_futures_protocol": self.fee_futures_protocol,
            "epoch_blocks": self.epoch_blocks,
            "market_ttl_blocks": self.market_ttl_blocks,
            "position_ttl_blocks": self.position_ttl_blocks,
            "oracle_ttl_blocks": self.oracle_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "route_receipt_finality_blocks": self.route_receipt_finality_blocks,
            "rebate_window_blocks": self.rebate_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "min_fence_nullifier_set_size": self.min_fence_nullifier_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_micro_units": self.base_fee_micro_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "oracle_fee_bps": self.oracle_fee_bps,
            "router_fee_bps": self.router_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "rebate_bps": self.rebate_bps,
            "slash_bps": self.slash_bps,
            "liquidation_bps": self.liquidation_bps,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "max_leverage_bps": self.max_leverage_bps,
            "max_markets": self.max_markets,
            "max_positions": self.max_positions,
            "max_oracle_attestations": self.max_oracle_attestations,
            "max_settlement_bands": self.max_settlement_bands,
            "max_sponsor_pools": self.max_sponsor_pools,
            "max_rebate_coupons": self.max_rebate_coupons,
            "max_route_receipts": self.max_route_receipts,
            "max_privacy_fences": self.max_privacy_fences,
            "max_liquidations": self.max_liquidations,
            "max_challenges": self.max_challenges,
            "max_slashes": self.max_slashes,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub markets_opened: u64,
    pub positions_submitted: u64,
    pub positions_hedged: u64,
    pub oracle_attestations: u64,
    pub settlement_bands: u64,
    pub sponsor_pools: u64,
    pub rebate_coupons: u64,
    pub route_receipts: u64,
    pub privacy_fences: u64,
    pub liquidations: u64,
    pub challenges: u64,
    pub slashes: u64,
    pub settlements: u64,
    pub total_notional_micro_units: u128,
    pub total_margin_micro_units: u128,
    pub total_sponsored_micro_units: u128,
    pub total_rebated_micro_units: u128,
    pub total_slashed_micro_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "markets_opened": self.markets_opened,
            "positions_submitted": self.positions_submitted,
            "positions_hedged": self.positions_hedged,
            "oracle_attestations": self.oracle_attestations,
            "settlement_bands": self.settlement_bands,
            "sponsor_pools": self.sponsor_pools,
            "rebate_coupons": self.rebate_coupons,
            "route_receipts": self.route_receipts,
            "privacy_fences": self.privacy_fences,
            "liquidations": self.liquidations,
            "challenges": self.challenges,
            "slashes": self.slashes,
            "settlements": self.settlements,
            "total_notional_micro_units": self.total_notional_micro_units.to_string(),
            "total_margin_micro_units": self.total_margin_micro_units.to_string(),
            "total_sponsored_micro_units": self.total_sponsored_micro_units.to_string(),
            "total_rebated_micro_units": self.total_rebated_micro_units.to_string(),
            "total_slashed_micro_units": self.total_slashed_micro_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub markets_root: String,
    pub positions_root: String,
    pub oracle_attestations_root: String,
    pub settlement_bands_root: String,
    pub sponsor_pools_root: String,
    pub rebate_coupons_root: String,
    pub route_receipts_root: String,
    pub privacy_fences_root: String,
    pub liquidations_root: String,
    pub challenges_root: String,
    pub slashing_evidence_root: String,
    pub latest_oracle_by_market_root: String,
    pub config_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "markets_root": self.markets_root,
            "positions_root": self.positions_root,
            "oracle_attestations_root": self.oracle_attestations_root,
            "settlement_bands_root": self.settlement_bands_root,
            "sponsor_pools_root": self.sponsor_pools_root,
            "rebate_coupons_root": self.rebate_coupons_root,
            "route_receipts_root": self.route_receipts_root,
            "privacy_fences_root": self.privacy_fences_root,
            "liquidations_root": self.liquidations_root,
            "challenges_root": self.challenges_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "latest_oracle_by_market_root": self.latest_oracle_by_market_root,
            "config_root": self.config_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROLLUP-FEE-FUTURES-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeFuturesMarket {
    pub market_id: String,
    pub market_kind: MarketKind,
    pub status: MarketStatus,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub fee_lane_root: String,
    pub rollup_domain_root: String,
    pub maturity_epoch: u64,
    pub settlement_band_id: Option<String>,
    pub last_oracle_attestation_id: Option<String>,
    pub open_interest_micro_units: u128,
    pub long_notional_micro_units: u128,
    pub short_notional_micro_units: u128,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub maker_fee_bps: u64,
    pub taker_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeFuturesMarket {
    pub fn public_record(&self) -> Value {
        json!({
            "market_id": self.market_id,
            "market_kind": self.market_kind,
            "status": self.status,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_lane_root": self.fee_lane_root,
            "rollup_domain_root": self.rollup_domain_root,
            "maturity_epoch": self.maturity_epoch,
            "settlement_band_id": self.settlement_band_id,
            "last_oracle_attestation_id": self.last_oracle_attestation_id,
            "open_interest_micro_units": self.open_interest_micro_units.to_string(),
            "long_notional_micro_units": self.long_notional_micro_units.to_string(),
            "short_notional_micro_units": self.short_notional_micro_units.to_string(),
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "maker_fee_bps": self.maker_fee_bps,
            "taker_fee_bps": self.taker_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("FEE-FUTURES-MARKET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedHedgePosition {
    pub position_id: String,
    pub market_id: String,
    pub owner_commitment: String,
    pub side: PositionSide,
    pub status: PositionStatus,
    pub notional_upper_bound_micro_units: u64,
    pub margin_commitment_root: String,
    pub hedge_commitment_root: String,
    pub ciphertext_root: String,
    pub nullifier_hash: String,
    pub range_proof_root: String,
    pub unlinkability_set_root: String,
    pub sponsor_pool_id: Option<String>,
    pub rebate_coupon_id: Option<String>,
    pub settlement_band_id: Option<String>,
    pub route_receipt_id: Option<String>,
    pub liquidation_id: Option<String>,
    pub leverage_bps: u64,
    pub privacy_set_size: u64,
    pub decoy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl EncryptedHedgePosition {
    pub fn public_record(&self) -> Value {
        json!({
            "position_id": self.position_id,
            "market_id": self.market_id,
            "owner_commitment": self.owner_commitment,
            "side": self.side,
            "status": self.status,
            "notional_upper_bound_micro_units": self.notional_upper_bound_micro_units,
            "margin_commitment_root": self.margin_commitment_root,
            "hedge_commitment_root": self.hedge_commitment_root,
            "ciphertext_root": self.ciphertext_root,
            "nullifier_hash": self.nullifier_hash,
            "range_proof_root": self.range_proof_root,
            "unlinkability_set_root": self.unlinkability_set_root,
            "sponsor_pool_id": self.sponsor_pool_id,
            "rebate_coupon_id": self.rebate_coupon_id,
            "settlement_band_id": self.settlement_band_id,
            "route_receipt_id": self.route_receipt_id,
            "liquidation_id": self.liquidation_id,
            "leverage_bps": self.leverage_bps,
            "privacy_set_size": self.privacy_set_size,
            "decoy_set_size": self.decoy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ENCRYPTED-HEDGE-POSITION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleRateAttestation {
    pub attestation_id: String,
    pub market_id: String,
    pub status: OracleStatus,
    pub oracle_committee_root: String,
    pub median_fee_rate_micro_units: u64,
    pub p05_fee_rate_micro_units: u64,
    pub p95_fee_rate_micro_units: u64,
    pub sample_window_start_height: u64,
    pub sample_window_end_height: u64,
    pub rollup_batch_root: String,
    pub da_cost_root: String,
    pub prover_cost_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub committee_weight: u64,
    pub quorum_weight: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqOracleRateAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "market_id": self.market_id,
            "status": self.status,
            "oracle_committee_root": self.oracle_committee_root,
            "median_fee_rate_micro_units": self.median_fee_rate_micro_units,
            "p05_fee_rate_micro_units": self.p05_fee_rate_micro_units,
            "p95_fee_rate_micro_units": self.p95_fee_rate_micro_units,
            "sample_window_start_height": self.sample_window_start_height,
            "sample_window_end_height": self.sample_window_end_height,
            "rollup_batch_root": self.rollup_batch_root,
            "da_cost_root": self.da_cost_root,
            "prover_cost_root": self.prover_cost_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "committee_weight": self.committee_weight,
            "quorum_weight": self.quorum_weight,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PQ-ORACLE-RATE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementBand {
    pub band_id: String,
    pub market_id: String,
    pub status: SettlementBandStatus,
    pub oracle_attestation_id: String,
    pub lower_rate_micro_units: u64,
    pub upper_rate_micro_units: u64,
    pub settlement_rate_micro_units: u64,
    pub max_payout_micro_units: u64,
    pub liquidity_root: String,
    pub proof_root: String,
    pub privacy_fence_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SettlementBand {
    pub fn public_record(&self) -> Value {
        json!({
            "band_id": self.band_id,
            "market_id": self.market_id,
            "status": self.status,
            "oracle_attestation_id": self.oracle_attestation_id,
            "lower_rate_micro_units": self.lower_rate_micro_units,
            "upper_rate_micro_units": self.upper_rate_micro_units,
            "settlement_rate_micro_units": self.settlement_rate_micro_units,
            "max_payout_micro_units": self.max_payout_micro_units,
            "liquidity_root": self.liquidity_root,
            "proof_root": self.proof_root,
            "privacy_fence_id": self.privacy_fence_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-BAND", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorPool {
    pub pool_id: String,
    pub market_id: String,
    pub status: SponsorStatus,
    pub sponsor_commitment: String,
    pub collateral_commitment_root: String,
    pub collateral_micro_units: u128,
    pub reserved_micro_units: u128,
    pub settled_micro_units: u128,
    pub cover_bps: u64,
    pub reserve_bps: u64,
    pub max_fee_rate_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_signature_root: String,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

impl SponsorPool {
    pub fn available_collateral(&self) -> u128 {
        self.collateral_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.settled_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "market_id": self.market_id,
            "status": self.status,
            "sponsor_commitment": self.sponsor_commitment,
            "collateral_commitment_root": self.collateral_commitment_root,
            "collateral_micro_units": self.collateral_micro_units.to_string(),
            "reserved_micro_units": self.reserved_micro_units.to_string(),
            "settled_micro_units": self.settled_micro_units.to_string(),
            "cover_bps": self.cover_bps,
            "reserve_bps": self.reserve_bps,
            "max_fee_rate_micro_units": self.max_fee_rate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_root": self.pq_signature_root,
            "opened_at_height": self.opened_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SPONSOR-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub market_id: String,
    pub position_id: String,
    pub status: CouponStatus,
    pub recipient_commitment_root: String,
    pub amount_micro_units: u64,
    pub coupon_commitment_root: String,
    pub nullifier_hash: String,
    pub route_receipt_id: Option<String>,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl RebateCoupon {
    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "status": self.status,
            "recipient_commitment_root": self.recipient_commitment_root,
            "amount_micro_units": self.amount_micro_units,
            "coupon_commitment_root": self.coupon_commitment_root,
            "nullifier_hash": self.nullifier_hash,
            "route_receipt_id": self.route_receipt_id,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("REBATE-COUPON", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub market_id: String,
    pub status: FenceStatus,
    pub nullifier_set_root: String,
    pub decoy_set_root: String,
    pub route_blinding_root: String,
    pub membership_proof_root: String,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "market_id": self.market_id,
            "status": self.status,
            "nullifier_set_root": self.nullifier_set_root,
            "decoy_set_root": self.decoy_set_root,
            "route_blinding_root": self.route_blinding_root,
            "membership_proof_root": self.membership_proof_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_decoy_set_size": self.min_decoy_set_size,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub position_id: Option<String>,
    pub coupon_id: Option<String>,
    pub router_commitment: String,
    pub route_root: String,
    pub fee_micro_units: u64,
    pub privacy_fence_id: Option<String>,
    pub finalized_at_height: u64,
    pub receipt_root: String,
}

impl RouteReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "coupon_id": self.coupon_id,
            "router_commitment": self.router_commitment,
            "route_root": self.route_root,
            "fee_micro_units": self.fee_micro_units,
            "privacy_fence_id": self.privacy_fence_id,
            "finalized_at_height": self.finalized_at_height,
            "receipt_root": self.receipt_root,
        })
    }

    pub fn root(&self) -> String {
        payload_root("ROUTE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidationFlow {
    pub liquidation_id: String,
    pub market_id: String,
    pub position_id: String,
    pub status: LiquidationStatus,
    pub liquidator_commitment: String,
    pub oracle_attestation_id: String,
    pub maintenance_margin_bps: u64,
    pub observed_margin_bps: u64,
    pub penalty_micro_units: u64,
    pub proof_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl LiquidationFlow {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_id": self.liquidation_id,
            "market_id": self.market_id,
            "position_id": self.position_id,
            "status": self.status,
            "liquidator_commitment": self.liquidator_commitment,
            "oracle_attestation_id": self.oracle_attestation_id,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "observed_margin_bps": self.observed_margin_bps,
            "penalty_micro_units": self.penalty_micro_units,
            "proof_root": self.proof_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("LIQUIDATION-FLOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeFlow {
    pub challenge_id: String,
    pub target_id: String,
    pub market_id: String,
    pub status: ChallengeStatus,
    pub challenger_commitment: String,
    pub bond_micro_units: u64,
    pub claim_root: String,
    pub rebuttal_root: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ChallengeFlow {
    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "target_id": self.target_id,
            "market_id": self.market_id,
            "status": self.status,
            "challenger_commitment": self.challenger_commitment,
            "bond_micro_units": self.bond_micro_units,
            "claim_root": self.claim_root,
            "rebuttal_root": self.rebuttal_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CHALLENGE-FLOW", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub market_id: String,
    pub target: SlashingTarget,
    pub target_id: String,
    pub evidence_root: String,
    pub transcript_root: String,
    pub slash_amount_micro_units: u64,
    pub slashed_at_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "market_id": self.market_id,
            "target": self.target,
            "target_id": self.target_id,
            "evidence_root": self.evidence_root,
            "transcript_root": self.transcript_root,
            "slash_amount_micro_units": self.slash_amount_micro_units,
            "slashed_at_height": self.slashed_at_height,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub markets: BTreeMap<String, FeeFuturesMarket>,
    pub positions: BTreeMap<String, EncryptedHedgePosition>,
    pub oracle_attestations: BTreeMap<String, PqOracleRateAttestation>,
    pub settlement_bands: BTreeMap<String, SettlementBand>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub rebate_coupons: BTreeMap<String, RebateCoupon>,
    pub route_receipts: BTreeMap<String, RouteReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub liquidations: BTreeMap<String, LiquidationFlow>,
    pub challenges: BTreeMap<String, ChallengeFlow>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub latest_oracle_by_market: BTreeMap<String, String>,
    pub position_nullifiers: BTreeSet<String>,
    pub coupon_nullifiers: BTreeSet<String>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, current_height: u64, current_epoch: u64) -> Self {
        Self {
            config,
            current_height,
            current_epoch,
            markets: BTreeMap::new(),
            positions: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            settlement_bands: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            route_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            liquidations: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            latest_oracle_by_market: BTreeMap::new(),
            position_nullifiers: BTreeSet::new(),
            coupon_nullifiers: BTreeSet::new(),
            counters: Counters::default(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let market_id = state
            .open_market(
                MarketKind::RollupGas,
                DEVNET_FEE_ASSET_ID.to_string(),
                DEVNET_QUOTE_ASSET_ID.to_string(),
                deterministic_root("devnet-fee-lane-root", &[HashPart::Str("rollup-gas")]),
                deterministic_root(
                    "devnet-rollup-domain-root",
                    &[HashPart::Str(DEVNET_L2_NETWORK)],
                ),
                DEVNET_EPOCH + 4,
                DEVNET_HEIGHT,
            )
            .expect("devnet market");
        let oracle_id = state
            .post_oracle_attestation(
                market_id.clone(),
                18,
                11,
                34,
                DEVNET_HEIGHT - 24,
                DEVNET_HEIGHT,
                deterministic_root("devnet-oracle-committee", &[HashPart::Str("committee")]),
                DEVNET_HEIGHT,
            )
            .expect("devnet oracle");
        let fence_id = state
            .open_privacy_fence(
                market_id.clone(),
                deterministic_root("devnet-nullifier-set", &[HashPart::Str("nullifiers")]),
                deterministic_root("devnet-decoy-set", &[HashPart::Str("decoys")]),
                DEVNET_HEIGHT,
            )
            .expect("devnet fence");
        let band_id = state
            .open_settlement_band(
                market_id.clone(),
                oracle_id.clone(),
                10,
                40,
                18,
                2_000_000,
                Some(fence_id.clone()),
                DEVNET_HEIGHT,
            )
            .expect("devnet settlement band");
        let pool_id = state
            .open_sponsor_pool(
                market_id.clone(),
                deterministic_root("devnet-sponsor", &[HashPart::Str("low-fee-sponsor")]),
                25_000_000,
                32,
                DEVNET_HEIGHT,
            )
            .expect("devnet sponsor pool");
        let position_id = state
            .submit_encrypted_position(
                market_id.clone(),
                PositionSide::LongFee,
                1_000_000,
                Some(pool_id),
                Some(band_id),
                Some(fence_id),
                DEVNET_HEIGHT,
            )
            .expect("devnet position");
        state
            .issue_route_receipt(
                market_id.clone(),
                Some(position_id.clone()),
                None,
                deterministic_root("devnet-router", &[HashPart::Str("router")]),
                deterministic_root("devnet-route", &[HashPart::Str("direct")]),
                DEVNET_HEIGHT + 8,
            )
            .expect("devnet route receipt");
        state
            .issue_rebate_coupon(
                position_id,
                deterministic_root("devnet-recipient", &[HashPart::Str("recipient")]),
                DEVNET_HEIGHT + 8,
            )
            .expect("devnet rebate");
        state
    }

    pub fn open_market(
        &mut self,
        market_kind: MarketKind,
        base_asset_id: String,
        quote_asset_id: String,
        fee_lane_root: String,
        rollup_domain_root: String,
        maturity_epoch: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.markets.len() < self.config.max_markets,
            "market capacity exceeded"
        );
        ensure!(!base_asset_id.is_empty(), "base asset id cannot be empty");
        ensure!(!quote_asset_id.is_empty(), "quote asset id cannot be empty");
        ensure!(
            maturity_epoch > self.current_epoch,
            "maturity epoch must be future"
        );
        let market_id = market_id(
            market_kind,
            &base_asset_id,
            &quote_asset_id,
            &fee_lane_root,
            maturity_epoch,
            self.counters.markets_opened,
        );
        ensure!(
            !self.markets.contains_key(&market_id),
            "market id collision: {market_id}"
        );
        let market = FeeFuturesMarket {
            market_id: market_id.clone(),
            market_kind,
            status: MarketStatus::Open,
            base_asset_id,
            quote_asset_id,
            fee_lane_root,
            rollup_domain_root,
            maturity_epoch,
            settlement_band_id: None,
            last_oracle_attestation_id: None,
            open_interest_micro_units: 0,
            long_notional_micro_units: 0,
            short_notional_micro_units: 0,
            initial_margin_bps: self.config.initial_margin_bps,
            maintenance_margin_bps: self.config.maintenance_margin_bps,
            maker_fee_bps: self.config.maker_fee_bps,
            taker_fee_bps: self.config.taker_fee_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.market_ttl_blocks),
        };
        self.markets.insert(market_id.clone(), market);
        self.counters.markets_opened = self.counters.markets_opened.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(market_id)
    }

    pub fn post_oracle_attestation(
        &mut self,
        market_id: String,
        median_fee_rate_micro_units: u64,
        p05_fee_rate_micro_units: u64,
        p95_fee_rate_micro_units: u64,
        sample_window_start_height: u64,
        sample_window_end_height: u64,
        oracle_committee_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.oracle_attestations.len() < self.config.max_oracle_attestations,
            "oracle attestation capacity exceeded"
        );
        let market = self
            .markets
            .get(&market_id)
            .ok_or_else(|| format!("unknown market: {market_id}"))?;
        ensure!(
            market.status.accepts_positions(),
            "market not oracle-active"
        );
        ensure!(
            p05_fee_rate_micro_units <= median_fee_rate_micro_units
                && median_fee_rate_micro_units <= p95_fee_rate_micro_units,
            "oracle quantiles are not ordered"
        );
        ensure!(
            sample_window_start_height <= sample_window_end_height,
            "oracle sample window invalid"
        );
        let attestation_id = oracle_attestation_id(
            &market_id,
            median_fee_rate_micro_units,
            sample_window_end_height,
            self.counters.oracle_attestations,
        );
        let attestation = PqOracleRateAttestation {
            attestation_id: attestation_id.clone(),
            market_id: market_id.clone(),
            status: OracleStatus::Usable,
            oracle_committee_root,
            median_fee_rate_micro_units,
            p05_fee_rate_micro_units,
            p95_fee_rate_micro_units,
            sample_window_start_height,
            sample_window_end_height,
            rollup_batch_root: deterministic_root(
                "oracle-rollup-batch-root",
                &[HashPart::Str(&attestation_id)],
            ),
            da_cost_root: deterministic_root(
                "oracle-da-cost-root",
                &[HashPart::Str(&attestation_id)],
            ),
            prover_cost_root: deterministic_root(
                "oracle-prover-cost-root",
                &[HashPart::Str(&attestation_id)],
            ),
            pq_signature_root: deterministic_root(
                "oracle-pq-signature-root",
                &[HashPart::Str(&attestation_id)],
            ),
            transcript_root: deterministic_root(
                "oracle-transcript-root",
                &[HashPart::Str(&attestation_id)],
            ),
            committee_weight: 100,
            quorum_weight: 67,
            posted_at_height: height,
            expires_at_height: height.saturating_add(self.config.oracle_ttl_blocks),
        };
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        self.latest_oracle_by_market
            .insert(market_id.clone(), attestation_id.clone());
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.last_oracle_attestation_id = Some(attestation_id.clone());
        }
        self.counters.oracle_attestations = self.counters.oracle_attestations.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(attestation_id)
    }

    pub fn open_settlement_band(
        &mut self,
        market_id: String,
        oracle_attestation_id: String,
        lower_rate_micro_units: u64,
        upper_rate_micro_units: u64,
        settlement_rate_micro_units: u64,
        max_payout_micro_units: u64,
        privacy_fence_id: Option<String>,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.settlement_bands.len() < self.config.max_settlement_bands,
            "settlement band capacity exceeded"
        );
        ensure!(
            lower_rate_micro_units <= settlement_rate_micro_units
                && settlement_rate_micro_units <= upper_rate_micro_units,
            "settlement rate outside band"
        );
        let oracle = self
            .oracle_attestations
            .get(&oracle_attestation_id)
            .ok_or_else(|| format!("unknown oracle attestation: {oracle_attestation_id}"))?;
        ensure!(oracle.market_id == market_id, "oracle market mismatch");
        ensure!(oracle.status.usable(), "oracle attestation not usable");
        ensure!(
            height <= oracle.expires_at_height,
            "oracle attestation expired"
        );
        if let Some(fence_id) = &privacy_fence_id {
            let fence = self
                .privacy_fences
                .get(fence_id)
                .ok_or_else(|| format!("unknown privacy fence: {fence_id}"))?;
            ensure!(
                fence.market_id == market_id,
                "privacy fence market mismatch"
            );
            ensure!(fence.status.open(), "privacy fence not open");
        }
        let band_id = settlement_band_id(
            &market_id,
            &oracle_attestation_id,
            lower_rate_micro_units,
            upper_rate_micro_units,
            self.counters.settlement_bands,
        );
        let band = SettlementBand {
            band_id: band_id.clone(),
            market_id: market_id.clone(),
            status: SettlementBandStatus::Active,
            oracle_attestation_id,
            lower_rate_micro_units,
            upper_rate_micro_units,
            settlement_rate_micro_units,
            max_payout_micro_units,
            liquidity_root: deterministic_root(
                "settlement-band-liquidity-root",
                &[HashPart::Str(&band_id)],
            ),
            proof_root: deterministic_root(
                "settlement-band-proof-root",
                &[HashPart::Str(&band_id)],
            ),
            privacy_fence_id,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.settlement_ttl_blocks),
        };
        self.settlement_bands.insert(band_id.clone(), band);
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.settlement_band_id = Some(band_id.clone());
            market.status = MarketStatus::Settling;
        }
        self.counters.settlement_bands = self.counters.settlement_bands.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(band_id)
    }

    pub fn open_sponsor_pool(
        &mut self,
        market_id: String,
        sponsor_commitment: String,
        collateral_micro_units: u128,
        max_fee_rate_micro_units: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool capacity exceeded"
        );
        ensure!(collateral_micro_units > 0, "collateral must be positive");
        let market = self
            .markets
            .get(&market_id)
            .ok_or_else(|| format!("unknown market: {market_id}"))?;
        ensure!(
            market.status.accepts_positions(),
            "market not sponsor-active"
        );
        let pool_id = sponsor_pool_id(&market_id, &sponsor_commitment, self.counters.sponsor_pools);
        let pool = SponsorPool {
            pool_id: pool_id.clone(),
            market_id,
            status: SponsorStatus::Active,
            sponsor_commitment,
            collateral_commitment_root: deterministic_root(
                "sponsor-collateral-root",
                &[HashPart::Str(&pool_id)],
            ),
            collateral_micro_units,
            reserved_micro_units: 0,
            settled_micro_units: 0,
            cover_bps: self.config.sponsor_cover_bps,
            reserve_bps: self.config.sponsor_reserve_bps,
            max_fee_rate_micro_units,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_signature_root: deterministic_root(
                "sponsor-pq-signature-root",
                &[HashPart::Str(&pool_id)],
            ),
            opened_at_height: height,
            updated_at_height: height,
        };
        self.sponsor_pools.insert(pool_id.clone(), pool);
        self.counters.sponsor_pools = self.counters.sponsor_pools.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(pool_id)
    }

    pub fn open_privacy_fence(
        &mut self,
        market_id: String,
        nullifier_set_root: String,
        decoy_set_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences,
            "privacy fence capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(&market_id),
            "unknown market: {market_id}"
        );
        let fence_id = privacy_fence_id(
            &market_id,
            &nullifier_set_root,
            self.counters.privacy_fences,
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            market_id,
            status: FenceStatus::Active,
            nullifier_set_root,
            decoy_set_root,
            route_blinding_root: deterministic_root(
                "privacy-route-blinding-root",
                &[HashPart::Str(&fence_id)],
            ),
            membership_proof_root: deterministic_root(
                "privacy-membership-proof-root",
                &[HashPart::Str(&fence_id)],
            ),
            min_privacy_set_size: self.config.min_privacy_set_size,
            min_decoy_set_size: self.config.min_decoy_set_size,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.position_ttl_blocks),
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        self.counters.privacy_fences = self.counters.privacy_fences.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(fence_id)
    }

    pub fn submit_encrypted_position(
        &mut self,
        market_id: String,
        side: PositionSide,
        notional_upper_bound_micro_units: u64,
        sponsor_pool_id: Option<String>,
        settlement_band_id: Option<String>,
        privacy_fence_id: Option<String>,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.positions.len() < self.config.max_positions,
            "position capacity exceeded"
        );
        ensure!(
            notional_upper_bound_micro_units > 0,
            "position notional must be positive"
        );
        let market = self
            .markets
            .get(&market_id)
            .ok_or_else(|| format!("unknown market: {market_id}"))?
            .clone();
        ensure!(
            market.status.accepts_positions(),
            "market not accepting positions"
        );
        ensure!(height <= market.expires_at_height, "market expired");
        if let Some(pool_id) = &sponsor_pool_id {
            let pool = self
                .sponsor_pools
                .get(pool_id)
                .ok_or_else(|| format!("unknown sponsor pool: {pool_id}"))?;
            ensure!(pool.market_id == market_id, "sponsor market mismatch");
            ensure!(pool.status.usable(), "sponsor pool not usable");
            let covered = bps_amount(notional_upper_bound_micro_units as u128, pool.cover_bps);
            let reserve = bps_amount(covered, pool.reserve_bps);
            ensure!(
                pool.available_collateral() >= covered.saturating_add(reserve),
                "sponsor pool undercollateralized"
            );
        }
        if let Some(band_id) = &settlement_band_id {
            let band = self
                .settlement_bands
                .get(band_id)
                .ok_or_else(|| format!("unknown settlement band: {band_id}"))?;
            ensure!(
                band.market_id == market_id,
                "settlement band market mismatch"
            );
            ensure!(band.status.usable(), "settlement band not usable");
        }
        if let Some(fence_id) = &privacy_fence_id {
            let fence = self
                .privacy_fences
                .get(fence_id)
                .ok_or_else(|| format!("unknown privacy fence: {fence_id}"))?;
            ensure!(
                fence.market_id == market_id,
                "privacy fence market mismatch"
            );
            ensure!(fence.status.open(), "privacy fence not open");
        }
        let nullifier_hash = deterministic_root(
            "position-nullifier",
            &[
                HashPart::Str(&market_id),
                HashPart::U64(self.counters.positions_submitted),
            ],
        );
        ensure!(
            !self.position_nullifiers.contains(&nullifier_hash),
            "duplicate position nullifier"
        );
        let position_id = position_id(
            &market_id,
            side,
            notional_upper_bound_micro_units,
            &nullifier_hash,
            self.counters.positions_submitted,
        );
        let position = EncryptedHedgePosition {
            position_id: position_id.clone(),
            market_id: market_id.clone(),
            owner_commitment: deterministic_root(
                "position-owner-commitment",
                &[HashPart::Str(&position_id)],
            ),
            side,
            status: PositionStatus::Admitted,
            notional_upper_bound_micro_units,
            margin_commitment_root: deterministic_root(
                "position-margin-root",
                &[HashPart::Str(&position_id)],
            ),
            hedge_commitment_root: deterministic_root(
                "position-hedge-root",
                &[HashPart::Str(&position_id)],
            ),
            ciphertext_root: deterministic_root(
                "position-ciphertext-root",
                &[HashPart::Str(&position_id)],
            ),
            nullifier_hash: nullifier_hash.clone(),
            range_proof_root: deterministic_root(
                "position-range-proof-root",
                &[HashPart::Str(&position_id)],
            ),
            unlinkability_set_root: deterministic_root(
                "position-unlinkability-root",
                &[HashPart::Str(&position_id)],
            ),
            sponsor_pool_id: sponsor_pool_id.clone(),
            rebate_coupon_id: None,
            settlement_band_id,
            route_receipt_id: None,
            liquidation_id: None,
            leverage_bps: self.config.max_leverage_bps.min(DEFAULT_MAX_LEVERAGE_BPS),
            privacy_set_size: self.config.target_privacy_set_size,
            decoy_set_size: self.config.min_decoy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(self.config.position_ttl_blocks),
        };
        self.positions.insert(position_id.clone(), position);
        self.position_nullifiers.insert(nullifier_hash);
        if let Some(market) = self.markets.get_mut(&market_id) {
            let notional = notional_upper_bound_micro_units as u128;
            market.open_interest_micro_units =
                market.open_interest_micro_units.saturating_add(notional);
            match side {
                PositionSide::LongFee | PositionSide::RebateClaim => {
                    market.long_notional_micro_units =
                        market.long_notional_micro_units.saturating_add(notional);
                }
                PositionSide::ShortFee | PositionSide::SponsorCovered => {
                    market.short_notional_micro_units =
                        market.short_notional_micro_units.saturating_add(notional);
                }
            }
            market.status = MarketStatus::Hedging;
        }
        if let Some(pool_id) = sponsor_pool_id {
            if let Some(pool) = self.sponsor_pools.get_mut(&pool_id) {
                let covered = bps_amount(notional_upper_bound_micro_units as u128, pool.cover_bps);
                let reserve = bps_amount(covered, pool.reserve_bps);
                pool.reserved_micro_units = pool
                    .reserved_micro_units
                    .saturating_add(covered.saturating_add(reserve));
                pool.updated_at_height = height;
            }
        }
        self.counters.positions_submitted = self.counters.positions_submitted.saturating_add(1);
        self.counters.total_notional_micro_units = self
            .counters
            .total_notional_micro_units
            .saturating_add(notional_upper_bound_micro_units as u128);
        self.counters.total_margin_micro_units = self
            .counters
            .total_margin_micro_units
            .saturating_add(bps_amount(
                notional_upper_bound_micro_units as u128,
                self.config.initial_margin_bps,
            ));
        self.current_height = self.current_height.max(height);
        Ok(position_id)
    }

    pub fn hedge_positions(
        &mut self,
        market_id: String,
        position_ids: Vec<String>,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(!position_ids.is_empty(), "position list cannot be empty");
        let mut leaves = Vec::with_capacity(position_ids.len());
        for position_id in &position_ids {
            let position = self
                .positions
                .get(position_id)
                .ok_or_else(|| format!("unknown position: {position_id}"))?;
            ensure!(position.market_id == market_id, "position market mismatch");
            ensure!(
                position.status.hedgeable(),
                "position not hedgeable: {position_id}"
            );
            ensure!(
                height <= position.expires_at_height,
                "position expired: {position_id}"
            );
            leaves.push(position.public_record());
        }
        let hedge_root = merkle_root("ROLLUP-FEE-FUTURES-HEDGE-BATCH", &leaves);
        for position_id in &position_ids {
            if let Some(position) = self.positions.get_mut(position_id) {
                position.status = PositionStatus::Hedged;
                position.hedge_commitment_root = hedge_root.clone();
            }
        }
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.status = MarketStatus::Hedging;
        }
        self.counters.positions_hedged = self
            .counters
            .positions_hedged
            .saturating_add(position_ids.len() as u64);
        self.current_height = self.current_height.max(height);
        Ok(hedge_root)
    }

    pub fn settle_market(&mut self, market_id: String, height: u64) -> Result<Vec<String>> {
        self.config.validate()?;
        let market = self
            .markets
            .get(&market_id)
            .ok_or_else(|| format!("unknown market: {market_id}"))?
            .clone();
        ensure!(market.status.can_settle(), "market cannot settle");
        let band_id = market
            .settlement_band_id
            .clone()
            .ok_or_else(|| "market has no settlement band".to_string())?;
        let band = self
            .settlement_bands
            .get(&band_id)
            .ok_or_else(|| format!("unknown settlement band: {band_id}"))?
            .clone();
        ensure!(band.status.usable(), "settlement band not usable");
        ensure!(height <= band.expires_at_height, "settlement band expired");
        let mut settled = Vec::new();
        for position in self.positions.values_mut() {
            if position.market_id == market_id && position.status == PositionStatus::Hedged {
                position.status = PositionStatus::Settled;
                position.settlement_band_id = Some(band_id.clone());
                settled.push(position.position_id.clone());
            }
        }
        if let Some(band) = self.settlement_bands.get_mut(&band_id) {
            band.status = SettlementBandStatus::Settled;
        }
        if let Some(market) = self.markets.get_mut(&market_id) {
            market.status = MarketStatus::Settled;
        }
        self.counters.settlements = self.counters.settlements.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(settled)
    }

    pub fn issue_rebate_coupon(
        &mut self,
        position_id: String,
        recipient_commitment_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.rebate_coupons.len() < self.config.max_rebate_coupons,
            "rebate coupon capacity exceeded"
        );
        let position = self
            .positions
            .get(&position_id)
            .ok_or_else(|| format!("unknown position: {position_id}"))?
            .clone();
        ensure!(
            matches!(
                position.status,
                PositionStatus::Admitted | PositionStatus::Hedged | PositionStatus::Settled
            ),
            "position cannot receive rebate"
        );
        let amount_micro_units = bps_amount(
            position.notional_upper_bound_micro_units as u128,
            self.config.rebate_bps,
        ) as u64;
        let nullifier_hash = deterministic_root(
            "rebate-coupon-nullifier",
            &[
                HashPart::Str(&position_id),
                HashPart::U64(self.counters.rebate_coupons),
            ],
        );
        ensure!(
            !self.coupon_nullifiers.contains(&nullifier_hash),
            "duplicate coupon nullifier"
        );
        let coupon_id = rebate_coupon_id(&position.market_id, &position_id, &nullifier_hash);
        let coupon = RebateCoupon {
            coupon_id: coupon_id.clone(),
            market_id: position.market_id.clone(),
            position_id: position_id.clone(),
            status: CouponStatus::Issued,
            recipient_commitment_root,
            amount_micro_units,
            coupon_commitment_root: deterministic_root(
                "rebate-coupon-commitment-root",
                &[HashPart::Str(&coupon_id)],
            ),
            nullifier_hash: nullifier_hash.clone(),
            route_receipt_id: None,
            issued_at_height: height,
            expires_at_height: height.saturating_add(self.config.rebate_window_blocks),
        };
        self.rebate_coupons.insert(coupon_id.clone(), coupon);
        self.coupon_nullifiers.insert(nullifier_hash);
        if let Some(position) = self.positions.get_mut(&position_id) {
            position.rebate_coupon_id = Some(coupon_id.clone());
            position.status = PositionStatus::Rebated;
        }
        self.counters.rebate_coupons = self.counters.rebate_coupons.saturating_add(1);
        self.counters.total_rebated_micro_units = self
            .counters
            .total_rebated_micro_units
            .saturating_add(amount_micro_units as u128);
        self.current_height = self.current_height.max(height);
        Ok(coupon_id)
    }

    pub fn issue_route_receipt(
        &mut self,
        market_id: String,
        position_id: Option<String>,
        coupon_id: Option<String>,
        router_commitment: String,
        route_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.route_receipts.len() < self.config.max_route_receipts,
            "route receipt capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(&market_id),
            "unknown market: {market_id}"
        );
        if let Some(position_id) = &position_id {
            let position = self
                .positions
                .get(position_id)
                .ok_or_else(|| format!("unknown position: {position_id}"))?;
            ensure!(
                position.market_id == market_id,
                "position route market mismatch"
            );
        }
        if let Some(coupon_id) = &coupon_id {
            let coupon = self
                .rebate_coupons
                .get(coupon_id)
                .ok_or_else(|| format!("unknown rebate coupon: {coupon_id}"))?;
            ensure!(
                coupon.market_id == market_id,
                "coupon route market mismatch"
            );
        }
        let fee_micro_units = self.config.base_fee_micro_units.saturating_add(bps_amount(
            self.config.base_fee_micro_units as u128,
            self.config.router_fee_bps,
        ) as u64);
        let receipt_id = route_receipt_id(
            &market_id,
            position_id.as_deref(),
            coupon_id.as_deref(),
            &router_commitment,
            self.counters.route_receipts,
        );
        let receipt_root = deterministic_root(
            "route-receipt-public-root",
            &[HashPart::Str(&receipt_id), HashPart::Str(&route_root)],
        );
        let receipt = RouteReceipt {
            receipt_id: receipt_id.clone(),
            market_id,
            position_id: position_id.clone(),
            coupon_id: coupon_id.clone(),
            router_commitment,
            route_root,
            fee_micro_units,
            privacy_fence_id: None,
            finalized_at_height: height.saturating_add(self.config.route_receipt_finality_blocks),
            receipt_root,
        };
        self.route_receipts.insert(receipt_id.clone(), receipt);
        if let Some(position_id) = position_id {
            if let Some(position) = self.positions.get_mut(&position_id) {
                position.route_receipt_id = Some(receipt_id.clone());
            }
        }
        if let Some(coupon_id) = coupon_id {
            if let Some(coupon) = self.rebate_coupons.get_mut(&coupon_id) {
                coupon.route_receipt_id = Some(receipt_id.clone());
                coupon.status = CouponStatus::Routed;
            }
        }
        self.counters.route_receipts = self.counters.route_receipts.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(receipt_id)
    }

    pub fn open_liquidation(
        &mut self,
        position_id: String,
        liquidator_commitment: String,
        observed_margin_bps: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.liquidations.len() < self.config.max_liquidations,
            "liquidation capacity exceeded"
        );
        let position = self
            .positions
            .get(&position_id)
            .ok_or_else(|| format!("unknown position: {position_id}"))?
            .clone();
        ensure!(position.status.can_liquidate(), "position cannot liquidate");
        let market = self
            .markets
            .get(&position.market_id)
            .ok_or_else(|| format!("unknown market: {}", position.market_id))?;
        ensure!(
            observed_margin_bps < market.maintenance_margin_bps,
            "position above maintenance margin"
        );
        let oracle_attestation_id = self
            .latest_oracle_by_market
            .get(&position.market_id)
            .ok_or_else(|| "missing oracle attestation".to_string())?
            .clone();
        let penalty_micro_units = bps_amount(
            position.notional_upper_bound_micro_units as u128,
            self.config.liquidation_bps,
        ) as u64;
        let liquidation_id = liquidation_id(
            &position.market_id,
            &position_id,
            self.counters.liquidations,
        );
        let liquidation = LiquidationFlow {
            liquidation_id: liquidation_id.clone(),
            market_id: position.market_id.clone(),
            position_id: position_id.clone(),
            status: LiquidationStatus::Open,
            liquidator_commitment,
            oracle_attestation_id,
            maintenance_margin_bps: market.maintenance_margin_bps,
            observed_margin_bps,
            penalty_micro_units,
            proof_root: deterministic_root(
                "liquidation-proof-root",
                &[HashPart::Str(&liquidation_id)],
            ),
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.challenge_ttl_blocks),
        };
        self.liquidations
            .insert(liquidation_id.clone(), liquidation);
        if let Some(position) = self.positions.get_mut(&position_id) {
            position.status = PositionStatus::Liquidating;
            position.liquidation_id = Some(liquidation_id.clone());
        }
        self.counters.liquidations = self.counters.liquidations.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(liquidation_id)
    }

    pub fn challenge_flow(
        &mut self,
        target_id: String,
        market_id: String,
        challenger_commitment: String,
        bond_micro_units: u64,
        claim_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.challenges.len() < self.config.max_challenges,
            "challenge capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(&market_id),
            "unknown market: {market_id}"
        );
        ensure!(bond_micro_units > 0, "challenge bond must be positive");
        let challenge_id = challenge_id(&market_id, &target_id, self.counters.challenges);
        let challenge = ChallengeFlow {
            challenge_id: challenge_id.clone(),
            target_id: target_id.clone(),
            market_id,
            status: ChallengeStatus::Open,
            challenger_commitment,
            bond_micro_units,
            claim_root,
            rebuttal_root: None,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.challenge_ttl_blocks),
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        if let Some(position) = self.positions.get_mut(&target_id) {
            position.status = PositionStatus::Challenged;
        }
        if let Some(liquidation) = self.liquidations.get_mut(&target_id) {
            liquidation.status = LiquidationStatus::Challenged;
        }
        self.counters.challenges = self.counters.challenges.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(challenge_id)
    }

    pub fn record_slashing_evidence(
        &mut self,
        market_id: String,
        target: SlashingTarget,
        target_id: String,
        evidence_root: String,
        transcript_root: String,
        slash_base_micro_units: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.slashing_evidence.len() < self.config.max_slashes,
            "slash capacity exceeded"
        );
        ensure!(
            self.markets.contains_key(&market_id),
            "unknown market: {market_id}"
        );
        let slash_amount_micro_units =
            bps_amount(slash_base_micro_units as u128, self.config.slash_bps) as u64;
        let evidence_id = slashing_evidence_id(&market_id, &target_id, self.counters.slashes);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            market_id,
            target,
            target_id: target_id.clone(),
            evidence_root,
            transcript_root,
            slash_amount_micro_units,
            slashed_at_height: height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        match target {
            SlashingTarget::SponsorPool => {
                if let Some(pool) = self.sponsor_pools.get_mut(&target_id) {
                    pool.status = SponsorStatus::Slashed;
                    pool.collateral_micro_units = pool
                        .collateral_micro_units
                        .saturating_sub(slash_amount_micro_units as u128);
                }
            }
            SlashingTarget::OracleCommittee => {
                if let Some(oracle) = self.oracle_attestations.get_mut(&target_id) {
                    oracle.status = OracleStatus::Slashed;
                }
            }
            SlashingTarget::Router
            | SlashingTarget::Liquidator
            | SlashingTarget::MarketMaker
            | SlashingTarget::SettlementOperator => {}
        }
        self.counters.slashes = self.counters.slashes.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(slash_amount_micro_units as u128);
        self.current_height = self.current_height.max(height);
        Ok(evidence_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            markets_root: map_root("ROLLUP-FEE-FUTURES-MARKETS", &self.markets, |market| {
                market.public_record()
            }),
            positions_root: map_root(
                "ROLLUP-FEE-FUTURES-POSITIONS",
                &self.positions,
                |position| position.public_record(),
            ),
            oracle_attestations_root: map_root(
                "ROLLUP-FEE-FUTURES-ORACLES",
                &self.oracle_attestations,
                |oracle| oracle.public_record(),
            ),
            settlement_bands_root: map_root(
                "ROLLUP-FEE-FUTURES-SETTLEMENT-BANDS",
                &self.settlement_bands,
                |band| band.public_record(),
            ),
            sponsor_pools_root: map_root(
                "ROLLUP-FEE-FUTURES-SPONSOR-POOLS",
                &self.sponsor_pools,
                |pool| pool.public_record(),
            ),
            rebate_coupons_root: map_root(
                "ROLLUP-FEE-FUTURES-REBATE-COUPONS",
                &self.rebate_coupons,
                |coupon| coupon.public_record(),
            ),
            route_receipts_root: map_root(
                "ROLLUP-FEE-FUTURES-ROUTE-RECEIPTS",
                &self.route_receipts,
                |receipt| receipt.public_record(),
            ),
            privacy_fences_root: map_root(
                "ROLLUP-FEE-FUTURES-PRIVACY-FENCES",
                &self.privacy_fences,
                |fence| fence.public_record(),
            ),
            liquidations_root: map_root(
                "ROLLUP-FEE-FUTURES-LIQUIDATIONS",
                &self.liquidations,
                |liquidation| liquidation.public_record(),
            ),
            challenges_root: map_root(
                "ROLLUP-FEE-FUTURES-CHALLENGES",
                &self.challenges,
                |challenge| challenge.public_record(),
            ),
            slashing_evidence_root: map_root(
                "ROLLUP-FEE-FUTURES-SLASHING-EVIDENCE",
                &self.slashing_evidence,
                |evidence| evidence.public_record(),
            ),
            latest_oracle_by_market_root: map_root(
                "ROLLUP-FEE-FUTURES-LATEST-ORACLE-BY-MARKET",
                &self.latest_oracle_by_market,
                |oracle_id| json!({ "oracle_attestation_id": oracle_id }),
            ),
            config_root: payload_root("ROLLUP-FEE-FUTURES-CONFIG", &self.config.public_record()),
            counters_root: payload_root(
                "ROLLUP-FEE-FUTURES-COUNTERS",
                &self.counters.public_record(),
            ),
        }
    }

    pub fn state_root(&self) -> String {
        payload_root("ROLLUP-FEE-FUTURES-STATE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_pq_confidential_rollup_fee_futures_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": self.counters.public_record(),
        })
    }
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn private_l2_low_fee_pq_confidential_rollup_fee_futures_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_rollup_fee_futures_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn market_id(
    market_kind: MarketKind,
    base_asset_id: &str,
    quote_asset_id: &str,
    fee_lane_root: &str,
    maturity_epoch: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-MARKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_kind.as_str()),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Str(fee_lane_root),
            HashPart::U64(maturity_epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn oracle_attestation_id(
    market_id: &str,
    median_fee_rate_micro_units: u64,
    sample_window_end_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-ORACLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::U64(median_fee_rate_micro_units),
            HashPart::U64(sample_window_end_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn settlement_band_id(
    market_id: &str,
    oracle_attestation_id: &str,
    lower_rate_micro_units: u64,
    upper_rate_micro_units: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-SETTLEMENT-BAND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(oracle_attestation_id),
            HashPart::U64(lower_rate_micro_units),
            HashPart::U64(upper_rate_micro_units),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn sponsor_pool_id(market_id: &str, sponsor_commitment: &str, nonce: u64) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-SPONSOR-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn privacy_fence_id(market_id: &str, nullifier_set_root: &str, nonce: u64) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(nullifier_set_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn position_id(
    market_id: &str,
    side: PositionSide,
    notional_upper_bound_micro_units: u64,
    nullifier_hash: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-POSITION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(match side {
                PositionSide::LongFee => "long_fee",
                PositionSide::ShortFee => "short_fee",
                PositionSide::SponsorCovered => "sponsor_covered",
                PositionSide::RebateClaim => "rebate_claim",
            }),
            HashPart::U64(notional_upper_bound_micro_units),
            HashPart::Str(nullifier_hash),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn rebate_coupon_id(market_id: &str, position_id: &str, nullifier_hash: &str) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-REBATE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

fn route_receipt_id(
    market_id: &str,
    position_id: Option<&str>,
    coupon_id: Option<&str>,
    router_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-ROUTE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id.unwrap_or("none")),
            HashPart::Str(coupon_id.unwrap_or("none")),
            HashPart::Str(router_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn liquidation_id(market_id: &str, position_id: &str, nonce: u64) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-LIQUIDATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(position_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn challenge_id(market_id: &str, target_id: &str, nonce: u64) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-CHALLENGE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(target_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn slashing_evidence_id(market_id: &str, target_id: &str, nonce: u64) -> String {
    domain_hash(
        "ROLLUP-FEE-FUTURES-SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(market_id),
            HashPart::Str(target_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}
