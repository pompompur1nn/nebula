use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedProverFailureInsuranceStructuredNoteLiquidityMiningRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-liquidity-mining-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_LIQUIDITY_MINING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_LIQUIDITY_MINING_AUTHORIZATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prover-failure-note-liquidity-mining-auth-v1";
pub const MINING_VENUE_SUITE: &str =
    "private-prover-failure-structured-note-liquidity-mining-venue-root-v1";
pub const ELIGIBLE_NOTE_MINING_SUITE: &str =
    "confidential-tokenized-prover-failure-structured-note-eligible-mining-root-v1";
pub const SEALED_LISTING_SUITE: &str =
    "sealed-confidential-prover-failure-structured-note-liquidity-mining-listing-root-v1";
pub const PRIVATE_RFQ_SUITE: &str =
    "private-prover-failure-structured-note-liquidity-mining-rfq-root-v1";
pub const ORDER_COMMITMENT_SUITE: &str =
    "pq-private-prover-failure-structured-note-liquidity-mining-order-commitment-root-v1";
pub const MATCH_INTENT_SUITE: &str =
    "confidential-prover-failure-structured-note-liquidity-mining-match-intent-root-v1";
pub const TRADE_FILL_SUITE: &str =
    "speedy-prover-failure-structured-note-liquidity-mining-trade-fill-root-v1";
pub const ATOMIC_SETTLEMENT_SUITE: &str =
    "low-fee-prover-failure-structured-note-liquidity-mining-atomic-settlement-root-v1";
pub const LIQUIDITY_LANE_SUITE: &str =
    "defi-prover-failure-structured-note-liquidity-mining-liquidity-lane-root-v1";
pub const PRICE_BAND_SUITE: &str =
    "privacy-preserving-prover-failure-structured-note-liquidity-mining-price-band-root-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "pq-prover-failure-structured-note-liquidity-mining-attestation-root-v1";
pub const FEE_REBATE_SUITE: &str =
    "low-fee-prover-failure-structured-note-liquidity-mining-fee-rebate-root-v1";
pub const INCENTIVE_CAMPAIGN_SUITE: &str =
    "defi-tokenized-prover-failure-structured-note-liquidity-mining-campaign-root-v1";
pub const MINING_POSITION_SUITE: &str =
    "confidential-tokenized-prover-failure-structured-note-liquidity-mining-position-root-v1";
pub const REWARD_EPOCH_SUITE: &str =
    "speedy-low-fee-prover-failure-structured-note-liquidity-mining-reward-epoch-root-v1";
pub const REWARD_CLAIM_SUITE: &str =
    "pq-private-prover-failure-structured-note-liquidity-mining-reward-claim-root-v1";
pub const NULLIFIER_SUITE: &str =
    "anti-replay-prover-failure-structured-note-liquidity-mining-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-prover-failure-insurance-structured-note-liquidity-mining-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-liquidity-mining-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-liquidity-mining-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-prover-failure-insurance-structured-note-liquidity-mining-devnet";
pub const DEVNET_RUNTIME_ID: &str =
    "private-l2-pq-prover-failure-insurance-structured-note-liquidity-mining-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_746_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_444_000;
pub const DEVNET_EPOCH: u64 = 25_616;
pub const DEVNET_NOTE_TOKEN_ID: &str = "tpfi-note-liquidity-mining-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_FAILURE_INDEX_ID: &str = "monero-private-l2-prover-failure-index-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_MATCHING_FEE_BPS: u64 = 2;
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = 1;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MINING_MAKER_QUORUM: u16 = 3;
pub const DEFAULT_SETTLEMENT_QUORUM: u16 = 3;
pub const DEFAULT_ATTESTATION_QUORUM: u16 = 4;
pub const DEFAULT_MAX_PRICE_DEVIATION_BPS: u64 = 1_250;
pub const DEFAULT_MAX_SPREAD_BPS: u64 = 450;
pub const DEFAULT_MIN_FILL_RATIO_BPS: u64 = 1_000;
pub const DEFAULT_MAX_NOTE_UTILIZATION_BPS: u64 = 8_750;
pub const DEFAULT_FAST_SETTLEMENT_BLOCKS: u64 = 6;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_LISTING_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_RFQ_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_LOW_FEE_BATCH_LIMIT: usize = 16_384;
pub const DEFAULT_MAX_VENUES: usize = 65_536;
pub const DEFAULT_MAX_NOTE_MININGS: usize = 262_144;
pub const DEFAULT_MAX_LISTINGS: usize = 1_048_576;
pub const DEFAULT_MAX_RFQS: usize = 524_288;
pub const DEFAULT_MAX_ORDERS: usize = 2_097_152;
pub const DEFAULT_MAX_MATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_FILLS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityMiningKind {
    ContinuousLimitOrderBook,
    BatchAuction,
    RfqCrossing,
    AmmBackstop,
    DealerQuoteStream,
    RedemptionExitLane,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProverFailureRiskKind {
    Timeout,
    InvalidProof,
    WitnessUnavailable,
    RecursiveProofStall,
    AggregatorOutage,
    DataAvailabilityGap,
    CatastrophicFailure,
}

impl ProverFailureRiskKind {
    pub fn liquidity_haircut_bps(self) -> u64 {
        match self {
            Self::Timeout => 125,
            Self::InvalidProof => 240,
            Self::WitnessUnavailable => 200,
            Self::RecursiveProofStall => 310,
            Self::AggregatorOutage => 375,
            Self::DataAvailabilityGap => 420,
            Self::CatastrophicFailure => 900,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteSeniority {
    SuperSenior,
    Senior,
    Mezzanine,
    Junior,
    Equity,
}

impl NoteSeniority {
    pub fn liquidity_mining_margin_bps(self) -> u64 {
        match self {
            Self::SuperSenior => 125,
            Self::Senior => 175,
            Self::Mezzanine => 350,
            Self::Junior => 650,
            Self::Equity => 1_100,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueStatus {
    Draft,
    Sealed,
    Active,
    RfqOnly,
    AuctionOnly,
    ReduceOnly,
    SettlementOnly,
    Halted,
    Retired,
    Quarantined,
}

impl VenueStatus {
    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Active | Self::RfqOnly | Self::AuctionOnly)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(self, Self::Active | Self::ReduceOnly | Self::SettlementOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingStatus {
    Draft,
    Sealed,
    Listed,
    PartiallyFilled,
    Matched,
    SettlementPending,
    Settled,
    Cancelled,
    Expired,
    Quarantined,
}

impl ListingStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Listed | Self::PartiallyFilled | Self::Matched | Self::SettlementPending
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderSide {
    BuyNote,
    SellNote,
    BuyProtection,
    SellProtection,
    ProvideLiquidity,
    ExitLiquidity,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Limit,
    PeggedMid,
    RfqResponse,
    AuctionCommit,
    ImmediateOrCancel,
    FillOrKill,
    MakerOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Submitted,
    PrivacyChecked,
    PqAuthorized,
    Resting,
    Matched,
    PartiallyFilled,
    Filled,
    Cancelled,
    Expired,
    Quarantined,
}

impl OrderStatus {
    pub fn executable(self) -> bool {
        matches!(
            self,
            Self::PqAuthorized | Self::Resting | Self::Matched | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Collecting,
    Proving,
    Posted,
    Finalized,
    Rejected,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub runtime_id: String,
    pub failure_index_id: String,
    pub note_token_id: String,
    pub quote_asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_liquidity_mining_authorization_suite: String,
    pub replay_domain: String,
    pub protocol_fee_bps: u64,
    pub matching_fee_bps: u64,
    pub settlement_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub max_price_deviation_bps: u64,
    pub max_spread_bps: u64,
    pub min_fill_ratio_bps: u64,
    pub max_note_utilization_bps: u64,
    pub fast_settlement_blocks: u64,
    pub order_ttl_blocks: u64,
    pub listing_ttl_blocks: u64,
    pub rfq_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub mining_maker_quorum: u16,
    pub settlement_quorum: u16,
    pub attestation_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_venues: usize,
    pub max_note_minings: usize,
    pub max_listings: usize,
    pub max_rfqs: usize,
    pub max_orders: usize,
    pub max_matches: usize,
    pub max_fills: usize,
    pub max_settlements: usize,
    pub max_nullifiers: usize,
    pub require_roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            runtime_id: DEVNET_RUNTIME_ID.to_string(),
            failure_index_id: DEVNET_FAILURE_INDEX_ID.to_string(),
            note_token_id: DEVNET_NOTE_TOKEN_ID.to_string(),
            quote_asset_id: DEVNET_QUOTE_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_liquidity_mining_authorization_suite: PQ_LIQUIDITY_MINING_AUTHORIZATION_SUITE
                .to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            matching_fee_bps: DEFAULT_MATCHING_FEE_BPS,
            settlement_fee_bps: DEFAULT_SETTLEMENT_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            max_price_deviation_bps: DEFAULT_MAX_PRICE_DEVIATION_BPS,
            max_spread_bps: DEFAULT_MAX_SPREAD_BPS,
            min_fill_ratio_bps: DEFAULT_MIN_FILL_RATIO_BPS,
            max_note_utilization_bps: DEFAULT_MAX_NOTE_UTILIZATION_BPS,
            fast_settlement_blocks: DEFAULT_FAST_SETTLEMENT_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            listing_ttl_blocks: DEFAULT_LISTING_TTL_BLOCKS,
            rfq_ttl_blocks: DEFAULT_RFQ_TTL_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            mining_maker_quorum: DEFAULT_MINING_MAKER_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            attestation_quorum: DEFAULT_ATTESTATION_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_venues: DEFAULT_MAX_VENUES,
            max_note_minings: DEFAULT_MAX_NOTE_MININGS,
            max_listings: DEFAULT_MAX_LISTINGS,
            max_rfqs: DEFAULT_MAX_RFQS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_matches: DEFAULT_MAX_MATCHES,
            max_fills: DEFAULT_MAX_FILLS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
            require_roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        require_nonempty("protocol_version", &self.protocol_version)?;
        require(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        require_bps("protocol_fee_bps", self.protocol_fee_bps)?;
        require_bps("matching_fee_bps", self.matching_fee_bps)?;
        require_bps("settlement_fee_bps", self.settlement_fee_bps)?;
        require_bps("maker_rebate_bps", self.maker_rebate_bps)?;
        require_bps("max_price_deviation_bps", self.max_price_deviation_bps)?;
        require_bps("max_spread_bps", self.max_spread_bps)?;
        require_bps("min_fill_ratio_bps", self.min_fill_ratio_bps)?;
        require_bps("max_note_utilization_bps", self.max_note_utilization_bps)?;
        require(
            self.fast_settlement_blocks > 0,
            "fast settlement window is zero",
        )?;
        require(self.order_ttl_blocks > 0, "order ttl is zero")?;
        require(self.listing_ttl_blocks > 0, "listing ttl is zero")?;
        require(self.rfq_ttl_blocks > 0, "rfq ttl is zero")?;
        require(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set below minimum",
        )?;
        require(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "minimum PQ security bits too low",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "runtime_id": self.runtime_id,
            "failure_index_id": self.failure_index_id,
            "note_token_id": self.note_token_id,
            "quote_asset_id": self.quote_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_liquidity_mining_authorization_suite": self.pq_liquidity_mining_authorization_suite,
            "replay_domain": self.replay_domain,
            "protocol_fee_bps": self.protocol_fee_bps,
            "matching_fee_bps": self.matching_fee_bps,
            "settlement_fee_bps": self.settlement_fee_bps,
            "maker_rebate_bps": self.maker_rebate_bps,
            "max_price_deviation_bps": self.max_price_deviation_bps,
            "max_spread_bps": self.max_spread_bps,
            "min_fill_ratio_bps": self.min_fill_ratio_bps,
            "max_note_utilization_bps": self.max_note_utilization_bps,
            "fast_settlement_blocks": self.fast_settlement_blocks,
            "order_ttl_blocks": self.order_ttl_blocks,
            "listing_ttl_blocks": self.listing_ttl_blocks,
            "rfq_ttl_blocks": self.rfq_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "mining_maker_quorum": self.mining_maker_quorum,
            "settlement_quorum": self.settlement_quorum,
            "attestation_quorum": self.attestation_quorum,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "require_roots_only_public_records": self.require_roots_only_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub venues: u64,
    pub note_minings: u64,
    pub listings: u64,
    pub rfqs: u64,
    pub orders: u64,
    pub matches: u64,
    pub fills: u64,
    pub settlements: u64,
    pub liquidity_lanes: u64,
    pub price_bands: u64,
    pub pq_attestations: u64,
    pub fee_rebates: u64,
    pub incentive_campaigns: u64,
    pub mining_positions: u64,
    pub reward_epochs: u64,
    pub reward_claims: u64,
    pub nullifiers: u64,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub venue_root: String,
    pub note_mining_root: String,
    pub listing_root: String,
    pub rfq_root: String,
    pub order_root: String,
    pub match_root: String,
    pub fill_root: String,
    pub settlement_root: String,
    pub liquidity_lane_root: String,
    pub price_band_root: String,
    pub pq_attestation_root: String,
    pub fee_rebate_root: String,
    pub incentive_campaign_root: String,
    pub mining_position_root: String,
    pub reward_epoch_root: String,
    pub reward_claim_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        let empty = merkle_root(PAYLOAD_ROOT_SUITE, &[] as &[Value]);
        Self {
            config_root: empty.clone(),
            counters_root: empty.clone(),
            venue_root: empty.clone(),
            note_mining_root: empty.clone(),
            listing_root: empty.clone(),
            rfq_root: empty.clone(),
            order_root: empty.clone(),
            match_root: empty.clone(),
            fill_root: empty.clone(),
            settlement_root: empty.clone(),
            liquidity_lane_root: empty.clone(),
            price_band_root: empty.clone(),
            pq_attestation_root: empty.clone(),
            fee_rebate_root: empty.clone(),
            incentive_campaign_root: empty.clone(),
            mining_position_root: empty.clone(),
            reward_epoch_root: empty.clone(),
            reward_claim_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_record_root: empty,
        }
    }

    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityMiningVenueInput {
    pub venue_id: String,
    pub kind: LiquidityMiningKind,
    pub operator_commitment: String,
    pub eligible_note_mining_root: String,
    pub quote_asset_root: String,
    pub fee_vault_root: String,
    pub risk_oracle_root: String,
    pub price_band_root: String,
    pub min_trade_units: u128,
    pub max_trade_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityMiningVenue {
    pub venue_id: String,
    pub kind: LiquidityMiningKind,
    pub status: VenueStatus,
    pub operator_commitment: String,
    pub eligible_note_mining_root: String,
    pub quote_asset_root: String,
    pub fee_vault_root: String,
    pub risk_oracle_root: String,
    pub price_band_root: String,
    pub min_trade_units: u128,
    pub max_trade_units: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_l2_height: u64,
    pub opened_monero_height: u64,
    pub venue_commitment_root: String,
}

impl LiquidityMiningVenue {
    pub fn public_record(&self) -> Value {
        roots_safe_record("mining_venue", &self.venue_id, &self.venue_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EligibleNoteMiningInput {
    pub mining_id: String,
    pub venue_id: String,
    pub source_program_root: String,
    pub tranche_root: String,
    pub note_token_root: String,
    pub seniority: NoteSeniority,
    pub risk_kind: ProverFailureRiskKind,
    pub outstanding_units: u128,
    pub tradable_units: u128,
    pub reference_nav_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EligibleNoteMining {
    pub mining_id: String,
    pub venue_id: String,
    pub source_program_root: String,
    pub tranche_root: String,
    pub note_token_root: String,
    pub seniority: NoteSeniority,
    pub risk_kind: ProverFailureRiskKind,
    pub outstanding_units: u128,
    pub tradable_units: u128,
    pub reference_nav_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub mining_commitment_root: String,
}

impl EligibleNoteMining {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "eligible_note_mining",
            &self.mining_id,
            &self.mining_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListingInput {
    pub listing_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub seller_commitment: String,
    pub note_position_root: String,
    pub ask_quote_root: String,
    pub reserve_price_root: String,
    pub quantity_units: u128,
    pub min_fill_units: u128,
    pub expires_l2_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedListing {
    pub listing_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub status: ListingStatus,
    pub seller_commitment: String,
    pub note_position_root: String,
    pub ask_quote_root: String,
    pub reserve_price_root: String,
    pub quantity_units: u128,
    pub remaining_units: u128,
    pub min_fill_units: u128,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub listing_commitment_root: String,
}

impl SealedListing {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "sealed_listing",
            &self.listing_id,
            &self.listing_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RfqInput {
    pub rfq_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub requester_commitment: String,
    pub side: OrderSide,
    pub notional_root: String,
    pub constraints_root: String,
    pub response_committee_root: String,
    pub expires_l2_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateRfq {
    pub rfq_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub requester_commitment: String,
    pub side: OrderSide,
    pub notional_root: String,
    pub constraints_root: String,
    pub response_committee_root: String,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub rfq_commitment_root: String,
}

impl PrivateRfq {
    pub fn public_record(&self) -> Value {
        roots_safe_record("private_rfq", &self.rfq_id, &self.rfq_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrderInput {
    pub order_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub listing_id: Option<String>,
    pub rfq_id: Option<String>,
    pub trader_commitment: String,
    pub side: OrderSide,
    pub kind: OrderKind,
    pub price_commitment_root: String,
    pub quantity_commitment_root: String,
    pub collateral_commitment_root: String,
    pub max_fee_root: String,
    pub expires_l2_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OrderCommitment {
    pub order_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub listing_id: Option<String>,
    pub rfq_id: Option<String>,
    pub trader_commitment: String,
    pub side: OrderSide,
    pub kind: OrderKind,
    pub status: OrderStatus,
    pub price_commitment_root: String,
    pub quantity_commitment_root: String,
    pub collateral_commitment_root: String,
    pub max_fee_root: String,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub order_commitment_root: String,
}

impl OrderCommitment {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "order_commitment",
            &self.order_id,
            &self.order_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MatchIntentInput {
    pub match_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub listing_id: Option<String>,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub price_band_id: String,
    pub matched_quantity_root: String,
    pub clearing_price_root: String,
    pub fee_quote_root: String,
    pub matcher_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MatchIntent {
    pub match_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub listing_id: Option<String>,
    pub maker_order_id: String,
    pub taker_order_id: String,
    pub price_band_id: String,
    pub matched_quantity_root: String,
    pub clearing_price_root: String,
    pub fee_quote_root: String,
    pub matcher_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub match_commitment_root: String,
}

impl MatchIntent {
    pub fn public_record(&self) -> Value {
        roots_safe_record("match_intent", &self.match_id, &self.match_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TradeFillInput {
    pub fill_id: String,
    pub match_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub debit_root: String,
    pub credit_root: String,
    pub note_transfer_root: String,
    pub quote_transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub filled_units: u128,
    pub settlement_deadline_l2_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TradeFill {
    pub fill_id: String,
    pub match_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub debit_root: String,
    pub credit_root: String,
    pub note_transfer_root: String,
    pub quote_transfer_root: String,
    pub fee_root: String,
    pub rebate_root: String,
    pub filled_units: u128,
    pub settlement_deadline_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub fill_commitment_root: String,
}

impl TradeFill {
    pub fn public_record(&self) -> Value {
        roots_safe_record("trade_fill", &self.fill_id, &self.fill_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SettlementInput {
    pub settlement_id: String,
    pub venue_id: String,
    pub fill_set_root: String,
    pub debit_batch_root: String,
    pub credit_batch_root: String,
    pub note_delivery_root: String,
    pub quote_delivery_root: String,
    pub fee_batch_root: String,
    pub rebate_batch_root: String,
    pub settled_fills: u64,
    pub protocol_fee_units: u128,
    pub settlement_fee_units: u128,
    pub maker_rebate_units: u128,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AtomicSettlementBatch {
    pub settlement_id: String,
    pub venue_id: String,
    pub status: SettlementStatus,
    pub fill_set_root: String,
    pub debit_batch_root: String,
    pub credit_batch_root: String,
    pub note_delivery_root: String,
    pub quote_delivery_root: String,
    pub fee_batch_root: String,
    pub rebate_batch_root: String,
    pub settled_fills: u64,
    pub protocol_fee_units: u128,
    pub settlement_fee_units: u128,
    pub maker_rebate_units: u128,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub settlement_commitment_root: String,
}

impl AtomicSettlementBatch {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "atomic_settlement_batch",
            &self.settlement_id,
            &self.settlement_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityLane {
    pub lane_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub maker_set_root: String,
    pub inventory_root: String,
    pub quote_depth_root: String,
    pub spread_bps: u64,
    pub utilization_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub lane_commitment_root: String,
}

impl LiquidityLane {
    pub fn public_record(&self) -> Value {
        roots_safe_record("liquidity_lane", &self.lane_id, &self.lane_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PriceBand {
    pub price_band_id: String,
    pub venue_id: String,
    pub mining_id: String,
    pub nav_commitment_root: String,
    pub lower_price_root: String,
    pub upper_price_root: String,
    pub deviation_bps: u64,
    pub oracle_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub price_band_commitment_root: String,
}

impl PriceBand {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "price_band",
            &self.price_band_id,
            &self.price_band_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqMiningAttestation {
    pub attestation_id: String,
    pub venue_id: String,
    pub subject_root: String,
    pub committee_root: String,
    pub signature_root: String,
    pub quorum_weight: u16,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attestation_commitment_root: String,
}

impl PqMiningAttestation {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "pq_mining_attestation",
            &self.attestation_id,
            &self.attestation_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FeeRebateEpoch {
    pub rebate_epoch_id: String,
    pub venue_id: String,
    pub maker_set_root: String,
    pub volume_root: String,
    pub fee_mining_root: String,
    pub rebate_distribution_root: String,
    pub epoch: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub rebate_commitment_root: String,
}

impl FeeRebateEpoch {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "fee_rebate_epoch",
            &self.rebate_epoch_id,
            &self.rebate_commitment_root,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncentiveCampaignKind {
    BootstrapNoteDepth,
    FastSettlementBonus,
    PqAttestedMaker,
    ProverFailureCoverageDepth,
    PrivateRfqResponder,
    LowFeeBatching,
    LongHorizonRetention,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MiningPositionStatus {
    Pending,
    Active,
    CoolingDown,
    RewardLocked,
    Claimed,
    Slashed,
    Exited,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncentiveCampaignInput {
    pub campaign_id: String,
    pub venue_id: String,
    pub kind: IncentiveCampaignKind,
    pub reward_asset_root: String,
    pub reward_vault_root: String,
    pub eligibility_circuit_root: String,
    pub emissions_curve_root: String,
    pub fee_discount_root: String,
    pub boost_policy_root: String,
    pub starts_epoch: u64,
    pub ends_epoch: u64,
    pub max_reward_bps: u64,
    pub fast_settlement_bonus_bps: u64,
    pub low_fee_cap_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncentiveCampaign {
    pub campaign_id: String,
    pub venue_id: String,
    pub kind: IncentiveCampaignKind,
    pub reward_asset_root: String,
    pub reward_vault_root: String,
    pub eligibility_circuit_root: String,
    pub emissions_curve_root: String,
    pub fee_discount_root: String,
    pub boost_policy_root: String,
    pub starts_epoch: u64,
    pub ends_epoch: u64,
    pub max_reward_bps: u64,
    pub fast_settlement_bonus_bps: u64,
    pub low_fee_cap_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub campaign_commitment_root: String,
}

impl IncentiveCampaign {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "incentive_campaign",
            &self.campaign_id,
            &self.campaign_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MiningPositionInput {
    pub position_id: String,
    pub campaign_id: String,
    pub venue_id: String,
    pub note_mining_id: String,
    pub miner_commitment: String,
    pub stake_commitment_root: String,
    pub note_inventory_root: String,
    pub protected_notional_root: String,
    pub settlement_speed_root: String,
    pub fee_budget_root: String,
    pub pq_attestation_root: String,
    pub lock_start_l2_height: u64,
    pub lock_end_l2_height: u64,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MiningPosition {
    pub position_id: String,
    pub campaign_id: String,
    pub venue_id: String,
    pub note_mining_id: String,
    pub status: MiningPositionStatus,
    pub miner_commitment: String,
    pub stake_commitment_root: String,
    pub note_inventory_root: String,
    pub protected_notional_root: String,
    pub settlement_speed_root: String,
    pub fee_budget_root: String,
    pub pq_attestation_root: String,
    pub lock_start_l2_height: u64,
    pub lock_end_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub position_commitment_root: String,
}

impl MiningPosition {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "mining_position",
            &self.position_id,
            &self.position_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardEpochInput {
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub venue_id: String,
    pub epoch: u64,
    pub eligible_position_set_root: String,
    pub volume_score_root: String,
    pub settlement_speed_score_root: String,
    pub pq_security_score_root: String,
    pub fee_efficiency_score_root: String,
    pub reward_distribution_root: String,
    pub carry_forward_root: String,
    pub settled_l2_height: u64,
    pub settled_monero_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardEpoch {
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub venue_id: String,
    pub epoch: u64,
    pub eligible_position_set_root: String,
    pub volume_score_root: String,
    pub settlement_speed_score_root: String,
    pub pq_security_score_root: String,
    pub fee_efficiency_score_root: String,
    pub reward_distribution_root: String,
    pub carry_forward_root: String,
    pub settled_l2_height: u64,
    pub settled_monero_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub reward_epoch_commitment_root: String,
}

impl RewardEpoch {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "reward_epoch",
            &self.reward_epoch_id,
            &self.reward_epoch_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardClaimInput {
    pub claim_id: String,
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub position_id: String,
    pub claimant_commitment: String,
    pub reward_note_transfer_root: String,
    pub reward_asset_transfer_root: String,
    pub fee_rebate_transfer_root: String,
    pub proof_bundle_root: String,
    pub settlement_authorization_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardClaim {
    pub claim_id: String,
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub position_id: String,
    pub claimant_commitment: String,
    pub reward_note_transfer_root: String,
    pub reward_asset_transfer_root: String,
    pub fee_rebate_transfer_root: String,
    pub proof_bundle_root: String,
    pub settlement_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub claim_commitment_root: String,
}

impl RewardClaim {
    pub fn public_record(&self) -> Value {
        roots_safe_record("reward_claim", &self.claim_id, &self.claim_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub venues: BTreeMap<String, LiquidityMiningVenue>,
    pub note_minings: BTreeMap<String, EligibleNoteMining>,
    pub listings: BTreeMap<String, SealedListing>,
    pub rfqs: BTreeMap<String, PrivateRfq>,
    pub orders: BTreeMap<String, OrderCommitment>,
    pub matches: BTreeMap<String, MatchIntent>,
    pub fills: BTreeMap<String, TradeFill>,
    pub settlements: BTreeMap<String, AtomicSettlementBatch>,
    pub liquidity_lanes: BTreeMap<String, LiquidityLane>,
    pub price_bands: BTreeMap<String, PriceBand>,
    pub pq_attestations: BTreeMap<String, PqMiningAttestation>,
    pub fee_rebates: BTreeMap<String, FeeRebateEpoch>,
    pub incentive_campaigns: BTreeMap<String, IncentiveCampaign>,
    pub mining_positions: BTreeMap<String, MiningPosition>,
    pub reward_epochs: BTreeMap<String, RewardEpoch>,
    pub reward_claims: BTreeMap<String, RewardClaim>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            venues: BTreeMap::new(),
            note_minings: BTreeMap::new(),
            listings: BTreeMap::new(),
            rfqs: BTreeMap::new(),
            orders: BTreeMap::new(),
            matches: BTreeMap::new(),
            fills: BTreeMap::new(),
            settlements: BTreeMap::new(),
            liquidity_lanes: BTreeMap::new(),
            price_bands: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            incentive_campaigns: BTreeMap::new(),
            mining_positions: BTreeMap::new(),
            reward_epochs: BTreeMap::new(),
            reward_claims: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.seed_devnet().expect("valid liquidity mining devnet");
        state
    }

    pub fn add_venue(&mut self, input: LiquidityMiningVenueInput) -> Result<LiquidityMiningVenue> {
        self.config.validate()?;
        ensure_capacity("venues", self.venues.len(), self.config.max_venues)?;
        require_nonempty("venue_id", &input.venue_id)?;
        require(
            input.min_trade_units > 0,
            "min trade units must be positive",
        )?;
        require(
            input.max_trade_units >= input.min_trade_units,
            "max trade units below min trade units",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("mining_venue", &public_record_for(&input));
        let venue = LiquidityMiningVenue {
            venue_id: input.venue_id,
            kind: input.kind,
            status: VenueStatus::Active,
            operator_commitment: input.operator_commitment,
            eligible_note_mining_root: input.eligible_note_mining_root,
            quote_asset_root: input.quote_asset_root,
            fee_vault_root: input.fee_vault_root,
            risk_oracle_root: input.risk_oracle_root,
            price_band_root: input.price_band_root,
            min_trade_units: input.min_trade_units,
            max_trade_units: input.max_trade_units,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            opened_l2_height: DEVNET_L2_HEIGHT,
            opened_monero_height: DEVNET_MONERO_HEIGHT,
            venue_commitment_root: root,
        };
        insert_unique(&mut self.venues, venue.venue_id.clone(), venue.clone())?;
        self.publish_roots_only(format!("venue:{}", venue.venue_id), venue.public_record())?;
        self.refresh_roots();
        Ok(venue)
    }

    pub fn add_note_mining(
        &mut self,
        input: EligibleNoteMiningInput,
    ) -> Result<EligibleNoteMining> {
        ensure_capacity(
            "note_minings",
            self.note_minings.len(),
            self.config.max_note_minings,
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require(
            input.outstanding_units > 0,
            "outstanding units must be positive",
        )?;
        require(input.tradable_units > 0, "tradable units must be positive")?;
        require(
            input.tradable_units <= input.outstanding_units,
            "tradable units exceed outstanding units",
        )?;
        require_bps("reference_nav_bps", input.reference_nav_bps)?;
        require_bps("utilization_bps", input.utilization_bps)?;
        require(
            input.utilization_bps <= self.config.max_note_utilization_bps,
            "note utilization exceeds configured cap",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("eligible_note_mining", &public_record_for(&input));
        let mining = EligibleNoteMining {
            mining_id: input.mining_id,
            venue_id: input.venue_id,
            source_program_root: input.source_program_root,
            tranche_root: input.tranche_root,
            note_token_root: input.note_token_root,
            seniority: input.seniority,
            risk_kind: input.risk_kind,
            outstanding_units: input.outstanding_units,
            tradable_units: input.tradable_units,
            reference_nav_bps: input.reference_nav_bps,
            utilization_bps: input.utilization_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            mining_commitment_root: root,
        };
        insert_unique(
            &mut self.note_minings,
            mining.mining_id.clone(),
            mining.clone(),
        )?;
        self.publish_roots_only(
            format!("note_mining:{}", mining.mining_id),
            mining.public_record(),
        )?;
        self.refresh_roots();
        Ok(mining)
    }

    pub fn add_listing(&mut self, input: ListingInput) -> Result<SealedListing> {
        ensure_capacity("listings", self.listings.len(), self.config.max_listings)?;
        self.require_venue_open(&input.venue_id)?;
        require(
            self.note_minings.contains_key(&input.mining_id),
            "unknown note mining",
        )?;
        require(
            input.quantity_units > 0,
            "listing quantity must be positive",
        )?;
        require(input.min_fill_units > 0, "min fill must be positive")?;
        require(
            input.min_fill_units <= input.quantity_units,
            "min fill exceeds quantity",
        )?;
        require(
            input.expires_l2_height > DEVNET_L2_HEIGHT,
            "listing expiry is not in the future",
        )?;
        self.consume_nullifier(&input.nullifier)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("sealed_listing", &public_record_for(&input));
        let listing = SealedListing {
            listing_id: input.listing_id,
            venue_id: input.venue_id,
            mining_id: input.mining_id,
            status: ListingStatus::Listed,
            seller_commitment: input.seller_commitment,
            note_position_root: input.note_position_root,
            ask_quote_root: input.ask_quote_root,
            reserve_price_root: input.reserve_price_root,
            quantity_units: input.quantity_units,
            remaining_units: input.quantity_units,
            min_fill_units: input.min_fill_units,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: input.expires_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            listing_commitment_root: root,
        };
        insert_unique(
            &mut self.listings,
            listing.listing_id.clone(),
            listing.clone(),
        )?;
        self.publish_roots_only(
            format!("listing:{}", listing.listing_id),
            listing.public_record(),
        )?;
        self.refresh_roots();
        Ok(listing)
    }

    pub fn open_rfq(&mut self, input: RfqInput) -> Result<PrivateRfq> {
        ensure_capacity("rfqs", self.rfqs.len(), self.config.max_rfqs)?;
        self.require_venue_open(&input.venue_id)?;
        require(
            self.note_minings.contains_key(&input.mining_id),
            "unknown note mining",
        )?;
        require(
            input.expires_l2_height > DEVNET_L2_HEIGHT,
            "rfq expiry is not in the future",
        )?;
        self.consume_nullifier(&input.nullifier)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("private_rfq", &public_record_for(&input));
        let rfq = PrivateRfq {
            rfq_id: input.rfq_id,
            venue_id: input.venue_id,
            mining_id: input.mining_id,
            requester_commitment: input.requester_commitment,
            side: input.side,
            notional_root: input.notional_root,
            constraints_root: input.constraints_root,
            response_committee_root: input.response_committee_root,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: input.expires_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            rfq_commitment_root: root,
        };
        insert_unique(&mut self.rfqs, rfq.rfq_id.clone(), rfq.clone())?;
        self.publish_roots_only(format!("rfq:{}", rfq.rfq_id), rfq.public_record())?;
        self.refresh_roots();
        Ok(rfq)
    }

    pub fn submit_order(&mut self, input: OrderInput) -> Result<OrderCommitment> {
        ensure_capacity("orders", self.orders.len(), self.config.max_orders)?;
        self.require_venue_open(&input.venue_id)?;
        require(
            self.note_minings.contains_key(&input.mining_id),
            "unknown note mining",
        )?;
        if let Some(listing_id) = &input.listing_id {
            require(self.listings.contains_key(listing_id), "unknown listing")?;
        }
        if let Some(rfq_id) = &input.rfq_id {
            require(self.rfqs.contains_key(rfq_id), "unknown rfq")?;
        }
        require(
            input.expires_l2_height > DEVNET_L2_HEIGHT,
            "order expiry is not in the future",
        )?;
        self.consume_nullifier(&input.nullifier)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("order_commitment", &public_record_for(&input));
        let order = OrderCommitment {
            order_id: input.order_id,
            venue_id: input.venue_id,
            mining_id: input.mining_id,
            listing_id: input.listing_id,
            rfq_id: input.rfq_id,
            trader_commitment: input.trader_commitment,
            side: input.side,
            kind: input.kind,
            status: OrderStatus::Resting,
            price_commitment_root: input.price_commitment_root,
            quantity_commitment_root: input.quantity_commitment_root,
            collateral_commitment_root: input.collateral_commitment_root,
            max_fee_root: input.max_fee_root,
            opened_l2_height: DEVNET_L2_HEIGHT,
            expires_l2_height: input.expires_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            order_commitment_root: root,
        };
        insert_unique(&mut self.orders, order.order_id.clone(), order.clone())?;
        self.publish_roots_only(format!("order:{}", order.order_id), order.public_record())?;
        self.refresh_roots();
        Ok(order)
    }

    pub fn match_orders(&mut self, input: MatchIntentInput) -> Result<MatchIntent> {
        ensure_capacity("matches", self.matches.len(), self.config.max_matches)?;
        self.require_venue_open(&input.venue_id)?;
        require(
            self.note_minings.contains_key(&input.mining_id),
            "unknown note mining",
        )?;
        let maker = self
            .orders
            .get(&input.maker_order_id)
            .ok_or_else(|| "unknown maker order".to_string())?;
        let taker = self
            .orders
            .get(&input.taker_order_id)
            .ok_or_else(|| "unknown taker order".to_string())?;
        require(maker.status.executable(), "maker order is not executable")?;
        require(taker.status.executable(), "taker order is not executable")?;
        require(
            self.price_bands.contains_key(&input.price_band_id),
            "unknown price band",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("match_intent", &public_record_for(&input));
        let intent = MatchIntent {
            match_id: input.match_id,
            venue_id: input.venue_id,
            mining_id: input.mining_id,
            listing_id: input.listing_id,
            maker_order_id: input.maker_order_id,
            taker_order_id: input.taker_order_id,
            price_band_id: input.price_band_id,
            matched_quantity_root: input.matched_quantity_root,
            clearing_price_root: input.clearing_price_root,
            fee_quote_root: input.fee_quote_root,
            matcher_attestation_root: input.matcher_attestation_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            match_commitment_root: root,
        };
        insert_unique(&mut self.matches, intent.match_id.clone(), intent.clone())?;
        self.publish_roots_only(format!("match:{}", intent.match_id), intent.public_record())?;
        self.refresh_roots();
        Ok(intent)
    }

    pub fn add_trade_fill(&mut self, input: TradeFillInput) -> Result<TradeFill> {
        ensure_capacity("fills", self.fills.len(), self.config.max_fills)?;
        require(self.matches.contains_key(&input.match_id), "unknown match")?;
        require(input.filled_units > 0, "filled units must be positive")?;
        require(
            input.settlement_deadline_l2_height
                >= DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks,
            "settlement deadline is too near",
        )?;
        self.consume_nullifier(&input.nullifier)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("trade_fill", &public_record_for(&input));
        let fill = TradeFill {
            fill_id: input.fill_id,
            match_id: input.match_id,
            venue_id: input.venue_id,
            mining_id: input.mining_id,
            debit_root: input.debit_root,
            credit_root: input.credit_root,
            note_transfer_root: input.note_transfer_root,
            quote_transfer_root: input.quote_transfer_root,
            fee_root: input.fee_root,
            rebate_root: input.rebate_root,
            filled_units: input.filled_units,
            settlement_deadline_l2_height: input.settlement_deadline_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            fill_commitment_root: root,
        };
        insert_unique(&mut self.fills, fill.fill_id.clone(), fill.clone())?;
        self.publish_roots_only(format!("fill:{}", fill.fill_id), fill.public_record())?;
        self.refresh_roots();
        Ok(fill)
    }

    pub fn add_settlement(&mut self, input: SettlementInput) -> Result<AtomicSettlementBatch> {
        ensure_capacity(
            "settlements",
            self.settlements.len(),
            self.config.max_settlements,
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require(input.settled_fills > 0, "settled fills must be positive")?;
        require(
            input.settled_fills as usize <= self.config.low_fee_batch_limit,
            "settlement batch exceeds low-fee batch limit",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("atomic_settlement", &public_record_for(&input));
        let batch = AtomicSettlementBatch {
            settlement_id: input.settlement_id,
            venue_id: input.venue_id,
            status: SettlementStatus::Finalized,
            fill_set_root: input.fill_set_root,
            debit_batch_root: input.debit_batch_root,
            credit_batch_root: input.credit_batch_root,
            note_delivery_root: input.note_delivery_root,
            quote_delivery_root: input.quote_delivery_root,
            fee_batch_root: input.fee_batch_root,
            rebate_batch_root: input.rebate_batch_root,
            settled_fills: input.settled_fills,
            protocol_fee_units: input.protocol_fee_units,
            settlement_fee_units: input.settlement_fee_units,
            maker_rebate_units: input.maker_rebate_units,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            settlement_commitment_root: root,
        };
        insert_unique(
            &mut self.settlements,
            batch.settlement_id.clone(),
            batch.clone(),
        )?;
        self.publish_roots_only(
            format!("settlement:{}", batch.settlement_id),
            batch.public_record(),
        )?;
        self.refresh_roots();
        Ok(batch)
    }

    pub fn add_liquidity_lane(&mut self, lane: LiquidityLane) -> Result<()> {
        require_bps("spread_bps", lane.spread_bps)?;
        require(
            lane.spread_bps <= self.config.max_spread_bps,
            "spread too wide",
        )?;
        require_bps("utilization_bps", lane.utilization_bps)?;
        self.require_privacy_and_pq(lane.privacy_set_size, lane.pq_security_bits)?;
        insert_unique(
            &mut self.liquidity_lanes,
            lane.lane_id.clone(),
            lane.clone(),
        )?;
        self.publish_roots_only(
            format!("liquidity_lane:{}", lane.lane_id),
            lane.public_record(),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_price_band(&mut self, band: PriceBand) -> Result<()> {
        require_bps("deviation_bps", band.deviation_bps)?;
        require(
            band.deviation_bps <= self.config.max_price_deviation_bps,
            "price deviation too wide",
        )?;
        self.require_privacy_and_pq(band.privacy_set_size, band.pq_security_bits)?;
        insert_unique(
            &mut self.price_bands,
            band.price_band_id.clone(),
            band.clone(),
        )?;
        self.publish_roots_only(
            format!("price_band:{}", band.price_band_id),
            band.public_record(),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_pq_attestation(&mut self, attestation: PqMiningAttestation) -> Result<()> {
        require(
            attestation.quorum_weight >= self.config.attestation_quorum,
            "attestation quorum below configured threshold",
        )?;
        self.require_privacy_and_pq(attestation.privacy_set_size, attestation.pq_security_bits)?;
        insert_unique(
            &mut self.pq_attestations,
            attestation.attestation_id.clone(),
            attestation.clone(),
        )?;
        self.publish_roots_only(
            format!("pq_attestation:{}", attestation.attestation_id),
            attestation.public_record(),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_fee_rebate_epoch(&mut self, rebate: FeeRebateEpoch) -> Result<()> {
        require_bps("rebate_bps", rebate.rebate_bps)?;
        self.require_privacy_and_pq(rebate.privacy_set_size, rebate.pq_security_bits)?;
        insert_unique(
            &mut self.fee_rebates,
            rebate.rebate_epoch_id.clone(),
            rebate.clone(),
        )?;
        self.publish_roots_only(
            format!("fee_rebate:{}", rebate.rebate_epoch_id),
            rebate.public_record(),
        )?;
        self.refresh_roots();
        Ok(())
    }

    pub fn add_incentive_campaign(
        &mut self,
        input: IncentiveCampaignInput,
    ) -> Result<IncentiveCampaign> {
        ensure_capacity(
            "incentive_campaigns",
            self.incentive_campaigns.len(),
            self.config.max_listings,
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require_nonempty("campaign_id", &input.campaign_id)?;
        require(
            input.ends_epoch >= input.starts_epoch,
            "campaign epoch range invalid",
        )?;
        require_bps("max_reward_bps", input.max_reward_bps)?;
        require_bps("fast_settlement_bonus_bps", input.fast_settlement_bonus_bps)?;
        require_bps("low_fee_cap_bps", input.low_fee_cap_bps)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("incentive_campaign", &public_record_for(&input));
        let campaign = IncentiveCampaign {
            campaign_id: input.campaign_id,
            venue_id: input.venue_id,
            kind: input.kind,
            reward_asset_root: input.reward_asset_root,
            reward_vault_root: input.reward_vault_root,
            eligibility_circuit_root: input.eligibility_circuit_root,
            emissions_curve_root: input.emissions_curve_root,
            fee_discount_root: input.fee_discount_root,
            boost_policy_root: input.boost_policy_root,
            starts_epoch: input.starts_epoch,
            ends_epoch: input.ends_epoch,
            max_reward_bps: input.max_reward_bps,
            fast_settlement_bonus_bps: input.fast_settlement_bonus_bps,
            low_fee_cap_bps: input.low_fee_cap_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            campaign_commitment_root: root,
        };
        insert_unique(
            &mut self.incentive_campaigns,
            campaign.campaign_id.clone(),
            campaign.clone(),
        )?;
        self.publish_roots_only(
            format!("incentive_campaign:{}", campaign.campaign_id),
            campaign.public_record(),
        )?;
        self.refresh_roots();
        Ok(campaign)
    }

    pub fn open_mining_position(&mut self, input: MiningPositionInput) -> Result<MiningPosition> {
        ensure_capacity(
            "mining_positions",
            self.mining_positions.len(),
            self.config.max_orders,
        )?;
        require(
            self.incentive_campaigns.contains_key(&input.campaign_id),
            "unknown incentive campaign",
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require(
            self.note_minings.contains_key(&input.note_mining_id),
            "unknown note mining",
        )?;
        require_nonempty("position_id", &input.position_id)?;
        require(
            input.lock_end_l2_height > input.lock_start_l2_height,
            "position lock window invalid",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        self.consume_nullifier(&input.nullifier)?;
        let root = payload_root("mining_position", &public_record_for(&input));
        let position = MiningPosition {
            position_id: input.position_id,
            campaign_id: input.campaign_id,
            venue_id: input.venue_id,
            note_mining_id: input.note_mining_id,
            status: MiningPositionStatus::Active,
            miner_commitment: input.miner_commitment,
            stake_commitment_root: input.stake_commitment_root,
            note_inventory_root: input.note_inventory_root,
            protected_notional_root: input.protected_notional_root,
            settlement_speed_root: input.settlement_speed_root,
            fee_budget_root: input.fee_budget_root,
            pq_attestation_root: input.pq_attestation_root,
            lock_start_l2_height: input.lock_start_l2_height,
            lock_end_l2_height: input.lock_end_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            position_commitment_root: root,
        };
        insert_unique(
            &mut self.mining_positions,
            position.position_id.clone(),
            position.clone(),
        )?;
        self.publish_roots_only(
            format!("mining_position:{}", position.position_id),
            position.public_record(),
        )?;
        self.refresh_roots();
        Ok(position)
    }

    pub fn close_reward_epoch(&mut self, input: RewardEpochInput) -> Result<RewardEpoch> {
        ensure_capacity(
            "reward_epochs",
            self.reward_epochs.len(),
            self.config.max_matches,
        )?;
        require(
            self.incentive_campaigns.contains_key(&input.campaign_id),
            "unknown incentive campaign",
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require_nonempty("reward_epoch_id", &input.reward_epoch_id)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("reward_epoch", &public_record_for(&input));
        let epoch = RewardEpoch {
            reward_epoch_id: input.reward_epoch_id,
            campaign_id: input.campaign_id,
            venue_id: input.venue_id,
            epoch: input.epoch,
            eligible_position_set_root: input.eligible_position_set_root,
            volume_score_root: input.volume_score_root,
            settlement_speed_score_root: input.settlement_speed_score_root,
            pq_security_score_root: input.pq_security_score_root,
            fee_efficiency_score_root: input.fee_efficiency_score_root,
            reward_distribution_root: input.reward_distribution_root,
            carry_forward_root: input.carry_forward_root,
            settled_l2_height: input.settled_l2_height,
            settled_monero_height: input.settled_monero_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            reward_epoch_commitment_root: root,
        };
        insert_unique(
            &mut self.reward_epochs,
            epoch.reward_epoch_id.clone(),
            epoch.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_epoch:{}", epoch.reward_epoch_id),
            epoch.public_record(),
        )?;
        self.refresh_roots();
        Ok(epoch)
    }

    pub fn claim_reward(&mut self, input: RewardClaimInput) -> Result<RewardClaim> {
        ensure_capacity(
            "reward_claims",
            self.reward_claims.len(),
            self.config.max_fills,
        )?;
        require(
            self.reward_epochs.contains_key(&input.reward_epoch_id),
            "unknown reward epoch",
        )?;
        require(
            self.incentive_campaigns.contains_key(&input.campaign_id),
            "unknown incentive campaign",
        )?;
        require(
            self.mining_positions.contains_key(&input.position_id),
            "unknown mining position",
        )?;
        require_nonempty("claim_id", &input.claim_id)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        self.consume_nullifier(&input.nullifier)?;
        let root = payload_root("reward_claim", &public_record_for(&input));
        let claim = RewardClaim {
            claim_id: input.claim_id,
            reward_epoch_id: input.reward_epoch_id,
            campaign_id: input.campaign_id,
            position_id: input.position_id,
            claimant_commitment: input.claimant_commitment,
            reward_note_transfer_root: input.reward_note_transfer_root,
            reward_asset_transfer_root: input.reward_asset_transfer_root,
            fee_rebate_transfer_root: input.fee_rebate_transfer_root,
            proof_bundle_root: input.proof_bundle_root,
            settlement_authorization_root: input.settlement_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            claim_commitment_root: root,
        };
        insert_unique(
            &mut self.reward_claims,
            claim.claim_id.clone(),
            claim.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_claim:{}", claim.claim_id),
            claim.public_record(),
        )?;
        self.refresh_roots();
        Ok(claim)
    }

    pub fn state_root(&self) -> String {
        let roots = self.compute_roots();
        domain_hash(
            STATE_ROOT_SUITE,
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.compute_roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "state_root": self.state_root(),
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "roots_only": true,
        })
    }

    pub fn compute_roots(&self) -> Roots {
        let counters = self.current_counters();
        Roots {
            config_root: root_from_record("CONFIG", &self.config.public_record()),
            counters_root: root_from_record("COUNTERS", &counters.public_record()),
            venue_root: map_public_root(
                MINING_VENUE_SUITE,
                &self.venues,
                LiquidityMiningVenue::public_record,
            ),
            note_mining_root: map_public_root(
                ELIGIBLE_NOTE_MINING_SUITE,
                &self.note_minings,
                EligibleNoteMining::public_record,
            ),
            listing_root: map_public_root(
                SEALED_LISTING_SUITE,
                &self.listings,
                SealedListing::public_record,
            ),
            rfq_root: map_public_root(PRIVATE_RFQ_SUITE, &self.rfqs, PrivateRfq::public_record),
            order_root: map_public_root(
                ORDER_COMMITMENT_SUITE,
                &self.orders,
                OrderCommitment::public_record,
            ),
            match_root: map_public_root(
                MATCH_INTENT_SUITE,
                &self.matches,
                MatchIntent::public_record,
            ),
            fill_root: map_public_root(TRADE_FILL_SUITE, &self.fills, TradeFill::public_record),
            settlement_root: map_public_root(
                ATOMIC_SETTLEMENT_SUITE,
                &self.settlements,
                AtomicSettlementBatch::public_record,
            ),
            liquidity_lane_root: map_public_root(
                LIQUIDITY_LANE_SUITE,
                &self.liquidity_lanes,
                LiquidityLane::public_record,
            ),
            price_band_root: map_public_root(
                PRICE_BAND_SUITE,
                &self.price_bands,
                PriceBand::public_record,
            ),
            pq_attestation_root: map_public_root(
                PQ_ATTESTATION_SUITE,
                &self.pq_attestations,
                PqMiningAttestation::public_record,
            ),
            fee_rebate_root: map_public_root(
                FEE_REBATE_SUITE,
                &self.fee_rebates,
                FeeRebateEpoch::public_record,
            ),
            incentive_campaign_root: map_public_root(
                INCENTIVE_CAMPAIGN_SUITE,
                &self.incentive_campaigns,
                IncentiveCampaign::public_record,
            ),
            mining_position_root: map_public_root(
                MINING_POSITION_SUITE,
                &self.mining_positions,
                MiningPosition::public_record,
            ),
            reward_epoch_root: map_public_root(
                REWARD_EPOCH_SUITE,
                &self.reward_epochs,
                RewardEpoch::public_record,
            ),
            reward_claim_root: map_public_root(
                REWARD_CLAIM_SUITE,
                &self.reward_claims,
                RewardClaim::public_record,
            ),
            nullifier_root: set_root(NULLIFIER_SUITE, &self.nullifiers),
            public_record_root: value_map_root(PUBLIC_RECORD_SUITE, &self.public_records),
        }
    }

    fn current_counters(&self) -> Counters {
        Counters {
            venues: self.venues.len() as u64,
            note_minings: self.note_minings.len() as u64,
            listings: self.listings.len() as u64,
            rfqs: self.rfqs.len() as u64,
            orders: self.orders.len() as u64,
            matches: self.matches.len() as u64,
            fills: self.fills.len() as u64,
            settlements: self.settlements.len() as u64,
            liquidity_lanes: self.liquidity_lanes.len() as u64,
            price_bands: self.price_bands.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
            incentive_campaigns: self.incentive_campaigns.len() as u64,
            mining_positions: self.mining_positions.len() as u64,
            reward_epochs: self.reward_epochs.len() as u64,
            reward_claims: self.reward_claims.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            public_records: self.public_records.len() as u64,
        }
    }

    fn refresh_roots(&mut self) {
        self.counters = self.current_counters();
        self.roots = self.compute_roots();
    }

    fn publish_roots_only(&mut self, key: String, record: Value) -> Result<()> {
        if self.config.require_roots_only_public_records {
            require(
                record
                    .get("roots_only")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                "public records must be roots-only",
            )?;
        }
        insert_unique(&mut self.public_records, key, record)?;
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: &str) -> Result<()> {
        require_nonempty("nullifier", nullifier)?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        if self.nullifiers.insert(nullifier.to_string()) {
            Ok(())
        } else {
            Err("duplicate nullifier".to_string())
        }
    }

    fn require_venue_open(&self, venue_id: &str) -> Result<()> {
        let venue = self
            .venues
            .get(venue_id)
            .ok_or_else(|| "unknown venue".to_string())?;
        require(
            venue.status.accepts_orders(),
            "venue is not accepting orders",
        )
    }

    fn require_privacy_and_pq(&self, privacy_set_size: u64, pq_security_bits: u16) -> Result<()> {
        require(
            privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set is below configured anonymity threshold",
        )?;
        require(
            pq_security_bits >= self.config.min_pq_security_bits,
            "PQ authorization security bits below configured minimum",
        )
    }

    fn seed_devnet(&mut self) -> Result<()> {
        let venue = self.add_venue(LiquidityMiningVenueInput {
            venue_id: "pf-note-liquidity-mining-clob-devnet".to_string(),
            kind: LiquidityMiningKind::ContinuousLimitOrderBook,
            operator_commitment: demo_root("operator", "liquidity-mining"),
            eligible_note_mining_root: demo_root("eligible_mining_set", "autocall-senior"),
            quote_asset_root: demo_root("quote_asset", DEVNET_QUOTE_ASSET_ID),
            fee_vault_root: demo_root("fee_vault", "liquidity-mining"),
            risk_oracle_root: demo_root("risk_oracle", "prover-failure"),
            price_band_root: demo_root("price_bands", "autocall-senior"),
            min_trade_units: 1_000_000,
            max_trade_units: 25_000_000_000,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let mining = self.add_note_mining(EligibleNoteMiningInput {
            mining_id: "pf-note-liquidity-mining-autocall-senior-devnet".to_string(),
            venue_id: venue.venue_id.clone(),
            source_program_root: demo_root("source_program", "structured-note-autocall"),
            tranche_root: demo_root("tranche", "senior"),
            note_token_root: demo_root("note_token", DEVNET_NOTE_TOKEN_ID),
            seniority: NoteSeniority::Senior,
            risk_kind: ProverFailureRiskKind::RecursiveProofStall,
            outstanding_units: 100_000_000_000,
            tradable_units: 40_000_000_000,
            reference_nav_bps: 9_850,
            utilization_bps: 3_650,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_price_band(PriceBand {
            price_band_id: "pf-note-price-band-autocall-senior-devnet".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            nav_commitment_root: demo_root("nav", "autocall-senior"),
            lower_price_root: demo_root("lower_price", "autocall-senior"),
            upper_price_root: demo_root("upper_price", "autocall-senior"),
            deviation_bps: 280,
            oracle_attestation_root: demo_root("oracle_attestation", "price-band"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            price_band_commitment_root: demo_root("price_band_commitment", "autocall-senior"),
        })?;
        self.add_liquidity_lane(LiquidityLane {
            lane_id: "pf-note-liquidity-lane-senior-devnet".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            maker_set_root: demo_root("maker_set", "lane-a"),
            inventory_root: demo_root("inventory", "lane-a"),
            quote_depth_root: demo_root("quote_depth", "lane-a"),
            spread_bps: 36,
            utilization_bps: 2_900,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            lane_commitment_root: demo_root("lane_commitment", "lane-a"),
        })?;
        self.add_pq_attestation(PqMiningAttestation {
            attestation_id: "pq-liquidity-mining-attestation-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            subject_root: demo_root("attestation_subject", "venue-open"),
            committee_root: demo_root("committee", "liquidity-mining"),
            signature_root: demo_root("signature", "venue-open"),
            quorum_weight: self.config.attestation_quorum,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            attestation_commitment_root: demo_root("attestation_commitment", "venue-open"),
        })?;
        let listing = self.add_listing(ListingInput {
            listing_id: "pf-note-listing-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            seller_commitment: demo_root("seller", "alice"),
            note_position_root: demo_root("note_position", "alice"),
            ask_quote_root: demo_root("ask_quote", "alice"),
            reserve_price_root: demo_root("reserve_price", "alice"),
            quantity_units: 5_000_000_000,
            min_fill_units: 500_000_000,
            expires_l2_height: DEVNET_L2_HEIGHT + self.config.listing_ttl_blocks,
            nullifier: demo_root("nullifier", "listing-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let rfq = self.open_rfq(RfqInput {
            rfq_id: "pf-note-rfq-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            requester_commitment: demo_root("requester", "bob"),
            side: OrderSide::BuyNote,
            notional_root: demo_root("notional", "bob"),
            constraints_root: demo_root("constraints", "bob"),
            response_committee_root: demo_root("response_committee", "dealer-set-a"),
            expires_l2_height: DEVNET_L2_HEIGHT + self.config.rfq_ttl_blocks,
            nullifier: demo_root("nullifier", "rfq-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let maker = self.submit_order(OrderInput {
            order_id: "pf-note-order-maker-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            listing_id: Some(listing.listing_id.clone()),
            rfq_id: None,
            trader_commitment: demo_root("trader", "alice"),
            side: OrderSide::SellNote,
            kind: OrderKind::MakerOnly,
            price_commitment_root: demo_root("price", "maker"),
            quantity_commitment_root: demo_root("quantity", "maker"),
            collateral_commitment_root: demo_root("collateral", "maker"),
            max_fee_root: demo_root("max_fee", "maker"),
            expires_l2_height: DEVNET_L2_HEIGHT + self.config.order_ttl_blocks,
            nullifier: demo_root("nullifier", "maker-order-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let taker = self.submit_order(OrderInput {
            order_id: "pf-note-order-taker-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            listing_id: Some(listing.listing_id.clone()),
            rfq_id: Some(rfq.rfq_id.clone()),
            trader_commitment: demo_root("trader", "bob"),
            side: OrderSide::BuyNote,
            kind: OrderKind::RfqResponse,
            price_commitment_root: demo_root("price", "taker"),
            quantity_commitment_root: demo_root("quantity", "taker"),
            collateral_commitment_root: demo_root("collateral", "taker"),
            max_fee_root: demo_root("max_fee", "taker"),
            expires_l2_height: DEVNET_L2_HEIGHT + self.config.order_ttl_blocks,
            nullifier: demo_root("nullifier", "taker-order-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let intent = self.match_orders(MatchIntentInput {
            match_id: "pf-note-match-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            listing_id: Some(listing.listing_id),
            maker_order_id: maker.order_id,
            taker_order_id: taker.order_id,
            price_band_id: "pf-note-price-band-autocall-senior-devnet".to_string(),
            matched_quantity_root: demo_root("matched_quantity", "match-0"),
            clearing_price_root: demo_root("clearing_price", "match-0"),
            fee_quote_root: demo_root("fee_quote", "match-0"),
            matcher_attestation_root: demo_root("matcher_attestation", "match-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let fill = self.add_trade_fill(TradeFillInput {
            fill_id: "pf-note-fill-devnet-0".to_string(),
            match_id: intent.match_id,
            venue_id: venue.venue_id.clone(),
            mining_id: mining.mining_id.clone(),
            debit_root: demo_root("debit", "fill-0"),
            credit_root: demo_root("credit", "fill-0"),
            note_transfer_root: demo_root("note_transfer", "fill-0"),
            quote_transfer_root: demo_root("quote_transfer", "fill-0"),
            fee_root: demo_root("fee", "fill-0"),
            rebate_root: demo_root("rebate", "fill-0"),
            filled_units: 1_250_000_000,
            settlement_deadline_l2_height: DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks,
            nullifier: demo_root("nullifier", "fill-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_settlement(SettlementInput {
            settlement_id: "pf-note-liquidity-mining-settlement-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            fill_set_root: root_from_record("DEVNET_FILL", &fill.public_record()),
            debit_batch_root: demo_root("debit_batch", "settlement-0"),
            credit_batch_root: demo_root("credit_batch", "settlement-0"),
            note_delivery_root: demo_root("note_delivery", "settlement-0"),
            quote_delivery_root: demo_root("quote_delivery", "settlement-0"),
            fee_batch_root: demo_root("fee_batch", "settlement-0"),
            rebate_batch_root: demo_root("rebate_batch", "settlement-0"),
            settled_fills: 1,
            protocol_fee_units: 12_500,
            settlement_fee_units: 7_500,
            maker_rebate_units: 4_000,
            pq_authorization_root: demo_root("pq_authorization", "settlement-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_fee_rebate_epoch(FeeRebateEpoch {
            rebate_epoch_id: "pf-note-liquidity-mining-rebate-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            maker_set_root: demo_root("maker_set", "rebate-0"),
            volume_root: demo_root("volume", "rebate-0"),
            fee_mining_root: demo_root("fee_mining", "rebate-0"),
            rebate_distribution_root: demo_root("rebate_distribution", "rebate-0"),
            epoch: DEVNET_EPOCH,
            rebate_bps: self.config.maker_rebate_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            rebate_commitment_root: demo_root("rebate_commitment", "rebate-0"),
        })?;
        let campaign = self.add_incentive_campaign(IncentiveCampaignInput {
            campaign_id: "pf-note-liquidity-mining-campaign-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            kind: IncentiveCampaignKind::FastSettlementBonus,
            reward_asset_root: demo_root("reward_asset", "private-dusd-plus-note"),
            reward_vault_root: demo_root("reward_vault", "mining-vault-0"),
            eligibility_circuit_root: demo_root("eligibility_circuit", "pq-private-lp"),
            emissions_curve_root: demo_root("emissions_curve", "fast-settlement-decay"),
            fee_discount_root: demo_root("fee_discount", "low-fee-maker"),
            boost_policy_root: demo_root("boost_policy", "pq-attested-speed"),
            starts_epoch: DEVNET_EPOCH,
            ends_epoch: DEVNET_EPOCH + 24,
            max_reward_bps: 420,
            fast_settlement_bonus_bps: 175,
            low_fee_cap_bps: self.config.protocol_fee_bps + self.config.settlement_fee_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let position = self.open_mining_position(MiningPositionInput {
            position_id: "pf-note-liquidity-mining-position-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            venue_id: venue.venue_id.clone(),
            note_mining_id: mining.mining_id,
            miner_commitment: demo_root("miner", "alice-private-maker"),
            stake_commitment_root: demo_root("stake", "position-0"),
            note_inventory_root: demo_root("note_inventory", "position-0"),
            protected_notional_root: demo_root("protected_notional", "position-0"),
            settlement_speed_root: demo_root("settlement_speed", "position-0"),
            fee_budget_root: demo_root("fee_budget", "position-0"),
            pq_attestation_root: demo_root("pq_attestation", "position-0"),
            lock_start_l2_height: DEVNET_L2_HEIGHT,
            lock_end_l2_height: DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks * 64,
            nullifier: demo_root("nullifier", "mining-position-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let reward_epoch = self.close_reward_epoch(RewardEpochInput {
            reward_epoch_id: "pf-note-liquidity-mining-reward-epoch-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            venue_id: venue.venue_id.clone(),
            epoch: DEVNET_EPOCH,
            eligible_position_set_root: demo_root("eligible_position_set", "reward-epoch-0"),
            volume_score_root: demo_root("volume_score", "reward-epoch-0"),
            settlement_speed_score_root: demo_root("settlement_speed_score", "reward-epoch-0"),
            pq_security_score_root: demo_root("pq_security_score", "reward-epoch-0"),
            fee_efficiency_score_root: demo_root("fee_efficiency_score", "reward-epoch-0"),
            reward_distribution_root: demo_root("reward_distribution", "reward-epoch-0"),
            carry_forward_root: demo_root("carry_forward", "reward-epoch-0"),
            settled_l2_height: DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks,
            settled_monero_height: DEVNET_MONERO_HEIGHT + 2,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.claim_reward(RewardClaimInput {
            claim_id: "pf-note-liquidity-mining-claim-devnet-0".to_string(),
            reward_epoch_id: reward_epoch.reward_epoch_id,
            campaign_id: campaign.campaign_id,
            position_id: position.position_id,
            claimant_commitment: demo_root("claimant", "alice-private-maker"),
            reward_note_transfer_root: demo_root("reward_note_transfer", "claim-0"),
            reward_asset_transfer_root: demo_root("reward_asset_transfer", "claim-0"),
            fee_rebate_transfer_root: demo_root("fee_rebate_transfer", "claim-0"),
            proof_bundle_root: demo_root("proof_bundle", "claim-0"),
            settlement_authorization_root: demo_root("settlement_authorization", "claim-0"),
            nullifier: demo_root("nullifier", "reward-claim-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.refresh_roots();
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

fn roots_safe_record(kind: &str, id: &str, commitment_root: &str) -> Value {
    json!({
        "kind": kind,
        "id": id,
        "commitment_root": commitment_root,
        "roots_only": true,
        "protocol_version": PROTOCOL_VERSION,
    })
}

fn root_from_record(label: &str, value: &Value) -> String {
    domain_hash(
        label,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn payload_root(label: &str, value: &Value) -> String {
    domain_hash(
        PAYLOAD_ROOT_SUITE,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}

fn demo_root(label: &str, salt: &str) -> String {
    domain_hash(
        &format!("{PAYLOAD_ROOT_SUITE}:devnet:{label}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(salt)],
        32,
    )
}

fn public_record_for<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("serializable runtime public record")
}

fn map_public_root<T, F>(label: &str, map: &BTreeMap<String, T>, f: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": f(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn value_map_root(label: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "label": label,
                "key": key,
                "record": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn set_root(label: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!({
                "label": label,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(label, &leaves)
}

fn insert_unique<T>(map: &mut BTreeMap<String, T>, key: String, value: T) -> Result<()> {
    if map.contains_key(&key) {
        Err(format!("duplicate key {key}"))
    } else {
        map.insert(key, value);
        Ok(())
    }
}

fn ensure_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(value <= MAX_BPS, &format!("{label} exceeds MAX_BPS"))
}
