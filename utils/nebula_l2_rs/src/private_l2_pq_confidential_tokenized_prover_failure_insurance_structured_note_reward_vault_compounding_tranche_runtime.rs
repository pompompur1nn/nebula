use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedProverFailureInsuranceStructuredNoteRewardVaultCompoundingTrancheRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_REWARD_VAULT_COMPOUNDING_TRANCHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-reward-vault-compounding-tranche-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_PROVER_FAILURE_INSURANCE_STRUCTURED_NOTE_REWARD_VAULT_COMPOUNDING_TRANCHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_REWARD_VAULT_AUTHORIZATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-prover-failure-note-reward-vault-auth-v1";
pub const VAULT_VENUE_SUITE: &str =
    "private-prover-failure-structured-note-reward-vault-venue-root-v1";
pub const ELIGIBLE_NOTE_VAULT_SUITE: &str =
    "confidential-tokenized-prover-failure-structured-note-eligible-vault-root-v1";
pub const SEALED_LISTING_SUITE: &str =
    "sealed-confidential-prover-failure-structured-note-reward-vault-listing-root-v1";
pub const PRIVATE_RFQ_SUITE: &str =
    "private-prover-failure-structured-note-reward-vault-rfq-root-v1";
pub const ORDER_COMMITMENT_SUITE: &str =
    "pq-private-prover-failure-structured-note-reward-vault-order-commitment-root-v1";
pub const MATCH_INTENT_SUITE: &str =
    "confidential-prover-failure-structured-note-reward-vault-match-intent-root-v1";
pub const TRADE_FILL_SUITE: &str =
    "speedy-prover-failure-structured-note-reward-vault-trade-fill-root-v1";
pub const ATOMIC_SETTLEMENT_SUITE: &str =
    "low-fee-prover-failure-structured-note-reward-vault-atomic-settlement-root-v1";
pub const LIQUIDITY_LANE_SUITE: &str =
    "defi-prover-failure-structured-note-reward-vault-liquidity-lane-root-v1";
pub const PRICE_BAND_SUITE: &str =
    "privacy-preserving-prover-failure-structured-note-reward-vault-price-band-root-v1";
pub const PQ_ATTESTATION_SUITE: &str =
    "pq-prover-failure-structured-note-reward-vault-attestation-root-v1";
pub const FEE_REBATE_SUITE: &str =
    "low-fee-prover-failure-structured-note-reward-vault-fee-rebate-root-v1";
pub const REWARD_CAMPAIGN_SUITE: &str =
    "defi-tokenized-prover-failure-structured-note-reward-vault-campaign-root-v1";
pub const REWARD_TRANCHE_SUITE: &str =
    "confidential-prover-failure-structured-note-reward-vault-tranche-root-v1";
pub const REWARD_EPOCH_SUITE: &str =
    "speedy-low-fee-prover-failure-structured-note-reward-vault-epoch-root-v1";
pub const REWARD_CLAIM_SUITE: &str =
    "pq-private-prover-failure-structured-note-reward-vault-claim-root-v1";
pub const REWARD_BOOST_SUITE: &str =
    "privacy-preserving-prover-failure-structured-note-reward-vault-boost-root-v1";
pub const COMPOUNDING_SUBSCRIPTION_SUITE: &str =
    "confidential-prover-failure-structured-note-reward-vault-compounding-subscription-root-v1";
pub const REWARD_DEPOSIT_SUITE: &str =
    "private-prover-failure-structured-note-reward-vault-compounding-reward-deposit-root-v1";
pub const COMPOUNDING_EPOCH_SUITE: &str =
    "low-fee-prover-failure-structured-note-reward-vault-compounding-epoch-root-v1";
pub const CLAIM_IMPAIRMENT_SUITE: &str =
    "claim-aware-prover-failure-structured-note-reward-vault-compounding-impairment-root-v1";
pub const NOTE_REDEMPTION_SUITE: &str =
    "confidential-prover-failure-structured-note-reward-vault-compounding-redemption-root-v1";
pub const REBATE_ACCOUNTING_SUITE: &str =
    "low-fee-prover-failure-structured-note-reward-vault-compounding-rebate-accounting-root-v1";
pub const TRANCHE_WATERFALL_SUITE: &str =
    "confidential-prover-failure-structured-note-reward-vault-compounding-tranche-waterfall-root-v1";
pub const QUARANTINE_SUITE: &str =
    "pq-prover-failure-structured-note-reward-vault-compounding-quarantine-root-v1";
pub const NULLIFIER_SUITE: &str =
    "anti-replay-prover-failure-structured-note-reward-vault-nullifier-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-prover-failure-insurance-structured-note-reward-vault-compounding-public-record-v1";
pub const STATE_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-reward-vault-compounding-tranche-state-root-v1";
pub const PAYLOAD_ROOT_SUITE: &str =
    "private-l2-pq-confidential-tokenized-prover-failure-insurance-structured-note-reward-vault-compounding-tranche-payload-root-v1";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-prover-failure-insurance-structured-note-reward-vault-compounding-tranche-devnet";
pub const DEVNET_RUNTIME_ID: &str =
    "private-l2-pq-prover-failure-insurance-structured-note-reward-vault-compounding-tranche-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_746_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 5_444_000;
pub const DEVNET_EPOCH: u64 = 25_616;
pub const DEVNET_NOTE_TOKEN_ID: &str = "tpfi-note-reward-vault-compounding-tranche-devnet";
pub const DEVNET_QUOTE_ASSET_ID: &str = "dusd-private-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_FAILURE_INDEX_ID: &str = "monero-private-l2-prover-failure-index-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 1;
pub const DEFAULT_MATCHING_FEE_BPS: u64 = 2;
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = 1;
pub const DEFAULT_MAKER_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_BASE_REWARD_RATE_BPS: u64 = 420;
pub const DEFAULT_FAILURE_PROTECTION_BOOST_BPS: u64 = 650;
pub const DEFAULT_SPEEDY_SETTLEMENT_BOOST_BPS: u64 = 120;
pub const DEFAULT_PRIVACY_BOOST_BPS: u64 = 180;
pub const DEFAULT_MAX_REWARD_BOOST_BPS: u64 = 2_500;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_VAULT_MAKER_QUORUM: u16 = 3;
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
pub const DEFAULT_MAX_NOTE_VAULTS: usize = 262_144;
pub const DEFAULT_MAX_LISTINGS: usize = 1_048_576;
pub const DEFAULT_MAX_RFQS: usize = 524_288;
pub const DEFAULT_MAX_ORDERS: usize = 2_097_152;
pub const DEFAULT_MAX_MATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_FILLS: usize = 1_048_576;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 524_288;
pub const DEFAULT_MAX_REWARD_CAMPAIGNS: usize = 131_072;
pub const DEFAULT_MAX_REWARD_TRANCHES: usize = 524_288;
pub const DEFAULT_MAX_REWARD_EPOCHS: usize = 524_288;
pub const DEFAULT_MAX_REWARD_CLAIMS: usize = 2_097_152;
pub const DEFAULT_MAX_REWARD_BOOSTS: usize = 1_048_576;
pub const DEFAULT_MAX_COMPOUNDING_SUBSCRIPTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_REWARD_DEPOSITS: usize = 1_048_576;
pub const DEFAULT_MAX_COMPOUNDING_EPOCHS: usize = 524_288;
pub const DEFAULT_MAX_CLAIM_IMPAIRMENTS: usize = 524_288;
pub const DEFAULT_MAX_NOTE_REDEMPTIONS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATE_ACCOUNTING_ENTRIES: usize = 1_048_576;
pub const DEFAULT_MAX_QUARANTINE_EVENTS: usize = 524_288;
pub const DEFAULT_MAX_NULLIFIERS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardVaultKind {
    NoteStakingVault,
    SettlementRewardVault,
    MakerIncentiveVault,
    FailureProtectionVault,
    PrivacySetGrowthVault,
    HybridDefiVault,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardCampaignStatus {
    Draft,
    Sealed,
    Active,
    DistributionPending,
    Settling,
    Finalized,
    Paused,
    Retired,
    Quarantined,
}

impl RewardCampaignStatus {
    pub fn accepts_epochs(self) -> bool {
        matches!(
            self,
            Self::Active | Self::DistributionPending | Self::Settling
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardEpochStatus {
    Draft,
    Open,
    Sealed,
    Proving,
    Claimable,
    Settled,
    Cancelled,
    Quarantined,
}

impl RewardEpochStatus {
    pub fn claimable(self) -> bool {
        matches!(self, Self::Claimable | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardClaimStatus {
    Draft,
    Submitted,
    Verified,
    Queued,
    Settled,
    Rejected,
    Quarantined,
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
    pub fn reward_vault_margin_bps(self) -> u64 {
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
    pub pq_reward_vault_authorization_suite: String,
    pub replay_domain: String,
    pub protocol_fee_bps: u64,
    pub matching_fee_bps: u64,
    pub settlement_fee_bps: u64,
    pub maker_rebate_bps: u64,
    pub base_reward_rate_bps: u64,
    pub failure_protection_boost_bps: u64,
    pub speedy_settlement_boost_bps: u64,
    pub privacy_boost_bps: u64,
    pub max_reward_boost_bps: u64,
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
    pub vault_maker_quorum: u16,
    pub settlement_quorum: u16,
    pub attestation_quorum: u16,
    pub low_fee_batch_limit: usize,
    pub max_venues: usize,
    pub max_note_vaults: usize,
    pub max_listings: usize,
    pub max_rfqs: usize,
    pub max_orders: usize,
    pub max_matches: usize,
    pub max_fills: usize,
    pub max_settlements: usize,
    pub max_reward_campaigns: usize,
    pub max_reward_tranches: usize,
    pub max_reward_epochs: usize,
    pub max_reward_claims: usize,
    pub max_reward_boosts: usize,
    pub max_compounding_subscriptions: usize,
    pub max_reward_deposits: usize,
    pub max_compounding_epochs: usize,
    pub max_claim_impairments: usize,
    pub max_note_redemptions: usize,
    pub max_rebate_accounting_entries: usize,
    pub max_quarantine_events: usize,
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
            pq_reward_vault_authorization_suite: PQ_REWARD_VAULT_AUTHORIZATION_SUITE.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            matching_fee_bps: DEFAULT_MATCHING_FEE_BPS,
            settlement_fee_bps: DEFAULT_SETTLEMENT_FEE_BPS,
            maker_rebate_bps: DEFAULT_MAKER_REBATE_BPS,
            base_reward_rate_bps: DEFAULT_BASE_REWARD_RATE_BPS,
            failure_protection_boost_bps: DEFAULT_FAILURE_PROTECTION_BOOST_BPS,
            speedy_settlement_boost_bps: DEFAULT_SPEEDY_SETTLEMENT_BOOST_BPS,
            privacy_boost_bps: DEFAULT_PRIVACY_BOOST_BPS,
            max_reward_boost_bps: DEFAULT_MAX_REWARD_BOOST_BPS,
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
            vault_maker_quorum: DEFAULT_VAULT_MAKER_QUORUM,
            settlement_quorum: DEFAULT_SETTLEMENT_QUORUM,
            attestation_quorum: DEFAULT_ATTESTATION_QUORUM,
            low_fee_batch_limit: DEFAULT_LOW_FEE_BATCH_LIMIT,
            max_venues: DEFAULT_MAX_VENUES,
            max_note_vaults: DEFAULT_MAX_NOTE_VAULTS,
            max_listings: DEFAULT_MAX_LISTINGS,
            max_rfqs: DEFAULT_MAX_RFQS,
            max_orders: DEFAULT_MAX_ORDERS,
            max_matches: DEFAULT_MAX_MATCHES,
            max_fills: DEFAULT_MAX_FILLS,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_reward_campaigns: DEFAULT_MAX_REWARD_CAMPAIGNS,
            max_reward_tranches: DEFAULT_MAX_REWARD_TRANCHES,
            max_reward_epochs: DEFAULT_MAX_REWARD_EPOCHS,
            max_reward_claims: DEFAULT_MAX_REWARD_CLAIMS,
            max_reward_boosts: DEFAULT_MAX_REWARD_BOOSTS,
            max_compounding_subscriptions: DEFAULT_MAX_COMPOUNDING_SUBSCRIPTIONS,
            max_reward_deposits: DEFAULT_MAX_REWARD_DEPOSITS,
            max_compounding_epochs: DEFAULT_MAX_COMPOUNDING_EPOCHS,
            max_claim_impairments: DEFAULT_MAX_CLAIM_IMPAIRMENTS,
            max_note_redemptions: DEFAULT_MAX_NOTE_REDEMPTIONS,
            max_rebate_accounting_entries: DEFAULT_MAX_REBATE_ACCOUNTING_ENTRIES,
            max_quarantine_events: DEFAULT_MAX_QUARANTINE_EVENTS,
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
        require_bps("base_reward_rate_bps", self.base_reward_rate_bps)?;
        require_bps(
            "failure_protection_boost_bps",
            self.failure_protection_boost_bps,
        )?;
        require_bps(
            "speedy_settlement_boost_bps",
            self.speedy_settlement_boost_bps,
        )?;
        require_bps("privacy_boost_bps", self.privacy_boost_bps)?;
        require_bps("max_reward_boost_bps", self.max_reward_boost_bps)?;
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
            "pq_reward_vault_authorization_suite": self.pq_reward_vault_authorization_suite,
            "replay_domain": self.replay_domain,
            "protocol_fee_bps": self.protocol_fee_bps,
            "matching_fee_bps": self.matching_fee_bps,
            "settlement_fee_bps": self.settlement_fee_bps,
            "maker_rebate_bps": self.maker_rebate_bps,
            "base_reward_rate_bps": self.base_reward_rate_bps,
            "failure_protection_boost_bps": self.failure_protection_boost_bps,
            "speedy_settlement_boost_bps": self.speedy_settlement_boost_bps,
            "privacy_boost_bps": self.privacy_boost_bps,
            "max_reward_boost_bps": self.max_reward_boost_bps,
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
            "vault_maker_quorum": self.vault_maker_quorum,
            "settlement_quorum": self.settlement_quorum,
            "attestation_quorum": self.attestation_quorum,
            "low_fee_batch_limit": self.low_fee_batch_limit,
            "max_compounding_subscriptions": self.max_compounding_subscriptions,
            "max_reward_deposits": self.max_reward_deposits,
            "max_compounding_epochs": self.max_compounding_epochs,
            "max_claim_impairments": self.max_claim_impairments,
            "max_note_redemptions": self.max_note_redemptions,
            "max_rebate_accounting_entries": self.max_rebate_accounting_entries,
            "max_quarantine_events": self.max_quarantine_events,
            "require_roots_only_public_records": self.require_roots_only_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub venues: u64,
    pub note_vaults: u64,
    pub listings: u64,
    pub rfqs: u64,
    pub orders: u64,
    pub matches: u64,
    pub fills: u64,
    pub settlements: u64,
    pub reward_campaigns: u64,
    pub reward_tranches: u64,
    pub reward_epochs: u64,
    pub reward_claims: u64,
    pub reward_boosts: u64,
    pub compounding_subscriptions: u64,
    pub reward_deposits: u64,
    pub compounding_epochs: u64,
    pub claim_impairments: u64,
    pub note_redemptions: u64,
    pub rebate_accounting_entries: u64,
    pub quarantine_events: u64,
    pub liquidity_lanes: u64,
    pub price_bands: u64,
    pub pq_attestations: u64,
    pub fee_rebates: u64,
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
    pub note_vault_root: String,
    pub listing_root: String,
    pub rfq_root: String,
    pub order_root: String,
    pub match_root: String,
    pub fill_root: String,
    pub settlement_root: String,
    pub reward_campaign_root: String,
    pub reward_tranche_root: String,
    pub reward_epoch_root: String,
    pub reward_claim_root: String,
    pub reward_boost_root: String,
    pub compounding_subscription_root: String,
    pub reward_deposit_root: String,
    pub compounding_epoch_root: String,
    pub claim_impairment_root: String,
    pub note_redemption_root: String,
    pub rebate_accounting_root: String,
    pub quarantine_root: String,
    pub liquidity_lane_root: String,
    pub price_band_root: String,
    pub pq_attestation_root: String,
    pub fee_rebate_root: String,
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
            note_vault_root: empty.clone(),
            listing_root: empty.clone(),
            rfq_root: empty.clone(),
            order_root: empty.clone(),
            match_root: empty.clone(),
            fill_root: empty.clone(),
            settlement_root: empty.clone(),
            reward_campaign_root: empty.clone(),
            reward_tranche_root: empty.clone(),
            reward_epoch_root: empty.clone(),
            reward_claim_root: empty.clone(),
            reward_boost_root: empty.clone(),
            compounding_subscription_root: empty.clone(),
            reward_deposit_root: empty.clone(),
            compounding_epoch_root: empty.clone(),
            claim_impairment_root: empty.clone(),
            note_redemption_root: empty.clone(),
            rebate_accounting_root: empty.clone(),
            quarantine_root: empty.clone(),
            liquidity_lane_root: empty.clone(),
            price_band_root: empty.clone(),
            pq_attestation_root: empty.clone(),
            fee_rebate_root: empty.clone(),
            nullifier_root: empty.clone(),
            public_record_root: empty,
        }
    }

    pub fn public_record(&self) -> Value {
        public_record_for(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardVaultVenueInput {
    pub venue_id: String,
    pub kind: RewardVaultKind,
    pub operator_commitment: String,
    pub eligible_note_vault_root: String,
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
pub struct RewardVaultVenue {
    pub venue_id: String,
    pub kind: RewardVaultKind,
    pub status: VenueStatus,
    pub operator_commitment: String,
    pub eligible_note_vault_root: String,
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

impl RewardVaultVenue {
    pub fn public_record(&self) -> Value {
        roots_safe_record("vault_venue", &self.venue_id, &self.venue_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EligibleNoteVaultInput {
    pub vault_id: String,
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
pub struct EligibleNoteVault {
    pub vault_id: String,
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
    pub vault_commitment_root: String,
}

impl EligibleNoteVault {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "eligible_note_vault",
            &self.vault_id,
            &self.vault_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ListingInput {
    pub listing_id: String,
    pub venue_id: String,
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
    pub vault_id: String,
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
pub struct PqVaultAttestation {
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

impl PqVaultAttestation {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "pq_vault_attestation",
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
    pub fee_vault_root: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardCampaignInput {
    pub campaign_id: String,
    pub venue_id: String,
    pub sponsor_commitment: String,
    pub reward_asset_root: String,
    pub eligible_vault_set_root: String,
    pub emission_schedule_root: String,
    pub distribution_policy_root: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub base_reward_rate_bps: u64,
    pub max_boost_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardCampaignEntry {
    pub campaign_id: String,
    pub venue_id: String,
    pub status: RewardCampaignStatus,
    pub sponsor_commitment: String,
    pub reward_asset_root: String,
    pub eligible_vault_set_root: String,
    pub emission_schedule_root: String,
    pub distribution_policy_root: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub base_reward_rate_bps: u64,
    pub max_boost_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub campaign_commitment_root: String,
}

impl RewardCampaignEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "reward_campaign",
            &self.campaign_id,
            &self.campaign_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardTrancheInput {
    pub tranche_id: String,
    pub campaign_id: String,
    pub vault_id: String,
    pub seniority: NoteSeniority,
    pub risk_kind: ProverFailureRiskKind,
    pub eligibility_root: String,
    pub stake_position_root: String,
    pub failure_cover_root: String,
    pub reward_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardTrancheEntry {
    pub tranche_id: String,
    pub campaign_id: String,
    pub vault_id: String,
    pub seniority: NoteSeniority,
    pub risk_kind: ProverFailureRiskKind,
    pub eligibility_root: String,
    pub stake_position_root: String,
    pub failure_cover_root: String,
    pub reward_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub tranche_commitment_root: String,
}

impl RewardTrancheEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "reward_tranche",
            &self.tranche_id,
            &self.tranche_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardEpochInput {
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub tranche_set_root: String,
    pub eligible_activity_root: String,
    pub sealed_score_root: String,
    pub reward_pool_root: String,
    pub settlement_batch_root: String,
    pub epoch: u64,
    pub claimable_after_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardEpochEntry {
    pub reward_epoch_id: String,
    pub campaign_id: String,
    pub status: RewardEpochStatus,
    pub tranche_set_root: String,
    pub eligible_activity_root: String,
    pub sealed_score_root: String,
    pub reward_pool_root: String,
    pub settlement_batch_root: String,
    pub epoch: u64,
    pub claimable_after_l2_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub epoch_commitment_root: String,
}

impl RewardEpochEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "reward_epoch",
            &self.reward_epoch_id,
            &self.epoch_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardClaimInput {
    pub claim_id: String,
    pub reward_epoch_id: String,
    pub claimant_commitment: String,
    pub note_position_root: String,
    pub entitlement_root: String,
    pub destination_root: String,
    pub pq_authorization_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardClaimEntry {
    pub claim_id: String,
    pub reward_epoch_id: String,
    pub status: RewardClaimStatus,
    pub claimant_commitment: String,
    pub note_position_root: String,
    pub entitlement_root: String,
    pub destination_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub claim_commitment_root: String,
}

impl RewardClaimEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record("reward_claim", &self.claim_id, &self.claim_commitment_root)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardBoostEntry {
    pub boost_id: String,
    pub campaign_id: String,
    pub vault_id: String,
    pub boost_policy_root: String,
    pub failure_protection_root: String,
    pub privacy_growth_root: String,
    pub speedy_settlement_root: String,
    pub boost_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub boost_commitment_root: String,
}

impl RewardBoostEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record("reward_boost", &self.boost_id, &self.boost_commitment_root)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompoundingStatus {
    Active,
    Paused,
    ClaimImpaired,
    Redeeming,
    Redeemed,
    Quarantined,
}

impl CompoundingStatus {
    pub fn accepts_accrual(self) -> bool {
        matches!(self, Self::Active | Self::ClaimImpaired)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubscriptionInput {
    pub subscription_id: String,
    pub campaign_id: String,
    pub vault_id: String,
    pub owner_commitment: String,
    pub note_position_root: String,
    pub auto_compound_policy_root: String,
    pub reward_destination_root: String,
    pub subscribed_units: u64,
    pub min_compound_units: u64,
    pub max_haircut_bps: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompoundingSubscription {
    pub subscription_id: String,
    pub campaign_id: String,
    pub vault_id: String,
    pub status: CompoundingStatus,
    pub owner_commitment: String,
    pub note_position_root: String,
    pub auto_compound_policy_root: String,
    pub reward_destination_root: String,
    pub subscribed_units: u64,
    pub compounded_units: u64,
    pub accrued_reward_units: u64,
    pub claim_haircut_bps: u64,
    pub min_compound_units: u64,
    pub max_haircut_bps: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_l2_height: u64,
    pub subscription_commitment_root: String,
}

impl CompoundingSubscription {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "compounding_subscription",
            &self.subscription_id,
            &self.subscription_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardDepositInput {
    pub deposit_id: String,
    pub campaign_id: String,
    pub reward_asset_root: String,
    pub sponsor_commitment: String,
    pub amount_units: u64,
    pub epoch: u64,
    pub deposit_note_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RewardDepositEntry {
    pub deposit_id: String,
    pub campaign_id: String,
    pub reward_asset_root: String,
    pub sponsor_commitment: String,
    pub amount_units: u64,
    pub unallocated_units: u64,
    pub epoch: u64,
    pub deposit_note_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub deposit_commitment_root: String,
}

impl RewardDepositEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "reward_deposit",
            &self.deposit_id,
            &self.deposit_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompoundingEpochInput {
    pub compounding_epoch_id: String,
    pub campaign_id: String,
    pub subscription_set_root: String,
    pub reward_deposit_set_root: String,
    pub accrued_reward_root: String,
    pub compounded_note_root: String,
    pub fee_batch_root: String,
    pub rebate_batch_root: String,
    pub epoch: u64,
    pub gross_reward_units: u64,
    pub compounded_reward_units: u64,
    pub low_fee_units: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompoundingEpochEntry {
    pub compounding_epoch_id: String,
    pub campaign_id: String,
    pub status: RewardEpochStatus,
    pub subscription_set_root: String,
    pub reward_deposit_set_root: String,
    pub accrued_reward_root: String,
    pub compounded_note_root: String,
    pub fee_batch_root: String,
    pub rebate_batch_root: String,
    pub epoch: u64,
    pub gross_reward_units: u64,
    pub compounded_reward_units: u64,
    pub low_fee_units: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub epoch_commitment_root: String,
}

impl CompoundingEpochEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "compounding_epoch",
            &self.compounding_epoch_id,
            &self.epoch_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimImpairmentInput {
    pub impairment_id: String,
    pub subscription_id: String,
    pub claim_root: String,
    pub failure_risk: ProverFailureRiskKind,
    pub claim_amount_root: String,
    pub haircut_bps: u64,
    pub underwriter_decision_root: String,
    pub prover_failure_evidence_root: String,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimImpairmentEntry {
    pub impairment_id: String,
    pub subscription_id: String,
    pub claim_root: String,
    pub failure_risk: ProverFailureRiskKind,
    pub claim_amount_root: String,
    pub haircut_bps: u64,
    pub underwriter_decision_root: String,
    pub prover_failure_evidence_root: String,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub impairment_commitment_root: String,
}

impl ClaimImpairmentEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "claim_impairment",
            &self.impairment_id,
            &self.impairment_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteRedemptionInput {
    pub redemption_id: String,
    pub subscription_id: String,
    pub destination_root: String,
    pub redeemed_note_root: String,
    pub reward_payout_root: String,
    pub redeemed_units: u64,
    pub fee_units: u64,
    pub pq_authorization_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NoteRedemptionEntry {
    pub redemption_id: String,
    pub subscription_id: String,
    pub destination_root: String,
    pub redeemed_note_root: String,
    pub reward_payout_root: String,
    pub redeemed_units: u64,
    pub fee_units: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub redemption_commitment_root: String,
}

impl NoteRedemptionEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "note_redemption",
            &self.redemption_id,
            &self.redemption_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateAccountingInput {
    pub rebate_accounting_id: String,
    pub subscription_id: String,
    pub compounding_epoch_id: String,
    pub maker_rebate_root: String,
    pub low_fee_settlement_root: String,
    pub rebate_units: u64,
    pub fee_units: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheWaterfallInput {
    pub waterfall_id: String,
    pub tranche_id: String,
    pub compounding_epoch_id: String,
    pub senior_note_root: String,
    pub mezzanine_note_root: String,
    pub junior_note_root: String,
    pub residual_note_root: String,
    pub claim_impairment_root: String,
    pub gross_reward_units: u64,
    pub senior_payout_units: u64,
    pub mezzanine_payout_units: u64,
    pub junior_payout_units: u64,
    pub residual_payout_units: u64,
    pub retained_reserve_units: u64,
    pub low_fee_settlement_units: u64,
    pub haircut_bps: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheWaterfallEntry {
    pub waterfall_id: String,
    pub tranche_id: String,
    pub compounding_epoch_id: String,
    pub senior_note_root: String,
    pub mezzanine_note_root: String,
    pub junior_note_root: String,
    pub residual_note_root: String,
    pub claim_impairment_root: String,
    pub gross_reward_units: u64,
    pub senior_payout_units: u64,
    pub mezzanine_payout_units: u64,
    pub junior_payout_units: u64,
    pub residual_payout_units: u64,
    pub retained_reserve_units: u64,
    pub low_fee_settlement_units: u64,
    pub haircut_bps: u64,
    pub pq_underwriter_attestation_root: String,
    pub pq_prover_attestation_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub waterfall_commitment_root: String,
}

impl TrancheWaterfallEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "tranche_waterfall",
            &self.waterfall_id,
            &self.waterfall_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheWaterfallReceipt {
    pub entry: TrancheWaterfallEntry,
    pub payout_total_units: u64,
    pub impaired_units: u64,
    pub public_waterfall_root: String,
}

impl TrancheWaterfallReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tranche_waterfall_receipt",
            "entry": self.entry.public_record(),
            "payout_total_units": self.payout_total_units,
            "impaired_units": self.impaired_units,
            "public_waterfall_root": self.public_waterfall_root,
            "roots_only": true,
            "protocol_version": PROTOCOL_VERSION,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RebateAccountingEntry {
    pub rebate_accounting_id: String,
    pub subscription_id: String,
    pub compounding_epoch_id: String,
    pub maker_rebate_root: String,
    pub low_fee_settlement_root: String,
    pub rebate_units: u64,
    pub fee_units: u64,
    pub net_fee_units: u64,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub rebate_accounting_commitment_root: String,
}

impl RebateAccountingEntry {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "rebate_accounting",
            &self.rebate_accounting_id,
            &self.rebate_accounting_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineInput {
    pub quarantine_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub reviewer_committee_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuarantineEvent {
    pub quarantine_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub reason_root: String,
    pub evidence_root: String,
    pub reviewer_committee_root: String,
    pub pq_authorization_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub quarantine_commitment_root: String,
}

impl QuarantineEvent {
    pub fn public_record(&self) -> Value {
        roots_safe_record(
            "quarantine_event",
            &self.quarantine_id,
            &self.quarantine_commitment_root,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub venues: BTreeMap<String, RewardVaultVenue>,
    pub note_vaults: BTreeMap<String, EligibleNoteVault>,
    pub listings: BTreeMap<String, SealedListing>,
    pub rfqs: BTreeMap<String, PrivateRfq>,
    pub orders: BTreeMap<String, OrderCommitment>,
    pub matches: BTreeMap<String, MatchIntent>,
    pub fills: BTreeMap<String, TradeFill>,
    pub settlements: BTreeMap<String, AtomicSettlementBatch>,
    pub reward_campaigns: BTreeMap<String, RewardCampaignEntry>,
    pub reward_tranches: BTreeMap<String, RewardTrancheEntry>,
    pub reward_epochs: BTreeMap<String, RewardEpochEntry>,
    pub reward_claims: BTreeMap<String, RewardClaimEntry>,
    pub reward_boosts: BTreeMap<String, RewardBoostEntry>,
    pub compounding_subscriptions: BTreeMap<String, CompoundingSubscription>,
    pub reward_deposits: BTreeMap<String, RewardDepositEntry>,
    pub compounding_epochs: BTreeMap<String, CompoundingEpochEntry>,
    pub claim_impairments: BTreeMap<String, ClaimImpairmentEntry>,
    pub note_redemptions: BTreeMap<String, NoteRedemptionEntry>,
    pub rebate_accounting: BTreeMap<String, RebateAccountingEntry>,
    pub quarantine_events: BTreeMap<String, QuarantineEvent>,
    pub liquidity_lanes: BTreeMap<String, LiquidityLane>,
    pub price_bands: BTreeMap<String, PriceBand>,
    pub pq_attestations: BTreeMap<String, PqVaultAttestation>,
    pub fee_rebates: BTreeMap<String, FeeRebateEpoch>,
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
            note_vaults: BTreeMap::new(),
            listings: BTreeMap::new(),
            rfqs: BTreeMap::new(),
            orders: BTreeMap::new(),
            matches: BTreeMap::new(),
            fills: BTreeMap::new(),
            settlements: BTreeMap::new(),
            reward_campaigns: BTreeMap::new(),
            reward_tranches: BTreeMap::new(),
            reward_epochs: BTreeMap::new(),
            reward_claims: BTreeMap::new(),
            reward_boosts: BTreeMap::new(),
            compounding_subscriptions: BTreeMap::new(),
            reward_deposits: BTreeMap::new(),
            compounding_epochs: BTreeMap::new(),
            claim_impairments: BTreeMap::new(),
            note_redemptions: BTreeMap::new(),
            rebate_accounting: BTreeMap::new(),
            quarantine_events: BTreeMap::new(),
            liquidity_lanes: BTreeMap::new(),
            price_bands: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state.seed_devnet().expect("valid reward vault devnet");
        state
    }

    pub fn add_venue(&mut self, input: RewardVaultVenueInput) -> Result<RewardVaultVenue> {
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
        let root = payload_root("vault_venue", &public_record_for(&input));
        let venue = RewardVaultVenue {
            venue_id: input.venue_id,
            kind: input.kind,
            status: VenueStatus::Active,
            operator_commitment: input.operator_commitment,
            eligible_note_vault_root: input.eligible_note_vault_root,
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

    pub fn add_note_vault(&mut self, input: EligibleNoteVaultInput) -> Result<EligibleNoteVault> {
        ensure_capacity(
            "note_vaults",
            self.note_vaults.len(),
            self.config.max_note_vaults,
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
        let root = payload_root("eligible_note_vault", &public_record_for(&input));
        let vault = EligibleNoteVault {
            vault_id: input.vault_id,
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
            vault_commitment_root: root,
        };
        insert_unique(&mut self.note_vaults, vault.vault_id.clone(), vault.clone())?;
        self.publish_roots_only(
            format!("note_vault:{}", vault.vault_id),
            vault.public_record(),
        )?;
        self.refresh_roots();
        Ok(vault)
    }

    pub fn add_listing(&mut self, input: ListingInput) -> Result<SealedListing> {
        ensure_capacity("listings", self.listings.len(), self.config.max_listings)?;
        self.require_venue_open(&input.venue_id)?;
        require(
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
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
            vault_id: input.vault_id,
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
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
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
            vault_id: input.vault_id,
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
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
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
            vault_id: input.vault_id,
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
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
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
            vault_id: input.vault_id,
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
            vault_id: input.vault_id,
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

    pub fn open_reward_campaign(
        &mut self,
        input: RewardCampaignInput,
    ) -> Result<RewardCampaignEntry> {
        ensure_capacity(
            "reward_campaigns",
            self.reward_campaigns.len(),
            self.config.max_reward_campaigns,
        )?;
        require(self.venues.contains_key(&input.venue_id), "unknown venue")?;
        require(
            input.start_epoch <= input.end_epoch,
            "campaign epoch range is inverted",
        )?;
        require_bps("base_reward_rate_bps", input.base_reward_rate_bps)?;
        require_bps("max_boost_bps", input.max_boost_bps)?;
        require(
            input.max_boost_bps <= self.config.max_reward_boost_bps,
            "campaign boost exceeds configured cap",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("reward_campaign", &public_record_for(&input));
        let campaign = RewardCampaignEntry {
            campaign_id: input.campaign_id,
            venue_id: input.venue_id,
            status: RewardCampaignStatus::Active,
            sponsor_commitment: input.sponsor_commitment,
            reward_asset_root: input.reward_asset_root,
            eligible_vault_set_root: input.eligible_vault_set_root,
            emission_schedule_root: input.emission_schedule_root,
            distribution_policy_root: input.distribution_policy_root,
            start_epoch: input.start_epoch,
            end_epoch: input.end_epoch,
            base_reward_rate_bps: input.base_reward_rate_bps,
            max_boost_bps: input.max_boost_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            campaign_commitment_root: root,
        };
        insert_unique(
            &mut self.reward_campaigns,
            campaign.campaign_id.clone(),
            campaign.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_campaign:{}", campaign.campaign_id),
            campaign.public_record(),
        )?;
        self.refresh_roots();
        Ok(campaign)
    }

    pub fn add_reward_tranche(&mut self, input: RewardTrancheInput) -> Result<RewardTrancheEntry> {
        ensure_capacity(
            "reward_tranches",
            self.reward_tranches.len(),
            self.config.max_reward_tranches,
        )?;
        let campaign = self
            .reward_campaigns
            .get(&input.campaign_id)
            .ok_or_else(|| "unknown reward campaign".to_string())?;
        require(
            campaign.status.accepts_epochs(),
            "reward campaign is not active",
        )?;
        require(
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
        )?;
        require_bps("reward_weight_bps", input.reward_weight_bps)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("reward_tranche", &public_record_for(&input));
        let tranche = RewardTrancheEntry {
            tranche_id: input.tranche_id,
            campaign_id: input.campaign_id,
            vault_id: input.vault_id,
            seniority: input.seniority,
            risk_kind: input.risk_kind,
            eligibility_root: input.eligibility_root,
            stake_position_root: input.stake_position_root,
            failure_cover_root: input.failure_cover_root,
            reward_weight_bps: input.reward_weight_bps,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            tranche_commitment_root: root,
        };
        insert_unique(
            &mut self.reward_tranches,
            tranche.tranche_id.clone(),
            tranche.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_tranche:{}", tranche.tranche_id),
            tranche.public_record(),
        )?;
        self.refresh_roots();
        Ok(tranche)
    }

    pub fn seal_reward_epoch(&mut self, input: RewardEpochInput) -> Result<RewardEpochEntry> {
        ensure_capacity(
            "reward_epochs",
            self.reward_epochs.len(),
            self.config.max_reward_epochs,
        )?;
        let campaign = self
            .reward_campaigns
            .get(&input.campaign_id)
            .ok_or_else(|| "unknown reward campaign".to_string())?;
        require(
            campaign.status.accepts_epochs(),
            "reward campaign is not active",
        )?;
        require(
            input.epoch >= campaign.start_epoch && input.epoch <= campaign.end_epoch,
            "reward epoch outside campaign range",
        )?;
        require(
            input.claimable_after_l2_height
                >= DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks,
            "reward epoch claim window is too near",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("reward_epoch", &public_record_for(&input));
        let epoch = RewardEpochEntry {
            reward_epoch_id: input.reward_epoch_id,
            campaign_id: input.campaign_id,
            status: RewardEpochStatus::Claimable,
            tranche_set_root: input.tranche_set_root,
            eligible_activity_root: input.eligible_activity_root,
            sealed_score_root: input.sealed_score_root,
            reward_pool_root: input.reward_pool_root,
            settlement_batch_root: input.settlement_batch_root,
            epoch: input.epoch,
            claimable_after_l2_height: input.claimable_after_l2_height,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            epoch_commitment_root: root,
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

    pub fn submit_reward_claim(&mut self, input: RewardClaimInput) -> Result<RewardClaimEntry> {
        ensure_capacity(
            "reward_claims",
            self.reward_claims.len(),
            self.config.max_reward_claims,
        )?;
        let epoch = self
            .reward_epochs
            .get(&input.reward_epoch_id)
            .ok_or_else(|| "unknown reward epoch".to_string())?;
        require(epoch.status.claimable(), "reward epoch is not claimable")?;
        self.consume_nullifier(&input.nullifier)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("reward_claim", &public_record_for(&input));
        let claim = RewardClaimEntry {
            claim_id: input.claim_id,
            reward_epoch_id: input.reward_epoch_id,
            status: RewardClaimStatus::Verified,
            claimant_commitment: input.claimant_commitment,
            note_position_root: input.note_position_root,
            entitlement_root: input.entitlement_root,
            destination_root: input.destination_root,
            pq_authorization_root: input.pq_authorization_root,
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

    pub fn add_reward_boost(&mut self, boost: RewardBoostEntry) -> Result<()> {
        ensure_capacity(
            "reward_boosts",
            self.reward_boosts.len(),
            self.config.max_reward_boosts,
        )?;
        require(
            self.reward_campaigns.contains_key(&boost.campaign_id),
            "unknown reward campaign",
        )?;
        require(
            self.note_vaults.contains_key(&boost.vault_id),
            "unknown note vault",
        )?;
        require_bps("boost_bps", boost.boost_bps)?;
        require(
            boost.boost_bps <= self.config.max_reward_boost_bps,
            "reward boost exceeds configured cap",
        )?;
        self.require_privacy_and_pq(boost.privacy_set_size, boost.pq_security_bits)?;
        insert_unique(
            &mut self.reward_boosts,
            boost.boost_id.clone(),
            boost.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_boost:{}", boost.boost_id),
            boost.public_record(),
        )?;
        self.refresh_roots();
        Ok(())
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

    pub fn add_pq_attestation(&mut self, attestation: PqVaultAttestation) -> Result<()> {
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

    pub fn subscribe_compounding(
        &mut self,
        input: SubscriptionInput,
    ) -> Result<CompoundingSubscription> {
        ensure_capacity(
            "compounding_subscriptions",
            self.compounding_subscriptions.len(),
            self.config.max_compounding_subscriptions,
        )?;
        require_nonempty("subscription_id", &input.subscription_id)?;
        require(
            self.reward_campaigns.contains_key(&input.campaign_id),
            "unknown reward campaign",
        )?;
        require(
            self.note_vaults.contains_key(&input.vault_id),
            "unknown note vault",
        )?;
        require(
            input.subscribed_units > 0,
            "subscribed units must be positive",
        )?;
        require_bps("max_haircut_bps", input.max_haircut_bps)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        self.consume_nullifier(&input.nullifier)?;
        let root = payload_root("compounding_subscription", &public_record_for(&input));
        let subscription = CompoundingSubscription {
            subscription_id: input.subscription_id,
            campaign_id: input.campaign_id,
            vault_id: input.vault_id,
            status: CompoundingStatus::Active,
            owner_commitment: input.owner_commitment,
            note_position_root: input.note_position_root,
            auto_compound_policy_root: input.auto_compound_policy_root,
            reward_destination_root: input.reward_destination_root,
            subscribed_units: input.subscribed_units,
            compounded_units: 0,
            accrued_reward_units: 0,
            claim_haircut_bps: 0,
            min_compound_units: input.min_compound_units,
            max_haircut_bps: input.max_haircut_bps,
            pq_underwriter_attestation_root: input.pq_underwriter_attestation_root,
            pq_prover_attestation_root: input.pq_prover_attestation_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            opened_l2_height: DEVNET_L2_HEIGHT,
            subscription_commitment_root: root,
        };
        insert_unique(
            &mut self.compounding_subscriptions,
            subscription.subscription_id.clone(),
            subscription.clone(),
        )?;
        self.publish_roots_only(
            format!("compounding_subscription:{}", subscription.subscription_id),
            subscription.public_record(),
        )?;
        self.refresh_roots();
        Ok(subscription)
    }

    pub fn deposit_rewards(&mut self, input: RewardDepositInput) -> Result<RewardDepositEntry> {
        ensure_capacity(
            "reward_deposits",
            self.reward_deposits.len(),
            self.config.max_reward_deposits,
        )?;
        require(
            self.reward_campaigns.contains_key(&input.campaign_id),
            "unknown reward campaign",
        )?;
        require(
            input.amount_units > 0,
            "reward deposit amount must be positive",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("compounding_reward_deposit", &public_record_for(&input));
        let deposit = RewardDepositEntry {
            deposit_id: input.deposit_id,
            campaign_id: input.campaign_id,
            reward_asset_root: input.reward_asset_root,
            sponsor_commitment: input.sponsor_commitment,
            amount_units: input.amount_units,
            unallocated_units: input.amount_units,
            epoch: input.epoch,
            deposit_note_root: input.deposit_note_root,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            deposit_commitment_root: root,
        };
        insert_unique(
            &mut self.reward_deposits,
            deposit.deposit_id.clone(),
            deposit.clone(),
        )?;
        self.publish_roots_only(
            format!("reward_deposit:{}", deposit.deposit_id),
            deposit.public_record(),
        )?;
        self.refresh_roots();
        Ok(deposit)
    }

    pub fn compound_epoch(
        &mut self,
        input: CompoundingEpochInput,
    ) -> Result<CompoundingEpochEntry> {
        ensure_capacity(
            "compounding_epochs",
            self.compounding_epochs.len(),
            self.config.max_compounding_epochs,
        )?;
        require(
            self.reward_campaigns.contains_key(&input.campaign_id),
            "unknown reward campaign",
        )?;
        require(
            input.compounded_reward_units <= input.gross_reward_units,
            "compounded rewards exceed gross rewards",
        )?;
        require(
            input.low_fee_units <= input.gross_reward_units,
            "low fee exceeds gross rewards",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("compounding_epoch", &public_record_for(&input));
        let epoch = CompoundingEpochEntry {
            compounding_epoch_id: input.compounding_epoch_id,
            campaign_id: input.campaign_id,
            status: RewardEpochStatus::Settled,
            subscription_set_root: input.subscription_set_root,
            reward_deposit_set_root: input.reward_deposit_set_root,
            accrued_reward_root: input.accrued_reward_root,
            compounded_note_root: input.compounded_note_root,
            fee_batch_root: input.fee_batch_root,
            rebate_batch_root: input.rebate_batch_root,
            epoch: input.epoch,
            gross_reward_units: input.gross_reward_units,
            compounded_reward_units: input.compounded_reward_units,
            low_fee_units: input.low_fee_units,
            pq_underwriter_attestation_root: input.pq_underwriter_attestation_root,
            pq_prover_attestation_root: input.pq_prover_attestation_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            epoch_commitment_root: root,
        };
        insert_unique(
            &mut self.compounding_epochs,
            epoch.compounding_epoch_id.clone(),
            epoch.clone(),
        )?;
        self.publish_roots_only(
            format!("compounding_epoch:{}", epoch.compounding_epoch_id),
            epoch.public_record(),
        )?;
        self.refresh_roots();
        Ok(epoch)
    }

    pub fn accrue_subscription_reward(
        &mut self,
        subscription_id: &str,
        reward_units: u64,
    ) -> Result<CompoundingSubscription> {
        require(reward_units > 0, "reward units must be positive")?;
        let updated = {
            let subscription = self
                .compounding_subscriptions
                .get_mut(subscription_id)
                .ok_or_else(|| "unknown compounding subscription".to_string())?;
            require(
                subscription.status.accepts_accrual(),
                "subscription does not accept accrual",
            )?;
            subscription.accrued_reward_units = subscription
                .accrued_reward_units
                .saturating_add(reward_units);
            subscription.subscription_commitment_root = payload_root(
                "compounding_subscription_accrual",
                &subscription.public_record(),
            );
            subscription.clone()
        };
        self.publish_roots_only(
            format!("compounding_subscription:{subscription_id}:accrual"),
            updated.public_record(),
        )?;
        self.refresh_roots();
        Ok(updated)
    }

    pub fn apply_claim_impairment(
        &mut self,
        input: ClaimImpairmentInput,
    ) -> Result<ClaimImpairmentEntry> {
        ensure_capacity(
            "claim_impairments",
            self.claim_impairments.len(),
            self.config.max_claim_impairments,
        )?;
        require_bps("haircut_bps", input.haircut_bps)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let risk_floor = input.failure_risk.liquidity_haircut_bps();
        require(
            input.haircut_bps >= risk_floor,
            "claim haircut below failure-risk floor",
        )?;
        let root = payload_root("claim_impairment", &public_record_for(&input));
        let entry = ClaimImpairmentEntry {
            impairment_id: input.impairment_id,
            subscription_id: input.subscription_id,
            claim_root: input.claim_root,
            failure_risk: input.failure_risk,
            claim_amount_root: input.claim_amount_root,
            haircut_bps: input.haircut_bps,
            underwriter_decision_root: input.underwriter_decision_root,
            prover_failure_evidence_root: input.prover_failure_evidence_root,
            pq_underwriter_attestation_root: input.pq_underwriter_attestation_root,
            pq_prover_attestation_root: input.pq_prover_attestation_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            impairment_commitment_root: root,
        };
        {
            let subscription = self
                .compounding_subscriptions
                .get_mut(&entry.subscription_id)
                .ok_or_else(|| "unknown compounding subscription".to_string())?;
            require(
                entry.haircut_bps <= subscription.max_haircut_bps,
                "claim haircut exceeds subscriber limit",
            )?;
            subscription.claim_haircut_bps = subscription
                .claim_haircut_bps
                .saturating_add(entry.haircut_bps)
                .min(MAX_BPS);
            subscription.status = CompoundingStatus::ClaimImpaired;
        }
        insert_unique(
            &mut self.claim_impairments,
            entry.impairment_id.clone(),
            entry.clone(),
        )?;
        self.publish_roots_only(
            format!("claim_impairment:{}", entry.impairment_id),
            entry.public_record(),
        )?;
        self.refresh_roots();
        Ok(entry)
    }

    pub fn redeem_note(&mut self, input: NoteRedemptionInput) -> Result<NoteRedemptionEntry> {
        ensure_capacity(
            "note_redemptions",
            self.note_redemptions.len(),
            self.config.max_note_redemptions,
        )?;
        require(input.redeemed_units > 0, "redeemed units must be positive")?;
        require(
            input.fee_units <= input.redeemed_units,
            "redemption fee exceeds redeemed units",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        self.consume_nullifier(&input.nullifier)?;
        let root = payload_root("note_redemption", &public_record_for(&input));
        let entry = NoteRedemptionEntry {
            redemption_id: input.redemption_id,
            subscription_id: input.subscription_id,
            destination_root: input.destination_root,
            redeemed_note_root: input.redeemed_note_root,
            reward_payout_root: input.reward_payout_root,
            redeemed_units: input.redeemed_units,
            fee_units: input.fee_units,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            redemption_commitment_root: root,
        };
        {
            let subscription = self
                .compounding_subscriptions
                .get_mut(&entry.subscription_id)
                .ok_or_else(|| "unknown compounding subscription".to_string())?;
            require(
                entry.redeemed_units
                    <= subscription.subscribed_units + subscription.compounded_units,
                "redemption exceeds subscribed plus compounded units",
            )?;
            subscription.status = CompoundingStatus::Redeemed;
        }
        insert_unique(
            &mut self.note_redemptions,
            entry.redemption_id.clone(),
            entry.clone(),
        )?;
        self.publish_roots_only(
            format!("note_redemption:{}", entry.redemption_id),
            entry.public_record(),
        )?;
        self.refresh_roots();
        Ok(entry)
    }

    pub fn account_rebate(
        &mut self,
        input: RebateAccountingInput,
    ) -> Result<RebateAccountingEntry> {
        ensure_capacity(
            "rebate_accounting",
            self.rebate_accounting.len(),
            self.config.max_rebate_accounting_entries,
        )?;
        require(
            self.compounding_subscriptions
                .contains_key(&input.subscription_id),
            "unknown compounding subscription",
        )?;
        require(
            self.compounding_epochs
                .contains_key(&input.compounding_epoch_id),
            "unknown compounding epoch",
        )?;
        require(
            input.rebate_units <= input.fee_units,
            "rebate exceeds accounted fee",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("rebate_accounting", &public_record_for(&input));
        let entry = RebateAccountingEntry {
            rebate_accounting_id: input.rebate_accounting_id,
            subscription_id: input.subscription_id,
            compounding_epoch_id: input.compounding_epoch_id,
            maker_rebate_root: input.maker_rebate_root,
            low_fee_settlement_root: input.low_fee_settlement_root,
            rebate_units: input.rebate_units,
            fee_units: input.fee_units,
            net_fee_units: input.fee_units - input.rebate_units,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            rebate_accounting_commitment_root: root,
        };
        insert_unique(
            &mut self.rebate_accounting,
            entry.rebate_accounting_id.clone(),
            entry.clone(),
        )?;
        self.publish_roots_only(
            format!("rebate_accounting:{}", entry.rebate_accounting_id),
            entry.public_record(),
        )?;
        self.refresh_roots();
        Ok(entry)
    }

    pub fn quarantine(&mut self, input: QuarantineInput) -> Result<QuarantineEvent> {
        ensure_capacity(
            "quarantine_events",
            self.quarantine_events.len(),
            self.config.max_quarantine_events,
        )?;
        require_nonempty("subject_kind", &input.subject_kind)?;
        require_nonempty("subject_id", &input.subject_id)?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;
        let root = payload_root("quarantine_event", &public_record_for(&input));
        let event = QuarantineEvent {
            quarantine_id: input.quarantine_id,
            subject_kind: input.subject_kind,
            subject_id: input.subject_id,
            reason_root: input.reason_root,
            evidence_root: input.evidence_root,
            reviewer_committee_root: input.reviewer_committee_root,
            pq_authorization_root: input.pq_authorization_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            quarantine_commitment_root: root,
        };
        if event.subject_kind == "compounding_subscription" {
            if let Some(subscription) = self.compounding_subscriptions.get_mut(&event.subject_id) {
                subscription.status = CompoundingStatus::Quarantined;
            }
        }
        insert_unique(
            &mut self.quarantine_events,
            event.quarantine_id.clone(),
            event.clone(),
        )?;
        self.publish_roots_only(
            format!("quarantine:{}", event.quarantine_id),
            event.public_record(),
        )?;
        self.refresh_roots();
        Ok(event)
    }

    pub fn apply_tranche_waterfall(
        &mut self,
        input: TrancheWaterfallInput,
    ) -> Result<TrancheWaterfallReceipt> {
        require_nonempty("waterfall_id", &input.waterfall_id)?;
        let tranche = self
            .reward_tranches
            .get(&input.tranche_id)
            .ok_or_else(|| "unknown reward tranche".to_string())?;
        let epoch = self
            .compounding_epochs
            .get(&input.compounding_epoch_id)
            .ok_or_else(|| "unknown compounding epoch".to_string())?;
        require(
            tranche.campaign_id == epoch.campaign_id,
            "waterfall tranche and epoch campaign mismatch",
        )?;
        require(
            input.gross_reward_units > 0,
            "waterfall gross reward units must be positive",
        )?;
        require_bps("haircut_bps", input.haircut_bps)?;
        require(
            input.haircut_bps >= tranche.risk_kind.liquidity_haircut_bps(),
            "waterfall haircut below tranche failure-risk floor",
        )?;
        self.require_privacy_and_pq(input.privacy_set_size, input.pq_security_bits)?;

        let payout_total_units = input
            .senior_payout_units
            .saturating_add(input.mezzanine_payout_units)
            .saturating_add(input.junior_payout_units)
            .saturating_add(input.residual_payout_units);
        let committed_units = payout_total_units
            .saturating_add(input.retained_reserve_units)
            .saturating_add(input.low_fee_settlement_units);
        require(
            committed_units <= input.gross_reward_units,
            "waterfall commits more units than gross rewards",
        )?;
        let impaired_units = input.gross_reward_units.saturating_sub(committed_units);
        let entry_root = payload_root("tranche_waterfall", &public_record_for(&input));
        let entry = TrancheWaterfallEntry {
            waterfall_id: input.waterfall_id,
            tranche_id: input.tranche_id,
            compounding_epoch_id: input.compounding_epoch_id,
            senior_note_root: input.senior_note_root,
            mezzanine_note_root: input.mezzanine_note_root,
            junior_note_root: input.junior_note_root,
            residual_note_root: input.residual_note_root,
            claim_impairment_root: input.claim_impairment_root,
            gross_reward_units: input.gross_reward_units,
            senior_payout_units: input.senior_payout_units,
            mezzanine_payout_units: input.mezzanine_payout_units,
            junior_payout_units: input.junior_payout_units,
            residual_payout_units: input.residual_payout_units,
            retained_reserve_units: input.retained_reserve_units,
            low_fee_settlement_units: input.low_fee_settlement_units,
            haircut_bps: input.haircut_bps,
            pq_underwriter_attestation_root: input.pq_underwriter_attestation_root,
            pq_prover_attestation_root: input.pq_prover_attestation_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            waterfall_commitment_root: entry_root,
        };
        let public_waterfall_root =
            root_from_record(TRANCHE_WATERFALL_SUITE, &entry.public_record());
        for subscription in self.compounding_subscriptions.values_mut() {
            if subscription.vault_id == tranche.vault_id
                && subscription.campaign_id == tranche.campaign_id
                && subscription.status.accepts_accrual()
            {
                subscription.accrued_reward_units = subscription
                    .accrued_reward_units
                    .saturating_add(payout_total_units);
                subscription.claim_haircut_bps =
                    subscription.claim_haircut_bps.max(entry.haircut_bps);
                subscription.subscription_commitment_root = payload_root(
                    "tranche_waterfall_subscription",
                    &subscription.public_record(),
                );
            }
        }
        let receipt = TrancheWaterfallReceipt {
            entry,
            payout_total_units,
            impaired_units,
            public_waterfall_root,
        };
        self.publish_roots_only(
            format!("tranche_waterfall:{}", receipt.entry.waterfall_id),
            receipt.public_record(),
        )?;
        self.refresh_roots();
        Ok(receipt)
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
                VAULT_VENUE_SUITE,
                &self.venues,
                RewardVaultVenue::public_record,
            ),
            note_vault_root: map_public_root(
                ELIGIBLE_NOTE_VAULT_SUITE,
                &self.note_vaults,
                EligibleNoteVault::public_record,
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
            reward_campaign_root: map_public_root(
                REWARD_CAMPAIGN_SUITE,
                &self.reward_campaigns,
                RewardCampaignEntry::public_record,
            ),
            reward_tranche_root: map_public_root(
                REWARD_TRANCHE_SUITE,
                &self.reward_tranches,
                RewardTrancheEntry::public_record,
            ),
            reward_epoch_root: map_public_root(
                REWARD_EPOCH_SUITE,
                &self.reward_epochs,
                RewardEpochEntry::public_record,
            ),
            reward_claim_root: map_public_root(
                REWARD_CLAIM_SUITE,
                &self.reward_claims,
                RewardClaimEntry::public_record,
            ),
            reward_boost_root: map_public_root(
                REWARD_BOOST_SUITE,
                &self.reward_boosts,
                RewardBoostEntry::public_record,
            ),
            compounding_subscription_root: map_public_root(
                COMPOUNDING_SUBSCRIPTION_SUITE,
                &self.compounding_subscriptions,
                CompoundingSubscription::public_record,
            ),
            reward_deposit_root: map_public_root(
                REWARD_DEPOSIT_SUITE,
                &self.reward_deposits,
                RewardDepositEntry::public_record,
            ),
            compounding_epoch_root: map_public_root(
                COMPOUNDING_EPOCH_SUITE,
                &self.compounding_epochs,
                CompoundingEpochEntry::public_record,
            ),
            claim_impairment_root: map_public_root(
                CLAIM_IMPAIRMENT_SUITE,
                &self.claim_impairments,
                ClaimImpairmentEntry::public_record,
            ),
            note_redemption_root: map_public_root(
                NOTE_REDEMPTION_SUITE,
                &self.note_redemptions,
                NoteRedemptionEntry::public_record,
            ),
            rebate_accounting_root: map_public_root(
                REBATE_ACCOUNTING_SUITE,
                &self.rebate_accounting,
                RebateAccountingEntry::public_record,
            ),
            quarantine_root: map_public_root(
                QUARANTINE_SUITE,
                &self.quarantine_events,
                QuarantineEvent::public_record,
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
                PqVaultAttestation::public_record,
            ),
            fee_rebate_root: map_public_root(
                FEE_REBATE_SUITE,
                &self.fee_rebates,
                FeeRebateEpoch::public_record,
            ),
            nullifier_root: set_root(NULLIFIER_SUITE, &self.nullifiers),
            public_record_root: value_map_root(PUBLIC_RECORD_SUITE, &self.public_records),
        }
    }

    fn current_counters(&self) -> Counters {
        Counters {
            venues: self.venues.len() as u64,
            note_vaults: self.note_vaults.len() as u64,
            listings: self.listings.len() as u64,
            rfqs: self.rfqs.len() as u64,
            orders: self.orders.len() as u64,
            matches: self.matches.len() as u64,
            fills: self.fills.len() as u64,
            settlements: self.settlements.len() as u64,
            reward_campaigns: self.reward_campaigns.len() as u64,
            reward_tranches: self.reward_tranches.len() as u64,
            reward_epochs: self.reward_epochs.len() as u64,
            reward_claims: self.reward_claims.len() as u64,
            reward_boosts: self.reward_boosts.len() as u64,
            compounding_subscriptions: self.compounding_subscriptions.len() as u64,
            reward_deposits: self.reward_deposits.len() as u64,
            compounding_epochs: self.compounding_epochs.len() as u64,
            claim_impairments: self.claim_impairments.len() as u64,
            note_redemptions: self.note_redemptions.len() as u64,
            rebate_accounting_entries: self.rebate_accounting.len() as u64,
            quarantine_events: self.quarantine_events.len() as u64,
            liquidity_lanes: self.liquidity_lanes.len() as u64,
            price_bands: self.price_bands.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            fee_rebates: self.fee_rebates.len() as u64,
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
        let venue = self.add_venue(RewardVaultVenueInput {
            venue_id: "pf-note-reward-vault-clob-devnet".to_string(),
            kind: RewardVaultKind::HybridDefiVault,
            operator_commitment: demo_root("operator", "reward-vault"),
            eligible_note_vault_root: demo_root("eligible_vault_set", "autocall-senior"),
            quote_asset_root: demo_root("quote_asset", DEVNET_QUOTE_ASSET_ID),
            fee_vault_root: demo_root("fee_vault", "reward-vault"),
            risk_oracle_root: demo_root("risk_oracle", "prover-failure"),
            price_band_root: demo_root("price_bands", "autocall-senior"),
            min_trade_units: 1_000_000,
            max_trade_units: 25_000_000_000,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let vault = self.add_note_vault(EligibleNoteVaultInput {
            vault_id: "pf-note-reward-vault-autocall-senior-devnet".to_string(),
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
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id.clone(),
            maker_set_root: demo_root("maker_set", "lane-a"),
            inventory_root: demo_root("inventory", "lane-a"),
            quote_depth_root: demo_root("quote_depth", "lane-a"),
            spread_bps: 36,
            utilization_bps: 2_900,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            lane_commitment_root: demo_root("lane_commitment", "lane-a"),
        })?;
        self.add_pq_attestation(PqVaultAttestation {
            attestation_id: "pq-reward-vault-attestation-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            subject_root: demo_root("attestation_subject", "venue-open"),
            committee_root: demo_root("committee", "reward-vault"),
            signature_root: demo_root("signature", "venue-open"),
            quorum_weight: self.config.attestation_quorum,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            attestation_commitment_root: demo_root("attestation_commitment", "venue-open"),
        })?;
        let campaign = self.open_reward_campaign(RewardCampaignInput {
            campaign_id: "pf-note-reward-campaign-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            sponsor_commitment: demo_root("reward_sponsor", "foundation"),
            reward_asset_root: demo_root("reward_asset", "nebula-points-private"),
            eligible_vault_set_root: demo_root("eligible_reward_vaults", "senior-set"),
            emission_schedule_root: demo_root("emission_schedule", "fast-settlement"),
            distribution_policy_root: demo_root("distribution_policy", "roots-only"),
            start_epoch: DEVNET_EPOCH,
            end_epoch: DEVNET_EPOCH + 12,
            base_reward_rate_bps: self.config.base_reward_rate_bps,
            max_boost_bps: self.config.max_reward_boost_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let tranche = self.add_reward_tranche(RewardTrancheInput {
            tranche_id: "pf-note-reward-tranche-senior-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            vault_id: vault.vault_id.clone(),
            seniority: NoteSeniority::Senior,
            risk_kind: ProverFailureRiskKind::RecursiveProofStall,
            eligibility_root: demo_root("reward_eligibility", "senior"),
            stake_position_root: demo_root("stake_position", "sealed-senior"),
            failure_cover_root: demo_root("failure_cover", "recursive-proof-stall"),
            reward_weight_bps: 6_250,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.add_reward_boost(RewardBoostEntry {
            boost_id: "pf-note-reward-boost-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            vault_id: vault.vault_id.clone(),
            boost_policy_root: demo_root("boost_policy", "privacy-speedy-failure-cover"),
            failure_protection_root: demo_root("failure_protection", "insured-prover"),
            privacy_growth_root: demo_root("privacy_growth", "large-set"),
            speedy_settlement_root: demo_root("speedy_settlement", "six-blocks"),
            boost_bps: self.config.failure_protection_boost_bps
                + self.config.privacy_boost_bps
                + self.config.speedy_settlement_boost_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            boost_commitment_root: demo_root("reward_boost_commitment", "devnet-0"),
        })?;
        let reward_epoch = self.seal_reward_epoch(RewardEpochInput {
            reward_epoch_id: "pf-note-reward-epoch-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            tranche_set_root: root_from_record("DEVNET_REWARD_TRANCHE", &tranche.public_record()),
            eligible_activity_root: demo_root("eligible_activity", "maker-fill-privacy"),
            sealed_score_root: demo_root("sealed_score", "epoch-0"),
            reward_pool_root: demo_root("reward_pool", "epoch-0"),
            settlement_batch_root: demo_root("reward_settlement_batch", "epoch-0"),
            epoch: DEVNET_EPOCH,
            claimable_after_l2_height: DEVNET_L2_HEIGHT + self.config.fast_settlement_blocks,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let listing = self.add_listing(ListingInput {
            listing_id: "pf-note-listing-devnet-0".to_string(),
            venue_id: venue.venue_id.clone(),
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id.clone(),
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
            vault_id: vault.vault_id,
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
            settlement_id: "pf-note-reward-vault-settlement-devnet-0".to_string(),
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
            rebate_epoch_id: "pf-note-reward-vault-rebate-devnet-0".to_string(),
            venue_id: venue.venue_id,
            maker_set_root: demo_root("maker_set", "rebate-0"),
            volume_root: demo_root("volume", "rebate-0"),
            fee_vault_root: demo_root("fee_vault", "rebate-0"),
            rebate_distribution_root: demo_root("rebate_distribution", "rebate-0"),
            epoch: DEVNET_EPOCH,
            rebate_bps: self.config.maker_rebate_bps,
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            rebate_commitment_root: demo_root("rebate_commitment", "rebate-0"),
        })?;
        self.submit_reward_claim(RewardClaimInput {
            claim_id: "pf-note-reward-claim-devnet-0".to_string(),
            reward_epoch_id: reward_epoch.reward_epoch_id,
            claimant_commitment: demo_root("reward_claimant", "alice"),
            note_position_root: demo_root("reward_note_position", "alice"),
            entitlement_root: demo_root("reward_entitlement", "alice"),
            destination_root: demo_root("reward_destination", "alice"),
            pq_authorization_root: demo_root("reward_pq_authorization", "alice"),
            nullifier: demo_root("nullifier", "reward-claim-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let subscription = self.subscribe_compounding(SubscriptionInput {
            subscription_id: "pf-note-compounding-subscription-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            vault_id: "pf-note-reward-vault-autocall-senior-devnet".to_string(),
            owner_commitment: demo_root("compounding_owner", "alice"),
            note_position_root: demo_root("compounding_note_position", "alice"),
            auto_compound_policy_root: demo_root("auto_compound_policy", "monthly-net-reward"),
            reward_destination_root: demo_root("reward_destination", "alice-compounded-note"),
            subscribed_units: 2_500_000_000,
            min_compound_units: 10_000,
            max_haircut_bps: 1_500,
            pq_underwriter_attestation_root: demo_root(
                "pq_underwriter_attestation",
                "subscription-0",
            ),
            pq_prover_attestation_root: demo_root("pq_prover_attestation", "subscription-0"),
            nullifier: demo_root("nullifier", "compounding-subscription-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.deposit_rewards(RewardDepositInput {
            deposit_id: "pf-note-compounding-reward-deposit-devnet-0".to_string(),
            campaign_id: campaign.campaign_id.clone(),
            reward_asset_root: demo_root("reward_asset", "nebula-points-private"),
            sponsor_commitment: demo_root("reward_sponsor", "foundation-compounding"),
            amount_units: 7_500_000,
            epoch: DEVNET_EPOCH,
            deposit_note_root: demo_root("reward_deposit_note", "epoch-0"),
            pq_authorization_root: demo_root("pq_authorization", "reward-deposit-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        let subscription =
            self.accrue_subscription_reward(&subscription.subscription_id, 125_000)?;
        let compounding_epoch = self.compound_epoch(CompoundingEpochInput {
            compounding_epoch_id: "pf-note-compounding-epoch-devnet-0".to_string(),
            campaign_id: campaign.campaign_id,
            subscription_set_root: root_from_record(
                "DEVNET_COMPOUNDING_SUBSCRIPTION",
                &subscription.public_record(),
            ),
            reward_deposit_set_root: demo_root("reward_deposit_set", "epoch-0"),
            accrued_reward_root: demo_root("accrued_reward", "epoch-0"),
            compounded_note_root: demo_root("compounded_note", "epoch-0"),
            fee_batch_root: demo_root("low_fee_batch", "compounding-epoch-0"),
            rebate_batch_root: demo_root("rebate_batch", "compounding-epoch-0"),
            epoch: DEVNET_EPOCH,
            gross_reward_units: 125_000,
            compounded_reward_units: 123_750,
            low_fee_units: 1_250,
            pq_underwriter_attestation_root: demo_root(
                "pq_underwriter_attestation",
                "compounding-epoch-0",
            ),
            pq_prover_attestation_root: demo_root("pq_prover_attestation", "compounding-epoch-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.apply_claim_impairment(ClaimImpairmentInput {
            impairment_id: "pf-note-compounding-claim-impairment-devnet-0".to_string(),
            subscription_id: subscription.subscription_id.clone(),
            claim_root: demo_root("claim", "recursive-proof-stall-0"),
            failure_risk: ProverFailureRiskKind::RecursiveProofStall,
            claim_amount_root: demo_root("claim_amount", "recursive-proof-stall-0"),
            haircut_bps: ProverFailureRiskKind::RecursiveProofStall.liquidity_haircut_bps(),
            underwriter_decision_root: demo_root("underwriter_decision", "approve-haircut-0"),
            prover_failure_evidence_root: demo_root("prover_failure_evidence", "stall-0"),
            pq_underwriter_attestation_root: demo_root(
                "pq_underwriter_attestation",
                "claim-impairment-0",
            ),
            pq_prover_attestation_root: demo_root("pq_prover_attestation", "claim-impairment-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.account_rebate(RebateAccountingInput {
            rebate_accounting_id: "pf-note-compounding-rebate-accounting-devnet-0".to_string(),
            subscription_id: subscription.subscription_id.clone(),
            compounding_epoch_id: compounding_epoch.compounding_epoch_id,
            maker_rebate_root: demo_root("maker_rebate", "compounding-0"),
            low_fee_settlement_root: demo_root("low_fee_settlement", "compounding-0"),
            rebate_units: 500,
            fee_units: 1_250,
            pq_authorization_root: demo_root("pq_authorization", "rebate-accounting-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.redeem_note(NoteRedemptionInput {
            redemption_id: "pf-note-compounding-redemption-devnet-0".to_string(),
            subscription_id: subscription.subscription_id.clone(),
            destination_root: demo_root("redemption_destination", "alice"),
            redeemed_note_root: demo_root("redeemed_note", "alice"),
            reward_payout_root: demo_root("reward_payout", "alice"),
            redeemed_units: 1_000_000_000,
            fee_units: 750,
            pq_authorization_root: demo_root("pq_authorization", "redemption-0"),
            nullifier: demo_root("nullifier", "compounding-redemption-0"),
            privacy_set_size: self.config.target_privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
        })?;
        self.quarantine(QuarantineInput {
            quarantine_id: "pf-note-compounding-quarantine-devnet-0".to_string(),
            subject_kind: "compounding_subscription".to_string(),
            subject_id: subscription.subscription_id,
            reason_root: demo_root("quarantine_reason", "post-redemption-review"),
            evidence_root: demo_root("quarantine_evidence", "review-batch-0"),
            reviewer_committee_root: demo_root("reviewer_committee", "risk-committee-a"),
            pq_authorization_root: demo_root("pq_authorization", "quarantine-0"),
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
