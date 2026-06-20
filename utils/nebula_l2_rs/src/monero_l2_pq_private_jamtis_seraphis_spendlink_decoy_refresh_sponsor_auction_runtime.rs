use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisSeraphisSpendlinkDecoyRefreshSponsorAuctionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_SPONSOR_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-seraphis-spendlink-decoy-refresh-sponsor-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_SPONSOR_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-JAMTIS-SERAPHIS-SPENDLINK-DECOY-REFRESH-SPONSOR-AUCTION";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_224_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_872_000;
pub const DEVNET_EPOCH: u64 = 18_944;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 128;
pub const DEFAULT_MIN_DECOY_POOL_OUTPUTS: u64 = 131_072;
pub const DEFAULT_TARGET_DECOY_POOL_OUTPUTS: u64 = 1_048_576;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 8_900;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 8_850;
pub const DEFAULT_MIN_REFRESH_UTILITY_BPS: u64 = 8_550;
pub const DEFAULT_MIN_AUCTION_CLEARING_BPS: u64 = 8_900;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_REFRESH_FEE_BPS: u64 = 4;
pub const DEFAULT_TARGET_SPONSOR_COVER_BPS: u64 = 9_600;
pub const DEFAULT_MIN_SPONSOR_SOLVENCY_BPS: u64 = 9_250;
pub const DEFAULT_MIN_BID_DIVERSITY_BPS: u64 = 7_500;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_LOT: u64 = 16_384;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_AUCTION: u64 = 262_144;
pub const DEFAULT_REFRESH_LOT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_BID_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_ASSIGNMENT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const REFRESH_LOT_SCHEME: &str = "jamtis-seraphis-spendlink-decoy-refresh-auction-lot-root-v1";
pub const SPONSOR_BID_SCHEME: &str =
    "pq-private-jamtis-seraphis-refresh-sponsor-sealed-bid-root-v1";
pub const AUCTION_ROUND_SCHEME: &str = "defi-style-refresh-sponsor-auction-round-clearing-root-v1";
pub const AUCTION_ASSIGNMENT_SCHEME: &str = "private-refresh-sponsor-auction-assignment-root-v1";
pub const PQ_AUCTION_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-seraphis-refresh-sponsor-auction-attestation-v1";
pub const AUCTION_SETTLEMENT_SCHEME: &str =
    "defi-style-private-refresh-sponsor-auction-settlement-root-v1";
pub const LOW_FEE_AUCTION_AUDIT_SCHEME: &str =
    "low-fee-jamtis-seraphis-refresh-sponsor-auction-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-jamtis-seraphis-refresh-sponsor-auction-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_viewtags_spendlinks_ring_members_decoy_graphs_sponsor_identities_bid_prices_or_assignment_witnesses";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionLane {
    WalletRefresh,
    DexSettlement,
    BridgeWithdrawal,
    MerchantReceive,
    WatchtowerRepair,
    ReorgRecovery,
    Migration,
    EmergencyPrivacy,
}

impl AuctionLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRefresh => "wallet_refresh",
            Self::DexSettlement => "dex_settlement",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantReceive => "merchant_receive",
            Self::WatchtowerRepair => "watchtower_repair",
            Self::ReorgRecovery => "reorg_recovery",
            Self::Migration => "migration",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::ReorgRecovery => 970,
            Self::BridgeWithdrawal => 940,
            Self::Migration => 910,
            Self::DexSettlement => 880,
            Self::WatchtowerRepair => 850,
            Self::MerchantReceive => 820,
            Self::WalletRefresh => 790,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Draft,
    Open,
    CommitClosed,
    RevealClosed,
    Cleared,
    Assigned,
    Settling,
    Settled,
    Audited,
    Sealed,
    Quarantined,
    Rejected,
    Expired,
}

impl AuctionStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::CommitClosed | Self::RevealClosed | Self::Cleared | Self::Assigned
        )
    }

    pub fn is_success(self) -> bool {
        matches!(
            self,
            Self::Cleared | Self::Assigned | Self::Settled | Self::Audited | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Eligible,
    Winning,
    Losing,
    Refunded,
    Slashed,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Revealed | Self::Eligible | Self::Winning
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentStatus {
    Draft,
    Matched,
    Reserved,
    Refreshing,
    Completed,
    Settled,
    Slashed,
    Challenged,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    StrongQuorum,
    Rotating,
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
pub enum SettlementStatus {
    Draft,
    Netting,
    Cleared,
    Rebalanced,
    Refunded,
    Slashed,
    Challenged,
    Final,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Draft,
    Sampling,
    Published,
    Disputed,
    Accepted,
    Regression,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAudience {
    Wallets,
    Sponsors,
    Solvers,
    Watchtowers,
    Governance,
    Public,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub public_bucket_size: u64,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_decoy_pool_outputs: u64,
    pub target_decoy_pool_outputs: u64,
    pub min_decoy_entropy_bps: u64,
    pub min_spendlink_shield_bps: u64,
    pub min_refresh_utility_bps: u64,
    pub min_auction_clearing_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_refresh_fee_bps: u64,
    pub target_sponsor_cover_bps: u64,
    pub min_sponsor_solvency_bps: u64,
    pub min_bid_diversity_bps: u64,
    pub max_refresh_units_per_lot: u64,
    pub max_refresh_units_per_auction: u64,
    pub refresh_lot_ttl_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub assignment_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_decoy_pool_outputs: DEFAULT_MIN_DECOY_POOL_OUTPUTS,
            target_decoy_pool_outputs: DEFAULT_TARGET_DECOY_POOL_OUTPUTS,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_spendlink_shield_bps: DEFAULT_MIN_SPENDLINK_SHIELD_BPS,
            min_refresh_utility_bps: DEFAULT_MIN_REFRESH_UTILITY_BPS,
            min_auction_clearing_bps: DEFAULT_MIN_AUCTION_CLEARING_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_refresh_fee_bps: DEFAULT_MAX_USER_REFRESH_FEE_BPS,
            target_sponsor_cover_bps: DEFAULT_TARGET_SPONSOR_COVER_BPS,
            min_sponsor_solvency_bps: DEFAULT_MIN_SPONSOR_SOLVENCY_BPS,
            min_bid_diversity_bps: DEFAULT_MIN_BID_DIVERSITY_BPS,
            max_refresh_units_per_lot: DEFAULT_MAX_REFRESH_UNITS_PER_LOT,
            max_refresh_units_per_auction: DEFAULT_MAX_REFRESH_UNITS_PER_AUCTION,
            refresh_lot_ttl_blocks: DEFAULT_REFRESH_LOT_TTL_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            bid_ttl_blocks: DEFAULT_BID_TTL_BLOCKS,
            assignment_ttl_blocks: DEFAULT_ASSIGNMENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch",
        )?;
        ensure(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch",
        )?;
        ensure(!self.chain_id.is_empty(), "chain id is required")?;
        ensure(!self.l2_network.is_empty(), "l2 network is required")?;
        ensure(
            !self.monero_network.is_empty(),
            "monero network is required",
        )?;
        ensure(!self.fee_asset_id.is_empty(), "fee asset id is required")?;
        ensure(
            self.public_bucket_size > 0,
            "public bucket size must be positive",
        )?;
        ensure(self.min_ring_size >= 11, "minimum ring size is too small")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size must meet minimum",
        )?;
        ensure(
            self.target_decoy_pool_outputs >= self.min_decoy_pool_outputs,
            "target decoy pool must meet minimum",
        )?;
        ensure_bps(self.min_decoy_entropy_bps, "min decoy entropy bps")?;
        ensure_bps(self.min_spendlink_shield_bps, "min spendlink shield bps")?;
        ensure_bps(self.min_refresh_utility_bps, "min refresh utility bps")?;
        ensure_bps(self.min_auction_clearing_bps, "min auction clearing bps")?;
        ensure_bps(self.max_user_refresh_fee_bps, "max user refresh fee bps")?;
        ensure_bps(self.target_sponsor_cover_bps, "target sponsor cover bps")?;
        ensure_bps(self.min_sponsor_solvency_bps, "min sponsor solvency bps")?;
        ensure_bps(self.min_bid_diversity_bps, "min bid diversity bps")?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security must meet minimum",
        )?;
        ensure(
            self.max_refresh_units_per_lot > 0,
            "max refresh units per lot must be positive",
        )?;
        ensure(
            self.max_refresh_units_per_auction >= self.max_refresh_units_per_lot,
            "auction unit cap must cover at least one lot",
        )?;
        ensure(
            self.refresh_lot_ttl_blocks > 0,
            "refresh lot ttl is required",
        )?;
        ensure(self.auction_ttl_blocks > 0, "auction ttl is required")?;
        ensure(self.bid_ttl_blocks > 0, "bid ttl is required")?;
        ensure(self.assignment_ttl_blocks > 0, "assignment ttl is required")?;
        ensure(
            self.attestation_ttl_blocks > 0,
            "attestation ttl is required",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": HASH_SUITE,
            "public_bucket_size": self.public_bucket_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_decoy_pool_outputs": self.min_decoy_pool_outputs,
            "target_decoy_pool_outputs": self.target_decoy_pool_outputs,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_refresh_utility_bps": self.min_refresh_utility_bps,
            "min_auction_clearing_bps": self.min_auction_clearing_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_refresh_fee_bps": self.max_user_refresh_fee_bps,
            "target_sponsor_cover_bps": self.target_sponsor_cover_bps,
            "min_sponsor_solvency_bps": self.min_sponsor_solvency_bps,
            "min_bid_diversity_bps": self.min_bid_diversity_bps,
            "max_refresh_units_per_lot": self.max_refresh_units_per_lot,
            "max_refresh_units_per_auction": self.max_refresh_units_per_auction,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub refresh_lots: u64,
    pub sponsor_bids: u64,
    pub auction_rounds: u64,
    pub auction_assignments: u64,
    pub pq_attestations: u64,
    pub auction_settlements: u64,
    pub low_fee_audits: u64,
    pub public_records: u64,
    pub quarantined_lots: u64,
    pub slashed_bids: u64,
    pub rejected_lots: u64,
    pub expired_auctions: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub refresh_lot_root: String,
    pub sponsor_bid_root: String,
    pub auction_round_root: String,
    pub auction_assignment_root: String,
    pub pq_attestation_root: String,
    pub auction_settlement_root: String,
    pub low_fee_audit_root: String,
    pub quarantined_lot_root: String,
    pub used_bid_nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            config_root: empty_root("sponsor-auction-config"),
            counters_root: empty_root("sponsor-auction-counters"),
            refresh_lot_root: empty_root(REFRESH_LOT_SCHEME),
            sponsor_bid_root: empty_root(SPONSOR_BID_SCHEME),
            auction_round_root: empty_root(AUCTION_ROUND_SCHEME),
            auction_assignment_root: empty_root(AUCTION_ASSIGNMENT_SCHEME),
            pq_attestation_root: empty_root(PQ_AUCTION_ATTESTATION_SCHEME),
            auction_settlement_root: empty_root(AUCTION_SETTLEMENT_SCHEME),
            low_fee_audit_root: empty_root(LOW_FEE_AUCTION_AUDIT_SCHEME),
            quarantined_lot_root: empty_root("quarantined-refresh-lots"),
            used_bid_nullifier_root: empty_root("used-sponsor-bid-nullifiers"),
            public_record_root: empty_root(PUBLIC_RECORD_SCHEME),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-roots", &self.public_record())
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshLotInput {
    pub lot_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_root: String,
    pub solver_commitment_root: String,
    pub expires_at_height: u64,
    pub status: AuctionStatus,
}

impl RefreshLotInput {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.lot_id.is_empty(), "lot id is required")?;
        ensure(
            self.output_count_bucket >= config.min_decoy_pool_outputs,
            "lot decoy pool is too small",
        )?;
        ensure(
            self.ring_size >= config.min_ring_size,
            "lot ring size is too small",
        )?;
        ensure(
            self.refresh_unit_bucket <= config.max_refresh_units_per_lot,
            "lot refresh unit bucket exceeds maximum",
        )?;
        ensure(
            self.refresh_unit_bucket > 0,
            "lot refresh units are required",
        )?;
        ensure_bps(self.decoy_entropy_bps, "lot decoy entropy bps")?;
        ensure_bps(self.spendlink_shield_bps, "lot spendlink shield bps")?;
        ensure_bps(self.refresh_utility_bps, "lot refresh utility bps")?;
        ensure(
            self.decoy_entropy_bps >= config.min_decoy_entropy_bps,
            "lot decoy entropy is below floor",
        )?;
        ensure(
            self.spendlink_shield_bps >= config.min_spendlink_shield_bps,
            "lot spendlink shield is below floor",
        )?;
        ensure(
            self.refresh_utility_bps >= config.min_refresh_utility_bps,
            "lot refresh utility is below floor",
        )?;
        ensure(
            !self.decoy_pool_root.is_empty(),
            "decoy pool root is required",
        )?;
        ensure(
            !self.spendlink_shield_root.is_empty(),
            "spendlink shield root is required",
        )?;
        ensure(
            !self.refresh_plan_root.is_empty(),
            "refresh plan root is required",
        )?;
        ensure(
            !self.solver_commitment_root.is_empty(),
            "solver commitment root is required",
        )?;
        ensure(self.expires_at_height > monero_height, "lot is expired")
    }

    pub fn privacy_score_bps(&self) -> u64 {
        self.decoy_entropy_bps
            .saturating_mul(42)
            .saturating_add(self.spendlink_shield_bps.saturating_mul(38))
            .saturating_add(self.refresh_utility_bps.saturating_mul(20))
            .saturating_div(100)
            .min(MAX_BPS)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lot_id": self.lot_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "ring_size": self.ring_size,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "privacy_score_bps": self.privacy_score_bps(),
            "decoy_pool_root": self.decoy_pool_root,
            "spendlink_shield_root": self.spendlink_shield_root,
            "refresh_plan_root": self.refresh_plan_root,
            "solver_commitment_root": self.solver_commitment_root,
            "expires_at_height_bucket": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-refresh-lot", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBidInput {
    pub bid_id: String,
    pub auction_id: String,
    pub sponsor_bucket: String,
    pub fee_asset_id: String,
    pub bid_commitment_root: String,
    pub policy_root: String,
    pub solvency_root: String,
    pub bid_nullifier: String,
    pub max_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub solvency_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub reserved_fee_bucket: u64,
    pub priority_rebate_bps: u64,
    pub expires_at_height: u64,
    pub status: BidStatus,
}

impl SponsorBidInput {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.bid_id.is_empty(), "bid id is required")?;
        ensure(!self.auction_id.is_empty(), "auction id is required")?;
        ensure(
            !self.sponsor_bucket.is_empty(),
            "sponsor bucket is required",
        )?;
        ensure(
            self.fee_asset_id == config.fee_asset_id,
            "fee asset mismatch",
        )?;
        ensure(
            !self.bid_commitment_root.is_empty(),
            "bid commitment root is required",
        )?;
        ensure(!self.policy_root.is_empty(), "policy root is required")?;
        ensure(!self.solvency_root.is_empty(), "solvency root is required")?;
        ensure(!self.bid_nullifier.is_empty(), "bid nullifier is required")?;
        ensure_bps(self.max_user_fee_bps, "bid max user fee bps")?;
        ensure_bps(self.sponsor_cover_bps, "bid sponsor cover bps")?;
        ensure_bps(self.solvency_bps, "bid solvency bps")?;
        ensure_bps(self.priority_rebate_bps, "priority rebate bps")?;
        ensure(
            self.max_user_fee_bps <= config.max_user_refresh_fee_bps,
            "bid user fee exceeds runtime ceiling",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "bid sponsor cover below target",
        )?;
        ensure(
            self.solvency_bps >= config.min_sponsor_solvency_bps,
            "bid sponsor solvency below floor",
        )?;
        ensure(
            self.refresh_unit_budget_bucket > 0,
            "bid refresh unit budget is required",
        )?;
        ensure(self.reserved_fee_bucket > 0, "bid reserved fee is required")?;
        ensure(self.expires_at_height > monero_height, "bid is expired")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "sponsor_bucket": self.sponsor_bucket,
            "fee_asset_id": self.fee_asset_id,
            "bid_commitment_root": self.bid_commitment_root,
            "policy_root": self.policy_root,
            "solvency_root": self.solvency_root,
            "bid_nullifier_root": root_from_parts("public-bid-nullifier", &[HashPart::Str(&self.bid_nullifier)]),
            "max_user_fee_bps": self.max_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "solvency_bps": self.solvency_bps,
            "refresh_unit_budget_bucket": self.refresh_unit_budget_bucket,
            "reserved_fee_bucket": self.reserved_fee_bucket,
            "priority_rebate_bps": self.priority_rebate_bps,
            "expires_at_height_bucket": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-sealed-bid", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionRoundEntry {
    pub auction_id: String,
    pub lane: AuctionLane,
    pub epoch: u64,
    pub lot_root: String,
    pub bid_book_root: String,
    pub clearing_transcript_root: String,
    pub clearing_price_bucket: u64,
    pub total_refresh_units_bucket: u64,
    pub eligible_bid_count_bucket: u64,
    pub winning_bid_count_bucket: u64,
    pub bid_diversity_bps: u64,
    pub clearing_quality_bps: u64,
    pub user_fee_ceiling_bps: u64,
    pub sponsor_cover_bps: u64,
    pub commit_deadline_height: u64,
    pub reveal_deadline_height: u64,
    pub expires_at_height: u64,
    pub status: AuctionStatus,
}

impl AuctionRoundEntry {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.auction_id.is_empty(), "auction id is required")?;
        ensure(!self.lot_root.is_empty(), "auction lot root is required")?;
        ensure(
            !self.bid_book_root.is_empty(),
            "auction bid book root is required",
        )?;
        ensure(
            !self.clearing_transcript_root.is_empty(),
            "clearing transcript root is required",
        )?;
        ensure(
            self.total_refresh_units_bucket <= config.max_refresh_units_per_auction,
            "auction refresh units exceed cap",
        )?;
        ensure(
            self.total_refresh_units_bucket > 0,
            "auction refresh units are required",
        )?;
        ensure(
            self.eligible_bid_count_bucket >= self.winning_bid_count_bucket,
            "winning bid count exceeds eligible bid count",
        )?;
        ensure(
            self.winning_bid_count_bucket > 0,
            "auction has no winning bids",
        )?;
        ensure_bps(self.bid_diversity_bps, "auction bid diversity bps")?;
        ensure_bps(self.clearing_quality_bps, "auction clearing quality bps")?;
        ensure_bps(self.user_fee_ceiling_bps, "auction user fee ceiling bps")?;
        ensure_bps(self.sponsor_cover_bps, "auction sponsor cover bps")?;
        ensure(
            self.bid_diversity_bps >= config.min_bid_diversity_bps,
            "auction bid diversity below floor",
        )?;
        ensure(
            self.clearing_quality_bps >= config.min_auction_clearing_bps,
            "auction clearing quality below floor",
        )?;
        ensure(
            self.user_fee_ceiling_bps <= config.max_user_refresh_fee_bps,
            "auction user fee exceeds runtime ceiling",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "auction sponsor cover below target",
        )?;
        ensure(
            self.commit_deadline_height <= self.reveal_deadline_height,
            "commit deadline must not exceed reveal deadline",
        )?;
        ensure(self.expires_at_height > monero_height, "auction is expired")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "lane": self.lane.as_str(),
            "epoch": self.epoch,
            "lot_root": self.lot_root,
            "bid_book_root": self.bid_book_root,
            "clearing_transcript_root": self.clearing_transcript_root,
            "clearing_price_bucket": self.clearing_price_bucket,
            "total_refresh_units_bucket": self.total_refresh_units_bucket,
            "eligible_bid_count_bucket": self.eligible_bid_count_bucket,
            "winning_bid_count_bucket": self.winning_bid_count_bucket,
            "bid_diversity_bps": self.bid_diversity_bps,
            "clearing_quality_bps": self.clearing_quality_bps,
            "user_fee_ceiling_bps": self.user_fee_ceiling_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "commit_deadline_height_bucket": self.commit_deadline_height,
            "reveal_deadline_height_bucket": self.reveal_deadline_height,
            "expires_at_height_bucket": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-round", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionAssignmentEntry {
    pub assignment_id: String,
    pub auction_id: String,
    pub lot_id: String,
    pub bid_id: String,
    pub assignment_commitment_root: String,
    pub refresh_receipt_root: String,
    pub sponsor_receipt_root: String,
    pub refresh_unit_bucket: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub privacy_score_bps: u64,
    pub assigned_at_height: u64,
    pub expires_at_height: u64,
    pub status: AssignmentStatus,
}

impl AuctionAssignmentEntry {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(!self.assignment_id.is_empty(), "assignment id is required")?;
        ensure(
            !self.auction_id.is_empty(),
            "assignment auction id is required",
        )?;
        ensure(!self.lot_id.is_empty(), "assignment lot id is required")?;
        ensure(!self.bid_id.is_empty(), "assignment bid id is required")?;
        ensure(
            !self.assignment_commitment_root.is_empty(),
            "assignment commitment root is required",
        )?;
        ensure(
            !self.refresh_receipt_root.is_empty(),
            "refresh receipt root is required",
        )?;
        ensure(
            !self.sponsor_receipt_root.is_empty(),
            "sponsor receipt root is required",
        )?;
        ensure(
            self.refresh_unit_bucket <= config.max_refresh_units_per_lot,
            "assignment refresh units exceed lot cap",
        )?;
        ensure(
            self.refresh_unit_bucket > 0,
            "assignment refresh units are required",
        )?;
        ensure_bps(self.user_fee_bps, "assignment user fee bps")?;
        ensure_bps(self.sponsor_cover_bps, "assignment sponsor cover bps")?;
        ensure_bps(self.privacy_score_bps, "assignment privacy score bps")?;
        ensure(
            self.user_fee_bps <= config.max_user_refresh_fee_bps,
            "assignment user fee exceeds runtime ceiling",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "assignment sponsor cover below target",
        )?;
        ensure(
            self.privacy_score_bps >= config.min_refresh_utility_bps,
            "assignment privacy score below floor",
        )?;
        ensure(
            self.expires_at_height > self.assigned_at_height,
            "assignment expiry must follow assignment height",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "assignment is expired",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "assignment_id": self.assignment_id,
            "auction_id": self.auction_id,
            "lot_id": self.lot_id,
            "bid_id": self.bid_id,
            "assignment_commitment_root": self.assignment_commitment_root,
            "refresh_receipt_root": self.refresh_receipt_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "privacy_score_bps": self.privacy_score_bps,
            "assigned_at_height_bucket": self.assigned_at_height,
            "expires_at_height_bucket": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-assignment", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuctionAttestationEntry {
    pub attestation_id: String,
    pub auction_id: String,
    pub assignment_id: String,
    pub signer_set_root: String,
    pub pq_transcript_root: String,
    pub refresh_integrity_root: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqAuctionAttestationEntry {
    pub fn validate(&self, config: &Config, monero_height: u64) -> Result<()> {
        ensure(
            !self.attestation_id.is_empty(),
            "attestation id is required",
        )?;
        ensure(
            !self.auction_id.is_empty(),
            "attestation auction id is required",
        )?;
        ensure(
            !self.assignment_id.is_empty(),
            "attestation assignment id is required",
        )?;
        ensure(
            !self.signer_set_root.is_empty(),
            "signer set root is required",
        )?;
        ensure(
            !self.pq_transcript_root.is_empty(),
            "pq transcript root is required",
        )?;
        ensure(
            !self.refresh_integrity_root.is_empty(),
            "refresh integrity root is required",
        )?;
        ensure(
            self.pq_security_bits >= config.min_pq_security_bits,
            "pq security bits below floor",
        )?;
        ensure(
            self.classical_fallback_disabled,
            "classical fallback must be disabled",
        )?;
        ensure(
            self.expires_at_height > self.attested_at_height,
            "attestation expiry must follow attestation height",
        )?;
        ensure(
            self.expires_at_height > monero_height,
            "attestation is expired",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "auction_id": self.auction_id,
            "assignment_id": self.assignment_id,
            "signer_set_root": self.signer_set_root,
            "pq_transcript_root": self.pq_transcript_root,
            "refresh_integrity_root": self.refresh_integrity_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height_bucket": self.attested_at_height,
            "expires_at_height_bucket": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-pq-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuctionSettlementEntry {
    pub settlement_id: String,
    pub auction_id: String,
    pub assignment_id: String,
    pub bid_nullifier: String,
    pub settlement_receipt_root: String,
    pub defi_accounting_root: String,
    pub rebate_root: String,
    pub refresh_unit_bucket: u64,
    pub user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub clearing_price_bucket: u64,
    pub rebate_bucket: u64,
    pub settlement_delay_blocks: u64,
    pub status: SettlementStatus,
}

impl AuctionSettlementEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.settlement_id.is_empty(), "settlement id is required")?;
        ensure(
            !self.auction_id.is_empty(),
            "settlement auction id is required",
        )?;
        ensure(
            !self.assignment_id.is_empty(),
            "settlement assignment id is required",
        )?;
        ensure(
            !self.bid_nullifier.is_empty(),
            "settlement bid nullifier is required",
        )?;
        ensure(
            !self.settlement_receipt_root.is_empty(),
            "settlement receipt root is required",
        )?;
        ensure(
            !self.defi_accounting_root.is_empty(),
            "defi accounting root is required",
        )?;
        ensure(!self.rebate_root.is_empty(), "rebate root is required")?;
        ensure(
            self.refresh_unit_bucket > 0,
            "settlement refresh units are required",
        )?;
        ensure_bps(self.user_fee_bps, "settlement user fee bps")?;
        ensure_bps(self.sponsor_cover_bps, "settlement sponsor cover bps")?;
        ensure(
            self.user_fee_bps <= config.max_user_refresh_fee_bps,
            "settlement user fee exceeds runtime ceiling",
        )?;
        ensure(
            self.sponsor_cover_bps >= config.target_sponsor_cover_bps,
            "settlement sponsor cover below target",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "auction_id": self.auction_id,
            "assignment_id": self.assignment_id,
            "bid_nullifier_root": root_from_parts("settled-bid-nullifier", &[HashPart::Str(&self.bid_nullifier)]),
            "settlement_receipt_root": self.settlement_receipt_root,
            "defi_accounting_root": self.defi_accounting_root,
            "rebate_root": self.rebate_root,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "user_fee_bps": self.user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "clearing_price_bucket": self.clearing_price_bucket,
            "rebate_bucket": self.rebate_bucket,
            "settlement_delay_blocks": self.settlement_delay_blocks,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-settlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAuctionAuditEntry {
    pub audit_id: String,
    pub auction_id: String,
    pub settlement_id: String,
    pub measured_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub sponsor_efficiency_bps: u64,
    pub clearing_quality_bps: u64,
    pub refresh_latency_blocks: u64,
    pub fee_sample_root: String,
    pub privacy_regression_root: String,
    pub auction_fairness_root: String,
    pub accounting_evidence_root: String,
    pub status: AuditStatus,
}

impl LowFeeAuctionAuditEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.audit_id.is_empty(), "audit id is required")?;
        ensure(!self.auction_id.is_empty(), "audit auction id is required")?;
        ensure(
            !self.settlement_id.is_empty(),
            "audit settlement id is required",
        )?;
        ensure_bps(self.measured_user_fee_bps, "audit measured user fee bps")?;
        ensure_bps(self.target_user_fee_bps, "audit target user fee bps")?;
        ensure_bps(self.sponsor_efficiency_bps, "audit sponsor efficiency bps")?;
        ensure_bps(self.clearing_quality_bps, "audit clearing quality bps")?;
        ensure(
            self.measured_user_fee_bps <= config.max_user_refresh_fee_bps,
            "audit measured fee exceeds runtime ceiling",
        )?;
        ensure(
            self.target_user_fee_bps <= config.max_user_refresh_fee_bps,
            "audit target fee exceeds runtime ceiling",
        )?;
        ensure(
            self.clearing_quality_bps >= config.min_auction_clearing_bps,
            "audit clearing quality below floor",
        )?;
        ensure(
            !self.fee_sample_root.is_empty(),
            "fee sample root is required",
        )?;
        ensure(
            !self.privacy_regression_root.is_empty(),
            "privacy regression root is required",
        )?;
        ensure(
            !self.auction_fairness_root.is_empty(),
            "auction fairness root is required",
        )?;
        ensure(
            !self.accounting_evidence_root.is_empty(),
            "accounting evidence root is required",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "audit_id": self.audit_id,
            "auction_id": self.auction_id,
            "settlement_id": self.settlement_id,
            "measured_user_fee_bps": self.measured_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "sponsor_efficiency_bps": self.sponsor_efficiency_bps,
            "clearing_quality_bps": self.clearing_quality_bps,
            "refresh_latency_blocks": self.refresh_latency_blocks,
            "fee_sample_root": self.fee_sample_root,
            "privacy_regression_root": self.privacy_regression_root,
            "auction_fairness_root": self.auction_fairness_root,
            "accounting_evidence_root": self.accounting_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("sponsor-auction-low-fee-audit", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub audience: PublicAudience,
    pub epoch: u64,
    pub l2_height: u64,
    pub monero_height_bucket: u64,
    pub roots: Roots,
    pub counters: Counters,
    pub sponsor_coverage_bps: u64,
    pub attested_assignment_bps: u64,
    pub low_fee_success_bps: u64,
    pub privacy_boundary: String,
}

impl RootsOnlyPublicRecord {
    pub fn validate(&self) -> Result<()> {
        ensure(!self.record_id.is_empty(), "record id is required")?;
        ensure(
            self.privacy_boundary == PRIVACY_BOUNDARY,
            "privacy boundary mismatch",
        )?;
        ensure_bps(self.sponsor_coverage_bps, "record sponsor coverage bps")?;
        ensure_bps(
            self.attested_assignment_bps,
            "record attested assignment bps",
        )?;
        ensure_bps(self.low_fee_success_bps, "record low fee success bps")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": self.monero_height_bucket,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "attested_assignment_bps": self.attested_assignment_bps,
            "low_fee_success_bps": self.low_fee_success_bps,
            "privacy_boundary": self.privacy_boundary,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record(
            "sponsor-auction-roots-only-public-record",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub refresh_lots: BTreeMap<String, RefreshLotInput>,
    pub sponsor_bids: BTreeMap<String, SponsorBidInput>,
    pub auction_rounds: BTreeMap<String, AuctionRoundEntry>,
    pub auction_assignments: BTreeMap<String, AuctionAssignmentEntry>,
    pub pq_attestations: BTreeMap<String, PqAuctionAttestationEntry>,
    pub auction_settlements: BTreeMap<String, AuctionSettlementEntry>,
    pub low_fee_audits: BTreeMap<String, LowFeeAuctionAuditEntry>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub quarantined_lot_ids: BTreeSet<String>,
    pub used_bid_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_height,
            monero_height,
            epoch,
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            refresh_lots: BTreeMap::new(),
            sponsor_bids: BTreeMap::new(),
            auction_rounds: BTreeMap::new(),
            auction_assignments: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            auction_settlements: BTreeMap::new(),
            low_fee_audits: BTreeMap::new(),
            public_records: BTreeMap::new(),
            quarantined_lot_ids: BTreeSet::new(),
            used_bid_nullifiers: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet config validates");
        state.seed_devnet();
        state
    }

    pub fn insert_refresh_lot(&mut self, lot: RefreshLotInput) -> Result<()> {
        lot.validate(&self.config, self.monero_height)?;
        ensure(
            !self.refresh_lots.contains_key(&lot.lot_id),
            "duplicate refresh lot",
        )?;
        self.refresh_lots.insert(lot.lot_id.clone(), lot);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_sponsor_bid(&mut self, bid: SponsorBidInput) -> Result<()> {
        bid.validate(&self.config, self.monero_height)?;
        ensure(
            self.auction_rounds.contains_key(&bid.auction_id),
            "bid references unknown auction",
        )?;
        ensure(
            !self.sponsor_bids.contains_key(&bid.bid_id),
            "duplicate sponsor bid",
        )?;
        ensure(
            !self.used_bid_nullifiers.contains(&bid.bid_nullifier),
            "bid nullifier already used",
        )?;
        self.used_bid_nullifiers.insert(bid.bid_nullifier.clone());
        self.sponsor_bids.insert(bid.bid_id.clone(), bid);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_auction_round(&mut self, auction: AuctionRoundEntry) -> Result<()> {
        auction.validate(&self.config, self.monero_height)?;
        ensure(
            !self.auction_rounds.contains_key(&auction.auction_id),
            "duplicate auction round",
        )?;
        self.auction_rounds
            .insert(auction.auction_id.clone(), auction);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_auction_assignment(&mut self, assignment: AuctionAssignmentEntry) -> Result<()> {
        assignment.validate(&self.config, self.monero_height)?;
        ensure(
            self.auction_rounds.contains_key(&assignment.auction_id),
            "assignment references unknown auction",
        )?;
        ensure(
            self.refresh_lots.contains_key(&assignment.lot_id),
            "assignment references unknown lot",
        )?;
        ensure(
            self.sponsor_bids.contains_key(&assignment.bid_id),
            "assignment references unknown bid",
        )?;
        ensure(
            !self
                .auction_assignments
                .contains_key(&assignment.assignment_id),
            "duplicate auction assignment",
        )?;
        self.auction_assignments
            .insert(assignment.assignment_id.clone(), assignment);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqAuctionAttestationEntry) -> Result<()> {
        attestation.validate(&self.config, self.monero_height)?;
        ensure(
            self.auction_rounds.contains_key(&attestation.auction_id),
            "attestation references unknown auction",
        )?;
        ensure(
            self.auction_assignments
                .contains_key(&attestation.assignment_id),
            "attestation references unknown assignment",
        )?;
        ensure(
            !self
                .pq_attestations
                .contains_key(&attestation.attestation_id),
            "duplicate pq auction attestation",
        )?;
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_auction_settlement(&mut self, settlement: AuctionSettlementEntry) -> Result<()> {
        settlement.validate(&self.config)?;
        ensure(
            self.auction_rounds.contains_key(&settlement.auction_id),
            "settlement references unknown auction",
        )?;
        ensure(
            self.auction_assignments
                .contains_key(&settlement.assignment_id),
            "settlement references unknown assignment",
        )?;
        ensure(
            !self
                .auction_settlements
                .contains_key(&settlement.settlement_id),
            "duplicate auction settlement",
        )?;
        self.auction_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.refresh_roots();
        Ok(())
    }

    pub fn insert_low_fee_audit(&mut self, audit: LowFeeAuctionAuditEntry) -> Result<()> {
        audit.validate(&self.config)?;
        ensure(
            self.auction_rounds.contains_key(&audit.auction_id),
            "audit references unknown auction",
        )?;
        ensure(
            self.auction_settlements.contains_key(&audit.settlement_id),
            "audit references unknown settlement",
        )?;
        ensure(
            !self.low_fee_audits.contains_key(&audit.audit_id),
            "duplicate audit",
        )?;
        self.low_fee_audits.insert(audit.audit_id.clone(), audit);
        self.refresh_roots();
        Ok(())
    }

    pub fn quarantine_lot(&mut self, lot_id: &str) -> Result<()> {
        ensure(
            self.refresh_lots.contains_key(lot_id),
            "cannot quarantine unknown lot",
        )?;
        self.quarantined_lot_ids.insert(lot_id.to_string());
        if let Some(lot) = self.refresh_lots.get_mut(lot_id) {
            lot.status = AuctionStatus::Quarantined;
        }
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_roots_only_record(
        &mut self,
        record_id: impl Into<String>,
        audience: PublicAudience,
    ) -> Result<String> {
        self.refresh_roots();
        let record_id = record_id.into();
        ensure(!record_id.is_empty(), "public record id is required")?;
        ensure(
            !self.public_records.contains_key(&record_id),
            "duplicate public record",
        )?;
        let record = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            audience,
            epoch: self.epoch,
            l2_height: self.l2_height,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            roots: self.roots.clone(),
            counters: self.counters.clone(),
            sponsor_coverage_bps: self.sponsor_coverage_bps(),
            attested_assignment_bps: self.attested_assignment_bps(),
            low_fee_success_bps: self.low_fee_success_bps(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        };
        record.validate()?;
        let root = record.state_root();
        self.public_records.insert(record_id, record);
        self.refresh_roots();
        Ok(root)
    }

    pub fn sponsor_coverage_bps(&self) -> u64 {
        if self.refresh_lots.is_empty() {
            return 0;
        }
        let covered = self
            .auction_assignments
            .values()
            .filter(|entry| {
                matches!(
                    entry.status,
                    AssignmentStatus::Reserved
                        | AssignmentStatus::Refreshing
                        | AssignmentStatus::Completed
                        | AssignmentStatus::Settled
                )
            })
            .map(|entry| entry.lot_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        covered
            .saturating_mul(MAX_BPS)
            .saturating_div(self.refresh_lots.len() as u64)
            .min(MAX_BPS)
    }

    pub fn attested_assignment_bps(&self) -> u64 {
        if self.auction_assignments.is_empty() {
            return 0;
        }
        let attested = self
            .pq_attestations
            .values()
            .filter(|entry| entry.status.counts_for_quorum())
            .map(|entry| entry.assignment_id.clone())
            .collect::<BTreeSet<_>>()
            .len() as u64;
        attested
            .saturating_mul(MAX_BPS)
            .saturating_div(self.auction_assignments.len() as u64)
            .min(MAX_BPS)
    }

    pub fn low_fee_success_bps(&self) -> u64 {
        if self.auction_settlements.is_empty() {
            return 0;
        }
        let low_fee = self
            .auction_settlements
            .values()
            .filter(|entry| {
                entry.user_fee_bps <= self.config.max_user_refresh_fee_bps
                    && matches!(
                        entry.status,
                        SettlementStatus::Cleared
                            | SettlementStatus::Rebalanced
                            | SettlementStatus::Final
                    )
            })
            .count() as u64;
        low_fee
            .saturating_mul(MAX_BPS)
            .saturating_div(self.auction_settlements.len() as u64)
            .min(MAX_BPS)
    }

    pub fn auction_clearing_bps(&self) -> u64 {
        if self.auction_rounds.is_empty() {
            return 0;
        }
        let cleared = self
            .auction_rounds
            .values()
            .filter(|entry| entry.status.is_success())
            .count() as u64;
        cleared
            .saturating_mul(MAX_BPS)
            .saturating_div(self.auction_rounds.len() as u64)
            .min(MAX_BPS)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.refresh_lots = self.refresh_lots.len() as u64;
        self.counters.sponsor_bids = self.sponsor_bids.len() as u64;
        self.counters.auction_rounds = self.auction_rounds.len() as u64;
        self.counters.auction_assignments = self.auction_assignments.len() as u64;
        self.counters.pq_attestations = self.pq_attestations.len() as u64;
        self.counters.auction_settlements = self.auction_settlements.len() as u64;
        self.counters.low_fee_audits = self.low_fee_audits.len() as u64;
        self.counters.public_records = self.public_records.len() as u64;
        self.counters.quarantined_lots = self.quarantined_lot_ids.len() as u64;
        self.counters.slashed_bids = self
            .sponsor_bids
            .values()
            .filter(|entry| entry.status == BidStatus::Slashed)
            .count() as u64;
        self.counters.rejected_lots = self
            .refresh_lots
            .values()
            .filter(|entry| entry.status == AuctionStatus::Rejected)
            .count() as u64;
        self.counters.expired_auctions = self
            .auction_rounds
            .values()
            .filter(|entry| entry.status == AuctionStatus::Expired)
            .count() as u64;
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            refresh_lot_root: map_root(
                REFRESH_LOT_SCHEME,
                self.refresh_lots
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            sponsor_bid_root: map_root(
                SPONSOR_BID_SCHEME,
                self.sponsor_bids
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            auction_round_root: map_root(
                AUCTION_ROUND_SCHEME,
                self.auction_rounds
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            auction_assignment_root: map_root(
                AUCTION_ASSIGNMENT_SCHEME,
                self.auction_assignments
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            pq_attestation_root: map_root(
                PQ_AUCTION_ATTESTATION_SCHEME,
                self.pq_attestations
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            auction_settlement_root: map_root(
                AUCTION_SETTLEMENT_SCHEME,
                self.auction_settlements
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            low_fee_audit_root: map_root(
                LOW_FEE_AUCTION_AUDIT_SCHEME,
                self.low_fee_audits
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
            quarantined_lot_root: set_root("quarantined-refresh-lots", &self.quarantined_lot_ids),
            used_bid_nullifier_root: set_root(
                "used-sponsor-bid-nullifiers",
                &self.used_bid_nullifiers,
            ),
            public_record_root: map_root(
                PUBLIC_RECORD_SCHEME,
                self.public_records
                    .iter()
                    .map(|(id, item)| (id.as_str(), item.state_root())),
            ),
        };
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.config.l2_network,
            "monero_network": self.config.monero_network,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "sponsor_coverage_bps": self.sponsor_coverage_bps(),
            "attested_assignment_bps": self.attested_assignment_bps(),
            "low_fee_success_bps": self.low_fee_success_bps(),
            "auction_clearing_bps": self.auction_clearing_bps(),
        })
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Json(&self.public_record()),
                HashPart::Str(&self.roots.state_root()),
            ],
        )
    }

    fn seed_devnet(&mut self) {
        let lot_id = "jamtis-seraphis-refresh-auction-lot-devnet-0".to_string();
        let auction_id = "jamtis-seraphis-refresh-sponsor-auction-devnet-0".to_string();
        let bid_id = "pq-private-refresh-sponsor-bid-devnet-0".to_string();
        let assignment_id = "refresh-sponsor-auction-assignment-devnet-0".to_string();
        let settlement_id = "refresh-sponsor-auction-settlement-devnet-0".to_string();

        self.insert_refresh_lot(RefreshLotInput {
            lot_id: lot_id.clone(),
            lane: AuctionLane::DexSettlement,
            epoch: self.epoch,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            output_count_bucket: self.config.target_decoy_pool_outputs,
            ring_size: self.config.target_ring_size,
            refresh_unit_bucket: 8_192,
            decoy_entropy_bps: 9_320,
            spendlink_shield_bps: 9_180,
            refresh_utility_bps: 9_020,
            decoy_pool_root: root_from_parts(
                "devnet-auction-decoy-pool",
                &[HashPart::Str(&lot_id)],
            ),
            spendlink_shield_root: root_from_parts(
                "devnet-auction-spendlink-shield",
                &[HashPart::Str(&lot_id)],
            ),
            refresh_plan_root: root_from_parts(
                "devnet-auction-refresh-plan",
                &[HashPart::Str(&lot_id)],
            ),
            solver_commitment_root: root_from_parts(
                "devnet-auction-solver-commitment",
                &[HashPart::Str(&lot_id)],
            ),
            expires_at_height: self.monero_height + self.config.refresh_lot_ttl_blocks,
            status: AuctionStatus::Open,
        })
        .expect("devnet refresh lot inserts");

        self.insert_auction_round(AuctionRoundEntry {
            auction_id: auction_id.clone(),
            lane: AuctionLane::DexSettlement,
            epoch: self.epoch,
            lot_root: map_root(
                "devnet-auction-lot-set",
                [(&lot_id as &str, self.refresh_lots[&lot_id].state_root())],
            ),
            bid_book_root: root_from_parts(
                "devnet-auction-bid-book",
                &[HashPart::Str(&auction_id)],
            ),
            clearing_transcript_root: root_from_parts(
                "devnet-auction-clearing-transcript",
                &[HashPart::Str(&auction_id)],
            ),
            clearing_price_bucket: 24,
            total_refresh_units_bucket: 8_192,
            eligible_bid_count_bucket: 16,
            winning_bid_count_bucket: 4,
            bid_diversity_bps: 8_760,
            clearing_quality_bps: 9_240,
            user_fee_ceiling_bps: 3,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            commit_deadline_height: self.monero_height + 48,
            reveal_deadline_height: self.monero_height + 96,
            expires_at_height: self.monero_height + self.config.auction_ttl_blocks,
            status: AuctionStatus::Cleared,
        })
        .expect("devnet auction inserts");

        self.insert_sponsor_bid(SponsorBidInput {
            bid_id: bid_id.clone(),
            auction_id: auction_id.clone(),
            sponsor_bucket: "devnet-private-sponsor-bucket-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            bid_commitment_root: root_from_parts(
                "devnet-sponsor-bid-commitment",
                &[HashPart::Str(&bid_id)],
            ),
            policy_root: root_from_parts("devnet-sponsor-policy", &[HashPart::Str(&bid_id)]),
            solvency_root: root_from_parts("devnet-sponsor-solvency", &[HashPart::Str(&bid_id)]),
            bid_nullifier: "devnet-private-sponsor-auction-nullifier-0".to_string(),
            max_user_fee_bps: 3,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            solvency_bps: 9_840,
            refresh_unit_budget_bucket: 65_536,
            reserved_fee_bucket: 96,
            priority_rebate_bps: 120,
            expires_at_height: self.monero_height + self.config.bid_ttl_blocks,
            status: BidStatus::Winning,
        })
        .expect("devnet sponsor bid inserts");

        self.insert_auction_assignment(AuctionAssignmentEntry {
            assignment_id: assignment_id.clone(),
            auction_id: auction_id.clone(),
            lot_id: lot_id.clone(),
            bid_id: bid_id.clone(),
            assignment_commitment_root: root_from_parts(
                "devnet-auction-assignment-commitment",
                &[HashPart::Str(&assignment_id)],
            ),
            refresh_receipt_root: root_from_parts(
                "devnet-auction-refresh-receipt",
                &[HashPart::Str(&assignment_id)],
            ),
            sponsor_receipt_root: root_from_parts(
                "devnet-auction-sponsor-receipt",
                &[HashPart::Str(&assignment_id)],
            ),
            refresh_unit_bucket: 8_192,
            user_fee_bps: 3,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            privacy_score_bps: 9_160,
            assigned_at_height: self.monero_height + 100,
            expires_at_height: self.monero_height + self.config.assignment_ttl_blocks,
            status: AssignmentStatus::Settled,
        })
        .expect("devnet assignment inserts");

        self.insert_pq_attestation(PqAuctionAttestationEntry {
            attestation_id: "pq-refresh-sponsor-auction-attestation-devnet-0".to_string(),
            auction_id: auction_id.clone(),
            assignment_id: assignment_id.clone(),
            signer_set_root: root_from_parts("devnet-pq-auction-signers", &[HashPart::Str("0")]),
            pq_transcript_root: root_from_parts(
                "devnet-pq-auction-transcript",
                &[HashPart::Str(&assignment_id)],
            ),
            refresh_integrity_root: root_from_parts(
                "devnet-refresh-integrity",
                &[HashPart::Str(&assignment_id)],
            ),
            pq_security_bits: self.config.target_pq_security_bits,
            classical_fallback_disabled: true,
            attested_at_height: self.monero_height + 120,
            expires_at_height: self.monero_height + self.config.attestation_ttl_blocks,
            status: AttestationStatus::StrongQuorum,
        })
        .expect("devnet pq auction attestation inserts");

        self.insert_auction_settlement(AuctionSettlementEntry {
            settlement_id: settlement_id.clone(),
            auction_id: auction_id.clone(),
            assignment_id: assignment_id.clone(),
            bid_nullifier: "devnet-private-sponsor-auction-nullifier-settled-0".to_string(),
            settlement_receipt_root: root_from_parts(
                "devnet-auction-settlement-receipt",
                &[HashPart::Str(&settlement_id)],
            ),
            defi_accounting_root: root_from_parts(
                "devnet-auction-defi-accounting",
                &[HashPart::Str(&settlement_id)],
            ),
            rebate_root: root_from_parts("devnet-auction-rebate", &[HashPart::Str(&settlement_id)]),
            refresh_unit_bucket: 8_192,
            user_fee_bps: 3,
            sponsor_cover_bps: self.config.target_sponsor_cover_bps,
            clearing_price_bucket: 24,
            rebate_bucket: 8,
            settlement_delay_blocks: 12,
            status: SettlementStatus::Final,
        })
        .expect("devnet auction settlement inserts");

        self.insert_low_fee_audit(LowFeeAuctionAuditEntry {
            audit_id: "refresh-sponsor-auction-low-fee-audit-devnet-0".to_string(),
            auction_id,
            settlement_id,
            measured_user_fee_bps: 3,
            target_user_fee_bps: self.config.max_user_refresh_fee_bps,
            sponsor_efficiency_bps: 9_420,
            clearing_quality_bps: 9_240,
            refresh_latency_blocks: 14,
            fee_sample_root: root_from_parts("devnet-auction-fee-samples", &[HashPart::Str("0")]),
            privacy_regression_root: root_from_parts(
                "devnet-auction-privacy-regression",
                &[HashPart::Str("0")],
            ),
            auction_fairness_root: root_from_parts(
                "devnet-auction-fairness",
                &[HashPart::Str("0")],
            ),
            accounting_evidence_root: root_from_parts(
                "devnet-auction-accounting-evidence",
                &[HashPart::Str("0")],
            ),
            status: AuditStatus::Accepted,
        })
        .expect("devnet low fee auction audit inserts");

        self.publish_roots_only_record(
            "roots-only-refresh-sponsor-auction-public-record-devnet-0",
            PublicAudience::Public,
        )
        .expect("devnet roots-only public record publishes");
        self.refresh_roots();
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn ensure_bps(value: u64, label: &str) -> Result<()> {
    ensure(value <= MAX_BPS, &format!("{label} exceeds 10000 bps"))
}

fn bucket(value: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        value
    } else {
        (value / bucket_size) * bucket_size
    }
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        STATE_ROOT_DOMAIN,
        &[HashPart::Str(domain), HashPart::Parts(parts)],
    )
}

fn map_root<I, S>(domain: &str, entries: I) -> String
where
    I: IntoIterator<Item = (S, String)>,
    S: AsRef<str>,
{
    let leaves = entries
        .into_iter()
        .map(|(key, root)| {
            domain_hash(
                STATE_ROOT_DOMAIN,
                &[
                    HashPart::Str(domain),
                    HashPart::Str(key.as_ref()),
                    HashPart::Str(&root),
                ],
            )
        })
        .collect::<Vec<_>>();
    if leaves.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(STATE_ROOT_DOMAIN, leaves.iter().map(String::as_str))
    }
}

fn set_root(domain: &str, entries: &BTreeSet<String>) -> String {
    map_root(
        domain,
        entries.iter().map(|entry| (entry.as_str(), entry.clone())),
    )
}
