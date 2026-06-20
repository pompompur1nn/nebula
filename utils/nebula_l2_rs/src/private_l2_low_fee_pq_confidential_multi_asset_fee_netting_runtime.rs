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
    "nebula-private-l2-low-fee-pq-confidential-multi-asset-fee-netting-runtime-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_ASSET_FEE_NETTING_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-low-fee-multi-asset-fee-netting-auth-v1";
pub const PQ_SEALING_SCHEME: &str = "ml-kem-1024+xwing-sealed-confidential-fee-obligation-v1";
pub const FEE_NETTING_PROTOCOL: &str = "monero-l2-pq-confidential-multi-asset-low-fee-netting-v1";
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_MULTI_ASSET_FEE_NETTING_RUNTIME_FEE_NETTING_PROTOCOL:
    &str = FEE_NETTING_PROTOCOL;
pub const ASSET_ORACLE_ATTESTATION_SCHEME: &str = "pq-asset-oracle-rate-attestation-root-v1";
pub const ENCRYPTED_OBLIGATION_SCHEME: &str = "ringct-style-sealed-fee-obligation-commitment-v1";
pub const BATCH_CLEARING_PROOF_SCHEME: &str =
    "zk-pq-confidential-multi-asset-fee-clearing-proof-v1";
pub const SPONSOR_POOL_SCHEME: &str = "low-fee-private-sponsor-pool-liquidity-root-v1";
pub const REBATE_COUPON_SCHEME: &str = "roots-only-private-multi-asset-fee-rebate-coupon-v1";
pub const ROUTING_RECEIPT_SCHEME: &str = "pq-private-fee-routing-receipt-root-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-l2-fee-netting-privacy-fence-v1";
pub const UNDERCOLLATERALIZED_CHALLENGE_SCHEME: &str =
    "private-fee-netting-undercollateralized-challenge-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-private-fee-netting-sponsor-router-slasher-v1";
pub const DEVNET_HEIGHT: u64 = 1_744_320;
pub const DEVNET_EPOCH: u64 = 2_423;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_OBLIGATION_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 36;
pub const DEFAULT_CHALLENGE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 8;
pub const DEFAULT_REBATE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 4_096;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_DECOY_SET_SIZE: u64 = 1_024;
pub const DEFAULT_MIN_FENCE_NULLIFIER_SET_SIZE: u64 = 512;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_FEE_MICRO_UNITS: u64 = 12;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_CLEARING_FEE_BPS: u64 = 2;
pub const DEFAULT_ORACLE_FEE_BPS: u64 = 1;
pub const DEFAULT_ROUTER_FEE_BPS: u64 = 3;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_000;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_200;
pub const DEFAULT_REBATE_BPS: u64 = 6;
pub const DEFAULT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_UNDERCOLLATERALIZED_BPS: u64 = 9_500;
pub const DEFAULT_MAX_ASSETS: usize = 1_048_576;
pub const DEFAULT_MAX_FEE_LANES: usize = 1_048_576;
pub const DEFAULT_MAX_OBLIGATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_BATCHES: usize = 2_097_152;
pub const DEFAULT_MAX_SPONSOR_POOLS: usize = 524_288;
pub const DEFAULT_MAX_REBATES: usize = 4_194_304;
pub const DEFAULT_MAX_ROUTING_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;
pub const DEFAULT_MAX_SLASHES: usize = 1_048_576;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    WrappedMonero,
    ConfidentialToken,
    StableAsset,
    VaultShare,
    LpToken,
    SyntheticAsset,
    GovernanceToken,
    RebateCoupon,
    AppFeeCredit,
}

impl AssetKind {
    pub fn stable_for_fee(self) -> bool {
        matches!(
            self,
            Self::WrappedMonero
                | Self::ConfidentialToken
                | Self::StableAsset
                | Self::AppFeeCredit
                | Self::RebateCoupon
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Registered,
    Active,
    OracleOnly,
    Paused,
    Frozen,
    Retired,
    Slashed,
}

impl AssetStatus {
    pub fn accepts_obligations(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }

    pub fn accepts_oracle(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::OracleOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneKind {
    PrivateTransfer,
    ConfidentialSwap,
    StableSwap,
    LendingPool,
    VaultStrategy,
    Perpetuals,
    BridgeExit,
    ContractCall,
    BatchMintBurn,
    AccountAbstraction,
    SponsorRelay,
    RouterAggregator,
}

impl FeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ConfidentialSwap => "confidential_swap",
            Self::StableSwap => "stable_swap",
            Self::LendingPool => "lending_pool",
            Self::VaultStrategy => "vault_strategy",
            Self::Perpetuals => "perpetuals",
            Self::BridgeExit => "bridge_exit",
            Self::ContractCall => "contract_call",
            Self::BatchMintBurn => "batch_mint_burn",
            Self::AccountAbstraction => "account_abstraction",
            Self::SponsorRelay => "sponsor_relay",
            Self::RouterAggregator => "router_aggregator",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeLaneStatus {
    Proposed,
    Open,
    Netting,
    Clearing,
    Settling,
    Settled,
    Paused,
    Expired,
    Slashed,
}

impl FeeLaneStatus {
    pub fn accepts_obligation(self) -> bool {
        matches!(self, Self::Proposed | Self::Open | Self::Netting)
    }

    pub fn can_build_batch(self) -> bool {
        matches!(self, Self::Open | Self::Netting | Self::Clearing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationStatus {
    Submitted,
    Admitted,
    Netted,
    Cleared,
    Sponsored,
    Rebated,
    Settled,
    Challenged,
    Rejected,
    Expired,
}

impl ObligationStatus {
    pub fn batchable(self) -> bool {
        matches!(self, Self::Submitted | Self::Admitted | Self::Sponsored)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationSide {
    UserPays,
    SponsorPays,
    RouterAdvances,
    RebateOffsets,
    PoolInternalizes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Proposed,
    Accepted,
    Superseded,
    Expired,
    Disputed,
    Slashed,
}

impl OracleStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Proposed | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    OracleLocked,
    Netted,
    Clearing,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
    Slashed,
}

impl BatchStatus {
    pub fn can_settle(self) -> bool {
        matches!(self, Self::Netted | Self::Clearing | Self::SettlementReady)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Registered,
    Active,
    Settling,
    Exhausted,
    Paused,
    Challenged,
    Slashed,
    Closed,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Registered | Self::Active | Self::Settling)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Redeemed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Issued,
    Finalized,
    Disputed,
    Superseded,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    NullifierSet,
    DecoySet,
    BatchSize,
    AssetBucket,
    SponsorBucket,
    RouterBucket,
    TimeBucket,
    CrossContractJoin,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierSet => "nullifier_set",
            Self::DecoySet => "decoy_set",
            Self::BatchSize => "batch_size",
            Self::AssetBucket => "asset_bucket",
            Self::SponsorBucket => "sponsor_bucket",
            Self::RouterBucket => "router_bucket",
            Self::TimeBucket => "time_bucket",
            Self::CrossContractJoin => "cross_contract_join",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Settled,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashTarget {
    SponsorPool,
    Router,
    Oracle,
    LaneOperator,
}

impl SlashTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorPool => "sponsor_pool",
            Self::Router => "router",
            Self::Oracle => "oracle",
            Self::LaneOperator => "lane_operator",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_auth_scheme: String,
    pub pq_sealing_scheme: String,
    pub fee_netting_protocol: String,
    pub asset_oracle_attestation_scheme: String,
    pub encrypted_obligation_scheme: String,
    pub batch_clearing_proof_scheme: String,
    pub sponsor_pool_scheme: String,
    pub rebate_coupon_scheme: String,
    pub routing_receipt_scheme: String,
    pub privacy_fence_scheme: String,
    pub challenge_scheme: String,
    pub slashing_evidence_scheme: String,
    pub epoch_blocks: u64,
    pub lane_ttl_blocks: u64,
    pub obligation_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub min_fence_nullifier_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_micro_units: u64,
    pub max_user_fee_bps: u64,
    pub clearing_fee_bps: u64,
    pub oracle_fee_bps: u64,
    pub router_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub rebate_bps: u64,
    pub slash_bps: u64,
    pub undercollateralized_bps: u64,
    pub max_assets: usize,
    pub max_fee_lanes: usize,
    pub max_obligations: usize,
    pub max_oracle_attestations: usize,
    pub max_batches: usize,
    pub max_sponsor_pools: usize,
    pub max_rebates: usize,
    pub max_routing_receipts: usize,
    pub max_privacy_fences: usize,
    pub max_challenges: usize,
    pub max_slashes: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_auth_scheme: PQ_AUTH_SCHEME.to_string(),
            pq_sealing_scheme: PQ_SEALING_SCHEME.to_string(),
            fee_netting_protocol: FEE_NETTING_PROTOCOL.to_string(),
            asset_oracle_attestation_scheme: ASSET_ORACLE_ATTESTATION_SCHEME.to_string(),
            encrypted_obligation_scheme: ENCRYPTED_OBLIGATION_SCHEME.to_string(),
            batch_clearing_proof_scheme: BATCH_CLEARING_PROOF_SCHEME.to_string(),
            sponsor_pool_scheme: SPONSOR_POOL_SCHEME.to_string(),
            rebate_coupon_scheme: REBATE_COUPON_SCHEME.to_string(),
            routing_receipt_scheme: ROUTING_RECEIPT_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            challenge_scheme: UNDERCOLLATERALIZED_CHALLENGE_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            obligation_ttl_blocks: DEFAULT_OBLIGATION_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            challenge_ttl_blocks: DEFAULT_CHALLENGE_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_window_blocks: DEFAULT_REBATE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_decoy_set_size: DEFAULT_MIN_DECOY_SET_SIZE,
            min_fence_nullifier_set_size: DEFAULT_MIN_FENCE_NULLIFIER_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_micro_units: DEFAULT_BASE_FEE_MICRO_UNITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            clearing_fee_bps: DEFAULT_CLEARING_FEE_BPS,
            oracle_fee_bps: DEFAULT_ORACLE_FEE_BPS,
            router_fee_bps: DEFAULT_ROUTER_FEE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            rebate_bps: DEFAULT_REBATE_BPS,
            slash_bps: DEFAULT_SLASH_BPS,
            undercollateralized_bps: DEFAULT_UNDERCOLLATERALIZED_BPS,
            max_assets: DEFAULT_MAX_ASSETS,
            max_fee_lanes: DEFAULT_MAX_FEE_LANES,
            max_obligations: DEFAULT_MAX_OBLIGATIONS,
            max_oracle_attestations: DEFAULT_MAX_ORACLE_ATTESTATIONS,
            max_batches: DEFAULT_MAX_BATCHES,
            max_sponsor_pools: DEFAULT_MAX_SPONSOR_POOLS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_routing_receipts: DEFAULT_MAX_ROUTING_RECEIPTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
            max_slashes: DEFAULT_MAX_SLASHES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "protocol version mismatch: {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "schema version mismatch"
        );
        ensure!(
            self.chain_id == CHAIN_ID,
            "chain id mismatch: {}",
            self.chain_id
        );
        ensure!(self.hash_suite == HASH_SUITE, "hash suite mismatch");
        ensure!(
            self.pq_auth_scheme == PQ_AUTH_SCHEME,
            "pq auth scheme mismatch"
        );
        ensure!(
            self.pq_sealing_scheme == PQ_SEALING_SCHEME,
            "pq sealing scheme mismatch"
        );
        ensure!(self.epoch_blocks > 0, "epoch blocks must be non-zero");
        ensure!(
            self.lane_ttl_blocks >= self.batch_ttl_blocks,
            "lane ttl must cover batch ttl"
        );
        ensure!(
            self.obligation_ttl_blocks >= self.batch_ttl_blocks,
            "obligation ttl must cover batch ttl"
        );
        ensure!(
            self.min_privacy_set_size >= self.min_decoy_set_size,
            "privacy set must cover decoy set"
        );
        ensure!(
            self.target_privacy_set_size >= self.min_privacy_set_size,
            "target privacy set too small"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security bits below minimum"
        );
        ensure!(self.max_user_fee_bps <= MAX_BPS, "user fee bps too high");
        ensure!(
            self.clearing_fee_bps <= MAX_BPS,
            "clearing fee bps too high"
        );
        ensure!(self.oracle_fee_bps <= MAX_BPS, "oracle fee bps too high");
        ensure!(self.router_fee_bps <= MAX_BPS, "router fee bps too high");
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps too high"
        );
        ensure!(
            self.sponsor_reserve_bps <= MAX_BPS,
            "sponsor reserve bps too high"
        );
        ensure!(self.rebate_bps <= MAX_BPS, "rebate bps too high");
        ensure!(self.slash_bps <= MAX_BPS, "slash bps too high");
        ensure!(
            self.undercollateralized_bps <= MAX_BPS,
            "undercollateralized bps too high"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub assets_registered: u64,
    pub fee_lanes_opened: u64,
    pub obligations_submitted: u64,
    pub obligations_admitted: u64,
    pub obligations_netted: u64,
    pub obligations_settled: u64,
    pub oracle_attestations: u64,
    pub batches_built: u64,
    pub sponsor_pools_opened: u64,
    pub sponsor_pool_settlements: u64,
    pub rebates_issued: u64,
    pub rebates_redeemed: u64,
    pub routing_receipts_issued: u64,
    pub privacy_fences_posted: u64,
    pub undercollateralized_challenges: u64,
    pub slashes: u64,
    pub total_fee_micro_units: u128,
    pub total_sponsored_micro_units: u128,
    pub total_rebated_micro_units: u128,
    pub total_slashed_micro_units: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub assets_root: String,
    pub fee_lanes_root: String,
    pub obligations_root: String,
    pub oracle_attestations_root: String,
    pub batches_root: String,
    pub sponsor_pools_root: String,
    pub rebates_root: String,
    pub routing_receipts_root: String,
    pub privacy_fences_root: String,
    pub challenges_root: String,
    pub slashes_root: String,
    pub counters_root: String,
    pub config_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRegistryEntry {
    pub asset_id: String,
    pub asset_kind: AssetKind,
    pub status: AssetStatus,
    pub issuer_commitment: String,
    pub metadata_root: String,
    pub oracle_set_root: String,
    pub fee_discount_bps: u64,
    pub min_obligation_micro_units: u64,
    pub max_obligation_micro_units: u64,
    pub decimals: u8,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeLane {
    pub lane_id: String,
    pub lane_kind: FeeLaneKind,
    pub status: FeeLaneStatus,
    pub operator_commitment: String,
    pub router_commitment: String,
    pub sponsor_pool_id: Option<String>,
    pub accepted_asset_ids: BTreeSet<String>,
    pub admission_root: String,
    pub privacy_fence_root: String,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub obligation_count: u64,
    pub netted_count: u64,
    pub settled_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFeeObligation {
    pub obligation_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub side: ObligationSide,
    pub status: ObligationStatus,
    pub payer_commitment: String,
    pub sponsor_pool_id: Option<String>,
    pub encrypted_amount_commitment: String,
    pub amount_upper_bound_micro_units: u64,
    pub fee_cap_micro_units: u64,
    pub nullifier: String,
    pub note_commitment: String,
    pub route_commitment: String,
    pub proof_root: String,
    pub privacy_fence_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub batch_id: Option<String>,
    pub routing_receipt_id: Option<String>,
    pub rebate_coupon_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAssetOracleAttestation {
    pub attestation_id: String,
    pub asset_id: String,
    pub status: OracleStatus,
    pub oracle_committee_root: String,
    pub rate_commitment: String,
    pub quote_asset_id: String,
    pub price_micro_units: u64,
    pub confidence_bps: u64,
    pub volatility_bps: u64,
    pub pq_signature_root: String,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFeeClearing {
    pub batch_id: String,
    pub lane_id: String,
    pub status: BatchStatus,
    pub obligation_ids: BTreeSet<String>,
    pub asset_ids: BTreeSet<String>,
    pub oracle_attestation_ids: BTreeSet<String>,
    pub sponsor_pool_ids: BTreeSet<String>,
    pub gross_fee_micro_units: u128,
    pub net_fee_micro_units: u128,
    pub sponsored_micro_units: u128,
    pub rebate_micro_units: u128,
    pub clearing_fee_micro_units: u64,
    pub proof_root: String,
    pub netting_root: String,
    pub settlement_root: String,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPool {
    pub sponsor_pool_id: String,
    pub status: SponsorStatus,
    pub sponsor_commitment: String,
    pub collateral_asset_id: String,
    pub accepted_lane_ids: BTreeSet<String>,
    pub liquidity_commitment: String,
    pub collateral_micro_units: u128,
    pub reserved_micro_units: u128,
    pub settled_micro_units: u128,
    pub slashed_micro_units: u128,
    pub cover_bps: u64,
    pub reserve_bps: u64,
    pub opened_at_height: u64,
    pub updated_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateCoupon {
    pub coupon_id: String,
    pub status: CouponStatus,
    pub batch_id: String,
    pub obligation_id: String,
    pub asset_id: String,
    pub sponsor_pool_id: Option<String>,
    pub recipient_commitment: String,
    pub coupon_commitment: String,
    pub amount_micro_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed_at_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingReceipt {
    pub receipt_id: String,
    pub batch_id: String,
    pub obligation_id: String,
    pub lane_id: String,
    pub router_commitment: String,
    pub status: ReceiptStatus,
    pub route_commitment: String,
    pub fee_asset_id: String,
    pub charged_micro_units: u64,
    pub sponsored_micro_units: u64,
    pub rebate_micro_units: u64,
    pub receipt_root: String,
    pub issued_at_height: u64,
    pub finalizes_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub lane_id: String,
    pub kind: FenceKind,
    pub status: ReceiptStatus,
    pub nullifier_set_root: String,
    pub decoy_set_root: String,
    pub asset_bucket_root: String,
    pub sponsor_bucket_root: String,
    pub min_privacy_set_size: u64,
    pub min_decoy_set_size: u64,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndercollateralizedFeeChallenge {
    pub challenge_id: String,
    pub batch_id: String,
    pub sponsor_pool_id: String,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub alleged_required_collateral_micro_units: u128,
    pub alleged_available_collateral_micro_units: u128,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub slash_id: String,
    pub target: SlashTarget,
    pub target_id: String,
    pub related_batch_id: Option<String>,
    pub related_challenge_id: Option<String>,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub penalty_micro_units: u128,
    pub accepted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub assets: BTreeMap<String, AssetRegistryEntry>,
    pub fee_lanes: BTreeMap<String, FeeLane>,
    pub obligations: BTreeMap<String, EncryptedFeeObligation>,
    pub oracle_attestations: BTreeMap<String, PqAssetOracleAttestation>,
    pub latest_oracle_by_asset: BTreeMap<String, String>,
    pub batches: BTreeMap<String, BatchFeeClearing>,
    pub sponsor_pools: BTreeMap<String, SponsorPool>,
    pub rebates: BTreeMap<String, RebateCoupon>,
    pub routing_receipts: BTreeMap<String, RoutingReceipt>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub challenges: BTreeMap<String, UndercollateralizedFeeChallenge>,
    pub slashes: BTreeMap<String, SlashingEvidence>,
    pub nullifiers: BTreeSet<String>,
    pub current_height: u64,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            assets: BTreeMap::new(),
            fee_lanes: BTreeMap::new(),
            obligations: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            latest_oracle_by_asset: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            rebates: BTreeMap::new(),
            routing_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashes: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            current_height: DEVNET_HEIGHT,
        };
        state.install_devnet_assets();
        state
    }
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            ..Self::empty_without_devnet()
        })
    }

    pub fn empty_without_devnet() -> Self {
        Self {
            config: Config::default(),
            counters: Counters::default(),
            assets: BTreeMap::new(),
            fee_lanes: BTreeMap::new(),
            obligations: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            latest_oracle_by_asset: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsor_pools: BTreeMap::new(),
            rebates: BTreeMap::new(),
            routing_receipts: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            challenges: BTreeMap::new(),
            slashes: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            current_height: DEVNET_HEIGHT,
        }
    }

    pub fn devnet() -> Self {
        Self::default()
    }

    fn install_devnet_assets(&mut self) {
        let _ = self.register_asset(
            DEVNET_FEE_ASSET_ID.to_string(),
            AssetKind::WrappedMonero,
            "devnet-wxmr-issuer".to_string(),
            deterministic_root(
                "devnet-wxmr-metadata",
                &[HashPart::Str(DEVNET_FEE_ASSET_ID)],
            ),
            deterministic_root("devnet-wxmr-oracles", &[HashPart::Str(DEVNET_FEE_ASSET_ID)]),
            0,
            1,
            50_000_000_000,
            12,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEVNET_HEIGHT,
        );
        let _ = self.register_asset(
            DEVNET_STABLE_ASSET_ID.to_string(),
            AssetKind::StableAsset,
            "devnet-dusd-issuer".to_string(),
            deterministic_root(
                "devnet-dusd-metadata",
                &[HashPart::Str(DEVNET_STABLE_ASSET_ID)],
            ),
            deterministic_root(
                "devnet-dusd-oracles",
                &[HashPart::Str(DEVNET_STABLE_ASSET_ID)],
            ),
            0,
            1,
            100_000_000_000,
            6,
            DEFAULT_MIN_PQ_SECURITY_BITS,
            DEVNET_HEIGHT,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_asset(
        &mut self,
        asset_id: String,
        asset_kind: AssetKind,
        issuer_commitment: String,
        metadata_root: String,
        oracle_set_root: String,
        fee_discount_bps: u64,
        min_obligation_micro_units: u64,
        max_obligation_micro_units: u64,
        decimals: u8,
        pq_security_bits: u16,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(!asset_id.is_empty(), "asset id cannot be empty");
        ensure!(
            self.assets.len() < self.config.max_assets,
            "asset registry capacity exceeded"
        );
        ensure!(
            !self.assets.contains_key(&asset_id),
            "asset already registered: {}",
            asset_id
        );
        ensure!(
            asset_kind.stable_for_fee(),
            "asset kind is not accepted for fee netting: {:?}",
            asset_kind
        );
        ensure!(
            !issuer_commitment.is_empty(),
            "issuer commitment cannot be empty"
        );
        ensure!(!metadata_root.is_empty(), "metadata root cannot be empty");
        ensure!(
            !oracle_set_root.is_empty(),
            "oracle set root cannot be empty"
        );
        ensure!(fee_discount_bps <= MAX_BPS, "fee discount too high");
        ensure!(
            min_obligation_micro_units <= max_obligation_micro_units,
            "asset min obligation exceeds max"
        );
        ensure!(decimals <= 18, "asset decimals too high");
        ensure!(
            pq_security_bits >= self.config.min_pq_security_bits,
            "asset pq security below runtime minimum"
        );

        let entry = AssetRegistryEntry {
            asset_id: asset_id.clone(),
            asset_kind,
            status: AssetStatus::Registered,
            issuer_commitment,
            metadata_root,
            oracle_set_root,
            fee_discount_bps,
            min_obligation_micro_units,
            max_obligation_micro_units,
            decimals,
            pq_security_bits,
            registered_at_height: height,
            updated_at_height: height,
        };
        self.assets.insert(asset_id.clone(), entry);
        self.counters.assets_registered = self.counters.assets_registered.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(asset_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_fee_lane(
        &mut self,
        lane_kind: FeeLaneKind,
        operator_commitment: String,
        router_commitment: String,
        sponsor_pool_id: Option<String>,
        accepted_asset_ids: BTreeSet<String>,
        admission_root: String,
        privacy_fence_root: String,
        max_user_fee_bps: u64,
        min_privacy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.fee_lanes.len() < self.config.max_fee_lanes,
            "fee lane capacity exceeded"
        );
        ensure!(
            !operator_commitment.is_empty(),
            "operator commitment cannot be empty"
        );
        ensure!(
            !router_commitment.is_empty(),
            "router commitment cannot be empty"
        );
        ensure!(
            !accepted_asset_ids.is_empty(),
            "fee lane requires accepted assets"
        );
        ensure!(
            max_user_fee_bps <= self.config.max_user_fee_bps,
            "lane max user fee exceeds runtime cap"
        );
        ensure!(
            min_privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set below runtime minimum"
        );
        for asset_id in &accepted_asset_ids {
            let asset = self
                .assets
                .get(asset_id)
                .ok_or_else(|| format!("unknown accepted asset: {asset_id}"))?;
            ensure!(
                asset.status.accepts_obligations(),
                "accepted asset is not active for obligations: {}",
                asset_id
            );
        }
        if let Some(pool_id) = &sponsor_pool_id {
            let pool = self
                .sponsor_pools
                .get(pool_id)
                .ok_or_else(|| format!("unknown sponsor pool: {pool_id}"))?;
            ensure!(
                pool.status.usable(),
                "sponsor pool is not usable: {}",
                pool_id
            );
        }

        let lane_id = fee_lane_id(
            lane_kind,
            &operator_commitment,
            &router_commitment,
            &accepted_asset_ids,
            height,
            self.counters.fee_lanes_opened,
        );
        ensure!(
            !self.fee_lanes.contains_key(&lane_id),
            "fee lane id collision: {}",
            lane_id
        );
        let lane = FeeLane {
            lane_id: lane_id.clone(),
            lane_kind,
            status: FeeLaneStatus::Open,
            operator_commitment,
            router_commitment,
            sponsor_pool_id,
            accepted_asset_ids,
            admission_root,
            privacy_fence_root,
            max_user_fee_bps,
            min_privacy_set_size,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.lane_ttl_blocks),
            obligation_count: 0,
            netted_count: 0,
            settled_count: 0,
        };
        self.fee_lanes.insert(lane_id.clone(), lane);
        self.counters.fee_lanes_opened = self.counters.fee_lanes_opened.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(lane_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_sponsor_pool(
        &mut self,
        sponsor_commitment: String,
        collateral_asset_id: String,
        accepted_lane_ids: BTreeSet<String>,
        liquidity_commitment: String,
        collateral_micro_units: u128,
        cover_bps: u64,
        reserve_bps: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.sponsor_pools.len() < self.config.max_sponsor_pools,
            "sponsor pool capacity exceeded"
        );
        ensure!(
            !sponsor_commitment.is_empty(),
            "sponsor commitment cannot be empty"
        );
        ensure!(
            !liquidity_commitment.is_empty(),
            "liquidity commitment cannot be empty"
        );
        let asset = self
            .assets
            .get(&collateral_asset_id)
            .ok_or_else(|| format!("unknown collateral asset: {collateral_asset_id}"))?;
        ensure!(
            asset.status.accepts_obligations(),
            "collateral asset is not usable"
        );
        ensure!(collateral_micro_units > 0, "collateral must be non-zero");
        ensure!(
            cover_bps >= self.config.sponsor_cover_bps,
            "sponsor cover below runtime minimum"
        );
        ensure!(cover_bps <= MAX_BPS, "sponsor cover too high");
        ensure!(
            reserve_bps >= self.config.sponsor_reserve_bps,
            "sponsor reserve below runtime minimum"
        );
        ensure!(reserve_bps <= MAX_BPS, "sponsor reserve too high");
        for lane_id in &accepted_lane_ids {
            ensure!(
                self.fee_lanes.contains_key(lane_id),
                "unknown accepted lane: {}",
                lane_id
            );
        }

        let sponsor_pool_id = sponsor_pool_id(
            &sponsor_commitment,
            &collateral_asset_id,
            &liquidity_commitment,
            height,
            self.counters.sponsor_pools_opened,
        );
        ensure!(
            !self.sponsor_pools.contains_key(&sponsor_pool_id),
            "sponsor pool id collision: {}",
            sponsor_pool_id
        );
        let pool = SponsorPool {
            sponsor_pool_id: sponsor_pool_id.clone(),
            status: SponsorStatus::Active,
            sponsor_commitment,
            collateral_asset_id,
            accepted_lane_ids,
            liquidity_commitment,
            collateral_micro_units,
            reserved_micro_units: 0,
            settled_micro_units: 0,
            slashed_micro_units: 0,
            cover_bps,
            reserve_bps,
            opened_at_height: height,
            updated_at_height: height,
        };
        self.sponsor_pools.insert(sponsor_pool_id.clone(), pool);
        self.counters.sponsor_pools_opened = self.counters.sponsor_pools_opened.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(sponsor_pool_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn submit_encrypted_obligation(
        &mut self,
        lane_id: String,
        asset_id: String,
        side: ObligationSide,
        payer_commitment: String,
        sponsor_pool_id: Option<String>,
        encrypted_amount_commitment: String,
        amount_upper_bound_micro_units: u64,
        fee_cap_micro_units: u64,
        nullifier: String,
        note_commitment: String,
        route_commitment: String,
        proof_root: String,
        privacy_fence_id: Option<String>,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.obligations.len() < self.config.max_obligations,
            "obligation capacity exceeded"
        );
        ensure!(!payer_commitment.is_empty(), "payer commitment is empty");
        ensure!(
            !encrypted_amount_commitment.is_empty(),
            "encrypted amount commitment is empty"
        );
        ensure!(
            !nullifier.is_empty() && !self.nullifiers.contains(&nullifier),
            "nullifier already used or empty"
        );
        ensure!(!note_commitment.is_empty(), "note commitment is empty");
        ensure!(!route_commitment.is_empty(), "route commitment is empty");
        ensure!(!proof_root.is_empty(), "proof root is empty");
        let lane = self
            .fee_lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        ensure!(height <= lane.expires_at_height, "fee lane expired");
        ensure!(
            lane.status.accepts_obligation(),
            "fee lane does not accept obligations"
        );
        ensure!(
            lane.accepted_asset_ids.contains(&asset_id),
            "asset not accepted by lane"
        );
        let asset = self
            .assets
            .get(&asset_id)
            .ok_or_else(|| format!("unknown asset: {asset_id}"))?;
        ensure!(
            asset.status.accepts_obligations(),
            "asset does not accept obligations"
        );
        ensure!(
            amount_upper_bound_micro_units >= asset.min_obligation_micro_units,
            "obligation below asset minimum"
        );
        ensure!(
            amount_upper_bound_micro_units <= asset.max_obligation_micro_units,
            "obligation exceeds asset maximum"
        );
        ensure!(
            fee_cap_micro_units >= self.config.base_fee_micro_units,
            "fee cap below base fee"
        );
        ensure!(
            fee_cap_micro_units >= amount_upper_bound_micro_units,
            "fee cap below amount upper bound"
        );
        if let Some(fence_id) = &privacy_fence_id {
            let fence = self
                .privacy_fences
                .get(fence_id)
                .ok_or_else(|| format!("unknown privacy fence: {fence_id}"))?;
            ensure!(fence.lane_id == lane_id, "privacy fence lane mismatch");
            ensure!(
                fence.min_privacy_set_size >= lane.min_privacy_set_size,
                "privacy fence below lane minimum"
            );
            ensure!(height <= fence.expires_at_height, "privacy fence expired");
        }
        if let Some(pool_id) = &sponsor_pool_id {
            let pool = self
                .sponsor_pools
                .get(pool_id)
                .ok_or_else(|| format!("unknown sponsor pool: {pool_id}"))?;
            ensure!(pool.status.usable(), "sponsor pool not usable");
            ensure!(
                pool.accepted_lane_ids.is_empty() || pool.accepted_lane_ids.contains(&lane_id),
                "sponsor pool does not accept lane"
            );
        }

        let obligation_id = obligation_id(
            &lane_id,
            &asset_id,
            &payer_commitment,
            &nullifier,
            height,
            self.counters.obligations_submitted,
        );
        ensure!(
            !self.obligations.contains_key(&obligation_id),
            "obligation id collision: {}",
            obligation_id
        );
        let obligation = EncryptedFeeObligation {
            obligation_id: obligation_id.clone(),
            lane_id: lane_id.clone(),
            asset_id,
            side,
            status: ObligationStatus::Admitted,
            payer_commitment,
            sponsor_pool_id,
            encrypted_amount_commitment,
            amount_upper_bound_micro_units,
            fee_cap_micro_units,
            nullifier: nullifier.clone(),
            note_commitment,
            route_commitment,
            proof_root,
            privacy_fence_id,
            submitted_at_height: height,
            expires_at_height: height.saturating_add(self.config.obligation_ttl_blocks),
            batch_id: None,
            routing_receipt_id: None,
            rebate_coupon_id: None,
        };
        self.obligations.insert(obligation_id.clone(), obligation);
        self.nullifiers.insert(nullifier);
        let lane = self
            .fee_lanes
            .get_mut(&lane_id)
            .expect("lane checked before obligation insert");
        lane.obligation_count = lane.obligation_count.saturating_add(1);
        if lane.status == FeeLaneStatus::Open {
            lane.status = FeeLaneStatus::Netting;
        }
        self.counters.obligations_submitted = self.counters.obligations_submitted.saturating_add(1);
        self.counters.obligations_admitted = self.counters.obligations_admitted.saturating_add(1);
        self.counters.total_fee_micro_units = self
            .counters
            .total_fee_micro_units
            .saturating_add(amount_upper_bound_micro_units as u128);
        self.current_height = self.current_height.max(height);
        Ok(obligation_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn attest_asset_rate(
        &mut self,
        asset_id: String,
        oracle_committee_root: String,
        rate_commitment: String,
        quote_asset_id: String,
        price_micro_units: u64,
        confidence_bps: u64,
        volatility_bps: u64,
        pq_signature_root: String,
        observed_at_height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.oracle_attestations.len() < self.config.max_oracle_attestations,
            "oracle attestation capacity exceeded"
        );
        let asset = self
            .assets
            .get(&asset_id)
            .ok_or_else(|| format!("unknown asset: {asset_id}"))?;
        ensure!(asset.status.accepts_oracle(), "asset not open for oracle");
        ensure!(
            self.assets.contains_key(&quote_asset_id),
            "unknown quote asset: {}",
            quote_asset_id
        );
        ensure!(
            !oracle_committee_root.is_empty(),
            "oracle committee root cannot be empty"
        );
        ensure!(
            !rate_commitment.is_empty(),
            "rate commitment cannot be empty"
        );
        ensure!(price_micro_units > 0, "oracle price must be non-zero");
        ensure!(confidence_bps <= MAX_BPS, "confidence bps too high");
        ensure!(volatility_bps <= MAX_BPS, "volatility bps too high");
        ensure!(
            !pq_signature_root.is_empty(),
            "pq signature root cannot be empty"
        );

        if let Some(previous_id) = self.latest_oracle_by_asset.get(&asset_id).cloned() {
            if let Some(previous) = self.oracle_attestations.get_mut(&previous_id) {
                if previous.status.usable() {
                    previous.status = OracleStatus::Superseded;
                }
            }
        }

        let attestation_id = oracle_attestation_id(
            &asset_id,
            &quote_asset_id,
            &rate_commitment,
            observed_at_height,
            self.counters.oracle_attestations,
        );
        ensure!(
            !self.oracle_attestations.contains_key(&attestation_id),
            "oracle attestation id collision: {}",
            attestation_id
        );
        let attestation = PqAssetOracleAttestation {
            attestation_id: attestation_id.clone(),
            asset_id: asset_id.clone(),
            status: OracleStatus::Accepted,
            oracle_committee_root,
            rate_commitment,
            quote_asset_id,
            price_micro_units,
            confidence_bps,
            volatility_bps,
            pq_signature_root,
            observed_at_height,
            expires_at_height: observed_at_height.saturating_add(self.config.oracle_ttl_blocks),
        };
        self.oracle_attestations
            .insert(attestation_id.clone(), attestation);
        self.latest_oracle_by_asset
            .insert(asset_id, attestation_id.clone());
        self.counters.oracle_attestations = self.counters.oracle_attestations.saturating_add(1);
        self.current_height = self.current_height.max(observed_at_height);
        Ok(attestation_id)
    }

    pub fn post_privacy_fence(
        &mut self,
        lane_id: String,
        kind: FenceKind,
        nullifier_set_root: String,
        decoy_set_root: String,
        asset_bucket_root: String,
        sponsor_bucket_root: String,
        min_privacy_set_size: u64,
        min_decoy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.privacy_fences.len() < self.config.max_privacy_fences,
            "privacy fence capacity exceeded"
        );
        let lane = self
            .fee_lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        ensure!(height <= lane.expires_at_height, "lane expired");
        ensure!(
            min_privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below runtime minimum"
        );
        ensure!(
            min_privacy_set_size >= lane.min_privacy_set_size,
            "privacy set below lane minimum"
        );
        ensure!(
            min_decoy_set_size >= self.config.min_decoy_set_size,
            "decoy set below runtime minimum"
        );
        ensure!(
            !nullifier_set_root.is_empty(),
            "nullifier set root cannot be empty"
        );
        ensure!(!decoy_set_root.is_empty(), "decoy set root cannot be empty");
        ensure!(
            !asset_bucket_root.is_empty(),
            "asset bucket root cannot be empty"
        );
        ensure!(
            !sponsor_bucket_root.is_empty(),
            "sponsor bucket root cannot be empty"
        );
        let fence_id = privacy_fence_id(
            &lane_id,
            kind,
            &nullifier_set_root,
            height,
            self.counters.privacy_fences_posted,
        );
        ensure!(
            !self.privacy_fences.contains_key(&fence_id),
            "privacy fence id collision: {}",
            fence_id
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            lane_id: lane_id.clone(),
            kind,
            status: ReceiptStatus::Issued,
            nullifier_set_root,
            decoy_set_root,
            asset_bucket_root,
            sponsor_bucket_root,
            min_privacy_set_size,
            min_decoy_set_size,
            posted_at_height: height,
            expires_at_height: height.saturating_add(self.config.epoch_blocks),
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        let lane = self
            .fee_lanes
            .get_mut(&lane_id)
            .expect("lane checked before fence insert");
        lane.privacy_fence_root = deterministic_root(
            "fee-lane-privacy-fence-update",
            &[
                HashPart::Str(&lane.privacy_fence_root),
                HashPart::Str(&fence_id),
            ],
        );
        self.counters.privacy_fences_posted = self.counters.privacy_fences_posted.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(fence_id)
    }

    pub fn build_netting_batch(
        &mut self,
        lane_id: String,
        obligation_ids: BTreeSet<String>,
        proof_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.batches.len() < self.config.max_batches,
            "batch capacity exceeded"
        );
        ensure!(!obligation_ids.is_empty(), "batch needs obligations");
        ensure!(!proof_root.is_empty(), "batch proof root cannot be empty");
        let lane = self
            .fee_lanes
            .get(&lane_id)
            .ok_or_else(|| format!("unknown lane: {lane_id}"))?;
        ensure!(lane.status.can_build_batch(), "lane cannot build batch");
        ensure!(height <= lane.expires_at_height, "lane expired");

        let mut asset_ids = BTreeSet::new();
        let mut oracle_attestation_ids = BTreeSet::new();
        let mut sponsor_pool_ids = BTreeSet::new();
        let mut gross_fee_micro_units = 0_u128;
        let mut sponsored_micro_units = 0_u128;
        let mut rebate_micro_units = 0_u128;

        for obligation_id in &obligation_ids {
            let obligation = self
                .obligations
                .get(obligation_id)
                .ok_or_else(|| format!("unknown obligation: {obligation_id}"))?;
            ensure!(obligation.lane_id == lane_id, "obligation lane mismatch");
            ensure!(
                obligation.status.batchable(),
                "obligation is not batchable: {}",
                obligation_id
            );
            ensure!(
                height <= obligation.expires_at_height,
                "obligation expired: {}",
                obligation_id
            );
            let asset = self
                .assets
                .get(&obligation.asset_id)
                .ok_or_else(|| format!("unknown obligation asset: {}", obligation.asset_id))?;
            ensure!(
                asset.status.accepts_obligations(),
                "obligation asset not active"
            );
            let oracle_id = self
                .latest_oracle_by_asset
                .get(&obligation.asset_id)
                .ok_or_else(|| format!("missing oracle for asset: {}", obligation.asset_id))?;
            let oracle = self
                .oracle_attestations
                .get(oracle_id)
                .ok_or_else(|| format!("missing oracle attestation: {oracle_id}"))?;
            ensure!(
                oracle.status.usable(),
                "oracle attestation not usable: {}",
                oracle_id
            );
            ensure!(
                height <= oracle.expires_at_height,
                "oracle attestation expired: {}",
                oracle_id
            );
            asset_ids.insert(obligation.asset_id.clone());
            oracle_attestation_ids.insert(oracle_id.clone());
            gross_fee_micro_units = gross_fee_micro_units
                .saturating_add(obligation.amount_upper_bound_micro_units as u128);
            if let Some(pool_id) = &obligation.sponsor_pool_id {
                let pool = self
                    .sponsor_pools
                    .get(pool_id)
                    .ok_or_else(|| format!("unknown sponsor pool: {pool_id}"))?;
                ensure!(pool.status.usable(), "sponsor pool not usable");
                sponsor_pool_ids.insert(pool_id.clone());
                let sponsored = bps_amount(
                    obligation.amount_upper_bound_micro_units as u128,
                    self.config.sponsor_cover_bps,
                );
                sponsored_micro_units = sponsored_micro_units.saturating_add(sponsored);
            }
            let discount = bps_amount(
                obligation.amount_upper_bound_micro_units as u128,
                asset.fee_discount_bps.min(self.config.rebate_bps),
            );
            rebate_micro_units = rebate_micro_units.saturating_add(discount);
        }

        let clearing_fee_micro_units =
            bps_amount(gross_fee_micro_units, self.config.clearing_fee_bps) as u64;
        let net_fee_micro_units = gross_fee_micro_units
            .saturating_add(clearing_fee_micro_units as u128)
            .saturating_sub(sponsored_micro_units)
            .saturating_sub(rebate_micro_units);
        let batch_id = batch_id(
            &lane_id,
            &obligation_ids,
            &asset_ids,
            &oracle_attestation_ids,
            height,
            self.counters.batches_built,
        );
        ensure!(
            !self.batches.contains_key(&batch_id),
            "batch id collision: {}",
            batch_id
        );
        let netting_root = netting_root(
            &obligation_ids,
            &asset_ids,
            &oracle_attestation_ids,
            gross_fee_micro_units,
            net_fee_micro_units,
        );
        let settlement_root = deterministic_root(
            "fee-netting-batch-settlement-root",
            &[
                HashPart::Str(&batch_id),
                HashPart::Int(net_fee_micro_units as i128),
                HashPart::Int(sponsored_micro_units as i128),
                HashPart::Int(rebate_micro_units as i128),
            ],
        );
        let batch = BatchFeeClearing {
            batch_id: batch_id.clone(),
            lane_id: lane_id.clone(),
            status: BatchStatus::Netted,
            obligation_ids: obligation_ids.clone(),
            asset_ids,
            oracle_attestation_ids,
            sponsor_pool_ids: sponsor_pool_ids.clone(),
            gross_fee_micro_units,
            net_fee_micro_units,
            sponsored_micro_units,
            rebate_micro_units,
            clearing_fee_micro_units,
            proof_root,
            netting_root,
            settlement_root,
            built_at_height: height,
            expires_at_height: height.saturating_add(self.config.batch_ttl_blocks),
        };
        self.batches.insert(batch_id.clone(), batch);

        for obligation_id in &obligation_ids {
            let obligation = self
                .obligations
                .get_mut(obligation_id)
                .expect("obligation checked before batch insert");
            obligation.status = ObligationStatus::Netted;
            obligation.batch_id = Some(batch_id.clone());
        }
        for pool_id in sponsor_pool_ids {
            if let Some(pool) = self.sponsor_pools.get_mut(&pool_id) {
                let reserve = bps_amount(sponsored_micro_units, pool.reserve_bps);
                let reserved = sponsored_micro_units.saturating_add(reserve);
                ensure!(
                    pool.available_collateral() >= reserved,
                    "sponsor pool undercollateralized at reserve"
                );
                pool.reserved_micro_units = pool.reserved_micro_units.saturating_add(reserved);
                pool.status = SponsorStatus::Settling;
                pool.updated_at_height = height;
            }
        }
        let lane = self
            .fee_lanes
            .get_mut(&lane_id)
            .expect("lane checked before batch insert");
        lane.status = FeeLaneStatus::Clearing;
        lane.netted_count = lane
            .netted_count
            .saturating_add(obligation_ids.len() as u64);
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.obligations_netted = self
            .counters
            .obligations_netted
            .saturating_add(obligation_ids.len() as u64);
        self.current_height = self.current_height.max(height);
        Ok(batch_id)
    }

    pub fn settle_sponsor_pools(&mut self, batch_id: String, height: u64) -> Result<()> {
        self.config.validate()?;
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?
            .clone();
        ensure!(batch.status.can_settle(), "batch cannot settle");
        ensure!(height <= batch.expires_at_height, "batch expired");

        for pool_id in &batch.sponsor_pool_ids {
            let pool = self
                .sponsor_pools
                .get_mut(pool_id)
                .ok_or_else(|| format!("unknown sponsor pool: {pool_id}"))?;
            ensure!(pool.status.usable(), "sponsor pool cannot settle");
            let pool_share = if batch.sponsor_pool_ids.is_empty() {
                0
            } else {
                batch.sponsored_micro_units / batch.sponsor_pool_ids.len() as u128
            };
            ensure!(
                pool.available_collateral()
                    .saturating_add(pool.reserved_micro_units)
                    >= pool_share,
                "sponsor pool cannot cover settlement: {}",
                pool_id
            );
            pool.reserved_micro_units = pool.reserved_micro_units.saturating_sub(pool_share);
            pool.settled_micro_units = pool.settled_micro_units.saturating_add(pool_share);
            pool.status = if pool.available_collateral() == 0 {
                SponsorStatus::Exhausted
            } else {
                SponsorStatus::Active
            };
            pool.updated_at_height = height;
        }

        let batch = self
            .batches
            .get_mut(&batch_id)
            .expect("batch checked before sponsor settlement");
        batch.status = BatchStatus::SettlementReady;
        self.counters.sponsor_pool_settlements =
            self.counters.sponsor_pool_settlements.saturating_add(1);
        self.counters.total_sponsored_micro_units = self
            .counters
            .total_sponsored_micro_units
            .saturating_add(batch.sponsored_micro_units);
        self.current_height = self.current_height.max(height);
        Ok(())
    }

    pub fn issue_rebates_and_receipts(
        &mut self,
        batch_id: String,
        recipient_commitment_root: String,
        height: u64,
    ) -> Result<Vec<String>> {
        self.config.validate()?;
        ensure!(
            !recipient_commitment_root.is_empty(),
            "recipient commitment root cannot be empty"
        );
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?
            .clone();
        ensure!(batch.status.can_settle(), "batch cannot issue receipts");
        ensure!(height <= batch.expires_at_height, "batch expired");
        ensure!(
            self.rebates
                .len()
                .saturating_add(batch.obligation_ids.len())
                <= self.config.max_rebates,
            "rebate capacity exceeded"
        );
        ensure!(
            self.routing_receipts
                .len()
                .saturating_add(batch.obligation_ids.len())
                <= self.config.max_routing_receipts,
            "routing receipt capacity exceeded"
        );

        let mut issued = Vec::with_capacity(batch.obligation_ids.len() * 2);
        for obligation_id in &batch.obligation_ids {
            let obligation = self
                .obligations
                .get(obligation_id)
                .ok_or_else(|| format!("missing obligation: {obligation_id}"))?
                .clone();
            let asset = self
                .assets
                .get(&obligation.asset_id)
                .ok_or_else(|| format!("missing asset: {}", obligation.asset_id))?;
            let rebate_amount = bps_amount(
                obligation.amount_upper_bound_micro_units as u128,
                self.config.rebate_bps.min(asset.fee_discount_bps.max(1)),
            ) as u64;
            let sponsored_amount = if obligation.sponsor_pool_id.is_some() {
                bps_amount(
                    obligation.amount_upper_bound_micro_units as u128,
                    self.config.sponsor_cover_bps,
                ) as u64
            } else {
                0
            };
            let charged = obligation
                .amount_upper_bound_micro_units
                .saturating_sub(sponsored_amount)
                .saturating_sub(rebate_amount);

            let coupon_id = rebate_coupon_id(
                &batch_id,
                obligation_id,
                &recipient_commitment_root,
                height,
                self.counters.rebates_issued,
            );
            let coupon = RebateCoupon {
                coupon_id: coupon_id.clone(),
                status: CouponStatus::Issued,
                batch_id: batch_id.clone(),
                obligation_id: obligation_id.clone(),
                asset_id: obligation.asset_id.clone(),
                sponsor_pool_id: obligation.sponsor_pool_id.clone(),
                recipient_commitment: recipient_commitment_root.clone(),
                coupon_commitment: deterministic_root(
                    "fee-netting-rebate-coupon-commitment",
                    &[
                        HashPart::Str(&coupon_id),
                        HashPart::Str(obligation_id),
                        HashPart::U64(rebate_amount),
                    ],
                ),
                amount_micro_units: rebate_amount,
                issued_at_height: height,
                expires_at_height: height.saturating_add(self.config.rebate_window_blocks),
                redeemed_at_height: None,
            };
            let receipt_id = routing_receipt_id(
                &batch_id,
                obligation_id,
                &obligation.route_commitment,
                height,
                self.counters.routing_receipts_issued,
            );
            let receipt_root = deterministic_root(
                "fee-netting-routing-receipt",
                &[
                    HashPart::Str(&receipt_id),
                    HashPart::Str(&batch_id),
                    HashPart::Str(obligation_id),
                    HashPart::Str(&obligation.route_commitment),
                    HashPart::U64(charged),
                    HashPart::U64(sponsored_amount),
                    HashPart::U64(rebate_amount),
                ],
            );
            let lane = self
                .fee_lanes
                .get(&obligation.lane_id)
                .ok_or_else(|| format!("unknown lane: {}", obligation.lane_id))?;
            let receipt = RoutingReceipt {
                receipt_id: receipt_id.clone(),
                batch_id: batch_id.clone(),
                obligation_id: obligation_id.clone(),
                lane_id: obligation.lane_id.clone(),
                router_commitment: lane.router_commitment.clone(),
                status: ReceiptStatus::Issued,
                route_commitment: obligation.route_commitment.clone(),
                fee_asset_id: obligation.asset_id.clone(),
                charged_micro_units: charged,
                sponsored_micro_units: sponsored_amount,
                rebate_micro_units: rebate_amount,
                receipt_root,
                issued_at_height: height,
                finalizes_at_height: height.saturating_add(self.config.receipt_finality_blocks),
            };
            self.rebates.insert(coupon_id.clone(), coupon);
            self.routing_receipts.insert(receipt_id.clone(), receipt);
            let obligation = self
                .obligations
                .get_mut(obligation_id)
                .expect("obligation checked before coupon insert");
            obligation.status = if sponsored_amount > 0 {
                ObligationStatus::Sponsored
            } else {
                ObligationStatus::Cleared
            };
            obligation.rebate_coupon_id = Some(coupon_id.clone());
            obligation.routing_receipt_id = Some(receipt_id.clone());
            issued.push(coupon_id);
            issued.push(receipt_id);
            self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
            self.counters.routing_receipts_issued =
                self.counters.routing_receipts_issued.saturating_add(1);
            self.counters.total_rebated_micro_units = self
                .counters
                .total_rebated_micro_units
                .saturating_add(rebate_amount as u128);
        }
        let batch = self
            .batches
            .get_mut(&batch_id)
            .expect("batch checked before receipt issue");
        batch.status = BatchStatus::Settled;
        for obligation_id in &batch.obligation_ids {
            if let Some(obligation) = self.obligations.get_mut(obligation_id) {
                obligation.status = ObligationStatus::Settled;
            }
        }
        if let Some(lane) = self.fee_lanes.get_mut(&batch.lane_id) {
            lane.status = FeeLaneStatus::Settled;
            lane.settled_count = lane
                .settled_count
                .saturating_add(batch.obligation_ids.len() as u64);
        }
        self.counters.obligations_settled = self
            .counters
            .obligations_settled
            .saturating_add(batch.obligation_ids.len() as u64);
        self.current_height = self.current_height.max(height);
        Ok(issued)
    }

    pub fn redeem_rebate_coupon(&mut self, coupon_id: String, height: u64) -> Result<()> {
        self.config.validate()?;
        let coupon = self
            .rebates
            .get_mut(&coupon_id)
            .ok_or_else(|| format!("unknown coupon: {coupon_id}"))?;
        ensure!(
            matches!(coupon.status, CouponStatus::Issued | CouponStatus::Reserved),
            "coupon cannot be redeemed"
        );
        ensure!(height <= coupon.expires_at_height, "coupon expired");
        coupon.status = CouponStatus::Redeemed;
        coupon.redeemed_at_height = Some(height);
        self.counters.rebates_redeemed = self.counters.rebates_redeemed.saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(())
    }

    pub fn challenge_undercollateralization(
        &mut self,
        batch_id: String,
        sponsor_pool_id: String,
        challenger_commitment: String,
        alleged_required_collateral_micro_units: u128,
        alleged_available_collateral_micro_units: u128,
        evidence_root: String,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.challenges.len() < self.config.max_challenges,
            "challenge capacity exceeded"
        );
        ensure!(
            !challenger_commitment.is_empty(),
            "challenger commitment cannot be empty"
        );
        ensure!(!evidence_root.is_empty(), "evidence root cannot be empty");
        let batch = self
            .batches
            .get(&batch_id)
            .ok_or_else(|| format!("unknown batch: {batch_id}"))?;
        ensure!(
            batch.sponsor_pool_ids.contains(&sponsor_pool_id),
            "batch does not use sponsor pool"
        );
        let pool = self
            .sponsor_pools
            .get(&sponsor_pool_id)
            .ok_or_else(|| format!("unknown sponsor pool: {sponsor_pool_id}"))?;
        let required = bps_amount(
            alleged_required_collateral_micro_units,
            self.config.undercollateralized_bps,
        );
        ensure!(
            alleged_available_collateral_micro_units < required,
            "challenge is not undercollateralized by threshold"
        );
        ensure!(
            pool.available_collateral() <= alleged_available_collateral_micro_units,
            "challenge overstates pool availability"
        );
        let challenge_id = challenge_id(
            &batch_id,
            &sponsor_pool_id,
            &challenger_commitment,
            &evidence_root,
            height,
            self.counters.undercollateralized_challenges,
        );
        ensure!(
            !self.challenges.contains_key(&challenge_id),
            "challenge id collision: {}",
            challenge_id
        );
        let challenge = UndercollateralizedFeeChallenge {
            challenge_id: challenge_id.clone(),
            batch_id: batch_id.clone(),
            sponsor_pool_id: sponsor_pool_id.clone(),
            challenger_commitment,
            status: ChallengeStatus::Open,
            alleged_required_collateral_micro_units,
            alleged_available_collateral_micro_units,
            evidence_root,
            opened_at_height: height,
            expires_at_height: height.saturating_add(self.config.challenge_ttl_blocks),
            resolved_at_height: None,
        };
        self.challenges.insert(challenge_id.clone(), challenge);
        if let Some(pool) = self.sponsor_pools.get_mut(&sponsor_pool_id) {
            pool.status = SponsorStatus::Challenged;
            pool.updated_at_height = height;
        }
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            batch.status = BatchStatus::Disputed;
        }
        self.counters.undercollateralized_challenges = self
            .counters
            .undercollateralized_challenges
            .saturating_add(1);
        self.current_height = self.current_height.max(height);
        Ok(challenge_id)
    }

    pub fn slash_bad_sponsor_or_router(
        &mut self,
        target: SlashTarget,
        target_id: String,
        related_batch_id: Option<String>,
        related_challenge_id: Option<String>,
        reporter_commitment: String,
        evidence_root: String,
        penalty_micro_units: u128,
        height: u64,
    ) -> Result<String> {
        self.config.validate()?;
        ensure!(
            self.slashes.len() < self.config.max_slashes,
            "slash capacity exceeded"
        );
        ensure!(!target_id.is_empty(), "slash target id cannot be empty");
        ensure!(
            !reporter_commitment.is_empty(),
            "reporter commitment cannot be empty"
        );
        ensure!(!evidence_root.is_empty(), "evidence root cannot be empty");
        ensure!(penalty_micro_units > 0, "penalty must be non-zero");
        if let Some(batch_id) = &related_batch_id {
            ensure!(
                self.batches.contains_key(batch_id),
                "unknown related batch: {}",
                batch_id
            );
        }
        if let Some(challenge_id) = &related_challenge_id {
            let challenge = self
                .challenges
                .get(challenge_id)
                .ok_or_else(|| format!("unknown challenge: {challenge_id}"))?;
            ensure!(
                matches!(
                    challenge.status,
                    ChallengeStatus::Open | ChallengeStatus::Accepted
                ),
                "challenge cannot support slashing"
            );
        }
        match target {
            SlashTarget::SponsorPool => {
                let pool = self
                    .sponsor_pools
                    .get(&target_id)
                    .ok_or_else(|| format!("unknown sponsor pool: {target_id}"))?;
                ensure!(
                    pool.collateral_micro_units >= penalty_micro_units,
                    "penalty exceeds sponsor collateral"
                );
            }
            SlashTarget::Router | SlashTarget::LaneOperator => {
                ensure!(
                    self.fee_lanes
                        .values()
                        .any(|lane| lane.router_commitment == target_id
                            || lane.operator_commitment == target_id
                            || lane.lane_id == target_id),
                    "unknown router or lane operator target"
                );
            }
            SlashTarget::Oracle => {
                ensure!(
                    self.oracle_attestations.contains_key(&target_id),
                    "unknown oracle attestation target"
                );
            }
        }

        let slash_id = slash_id(
            target,
            &target_id,
            related_batch_id.as_deref(),
            related_challenge_id.as_deref(),
            &evidence_root,
            height,
            self.counters.slashes,
        );
        ensure!(
            !self.slashes.contains_key(&slash_id),
            "slash id collision: {}",
            slash_id
        );
        let evidence = SlashingEvidence {
            slash_id: slash_id.clone(),
            target,
            target_id: target_id.clone(),
            related_batch_id: related_batch_id.clone(),
            related_challenge_id: related_challenge_id.clone(),
            reporter_commitment,
            evidence_root,
            penalty_micro_units,
            accepted_at_height: height,
        };
        self.slashes.insert(slash_id.clone(), evidence);
        match target {
            SlashTarget::SponsorPool => {
                if let Some(pool) = self.sponsor_pools.get_mut(&target_id) {
                    pool.status = SponsorStatus::Slashed;
                    pool.slashed_micro_units =
                        pool.slashed_micro_units.saturating_add(penalty_micro_units);
                    pool.updated_at_height = height;
                }
            }
            SlashTarget::Router | SlashTarget::LaneOperator => {
                for lane in self.fee_lanes.values_mut() {
                    if lane.router_commitment == target_id
                        || lane.operator_commitment == target_id
                        || lane.lane_id == target_id
                    {
                        lane.status = FeeLaneStatus::Slashed;
                    }
                }
            }
            SlashTarget::Oracle => {
                if let Some(attestation) = self.oracle_attestations.get_mut(&target_id) {
                    attestation.status = OracleStatus::Slashed;
                }
            }
        }
        if let Some(challenge_id) = related_challenge_id {
            if let Some(challenge) = self.challenges.get_mut(&challenge_id) {
                challenge.status = ChallengeStatus::Slashed;
                challenge.resolved_at_height = Some(height);
            }
        }
        if let Some(batch_id) = related_batch_id {
            if let Some(batch) = self.batches.get_mut(&batch_id) {
                batch.status = BatchStatus::Slashed;
            }
        }
        self.counters.slashes = self.counters.slashes.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(penalty_micro_units);
        self.current_height = self.current_height.max(height);
        Ok(slash_id)
    }

    pub fn roots(&self) -> Roots {
        let assets_root = map_root("multi-asset-fee-netting-assets", &self.assets);
        let fee_lanes_root = map_root("multi-asset-fee-netting-lanes", &self.fee_lanes);
        let obligations_root = map_root("multi-asset-fee-netting-obligations", &self.obligations);
        let oracle_attestations_root = map_root(
            "multi-asset-fee-netting-oracle-attestations",
            &self.oracle_attestations,
        );
        let batches_root = map_root("multi-asset-fee-netting-batches", &self.batches);
        let sponsor_pools_root =
            map_root("multi-asset-fee-netting-sponsor-pools", &self.sponsor_pools);
        let rebates_root = map_root("multi-asset-fee-netting-rebates", &self.rebates);
        let routing_receipts_root = map_root(
            "multi-asset-fee-netting-routing-receipts",
            &self.routing_receipts,
        );
        let privacy_fences_root = map_root(
            "multi-asset-fee-netting-privacy-fences",
            &self.privacy_fences,
        );
        let challenges_root = map_root("multi-asset-fee-netting-challenges", &self.challenges);
        let slashes_root = map_root("multi-asset-fee-netting-slashes", &self.slashes);
        let counters_value = json!(self.counters);
        let config_value = json!(self.config);
        let counters_root = deterministic_root(
            "multi-asset-fee-netting-counters",
            &[HashPart::Json(&counters_value)],
        );
        let config_root = deterministic_root(
            "multi-asset-fee-netting-config",
            &[HashPart::Json(&config_value)],
        );
        let state_root = deterministic_root(
            "multi-asset-fee-netting-state",
            &[
                HashPart::Str(&assets_root),
                HashPart::Str(&fee_lanes_root),
                HashPart::Str(&obligations_root),
                HashPart::Str(&oracle_attestations_root),
                HashPart::Str(&batches_root),
                HashPart::Str(&sponsor_pools_root),
                HashPart::Str(&rebates_root),
                HashPart::Str(&routing_receipts_root),
                HashPart::Str(&privacy_fences_root),
                HashPart::Str(&challenges_root),
                HashPart::Str(&slashes_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&config_root),
                HashPart::U64(self.current_height),
            ],
        );
        Roots {
            assets_root,
            fee_lanes_root,
            obligations_root,
            oracle_attestations_root,
            batches_root,
            sponsor_pools_root,
            rebates_root,
            routing_receipts_root,
            privacy_fences_root,
            challenges_root,
            slashes_root,
            counters_root,
            config_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "hash_suite": self.config.hash_suite,
            "pq_auth_scheme": self.config.pq_auth_scheme,
            "pq_sealing_scheme": self.config.pq_sealing_scheme,
            "fee_netting_protocol": self.config.fee_netting_protocol,
            "devnet_height": DEVNET_HEIGHT,
            "current_height": self.current_height,
            "counters": self.counters,
            "roots": roots,
        })
    }

    pub fn devnet_public_record() -> Value {
        Self::devnet().public_record()
    }
}

impl SponsorPool {
    pub fn available_collateral(&self) -> u128 {
        self.collateral_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.settled_micro_units)
            .saturating_sub(self.slashed_micro_units)
    }
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{FEE_NETTING_PROTOCOL}:{domain}:id"), parts, 24)
}

pub fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{FEE_NETTING_PROTOCOL}:{domain}:root"), parts, 32)
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(&format!("{FEE_NETTING_PROTOCOL}:{domain}"), &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(&format!("{FEE_NETTING_PROTOCOL}:{domain}"), &leaves)
}

fn fee_lane_id(
    lane_kind: FeeLaneKind,
    operator_commitment: &str,
    router_commitment: &str,
    accepted_asset_ids: &BTreeSet<String>,
    height: u64,
    nonce: u64,
) -> String {
    let assets_root = set_root("fee-lane-id-assets", accepted_asset_ids);
    deterministic_id(
        "fee-lane",
        &[
            HashPart::Str(lane_kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(router_commitment),
            HashPart::Str(&assets_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn sponsor_pool_id(
    sponsor_commitment: &str,
    collateral_asset_id: &str,
    liquidity_commitment: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "sponsor-pool",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(collateral_asset_id),
            HashPart::Str(liquidity_commitment),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn obligation_id(
    lane_id: &str,
    asset_id: &str,
    payer_commitment: &str,
    nullifier: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "encrypted-fee-obligation",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(asset_id),
            HashPart::Str(payer_commitment),
            HashPart::Str(nullifier),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn oracle_attestation_id(
    asset_id: &str,
    quote_asset_id: &str,
    rate_commitment: &str,
    observed_at_height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "pq-asset-oracle-attestation",
        &[
            HashPart::Str(asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Str(rate_commitment),
            HashPart::U64(observed_at_height),
            HashPart::U64(nonce),
        ],
    )
}

fn privacy_fence_id(
    lane_id: &str,
    kind: FenceKind,
    nullifier_set_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "privacy-fence",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(nullifier_set_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn batch_id(
    lane_id: &str,
    obligation_ids: &BTreeSet<String>,
    asset_ids: &BTreeSet<String>,
    oracle_attestation_ids: &BTreeSet<String>,
    height: u64,
    nonce: u64,
) -> String {
    let obligations_root = set_root("batch-id-obligations", obligation_ids);
    let assets_root = set_root("batch-id-assets", asset_ids);
    let oracles_root = set_root("batch-id-oracles", oracle_attestation_ids);
    deterministic_id(
        "batch-fee-clearing",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(&obligations_root),
            HashPart::Str(&assets_root),
            HashPart::Str(&oracles_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn netting_root(
    obligation_ids: &BTreeSet<String>,
    asset_ids: &BTreeSet<String>,
    oracle_attestation_ids: &BTreeSet<String>,
    gross_fee_micro_units: u128,
    net_fee_micro_units: u128,
) -> String {
    let obligations_root = set_root("netting-root-obligations", obligation_ids);
    let assets_root = set_root("netting-root-assets", asset_ids);
    let oracles_root = set_root("netting-root-oracles", oracle_attestation_ids);
    deterministic_root(
        "batch-netting",
        &[
            HashPart::Str(&obligations_root),
            HashPart::Str(&assets_root),
            HashPart::Str(&oracles_root),
            HashPart::Int(gross_fee_micro_units as i128),
            HashPart::Int(net_fee_micro_units as i128),
        ],
    )
}

fn rebate_coupon_id(
    batch_id: &str,
    obligation_id: &str,
    recipient_commitment_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "rebate-coupon",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(obligation_id),
            HashPart::Str(recipient_commitment_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn routing_receipt_id(
    batch_id: &str,
    obligation_id: &str,
    route_commitment: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "routing-receipt",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(obligation_id),
            HashPart::Str(route_commitment),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn challenge_id(
    batch_id: &str,
    sponsor_pool_id: &str,
    challenger_commitment: &str,
    evidence_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "undercollateralized-fee-challenge",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(sponsor_pool_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

fn slash_id(
    target: SlashTarget,
    target_id: &str,
    related_batch_id: Option<&str>,
    related_challenge_id: Option<&str>,
    evidence_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_id(
        "slashing-evidence",
        &[
            HashPart::Str(target.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(related_batch_id.unwrap_or("none")),
            HashPart::Str(related_challenge_id.unwrap_or("none")),
            HashPart::Str(evidence_root),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}
