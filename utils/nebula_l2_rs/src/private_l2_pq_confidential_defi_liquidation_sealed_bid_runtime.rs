use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-defi-liquidation-sealed-bid-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_PROTOCOL_VERSION: &str =
    PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_CASE_SCHEME: &str =
    "ml-kem-1024+zk-pq-confidential-liquidation-case-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_ORACLE_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256s-oracle-risk-attestation-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_BID_SCHEME: &str =
    "pq-commitment-sealed-liquidation-bid-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_BACKSTOP_SCHEME: &str =
    "zk-private-backstop-liquidity-pool-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_SETTLEMENT_SCHEME: &str =
    "zk-pq-fast-lane-liquidation-settlement-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_RECURSIVE_PROOF_SCHEME:
    &str = "pq-recursive-proof-liquidation-receipt-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_CHALLENGE_SCHEME: &str =
    "roots-only-private-liquidation-challenge-bond-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_REBATE_SCHEME: &str =
    "roots-only-private-low-fee-liquidation-rebate-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_MEV_GUARD_SCHEME: &str =
    "deterministic-private-liquidation-mev-guard-fence-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_FAST_LANE: &str =
    "devnet-private-l2-pq-liquidation-fast-lane";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_LOW_FEE_LANE:
    &str = "devnet-private-l2-pq-liquidation-low-fee";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEVNET_HEIGHT: u64 =
    1_104_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_CASE_TTL_BLOCKS:
    u64 = 72;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BID_TTL_BLOCKS:
    u64 = 24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_LANE_TTL_BLOCKS:
    u64 = 12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS:
    u64 = 1_440;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BACKSTOP_TTL_BLOCKS:
    u64 = 21_600;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CASES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BIDS: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BACKSTOP_POOLS:
    usize = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_LANES: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CHALLENGES:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_FENCES: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BIDS_PER_CASE:
    usize = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CASES_PER_RECEIPT:
    usize = 128;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 512;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 8_192;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 16;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS:
    u64 = 20;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_BONUS_BPS:
    u64 = 90;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BONUS_BPS:
    u64 = 1_250;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_REBATE_BPS:
    u64 = 24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_SLASH_BPS:
    u64 = 200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_SLASH_BPS:
    u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_FAST_LANE_BUDGET_MICRO_UNITS:
    u64 = 1_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationDomain {
    Lending,
    Perpetuals,
    Options,
    Stablecoin,
    Vaults,
    CrossMargin,
    BridgeReserve,
    Insurance,
}

impl LiquidationDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lending => "lending",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::Stablecoin => "stablecoin",
            Self::Vaults => "vaults",
            Self::CrossMargin => "cross_margin",
            Self::BridgeReserve => "bridge_reserve",
            Self::Insurance => "insurance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationVenue {
    PrivateAmm,
    Darkpool,
    LendingPool,
    PerpEngine,
    VaultRouter,
    StableSwap,
    InternalNetting,
    BridgeReserve,
}

impl LiquidationVenue {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateAmm => "private_amm",
            Self::Darkpool => "darkpool",
            Self::LendingPool => "lending_pool",
            Self::PerpEngine => "perp_engine",
            Self::VaultRouter => "vault_router",
            Self::StableSwap => "stable_swap",
            Self::InternalNetting => "internal_netting",
            Self::BridgeReserve => "bridge_reserve",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Open,
    RiskAttested,
    Bidding,
    BackstopReady,
    LaneReserved,
    SettlementReady,
    Settled,
    Challenged,
    Slashed,
    Expired,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::RiskAttested => "risk_attested",
            Self::Bidding => "bidding",
            Self::BackstopReady => "backstop_ready",
            Self::LaneReserved => "lane_reserved",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn can_attest(self) -> bool {
        matches!(self, Self::Open | Self::RiskAttested | Self::Bidding)
    }

    pub fn can_bid(self) -> bool {
        matches!(
            self,
            Self::Open | Self::RiskAttested | Self::Bidding | Self::BackstopReady
        )
    }

    pub fn can_settle(self) -> bool {
        matches!(
            self,
            Self::RiskAttested | Self::Bidding | Self::BackstopReady | Self::LaneReserved
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskVerdict {
    Healthy,
    Watch,
    ReduceOnly,
    Liquidatable,
    BackstopOnly,
    FreezeAndAuction,
    Halt,
}

impl RiskVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Watch => "watch",
            Self::ReduceOnly => "reduce_only",
            Self::Liquidatable => "liquidatable",
            Self::BackstopOnly => "backstop_only",
            Self::FreezeAndAuction => "freeze_and_auction",
            Self::Halt => "halt",
        }
    }

    pub fn allows_liquidation(self) -> bool {
        matches!(
            self,
            Self::Liquidatable | Self::BackstopOnly | Self::FreezeAndAuction
        )
    }

    pub fn requires_backstop(self) -> bool {
        matches!(self, Self::BackstopOnly | Self::FreezeAndAuction)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleAttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Rejected,
    Expired,
}

impl OracleAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedBidKind {
    FullRepay,
    PartialRepay,
    DutchDiscount,
    BackstopTakeover,
    NettingClose,
    FlashClose,
    InsuranceAbsorb,
}

impl SealedBidKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FullRepay => "full_repay",
            Self::PartialRepay => "partial_repay",
            Self::DutchDiscount => "dutch_discount",
            Self::BackstopTakeover => "backstop_takeover",
            Self::NettingClose => "netting_close",
            Self::FlashClose => "flash_close",
            Self::InsuranceAbsorb => "insurance_absorb",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SealedBidStatus {
    Committed,
    Qualified,
    BackstopMatched,
    Selected,
    Settled,
    Rejected,
    Slashed,
    Expired,
}

impl SealedBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Qualified => "qualified",
            Self::BackstopMatched => "backstop_matched",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Qualified | Self::BackstopMatched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopPoolStatus {
    Proposed,
    Active,
    Saturated,
    Paused,
    Draining,
    Closed,
    Slashed,
    Expired,
}

impl BackstopPoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn available(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FastLaneStatus {
    Reserved,
    Executing,
    ReceiptAttached,
    Finalized,
    Disputed,
    Released,
    Slashed,
    Expired,
}

impl FastLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Executing => "executing",
            Self::ReceiptAttached => "receipt_attached",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecursiveProofStatus {
    Submitted,
    Attached,
    Finalized,
    Disputed,
}

impl RecursiveProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Attached => "attached",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Proven,
    Slashed,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Proven => "proven",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Paid,
    Donated,
    Expired,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Paid => "paid",
            Self::Donated => "donated",
            Self::Expired => "expired",
        }
    }
}

pub trait PublicRecord {
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub monero_network: String,
    pub fast_lane: String,
    pub low_fee_lane: String,
    pub encrypted_case_scheme: String,
    pub oracle_attestation_scheme: String,
    pub sealed_bid_scheme: String,
    pub backstop_pool_scheme: String,
    pub settlement_scheme: String,
    pub recursive_proof_scheme: String,
    pub challenge_scheme: String,
    pub rebate_scheme: String,
    pub mev_guard_scheme: String,
    pub case_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub lane_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub challenge_ttl_blocks: u64,
    pub rebate_epoch_blocks: u64,
    pub backstop_pool_ttl_blocks: u64,
    pub max_cases: usize,
    pub max_attestations: usize,
    pub max_bids: usize,
    pub max_backstop_pools: usize,
    pub max_fast_lanes: usize,
    pub max_receipts: usize,
    pub max_challenges: usize,
    pub max_rebates: usize,
    pub max_mev_fences: usize,
    pub max_bids_per_case: usize,
    pub max_cases_per_receipt: usize,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_keeper_fee_bps: u64,
    pub min_liquidation_bonus_bps: u64,
    pub max_liquidation_bonus_bps: u64,
    pub min_rebate_bps: u64,
    pub max_rebate_bps: u64,
    pub min_slash_bps: u64,
    pub max_slash_bps: u64,
    pub fast_lane_budget_micro_units: u64,
    pub require_oracle_attestations: bool,
    pub require_backstop_for_freeze: bool,
    pub require_recursive_proof_receipts: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_SCHEMA_VERSION,
            hash_suite: PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_HASH_SUITE
                .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MONERO_NETWORK
                    .to_string(),
            fast_lane:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_FAST_LANE
                    .to_string(),
            low_fee_lane:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_LOW_FEE_LANE
                    .to_string(),
            encrypted_case_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_CASE_SCHEME
                    .to_string(),
            oracle_attestation_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_ORACLE_SCHEME
                    .to_string(),
            sealed_bid_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_BID_SCHEME
                    .to_string(),
            backstop_pool_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_BACKSTOP_SCHEME
                    .to_string(),
            settlement_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_SETTLEMENT_SCHEME
                    .to_string(),
            recursive_proof_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_RECURSIVE_PROOF_SCHEME
                    .to_string(),
            challenge_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_CHALLENGE_SCHEME
                    .to_string(),
            rebate_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_REBATE_SCHEME
                    .to_string(),
            mev_guard_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_MEV_GUARD_SCHEME
                    .to_string(),
            case_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_CASE_TTL_BLOCKS,
            attestation_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            bid_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            lane_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_LANE_TTL_BLOCKS,
            settlement_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            challenge_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_CHALLENGE_TTL_BLOCKS,
            rebate_epoch_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_REBATE_EPOCH_BLOCKS,
            backstop_pool_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BACKSTOP_TTL_BLOCKS,
            max_cases:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CASES,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_bids:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BIDS,
            max_backstop_pools:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BACKSTOP_POOLS,
            max_fast_lanes:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_LANES,
            max_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_challenges:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CHALLENGES,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_REBATES,
            max_mev_fences:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_FENCES,
            max_bids_per_case:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BIDS_PER_CASE,
            max_cases_per_receipt:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_CASES_PER_RECEIPT,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_keeper_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_KEEPER_FEE_BPS,
            min_liquidation_bonus_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_BONUS_BPS,
            max_liquidation_bonus_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_BONUS_BPS,
            min_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_REBATE_BPS,
            max_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_REBATE_BPS,
            min_slash_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MIN_SLASH_BPS,
            max_slash_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_MAX_SLASH_BPS,
            fast_lane_budget_micro_units:
                PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEFAULT_FAST_LANE_BUDGET_MICRO_UNITS,
            require_oracle_attestations: true,
            require_backstop_for_freeze: true,
            require_recursive_proof_receipts: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.fast_lane, "fast lane")?;
        ensure_non_empty(&self.low_fee_lane, "low fee lane")?;
        ensure_bps(self.max_user_fee_bps, "max user fee bps")?;
        ensure_bps(self.max_keeper_fee_bps, "max keeper fee bps")?;
        ensure_bps(self.min_liquidation_bonus_bps, "min liquidation bonus bps")?;
        ensure_bps(self.max_liquidation_bonus_bps, "max liquidation bonus bps")?;
        ensure_bps(self.min_rebate_bps, "min rebate bps")?;
        ensure_bps(self.max_rebate_bps, "max rebate bps")?;
        ensure_bps(self.min_slash_bps, "min slash bps")?;
        ensure_bps(self.max_slash_bps, "max slash bps")?;
        if self.min_liquidation_bonus_bps > self.max_liquidation_bonus_bps {
            return Err("min liquidation bonus exceeds max liquidation bonus".to_string());
        }
        if self.min_rebate_bps > self.max_rebate_bps {
            return Err("min rebate exceeds max rebate".to_string());
        }
        if self.min_slash_bps > self.max_slash_bps {
            return Err("min slash exceeds max slash".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set cannot be below minimum privacy set".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "monero_network": self.monero_network,
            "fast_lane": self.fast_lane,
            "low_fee_lane": self.low_fee_lane,
            "encrypted_case_scheme": self.encrypted_case_scheme,
            "oracle_attestation_scheme": self.oracle_attestation_scheme,
            "sealed_bid_scheme": self.sealed_bid_scheme,
            "backstop_pool_scheme": self.backstop_pool_scheme,
            "settlement_scheme": self.settlement_scheme,
            "recursive_proof_scheme": self.recursive_proof_scheme,
            "challenge_scheme": self.challenge_scheme,
            "rebate_scheme": self.rebate_scheme,
            "mev_guard_scheme": self.mev_guard_scheme,
            "case_ttl_blocks": self.case_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "lane_ttl_blocks": self.lane_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "challenge_ttl_blocks": self.challenge_ttl_blocks,
            "rebate_epoch_blocks": self.rebate_epoch_blocks,
            "backstop_pool_ttl_blocks": self.backstop_pool_ttl_blocks,
            "max_cases": self.max_cases,
            "max_attestations": self.max_attestations,
            "max_bids": self.max_bids,
            "max_backstop_pools": self.max_backstop_pools,
            "max_fast_lanes": self.max_fast_lanes,
            "max_receipts": self.max_receipts,
            "max_challenges": self.max_challenges,
            "max_rebates": self.max_rebates,
            "max_mev_fences": self.max_mev_fences,
            "max_bids_per_case": self.max_bids_per_case,
            "max_cases_per_receipt": self.max_cases_per_receipt,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_keeper_fee_bps": self.max_keeper_fee_bps,
            "min_liquidation_bonus_bps": self.min_liquidation_bonus_bps,
            "max_liquidation_bonus_bps": self.max_liquidation_bonus_bps,
            "min_rebate_bps": self.min_rebate_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "min_slash_bps": self.min_slash_bps,
            "max_slash_bps": self.max_slash_bps,
            "fast_lane_budget_micro_units": self.fast_lane_budget_micro_units,
            "require_oracle_attestations": self.require_oracle_attestations,
            "require_backstop_for_freeze": self.require_backstop_for_freeze,
            "require_recursive_proof_receipts": self.require_recursive_proof_receipts
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_case_nonce: u64,
    pub next_attestation_nonce: u64,
    pub next_bid_nonce: u64,
    pub next_backstop_pool_nonce: u64,
    pub next_lane_nonce: u64,
    pub next_receipt_nonce: u64,
    pub next_challenge_nonce: u64,
    pub next_rebate_nonce: u64,
    pub next_fence_nonce: u64,
    pub cases_opened: u64,
    pub oracle_attestations_accepted: u64,
    pub sealed_bids_committed: u64,
    pub backstop_matches: u64,
    pub fast_lanes_reserved: u64,
    pub receipts_published: u64,
    pub challenges_opened: u64,
    pub slashes_executed: u64,
    pub rebates_queued: u64,
    pub mev_fences_opened: u64,
    pub consumed_nullifiers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_case_nonce": self.next_case_nonce,
            "next_attestation_nonce": self.next_attestation_nonce,
            "next_bid_nonce": self.next_bid_nonce,
            "next_backstop_pool_nonce": self.next_backstop_pool_nonce,
            "next_lane_nonce": self.next_lane_nonce,
            "next_receipt_nonce": self.next_receipt_nonce,
            "next_challenge_nonce": self.next_challenge_nonce,
            "next_rebate_nonce": self.next_rebate_nonce,
            "next_fence_nonce": self.next_fence_nonce,
            "cases_opened": self.cases_opened,
            "oracle_attestations_accepted": self.oracle_attestations_accepted,
            "sealed_bids_committed": self.sealed_bids_committed,
            "backstop_matches": self.backstop_matches,
            "fast_lanes_reserved": self.fast_lanes_reserved,
            "receipts_published": self.receipts_published,
            "challenges_opened": self.challenges_opened,
            "slashes_executed": self.slashes_executed,
            "rebates_queued": self.rebates_queued,
            "mev_fences_opened": self.mev_fences_opened,
            "consumed_nullifiers": self.consumed_nullifiers
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenCollateralLeg {
    pub token_id: String,
    pub amount_micro_units: u64,
    pub price_quote_root: String,
    pub haircut_bps: u64,
    pub venue: LiquidationVenue,
    pub unlock_hint_root: String,
}

impl TokenCollateralLeg {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.token_id, "token id")?;
        require_root("price quote root", &self.price_quote_root)?;
        ensure_bps(self.haircut_bps, "haircut bps")?;
        require_root("unlock hint root", &self.unlock_hint_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "token_id": self.token_id,
            "amount_micro_units": self.amount_micro_units,
            "price_quote_root": self.price_quote_root,
            "haircut_bps": self.haircut_bps,
            "venue": self.venue.as_str(),
            "unlock_hint_root": self.unlock_hint_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLiquidationCaseRequest {
    pub account_commitment: String,
    pub domain: LiquidationDomain,
    pub venue: LiquidationVenue,
    pub debtor_note_root: String,
    pub debt_token_id: String,
    pub debt_micro_units: u64,
    pub debt_price_root: String,
    pub collateral_legs: Vec<TokenCollateralLeg>,
    pub case_ciphertext_root: String,
    pub liquidation_policy_root: String,
    pub oracle_snapshot_root: String,
    pub nullifier_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub requested_bonus_bps: u64,
    pub mev_guard_hint_root: String,
    pub metadata_root: String,
}

impl EncryptedLiquidationCaseRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        require_root("account commitment", &self.account_commitment)?;
        require_root("debtor note root", &self.debtor_note_root)?;
        ensure_non_empty(&self.debt_token_id, "debt token id")?;
        require_root("debt price root", &self.debt_price_root)?;
        if self.collateral_legs.is_empty() {
            return Err("at least one collateral leg is required".to_string());
        }
        for leg in &self.collateral_legs {
            leg.validate()?;
        }
        require_root("case ciphertext root", &self.case_ciphertext_root)?;
        require_root("liquidation policy root", &self.liquidation_policy_root)?;
        require_root("oracle snapshot root", &self.oracle_snapshot_root)?;
        require_root("nullifier root", &self.nullifier_root)?;
        require_root("mev guard hint root", &self.mev_guard_hint_root)?;
        require_root("metadata root", &self.metadata_root)?;
        ensure_bps(self.max_user_fee_bps, "max user fee bps")?;
        ensure_bps(self.requested_bonus_bps, "requested bonus bps")?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("max user fee exceeds configured ceiling".to_string());
        }
        if self.requested_bonus_bps < config.min_liquidation_bonus_bps
            || self.requested_bonus_bps > config.max_liquidation_bonus_bps
        {
            return Err("requested bonus outside configured liquidation range".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("case privacy set below configured minimum".to_string());
        }
        if self.expires_at_height > 0 && self.expires_at_height <= self.opened_at_height {
            return Err("case expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "account_commitment": self.account_commitment,
            "domain": self.domain.as_str(),
            "venue": self.venue.as_str(),
            "debtor_note_root": self.debtor_note_root,
            "debt_token_id": self.debt_token_id,
            "debt_micro_units": self.debt_micro_units,
            "debt_price_root": self.debt_price_root,
            "collateral_legs": self.collateral_legs.iter().map(TokenCollateralLeg::public_record).collect::<Vec<_>>(),
            "case_ciphertext_root": self.case_ciphertext_root,
            "liquidation_policy_root": self.liquidation_policy_root,
            "oracle_snapshot_root": self.oracle_snapshot_root,
            "nullifier_root": self.nullifier_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "requested_bonus_bps": self.requested_bonus_bps,
            "mev_guard_hint_root": self.mev_guard_hint_root,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedLiquidationCaseRecord {
    pub case_id: String,
    pub request: EncryptedLiquidationCaseRequest,
    pub status: CaseStatus,
    pub attestation_ids: BTreeSet<String>,
    pub bid_ids: BTreeSet<String>,
    pub backstop_pool_ids: BTreeSet<String>,
    pub lane_id: Option<String>,
    pub recursive_receipt_id: Option<String>,
    pub challenge_ids: BTreeSet<String>,
    pub latest_risk_root: String,
    pub collateral_root: String,
}

impl PublicRecord for EncryptedLiquidationCaseRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_liquidation_case",
            "case_id": self.case_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "attestation_ids": self.attestation_ids.iter().cloned().collect::<Vec<_>>(),
            "bid_ids": self.bid_ids.iter().cloned().collect::<Vec<_>>(),
            "backstop_pool_ids": self.backstop_pool_ids.iter().cloned().collect::<Vec<_>>(),
            "lane_id": self.lane_id,
            "recursive_receipt_id": self.recursive_receipt_id,
            "challenge_ids": self.challenge_ids.iter().cloned().collect::<Vec<_>>(),
            "latest_risk_root": self.latest_risk_root,
            "collateral_root": self.collateral_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRiskAttestationRequest {
    pub case_id: String,
    pub committee_commitment: String,
    pub verdict: RiskVerdict,
    pub attestation_root: String,
    pub oracle_window_root: String,
    pub risk_model_root: String,
    pub debt_repricing_root: String,
    pub collateral_repricing_root: String,
    pub minimum_recovery_bps: u64,
    pub required_backstop_micro_units: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl OracleRiskAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty(&self.case_id, "case id")?;
        require_root("committee commitment", &self.committee_commitment)?;
        require_root("attestation root", &self.attestation_root)?;
        require_root("oracle window root", &self.oracle_window_root)?;
        require_root("risk model root", &self.risk_model_root)?;
        require_root("debt repricing root", &self.debt_repricing_root)?;
        require_root("collateral repricing root", &self.collateral_repricing_root)?;
        ensure_bps(self.minimum_recovery_bps, "minimum recovery bps")?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq security bits below configured minimum".to_string());
        }
        if self.expires_at_height > 0 && self.expires_at_height <= self.attested_at_height {
            return Err("attestation expiry must be after submit height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "committee_commitment": self.committee_commitment,
            "verdict": self.verdict.as_str(),
            "attestation_root": self.attestation_root,
            "oracle_window_root": self.oracle_window_root,
            "risk_model_root": self.risk_model_root,
            "debt_repricing_root": self.debt_repricing_root,
            "collateral_repricing_root": self.collateral_repricing_root,
            "minimum_recovery_bps": self.minimum_recovery_bps,
            "required_backstop_micro_units": self.required_backstop_micro_units,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleRiskAttestationRecord {
    pub attestation_id: String,
    pub request: OracleRiskAttestationRequest,
    pub status: OracleAttestationStatus,
    pub accepted_at_height: Option<u64>,
}

impl PublicRecord for OracleRiskAttestationRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "oracle_risk_attestation",
            "attestation_id": self.attestation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBidRequest {
    pub case_id: String,
    pub bidder_commitment: String,
    pub bid_kind: SealedBidKind,
    pub sealed_commitment_root: String,
    pub execution_hint_root: String,
    pub funding_commitment_root: String,
    pub requested_repay_micro_units: u64,
    pub expected_recovery_bps: u64,
    pub keeper_fee_bps: u64,
    pub user_fee_bps: u64,
    pub bonus_bps: u64,
    pub bond_micro_units: u64,
    pub allow_backstop_match: bool,
    pub privacy_set_size: u64,
    pub committed_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedBidRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty(&self.case_id, "case id")?;
        require_root("bidder commitment", &self.bidder_commitment)?;
        require_root("sealed commitment root", &self.sealed_commitment_root)?;
        require_root("execution hint root", &self.execution_hint_root)?;
        require_root("funding commitment root", &self.funding_commitment_root)?;
        ensure_bps(self.expected_recovery_bps, "expected recovery bps")?;
        ensure_bps(self.keeper_fee_bps, "keeper fee bps")?;
        ensure_bps(self.user_fee_bps, "user fee bps")?;
        ensure_bps(self.bonus_bps, "bonus bps")?;
        if self.user_fee_bps > config.max_user_fee_bps {
            return Err("user fee bps exceeds configured ceiling".to_string());
        }
        if self.keeper_fee_bps > config.max_keeper_fee_bps {
            return Err("keeper fee bps exceeds configured ceiling".to_string());
        }
        if self.bonus_bps < config.min_liquidation_bonus_bps
            || self.bonus_bps > config.max_liquidation_bonus_bps
        {
            return Err("bonus bps outside configured liquidation range".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("sealed bid privacy set below configured minimum".to_string());
        }
        if self.expires_at_height > 0 && self.expires_at_height <= self.committed_at_height {
            return Err("sealed bid expiry must be after commit height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "bidder_commitment": self.bidder_commitment,
            "bid_kind": self.bid_kind.as_str(),
            "sealed_commitment_root": self.sealed_commitment_root,
            "execution_hint_root": self.execution_hint_root,
            "funding_commitment_root": self.funding_commitment_root,
            "requested_repay_micro_units": self.requested_repay_micro_units,
            "expected_recovery_bps": self.expected_recovery_bps,
            "keeper_fee_bps": self.keeper_fee_bps,
            "user_fee_bps": self.user_fee_bps,
            "bonus_bps": self.bonus_bps,
            "bond_micro_units": self.bond_micro_units,
            "allow_backstop_match": self.allow_backstop_match,
            "privacy_set_size": self.privacy_set_size,
            "committed_at_height": self.committed_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBidRecord {
    pub bid_id: String,
    pub request: SealedBidRequest,
    pub status: SealedBidStatus,
    pub score: u64,
    pub backstop_pool_id: Option<String>,
    pub lane_id: Option<String>,
    pub recursive_receipt_id: Option<String>,
}

impl PublicRecord for SealedBidRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "sealed_bid",
            "bid_id": self.bid_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "score": self.score,
            "backstop_pool_id": self.backstop_pool_id,
            "lane_id": self.lane_id,
            "recursive_receipt_id": self.recursive_receipt_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateBackstopPool {
    pub pool_id: String,
    pub label: String,
    pub venue: LiquidationVenue,
    pub status: BackstopPoolStatus,
    pub operator_commitment: String,
    pub liquidity_commitment: String,
    pub risk_scope_root: String,
    pub liquidity_budget_micro_units: u64,
    pub max_case_notional_micro_units: u64,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub metadata_root: String,
}

impl PublicRecord for PrivateBackstopPool {
    fn public_record(&self) -> Value {
        json!({
            "kind": "private_backstop_pool",
            "pool_id": self.pool_id,
            "label": self.label,
            "venue": self.venue.as_str(),
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "liquidity_commitment": self.liquidity_commitment,
            "risk_scope_root": self.risk_scope_root,
            "liquidity_budget_micro_units": self.liquidity_budget_micro_units,
            "max_case_notional_micro_units": self.max_case_notional_micro_units,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastSettlementLaneRequest {
    pub case_ids: Vec<String>,
    pub selected_bid_id: String,
    pub backstop_pool_id: Option<String>,
    pub lane_ciphertext_root: String,
    pub mev_guard_root: String,
    pub token_accounting_root: String,
    pub settlement_plan_root: String,
    pub lane_budget_micro_units: u64,
    pub keeper_fee_micro_units: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl FastSettlementLaneRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.case_ids.is_empty() {
            return Err("at least one case id is required".to_string());
        }
        if self.case_ids.len() > config.max_cases_per_receipt {
            return Err("too many cases referenced by settlement lane".to_string());
        }
        ensure_non_empty(&self.selected_bid_id, "selected bid id")?;
        if let Some(pool_id) = &self.backstop_pool_id {
            ensure_non_empty(pool_id, "backstop pool id")?;
        }
        require_root("lane ciphertext root", &self.lane_ciphertext_root)?;
        require_root("mev guard root", &self.mev_guard_root)?;
        require_root("token accounting root", &self.token_accounting_root)?;
        require_root("settlement plan root", &self.settlement_plan_root)?;
        if self.lane_budget_micro_units > config.fast_lane_budget_micro_units {
            return Err("lane budget exceeds configured fast-lane budget".to_string());
        }
        if self.expires_at_height > 0 && self.expires_at_height <= self.reserved_at_height {
            return Err("lane expiry must be after reserve height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_ids": self.case_ids,
            "selected_bid_id": self.selected_bid_id,
            "backstop_pool_id": self.backstop_pool_id,
            "lane_ciphertext_root": self.lane_ciphertext_root,
            "mev_guard_root": self.mev_guard_root,
            "token_accounting_root": self.token_accounting_root,
            "settlement_plan_root": self.settlement_plan_root,
            "lane_budget_micro_units": self.lane_budget_micro_units,
            "keeper_fee_micro_units": self.keeper_fee_micro_units,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FastSettlementLaneRecord {
    pub lane_id: String,
    pub request: FastSettlementLaneRequest,
    pub status: FastLaneStatus,
    pub recursive_receipt_id: Option<String>,
}

impl PublicRecord for FastSettlementLaneRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "fast_settlement_lane",
            "lane_id": self.lane_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "recursive_receipt_id": self.recursive_receipt_id
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofReceiptRequest {
    pub lane_id: String,
    pub case_ids: Vec<String>,
    pub selected_bid_id: String,
    pub proof_root: String,
    pub aggregate_public_inputs_root: String,
    pub token_delta_root: String,
    pub nullifier_spend_root: String,
    pub fee_rebate_root: String,
    pub settled_at_height: u64,
    pub finalized_at_height: Option<u64>,
}

impl RecursiveProofReceiptRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.lane_id, "lane id")?;
        if self.case_ids.is_empty() {
            return Err("receipt must reference at least one case".to_string());
        }
        ensure_non_empty(&self.selected_bid_id, "selected bid id")?;
        require_root("proof root", &self.proof_root)?;
        require_root(
            "aggregate public inputs root",
            &self.aggregate_public_inputs_root,
        )?;
        require_root("token delta root", &self.token_delta_root)?;
        require_root("nullifier spend root", &self.nullifier_spend_root)?;
        require_root("fee rebate root", &self.fee_rebate_root)?;
        if let Some(finalized_at_height) = self.finalized_at_height {
            if finalized_at_height < self.settled_at_height {
                return Err("receipt finalization height cannot precede settlement".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "case_ids": self.case_ids,
            "selected_bid_id": self.selected_bid_id,
            "proof_root": self.proof_root,
            "aggregate_public_inputs_root": self.aggregate_public_inputs_root,
            "token_delta_root": self.token_delta_root,
            "nullifier_spend_root": self.nullifier_spend_root,
            "fee_rebate_root": self.fee_rebate_root,
            "settled_at_height": self.settled_at_height,
            "finalized_at_height": self.finalized_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveProofReceiptRecord {
    pub receipt_id: String,
    pub request: RecursiveProofReceiptRequest,
    pub status: RecursiveProofStatus,
}

impl PublicRecord for RecursiveProofReceiptRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "recursive_proof_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeBondRequest {
    pub case_id: String,
    pub lane_id: Option<String>,
    pub receipt_id: Option<String>,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub bond_micro_units: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ChallengeBondRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty(&self.case_id, "case id")?;
        if let Some(lane_id) = &self.lane_id {
            ensure_non_empty(lane_id, "lane id")?;
        }
        if let Some(receipt_id) = &self.receipt_id {
            ensure_non_empty(receipt_id, "receipt id")?;
        }
        require_root("challenger commitment", &self.challenger_commitment)?;
        require_root("evidence root", &self.evidence_root)?;
        ensure_bps(self.slash_bps, "slash bps")?;
        if self.slash_bps < config.min_slash_bps || self.slash_bps > config.max_slash_bps {
            return Err("slash bps outside configured range".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("challenge expiry must be after open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "lane_id": self.lane_id,
            "receipt_id": self.receipt_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "slash_bps": self.slash_bps,
            "bond_micro_units": self.bond_micro_units,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeBondRecord {
    pub challenge_id: String,
    pub request: ChallengeBondRequest,
    pub status: ChallengeStatus,
    pub slashed_subject_id: Option<String>,
    pub resolved_at_height: Option<u64>,
}

impl PublicRecord for ChallengeBondRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_bond",
            "challenge_id": self.challenge_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "slashed_subject_id": self.slashed_subject_id,
            "resolved_at_height": self.resolved_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub lane_id: String,
    pub receipt_id: String,
    pub beneficiary_commitment: String,
    pub rebate_root: String,
    pub rebate_bps: u64,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
    pub status: RebateStatus,
}

impl PublicRecord for FeeRebateRecord {
    fn public_record(&self) -> Value {
        json!({
            "kind": "fee_rebate",
            "rebate_id": self.rebate_id,
            "lane_id": self.lane_id,
            "receipt_id": self.receipt_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "rebate_root": self.rebate_root,
            "rebate_bps": self.rebate_bps,
            "queued_at_height": self.queued_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MevGuardFence {
    pub fence_id: String,
    pub subject_id: String,
    pub scope: String,
    pub viewer_set_root: String,
    pub ordering_root: String,
    pub nullifier_root: String,
    pub disclosure_policy_root: String,
    pub min_delay_blocks: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PublicRecord for MevGuardFence {
    fn public_record(&self) -> Value {
        json!({
            "kind": "mev_guard_fence",
            "fence_id": self.fence_id,
            "subject_id": self.subject_id,
            "scope": self.scope,
            "viewer_set_root": self.viewer_set_root,
            "ordering_root": self.ordering_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "min_delay_blocks": self.min_delay_blocks,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub case_root: String,
    pub attestation_root: String,
    pub bid_root: String,
    pub backstop_pool_root: String,
    pub lane_root: String,
    pub receipt_root: String,
    pub challenge_root: String,
    pub rebate_root: String,
    pub mev_fence_root: String,
    pub active_case_root: String,
    pub settlement_ready_root: String,
    pub consumed_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "case_root": self.case_root,
            "attestation_root": self.attestation_root,
            "bid_root": self.bid_root,
            "backstop_pool_root": self.backstop_pool_root,
            "lane_root": self.lane_root,
            "receipt_root": self.receipt_root,
            "challenge_root": self.challenge_root,
            "rebate_root": self.rebate_root,
            "mev_fence_root": self.mev_fence_root,
            "active_case_root": self.active_case_root,
            "settlement_ready_root": self.settlement_ready_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_height: u64,
    pub runtime_root: String,
    pub fast_lane_budget_remaining_micro_units: u64,
    pub cases: BTreeMap<String, EncryptedLiquidationCaseRecord>,
    pub oracle_attestations: BTreeMap<String, OracleRiskAttestationRecord>,
    pub sealed_bids: BTreeMap<String, SealedBidRecord>,
    pub private_backstop_pools: BTreeMap<String, PrivateBackstopPool>,
    pub fast_lanes: BTreeMap<String, FastSettlementLaneRecord>,
    pub recursive_receipts: BTreeMap<String, RecursiveProofReceiptRecord>,
    pub challenges: BTreeMap<String, ChallengeBondRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub mev_fences: BTreeMap<String, MevGuardFence>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub active_case_ids: BTreeSet<String>,
    pub settlement_ready_case_ids: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            fast_lane_budget_remaining_micro_units: config.fast_lane_budget_micro_units,
            runtime_root: payload_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-SEALED-BID-GENESIS",
                &json!({ "chain_id": CHAIN_ID, "current_height": current_height }),
            ),
            config,
            counters: Counters::default(),
            current_height,
            cases: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            sealed_bids: BTreeMap::new(),
            private_backstop_pools: BTreeMap::new(),
            fast_lanes: BTreeMap::new(),
            recursive_receipts: BTreeMap::new(),
            challenges: BTreeMap::new(),
            rebates: BTreeMap::new(),
            mev_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            active_case_ids: BTreeSet::new(),
            settlement_ready_case_ids: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_DEVNET_HEIGHT,
        )?;

        let pool_id = state.register_backstop_pool(
            "devnet-xmr-liquidity-backstop",
            LiquidationVenue::LendingPool,
            "operator-devnet-alpha",
            2_800_000_000,
            14,
            12,
            state.config.batch_privacy_set_size,
            json!({"domain":"lending","asset":"pxmr","tier":"senior"}),
        )?;

        let case_id = state.open_encrypted_liquidation_case(EncryptedLiquidationCaseRequest {
            account_commitment: commitment_root("account", "devnet-account-alpha"),
            domain: LiquidationDomain::Lending,
            venue: LiquidationVenue::LendingPool,
            debtor_note_root: commitment_root("debtor-note", "devnet-debtor-alpha"),
            debt_token_id: "pxmr".to_string(),
            debt_micro_units: 980_000_000,
            debt_price_root: commitment_root("debt-price", "devnet-pxmr-usd"),
            collateral_legs: vec![
                TokenCollateralLeg {
                    token_id: "pxmr".to_string(),
                    amount_micro_units: 1_240_000_000,
                    price_quote_root: commitment_root("collateral-price", "devnet-pxmr-usd"),
                    haircut_bps: 650,
                    venue: LiquidationVenue::PrivateAmm,
                    unlock_hint_root: commitment_root("unlock", "devnet-leg-one"),
                },
                TokenCollateralLeg {
                    token_id: "pxmr-lst".to_string(),
                    amount_micro_units: 330_000_000,
                    price_quote_root: commitment_root("collateral-price", "devnet-pxmr-lst"),
                    haircut_bps: 900,
                    venue: LiquidationVenue::VaultRouter,
                    unlock_hint_root: commitment_root("unlock", "devnet-leg-two"),
                },
            ],
            case_ciphertext_root: commitment_root("case", "devnet-case-alpha"),
            liquidation_policy_root: commitment_root("policy", "devnet-policy-alpha"),
            oracle_snapshot_root: commitment_root("oracle-snapshot", "devnet-oracle-alpha"),
            nullifier_root: commitment_root("nullifier", "devnet-nullifier-alpha"),
            opened_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.case_ttl_blocks,
            privacy_set_size: state.config.batch_privacy_set_size,
            max_user_fee_bps: 12,
            requested_bonus_bps: 180,
            mev_guard_hint_root: commitment_root("mev-guard", "devnet-mev-alpha"),
            metadata_root: commitment_root("metadata", "devnet-metadata-alpha"),
        })?;

        state.submit_oracle_risk_attestation(OracleRiskAttestationRequest {
            case_id: case_id.clone(),
            committee_commitment: commitment_root("committee", "devnet-risk-committee"),
            verdict: RiskVerdict::Liquidatable,
            attestation_root: commitment_root("attestation", "devnet-attestation-alpha"),
            oracle_window_root: commitment_root("oracle-window", "12-block"),
            risk_model_root: commitment_root("risk-model", "devnet-risk-model"),
            debt_repricing_root: commitment_root("debt-repricing", "devnet-debt-repricing"),
            collateral_repricing_root: commitment_root(
                "collateral-repricing",
                "devnet-collateral-repricing",
            ),
            minimum_recovery_bps: 9_300,
            required_backstop_micro_units: 0,
            pq_security_bits: state.config.min_pq_security_bits,
            attested_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.attestation_ttl_blocks,
        })?;

        let bid_id = state.commit_sealed_bid(SealedBidRequest {
            case_id: case_id.clone(),
            bidder_commitment: commitment_root("bidder", "devnet-bidder-alpha"),
            bid_kind: SealedBidKind::FullRepay,
            sealed_commitment_root: commitment_root("sealed-bid", "devnet-sealed-bid-alpha"),
            execution_hint_root: commitment_root("execution-hint", "devnet-exec-alpha"),
            funding_commitment_root: commitment_root("funding", "devnet-funding-alpha"),
            requested_repay_micro_units: 980_000_000,
            expected_recovery_bps: 9_450,
            keeper_fee_bps: 11,
            user_fee_bps: 10,
            bonus_bps: 175,
            bond_micro_units: 38_000_000,
            allow_backstop_match: true,
            privacy_set_size: state.config.batch_privacy_set_size,
            committed_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.bid_ttl_blocks,
        })?;

        let lane_id = state.reserve_fast_settlement_lane(FastSettlementLaneRequest {
            case_ids: vec![case_id.clone()],
            selected_bid_id: bid_id.clone(),
            backstop_pool_id: Some(pool_id.clone()),
            lane_ciphertext_root: commitment_root("lane", "devnet-lane-alpha"),
            mev_guard_root: commitment_root("mev-root", "devnet-mev-root-alpha"),
            token_accounting_root: commitment_root("token-accounting", "devnet-token-acct-alpha"),
            settlement_plan_root: commitment_root("settlement-plan", "devnet-plan-alpha"),
            lane_budget_micro_units: 9_800_000,
            keeper_fee_micro_units: 760_000,
            reserved_at_height: state.current_height,
            expires_at_height: state.current_height + state.config.lane_ttl_blocks,
        })?;

        let receipt_id = state.attach_recursive_proof_receipt(RecursiveProofReceiptRequest {
            lane_id: lane_id.clone(),
            case_ids: vec![case_id.clone()],
            selected_bid_id: bid_id.clone(),
            proof_root: commitment_root("proof", "devnet-proof-alpha"),
            aggregate_public_inputs_root: commitment_root("inputs", "devnet-inputs-alpha"),
            token_delta_root: commitment_root("token-delta", "devnet-token-delta-alpha"),
            nullifier_spend_root: commitment_root("spend", "devnet-spend-alpha"),
            fee_rebate_root: commitment_root("rebate-root", "devnet-rebate-root-alpha"),
            settled_at_height: state.current_height,
            finalized_at_height: Some(state.current_height + 1),
        })?;

        state.queue_fee_rebate(
            &lane_id,
            &receipt_id,
            &commitment_root("beneficiary", "devnet-beneficiary-alpha"),
            &commitment_root("rebate", "devnet-rebate-alpha"),
            12,
        )?;

        state.open_mev_guard_fence(
            &lane_id,
            "settlement-view",
            &commitment_root("viewers", "devnet-viewers-alpha"),
            &commitment_root("ordering", "devnet-ordering-alpha"),
            &commitment_root("fence-nullifier", "devnet-fence-nullifier-alpha"),
            &commitment_root("policy", "devnet-disclosure-policy-alpha"),
            4,
        )?;

        Ok(state)
    }

    pub fn open_encrypted_liquidation_case(
        &mut self,
        mut request: EncryptedLiquidationCaseRequest,
    ) -> Result<String> {
        self.ensure_capacity(self.cases.len(), self.config.max_cases, "cases")?;
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .opened_at_height
                .saturating_add(self.config.case_ttl_blocks);
        }
        request.validate(&self.config)?;
        self.current_height = self.current_height.max(request.opened_at_height);
        self.consume_nullifier(&request.nullifier_root)?;
        let case_id = deterministic_id(
            "encrypted-liquidation-case",
            self.counters.next_case_nonce,
            &[
                request.domain.as_str(),
                request.venue.as_str(),
                &request.account_commitment,
            ],
        );
        let collateral_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-COLLATERAL",
            request
                .collateral_legs
                .iter()
                .map(TokenCollateralLeg::public_record)
                .collect(),
        );
        let case = EncryptedLiquidationCaseRecord {
            case_id: case_id.clone(),
            request,
            status: CaseStatus::Open,
            attestation_ids: BTreeSet::new(),
            bid_ids: BTreeSet::new(),
            backstop_pool_ids: BTreeSet::new(),
            lane_id: None,
            recursive_receipt_id: None,
            challenge_ids: BTreeSet::new(),
            latest_risk_root: payload_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-EMPTY-RISK",
                &json!({"case_id": case_id}),
            ),
            collateral_root,
        };
        self.counters.next_case_nonce = self.counters.next_case_nonce.saturating_add(1);
        self.counters.cases_opened = self.counters.cases_opened.saturating_add(1);
        self.active_case_ids.insert(case.case_id.clone());
        self.publish_public_record("case_opened", &case.case_id, case.public_record());
        self.cases.insert(case.case_id.clone(), case);
        Ok(case_id)
    }

    pub fn submit_oracle_risk_attestation(
        &mut self,
        mut request: OracleRiskAttestationRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.oracle_attestations.len(),
            self.config.max_attestations,
            "oracle attestations",
        )?;
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .attested_at_height
                .saturating_add(self.config.attestation_ttl_blocks);
        }
        request.validate(&self.config)?;
        let case = self
            .cases
            .get_mut(&request.case_id)
            .ok_or_else(|| "case not found for oracle attestation".to_string())?;
        if !case.status.can_attest() {
            return Err("case no longer accepts oracle attestations".to_string());
        }
        let attestation_id = deterministic_id(
            "oracle-risk-attestation",
            self.counters.next_attestation_nonce,
            &[&request.case_id, request.verdict.as_str()],
        );
        let status = if request.verdict.allows_liquidation() {
            OracleAttestationStatus::Accepted
        } else {
            OracleAttestationStatus::Submitted
        };
        let accepted_at_height = if status == OracleAttestationStatus::Accepted {
            Some(request.attested_at_height)
        } else {
            None
        };
        case.attestation_ids.insert(attestation_id.clone());
        case.latest_risk_root = payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-LATEST-RISK",
            &json!({
                "case_id": request.case_id,
                "attestation_id": attestation_id,
                "verdict": request.verdict.as_str(),
                "required_backstop_micro_units": request.required_backstop_micro_units,
            }),
        );
        case.status = if request.verdict.requires_backstop() {
            CaseStatus::BackstopReady
        } else if request.verdict.allows_liquidation() {
            CaseStatus::RiskAttested
        } else {
            case.status
        };
        if request.verdict.allows_liquidation() {
            self.settlement_ready_case_ids.insert(case.case_id.clone());
        }
        let record = OracleRiskAttestationRecord {
            attestation_id: attestation_id.clone(),
            request,
            status,
            accepted_at_height,
        };
        self.counters.next_attestation_nonce =
            self.counters.next_attestation_nonce.saturating_add(1);
        if record.status == OracleAttestationStatus::Accepted {
            self.counters.oracle_attestations_accepted =
                self.counters.oracle_attestations_accepted.saturating_add(1);
        }
        self.publish_public_record("oracle_attested", &attestation_id, record.public_record());
        self.oracle_attestations
            .insert(attestation_id.clone(), record);
        Ok(attestation_id)
    }

    pub fn commit_sealed_bid(&mut self, mut request: SealedBidRequest) -> Result<String> {
        self.ensure_capacity(self.sealed_bids.len(), self.config.max_bids, "sealed bids")?;
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .committed_at_height
                .saturating_add(self.config.bid_ttl_blocks);
        }
        request.validate(&self.config)?;
        let (case_status, case_bid_len, case_venue) = {
            let case = self
                .cases
                .get(&request.case_id)
                .ok_or_else(|| "case not found for sealed bid".to_string())?;
            (case.status, case.bid_ids.len(), case.request.venue)
        };
        if !case_status.can_bid() {
            return Err("case no longer accepts sealed bids".to_string());
        }
        if case_bid_len >= self.config.max_bids_per_case {
            return Err("sealed bid capacity reached for case".to_string());
        }
        let bid_id = deterministic_id(
            "sealed-bid",
            self.counters.next_bid_nonce,
            &[
                &request.case_id,
                request.bid_kind.as_str(),
                &request.bidder_commitment,
            ],
        );
        let score = bid_score(&request);
        let mut record = SealedBidRecord {
            bid_id: bid_id.clone(),
            request,
            status: SealedBidStatus::Committed,
            score,
            backstop_pool_id: None,
            lane_id: None,
            recursive_receipt_id: None,
        };
        if case_status == CaseStatus::BackstopReady && record.request.allow_backstop_match {
            if let Some(pool_id) = self.best_backstop_pool(case_venue, record.request.bonus_bps) {
                record.status = SealedBidStatus::BackstopMatched;
                record.backstop_pool_id = Some(pool_id.clone());
                self.counters.backstop_matches = self.counters.backstop_matches.saturating_add(1);
                let case = self
                    .cases
                    .get_mut(&record.request.case_id)
                    .ok_or_else(|| "case not found for backstop match".to_string())?;
                case.backstop_pool_ids.insert(pool_id);
            }
        } else {
            record.status = SealedBidStatus::Qualified;
        }
        let case = self
            .cases
            .get_mut(&record.request.case_id)
            .ok_or_else(|| "case not found for sealed bid insertion".to_string())?;
        case.bid_ids.insert(bid_id.clone());
        case.status = CaseStatus::Bidding;
        self.counters.next_bid_nonce = self.counters.next_bid_nonce.saturating_add(1);
        self.counters.sealed_bids_committed = self.counters.sealed_bids_committed.saturating_add(1);
        self.publish_public_record("sealed_bid_committed", &bid_id, record.public_record());
        self.sealed_bids.insert(bid_id.clone(), record);
        Ok(bid_id)
    }

    pub fn register_backstop_pool(
        &mut self,
        label: &str,
        venue: LiquidationVenue,
        operator_label: &str,
        liquidity_budget_micro_units: u64,
        fee_bps: u64,
        rebate_bps: u64,
        privacy_set_size: u64,
        metadata: Value,
    ) -> Result<String> {
        self.ensure_capacity(
            self.private_backstop_pools.len(),
            self.config.max_backstop_pools,
            "private backstop pools",
        )?;
        ensure_non_empty(label, "backstop pool label")?;
        ensure_non_empty(operator_label, "backstop operator label")?;
        ensure_bps(fee_bps, "backstop fee bps")?;
        ensure_bps(rebate_bps, "backstop rebate bps")?;
        if fee_bps > self.config.max_keeper_fee_bps {
            return Err("backstop fee exceeds configured ceiling".to_string());
        }
        if rebate_bps < self.config.min_rebate_bps || rebate_bps > self.config.max_rebate_bps {
            return Err("backstop rebate outside configured range".to_string());
        }
        self.ensure_privacy_set(privacy_set_size, "backstop pool privacy set")?;
        let pool_id = deterministic_id(
            "private-backstop-pool",
            self.counters.next_backstop_pool_nonce,
            &[label, venue.as_str(), operator_label],
        );
        let pool = PrivateBackstopPool {
            pool_id: pool_id.clone(),
            label: label.to_string(),
            venue,
            status: BackstopPoolStatus::Active,
            operator_commitment: commitment_root("backstop-operator", operator_label),
            liquidity_commitment: payload_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-BACKSTOP-LIQUIDITY",
                &json!({ "liquidity_budget_micro_units": liquidity_budget_micro_units }),
            ),
            risk_scope_root: roots_only_payload("backstop-risk-scope", &pool_id, &metadata),
            liquidity_budget_micro_units,
            max_case_notional_micro_units: liquidity_budget_micro_units / 3,
            fee_bps,
            rebate_bps,
            privacy_set_size,
            pq_security_bits: self.config.min_pq_security_bits,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.backstop_pool_ttl_blocks,
            metadata_root: roots_only_payload("backstop-metadata", &pool_id, &metadata),
        };
        self.counters.next_backstop_pool_nonce =
            self.counters.next_backstop_pool_nonce.saturating_add(1);
        self.publish_public_record("backstop_pool_registered", &pool_id, pool.public_record());
        self.private_backstop_pools.insert(pool_id.clone(), pool);
        Ok(pool_id)
    }

    pub fn reserve_fast_settlement_lane(
        &mut self,
        mut request: FastSettlementLaneRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.fast_lanes.len(),
            self.config.max_fast_lanes,
            "fast settlement lanes",
        )?;
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .reserved_at_height
                .saturating_add(self.config.lane_ttl_blocks);
        }
        request.validate(&self.config)?;
        if request.lane_budget_micro_units > self.fast_lane_budget_remaining_micro_units {
            return Err("insufficient fast lane budget".to_string());
        }
        let bid_status = self
            .sealed_bids
            .get(&request.selected_bid_id)
            .ok_or_else(|| "selected bid not found".to_string())?
            .status;
        if !bid_status.selectable() {
            return Err("selected bid is not eligible for fast-lane reservation".to_string());
        }
        for case_id in &request.case_ids {
            let case = self
                .cases
                .get(case_id)
                .ok_or_else(|| format!("case {case_id} not found for fast-lane reservation"))?;
            if !case.status.can_settle() {
                return Err(format!("case {case_id} is not settlement ready"));
            }
        }
        if let Some(pool_id) = &request.backstop_pool_id {
            let pool = self
                .private_backstop_pools
                .get(pool_id)
                .ok_or_else(|| "backstop pool not found for fast-lane reservation".to_string())?;
            if !pool.status.available() {
                return Err("backstop pool is not active".to_string());
            }
        }
        let lane_id = deterministic_id(
            "fast-settlement-lane",
            self.counters.next_lane_nonce,
            &[&request.selected_bid_id, &request.lane_ciphertext_root],
        );
        for case_id in &request.case_ids {
            let case = self
                .cases
                .get_mut(case_id)
                .ok_or_else(|| format!("case {case_id} not found"))?;
            case.status = CaseStatus::LaneReserved;
            case.lane_id = Some(lane_id.clone());
        }
        let bid = self
            .sealed_bids
            .get_mut(&request.selected_bid_id)
            .ok_or_else(|| "selected bid not found".to_string())?;
        bid.status = SealedBidStatus::Selected;
        bid.lane_id = Some(lane_id.clone());
        let record = FastSettlementLaneRecord {
            lane_id: lane_id.clone(),
            request,
            status: FastLaneStatus::Reserved,
            recursive_receipt_id: None,
        };
        self.fast_lane_budget_remaining_micro_units = self
            .fast_lane_budget_remaining_micro_units
            .saturating_sub(record.request.lane_budget_micro_units);
        self.counters.next_lane_nonce = self.counters.next_lane_nonce.saturating_add(1);
        self.counters.fast_lanes_reserved = self.counters.fast_lanes_reserved.saturating_add(1);
        self.publish_public_record("fast_lane_reserved", &lane_id, record.public_record());
        self.fast_lanes.insert(lane_id.clone(), record);
        Ok(lane_id)
    }

    pub fn attach_recursive_proof_receipt(
        &mut self,
        request: RecursiveProofReceiptRequest,
    ) -> Result<String> {
        self.ensure_capacity(
            self.recursive_receipts.len(),
            self.config.max_receipts,
            "recursive proof receipts",
        )?;
        request.validate()?;
        let lane_status = self
            .fast_lanes
            .get(&request.lane_id)
            .ok_or_else(|| "fast lane not found for recursive proof receipt".to_string())?
            .status;
        if !matches!(
            lane_status,
            FastLaneStatus::Reserved | FastLaneStatus::Executing
        ) {
            return Err("fast lane is not ready for recursive proof receipt".to_string());
        }
        let bid_lane_id = self
            .sealed_bids
            .get(&request.selected_bid_id)
            .ok_or_else(|| "selected bid not found for recursive proof receipt".to_string())?
            .lane_id
            .clone();
        if bid_lane_id.as_deref() != Some(&request.lane_id) {
            return Err("selected bid does not belong to settlement lane".to_string());
        }
        let receipt_id = deterministic_id(
            "recursive-proof-receipt",
            self.counters.next_receipt_nonce,
            &[&request.lane_id, &request.proof_root],
        );
        for case_id in &request.case_ids {
            let case = self
                .cases
                .get_mut(case_id)
                .ok_or_else(|| format!("case {case_id} not found for receipt"))?;
            case.status = CaseStatus::Settled;
            case.recursive_receipt_id = Some(receipt_id.clone());
            self.active_case_ids.remove(case_id);
            self.settlement_ready_case_ids.remove(case_id);
        }
        let bid = self
            .sealed_bids
            .get_mut(&request.selected_bid_id)
            .ok_or_else(|| "selected bid not found for recursive proof receipt".to_string())?;
        bid.status = SealedBidStatus::Settled;
        bid.recursive_receipt_id = Some(receipt_id.clone());
        let lane = self
            .fast_lanes
            .get_mut(&request.lane_id)
            .ok_or_else(|| "fast lane not found for recursive proof receipt".to_string())?;
        lane.status = FastLaneStatus::ReceiptAttached;
        lane.recursive_receipt_id = Some(receipt_id.clone());
        let record = RecursiveProofReceiptRecord {
            receipt_id: receipt_id.clone(),
            status: if request.finalized_at_height.is_some() {
                RecursiveProofStatus::Finalized
            } else {
                RecursiveProofStatus::Attached
            },
            request,
        };
        self.counters.next_receipt_nonce = self.counters.next_receipt_nonce.saturating_add(1);
        self.counters.receipts_published = self.counters.receipts_published.saturating_add(1);
        self.publish_public_record(
            "recursive_receipt_attached",
            &receipt_id,
            record.public_record(),
        );
        self.recursive_receipts.insert(receipt_id.clone(), record);
        Ok(receipt_id)
    }

    pub fn open_challenge_bond(&mut self, mut request: ChallengeBondRequest) -> Result<String> {
        self.ensure_capacity(
            self.challenges.len(),
            self.config.max_challenges,
            "challenge bonds",
        )?;
        if request.expires_at_height == 0 {
            request.expires_at_height = request
                .opened_at_height
                .saturating_add(self.config.challenge_ttl_blocks);
        }
        request.validate(&self.config)?;
        if let Some(lane_id) = &request.lane_id {
            if !self.fast_lanes.contains_key(lane_id) {
                return Err("lane not found for challenge".to_string());
            }
        }
        if let Some(receipt_id) = &request.receipt_id {
            if !self.recursive_receipts.contains_key(receipt_id) {
                return Err("receipt not found for challenge".to_string());
            }
        }
        let challenge_id = deterministic_id(
            "challenge-bond",
            self.counters.next_challenge_nonce,
            &[&request.case_id, &request.evidence_root],
        );
        let case = self
            .cases
            .get_mut(&request.case_id)
            .ok_or_else(|| "case not found for challenge".to_string())?;
        case.status = CaseStatus::Challenged;
        case.challenge_ids.insert(challenge_id.clone());
        let record = ChallengeBondRecord {
            challenge_id: challenge_id.clone(),
            request,
            status: ChallengeStatus::Open,
            slashed_subject_id: None,
            resolved_at_height: None,
        };
        self.counters.next_challenge_nonce = self.counters.next_challenge_nonce.saturating_add(1);
        self.counters.challenges_opened = self.counters.challenges_opened.saturating_add(1);
        self.publish_public_record("challenge_opened", &challenge_id, record.public_record());
        self.challenges.insert(challenge_id.clone(), record);
        Ok(challenge_id)
    }

    pub fn slash_challenge(
        &mut self,
        challenge_id: &str,
        slashed_subject_id: &str,
        resolved_at_height: u64,
    ) -> Result<()> {
        ensure_non_empty(slashed_subject_id, "slashed subject id")?;
        let (case_id, lane_id, receipt_id) = {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "challenge not found".to_string())?;
            challenge.status = ChallengeStatus::Slashed;
            challenge.slashed_subject_id = Some(slashed_subject_id.to_string());
            challenge.resolved_at_height = Some(resolved_at_height);
            (
                challenge.request.case_id.clone(),
                challenge.request.lane_id.clone(),
                challenge.request.receipt_id.clone(),
            )
        };
        if let Some(case) = self.cases.get_mut(&case_id) {
            case.status = CaseStatus::Slashed;
        }
        if let Some(lane_id) = lane_id {
            if let Some(lane) = self.fast_lanes.get_mut(&lane_id) {
                lane.status = FastLaneStatus::Slashed;
            }
        }
        if let Some(receipt_id) = receipt_id {
            if let Some(receipt) = self.recursive_receipts.get_mut(&receipt_id) {
                receipt.status = RecursiveProofStatus::Disputed;
            }
        }
        if let Some(bid) = self.sealed_bids.get_mut(slashed_subject_id) {
            bid.status = SealedBidStatus::Slashed;
        }
        if let Some(pool) = self.private_backstop_pools.get_mut(slashed_subject_id) {
            pool.status = BackstopPoolStatus::Slashed;
        }
        self.counters.slashes_executed = self.counters.slashes_executed.saturating_add(1);
        self.publish_public_record(
            "challenge_slashed",
            challenge_id,
            json!({
                "challenge_id": challenge_id,
                "slashed_subject_id": slashed_subject_id,
                "resolved_at_height": resolved_at_height
            }),
        );
        Ok(())
    }

    pub fn queue_fee_rebate(
        &mut self,
        lane_id: &str,
        receipt_id: &str,
        beneficiary_commitment: &str,
        rebate_root: &str,
        rebate_bps: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "fee rebates")?;
        ensure_non_empty(lane_id, "lane id")?;
        ensure_non_empty(receipt_id, "receipt id")?;
        require_root("beneficiary commitment", beneficiary_commitment)?;
        require_root("rebate root", rebate_root)?;
        ensure_bps(rebate_bps, "rebate bps")?;
        if rebate_bps < self.config.min_rebate_bps || rebate_bps > self.config.max_rebate_bps {
            return Err("rebate bps outside configured range".to_string());
        }
        if !self.fast_lanes.contains_key(lane_id) {
            return Err("lane not found for rebate".to_string());
        }
        if !self.recursive_receipts.contains_key(receipt_id) {
            return Err("receipt not found for rebate".to_string());
        }
        let rebate_id = deterministic_id(
            "fee-rebate",
            self.counters.next_rebate_nonce,
            &[lane_id, receipt_id, rebate_root],
        );
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            lane_id: lane_id.to_string(),
            receipt_id: receipt_id.to_string(),
            beneficiary_commitment: beneficiary_commitment.to_string(),
            rebate_root: rebate_root.to_string(),
            rebate_bps,
            queued_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.rebate_epoch_blocks,
            status: RebateStatus::Queued,
        };
        self.counters.next_rebate_nonce = self.counters.next_rebate_nonce.saturating_add(1);
        self.counters.rebates_queued = self.counters.rebates_queued.saturating_add(1);
        self.publish_public_record("rebate_queued", &rebate_id, record.public_record());
        self.rebates.insert(rebate_id.clone(), record);
        Ok(rebate_id)
    }

    pub fn open_mev_guard_fence(
        &mut self,
        subject_id: &str,
        scope: &str,
        viewer_set_root: &str,
        ordering_root: &str,
        nullifier_root: &str,
        disclosure_policy_root: &str,
        min_delay_blocks: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.mev_fences.len(),
            self.config.max_mev_fences,
            "mev fences",
        )?;
        ensure_non_empty(subject_id, "subject id")?;
        ensure_non_empty(scope, "scope")?;
        require_root("viewer set root", viewer_set_root)?;
        require_root("ordering root", ordering_root)?;
        require_root("nullifier root", nullifier_root)?;
        require_root("disclosure policy root", disclosure_policy_root)?;
        let fence_id = deterministic_id(
            "mev-guard-fence",
            self.counters.next_fence_nonce,
            &[subject_id, scope, ordering_root],
        );
        let record = MevGuardFence {
            fence_id: fence_id.clone(),
            subject_id: subject_id.to_string(),
            scope: scope.to_string(),
            viewer_set_root: viewer_set_root.to_string(),
            ordering_root: ordering_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            disclosure_policy_root: disclosure_policy_root.to_string(),
            min_delay_blocks,
            opened_at_height: self.current_height,
            expires_at_height: self.current_height + self.config.challenge_ttl_blocks,
        };
        self.counters.next_fence_nonce = self.counters.next_fence_nonce.saturating_add(1);
        self.counters.mev_fences_opened = self.counters.mev_fences_opened.saturating_add(1);
        self.publish_public_record("mev_fence_opened", &fence_id, record.public_record());
        self.mev_fences.insert(fence_id.clone(), record);
        Ok(fence_id)
    }

    pub fn expire_height(&mut self, height: u64) {
        self.current_height = self.current_height.max(height);

        for case in self.cases.values_mut() {
            if case.request.expires_at_height <= self.current_height
                && !matches!(
                    case.status,
                    CaseStatus::Settled | CaseStatus::Slashed | CaseStatus::Expired
                )
            {
                case.status = CaseStatus::Expired;
                self.active_case_ids.remove(&case.case_id);
                self.settlement_ready_case_ids.remove(&case.case_id);
            }
        }

        for attestation in self.oracle_attestations.values_mut() {
            if attestation.request.expires_at_height <= self.current_height
                && matches!(
                    attestation.status,
                    OracleAttestationStatus::Submitted | OracleAttestationStatus::Accepted
                )
            {
                attestation.status = OracleAttestationStatus::Expired;
            }
        }

        for bid in self.sealed_bids.values_mut() {
            if bid.request.expires_at_height <= self.current_height
                && !matches!(
                    bid.status,
                    SealedBidStatus::Settled
                        | SealedBidStatus::Rejected
                        | SealedBidStatus::Slashed
                        | SealedBidStatus::Expired
                )
            {
                bid.status = SealedBidStatus::Expired;
            }
        }

        for pool in self.private_backstop_pools.values_mut() {
            if pool.expires_at_height <= self.current_height
                && !matches!(
                    pool.status,
                    BackstopPoolStatus::Closed
                        | BackstopPoolStatus::Slashed
                        | BackstopPoolStatus::Expired
                )
            {
                pool.status = BackstopPoolStatus::Expired;
            }
        }

        for lane in self.fast_lanes.values_mut() {
            if lane.request.expires_at_height <= self.current_height
                && !matches!(
                    lane.status,
                    FastLaneStatus::Finalized
                        | FastLaneStatus::Released
                        | FastLaneStatus::Slashed
                        | FastLaneStatus::Expired
                )
            {
                lane.status = FastLaneStatus::Expired;
                self.fast_lane_budget_remaining_micro_units = self
                    .fast_lane_budget_remaining_micro_units
                    .saturating_add(lane.request.lane_budget_micro_units);
            }
        }

        for challenge in self.challenges.values_mut() {
            if challenge.request.expires_at_height <= self.current_height
                && matches!(
                    challenge.status,
                    ChallengeStatus::Open | ChallengeStatus::Proven
                )
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }

        for rebate in self.rebates.values_mut() {
            if rebate.expires_at_height <= self.current_height
                && rebate.status == RebateStatus::Queued
            {
                rebate.status = RebateStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-COUNTERS",
            &self.counters.public_record(),
        );
        let case_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-CASES",
            self.cases
                .values()
                .map(EncryptedLiquidationCaseRecord::public_record)
                .collect(),
        );
        let attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-ATTESTATIONS",
            self.oracle_attestations
                .values()
                .map(OracleRiskAttestationRecord::public_record)
                .collect(),
        );
        let bid_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-BIDS",
            self.sealed_bids
                .values()
                .map(SealedBidRecord::public_record)
                .collect(),
        );
        let backstop_pool_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-BACKSTOP-POOLS",
            self.private_backstop_pools
                .values()
                .map(PrivateBackstopPool::public_record)
                .collect(),
        );
        let lane_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-LANES",
            self.fast_lanes
                .values()
                .map(FastSettlementLaneRecord::public_record)
                .collect(),
        );
        let receipt_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-RECEIPTS",
            self.recursive_receipts
                .values()
                .map(RecursiveProofReceiptRecord::public_record)
                .collect(),
        );
        let challenge_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-CHALLENGES",
            self.challenges
                .values()
                .map(ChallengeBondRecord::public_record)
                .collect(),
        );
        let rebate_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-REBATES",
            self.rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect(),
        );
        let mev_fence_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-MEV-FENCES",
            self.mev_fences
                .values()
                .map(MevGuardFence::public_record)
                .collect(),
        );
        let active_case_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-ACTIVE-CASES",
            self.active_case_ids
                .iter()
                .map(|case_id| json!({ "case_id": case_id }))
                .collect(),
        );
        let settlement_ready_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-SETTLEMENT-READY",
            self.settlement_ready_case_ids
                .iter()
                .map(|case_id| json!({ "case_id": case_id }))
                .collect(),
        );
        let consumed_nullifier_root = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-CONSUMED-NULLIFIERS",
            self.consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect(),
        );
        let public_record_root_value = public_record_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-PUBLIC-RECORDS",
            self.public_records.values().cloned().collect(),
        );
        let state_root = state_root_from_record(&json!({
            "config_root": config_root,
            "counter_root": counter_root,
            "case_root": case_root,
            "attestation_root": attestation_root,
            "bid_root": bid_root,
            "backstop_pool_root": backstop_pool_root,
            "lane_root": lane_root,
            "receipt_root": receipt_root,
            "challenge_root": challenge_root,
            "rebate_root": rebate_root,
            "mev_fence_root": mev_fence_root,
            "active_case_root": active_case_root,
            "settlement_ready_root": settlement_ready_root,
            "consumed_nullifier_root": consumed_nullifier_root,
            "public_record_root": public_record_root_value,
            "runtime_root": self.runtime_root,
            "current_height": self.current_height,
            "fast_lane_budget_remaining_micro_units": self.fast_lane_budget_remaining_micro_units
        }));
        Roots {
            config_root,
            counter_root,
            case_root,
            attestation_root,
            bid_root,
            backstop_pool_root,
            lane_root,
            receipt_root,
            challenge_root,
            rebate_root,
            mev_fence_root,
            active_case_root,
            settlement_ready_root,
            consumed_nullifier_root,
            public_record_root: public_record_root_value,
            state_root,
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_defi_liquidation_sealed_bid_runtime_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_HASH_SUITE,
            "current_height": self.current_height,
            "runtime_root": self.runtime_root,
            "fast_lane_budget_remaining_micro_units": self.fast_lane_budget_remaining_micro_units,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "counts": {
                "cases": self.cases.len(),
                "oracle_attestations": self.oracle_attestations.len(),
                "sealed_bids": self.sealed_bids.len(),
                "private_backstop_pools": self.private_backstop_pools.len(),
                "fast_lanes": self.fast_lanes.len(),
                "recursive_receipts": self.recursive_receipts.len(),
                "challenges": self.challenges.len(),
                "rebates": self.rebates.len(),
                "mev_fences": self.mev_fences.len()
            }
        })
    }

    pub fn public_record(&self) -> Value {
        let record = self.public_record_without_state_root();
        json!({
            "state_root": state_root_from_record(&record),
            "record": record
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn ensure_capacity(&self, len: usize, limit: usize, label: &str) -> Result<()> {
        if len >= limit {
            return Err(format!("{label} capacity reached"));
        }
        Ok(())
    }

    fn ensure_privacy_set(&self, privacy_set_size: u64, label: &str) -> Result<()> {
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err(format!("{label} below configured privacy minimum"));
        }
        Ok(())
    }

    fn consume_nullifier(&mut self, nullifier: &str) -> Result<()> {
        require_root("nullifier", nullifier)?;
        let nullifier_hash = payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-NULLIFIER",
            &json!({ "nullifier": nullifier }),
        );
        if !self.consumed_nullifiers.insert(nullifier_hash) {
            return Err("nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifiers = self.counters.consumed_nullifiers.saturating_add(1);
        Ok(())
    }

    fn best_backstop_pool(&self, venue: LiquidationVenue, bonus_bps: u64) -> Option<String> {
        self.private_backstop_pools
            .values()
            .filter(|pool| {
                pool.venue == venue && pool.status.available() && pool.fee_bps <= bonus_bps
            })
            .min_by_key(|pool| {
                (
                    pool.fee_bps,
                    std::cmp::Reverse(pool.liquidity_budget_micro_units),
                )
            })
            .map(|pool| pool.pool_id.clone())
    }

    fn publish_public_record(&mut self, record_kind: &str, subject_id: &str, payload: Value) {
        let record_id = public_record_id(record_kind, subject_id, &payload);
        self.public_records.insert(
            record_id,
            roots_only_public_record(record_kind, subject_id, &payload),
        );
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
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
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

pub fn deterministic_id(kind: &str, nonce: u64, labels: &[&str]) -> String {
    let mut parts = vec![
        HashPart::Str(kind),
        HashPart::Str(CHAIN_ID),
        HashPart::U64(nonce),
    ];
    for label in labels {
        parts.push(HashPart::Str(label));
    }
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-DETERMINISTIC-ID",
        &parts,
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-STATE-ROOT",
        record,
    )
}

pub fn public_record_id(record_kind: &str, subject_id: &str, payload: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn roots_only_public_record(record_kind: &str, subject_id: &str, payload: &Value) -> Value {
    json!({
        "kind": "roots_only_public_record",
        "record_kind": record_kind,
        "subject_id": subject_id,
        "payload_root": payload_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-PAYLOAD-ROOT",
            payload
        ),
        "record_id": public_record_id(record_kind, subject_id, payload)
    })
}

pub fn roots_only_payload(kind: &str, subject_id: &str, payload: &Value) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-ROOTS-ONLY-PAYLOAD",
        &json!({
            "kind": kind,
            "subject_id": subject_id,
            "payload": payload
        }),
    )
}

pub fn commitment_root(domain: &str, label: &str) -> String {
    payload_root(
        "PRIVATE-L2-PQ-CONFIDENTIAL-DEFI-LIQUIDATION-COMMITMENT",
        &json!({ "domain": domain, "label": label }),
    )
}

pub fn bid_score(request: &SealedBidRequest) -> u64 {
    request
        .expected_recovery_bps
        .saturating_mul(100)
        .saturating_sub(request.user_fee_bps.saturating_mul(10))
        .saturating_sub(request.keeper_fee_bps.saturating_mul(8))
        .saturating_sub(request.bonus_bps)
        .saturating_add(request.bond_micro_units / 1_000_000)
}

pub fn ensure_non_empty(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

pub fn require_root(label: &str, root: &str) -> Result<()> {
    ensure_non_empty(root, label)?;
    if root.len() < 16 {
        return Err(format!("{label} must look like a deterministic root"));
    }
    Ok(())
}

pub fn ensure_bps(value: u64, label: &str) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_DEFI_LIQUIDATION_SEALED_BID_RUNTIME_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}
