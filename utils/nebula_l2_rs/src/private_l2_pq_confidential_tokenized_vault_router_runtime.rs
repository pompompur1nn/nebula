use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialTokenizedVaultRouterRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialTokenizedVaultRouterRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-vault-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SCHEMA_VERSION: u64 =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SCHEMA_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const HASH_SUITE: &str = PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_HASH_SUITE;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-pq-confidential-tokenized-vault-router-v1";
pub const PQ_AUTH_SUITE: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_PQ_AUTH_SUITE;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_VAULT_SCHEME: &str =
    "monero-private-l2-pq-confidential-tokenized-vault-root-v1";
pub const VAULT_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_VAULT_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SHARE_SCHEME: &str =
    "monero-private-l2-pq-confidential-vault-share-class-root-v1";
pub const SHARE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SHARE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_DEPOSIT_INTENT_SCHEME: &str =
    "monero-private-l2-encrypted-tokenized-vault-deposit-intent-root-v1";
pub const DEPOSIT_INTENT_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_DEPOSIT_INTENT_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_WITHDRAW_INTENT_SCHEME: &str =
    "monero-private-l2-encrypted-tokenized-vault-withdraw-intent-root-v1";
pub const WITHDRAW_INTENT_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_WITHDRAW_INTENT_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SWAP_ROUTE_SCHEME: &str =
    "monero-private-l2-confidential-swap-route-intent-root-v1";
pub const SWAP_ROUTE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SWAP_ROUTE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_LP_SCHEME: &str =
    "monero-private-l2-tokenized-vault-lp-position-root-v1";
pub const LP_SCHEME: &str = PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_LP_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_NETTING_SCHEME: &str =
    "monero-private-l2-tokenized-vault-mint-burn-netting-root-v1";
pub const NETTING_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_NETTING_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SOLVER_QUOTE_SCHEME: &str =
    "monero-private-l2-private-vault-solver-quote-root-v1";
pub const SOLVER_QUOTE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SOLVER_QUOTE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SPONSOR_SCHEME: &str =
    "monero-private-l2-low-fee-vault-sponsor-reservation-root-v1";
pub const SPONSOR_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_SPONSOR_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_RECEIPT_SCHEME: &str =
    "monero-private-l2-recursive-vault-proof-receipt-root-v1";
pub const RECEIPT_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_RECEIPT_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_COMPLIANCE_SCHEME: &str =
    "monero-private-l2-tokenized-vault-compliance-attestation-root-v1";
pub const COMPLIANCE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_COMPLIANCE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_FENCE_SCHEME: &str =
    "monero-private-l2-tokenized-vault-nullifier-fence-root-v1";
pub const FENCE_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_FENCE_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_LIQUIDATION_SCHEME: &str =
    "monero-private-l2-vault-liquidation-link-root-v1";
pub const LIQUIDATION_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_LIQUIDATION_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_BACKSTOP_SCHEME: &str =
    "monero-private-l2-vault-backstop-link-root-v1";
pub const BACKSTOP_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_BACKSTOP_SCHEME;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_EVENT_SCHEME: &str =
    "roots-only-private-l2-pq-confidential-tokenized-vault-router-public-record-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_VAULT_ROUTER_RUNTIME_EVENT_SCHEME;

pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:xusd-devnet";
pub const DEVNET_HEIGHT: u64 = 2_184_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_ROUTE_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_VAULT_INTENT_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SWAP_ROUTE_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_COMPLIANCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 15;
pub const DEFAULT_MAX_PROTOCOL_FEE_BPS: u64 = 9;
pub const DEFAULT_MAX_SOLVER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_SPONSOR_REBATE_BPS: u64 = 5;
pub const DEFAULT_LIQUIDATION_HAIRCUT_BPS: u64 = 850;
pub const DEFAULT_BACKSTOP_BUFFER_BPS: u64 = 1_250;
pub const DEFAULT_MIN_SOLVER_COLLATERAL: u64 = 50_000;
pub const DEFAULT_MIN_SPONSOR_ESCROW: u64 = 10_000;
pub const DEFAULT_MAX_ROUTE_LEGS: usize = 16;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 2_048;
pub const DEFAULT_MAX_SHARE_CLASSES_PER_VAULT: usize = 8;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VAULTS: usize = 262_144;
pub const MAX_SHARE_CLASSES: usize = 1_048_576;
pub const MAX_DEPOSIT_INTENTS: usize = 4_194_304;
pub const MAX_WITHDRAW_INTENTS: usize = 4_194_304;
pub const MAX_SWAP_ROUTES: usize = 4_194_304;
pub const MAX_LP_POSITIONS: usize = 2_097_152;
pub const MAX_NETTING_BATCHES: usize = 1_048_576;
pub const MAX_SOLVER_QUOTES: usize = 4_194_304;
pub const MAX_SPONSOR_RESERVATIONS: usize = 2_097_152;
pub const MAX_RECEIPTS: usize = 2_097_152;
pub const MAX_COMPLIANCE_ATTESTATIONS: usize = 4_194_304;
pub const MAX_FENCES: usize = 8_388_608;
pub const MAX_LIQUIDATION_LINKS: usize = 2_097_152;
pub const MAX_BACKSTOP_LINKS: usize = 2_097_152;
pub const MAX_EVENTS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultFlavor {
    YieldRouter,
    BasketIndex,
    StableSwap,
    AmmLp,
    Credit,
    Treasury,
    PerpetualCarry,
    Rwa,
    Insurance,
    LiquidStaking,
}

impl VaultFlavor {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::YieldRouter => "yield_router",
            Self::BasketIndex => "basket_index",
            Self::StableSwap => "stable_swap",
            Self::AmmLp => "amm_lp",
            Self::Credit => "credit",
            Self::Treasury => "treasury",
            Self::PerpetualCarry => "perpetual_carry",
            Self::Rwa => "rwa",
            Self::Insurance => "insurance",
            Self::LiquidStaking => "liquid_staking",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultStatus {
    Draft,
    Active,
    DepositOnly,
    WithdrawOnly,
    RebalanceOnly,
    LiquidationOnly,
    Paused,
    Frozen,
    Retired,
}

impl VaultStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::DepositOnly => "deposit_only",
            Self::WithdrawOnly => "withdraw_only",
            Self::RebalanceOnly => "rebalance_only",
            Self::LiquidationOnly => "liquidation_only",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_deposits(self) -> bool {
        matches!(self, Self::Active | Self::DepositOnly)
    }

    pub fn accepts_withdrawals(self) -> bool {
        matches!(self, Self::Active | Self::WithdrawOnly)
    }

    pub fn accepts_routing(self) -> bool {
        matches!(
            self,
            Self::Active | Self::DepositOnly | Self::WithdrawOnly | Self::RebalanceOnly
        )
    }

    pub fn accepts_liquidation(self) -> bool {
        matches!(self, Self::Active | Self::LiquidationOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareClassKind {
    Senior,
    Junior,
    Levered,
    Hedged,
    LpReceipt,
    Governance,
    Insurance,
    Synthetic,
}

impl ShareClassKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Junior => "junior",
            Self::Levered => "levered",
            Self::Hedged => "hedged",
            Self::LpReceipt => "lp_receipt",
            Self::Governance => "governance",
            Self::Insurance => "insurance",
            Self::Synthetic => "synthetic",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    Fenced,
    Quoted,
    Reserved,
    Netted,
    Receipted,
    Settled,
    Rejected,
    Expired,
    Cancelled,
    Liquidated,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Fenced => "fenced",
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Netted => "netted",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Liquidated => "liquidated",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Fenced | Self::Quoted | Self::Reserved | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutePriority {
    Cheap,
    Balanced,
    Fast,
    Critical,
    Liquidation,
}

impl RoutePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cheap => "cheap",
            Self::Balanced => "balanced",
            Self::Fast => "fast",
            Self::Critical => "critical",
            Self::Liquidation => "liquidation",
        }
    }

    pub fn fee_weight(self) -> u64 {
        match self {
            Self::Cheap => 1,
            Self::Balanced => 2,
            Self::Fast => 3,
            Self::Critical => 4,
            Self::Liquidation => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapLegKind {
    VaultShareSwap,
    StablePool,
    BasketRebalance,
    AmmHop,
    LendingRepay,
    LendingBorrow,
    LiquidationCover,
    BackstopRefill,
}

impl SwapLegKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultShareSwap => "vault_share_swap",
            Self::StablePool => "stable_pool",
            Self::BasketRebalance => "basket_rebalance",
            Self::AmmHop => "amm_hop",
            Self::LendingRepay => "lending_repay",
            Self::LendingBorrow => "lending_borrow",
            Self::LiquidationCover => "liquidation_cover",
            Self::BackstopRefill => "backstop_refill",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Attached,
    Reserved,
    Accepted,
    Expired,
    Rejected,
    Slashed,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Reserved => "reserved",
            Self::Accepted => "accepted",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Attached | Self::Reserved | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Consumed,
    Released,
    Expired,
    Slashed,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Proposed,
    Sponsored,
    Proving,
    Receipted,
    Settled,
    Expired,
    Rejected,
    Slashed,
}

impl NettingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Sponsored => "sponsored",
            Self::Proving => "proving",
            Self::Receipted => "receipted",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Proposed | Self::Sponsored | Self::Proving)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Finalized,
    Disputed,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceVerdict {
    Approved,
    NeedsReview,
    Rejected,
    Sanctioned,
}

impl ComplianceVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::NeedsReview => "needs_review",
            Self::Rejected => "rejected",
            Self::Sanctioned => "sanctioned",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Locked,
    Released,
    Consumed,
    Expired,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Locked => "locked",
            Self::Released => "released",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::Open | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidationStatus {
    Pending,
    Linked,
    Triggered,
    Cured,
    Settled,
    Expired,
}

impl LiquidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Linked => "linked",
            Self::Triggered => "triggered",
            Self::Cured => "cured",
            Self::Settled => "settled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackstopStatus {
    Registered,
    Armed,
    Drawn,
    Repaid,
    Retired,
}

impl BackstopStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Armed => "armed",
            Self::Drawn => "drawn",
            Self::Repaid => "repaid",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    VaultRegistered,
    ShareClassDefined,
    DepositSubmitted,
    WithdrawSubmitted,
    SwapRouteSubmitted,
    LpPositionAttached,
    SolverQuoteAttached,
    SponsorReserved,
    NettingBatchBuilt,
    ReceiptPublished,
    ComplianceAttested,
    FenceOpened,
    LiquidationLinked,
    BackstopLinked,
    IntentSettled,
    ReceiptFinalized,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VaultRegistered => "vault_registered",
            Self::ShareClassDefined => "share_class_defined",
            Self::DepositSubmitted => "deposit_submitted",
            Self::WithdrawSubmitted => "withdraw_submitted",
            Self::SwapRouteSubmitted => "swap_route_submitted",
            Self::LpPositionAttached => "lp_position_attached",
            Self::SolverQuoteAttached => "solver_quote_attached",
            Self::SponsorReserved => "sponsor_reserved",
            Self::NettingBatchBuilt => "netting_batch_built",
            Self::ReceiptPublished => "receipt_published",
            Self::ComplianceAttested => "compliance_attested",
            Self::FenceOpened => "fence_opened",
            Self::LiquidationLinked => "liquidation_linked",
            Self::BackstopLinked => "backstop_linked",
            Self::IntentSettled => "intent_settled",
            Self::ReceiptFinalized => "receipt_finalized",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_route_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub vault_intent_ttl_blocks: u64,
    pub swap_route_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub compliance_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_protocol_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub target_sponsor_rebate_bps: u64,
    pub liquidation_haircut_bps: u64,
    pub backstop_buffer_bps: u64,
    pub min_solver_collateral: u64,
    pub min_sponsor_escrow: u64,
    pub max_route_legs: usize,
    pub max_batch_items: usize,
    pub max_share_classes_per_vault: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_route_privacy_set_size: DEFAULT_TARGET_ROUTE_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            vault_intent_ttl_blocks: DEFAULT_VAULT_INTENT_TTL_BLOCKS,
            swap_route_ttl_blocks: DEFAULT_SWAP_ROUTE_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            compliance_ttl_blocks: DEFAULT_COMPLIANCE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_protocol_fee_bps: DEFAULT_MAX_PROTOCOL_FEE_BPS,
            max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
            target_sponsor_rebate_bps: DEFAULT_TARGET_SPONSOR_REBATE_BPS,
            liquidation_haircut_bps: DEFAULT_LIQUIDATION_HAIRCUT_BPS,
            backstop_buffer_bps: DEFAULT_BACKSTOP_BUFFER_BPS,
            min_solver_collateral: DEFAULT_MIN_SOLVER_COLLATERAL,
            min_sponsor_escrow: DEFAULT_MIN_SPONSOR_ESCROW,
            max_route_legs: DEFAULT_MAX_ROUTE_LEGS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_share_classes_per_vault: DEFAULT_MAX_SHARE_CLASSES_PER_VAULT,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_route_privacy_set_size": self.target_route_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "vault_intent_ttl_blocks": self.vault_intent_ttl_blocks,
            "swap_route_ttl_blocks": self.swap_route_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "compliance_ttl_blocks": self.compliance_ttl_blocks,
            "fence_ttl_blocks": self.fence_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_protocol_fee_bps": self.max_protocol_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "target_sponsor_rebate_bps": self.target_sponsor_rebate_bps,
            "liquidation_haircut_bps": self.liquidation_haircut_bps,
            "backstop_buffer_bps": self.backstop_buffer_bps,
            "min_solver_collateral": self.min_solver_collateral,
            "min_sponsor_escrow": self.min_sponsor_escrow,
            "max_route_legs": self.max_route_legs,
            "max_batch_items": self.max_batch_items,
            "max_share_classes_per_vault": self.max_share_classes_per_vault,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults_registered: u64,
    pub share_classes_defined: u64,
    pub deposit_intents_submitted: u64,
    pub withdraw_intents_submitted: u64,
    pub swap_routes_submitted: u64,
    pub lp_positions_attached: u64,
    pub solver_quotes_attached: u64,
    pub sponsor_reservations_created: u64,
    pub netting_batches_built: u64,
    pub receipts_published: u64,
    pub compliance_attestations_recorded: u64,
    pub fences_opened: u64,
    pub liquidation_links_created: u64,
    pub backstop_links_created: u64,
    pub events_recorded: u64,
    pub intents_expired: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Roots {
    pub vault_root: String,
    pub share_class_root: String,
    pub deposit_intent_root: String,
    pub withdraw_intent_root: String,
    pub swap_route_root: String,
    pub lp_position_root: String,
    pub netting_batch_root: String,
    pub solver_quote_root: String,
    pub sponsor_reservation_root: String,
    pub recursive_receipt_root: String,
    pub compliance_attestation_root: String,
    pub fence_root: String,
    pub liquidation_link_root: String,
    pub backstop_link_root: String,
    pub event_root: String,
    pub nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_root": self.vault_root,
            "share_class_root": self.share_class_root,
            "deposit_intent_root": self.deposit_intent_root,
            "withdraw_intent_root": self.withdraw_intent_root,
            "swap_route_root": self.swap_route_root,
            "lp_position_root": self.lp_position_root,
            "netting_batch_root": self.netting_batch_root,
            "solver_quote_root": self.solver_quote_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "recursive_receipt_root": self.recursive_receipt_root,
            "compliance_attestation_root": self.compliance_attestation_root,
            "fence_root": self.fence_root,
            "liquidation_link_root": self.liquidation_link_root,
            "backstop_link_root": self.backstop_link_root,
            "event_root": self.event_root,
            "nullifier_root": self.nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RegisterVaultRequest {
    pub operator_id: String,
    pub vault_label: String,
    pub vault_flavor: VaultFlavor,
    pub fee_model_root: String,
    pub asset_commitment_root: String,
    pub policy_root: String,
    pub compliance_root: String,
    pub liquidation_root: String,
    pub backstop_root: String,
    pub min_deposit_amount: u64,
    pub min_withdraw_amount: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub allow_external_liquidity: bool,
    pub allow_private_lp: bool,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultRecord {
    pub vault_id: String,
    pub operator_id: String,
    pub vault_label: String,
    pub vault_flavor: VaultFlavor,
    pub status: VaultStatus,
    pub fee_model_root: String,
    pub asset_commitment_root: String,
    pub policy_root: String,
    pub compliance_root: String,
    pub liquidation_root: String,
    pub backstop_root: String,
    pub min_deposit_amount: u64,
    pub min_withdraw_amount: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub allow_external_liquidity: bool,
    pub allow_private_lp: bool,
    pub metadata_root: String,
    pub registered_height: u64,
}

impl VaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "vault_id": self.vault_id,
            "operator_id": self.operator_id,
            "vault_label": self.vault_label,
            "vault_flavor": self.vault_flavor.as_str(),
            "status": self.status.as_str(),
            "fee_model_root": self.fee_model_root,
            "asset_commitment_root": self.asset_commitment_root,
            "policy_root": self.policy_root,
            "compliance_root": self.compliance_root,
            "liquidation_root": self.liquidation_root,
            "backstop_root": self.backstop_root,
            "min_deposit_amount": self.min_deposit_amount,
            "min_withdraw_amount": self.min_withdraw_amount,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "allow_external_liquidity": self.allow_external_liquidity,
            "allow_private_lp": self.allow_private_lp,
            "metadata_root": self.metadata_root,
            "registered_height": self.registered_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DefineShareClassRequest {
    pub vault_id: String,
    pub share_symbol: String,
    pub share_class_kind: ShareClassKind,
    pub share_asset_id: String,
    pub supply_cap: u64,
    pub management_fee_bps: u64,
    pub performance_fee_bps: u64,
    pub transfer_restricted: bool,
    pub allow_mint_netting: bool,
    pub allow_burn_netting: bool,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultShareClassRecord {
    pub share_class_id: String,
    pub vault_id: String,
    pub share_symbol: String,
    pub share_class_kind: ShareClassKind,
    pub share_asset_id: String,
    pub supply_cap: u64,
    pub minted_supply: u64,
    pub burned_supply: u64,
    pub management_fee_bps: u64,
    pub performance_fee_bps: u64,
    pub transfer_restricted: bool,
    pub allow_mint_netting: bool,
    pub allow_burn_netting: bool,
    pub metadata_root: String,
    pub defined_height: u64,
}

impl VaultShareClassRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "share_class_id": self.share_class_id,
            "vault_id": self.vault_id,
            "share_symbol": self.share_symbol,
            "share_class_kind": self.share_class_kind.as_str(),
            "share_asset_id": self.share_asset_id,
            "supply_cap": self.supply_cap,
            "minted_supply": self.minted_supply,
            "burned_supply": self.burned_supply,
            "management_fee_bps": self.management_fee_bps,
            "performance_fee_bps": self.performance_fee_bps,
            "transfer_restricted": self.transfer_restricted,
            "allow_mint_netting": self.allow_mint_netting,
            "allow_burn_netting": self.allow_burn_netting,
            "metadata_root": self.metadata_root,
            "defined_height": self.defined_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitDepositIntentRequest {
    pub vault_id: String,
    pub share_class_id: String,
    pub depositor_id: String,
    pub input_asset_id: String,
    pub encrypted_amount_root: String,
    pub encrypted_note_root: String,
    pub recipient_commitment: String,
    pub max_share_slippage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub route_preference: RoutePriority,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositIntentRecord {
    pub deposit_intent_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub depositor_id: String,
    pub input_asset_id: String,
    pub encrypted_amount_root: String,
    pub encrypted_note_root: String,
    pub recipient_commitment: String,
    pub max_share_slippage_bps: u64,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub route_preference: RoutePriority,
    pub status: IntentStatus,
    pub metadata_root: String,
    pub submitted_height: u64,
    pub expires_at_height: u64,
}

impl DepositIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "deposit_intent_id": self.deposit_intent_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "depositor_id": self.depositor_id,
            "input_asset_id": self.input_asset_id,
            "encrypted_amount_root": self.encrypted_amount_root,
            "encrypted_note_root": self.encrypted_note_root,
            "recipient_commitment": self.recipient_commitment,
            "max_share_slippage_bps": self.max_share_slippage_bps,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": root_from_strings("DEPOSIT-INTENT-NULLIFIER", &[&self.nullifier]),
            "route_preference": self.route_preference.as_str(),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "submitted_height": self.submitted_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitWithdrawIntentRequest {
    pub vault_id: String,
    pub share_class_id: String,
    pub withdrawer_id: String,
    pub output_asset_id: String,
    pub encrypted_share_amount_root: String,
    pub encrypted_note_root: String,
    pub recipient_commitment: String,
    pub min_output_amount_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub route_preference: RoutePriority,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WithdrawIntentRecord {
    pub withdraw_intent_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub withdrawer_id: String,
    pub output_asset_id: String,
    pub encrypted_share_amount_root: String,
    pub encrypted_note_root: String,
    pub recipient_commitment: String,
    pub min_output_amount_root: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub route_preference: RoutePriority,
    pub status: IntentStatus,
    pub metadata_root: String,
    pub submitted_height: u64,
    pub expires_at_height: u64,
}

impl WithdrawIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "withdraw_intent_id": self.withdraw_intent_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "withdrawer_id": self.withdrawer_id,
            "output_asset_id": self.output_asset_id,
            "encrypted_share_amount_root": self.encrypted_share_amount_root,
            "encrypted_note_root": self.encrypted_note_root,
            "recipient_commitment": self.recipient_commitment,
            "min_output_amount_root": self.min_output_amount_root,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": root_from_strings("WITHDRAW-INTENT-NULLIFIER", &[&self.nullifier]),
            "route_preference": self.route_preference.as_str(),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "submitted_height": self.submitted_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouteLeg {
    pub leg_index: u32,
    pub leg_kind: SwapLegKind,
    pub market_id: String,
    pub input_asset_id: String,
    pub output_asset_id: String,
    pub commitment_root: String,
    pub fee_limit_bps: u64,
}

impl RouteLeg {
    pub fn public_record(&self) -> Value {
        json!({
            "leg_index": self.leg_index,
            "leg_kind": self.leg_kind.as_str(),
            "market_id": self.market_id,
            "input_asset_id": self.input_asset_id,
            "output_asset_id": self.output_asset_id,
            "commitment_root": self.commitment_root,
            "fee_limit_bps": self.fee_limit_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubmitSwapRouteIntentRequest {
    pub vault_id: String,
    pub share_class_id: String,
    pub intent_subject_id: String,
    pub encrypted_in_amount_root: String,
    pub encrypted_min_out_amount_root: String,
    pub route_priority: RoutePriority,
    pub route_leg_commitments: Vec<RouteLeg>,
    pub destination_commitment: String,
    pub max_total_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialSwapRouteRecord {
    pub swap_route_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub intent_subject_id: String,
    pub encrypted_in_amount_root: String,
    pub encrypted_min_out_amount_root: String,
    pub route_priority: RoutePriority,
    pub route_leg_root: String,
    pub route_leg_count: usize,
    pub destination_commitment: String,
    pub max_total_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub privacy_set_size: u64,
    pub nullifier: String,
    pub status: IntentStatus,
    pub metadata_root: String,
    pub submitted_height: u64,
    pub expires_at_height: u64,
}

impl ConfidentialSwapRouteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "swap_route_id": self.swap_route_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "intent_subject_id": self.intent_subject_id,
            "encrypted_in_amount_root": self.encrypted_in_amount_root,
            "encrypted_min_out_amount_root": self.encrypted_min_out_amount_root,
            "route_priority": self.route_priority.as_str(),
            "route_leg_root": self.route_leg_root,
            "route_leg_count": self.route_leg_count,
            "destination_commitment": self.destination_commitment,
            "max_total_fee_bps": self.max_total_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "nullifier_root": root_from_strings("SWAP-ROUTE-NULLIFIER", &[&self.nullifier]),
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "submitted_height": self.submitted_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttachLpPositionRequest {
    pub vault_id: String,
    pub share_class_id: String,
    pub lp_provider_id: String,
    pub pool_id: String,
    pub lp_asset_id: String,
    pub share_commitment_root: String,
    pub claimable_fee_root: String,
    pub impermanent_loss_cap_bps: u64,
    pub backstop_eligible: bool,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LpSharePositionRecord {
    pub lp_position_id: String,
    pub vault_id: String,
    pub share_class_id: String,
    pub lp_provider_id: String,
    pub pool_id: String,
    pub lp_asset_id: String,
    pub share_commitment_root: String,
    pub claimable_fee_root: String,
    pub impermanent_loss_cap_bps: u64,
    pub backstop_eligible: bool,
    pub metadata_root: String,
    pub attached_height: u64,
}

impl LpSharePositionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lp_position_id": self.lp_position_id,
            "vault_id": self.vault_id,
            "share_class_id": self.share_class_id,
            "lp_provider_id": self.lp_provider_id,
            "pool_id": self.pool_id,
            "lp_asset_id": self.lp_asset_id,
            "share_commitment_root": self.share_commitment_root,
            "claimable_fee_root": self.claimable_fee_root,
            "impermanent_loss_cap_bps": self.impermanent_loss_cap_bps,
            "backstop_eligible": self.backstop_eligible,
            "metadata_root": self.metadata_root,
            "attached_height": self.attached_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttachSolverQuoteRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub solver_id: String,
    pub quote_commitment_root: String,
    pub route_output_root: String,
    pub collateral_commitment_root: String,
    pub quoted_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub solver_collateral: u64,
    pub security_bits: u16,
    pub valid_for_blocks: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SolverQuoteRecord {
    pub solver_quote_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub solver_id: String,
    pub quote_commitment_root: String,
    pub route_output_root: String,
    pub collateral_commitment_root: String,
    pub quoted_fee_bps: u64,
    pub sponsor_rebate_bps: u64,
    pub solver_collateral: u64,
    pub security_bits: u16,
    pub status: QuoteStatus,
    pub metadata_root: String,
    pub attached_height: u64,
    pub expires_at_height: u64,
}

impl SolverQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "solver_quote_id": self.solver_quote_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "solver_id": self.solver_id,
            "quote_commitment_root": self.quote_commitment_root,
            "route_output_root": self.route_output_root,
            "collateral_commitment_root": self.collateral_commitment_root,
            "quoted_fee_bps": self.quoted_fee_bps,
            "sponsor_rebate_bps": self.sponsor_rebate_bps,
            "solver_collateral": self.solver_collateral,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "attached_height": self.attached_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReserveSponsorRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub solver_quote_id: String,
    pub sponsor_id: String,
    pub escrow_commitment_root: String,
    pub reserved_fee_units: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub lane_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SponsorReservationRecord {
    pub sponsor_reservation_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub solver_quote_id: String,
    pub sponsor_id: String,
    pub escrow_commitment_root: String,
    pub reserved_fee_units: u64,
    pub max_user_fee_bps: u64,
    pub rebate_bps: u64,
    pub lane_id: String,
    pub status: ReservationStatus,
    pub reserved_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "solver_quote_id": self.solver_quote_id,
            "sponsor_id": self.sponsor_id,
            "escrow_commitment_root": self.escrow_commitment_root,
            "reserved_fee_units": self.reserved_fee_units,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_bps": self.rebate_bps,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "reserved_height": self.reserved_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BuildMintBurnNettingBatchRequest {
    pub vault_id: String,
    pub builder_id: String,
    pub share_class_id: String,
    pub deposit_intent_ids: Vec<String>,
    pub withdraw_intent_ids: Vec<String>,
    pub swap_route_ids: Vec<String>,
    pub solver_quote_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub net_deposit_commitment_root: String,
    pub net_burn_commitment_root: String,
    pub minted_share_root: String,
    pub burned_share_root: String,
    pub recursive_proof_input_root: String,
    pub target_settlement_asset_id: String,
    pub target_batch_privacy_set_size: u64,
    pub protocol_fee_bps: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MintBurnNettingBatchRecord {
    pub netting_batch_id: String,
    pub vault_id: String,
    pub builder_id: String,
    pub share_class_id: String,
    pub deposit_intent_ids: Vec<String>,
    pub withdraw_intent_ids: Vec<String>,
    pub swap_route_ids: Vec<String>,
    pub solver_quote_ids: Vec<String>,
    pub sponsor_reservation_ids: Vec<String>,
    pub deposit_root: String,
    pub withdraw_root: String,
    pub swap_route_root: String,
    pub solver_quote_root: String,
    pub sponsor_reservation_root: String,
    pub deposit_count: usize,
    pub withdraw_count: usize,
    pub swap_route_count: usize,
    pub net_deposit_commitment_root: String,
    pub net_burn_commitment_root: String,
    pub minted_share_root: String,
    pub burned_share_root: String,
    pub recursive_proof_input_root: String,
    pub target_settlement_asset_id: String,
    pub target_batch_privacy_set_size: u64,
    pub protocol_fee_bps: u64,
    pub status: NettingStatus,
    pub metadata_root: String,
    pub built_height: u64,
    pub expires_at_height: u64,
}

impl MintBurnNettingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "netting_batch_id": self.netting_batch_id,
            "vault_id": self.vault_id,
            "builder_id": self.builder_id,
            "share_class_id": self.share_class_id,
            "deposit_intent_id_root": root_from_strings("NETTING-BATCH-DEPOSIT-IDS", &self.deposit_intent_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "withdraw_intent_id_root": root_from_strings("NETTING-BATCH-WITHDRAW-IDS", &self.withdraw_intent_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "swap_route_id_root": root_from_strings("NETTING-BATCH-SWAP-IDS", &self.swap_route_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "solver_quote_id_root": root_from_strings("NETTING-BATCH-QUOTE-IDS", &self.solver_quote_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "sponsor_reservation_id_root": root_from_strings("NETTING-BATCH-SPONSOR-IDS", &self.sponsor_reservation_ids.iter().map(String::as_str).collect::<Vec<_>>()),
            "deposit_root": self.deposit_root,
            "withdraw_root": self.withdraw_root,
            "swap_route_root": self.swap_route_root,
            "solver_quote_root": self.solver_quote_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "deposit_count": self.deposit_count,
            "withdraw_count": self.withdraw_count,
            "swap_route_count": self.swap_route_count,
            "net_deposit_commitment_root": self.net_deposit_commitment_root,
            "net_burn_commitment_root": self.net_burn_commitment_root,
            "minted_share_root": self.minted_share_root,
            "burned_share_root": self.burned_share_root,
            "recursive_proof_input_root": self.recursive_proof_input_root,
            "target_settlement_asset_id": self.target_settlement_asset_id,
            "target_batch_privacy_set_size": self.target_batch_privacy_set_size,
            "protocol_fee_bps": self.protocol_fee_bps,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "built_height": self.built_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishRecursiveProofReceiptRequest {
    pub netting_batch_id: String,
    pub publisher_id: String,
    pub recursive_proof_root: String,
    pub recursive_verifier_root: String,
    pub public_inputs_root: String,
    pub settlement_root: String,
    pub minted_shares: u64,
    pub burned_shares: u64,
    pub fee_paid: u64,
    pub rebate_pool: u64,
    pub finality_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RecursiveProofReceiptRecord {
    pub recursive_receipt_id: String,
    pub netting_batch_id: String,
    pub publisher_id: String,
    pub recursive_proof_root: String,
    pub recursive_verifier_root: String,
    pub public_inputs_root: String,
    pub settlement_root: String,
    pub minted_shares: u64,
    pub burned_shares: u64,
    pub fee_paid: u64,
    pub rebate_pool: u64,
    pub status: ReceiptStatus,
    pub published_height: u64,
    pub finality_height: u64,
}

impl RecursiveProofReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "recursive_receipt_id": self.recursive_receipt_id,
            "netting_batch_id": self.netting_batch_id,
            "publisher_id": self.publisher_id,
            "recursive_proof_root": self.recursive_proof_root,
            "recursive_verifier_root": self.recursive_verifier_root,
            "public_inputs_root": self.public_inputs_root,
            "settlement_root": self.settlement_root,
            "minted_shares": self.minted_shares,
            "burned_shares": self.burned_shares,
            "fee_paid": self.fee_paid,
            "rebate_pool": self.rebate_pool,
            "status": self.status.as_str(),
            "published_height": self.published_height,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestComplianceRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub attestor_id: String,
    pub policy_version: String,
    pub compliance_root: String,
    pub sanctions_root: String,
    pub jurisdiction_root: String,
    pub verdict: ComplianceVerdict,
    pub valid_for_blocks: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceAttestationRecord {
    pub compliance_attestation_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub attestor_id: String,
    pub policy_version: String,
    pub compliance_root: String,
    pub sanctions_root: String,
    pub jurisdiction_root: String,
    pub verdict: ComplianceVerdict,
    pub metadata_root: String,
    pub attested_height: u64,
    pub expires_at_height: u64,
}

impl ComplianceAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "compliance_attestation_id": self.compliance_attestation_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "attestor_id": self.attestor_id,
            "policy_version": self.policy_version,
            "compliance_root": self.compliance_root,
            "sanctions_root": self.sanctions_root,
            "jurisdiction_root": self.jurisdiction_root,
            "verdict": self.verdict.as_str(),
            "metadata_root": self.metadata_root,
            "attested_height": self.attested_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OpenNullifierFenceRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub origin_nullifier: String,
    pub encrypted_fence_root: String,
    pub lock_commitment_root: String,
    pub lock_owner_id: String,
    pub expires_in_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NullifierFenceRecord {
    pub nullifier_fence_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub origin_nullifier: String,
    pub encrypted_fence_root: String,
    pub lock_commitment_root: String,
    pub lock_owner_id: String,
    pub status: FenceStatus,
    pub opened_height: u64,
    pub expires_at_height: u64,
}

impl NullifierFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "nullifier_fence_id": self.nullifier_fence_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "origin_nullifier_root": root_from_strings("NULLIFIER-FENCE-ORIGIN", &[&self.origin_nullifier]),
            "encrypted_fence_root": self.encrypted_fence_root,
            "lock_commitment_root": self.lock_commitment_root,
            "lock_owner_id": self.lock_owner_id,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkLiquidationRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub risk_engine_id: String,
    pub collateral_root: String,
    pub debt_root: String,
    pub trigger_price_root: String,
    pub insurance_take_rate_bps: u64,
    pub grace_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidationLinkRecord {
    pub liquidation_link_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub risk_engine_id: String,
    pub collateral_root: String,
    pub debt_root: String,
    pub trigger_price_root: String,
    pub insurance_take_rate_bps: u64,
    pub grace_blocks: u64,
    pub status: LiquidationStatus,
    pub linked_height: u64,
    pub trigger_height: u64,
}

impl LiquidationLinkRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "liquidation_link_id": self.liquidation_link_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "risk_engine_id": self.risk_engine_id,
            "collateral_root": self.collateral_root,
            "debt_root": self.debt_root,
            "trigger_price_root": self.trigger_price_root,
            "insurance_take_rate_bps": self.insurance_take_rate_bps,
            "grace_blocks": self.grace_blocks,
            "status": self.status.as_str(),
            "linked_height": self.linked_height,
            "trigger_height": self.trigger_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LinkBackstopRequest {
    pub vault_id: String,
    pub subject_id: String,
    pub provider_id: String,
    pub backstop_asset_id: String,
    pub reserve_commitment_root: String,
    pub draw_limit: u64,
    pub fee_bps: u64,
    pub metadata: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackstopLinkRecord {
    pub backstop_link_id: String,
    pub vault_id: String,
    pub subject_id: String,
    pub provider_id: String,
    pub backstop_asset_id: String,
    pub reserve_commitment_root: String,
    pub draw_limit: u64,
    pub fee_bps: u64,
    pub status: BackstopStatus,
    pub metadata_root: String,
    pub linked_height: u64,
}

impl BackstopLinkRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "backstop_link_id": self.backstop_link_id,
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "provider_id": self.provider_id,
            "backstop_asset_id": self.backstop_asset_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "draw_limit": self.draw_limit,
            "fee_bps": self.fee_bps,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
            "linked_height": self.linked_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: EventKind,
    pub vault_id: String,
    pub subject_id: String,
    pub related_root: String,
    pub height: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "vault_id": self.vault_id,
            "subject_id": self.subject_id,
            "related_root": self.related_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub vaults: BTreeMap<String, VaultRecord>,
    pub share_classes: BTreeMap<String, VaultShareClassRecord>,
    pub deposit_intents: BTreeMap<String, DepositIntentRecord>,
    pub withdraw_intents: BTreeMap<String, WithdrawIntentRecord>,
    pub swap_routes: BTreeMap<String, ConfidentialSwapRouteRecord>,
    pub route_legs: BTreeMap<String, Vec<RouteLeg>>,
    pub lp_positions: BTreeMap<String, LpSharePositionRecord>,
    pub netting_batches: BTreeMap<String, MintBurnNettingBatchRecord>,
    pub solver_quotes: BTreeMap<String, SolverQuoteRecord>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservationRecord>,
    pub recursive_receipts: BTreeMap<String, RecursiveProofReceiptRecord>,
    pub compliance_attestations: BTreeMap<String, ComplianceAttestationRecord>,
    pub nullifier_fences: BTreeMap<String, NullifierFenceRecord>,
    pub liquidation_links: BTreeMap<String, LiquidationLinkRecord>,
    pub backstop_links: BTreeMap<String, BackstopLinkRecord>,
    pub events: BTreeMap<String, RuntimeEvent>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        Self::with_config(Config::default())
    }
}

impl State {
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            vaults: BTreeMap::new(),
            share_classes: BTreeMap::new(),
            deposit_intents: BTreeMap::new(),
            withdraw_intents: BTreeMap::new(),
            swap_routes: BTreeMap::new(),
            route_legs: BTreeMap::new(),
            lp_positions: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            solver_quotes: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            recursive_receipts: BTreeMap::new(),
            compliance_attestations: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            liquidation_links: BTreeMap::new(),
            backstop_links: BTreeMap::new(),
            events: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();

        let vault = state
            .register_vault(RegisterVaultRequest {
                operator_id: "devnet-router-ops-0".to_string(),
                vault_label: "devnet-private-yield-router".to_string(),
                vault_flavor: VaultFlavor::YieldRouter,
                fee_model_root: deterministic_root(
                    "fee-model",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                asset_commitment_root: deterministic_root(
                    "asset-commitment",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                policy_root: deterministic_root(
                    "policy",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                compliance_root: deterministic_root(
                    "compliance",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                liquidation_root: deterministic_root(
                    "liquidation",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                backstop_root: deterministic_root(
                    "backstop",
                    &[HashPart::Str("devnet"), HashPart::Str("yield-router")],
                ),
                min_deposit_amount: 1_000,
                min_withdraw_amount: 500,
                min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
                max_solver_fee_bps: DEFAULT_MAX_SOLVER_FEE_BPS,
                allow_external_liquidity: true,
                allow_private_lp: true,
                metadata: json!({
                    "lane": "devnet",
                    "thesis": "fast-low-fee-privacy",
                    "router": "pq-confidential-tokenized-vault"
                }),
            })
            .expect("devnet vault");

        let share_class = state
            .define_share_class(DefineShareClassRequest {
                vault_id: vault.vault_id.clone(),
                share_symbol: "dYLD".to_string(),
                share_class_kind: ShareClassKind::Senior,
                share_asset_id: "asset:dyld-devnet".to_string(),
                supply_cap: 10_000_000,
                management_fee_bps: 45,
                performance_fee_bps: 250,
                transfer_restricted: true,
                allow_mint_netting: true,
                allow_burn_netting: true,
                metadata: json!({"risk_bucket": "blue", "transfer_path": "compliance-attested"}),
            })
            .expect("devnet share class");

        let deposit = state
            .submit_deposit_intent(SubmitDepositIntentRequest {
                vault_id: vault.vault_id.clone(),
                share_class_id: share_class.share_class_id.clone(),
                depositor_id: "devnet-user-0".to_string(),
                input_asset_id: "asset:xmr-wrapper-devnet".to_string(),
                encrypted_amount_root: deterministic_root(
                    "deposit-amount",
                    &[HashPart::Str("devnet-user-0"), HashPart::Str("0")],
                ),
                encrypted_note_root: deterministic_root(
                    "deposit-note",
                    &[HashPart::Str("devnet-user-0"), HashPart::Str("0")],
                ),
                recipient_commitment: deterministic_root(
                    "recipient",
                    &[HashPart::Str("devnet-user-0"), HashPart::Str("shares")],
                ),
                max_share_slippage_bps: 60,
                max_fee_bps: 9,
                privacy_set_size: DEFAULT_TARGET_ROUTE_PRIVACY_SET_SIZE,
                nullifier: "devnet-deposit-nullifier-0".to_string(),
                route_preference: RoutePriority::Balanced,
                metadata: json!({"origin": "wallet", "bucket": "core"}),
            })
            .expect("devnet deposit");

        let withdraw = state
            .submit_withdraw_intent(SubmitWithdrawIntentRequest {
                vault_id: vault.vault_id.clone(),
                share_class_id: share_class.share_class_id.clone(),
                withdrawer_id: "devnet-user-1".to_string(),
                output_asset_id: "asset:xusd-devnet".to_string(),
                encrypted_share_amount_root: deterministic_root(
                    "withdraw-share-amount",
                    &[HashPart::Str("devnet-user-1"), HashPart::Str("0")],
                ),
                encrypted_note_root: deterministic_root(
                    "withdraw-note",
                    &[HashPart::Str("devnet-user-1"), HashPart::Str("0")],
                ),
                recipient_commitment: deterministic_root(
                    "withdraw-recipient",
                    &[HashPart::Str("devnet-user-1"), HashPart::Str("cash")],
                ),
                min_output_amount_root: deterministic_root(
                    "withdraw-min-output",
                    &[HashPart::Str("devnet-user-1"), HashPart::Str("0")],
                ),
                max_fee_bps: 8,
                privacy_set_size: DEFAULT_TARGET_ROUTE_PRIVACY_SET_SIZE,
                nullifier: "devnet-withdraw-nullifier-0".to_string(),
                route_preference: RoutePriority::Cheap,
                metadata: json!({"origin": "wallet", "bucket": "rebalance"}),
            })
            .expect("devnet withdraw");

        let swap_route = state
            .submit_swap_route_intent(SubmitSwapRouteIntentRequest {
                vault_id: vault.vault_id.clone(),
                share_class_id: share_class.share_class_id.clone(),
                intent_subject_id: deposit.deposit_intent_id.clone(),
                encrypted_in_amount_root: deterministic_root(
                    "swap-in",
                    &[HashPart::Str("devnet"), HashPart::Str("deposit")],
                ),
                encrypted_min_out_amount_root: deterministic_root(
                    "swap-out",
                    &[HashPart::Str("devnet"), HashPart::Str("deposit")],
                ),
                route_priority: RoutePriority::Fast,
                route_leg_commitments: vec![
                    RouteLeg {
                        leg_index: 0,
                        leg_kind: SwapLegKind::StablePool,
                        market_id: "market:stable-devnet".to_string(),
                        input_asset_id: "asset:xmr-wrapper-devnet".to_string(),
                        output_asset_id: "asset:xusd-devnet".to_string(),
                        commitment_root: deterministic_root(
                            "leg-0",
                            &[HashPart::Str("stable"), HashPart::Str("devnet")],
                        ),
                        fee_limit_bps: 4,
                    },
                    RouteLeg {
                        leg_index: 1,
                        leg_kind: SwapLegKind::VaultShareSwap,
                        market_id: "market:vault-share-devnet".to_string(),
                        input_asset_id: "asset:xusd-devnet".to_string(),
                        output_asset_id: share_class.share_asset_id.clone(),
                        commitment_root: deterministic_root(
                            "leg-1",
                            &[HashPart::Str("share"), HashPart::Str("devnet")],
                        ),
                        fee_limit_bps: 5,
                    },
                ],
                destination_commitment: deterministic_root(
                    "destination",
                    &[HashPart::Str("devnet"), HashPart::Str("shares")],
                ),
                max_total_fee_bps: 10,
                max_solver_fee_bps: 8,
                privacy_set_size: DEFAULT_TARGET_ROUTE_PRIVACY_SET_SIZE,
                nullifier: "devnet-swap-nullifier-0".to_string(),
                metadata: json!({"route_type": "deposit-mint"}),
            })
            .expect("devnet swap route");

        let quote = state
            .attach_solver_quote(AttachSolverQuoteRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: swap_route.swap_route_id.clone(),
                solver_id: "devnet-solver-0".to_string(),
                quote_commitment_root: deterministic_root(
                    "quote",
                    &[HashPart::Str("devnet-solver-0"), HashPart::Str("0")],
                ),
                route_output_root: deterministic_root(
                    "route-output",
                    &[HashPart::Str("devnet-solver-0"), HashPart::Str("0")],
                ),
                collateral_commitment_root: deterministic_root(
                    "solver-collateral",
                    &[HashPart::Str("devnet-solver-0"), HashPart::Str("0")],
                ),
                quoted_fee_bps: 6,
                sponsor_rebate_bps: 3,
                solver_collateral: 75_000,
                security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
                valid_for_blocks: 32,
                metadata: json!({"lane": "fast", "curve": "deterministic"}),
            })
            .expect("devnet quote");

        let sponsor = state
            .reserve_sponsor(ReserveSponsorRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: swap_route.swap_route_id.clone(),
                solver_quote_id: quote.solver_quote_id.clone(),
                sponsor_id: "devnet-sponsor-0".to_string(),
                escrow_commitment_root: deterministic_root(
                    "sponsor-escrow",
                    &[HashPart::Str("devnet-sponsor-0"), HashPart::Str("0")],
                ),
                reserved_fee_units: 15_000,
                max_user_fee_bps: 7,
                rebate_bps: 3,
                lane_id: "lane:low-fee-devnet".to_string(),
            })
            .expect("devnet sponsor");

        let batch = state
            .build_mint_burn_netting_batch(BuildMintBurnNettingBatchRequest {
                vault_id: vault.vault_id.clone(),
                builder_id: "devnet-builder-0".to_string(),
                share_class_id: share_class.share_class_id.clone(),
                deposit_intent_ids: vec![deposit.deposit_intent_id.clone()],
                withdraw_intent_ids: vec![withdraw.withdraw_intent_id.clone()],
                swap_route_ids: vec![swap_route.swap_route_id.clone()],
                solver_quote_ids: vec![quote.solver_quote_id.clone()],
                sponsor_reservation_ids: vec![sponsor.sponsor_reservation_id.clone()],
                net_deposit_commitment_root: deterministic_root(
                    "net-deposit",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                net_burn_commitment_root: deterministic_root(
                    "net-burn",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                minted_share_root: deterministic_root(
                    "minted-shares",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                burned_share_root: deterministic_root(
                    "burned-shares",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                recursive_proof_input_root: deterministic_root(
                    "recursive-input",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                target_settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
                target_batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
                protocol_fee_bps: 4,
                metadata: json!({"mode": "netted"}),
            })
            .expect("devnet batch");

        let finality_height = state.height + DEFAULT_RECEIPT_FINALITY_BLOCKS;
        state
            .publish_recursive_proof_receipt(PublishRecursiveProofReceiptRequest {
                netting_batch_id: batch.netting_batch_id.clone(),
                publisher_id: "devnet-publisher-0".to_string(),
                recursive_proof_root: deterministic_root(
                    "recursive-proof",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                recursive_verifier_root: deterministic_root(
                    "recursive-verifier",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                public_inputs_root: deterministic_root(
                    "public-inputs",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                settlement_root: deterministic_root(
                    "settlement",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                minted_shares: 1_500,
                burned_shares: 900,
                fee_paid: 1_200,
                rebate_pool: 420,
                finality_height,
            })
            .expect("devnet receipt");

        state
            .attest_compliance(AttestComplianceRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: deposit.deposit_intent_id.clone(),
                attestor_id: "devnet-compliance-0".to_string(),
                policy_version: "policy-devnet-1".to_string(),
                compliance_root: deterministic_root(
                    "compliance-attestation",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                sanctions_root: deterministic_root(
                    "sanctions",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                jurisdiction_root: deterministic_root(
                    "jurisdiction",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                verdict: ComplianceVerdict::Approved,
                valid_for_blocks: DEFAULT_COMPLIANCE_TTL_BLOCKS,
                metadata: json!({"tier": "green"}),
            })
            .expect("devnet compliance");

        state
            .open_nullifier_fence(OpenNullifierFenceRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: deposit.deposit_intent_id.clone(),
                origin_nullifier: "devnet-fence-nullifier-0".to_string(),
                encrypted_fence_root: deterministic_root(
                    "fence",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                lock_commitment_root: deterministic_root(
                    "lock",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                lock_owner_id: "devnet-ops-lock".to_string(),
                expires_in_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            })
            .expect("devnet fence");

        state
            .link_liquidation(LinkLiquidationRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: withdraw.withdraw_intent_id.clone(),
                risk_engine_id: "devnet-risk-0".to_string(),
                collateral_root: deterministic_root(
                    "collateral",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                debt_root: deterministic_root(
                    "debt",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                trigger_price_root: deterministic_root(
                    "trigger-price",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                insurance_take_rate_bps: 275,
                grace_blocks: 20,
            })
            .expect("devnet liquidation");

        state
            .link_backstop(LinkBackstopRequest {
                vault_id: vault.vault_id.clone(),
                subject_id: withdraw.withdraw_intent_id.clone(),
                provider_id: "devnet-backstop-0".to_string(),
                backstop_asset_id: "asset:backstop-xusd-devnet".to_string(),
                reserve_commitment_root: deterministic_root(
                    "backstop-reserve",
                    &[HashPart::Str("devnet"), HashPart::Str("0")],
                ),
                draw_limit: 500_000,
                fee_bps: 80,
                metadata: json!({"type": "first-loss"}),
            })
            .expect("devnet backstop");

        state
    }

    pub fn register_vault(&mut self, request: RegisterVaultRequest) -> Result<VaultRecord> {
        self.ensure_capacity("vault", self.vaults.len(), MAX_VAULTS)?;
        ensure_nonempty("operator_id", &request.operator_id)?;
        ensure_nonempty("vault_label", &request.vault_label)?;
        ensure_nonempty("fee_model_root", &request.fee_model_root)?;
        ensure_nonempty("asset_commitment_root", &request.asset_commitment_root)?;
        ensure_nonempty("policy_root", &request.policy_root)?;
        ensure_nonempty("compliance_root", &request.compliance_root)?;
        ensure_nonempty("liquidation_root", &request.liquidation_root)?;
        ensure_nonempty("backstop_root", &request.backstop_root)?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure_bps("max_solver_fee_bps", request.max_solver_fee_bps)?;
        if request.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("vault pq security below runtime minimum".to_string());
        }
        if request.max_user_fee_bps > self.config.max_user_fee_bps {
            return Err("vault max user fee exceeds runtime maximum".to_string());
        }
        if request.max_solver_fee_bps > self.config.max_solver_fee_bps {
            return Err("vault max solver fee exceeds runtime maximum".to_string());
        }
        let sequence = self.counters.vaults_registered + 1;
        let metadata_root = root_from_record("VAULT-METADATA", &request.metadata);
        let vault_id = vault_id(sequence, &request, &metadata_root);
        let record = VaultRecord {
            vault_id: vault_id.clone(),
            operator_id: request.operator_id,
            vault_label: request.vault_label,
            vault_flavor: request.vault_flavor,
            status: VaultStatus::Active,
            fee_model_root: request.fee_model_root,
            asset_commitment_root: request.asset_commitment_root,
            policy_root: request.policy_root,
            compliance_root: request.compliance_root,
            liquidation_root: request.liquidation_root,
            backstop_root: request.backstop_root,
            min_deposit_amount: request.min_deposit_amount,
            min_withdraw_amount: request.min_withdraw_amount,
            min_pq_security_bits: request.min_pq_security_bits,
            max_user_fee_bps: request.max_user_fee_bps,
            max_solver_fee_bps: request.max_solver_fee_bps,
            allow_external_liquidity: request.allow_external_liquidity,
            allow_private_lp: request.allow_private_lp,
            metadata_root,
            registered_height: self.height,
        };
        self.vaults.insert(vault_id.clone(), record.clone());
        self.counters.vaults_registered = sequence;
        self.record_event(
            EventKind::VaultRegistered,
            &vault_id,
            &vault_id,
            &record_root("vault-record", &record),
        );
        Ok(record)
    }

    pub fn define_share_class(
        &mut self,
        request: DefineShareClassRequest,
    ) -> Result<VaultShareClassRecord> {
        self.ensure_capacity("share class", self.share_classes.len(), MAX_SHARE_CLASSES)?;
        ensure_nonempty("vault_id", &request.vault_id)?;
        ensure_nonempty("share_symbol", &request.share_symbol)?;
        ensure_nonempty("share_asset_id", &request.share_asset_id)?;
        ensure_bps("management_fee_bps", request.management_fee_bps)?;
        ensure_bps("performance_fee_bps", request.performance_fee_bps)?;
        let share_class_count = self
            .share_classes
            .values()
            .filter(|share_class| share_class.vault_id == request.vault_id)
            .count();
        if share_class_count >= self.config.max_share_classes_per_vault {
            return Err("share class limit exceeded for vault".to_string());
        }
        self.require_vault(&request.vault_id)?;
        let sequence = self.counters.share_classes_defined + 1;
        let metadata_root = root_from_record("SHARE-CLASS-METADATA", &request.metadata);
        let share_class_id = share_class_id(sequence, &request, &metadata_root);
        let record = VaultShareClassRecord {
            share_class_id: share_class_id.clone(),
            vault_id: request.vault_id.clone(),
            share_symbol: request.share_symbol,
            share_class_kind: request.share_class_kind,
            share_asset_id: request.share_asset_id,
            supply_cap: request.supply_cap,
            minted_supply: 0,
            burned_supply: 0,
            management_fee_bps: request.management_fee_bps,
            performance_fee_bps: request.performance_fee_bps,
            transfer_restricted: request.transfer_restricted,
            allow_mint_netting: request.allow_mint_netting,
            allow_burn_netting: request.allow_burn_netting,
            metadata_root,
            defined_height: self.height,
        };
        self.share_classes
            .insert(share_class_id.clone(), record.clone());
        self.counters.share_classes_defined = sequence;
        self.record_event(
            EventKind::ShareClassDefined,
            &request.vault_id,
            &share_class_id,
            &record_root("share-class-record", &record),
        );
        Ok(record)
    }

    pub fn submit_deposit_intent(
        &mut self,
        request: SubmitDepositIntentRequest,
    ) -> Result<DepositIntentRecord> {
        self.ensure_capacity(
            "deposit intent",
            self.deposit_intents.len(),
            MAX_DEPOSIT_INTENTS,
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        if !vault.status.accepts_deposits() {
            return Err("vault does not accept deposits".to_string());
        }
        let share_class = self.require_share_class(&request.share_class_id, &request.vault_id)?;
        if !share_class.allow_mint_netting {
            return Err("share class does not allow mint netting".to_string());
        }
        ensure_nonempty("depositor_id", &request.depositor_id)?;
        ensure_nonempty("input_asset_id", &request.input_asset_id)?;
        ensure_nonempty("encrypted_amount_root", &request.encrypted_amount_root)?;
        ensure_nonempty("encrypted_note_root", &request.encrypted_note_root)?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_bps("max_share_slippage_bps", request.max_share_slippage_bps)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        self.validate_privacy_set(request.privacy_set_size)?;
        self.ensure_unused_nullifier(&request.nullifier)?;
        if request.max_fee_bps > vault.max_user_fee_bps {
            return Err("deposit max fee exceeds vault maximum".to_string());
        }
        let sequence = self.counters.deposit_intents_submitted + 1;
        let metadata_root = root_from_record("DEPOSIT-INTENT-METADATA", &request.metadata);
        let deposit_intent_id = deposit_intent_id(sequence, &request, &metadata_root);
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let record = DepositIntentRecord {
            deposit_intent_id: deposit_intent_id.clone(),
            vault_id: request.vault_id.clone(),
            share_class_id: request.share_class_id,
            depositor_id: request.depositor_id,
            input_asset_id: request.input_asset_id,
            encrypted_amount_root: request.encrypted_amount_root,
            encrypted_note_root: request.encrypted_note_root,
            recipient_commitment: request.recipient_commitment,
            max_share_slippage_bps: request.max_share_slippage_bps,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            nullifier: request.nullifier,
            route_preference: request.route_preference,
            status: IntentStatus::Submitted,
            metadata_root,
            submitted_height: self.height,
            expires_at_height: self.height + self.config.vault_intent_ttl_blocks,
        };
        self.deposit_intents
            .insert(deposit_intent_id.clone(), record.clone());
        self.counters.deposit_intents_submitted = sequence;
        self.record_event(
            EventKind::DepositSubmitted,
            &request.vault_id,
            &deposit_intent_id,
            &record_root("deposit-intent-record", &record),
        );
        Ok(record)
    }

    pub fn submit_withdraw_intent(
        &mut self,
        request: SubmitWithdrawIntentRequest,
    ) -> Result<WithdrawIntentRecord> {
        self.ensure_capacity(
            "withdraw intent",
            self.withdraw_intents.len(),
            MAX_WITHDRAW_INTENTS,
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        if !vault.status.accepts_withdrawals() {
            return Err("vault does not accept withdrawals".to_string());
        }
        let share_class = self.require_share_class(&request.share_class_id, &request.vault_id)?;
        if !share_class.allow_burn_netting {
            return Err("share class does not allow burn netting".to_string());
        }
        ensure_nonempty("withdrawer_id", &request.withdrawer_id)?;
        ensure_nonempty("output_asset_id", &request.output_asset_id)?;
        ensure_nonempty(
            "encrypted_share_amount_root",
            &request.encrypted_share_amount_root,
        )?;
        ensure_nonempty("encrypted_note_root", &request.encrypted_note_root)?;
        ensure_nonempty("recipient_commitment", &request.recipient_commitment)?;
        ensure_nonempty("min_output_amount_root", &request.min_output_amount_root)?;
        ensure_bps("max_fee_bps", request.max_fee_bps)?;
        self.validate_privacy_set(request.privacy_set_size)?;
        self.ensure_unused_nullifier(&request.nullifier)?;
        if request.max_fee_bps > vault.max_user_fee_bps {
            return Err("withdraw max fee exceeds vault maximum".to_string());
        }
        let sequence = self.counters.withdraw_intents_submitted + 1;
        let metadata_root = root_from_record("WITHDRAW-INTENT-METADATA", &request.metadata);
        let withdraw_intent_id = withdraw_intent_id(sequence, &request, &metadata_root);
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let record = WithdrawIntentRecord {
            withdraw_intent_id: withdraw_intent_id.clone(),
            vault_id: request.vault_id.clone(),
            share_class_id: request.share_class_id,
            withdrawer_id: request.withdrawer_id,
            output_asset_id: request.output_asset_id,
            encrypted_share_amount_root: request.encrypted_share_amount_root,
            encrypted_note_root: request.encrypted_note_root,
            recipient_commitment: request.recipient_commitment,
            min_output_amount_root: request.min_output_amount_root,
            max_fee_bps: request.max_fee_bps,
            privacy_set_size: request.privacy_set_size,
            nullifier: request.nullifier,
            route_preference: request.route_preference,
            status: IntentStatus::Submitted,
            metadata_root,
            submitted_height: self.height,
            expires_at_height: self.height + self.config.vault_intent_ttl_blocks,
        };
        self.withdraw_intents
            .insert(withdraw_intent_id.clone(), record.clone());
        self.counters.withdraw_intents_submitted = sequence;
        self.record_event(
            EventKind::WithdrawSubmitted,
            &request.vault_id,
            &withdraw_intent_id,
            &record_root("withdraw-intent-record", &record),
        );
        Ok(record)
    }

    pub fn submit_swap_route_intent(
        &mut self,
        request: SubmitSwapRouteIntentRequest,
    ) -> Result<ConfidentialSwapRouteRecord> {
        self.ensure_capacity("swap route", self.swap_routes.len(), MAX_SWAP_ROUTES)?;
        let vault = self.require_vault(&request.vault_id)?;
        if !vault.status.accepts_routing() {
            return Err("vault does not accept routing".to_string());
        }
        self.require_share_class(&request.share_class_id, &request.vault_id)?;
        ensure_nonempty("intent_subject_id", &request.intent_subject_id)?;
        ensure_nonempty(
            "encrypted_in_amount_root",
            &request.encrypted_in_amount_root,
        )?;
        ensure_nonempty(
            "encrypted_min_out_amount_root",
            &request.encrypted_min_out_amount_root,
        )?;
        ensure_nonempty("destination_commitment", &request.destination_commitment)?;
        ensure_bps("max_total_fee_bps", request.max_total_fee_bps)?;
        ensure_bps("max_solver_fee_bps", request.max_solver_fee_bps)?;
        self.validate_privacy_set(request.privacy_set_size)?;
        self.ensure_unused_nullifier(&request.nullifier)?;
        self.validate_route_legs(&request.route_leg_commitments)?;
        if request.max_total_fee_bps > vault.max_user_fee_bps {
            return Err("swap route total fee exceeds vault maximum".to_string());
        }
        if request.max_solver_fee_bps > vault.max_solver_fee_bps {
            return Err("swap route solver fee exceeds vault maximum".to_string());
        }
        let sequence = self.counters.swap_routes_submitted + 1;
        let route_leg_root = route_leg_root(&request.route_leg_commitments);
        let metadata_root = root_from_record("SWAP-ROUTE-METADATA", &request.metadata);
        let swap_route_id = swap_route_id(sequence, &request, &route_leg_root, &metadata_root);
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let record = ConfidentialSwapRouteRecord {
            swap_route_id: swap_route_id.clone(),
            vault_id: request.vault_id.clone(),
            share_class_id: request.share_class_id,
            intent_subject_id: request.intent_subject_id,
            encrypted_in_amount_root: request.encrypted_in_amount_root,
            encrypted_min_out_amount_root: request.encrypted_min_out_amount_root,
            route_priority: request.route_priority,
            route_leg_root,
            route_leg_count: request.route_leg_commitments.len(),
            destination_commitment: request.destination_commitment,
            max_total_fee_bps: request.max_total_fee_bps,
            max_solver_fee_bps: request.max_solver_fee_bps,
            privacy_set_size: request.privacy_set_size,
            nullifier: request.nullifier,
            status: IntentStatus::Submitted,
            metadata_root,
            submitted_height: self.height,
            expires_at_height: self.height + self.config.swap_route_ttl_blocks,
        };
        self.route_legs
            .insert(swap_route_id.clone(), request.route_leg_commitments);
        self.swap_routes
            .insert(swap_route_id.clone(), record.clone());
        self.counters.swap_routes_submitted = sequence;
        self.record_event(
            EventKind::SwapRouteSubmitted,
            &request.vault_id,
            &swap_route_id,
            &record_root("swap-route-record", &record),
        );
        Ok(record)
    }

    pub fn attach_lp_position(
        &mut self,
        request: AttachLpPositionRequest,
    ) -> Result<LpSharePositionRecord> {
        self.ensure_capacity("lp position", self.lp_positions.len(), MAX_LP_POSITIONS)?;
        let vault = self.require_vault(&request.vault_id)?;
        if !vault.allow_private_lp {
            return Err("vault does not allow private lp".to_string());
        }
        self.require_share_class(&request.share_class_id, &request.vault_id)?;
        ensure_nonempty("lp_provider_id", &request.lp_provider_id)?;
        ensure_nonempty("pool_id", &request.pool_id)?;
        ensure_nonempty("lp_asset_id", &request.lp_asset_id)?;
        ensure_nonempty("share_commitment_root", &request.share_commitment_root)?;
        ensure_nonempty("claimable_fee_root", &request.claimable_fee_root)?;
        ensure_bps("impermanent_loss_cap_bps", request.impermanent_loss_cap_bps)?;
        let sequence = self.counters.lp_positions_attached + 1;
        let metadata_root = root_from_record("LP-POSITION-METADATA", &request.metadata);
        let lp_position_id = lp_position_id(sequence, &request, &metadata_root);
        let record = LpSharePositionRecord {
            lp_position_id: lp_position_id.clone(),
            vault_id: request.vault_id.clone(),
            share_class_id: request.share_class_id,
            lp_provider_id: request.lp_provider_id,
            pool_id: request.pool_id,
            lp_asset_id: request.lp_asset_id,
            share_commitment_root: request.share_commitment_root,
            claimable_fee_root: request.claimable_fee_root,
            impermanent_loss_cap_bps: request.impermanent_loss_cap_bps,
            backstop_eligible: request.backstop_eligible,
            metadata_root,
            attached_height: self.height,
        };
        self.lp_positions
            .insert(lp_position_id.clone(), record.clone());
        self.counters.lp_positions_attached = sequence;
        self.record_event(
            EventKind::LpPositionAttached,
            &request.vault_id,
            &lp_position_id,
            &record_root("lp-position-record", &record),
        );
        Ok(record)
    }

    pub fn attach_solver_quote(
        &mut self,
        request: AttachSolverQuoteRequest,
    ) -> Result<SolverQuoteRecord> {
        self.ensure_capacity("solver quote", self.solver_quotes.len(), MAX_SOLVER_QUOTES)?;
        let vault = self.require_vault(&request.vault_id)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("solver_id", &request.solver_id)?;
        ensure_nonempty("quote_commitment_root", &request.quote_commitment_root)?;
        ensure_nonempty("route_output_root", &request.route_output_root)?;
        ensure_nonempty(
            "collateral_commitment_root",
            &request.collateral_commitment_root,
        )?;
        ensure_bps("quoted_fee_bps", request.quoted_fee_bps)?;
        ensure_bps("sponsor_rebate_bps", request.sponsor_rebate_bps)?;
        if request.quoted_fee_bps > vault.max_solver_fee_bps {
            return Err("solver quoted fee exceeds vault maximum".to_string());
        }
        if request.solver_collateral < self.config.min_solver_collateral {
            return Err("solver collateral below runtime minimum".to_string());
        }
        if request.security_bits < self.config.min_pq_security_bits {
            return Err("solver quote pq security below runtime minimum".to_string());
        }
        let sequence = self.counters.solver_quotes_attached + 1;
        let metadata_root = root_from_record("SOLVER-QUOTE-METADATA", &request.metadata);
        let solver_quote_id = solver_quote_id(sequence, &request, &metadata_root);
        let record = SolverQuoteRecord {
            solver_quote_id: solver_quote_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id,
            solver_id: request.solver_id,
            quote_commitment_root: request.quote_commitment_root,
            route_output_root: request.route_output_root,
            collateral_commitment_root: request.collateral_commitment_root,
            quoted_fee_bps: request.quoted_fee_bps,
            sponsor_rebate_bps: request.sponsor_rebate_bps,
            solver_collateral: request.solver_collateral,
            security_bits: request.security_bits,
            status: QuoteStatus::Attached,
            metadata_root,
            attached_height: self.height,
            expires_at_height: self.height + request.valid_for_blocks.max(1),
        };
        self.solver_quotes
            .insert(solver_quote_id.clone(), record.clone());
        self.counters.solver_quotes_attached = sequence;
        self.record_event(
            EventKind::SolverQuoteAttached,
            &request.vault_id,
            &solver_quote_id,
            &record_root("solver-quote-record", &record),
        );
        Ok(record)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveSponsorRequest,
    ) -> Result<SponsorReservationRecord> {
        self.ensure_capacity(
            "sponsor reservation",
            self.sponsor_reservations.len(),
            MAX_SPONSOR_RESERVATIONS,
        )?;
        let vault_max_user_fee_bps = self.require_vault(&request.vault_id)?.max_user_fee_bps;
        let quote = self
            .solver_quotes
            .get_mut(&request.solver_quote_id)
            .ok_or_else(|| "unknown solver quote".to_string())?;
        if quote.vault_id != request.vault_id {
            return Err("solver quote vault mismatch".to_string());
        }
        if quote.subject_id != request.subject_id {
            return Err("solver quote subject mismatch".to_string());
        }
        if !quote.status.live() {
            return Err("solver quote is not reservable".to_string());
        }
        ensure_nonempty("sponsor_id", &request.sponsor_id)?;
        ensure_nonempty("escrow_commitment_root", &request.escrow_commitment_root)?;
        ensure_nonempty("lane_id", &request.lane_id)?;
        ensure_bps("max_user_fee_bps", request.max_user_fee_bps)?;
        ensure_bps("rebate_bps", request.rebate_bps)?;
        if request.max_user_fee_bps > vault_max_user_fee_bps {
            return Err("sponsor reservation max user fee exceeds vault maximum".to_string());
        }
        if request.rebate_bps > request.max_user_fee_bps {
            return Err("rebate bps exceeds max user fee".to_string());
        }
        if request.reserved_fee_units < self.config.min_sponsor_escrow {
            return Err("sponsor escrow below runtime minimum".to_string());
        }
        let sequence = self.counters.sponsor_reservations_created + 1;
        let sponsor_reservation_id = sponsor_reservation_id(sequence, &request);
        quote.status = QuoteStatus::Reserved;
        let record = SponsorReservationRecord {
            sponsor_reservation_id: sponsor_reservation_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id,
            solver_quote_id: request.solver_quote_id,
            sponsor_id: request.sponsor_id,
            escrow_commitment_root: request.escrow_commitment_root,
            reserved_fee_units: request.reserved_fee_units,
            max_user_fee_bps: request.max_user_fee_bps,
            rebate_bps: request.rebate_bps,
            lane_id: request.lane_id,
            status: ReservationStatus::Reserved,
            reserved_height: self.height,
            expires_at_height: self.height + self.config.sponsor_ttl_blocks,
        };
        self.sponsor_reservations
            .insert(sponsor_reservation_id.clone(), record.clone());
        self.counters.sponsor_reservations_created = sequence;
        self.record_event(
            EventKind::SponsorReserved,
            &request.vault_id,
            &sponsor_reservation_id,
            &record_root("sponsor-reservation-record", &record),
        );
        Ok(record)
    }

    pub fn build_mint_burn_netting_batch(
        &mut self,
        request: BuildMintBurnNettingBatchRequest,
    ) -> Result<MintBurnNettingBatchRecord> {
        self.ensure_capacity(
            "netting batch",
            self.netting_batches.len(),
            MAX_NETTING_BATCHES,
        )?;
        self.require_vault(&request.vault_id)?;
        let share_class = self.require_share_class(&request.share_class_id, &request.vault_id)?;
        if !share_class.allow_mint_netting && !request.deposit_intent_ids.is_empty() {
            return Err("share class does not allow mint netting".to_string());
        }
        if !share_class.allow_burn_netting && !request.withdraw_intent_ids.is_empty() {
            return Err("share class does not allow burn netting".to_string());
        }
        ensure_nonempty("builder_id", &request.builder_id)?;
        ensure_nonempty(
            "net_deposit_commitment_root",
            &request.net_deposit_commitment_root,
        )?;
        ensure_nonempty(
            "net_burn_commitment_root",
            &request.net_burn_commitment_root,
        )?;
        ensure_nonempty("minted_share_root", &request.minted_share_root)?;
        ensure_nonempty("burned_share_root", &request.burned_share_root)?;
        ensure_nonempty(
            "recursive_proof_input_root",
            &request.recursive_proof_input_root,
        )?;
        ensure_nonempty(
            "target_settlement_asset_id",
            &request.target_settlement_asset_id,
        )?;
        ensure_bps("protocol_fee_bps", request.protocol_fee_bps)?;
        if request.protocol_fee_bps > self.config.max_protocol_fee_bps {
            return Err("protocol fee exceeds runtime maximum".to_string());
        }
        if request.target_batch_privacy_set_size < self.config.batch_privacy_set_size {
            return Err("batch privacy set below runtime target".to_string());
        }
        let item_count = request.deposit_intent_ids.len()
            + request.withdraw_intent_ids.len()
            + request.swap_route_ids.len();
        if item_count == 0 {
            return Err("netting batch must include at least one intent".to_string());
        }
        if item_count > self.config.max_batch_items {
            return Err("netting batch item limit exceeded".to_string());
        }
        for deposit_intent_id in &request.deposit_intent_ids {
            let deposit = self
                .deposit_intents
                .get(deposit_intent_id)
                .ok_or_else(|| format!("unknown deposit intent {deposit_intent_id}"))?;
            if deposit.vault_id != request.vault_id
                || deposit.share_class_id != request.share_class_id
            {
                return Err("deposit intent batch mismatch".to_string());
            }
            if !deposit.status.live() {
                return Err("deposit intent is not batchable".to_string());
            }
        }
        for withdraw_intent_id in &request.withdraw_intent_ids {
            let withdraw = self
                .withdraw_intents
                .get(withdraw_intent_id)
                .ok_or_else(|| format!("unknown withdraw intent {withdraw_intent_id}"))?;
            if withdraw.vault_id != request.vault_id
                || withdraw.share_class_id != request.share_class_id
            {
                return Err("withdraw intent batch mismatch".to_string());
            }
            if !withdraw.status.live() {
                return Err("withdraw intent is not batchable".to_string());
            }
        }
        for swap_route_id in &request.swap_route_ids {
            let route = self
                .swap_routes
                .get(swap_route_id)
                .ok_or_else(|| format!("unknown swap route {swap_route_id}"))?;
            if route.vault_id != request.vault_id || route.share_class_id != request.share_class_id
            {
                return Err("swap route batch mismatch".to_string());
            }
            if !route.status.live() {
                return Err("swap route is not batchable".to_string());
            }
        }
        for solver_quote_id in &request.solver_quote_ids {
            let quote = self
                .solver_quotes
                .get(solver_quote_id)
                .ok_or_else(|| format!("unknown solver quote {solver_quote_id}"))?;
            if quote.vault_id != request.vault_id {
                return Err("solver quote vault mismatch".to_string());
            }
            if !quote.status.live() {
                return Err("solver quote is not batchable".to_string());
            }
        }
        for sponsor_reservation_id in &request.sponsor_reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(sponsor_reservation_id)
                .ok_or_else(|| format!("unknown sponsor reservation {sponsor_reservation_id}"))?;
            if reservation.vault_id != request.vault_id {
                return Err("sponsor reservation vault mismatch".to_string());
            }
            if reservation.status != ReservationStatus::Reserved {
                return Err("sponsor reservation is not consumable".to_string());
            }
        }
        let sequence = self.counters.netting_batches_built + 1;
        let deposit_root = root_from_strings(
            "NETTING-BATCH-DEPOSITS",
            &request
                .deposit_intent_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let withdraw_root = root_from_strings(
            "NETTING-BATCH-WITHDRAWS",
            &request
                .withdraw_intent_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let swap_route_root = root_from_strings(
            "NETTING-BATCH-SWAP-ROUTES",
            &request
                .swap_route_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let solver_quote_root = root_from_strings(
            "NETTING-BATCH-SOLVER-QUOTES",
            &request
                .solver_quote_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let sponsor_reservation_root = root_from_strings(
            "NETTING-BATCH-SPONSORS",
            &request
                .sponsor_reservation_ids
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let metadata_root = root_from_record("NETTING-BATCH-METADATA", &request.metadata);
        let netting_batch_id = netting_batch_id(
            sequence,
            &request,
            &deposit_root,
            &withdraw_root,
            &swap_route_root,
            &solver_quote_root,
            &sponsor_reservation_root,
            &metadata_root,
        );
        let deposit_count = request.deposit_intent_ids.len();
        let withdraw_count = request.withdraw_intent_ids.len();
        let swap_route_count = request.swap_route_ids.len();
        for deposit_intent_id in &request.deposit_intent_ids {
            if let Some(deposit) = self.deposit_intents.get_mut(deposit_intent_id) {
                deposit.status = IntentStatus::Netted;
            }
        }
        for withdraw_intent_id in &request.withdraw_intent_ids {
            if let Some(withdraw) = self.withdraw_intents.get_mut(withdraw_intent_id) {
                withdraw.status = IntentStatus::Netted;
            }
        }
        for swap_route_id in &request.swap_route_ids {
            if let Some(route) = self.swap_routes.get_mut(swap_route_id) {
                route.status = IntentStatus::Netted;
            }
        }
        for solver_quote_id in &request.solver_quote_ids {
            if let Some(quote) = self.solver_quotes.get_mut(solver_quote_id) {
                quote.status = QuoteStatus::Accepted;
            }
        }
        for sponsor_reservation_id in &request.sponsor_reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(sponsor_reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let record = MintBurnNettingBatchRecord {
            netting_batch_id: netting_batch_id.clone(),
            vault_id: request.vault_id.clone(),
            builder_id: request.builder_id,
            share_class_id: request.share_class_id,
            deposit_intent_ids: request.deposit_intent_ids,
            withdraw_intent_ids: request.withdraw_intent_ids,
            swap_route_ids: request.swap_route_ids,
            solver_quote_ids: request.solver_quote_ids,
            sponsor_reservation_ids: request.sponsor_reservation_ids,
            deposit_root,
            withdraw_root,
            swap_route_root,
            solver_quote_root,
            sponsor_reservation_root,
            deposit_count,
            withdraw_count,
            swap_route_count,
            net_deposit_commitment_root: request.net_deposit_commitment_root,
            net_burn_commitment_root: request.net_burn_commitment_root,
            minted_share_root: request.minted_share_root,
            burned_share_root: request.burned_share_root,
            recursive_proof_input_root: request.recursive_proof_input_root,
            target_settlement_asset_id: request.target_settlement_asset_id,
            target_batch_privacy_set_size: request.target_batch_privacy_set_size,
            protocol_fee_bps: request.protocol_fee_bps,
            status: NettingStatus::Proving,
            metadata_root,
            built_height: self.height,
            expires_at_height: self.height + self.config.swap_route_ttl_blocks,
        };
        self.netting_batches
            .insert(netting_batch_id.clone(), record.clone());
        self.counters.netting_batches_built = sequence;
        self.record_event(
            EventKind::NettingBatchBuilt,
            &request.vault_id,
            &netting_batch_id,
            &record_root("netting-batch-record", &record),
        );
        Ok(record)
    }

    pub fn publish_recursive_proof_receipt(
        &mut self,
        request: PublishRecursiveProofReceiptRequest,
    ) -> Result<RecursiveProofReceiptRecord> {
        self.ensure_capacity(
            "recursive receipt",
            self.recursive_receipts.len(),
            MAX_RECEIPTS,
        )?;
        let (vault_id, share_class_id) = {
            let batch = self
                .netting_batches
                .get_mut(&request.netting_batch_id)
                .ok_or_else(|| "unknown netting batch".to_string())?;
            if !batch.status.live() {
                return Err("netting batch is not receiptable".to_string());
            }
            batch.status = NettingStatus::Receipted;
            (batch.vault_id.clone(), batch.share_class_id.clone())
        };
        ensure_nonempty("publisher_id", &request.publisher_id)?;
        ensure_nonempty("recursive_proof_root", &request.recursive_proof_root)?;
        ensure_nonempty("recursive_verifier_root", &request.recursive_verifier_root)?;
        ensure_nonempty("public_inputs_root", &request.public_inputs_root)?;
        ensure_nonempty("settlement_root", &request.settlement_root)?;
        let sequence = self.counters.receipts_published + 1;
        let recursive_receipt_id = recursive_receipt_id(sequence, &request);
        let record = RecursiveProofReceiptRecord {
            recursive_receipt_id: recursive_receipt_id.clone(),
            netting_batch_id: request.netting_batch_id.clone(),
            publisher_id: request.publisher_id,
            recursive_proof_root: request.recursive_proof_root,
            recursive_verifier_root: request.recursive_verifier_root,
            public_inputs_root: request.public_inputs_root,
            settlement_root: request.settlement_root,
            minted_shares: request.minted_shares,
            burned_shares: request.burned_shares,
            fee_paid: request.fee_paid,
            rebate_pool: request.rebate_pool,
            status: ReceiptStatus::Published,
            published_height: self.height,
            finality_height: request.finality_height,
        };
        if let Some(share_class) = self.share_classes.get_mut(&share_class_id) {
            share_class.minted_supply = share_class
                .minted_supply
                .saturating_add(request.minted_shares);
            share_class.burned_supply = share_class
                .burned_supply
                .saturating_add(request.burned_shares);
        }
        self.mark_subjects_receipted(&request.netting_batch_id);
        self.recursive_receipts
            .insert(recursive_receipt_id.clone(), record.clone());
        self.counters.receipts_published = sequence;
        self.record_event(
            EventKind::ReceiptPublished,
            &vault_id,
            &recursive_receipt_id,
            &record_root("recursive-receipt-record", &record),
        );
        Ok(record)
    }

    pub fn attest_compliance(
        &mut self,
        request: AttestComplianceRequest,
    ) -> Result<ComplianceAttestationRecord> {
        self.ensure_capacity(
            "compliance attestation",
            self.compliance_attestations.len(),
            MAX_COMPLIANCE_ATTESTATIONS,
        )?;
        self.require_vault(&request.vault_id)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("attestor_id", &request.attestor_id)?;
        ensure_nonempty("policy_version", &request.policy_version)?;
        ensure_nonempty("compliance_root", &request.compliance_root)?;
        ensure_nonempty("sanctions_root", &request.sanctions_root)?;
        ensure_nonempty("jurisdiction_root", &request.jurisdiction_root)?;
        let sequence = self.counters.compliance_attestations_recorded + 1;
        let metadata_root = root_from_record("COMPLIANCE-ATTESTATION-METADATA", &request.metadata);
        let compliance_attestation_id =
            compliance_attestation_id(sequence, &request, &metadata_root);
        let record = ComplianceAttestationRecord {
            compliance_attestation_id: compliance_attestation_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id.clone(),
            attestor_id: request.attestor_id,
            policy_version: request.policy_version,
            compliance_root: request.compliance_root,
            sanctions_root: request.sanctions_root,
            jurisdiction_root: request.jurisdiction_root,
            verdict: request.verdict,
            metadata_root,
            attested_height: self.height,
            expires_at_height: self.height + request.valid_for_blocks.max(1),
        };
        self.apply_compliance_verdict(&request.subject_id, request.verdict);
        self.compliance_attestations
            .insert(compliance_attestation_id.clone(), record.clone());
        self.counters.compliance_attestations_recorded = sequence;
        self.record_event(
            EventKind::ComplianceAttested,
            &request.vault_id,
            &compliance_attestation_id,
            &record_root("compliance-attestation-record", &record),
        );
        Ok(record)
    }

    pub fn open_nullifier_fence(
        &mut self,
        request: OpenNullifierFenceRequest,
    ) -> Result<NullifierFenceRecord> {
        self.ensure_capacity("nullifier fence", self.nullifier_fences.len(), MAX_FENCES)?;
        self.require_vault(&request.vault_id)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("origin_nullifier", &request.origin_nullifier)?;
        ensure_nonempty("encrypted_fence_root", &request.encrypted_fence_root)?;
        ensure_nonempty("lock_commitment_root", &request.lock_commitment_root)?;
        ensure_nonempty("lock_owner_id", &request.lock_owner_id)?;
        self.ensure_unused_nullifier(&request.origin_nullifier)?;
        let sequence = self.counters.fences_opened + 1;
        let nullifier_fence_id = nullifier_fence_id(sequence, &request);
        self.consumed_nullifiers
            .insert(request.origin_nullifier.clone());
        let record = NullifierFenceRecord {
            nullifier_fence_id: nullifier_fence_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id,
            origin_nullifier: request.origin_nullifier,
            encrypted_fence_root: request.encrypted_fence_root,
            lock_commitment_root: request.lock_commitment_root,
            lock_owner_id: request.lock_owner_id,
            status: FenceStatus::Open,
            opened_height: self.height,
            expires_at_height: self.height + request.expires_in_blocks.max(1),
        };
        self.nullifier_fences
            .insert(nullifier_fence_id.clone(), record.clone());
        self.counters.fences_opened = sequence;
        self.record_event(
            EventKind::FenceOpened,
            &request.vault_id,
            &nullifier_fence_id,
            &record_root("nullifier-fence-record", &record),
        );
        Ok(record)
    }

    pub fn link_liquidation(
        &mut self,
        request: LinkLiquidationRequest,
    ) -> Result<LiquidationLinkRecord> {
        self.ensure_capacity(
            "liquidation link",
            self.liquidation_links.len(),
            MAX_LIQUIDATION_LINKS,
        )?;
        let vault = self.require_vault(&request.vault_id)?;
        if !vault.status.accepts_liquidation() {
            return Err("vault does not accept liquidation links".to_string());
        }
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("risk_engine_id", &request.risk_engine_id)?;
        ensure_nonempty("collateral_root", &request.collateral_root)?;
        ensure_nonempty("debt_root", &request.debt_root)?;
        ensure_nonempty("trigger_price_root", &request.trigger_price_root)?;
        ensure_bps("insurance_take_rate_bps", request.insurance_take_rate_bps)?;
        let sequence = self.counters.liquidation_links_created + 1;
        let liquidation_link_id = liquidation_link_id(sequence, &request);
        let record = LiquidationLinkRecord {
            liquidation_link_id: liquidation_link_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id,
            risk_engine_id: request.risk_engine_id,
            collateral_root: request.collateral_root,
            debt_root: request.debt_root,
            trigger_price_root: request.trigger_price_root,
            insurance_take_rate_bps: request.insurance_take_rate_bps,
            grace_blocks: request.grace_blocks,
            status: LiquidationStatus::Linked,
            linked_height: self.height,
            trigger_height: self.height + request.grace_blocks,
        };
        self.liquidation_links
            .insert(liquidation_link_id.clone(), record.clone());
        self.counters.liquidation_links_created = sequence;
        self.record_event(
            EventKind::LiquidationLinked,
            &request.vault_id,
            &liquidation_link_id,
            &record_root("liquidation-link-record", &record),
        );
        Ok(record)
    }

    pub fn link_backstop(&mut self, request: LinkBackstopRequest) -> Result<BackstopLinkRecord> {
        self.ensure_capacity(
            "backstop link",
            self.backstop_links.len(),
            MAX_BACKSTOP_LINKS,
        )?;
        self.require_vault(&request.vault_id)?;
        ensure_nonempty("subject_id", &request.subject_id)?;
        ensure_nonempty("provider_id", &request.provider_id)?;
        ensure_nonempty("backstop_asset_id", &request.backstop_asset_id)?;
        ensure_nonempty("reserve_commitment_root", &request.reserve_commitment_root)?;
        ensure_bps("fee_bps", request.fee_bps)?;
        let sequence = self.counters.backstop_links_created + 1;
        let metadata_root = root_from_record("BACKSTOP-LINK-METADATA", &request.metadata);
        let backstop_link_id = backstop_link_id(sequence, &request, &metadata_root);
        let record = BackstopLinkRecord {
            backstop_link_id: backstop_link_id.clone(),
            vault_id: request.vault_id.clone(),
            subject_id: request.subject_id,
            provider_id: request.provider_id,
            backstop_asset_id: request.backstop_asset_id,
            reserve_commitment_root: request.reserve_commitment_root,
            draw_limit: request.draw_limit,
            fee_bps: request.fee_bps,
            status: BackstopStatus::Registered,
            metadata_root,
            linked_height: self.height,
        };
        self.backstop_links
            .insert(backstop_link_id.clone(), record.clone());
        self.counters.backstop_links_created = sequence;
        self.record_event(
            EventKind::BackstopLinked,
            &request.vault_id,
            &backstop_link_id,
            &record_root("backstop-link-record", &record),
        );
        Ok(record)
    }

    pub fn finalize_recursive_receipt(&mut self, recursive_receipt_id: &str) -> Result<()> {
        let (netting_batch_id, receipt_root) = {
            let receipt = self
                .recursive_receipts
                .get_mut(recursive_receipt_id)
                .ok_or_else(|| "unknown recursive receipt".to_string())?;
            if matches!(
                receipt.status,
                ReceiptStatus::Disputed | ReceiptStatus::Expired
            ) {
                return Err("receipt cannot be finalized".to_string());
            }
            receipt.status = ReceiptStatus::Finalized;
            (
                receipt.netting_batch_id.clone(),
                record_root("recursive-receipt-record", receipt),
            )
        };
        let vault_id = if let Some(batch) = self.netting_batches.get_mut(&netting_batch_id) {
            batch.status = NettingStatus::Settled;
            Some(batch.vault_id.clone())
        } else {
            None
        };
        self.mark_subjects_settled(&netting_batch_id);
        if let Some(vault_id) = vault_id {
            self.record_event(
                EventKind::ReceiptFinalized,
                &vault_id,
                recursive_receipt_id,
                &receipt_root,
            );
        }
        Ok(())
    }

    pub fn advance_height(&mut self, height: u64) {
        if height > self.height {
            self.height = height;
        }
        self.expire_height_sensitive_records();
    }

    pub fn expire_height_sensitive_records(&mut self) {
        for deposit in self.deposit_intents.values_mut() {
            if deposit.status.live() && self.height > deposit.expires_at_height {
                deposit.status = IntentStatus::Expired;
                self.counters.intents_expired = self.counters.intents_expired.saturating_add(1);
            }
        }
        for withdraw in self.withdraw_intents.values_mut() {
            if withdraw.status.live() && self.height > withdraw.expires_at_height {
                withdraw.status = IntentStatus::Expired;
                self.counters.intents_expired = self.counters.intents_expired.saturating_add(1);
            }
        }
        for route in self.swap_routes.values_mut() {
            if route.status.live() && self.height > route.expires_at_height {
                route.status = IntentStatus::Expired;
                self.counters.intents_expired = self.counters.intents_expired.saturating_add(1);
            }
        }
        for quote in self.solver_quotes.values_mut() {
            if quote.status.live() && self.height > quote.expires_at_height {
                quote.status = QuoteStatus::Expired;
            }
        }
        for reservation in self.sponsor_reservations.values_mut() {
            if reservation.status == ReservationStatus::Reserved
                && self.height > reservation.expires_at_height
            {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for batch in self.netting_batches.values_mut() {
            if batch.status.live() && self.height > batch.expires_at_height {
                batch.status = NettingStatus::Expired;
            }
        }
        for attestation in self.compliance_attestations.values_mut() {
            if self.height > attestation.expires_at_height
                && attestation.verdict == ComplianceVerdict::NeedsReview
            {
                attestation.verdict = ComplianceVerdict::Rejected;
            }
        }
        for fence in self.nullifier_fences.values_mut() {
            if fence.status.live() && self.height > fence.expires_at_height {
                fence.status = FenceStatus::Expired;
            }
        }
        for receipt in self.recursive_receipts.values_mut() {
            if receipt.status == ReceiptStatus::Published && self.height > receipt.finality_height {
                receipt.status = ReceiptStatus::Finalized;
            }
        }
        for liquidation in self.liquidation_links.values_mut() {
            if matches!(
                liquidation.status,
                LiquidationStatus::Linked | LiquidationStatus::Pending
            ) && self.height > liquidation.trigger_height
            {
                liquidation.status = LiquidationStatus::Triggered;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            vault_root: map_root("TOKENIZED-VAULT-ROOT", &self.vaults),
            share_class_root: map_root("TOKENIZED-SHARE-CLASS-ROOT", &self.share_classes),
            deposit_intent_root: map_root("TOKENIZED-DEPOSIT-INTENT-ROOT", &self.deposit_intents),
            withdraw_intent_root: map_root(
                "TOKENIZED-WITHDRAW-INTENT-ROOT",
                &self.withdraw_intents,
            ),
            swap_route_root: map_root("TOKENIZED-SWAP-ROUTE-ROOT", &self.swap_routes),
            lp_position_root: map_root("TOKENIZED-LP-POSITION-ROOT", &self.lp_positions),
            netting_batch_root: map_root("TOKENIZED-NETTING-BATCH-ROOT", &self.netting_batches),
            solver_quote_root: map_root("TOKENIZED-SOLVER-QUOTE-ROOT", &self.solver_quotes),
            sponsor_reservation_root: map_root(
                "TOKENIZED-SPONSOR-RESERVATION-ROOT",
                &self.sponsor_reservations,
            ),
            recursive_receipt_root: map_root(
                "TOKENIZED-RECURSIVE-RECEIPT-ROOT",
                &self.recursive_receipts,
            ),
            compliance_attestation_root: map_root(
                "TOKENIZED-COMPLIANCE-ATTESTATION-ROOT",
                &self.compliance_attestations,
            ),
            fence_root: map_root("TOKENIZED-FENCE-ROOT", &self.nullifier_fences),
            liquidation_link_root: map_root(
                "TOKENIZED-LIQUIDATION-LINK-ROOT",
                &self.liquidation_links,
            ),
            backstop_link_root: map_root("TOKENIZED-BACKSTOP-LINK-ROOT", &self.backstop_links),
            event_root: map_root("TOKENIZED-EVENT-ROOT", &self.events),
            nullifier_root: set_root("TOKENIZED-NULLIFIER-ROOT", &self.consumed_nullifiers),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "public_record_scheme": PUBLIC_RECORD_SCHEME,
            "config": self.config.public_record(),
            "height": self.height,
            "counters": self.counters,
            "roots": roots.public_record(),
            "active_vaults": self.vaults.values().filter(|vault| vault.status == VaultStatus::Active).count(),
            "live_deposit_intents": self.deposit_intents.values().filter(|intent| intent.status.live()).count(),
            "live_withdraw_intents": self.withdraw_intents.values().filter(|intent| intent.status.live()).count(),
            "live_swap_routes": self.swap_routes.values().filter(|route| route.status.live()).count(),
            "live_solver_quotes": self.solver_quotes.values().filter(|quote| quote.status.live()).count(),
            "open_fences": self.nullifier_fences.values().filter(|fence| fence.status.live()).count(),
            "triggered_liquidations": self.liquidation_links.values().filter(|link| link.status == LiquidationStatus::Triggered).count(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        let state_root = state_root_from_record(&record);
        if let Some(map) = record.as_object_mut() {
            map.insert("state_root".to_string(), json!(state_root));
        }
        record
    }

    fn require_vault(&self, vault_id: &str) -> Result<&VaultRecord> {
        self.vaults
            .get(vault_id)
            .ok_or_else(|| "unknown vault".to_string())
    }

    fn require_share_class(
        &self,
        share_class_id: &str,
        vault_id: &str,
    ) -> Result<&VaultShareClassRecord> {
        let share_class = self
            .share_classes
            .get(share_class_id)
            .ok_or_else(|| "unknown share class".to_string())?;
        if share_class.vault_id != vault_id {
            return Err("share class vault mismatch".to_string());
        }
        Ok(share_class)
    }

    fn ensure_unused_nullifier(&self, nullifier: &str) -> Result<()> {
        ensure_nonempty("nullifier", nullifier)?;
        if self.consumed_nullifiers.contains(nullifier) {
            Err("nullifier already consumed".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_privacy_set(&self, size: u64) -> Result<()> {
        if size < self.config.min_privacy_set_size {
            Err("privacy set below runtime minimum".to_string())
        } else {
            Ok(())
        }
    }

    fn validate_route_legs(&self, legs: &[RouteLeg]) -> Result<()> {
        if legs.is_empty() {
            return Err("swap route requires at least one leg".to_string());
        }
        if legs.len() > self.config.max_route_legs {
            return Err("swap route exceeds maximum leg count".to_string());
        }
        let mut seen = BTreeSet::new();
        for leg in legs {
            ensure_nonempty("market_id", &leg.market_id)?;
            ensure_nonempty("input_asset_id", &leg.input_asset_id)?;
            ensure_nonempty("output_asset_id", &leg.output_asset_id)?;
            ensure_nonempty("commitment_root", &leg.commitment_root)?;
            ensure_bps("fee_limit_bps", leg.fee_limit_bps)?;
            if !seen.insert(leg.leg_index) {
                return Err("duplicate route leg index".to_string());
            }
        }
        Ok(())
    }

    fn apply_compliance_verdict(&mut self, subject_id: &str, verdict: ComplianceVerdict) {
        if let Some(intent) = self
            .deposit_intents
            .values_mut()
            .find(|intent| intent.deposit_intent_id == subject_id)
        {
            intent.status = match verdict {
                ComplianceVerdict::Approved => IntentStatus::Quoted,
                ComplianceVerdict::NeedsReview => IntentStatus::Fenced,
                ComplianceVerdict::Rejected | ComplianceVerdict::Sanctioned => {
                    IntentStatus::Rejected
                }
            };
            return;
        }
        if let Some(intent) = self
            .withdraw_intents
            .values_mut()
            .find(|intent| intent.withdraw_intent_id == subject_id)
        {
            intent.status = match verdict {
                ComplianceVerdict::Approved => IntentStatus::Quoted,
                ComplianceVerdict::NeedsReview => IntentStatus::Fenced,
                ComplianceVerdict::Rejected | ComplianceVerdict::Sanctioned => {
                    IntentStatus::Rejected
                }
            };
            return;
        }
        if let Some(route) = self
            .swap_routes
            .values_mut()
            .find(|route| route.swap_route_id == subject_id)
        {
            route.status = match verdict {
                ComplianceVerdict::Approved => IntentStatus::Quoted,
                ComplianceVerdict::NeedsReview => IntentStatus::Fenced,
                ComplianceVerdict::Rejected | ComplianceVerdict::Sanctioned => {
                    IntentStatus::Rejected
                }
            };
        }
    }

    fn mark_subjects_receipted(&mut self, netting_batch_id: &str) {
        if let Some(batch) = self.netting_batches.get(netting_batch_id) {
            let deposit_ids = batch.deposit_intent_ids.clone();
            let withdraw_ids = batch.withdraw_intent_ids.clone();
            let swap_ids = batch.swap_route_ids.clone();
            for id in &deposit_ids {
                if let Some(intent) = self.deposit_intents.get_mut(id) {
                    intent.status = IntentStatus::Receipted;
                }
            }
            for id in &withdraw_ids {
                if let Some(intent) = self.withdraw_intents.get_mut(id) {
                    intent.status = IntentStatus::Receipted;
                }
            }
            for id in &swap_ids {
                if let Some(route) = self.swap_routes.get_mut(id) {
                    route.status = IntentStatus::Receipted;
                }
            }
        }
    }

    fn mark_subjects_settled(&mut self, netting_batch_id: &str) {
        if let Some(batch) = self.netting_batches.get(netting_batch_id) {
            let deposit_ids = batch.deposit_intent_ids.clone();
            let withdraw_ids = batch.withdraw_intent_ids.clone();
            let swap_ids = batch.swap_route_ids.clone();
            for id in &deposit_ids {
                if let Some(intent) = self.deposit_intents.get_mut(id) {
                    intent.status = IntentStatus::Settled;
                }
            }
            for id in &withdraw_ids {
                if let Some(intent) = self.withdraw_intents.get_mut(id) {
                    intent.status = IntentStatus::Settled;
                }
            }
            for id in &swap_ids {
                if let Some(route) = self.swap_routes.get_mut(id) {
                    route.status = IntentStatus::Settled;
                }
            }
        }
    }

    fn record_event(
        &mut self,
        event_kind: EventKind,
        vault_id: &str,
        subject_id: &str,
        related_root: &str,
    ) {
        if self.events.len() >= MAX_EVENTS {
            return;
        }
        let event_id = runtime_event_id(
            event_kind,
            vault_id,
            subject_id,
            self.height,
            self.counters.events_recorded + 1,
        );
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind,
            vault_id: vault_id.to_string(),
            subject_id: subject_id.to_string(),
            related_root: related_root.to_string(),
            height: self.height,
        };
        self.events.insert(event_id, event);
        self.counters.events_recorded = self.counters.events_recorded.saturating_add(1);
    }

    fn ensure_capacity(&self, label: &str, len: usize, max: usize) -> Result<()> {
        if len >= max {
            Err(format!("{label} capacity exceeded"))
        } else {
            Ok(())
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_confidential_tokenized_vault_router_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

pub fn private_l2_pq_confidential_tokenized_vault_router_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn deterministic_root(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("private_l2_pq_confidential_tokenized_vault_router_runtime:{domain}"),
        parts,
        32,
    )
}

pub fn root_from_strings(domain: &str, parts: &[&str]) -> String {
    deterministic_root(
        domain,
        &parts.iter().copied().map(HashPart::Str).collect::<Vec<_>>(),
    )
}

pub fn root_from_record<T: Serialize>(domain: &str, value: &T) -> String {
    let value = serde_json::to_value(value).expect("serializable record");
    deterministic_root(domain, &[HashPart::Json(&value)])
}

pub fn record_root<T: Serialize>(domain: &str, value: &T) -> String {
    root_from_record(domain, value)
}

pub fn route_leg_root(legs: &[RouteLeg]) -> String {
    let leaves = legs
        .iter()
        .map(|leg| leg.public_record())
        .collect::<Vec<_>>();
    merkle_root("TOKENIZED-SWAP-ROUTE-LEG-ROOT", &leaves)
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value_root": record_root("MAP-ENTRY", value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(value: &Value) -> String {
    deterministic_root("state-root", &[HashPart::Json(value)])
}

pub fn vault_id(sequence: u64, request: &RegisterVaultRequest, metadata_root: &str) -> String {
    deterministic_root(
        "vault-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.operator_id),
            HashPart::Str(&request.vault_label),
            HashPart::Str(request.vault_flavor.as_str()),
            HashPart::Str(&request.asset_commitment_root),
            HashPart::Str(&request.policy_root),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn share_class_id(
    sequence: u64,
    request: &DefineShareClassRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "share-class-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_symbol),
            HashPart::Str(request.share_class_kind.as_str()),
            HashPart::Str(&request.share_asset_id),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn deposit_intent_id(
    sequence: u64,
    request: &SubmitDepositIntentRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "deposit-intent-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_class_id),
            HashPart::Str(&request.depositor_id),
            HashPart::Str(&request.input_asset_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn withdraw_intent_id(
    sequence: u64,
    request: &SubmitWithdrawIntentRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "withdraw-intent-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_class_id),
            HashPart::Str(&request.withdrawer_id),
            HashPart::Str(&request.output_asset_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn swap_route_id(
    sequence: u64,
    request: &SubmitSwapRouteIntentRequest,
    route_leg_root: &str,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "swap-route-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_class_id),
            HashPart::Str(&request.intent_subject_id),
            HashPart::Str(&request.nullifier),
            HashPart::Str(route_leg_root),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn lp_position_id(
    sequence: u64,
    request: &AttachLpPositionRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "lp-position-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.share_class_id),
            HashPart::Str(&request.lp_provider_id),
            HashPart::Str(&request.pool_id),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn solver_quote_id(
    sequence: u64,
    request: &AttachSolverQuoteRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "solver-quote-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.solver_id),
            HashPart::Str(&request.quote_commitment_root),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn sponsor_reservation_id(sequence: u64, request: &ReserveSponsorRequest) -> String {
    deterministic_root(
        "sponsor-reservation-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.solver_quote_id),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(&request.lane_id),
        ],
    )
}

pub fn netting_batch_id(
    sequence: u64,
    request: &BuildMintBurnNettingBatchRequest,
    deposit_root: &str,
    withdraw_root: &str,
    swap_route_root: &str,
    solver_quote_root: &str,
    sponsor_reservation_root: &str,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "netting-batch-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.builder_id),
            HashPart::Str(&request.share_class_id),
            HashPart::Str(deposit_root),
            HashPart::Str(withdraw_root),
            HashPart::Str(swap_route_root),
            HashPart::Str(solver_quote_root),
            HashPart::Str(sponsor_reservation_root),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn recursive_receipt_id(
    sequence: u64,
    request: &PublishRecursiveProofReceiptRequest,
) -> String {
    deterministic_root(
        "recursive-receipt-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.netting_batch_id),
            HashPart::Str(&request.publisher_id),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::Str(&request.settlement_root),
        ],
    )
}

pub fn compliance_attestation_id(
    sequence: u64,
    request: &AttestComplianceRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "compliance-attestation-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.attestor_id),
            HashPart::Str(&request.policy_version),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn nullifier_fence_id(sequence: u64, request: &OpenNullifierFenceRequest) -> String {
    deterministic_root(
        "nullifier-fence-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.origin_nullifier),
            HashPart::Str(&request.lock_owner_id),
        ],
    )
}

pub fn liquidation_link_id(sequence: u64, request: &LinkLiquidationRequest) -> String {
    deterministic_root(
        "liquidation-link-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.risk_engine_id),
            HashPart::Str(&request.trigger_price_root),
        ],
    )
}

pub fn backstop_link_id(
    sequence: u64,
    request: &LinkBackstopRequest,
    metadata_root: &str,
) -> String {
    deterministic_root(
        "backstop-link-id",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.vault_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.provider_id),
            HashPart::Str(&request.backstop_asset_id),
            HashPart::Str(metadata_root),
        ],
    )
}

pub fn runtime_event_id(
    event_kind: EventKind,
    vault_id: &str,
    subject_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    deterministic_root(
        "runtime-event-id",
        &[
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(vault_id),
            HashPart::Str(subject_id),
            HashPart::U64(height),
            HashPart::U64(nonce),
        ],
    )
}

pub fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

pub fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds bps maximum"))
    } else {
        Ok(())
    }
}
