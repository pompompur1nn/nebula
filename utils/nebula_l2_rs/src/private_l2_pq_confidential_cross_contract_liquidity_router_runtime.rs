use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialCrossContractLiquidityRouterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-cross-contract-liquidity-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_HEIGHT: u64 =
    1_148_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_L2_NETWORK:
    &str = "nebula-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_MONERO_NETWORK:
    &str = "monero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-cross-contract-router-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_VENUE_SCHEME: &str =
    "sealed-confidential-liquidity-venue-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_INTENT_SCHEME: &str =
    "sealed-cross-contract-liquidity-intent-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PQ_PROOF_SCHEME: &str =
    "pq-cross-contract-liquidity-authorization-proof-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_BATCH_SCHEME: &str =
    "routed-confidential-liquidity-netting-batch-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_RECEIPT_SCHEME: &str =
    "cross-contract-route-settlement-receipt-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_REBATE_SCHEME: &str =
    "private-cross-contract-route-fee-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_SLASHING_SCHEME: &str =
    "stale-invalid-confidential-router-slashing-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_VENUES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_INTENTS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_PROOFS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS:
    usize = 8_388_608;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_REBATES:
    usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_SLASHES:
    usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_ITEMS:
    usize = 16_384;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS:
    u64 = 128;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS:
    u64 = 48;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 10;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_ROUTER_FEE_BPS:
    u64 = 8;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS:
    u64 = 1_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_STALE_ROUTER_BLOCKS:
    u64 = 240;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LiquidityVenueKind {
    ConfidentialAmm,
    DarkPool,
    LendingPool,
    PerpetualsVault,
    OptionsVault,
    StableSwap,
    TokenizedVault,
    ContractEscrow,
    CrossMarginEngine,
    SyntheticAssetPool,
}

impl LiquidityVenueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialAmm => "confidential_amm",
            Self::DarkPool => "dark_pool",
            Self::LendingPool => "lending_pool",
            Self::PerpetualsVault => "perpetuals_vault",
            Self::OptionsVault => "options_vault",
            Self::StableSwap => "stable_swap",
            Self::TokenizedVault => "tokenized_vault",
            Self::ContractEscrow => "contract_escrow",
            Self::CrossMarginEngine => "cross_margin_engine",
            Self::SyntheticAssetPool => "synthetic_asset_pool",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VenueStatus {
    Registered,
    Active,
    Draining,
    Paused,
    Retired,
    Slashed,
}

impl VenueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn routable(self) -> bool {
        matches!(self, Self::Registered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossContractIntentKind {
    Swap,
    AddLiquidity,
    RemoveLiquidity,
    Borrow,
    Repay,
    MarginTransfer,
    VaultDeposit,
    VaultRedeem,
    TokenMint,
    TokenBurn,
}

impl CrossContractIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::AddLiquidity => "add_liquidity",
            Self::RemoveLiquidity => "remove_liquidity",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
            Self::MarginTransfer => "margin_transfer",
            Self::VaultDeposit => "vault_deposit",
            Self::VaultRedeem => "vault_redeem",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    PqAuthorized,
    Routed,
    Netted,
    Settled,
    RebateIssued,
    Expired,
    Rejected,
    Slashed,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::PqAuthorized => "pq_authorized",
            Self::Routed => "routed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::RebateIssued => "rebate_issued",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed | Self::PqAuthorized | Self::Routed | Self::Netted
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationKind {
    UserSpend,
    ContractDelegate,
    LiquiditySponsor,
    RouterCommittee,
    EmergencyCancel,
    RebateClaim,
}

impl PqAuthorizationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserSpend => "user_spend",
            Self::ContractDelegate => "contract_delegate",
            Self::LiquiditySponsor => "liquidity_sponsor",
            Self::RouterCommittee => "router_committee",
            Self::EmergencyCancel => "emergency_cancel",
            Self::RebateClaim => "rebate_claim",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Submitted,
    Verified,
    Linked,
    Consumed,
    Expired,
    Rejected,
    Slashed,
}

impl PqAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Linked => "linked",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingBatchStatus {
    Built,
    Sealed,
    SettlementReady,
    Settled,
    PartiallySettled,
    Failed,
    Expired,
    Slashed,
}

impl NettingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Sealed => "sealed",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::PartiallySettled => "partially_settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteReceiptStatus {
    Published,
    Finalized,
    Failed,
    Disputed,
}

impl RouteReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeRebateStatus {
    Open,
    Issued,
    Settled,
    Rejected,
    ClawedBack,
}

impl FeeRebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Issued => "issued",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::ClawedBack => "clawed_back",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterSlashKind {
    StaleRoute,
    InvalidWitness,
    DuplicateNullifier,
    FeeOvercharge,
    VenueMisreport,
    ReceiptWithheld,
    PrivacySetUnderflow,
}

impl RouterSlashKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleRoute => "stale_route",
            Self::InvalidWitness => "invalid_witness",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::FeeOvercharge => "fee_overcharge",
            Self::VenueMisreport => "venue_misreport",
            Self::ReceiptWithheld => "receipt_withheld",
            Self::PrivacySetUnderflow => "privacy_set_underflow",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterSlashStatus {
    Submitted,
    Proven,
    Executed,
    Rejected,
    Expired,
}

impl RouterSlashStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Proven => "proven",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub venue_scheme: String,
    pub intent_scheme: String,
    pub pq_proof_scheme: String,
    pub batch_scheme: String,
    pub receipt_scheme: String,
    pub rebate_scheme: String,
    pub slashing_scheme: String,
    pub genesis_height: u64,
    pub max_venues: usize,
    pub max_intents: usize,
    pub max_authorization_proofs: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_slashes: usize,
    pub max_batch_items: usize,
    pub intent_ttl_blocks: u64,
    pub proof_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub stale_router_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_router_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub slashing_penalty_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_SCHEMA_VERSION,
            l2_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_L2_NETWORK
                    .to_string(),
            monero_network:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_FEE_ASSET_ID
                    .to_string(),
            hash_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_HASH_SUITE
                    .to_string(),
            pq_auth_suite:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PQ_AUTH_SUITE
                    .to_string(),
            venue_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_VENUE_SCHEME
                    .to_string(),
            intent_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_INTENT_SCHEME
                    .to_string(),
            pq_proof_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_PQ_PROOF_SCHEME
                    .to_string(),
            batch_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_BATCH_SCHEME
                    .to_string(),
            receipt_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_RECEIPT_SCHEME
                    .to_string(),
            rebate_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_REBATE_SCHEME
                    .to_string(),
            slashing_scheme:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_SLASHING_SCHEME
                    .to_string(),
            genesis_height:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEVNET_HEIGHT,
            max_venues:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_VENUES,
            max_intents:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_INTENTS,
            max_authorization_proofs:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_PROOFS,
            max_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_REBATES,
            max_slashes:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_SLASHES,
            max_batch_items:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_ITEMS,
            intent_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            proof_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_finality_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            stale_router_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_STALE_ROUTER_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_router_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_MAX_ROUTER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            slashing_penalty_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_DEFAULT_SLASHING_PENALTY_BPS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_non_empty("chain id", &self.chain_id)?;
        ensure_non_empty("protocol version", &self.protocol_version)?;
        ensure_non_empty("l2 network", &self.l2_network)?;
        ensure_non_empty("monero network", &self.monero_network)?;
        ensure_non_empty("fee asset id", &self.fee_asset_id)?;
        ensure_bps("max user fee bps", self.max_user_fee_bps)?;
        ensure_bps("max router fee bps", self.max_router_fee_bps)?;
        ensure_bps("target rebate bps", self.target_rebate_bps)?;
        ensure_bps("slashing penalty bps", self.slashing_penalty_bps)?;
        ensure_capacity_nonzero("max venues", self.max_venues)?;
        ensure_capacity_nonzero("max intents", self.max_intents)?;
        ensure_capacity_nonzero("max authorization proofs", self.max_authorization_proofs)?;
        ensure_capacity_nonzero("max batches", self.max_batches)?;
        ensure_capacity_nonzero("max receipts", self.max_receipts)?;
        ensure_capacity_nonzero("max rebates", self.max_rebates)?;
        ensure_capacity_nonzero("max slashes", self.max_slashes)?;
        ensure_capacity_nonzero("max batch items", self.max_batch_items)?;
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security bits must be at least 192".to_string());
        }
        if self.batch_privacy_set_size < self.min_privacy_set_size {
            return Err("batch privacy set size must cover minimum privacy set".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub venues_registered: u64,
    pub intents_submitted: u64,
    pub pq_authorizations_attached: u64,
    pub batches_built: u64,
    pub receipts_settled: u64,
    pub rebates_issued: u64,
    pub routers_slashed: u64,
    pub expired_intents: u64,
    pub total_routed_notional_micro_units: u64,
    pub total_fees_charged_micro_units: u64,
    pub total_rebates_micro_units: u64,
    pub total_slashed_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "venues_registered": self.venues_registered,
            "intents_submitted": self.intents_submitted,
            "pq_authorizations_attached": self.pq_authorizations_attached,
            "batches_built": self.batches_built,
            "receipts_settled": self.receipts_settled,
            "rebates_issued": self.rebates_issued,
            "routers_slashed": self.routers_slashed,
            "expired_intents": self.expired_intents,
            "total_routed_notional_micro_units": self.total_routed_notional_micro_units,
            "total_fees_charged_micro_units": self.total_fees_charged_micro_units,
            "total_rebates_micro_units": self.total_rebates_micro_units,
            "total_slashed_micro_units": self.total_slashed_micro_units,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub venue_root: String,
    pub intent_root: String,
    pub pq_authorization_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub router_committee_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "venue_root": self.venue_root,
            "intent_root": self.intent_root,
            "pq_authorization_root": self.pq_authorization_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "router_committee_root": self.router_committee_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterLiquidityVenueRequest {
    pub kind: LiquidityVenueKind,
    pub operator_commitment: String,
    pub contract_commitment: String,
    pub asset_pair_root: String,
    pub liquidity_commitment_root: String,
    pub fee_policy_root: String,
    pub risk_policy_root: String,
    pub router_bond_micro_units: u64,
    pub max_router_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub nonce: u64,
}

impl RegisterLiquidityVenueRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("operator commitment", &self.operator_commitment)?;
        ensure_non_empty("contract commitment", &self.contract_commitment)?;
        ensure_root("asset pair root", &self.asset_pair_root)?;
        ensure_root("liquidity commitment root", &self.liquidity_commitment_root)?;
        ensure_root("fee policy root", &self.fee_policy_root)?;
        ensure_root("risk policy root", &self.risk_policy_root)?;
        ensure_bps("max router fee bps", self.max_router_fee_bps)?;
        if self.max_router_fee_bps > config.max_router_fee_bps {
            return Err("venue router fee exceeds configured maximum".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_pq(config, self.pq_security_bits)?;
        if self.router_bond_micro_units == 0 {
            return Err("router bond must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "contract_commitment": self.contract_commitment,
            "asset_pair_root": self.asset_pair_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "fee_policy_root": self.fee_policy_root,
            "risk_policy_root": self.risk_policy_root,
            "router_bond_micro_units": self.router_bond_micro_units,
            "max_router_fee_bps": self.max_router_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityVenueRecord {
    pub venue_id: String,
    pub status: VenueStatus,
    pub kind: LiquidityVenueKind,
    pub operator_commitment: String,
    pub contract_commitment: String,
    pub asset_pair_root: String,
    pub liquidity_commitment_root: String,
    pub fee_policy_root: String,
    pub risk_policy_root: String,
    pub router_bond_micro_units: u64,
    pub reserved_liquidity_micro_units: u64,
    pub settled_notional_micro_units: u64,
    pub fees_earned_micro_units: u64,
    pub slashed_micro_units: u64,
    pub max_router_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub last_routed_height: u64,
    pub nonce: u64,
}

impl LiquidityVenueRecord {
    pub fn from_request(venue_id: String, request: RegisterLiquidityVenueRequest) -> Self {
        Self {
            venue_id,
            status: VenueStatus::Registered,
            kind: request.kind,
            operator_commitment: request.operator_commitment,
            contract_commitment: request.contract_commitment,
            asset_pair_root: request.asset_pair_root,
            liquidity_commitment_root: request.liquidity_commitment_root,
            fee_policy_root: request.fee_policy_root,
            risk_policy_root: request.risk_policy_root,
            router_bond_micro_units: request.router_bond_micro_units,
            reserved_liquidity_micro_units: 0,
            settled_notional_micro_units: 0,
            fees_earned_micro_units: 0,
            slashed_micro_units: 0,
            max_router_fee_bps: request.max_router_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            last_routed_height: request.opened_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "venue_id": self.venue_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "operator_commitment": self.operator_commitment,
            "contract_commitment": self.contract_commitment,
            "asset_pair_root": self.asset_pair_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "fee_policy_root": self.fee_policy_root,
            "risk_policy_root": self.risk_policy_root,
            "router_bond_micro_units": self.router_bond_micro_units,
            "reserved_liquidity_micro_units": self.reserved_liquidity_micro_units,
            "settled_notional_micro_units": self.settled_notional_micro_units,
            "fees_earned_micro_units": self.fees_earned_micro_units,
            "slashed_micro_units": self.slashed_micro_units,
            "max_router_fee_bps": self.max_router_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "last_routed_height": self.last_routed_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitSealedIntentRequest {
    pub kind: CrossContractIntentKind,
    pub owner_commitment: String,
    pub source_contract_commitment: String,
    pub destination_contract_commitment: String,
    pub input_asset_root: String,
    pub output_asset_root: String,
    pub sealed_call_root: String,
    pub amount_commitment_root: String,
    pub limit_price_root: String,
    pub privacy_hint_root: String,
    pub nullifier: String,
    pub max_user_fee_bps: u64,
    pub notional_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl SubmitSealedIntentRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("owner commitment", &self.owner_commitment)?;
        ensure_non_empty(
            "source contract commitment",
            &self.source_contract_commitment,
        )?;
        ensure_non_empty(
            "destination contract commitment",
            &self.destination_contract_commitment,
        )?;
        ensure_root("input asset root", &self.input_asset_root)?;
        ensure_root("output asset root", &self.output_asset_root)?;
        ensure_root("sealed call root", &self.sealed_call_root)?;
        ensure_root("amount commitment root", &self.amount_commitment_root)?;
        ensure_root("limit price root", &self.limit_price_root)?;
        ensure_root("privacy hint root", &self.privacy_hint_root)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_bps("max user fee bps", self.max_user_fee_bps)?;
        if self.max_user_fee_bps > config.max_user_fee_bps {
            return Err("intent user fee exceeds configured maximum".to_string());
        }
        if self.notional_micro_units == 0 {
            return Err("intent notional must be non-zero".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_expiry(
            "intent",
            self.submitted_at_height,
            self.expires_at_height,
            config.intent_ttl_blocks,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "source_contract_commitment": self.source_contract_commitment,
            "destination_contract_commitment": self.destination_contract_commitment,
            "input_asset_root": self.input_asset_root,
            "output_asset_root": self.output_asset_root,
            "sealed_call_root": self.sealed_call_root,
            "amount_commitment_root": self.amount_commitment_root,
            "limit_price_root": self.limit_price_root,
            "privacy_hint_root": self.privacy_hint_root,
            "nullifier": self.nullifier,
            "max_user_fee_bps": self.max_user_fee_bps,
            "notional_micro_units": self.notional_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntentRecord {
    pub intent_id: String,
    pub status: IntentStatus,
    pub kind: CrossContractIntentKind,
    pub owner_commitment: String,
    pub source_contract_commitment: String,
    pub destination_contract_commitment: String,
    pub input_asset_root: String,
    pub output_asset_root: String,
    pub sealed_call_root: String,
    pub amount_commitment_root: String,
    pub limit_price_root: String,
    pub privacy_hint_root: String,
    pub nullifier: String,
    pub authorization_ids: Vec<String>,
    pub batch_id: String,
    pub receipt_id: String,
    pub rebate_id: String,
    pub max_user_fee_bps: u64,
    pub charged_fee_micro_units: u64,
    pub notional_micro_units: u64,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl SealedIntentRecord {
    pub fn from_request(intent_id: String, request: SubmitSealedIntentRequest) -> Self {
        Self {
            intent_id,
            status: IntentStatus::Sealed,
            kind: request.kind,
            owner_commitment: request.owner_commitment,
            source_contract_commitment: request.source_contract_commitment,
            destination_contract_commitment: request.destination_contract_commitment,
            input_asset_root: request.input_asset_root,
            output_asset_root: request.output_asset_root,
            sealed_call_root: request.sealed_call_root,
            amount_commitment_root: request.amount_commitment_root,
            limit_price_root: request.limit_price_root,
            privacy_hint_root: request.privacy_hint_root,
            nullifier: request.nullifier,
            authorization_ids: Vec::new(),
            batch_id: String::new(),
            receipt_id: String::new(),
            rebate_id: String::new(),
            max_user_fee_bps: request.max_user_fee_bps,
            charged_fee_micro_units: 0,
            notional_micro_units: request.notional_micro_units,
            privacy_set_size: request.privacy_set_size,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            settled_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "source_contract_commitment": self.source_contract_commitment,
            "destination_contract_commitment": self.destination_contract_commitment,
            "input_asset_root": self.input_asset_root,
            "output_asset_root": self.output_asset_root,
            "sealed_call_root": self.sealed_call_root,
            "amount_commitment_root": self.amount_commitment_root,
            "limit_price_root": self.limit_price_root,
            "privacy_hint_root": self.privacy_hint_root,
            "nullifier": self.nullifier,
            "authorization_ids": self.authorization_ids,
            "batch_id": self.batch_id,
            "receipt_id": self.receipt_id,
            "rebate_id": self.rebate_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "notional_micro_units": self.notional_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachPqAuthorizationRequest {
    pub kind: PqAuthorizationKind,
    pub intent_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub authorization_proof_root: String,
    pub session_policy_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl AttachPqAuthorizationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("intent id", &self.intent_id)?;
        ensure_non_empty("signer commitment", &self.signer_commitment)?;
        ensure_root("pq public key root", &self.pq_public_key_root)?;
        ensure_root("authorization proof root", &self.authorization_proof_root)?;
        ensure_root("session policy root", &self.session_policy_root)?;
        ensure_root("replay fence root", &self.replay_fence_root)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_pq(config, self.pq_security_bits)?;
        ensure_expiry(
            "pq authorization",
            self.submitted_at_height,
            self.expires_at_height,
            config.proof_ttl_blocks,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "intent_id": self.intent_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "authorization_proof_root": self.authorization_proof_root,
            "session_policy_root": self.session_policy_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAuthorizationRecord {
    pub authorization_id: String,
    pub status: PqAuthorizationStatus,
    pub kind: PqAuthorizationKind,
    pub intent_id: String,
    pub signer_commitment: String,
    pub pq_public_key_root: String,
    pub authorization_proof_root: String,
    pub session_policy_root: String,
    pub replay_fence_root: String,
    pub nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub linked_at_height: u64,
    pub nonce: u64,
}

impl PqAuthorizationRecord {
    pub fn from_request(authorization_id: String, request: AttachPqAuthorizationRequest) -> Self {
        Self {
            authorization_id,
            status: PqAuthorizationStatus::Submitted,
            kind: request.kind,
            intent_id: request.intent_id,
            signer_commitment: request.signer_commitment,
            pq_public_key_root: request.pq_public_key_root,
            authorization_proof_root: request.authorization_proof_root,
            session_policy_root: request.session_policy_root,
            replay_fence_root: request.replay_fence_root,
            nullifier: request.nullifier,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            linked_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "intent_id": self.intent_id,
            "signer_commitment": self.signer_commitment,
            "pq_public_key_root": self.pq_public_key_root,
            "authorization_proof_root": self.authorization_proof_root,
            "session_policy_root": self.session_policy_root,
            "replay_fence_root": self.replay_fence_root,
            "nullifier": self.nullifier,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "linked_at_height": self.linked_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildRoutedNettingBatchRequest {
    pub router_commitment: String,
    pub route_plan_root: String,
    pub input_balance_root: String,
    pub output_balance_root: String,
    pub witness_root: String,
    pub netting_proof_root: String,
    pub venue_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub router_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl BuildRoutedNettingBatchRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("router commitment", &self.router_commitment)?;
        ensure_root("route plan root", &self.route_plan_root)?;
        ensure_root("input balance root", &self.input_balance_root)?;
        ensure_root("output balance root", &self.output_balance_root)?;
        ensure_root("witness root", &self.witness_root)?;
        ensure_root("netting proof root", &self.netting_proof_root)?;
        ensure_unique("venue ids", &self.venue_ids)?;
        ensure_unique("intent ids", &self.intent_ids)?;
        if self.venue_ids.is_empty() {
            return Err("batch must include at least one venue".to_string());
        }
        if self.intent_ids.is_empty() {
            return Err("batch must include at least one intent".to_string());
        }
        if self.intent_ids.len() > config.max_batch_items {
            return Err("batch item count exceeds configured maximum".to_string());
        }
        ensure_bps("router fee bps", self.router_fee_bps)?;
        if self.router_fee_bps > config.max_router_fee_bps {
            return Err("router fee exceeds configured maximum".to_string());
        }
        ensure_min_privacy(config, self.privacy_set_size, true)?;
        ensure_pq(config, self.pq_security_bits)?;
        ensure_expiry(
            "batch",
            self.built_at_height,
            self.expires_at_height,
            config.batch_ttl_blocks,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "router_commitment": self.router_commitment,
            "route_plan_root": self.route_plan_root,
            "input_balance_root": self.input_balance_root,
            "output_balance_root": self.output_balance_root,
            "witness_root": self.witness_root,
            "netting_proof_root": self.netting_proof_root,
            "venue_ids": self.venue_ids,
            "intent_ids": self.intent_ids,
            "router_fee_bps": self.router_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutedNettingBatchRecord {
    pub batch_id: String,
    pub status: NettingBatchStatus,
    pub router_commitment: String,
    pub route_plan_root: String,
    pub input_balance_root: String,
    pub output_balance_root: String,
    pub witness_root: String,
    pub netting_proof_root: String,
    pub venue_ids: Vec<String>,
    pub intent_ids: Vec<String>,
    pub receipt_ids: Vec<String>,
    pub router_fee_bps: u64,
    pub charged_fee_micro_units: u64,
    pub net_notional_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: u64,
    pub nonce: u64,
}

impl RoutedNettingBatchRecord {
    pub fn from_request(
        batch_id: String,
        request: BuildRoutedNettingBatchRequest,
        net_notional_micro_units: u64,
        charged_fee_micro_units: u64,
    ) -> Self {
        Self {
            batch_id,
            status: NettingBatchStatus::Built,
            router_commitment: request.router_commitment,
            route_plan_root: request.route_plan_root,
            input_balance_root: request.input_balance_root,
            output_balance_root: request.output_balance_root,
            witness_root: request.witness_root,
            netting_proof_root: request.netting_proof_root,
            venue_ids: request.venue_ids,
            intent_ids: request.intent_ids,
            receipt_ids: Vec::new(),
            router_fee_bps: request.router_fee_bps,
            charged_fee_micro_units,
            net_notional_micro_units,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            built_at_height: request.built_at_height,
            expires_at_height: request.expires_at_height,
            settled_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "router_commitment": self.router_commitment,
            "route_plan_root": self.route_plan_root,
            "input_balance_root": self.input_balance_root,
            "output_balance_root": self.output_balance_root,
            "witness_root": self.witness_root,
            "netting_proof_root": self.netting_proof_root,
            "venue_ids": self.venue_ids,
            "intent_ids": self.intent_ids,
            "receipt_ids": self.receipt_ids,
            "router_fee_bps": self.router_fee_bps,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "net_notional_micro_units": self.net_notional_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleRouteReceiptRequest {
    pub batch_id: String,
    pub intent_id: String,
    pub venue_id: String,
    pub execution_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub settlement_proof_root: String,
    pub actual_notional_micro_units: u64,
    pub charged_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub finalizes_at_height: u64,
    pub nonce: u64,
}

impl SettleRouteReceiptRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("batch id", &self.batch_id)?;
        ensure_non_empty("intent id", &self.intent_id)?;
        ensure_non_empty("venue id", &self.venue_id)?;
        ensure_root("execution root", &self.execution_root)?;
        ensure_root("output note root", &self.output_note_root)?;
        ensure_root("fee note root", &self.fee_note_root)?;
        ensure_root("settlement proof root", &self.settlement_proof_root)?;
        if self.actual_notional_micro_units == 0 {
            return Err("receipt notional must be non-zero".to_string());
        }
        if self.finalizes_at_height < self.settled_at_height + config.receipt_finality_blocks {
            return Err("receipt finality height is too early".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "venue_id": self.venue_id,
            "execution_root": self.execution_root,
            "output_note_root": self.output_note_root,
            "fee_note_root": self.fee_note_root,
            "settlement_proof_root": self.settlement_proof_root,
            "actual_notional_micro_units": self.actual_notional_micro_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "settled_at_height": self.settled_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteReceiptRecord {
    pub receipt_id: String,
    pub status: RouteReceiptStatus,
    pub batch_id: String,
    pub intent_id: String,
    pub venue_id: String,
    pub execution_root: String,
    pub output_note_root: String,
    pub fee_note_root: String,
    pub settlement_proof_root: String,
    pub actual_notional_micro_units: u64,
    pub charged_fee_micro_units: u64,
    pub settled_at_height: u64,
    pub finalizes_at_height: u64,
    pub nonce: u64,
}

impl RouteReceiptRecord {
    pub fn from_request(receipt_id: String, request: SettleRouteReceiptRequest) -> Self {
        Self {
            receipt_id,
            status: RouteReceiptStatus::Published,
            batch_id: request.batch_id,
            intent_id: request.intent_id,
            venue_id: request.venue_id,
            execution_root: request.execution_root,
            output_note_root: request.output_note_root,
            fee_note_root: request.fee_note_root,
            settlement_proof_root: request.settlement_proof_root,
            actual_notional_micro_units: request.actual_notional_micro_units,
            charged_fee_micro_units: request.charged_fee_micro_units,
            settled_at_height: request.settled_at_height,
            finalizes_at_height: request.finalizes_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "venue_id": self.venue_id,
            "execution_root": self.execution_root,
            "output_note_root": self.output_note_root,
            "fee_note_root": self.fee_note_root,
            "settlement_proof_root": self.settlement_proof_root,
            "actual_notional_micro_units": self.actual_notional_micro_units,
            "charged_fee_micro_units": self.charged_fee_micro_units,
            "settled_at_height": self.settled_at_height,
            "finalizes_at_height": self.finalizes_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueFeeRebateRequest {
    pub intent_id: String,
    pub receipt_id: String,
    pub claimant_commitment: String,
    pub rebate_note_root: String,
    pub rebate_policy_root: String,
    pub claim_proof_root: String,
    pub fee_paid_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub nonce: u64,
}

impl IssueFeeRebateRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("intent id", &self.intent_id)?;
        ensure_non_empty("receipt id", &self.receipt_id)?;
        ensure_non_empty("claimant commitment", &self.claimant_commitment)?;
        ensure_root("rebate note root", &self.rebate_note_root)?;
        ensure_root("rebate policy root", &self.rebate_policy_root)?;
        ensure_root("claim proof root", &self.claim_proof_root)?;
        ensure_bps("rebate bps", self.rebate_bps)?;
        if self.rebate_bps > config.target_rebate_bps {
            return Err("rebate bps exceeds configured target".to_string());
        }
        if self.fee_paid_micro_units == 0 {
            return Err("rebate fee basis must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn rebate_amount_micro_units(&self) -> u64 {
        self.fee_paid_micro_units.saturating_mul(self.rebate_bps)
            / PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_policy_root": self.rebate_policy_root,
            "claim_proof_root": self.claim_proof_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub status: FeeRebateStatus,
    pub intent_id: String,
    pub receipt_id: String,
    pub claimant_commitment: String,
    pub rebate_note_root: String,
    pub rebate_policy_root: String,
    pub claim_proof_root: String,
    pub fee_paid_micro_units: u64,
    pub rebate_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub nonce: u64,
}

impl FeeRebateRecord {
    pub fn from_request(rebate_id: String, request: IssueFeeRebateRequest) -> Self {
        Self {
            rebate_id,
            status: FeeRebateStatus::Issued,
            intent_id: request.intent_id,
            receipt_id: request.receipt_id,
            claimant_commitment: request.claimant_commitment,
            rebate_note_root: request.rebate_note_root,
            rebate_policy_root: request.rebate_policy_root,
            claim_proof_root: request.claim_proof_root,
            fee_paid_micro_units: request.fee_paid_micro_units,
            rebate_micro_units: request.rebate_amount_micro_units(),
            rebate_bps: request.rebate_bps,
            issued_at_height: request.issued_at_height,
            nonce: request.nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "status": self.status.as_str(),
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "claimant_commitment": self.claimant_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_policy_root": self.rebate_policy_root,
            "claim_proof_root": self.claim_proof_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "rebate_micro_units": self.rebate_micro_units,
            "rebate_bps": self.rebate_bps,
            "issued_at_height": self.issued_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashRouterRequest {
    pub kind: RouterSlashKind,
    pub accused_router_commitment: String,
    pub reporter_commitment: String,
    pub venue_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub evidence_root: String,
    pub contradiction_root: String,
    pub transcript_root: String,
    pub public_hint_root: String,
    pub slash_bond_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub nonce: u64,
}

impl SlashRouterRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_non_empty("accused router commitment", &self.accused_router_commitment)?;
        ensure_non_empty("reporter commitment", &self.reporter_commitment)?;
        ensure_root("evidence root", &self.evidence_root)?;
        ensure_root("contradiction root", &self.contradiction_root)?;
        ensure_root("transcript root", &self.transcript_root)?;
        ensure_root("public hint root", &self.public_hint_root)?;
        ensure_min_privacy(config, self.privacy_set_size, false)?;
        ensure_pq(config, self.pq_security_bits)?;
        if self.slash_bond_micro_units == 0 {
            return Err("slash bond must be non-zero".to_string());
        }
        if self.challenge_deadline_height <= self.opened_at_height {
            return Err("challenge deadline must be after slashing open height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "accused_router_commitment": self.accused_router_commitment,
            "reporter_commitment": self.reporter_commitment,
            "venue_id": self.venue_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "evidence_root": self.evidence_root,
            "contradiction_root": self.contradiction_root,
            "transcript_root": self.transcript_root,
            "public_hint_root": self.public_hint_root,
            "slash_bond_micro_units": self.slash_bond_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouterSlashRecord {
    pub slash_id: String,
    pub status: RouterSlashStatus,
    pub kind: RouterSlashKind,
    pub accused_router_commitment: String,
    pub reporter_commitment: String,
    pub venue_id: String,
    pub batch_id: String,
    pub intent_id: String,
    pub receipt_id: String,
    pub evidence_root: String,
    pub contradiction_root: String,
    pub transcript_root: String,
    pub public_hint_root: String,
    pub slash_bond_micro_units: u64,
    pub reporter_reward_micro_units: u64,
    pub protocol_treasury_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub challenge_deadline_height: u64,
    pub executed_at_height: u64,
    pub nonce: u64,
}

impl RouterSlashRecord {
    pub fn from_request(slash_id: String, request: SlashRouterRequest) -> Self {
        Self {
            slash_id,
            status: RouterSlashStatus::Submitted,
            kind: request.kind,
            accused_router_commitment: request.accused_router_commitment,
            reporter_commitment: request.reporter_commitment,
            venue_id: request.venue_id,
            batch_id: request.batch_id,
            intent_id: request.intent_id,
            receipt_id: request.receipt_id,
            evidence_root: request.evidence_root,
            contradiction_root: request.contradiction_root,
            transcript_root: request.transcript_root,
            public_hint_root: request.public_hint_root,
            slash_bond_micro_units: request.slash_bond_micro_units,
            reporter_reward_micro_units: 0,
            protocol_treasury_micro_units: 0,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            challenge_deadline_height: request.challenge_deadline_height,
            executed_at_height: 0,
            nonce: request.nonce,
        }
    }

    pub fn prove(&mut self, penalty_bps: u64) -> Result<()> {
        if self.status != RouterSlashStatus::Submitted {
            return Err("only submitted slashing evidence can be proven".to_string());
        }
        ensure_bps("penalty bps", penalty_bps)?;
        self.reporter_reward_micro_units = self.slash_bond_micro_units.saturating_mul(penalty_bps)
            / PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS;
        self.protocol_treasury_micro_units = self
            .slash_bond_micro_units
            .saturating_sub(self.reporter_reward_micro_units);
        self.status = RouterSlashStatus::Proven;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "slash_id": self.slash_id,
            "status": self.status.as_str(),
            "kind": self.kind.as_str(),
            "accused_router_commitment": self.accused_router_commitment,
            "reporter_commitment": self.reporter_commitment,
            "venue_id": self.venue_id,
            "batch_id": self.batch_id,
            "intent_id": self.intent_id,
            "receipt_id": self.receipt_id,
            "evidence_root": self.evidence_root,
            "contradiction_root": self.contradiction_root,
            "transcript_root": self.transcript_root,
            "public_hint_root": self.public_hint_root,
            "slash_bond_micro_units": self.slash_bond_micro_units,
            "reporter_reward_micro_units": self.reporter_reward_micro_units,
            "protocol_treasury_micro_units": self.protocol_treasury_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "challenge_deadline_height": self.challenge_deadline_height,
            "executed_at_height": self.executed_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub current_height: u64,
    pub venues: BTreeMap<String, LiquidityVenueRecord>,
    pub intents: BTreeMap<String, SealedIntentRecord>,
    pub pq_authorizations: BTreeMap<String, PqAuthorizationRecord>,
    pub batches: BTreeMap<String, RoutedNettingBatchRecord>,
    pub receipts: BTreeMap<String, RouteReceiptRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub slashes: BTreeMap<String, RouterSlashRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub active_router_commitments: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = Self {
            current_height: config.genesis_height,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            venues: BTreeMap::new(),
            intents: BTreeMap::new(),
            pq_authorizations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashes: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            active_router_commitments: BTreeSet::new(),
        };
        state.recompute_roots();
        state
    }

    pub fn register_confidential_liquidity_venue(
        &mut self,
        request: RegisterLiquidityVenueRequest,
    ) -> Result<String> {
        self.config.validate()?;
        request.validate(&self.config)?;
        ensure_capacity("venues", self.venues.len(), self.config.max_venues)?;
        let venue_id = liquidity_venue_id(
            request.kind,
            &request.operator_commitment,
            &request.contract_commitment,
            request.nonce,
        );
        if self.venues.contains_key(&venue_id) {
            return Err("liquidity venue already registered".to_string());
        }
        self.active_router_commitments
            .insert(request.operator_commitment.clone());
        let record = LiquidityVenueRecord::from_request(venue_id.clone(), request);
        self.venues.insert(venue_id.clone(), record);
        self.counters.venues_registered = self.counters.venues_registered.saturating_add(1);
        self.recompute_roots();
        Ok(venue_id)
    }

    pub fn submit_sealed_cross_contract_liquidity_intent(
        &mut self,
        request: SubmitSealedIntentRequest,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("intents", self.intents.len(), self.config.max_intents)?;
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("intent nullifier has already been consumed".to_string());
        }
        let intent_id = sealed_intent_id(
            request.kind,
            &request.owner_commitment,
            &request.sealed_call_root,
            request.nonce,
        );
        if self.intents.contains_key(&intent_id) {
            return Err("sealed intent already submitted".to_string());
        }
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let record = SealedIntentRecord::from_request(intent_id.clone(), request);
        self.intents.insert(intent_id.clone(), record);
        self.counters.intents_submitted = self.counters.intents_submitted.saturating_add(1);
        self.recompute_roots();
        Ok(intent_id)
    }

    pub fn attach_pq_authorization_proof(
        &mut self,
        request: AttachPqAuthorizationRequest,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity(
            "pq authorizations",
            self.pq_authorizations.len(),
            self.config.max_authorization_proofs,
        )?;
        if self.consumed_nullifiers.contains(&request.nullifier) {
            return Err("authorization nullifier has already been consumed".to_string());
        }
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for pq authorization".to_string())?;
        if !intent.status.live() {
            return Err("intent is not live for pq authorization".to_string());
        }
        if request.expires_at_height > intent.expires_at_height {
            return Err("authorization expires after intent".to_string());
        }
        let authorization_id = pq_authorization_id(
            request.kind,
            &request.intent_id,
            &request.authorization_proof_root,
            request.nonce,
        );
        if self.pq_authorizations.contains_key(&authorization_id) {
            return Err("pq authorization already attached".to_string());
        }
        self.consumed_nullifiers.insert(request.nullifier.clone());
        let mut record = PqAuthorizationRecord::from_request(authorization_id.clone(), request);
        record.status = PqAuthorizationStatus::Linked;
        record.linked_at_height = self.current_height;
        intent.status = IntentStatus::PqAuthorized;
        intent.authorization_ids.push(authorization_id.clone());
        self.pq_authorizations
            .insert(authorization_id.clone(), record);
        self.counters.pq_authorizations_attached =
            self.counters.pq_authorizations_attached.saturating_add(1);
        self.recompute_roots();
        Ok(authorization_id)
    }

    pub fn build_routed_netting_batch(
        &mut self,
        request: BuildRoutedNettingBatchRequest,
    ) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("batches", self.batches.len(), self.config.max_batches)?;
        if !self
            .active_router_commitments
            .contains(&request.router_commitment)
        {
            return Err("router commitment is not active".to_string());
        }
        for venue_id in &request.venue_ids {
            let venue = self
                .venues
                .get(venue_id)
                .ok_or_else(|| format!("venue not found: {venue_id}"))?;
            if !venue.status.routable() {
                return Err(format!("venue is not routable: {venue_id}"));
            }
        }
        let mut net_notional = 0_u64;
        for intent_id in &request.intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("intent not found: {intent_id}"))?;
            if intent.status != IntentStatus::PqAuthorized {
                return Err(format!("intent is not pq authorized: {intent_id}"));
            }
            if intent.expires_at_height <= request.built_at_height {
                return Err(format!("intent expired before route: {intent_id}"));
            }
            net_notional = net_notional.saturating_add(intent.notional_micro_units);
        }
        let charged_fee = net_notional.saturating_mul(request.router_fee_bps)
            / PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS;
        let batch_id = routed_batch_id(
            &request.router_commitment,
            &request.route_plan_root,
            request.built_at_height,
            request.nonce,
        );
        if self.batches.contains_key(&batch_id) {
            return Err("routed netting batch already built".to_string());
        }
        let record = RoutedNettingBatchRecord::from_request(
            batch_id.clone(),
            request,
            net_notional,
            charged_fee,
        );
        for intent_id in &record.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.batch_id = batch_id.clone();
                intent.status = IntentStatus::Netted;
                intent.charged_fee_micro_units = intent
                    .notional_micro_units
                    .saturating_mul(record.router_fee_bps)
                    / PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS;
            }
        }
        for venue_id in &record.venue_ids {
            if let Some(venue) = self.venues.get_mut(venue_id) {
                venue.status = VenueStatus::Active;
                venue.last_routed_height = record.built_at_height;
                venue.reserved_liquidity_micro_units = venue
                    .reserved_liquidity_micro_units
                    .saturating_add(net_notional);
            }
        }
        self.counters.batches_built = self.counters.batches_built.saturating_add(1);
        self.counters.total_routed_notional_micro_units = self
            .counters
            .total_routed_notional_micro_units
            .saturating_add(net_notional);
        self.counters.total_fees_charged_micro_units = self
            .counters
            .total_fees_charged_micro_units
            .saturating_add(charged_fee);
        self.batches.insert(batch_id.clone(), record);
        self.recompute_roots();
        Ok(batch_id)
    }

    pub fn settle_route_receipt(&mut self, request: SettleRouteReceiptRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("receipts", self.receipts.len(), self.config.max_receipts)?;
        let batch = self
            .batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "batch not found for route receipt".to_string())?;
        if !batch.intent_ids.contains(&request.intent_id) {
            return Err("receipt intent is not in batch".to_string());
        }
        if !batch.venue_ids.contains(&request.venue_id) {
            return Err("receipt venue is not in batch".to_string());
        }
        if request.settled_at_height > batch.expires_at_height {
            return Err("receipt settles after batch expiration".to_string());
        }
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for receipt".to_string())?;
        if intent.status != IntentStatus::Netted {
            return Err("intent is not netted for settlement".to_string());
        }
        let receipt_id = route_receipt_id(
            &request.batch_id,
            &request.intent_id,
            &request.execution_root,
            request.nonce,
        );
        if self.receipts.contains_key(&receipt_id) {
            return Err("route receipt already exists".to_string());
        }
        intent.status = IntentStatus::Settled;
        intent.receipt_id = receipt_id.clone();
        intent.settled_at_height = request.settled_at_height;
        intent.charged_fee_micro_units = request.charged_fee_micro_units;
        batch.receipt_ids.push(receipt_id.clone());
        batch.settled_at_height = request.settled_at_height;
        batch.status = if batch.receipt_ids.len() == batch.intent_ids.len() {
            NettingBatchStatus::Settled
        } else {
            NettingBatchStatus::PartiallySettled
        };
        if let Some(venue) = self.venues.get_mut(&request.venue_id) {
            venue.reserved_liquidity_micro_units = venue
                .reserved_liquidity_micro_units
                .saturating_sub(request.actual_notional_micro_units);
            venue.settled_notional_micro_units = venue
                .settled_notional_micro_units
                .saturating_add(request.actual_notional_micro_units);
            venue.fees_earned_micro_units = venue
                .fees_earned_micro_units
                .saturating_add(request.charged_fee_micro_units);
        }
        let record = RouteReceiptRecord::from_request(receipt_id.clone(), request);
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.receipts_settled = self.counters.receipts_settled.saturating_add(1);
        self.recompute_roots();
        Ok(receipt_id)
    }

    pub fn issue_fee_rebate(&mut self, request: IssueFeeRebateRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("rebates", self.rebates.len(), self.config.max_rebates)?;
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found for rebate".to_string())?;
        if intent.status != IntentStatus::Settled {
            return Err("rebate requires a settled intent".to_string());
        }
        let receipt = self
            .receipts
            .get(&request.receipt_id)
            .ok_or_else(|| "receipt not found for rebate".to_string())?;
        if receipt.intent_id != request.intent_id {
            return Err("rebate receipt does not match intent".to_string());
        }
        if request.fee_paid_micro_units > receipt.charged_fee_micro_units {
            return Err("rebate fee basis exceeds receipt fee".to_string());
        }
        let rebate_id = fee_rebate_id(
            &request.intent_id,
            &request.receipt_id,
            &request.rebate_note_root,
            request.nonce,
        );
        if self.rebates.contains_key(&rebate_id) {
            return Err("fee rebate already issued".to_string());
        }
        let record = FeeRebateRecord::from_request(rebate_id.clone(), request);
        intent.status = IntentStatus::RebateIssued;
        intent.rebate_id = rebate_id.clone();
        self.counters.rebates_issued = self.counters.rebates_issued.saturating_add(1);
        self.counters.total_rebates_micro_units = self
            .counters
            .total_rebates_micro_units
            .saturating_add(record.rebate_micro_units);
        self.rebates.insert(rebate_id.clone(), record);
        self.recompute_roots();
        Ok(rebate_id)
    }

    pub fn slash_stale_or_invalid_router(&mut self, request: SlashRouterRequest) -> Result<String> {
        request.validate(&self.config)?;
        ensure_capacity("slashes", self.slashes.len(), self.config.max_slashes)?;
        let slash_id = router_slash_id(
            request.kind,
            &request.accused_router_commitment,
            &request.evidence_root,
            request.nonce,
        );
        if self.slashes.contains_key(&slash_id) {
            return Err("router slashing already submitted".to_string());
        }
        let mut record = RouterSlashRecord::from_request(slash_id.clone(), request);
        record.prove(self.config.slashing_penalty_bps)?;
        record.status = RouterSlashStatus::Executed;
        record.executed_at_height = self.current_height;
        self.active_router_commitments
            .remove(&record.accused_router_commitment);
        if let Some(venue) = self.venues.get_mut(&record.venue_id) {
            venue.status = VenueStatus::Slashed;
            venue.slashed_micro_units = venue
                .slashed_micro_units
                .saturating_add(record.slash_bond_micro_units);
        }
        if let Some(batch) = self.batches.get_mut(&record.batch_id) {
            batch.status = NettingBatchStatus::Slashed;
        }
        if let Some(intent) = self.intents.get_mut(&record.intent_id) {
            intent.status = IntentStatus::Slashed;
        }
        self.counters.routers_slashed = self.counters.routers_slashed.saturating_add(1);
        self.counters.total_slashed_micro_units = self
            .counters
            .total_slashed_micro_units
            .saturating_add(record.slash_bond_micro_units);
        self.slashes.insert(slash_id.clone(), record);
        self.recompute_roots();
        Ok(slash_id)
    }

    pub fn expire_stale_intents(&mut self, height: u64) -> Vec<String> {
        self.current_height = self.current_height.max(height);
        let mut expired = Vec::new();
        for (intent_id, intent) in self.intents.iter_mut() {
            if intent.status.live() && intent.expires_at_height <= height {
                intent.status = IntentStatus::Expired;
                expired.push(intent_id.clone());
            }
        }
        self.counters.expired_intents = self
            .counters
            .expired_intents
            .saturating_add(expired.len() as u64);
        if !expired.is_empty() {
            self.recompute_roots();
        }
        expired
    }

    pub fn recompute_roots(&mut self) {
        self.roots = self.roots_without_state_root();
        self.roots.public_record_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-PUBLIC-RECORD",
            &self.public_record_without_state_root(),
        );
        self.roots.state_root = state_root_from_record(&self.public_record_without_state_root());
    }

    pub fn roots(&self) -> Roots {
        self.roots_without_state_root()
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots_without_state_root();
        json!({
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "current_height": self.current_height,
            "venues": public_records_from_map(&self.venues, LiquidityVenueRecord::public_record),
            "intents": public_records_from_map(&self.intents, SealedIntentRecord::public_record),
            "pq_authorizations": public_records_from_map(&self.pq_authorizations, PqAuthorizationRecord::public_record),
            "batches": public_records_from_map(&self.batches, RoutedNettingBatchRecord::public_record),
            "receipts": public_records_from_map(&self.receipts, RouteReceiptRecord::public_record),
            "rebates": public_records_from_map(&self.rebates, FeeRebateRecord::public_record),
            "slashes": public_records_from_map(&self.slashes, RouterSlashRecord::public_record),
            "consumed_nullifiers": self.consumed_nullifiers.iter().cloned().collect::<Vec<_>>(),
            "active_router_commitments": self.active_router_commitments.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn roots_without_state_root(&self) -> Roots {
        Roots {
            venue_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-VENUES",
                &self.venues,
                LiquidityVenueRecord::public_record,
            ),
            intent_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-INTENTS",
                &self.intents,
                SealedIntentRecord::public_record,
            ),
            pq_authorization_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-PQ-AUTHS",
                &self.pq_authorizations,
                PqAuthorizationRecord::public_record,
            ),
            batch_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-BATCHES",
                &self.batches,
                RoutedNettingBatchRecord::public_record,
            ),
            receipt_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-RECEIPTS",
                &self.receipts,
                RouteReceiptRecord::public_record,
            ),
            rebate_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-REBATES",
                &self.rebates,
                FeeRebateRecord::public_record,
            ),
            slashing_root: map_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-SLASHES",
                &self.slashes,
                RouterSlashRecord::public_record,
            ),
            nullifier_root: set_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-NULLIFIERS",
                &self.consumed_nullifiers,
            ),
            router_committee_root: set_root(
                "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-COMMITTEE",
                &self.active_router_commitments,
            ),
            public_record_root: String::new(),
            state_root: String::new(),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn private_l2_pq_confidential_cross_contract_liquidity_router_runtime_state_root() -> String {
    State::devnet().state_root()
}

pub fn liquidity_venue_id(
    kind: LiquidityVenueKind,
    operator_commitment: &str,
    contract_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-VENUE-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(operator_commitment),
            HashPart::Str(contract_commitment),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn sealed_intent_id(
    kind: CrossContractIntentKind,
    owner_commitment: &str,
    sealed_call_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-INTENT-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
            HashPart::Str(sealed_call_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn pq_authorization_id(
    kind: PqAuthorizationKind,
    intent_id: &str,
    proof_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-PQ-AUTH-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(intent_id),
            HashPart::Str(proof_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn routed_batch_id(
    router_commitment: &str,
    route_plan_root: &str,
    built_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-BATCH-ID",
        &[
            HashPart::Str(router_commitment),
            HashPart::Str(route_plan_root),
            HashPart::U64(built_at_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn route_receipt_id(
    batch_id: &str,
    intent_id: &str,
    execution_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-RECEIPT-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(intent_id),
            HashPart::Str(execution_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn fee_rebate_id(
    intent_id: &str,
    receipt_id: &str,
    rebate_note_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-REBATE-ID",
        &[
            HashPart::Str(intent_id),
            HashPart::Str(receipt_id),
            HashPart::Str(rebate_note_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn router_slash_id(
    kind: RouterSlashKind,
    accused_router_commitment: &str,
    evidence_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-SLASH-ID",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(accused_router_commitment),
            HashPart::Str(evidence_root),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn deterministic_root(label: &str, subject: &str, nonce: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(label),
            HashPart::Str(subject),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-CROSS-CONTRACT-LIQUIDITY-ROUTER-STATE-ROOT",
        record,
    )
}

pub fn root_from_values(domain: &str, values: &[&str]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String((*value).to_string()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn public_records_from_map<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.values().map(public_record).collect()
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = public_records_from_map(map, public_record);
    public_record_root(domain, &records)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let records = set
        .iter()
        .map(|item| Value::String(item.clone()))
        .collect::<Vec<_>>();
    public_record_root(domain, &records)
}

fn ensure_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must be non-empty"));
    }
    Ok(())
}

fn ensure_root(name: &str, value: &str) -> Result<()> {
    ensure_non_empty(name, value)?;
    if value.len() < 16 {
        return Err(format!("{name} must be hash-like"));
    }
    Ok(())
}

fn ensure_bps(name: &str, value: u64) -> Result<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_CROSS_CONTRACT_LIQUIDITY_ROUTER_RUNTIME_MAX_BPS {
        return Err(format!("{name} exceeds max bps"));
    }
    Ok(())
}

fn ensure_capacity(name: &str, current_len: usize, max_len: usize) -> Result<()> {
    if current_len >= max_len {
        return Err(format!("{name} capacity exhausted"));
    }
    Ok(())
}

fn ensure_capacity_nonzero(name: &str, value: usize) -> Result<()> {
    if value == 0 {
        return Err(format!("{name} must be non-zero"));
    }
    Ok(())
}

fn ensure_unique(name: &str, values: &[String]) -> Result<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(format!("{name} must be unique"));
    }
    Ok(())
}

fn ensure_min_privacy(config: &Config, observed: u64, batch: bool) -> Result<()> {
    let required = if batch {
        config.batch_privacy_set_size
    } else {
        config.min_privacy_set_size
    };
    if observed < required {
        return Err("privacy set below configured minimum".to_string());
    }
    Ok(())
}

fn ensure_pq(config: &Config, bits: u16) -> Result<()> {
    if bits < config.min_pq_security_bits {
        return Err("pq security bits below configured minimum".to_string());
    }
    Ok(())
}

fn ensure_expiry(name: &str, opened: u64, expires: u64, max_ttl: u64) -> Result<()> {
    if expires <= opened {
        return Err(format!("{name} expiration must be after open height"));
    }
    if expires.saturating_sub(opened) > max_ttl {
        return Err(format!("{name} ttl exceeds configured maximum"));
    }
    Ok(())
}

pub fn invariant_anchor_001(state: &State) -> Value {
    json!({"invariant":"anchor_001","state_root":state.state_root(),"venue_root":state.roots().venue_root,"intent_root":state.roots().intent_root})
}

pub fn invariant_anchor_002(state: &State) -> Value {
    json!({"invariant":"anchor_002","state_root":state.state_root(),"pq_authorization_root":state.roots().pq_authorization_root,"batch_root":state.roots().batch_root})
}

pub fn invariant_anchor_003(state: &State) -> Value {
    json!({"invariant":"anchor_003","receipt_root":state.roots().receipt_root,"rebate_root":state.roots().rebate_root,"slashing_root":state.roots().slashing_root})
}

pub fn invariant_anchor_004(state: &State) -> Value {
    json!({"invariant":"anchor_004","nullifier_root":state.roots().nullifier_root,"router_committee_root":state.roots().router_committee_root,"height":state.current_height})
}

pub fn invariant_anchor_005(state: &State) -> Value {
    json!({"invariant":"anchor_005","venues":state.counters.venues_registered,"intents":state.counters.intents_submitted,"batches":state.counters.batches_built})
}

pub fn invariant_anchor_006(state: &State) -> Value {
    json!({"invariant":"anchor_006","receipts":state.counters.receipts_settled,"rebates":state.counters.rebates_issued,"slashes":state.counters.routers_slashed})
}
