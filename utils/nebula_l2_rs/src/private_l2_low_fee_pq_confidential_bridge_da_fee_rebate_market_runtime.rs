use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BRIDGE_DA_FEE_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-bridge-da-fee-rebate-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BRIDGE_DA_FEE_REBATE_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_BRIDGE_DA_REBATE_MARKET_SUITE: &str =
    "low-fee-pq-confidential-bridge-da-fee-rebate-market-v1";
pub const DA_VOUCHER_SCHEME: &str = "private-bridge-da-voucher-price-commitment-v1";
pub const BRIDGE_BATCH_SCHEME: &str = "pq-confidential-private-bridge-batch-root-v1";
pub const PROOF_COMPRESSION_CREDIT_SCHEME: &str =
    "recursive-proof-compression-credit-commitment-v1";
pub const REBATE_ALLOCATION_SCHEME: &str =
    "monero-exit-token-settlement-contract-receipt-da-rebate-v1";
pub const SPONSOR_BUDGET_SCHEME: &str = "anonymous-sponsor-da-budget-reservation-v1";
pub const STALE_ROOT_SLASHING_SCHEME: &str = "stale-da-root-sponsor-provider-slashing-v1";
pub const PUBLIC_STATE_SCHEME: &str = "roots-only-bridge-da-rebate-market-public-state-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_904_320;
pub const DEVNET_EPOCH: u64 = 5_101;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_TARGET_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7_500;
pub const DEFAULT_SPONSOR_MATCH_BPS: u64 = 8_500;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_250;
pub const DEFAULT_COMPRESSION_CREDIT_BPS: u64 = 2_000;
pub const DEFAULT_STALE_ROOT_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_CHALLENGER_REWARD_BPS: u64 = 1_000;
pub const DEFAULT_STRONG_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ROOT_FRESHNESS_BLOCKS: u64 = 64;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const DEFAULT_MIN_VOUCHER_PRICE_PICONERO: u128 = 10_000;
pub const DEFAULT_MIN_SPONSOR_BUDGET_PICONERO: u128 = 5_000_000_000;
pub const MAX_MARKET_LANES: usize = 262_144;
pub const MAX_SPONSOR_BUDGETS: usize = 1_048_576;
pub const MAX_CONGESTION_BANDS: usize = 32;
pub const MAX_VOUCHERS: usize = 4_194_304;
pub const MAX_BRIDGE_BATCHES: usize = 2_097_152;
pub const MAX_COMPRESSION_CREDITS: usize = 4_194_304;
pub const MAX_REBATE_EPOCHS: usize = 524_288;
pub const MAX_REBATE_ALLOCATIONS: usize = 8_388_608;
pub const MAX_DA_ROOTS: usize = 4_194_304;
pub const MAX_SLASHING_RECORDS: usize = 1_048_576;
pub const MAX_PUBLIC_EVENTS: usize = 16_777_216;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeLaneKind {
    MoneroFastExit,
    MoneroSlowExit,
    ConfidentialTokenBridge,
    DefiSettlement,
    ContractReceiptBundle,
    RecursiveProofWitness,
    EmergencyEscape,
}

impl BridgeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFastExit => "monero_fast_exit",
            Self::MoneroSlowExit => "monero_slow_exit",
            Self::ConfidentialTokenBridge => "confidential_token_bridge",
            Self::DefiSettlement => "defi_settlement",
            Self::ContractReceiptBundle => "contract_receipt_bundle",
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Throttled,
    Draining,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn accepts_batches(self) -> bool {
        matches!(self, Self::Open | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pledged,
    Active,
    Reserving,
    PayingRebates,
    Exhausted,
    Paused,
    Retired,
    Slashed,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserving | Self::PayingRebates)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VoucherStatus {
    Quoted,
    Reserved,
    BatchBound,
    RootAttested,
    Settled,
    Rebated,
    Expired,
    Cancelled,
    Slashed,
}

impl VoucherStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Quoted | Self::Reserved | Self::BatchBound | Self::RootAttested
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    VoucherPriced,
    DaRootPosted,
    SettlementQueued,
    Settled,
    Rebated,
    Challenged,
    Expired,
    Slashed,
}

impl BatchStatus {
    pub fn can_receive_rebate(self) -> bool {
        matches!(
            self,
            Self::DaRootPosted | Self::SettlementQueued | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementKind {
    MoneroExit,
    TokenBridgeSettlement,
    ContractReceiptBundle,
}

impl SettlementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExit => "monero_exit",
            Self::TokenBridgeSettlement => "token_bridge_settlement",
            Self::ContractReceiptBundle => "contract_receipt_bundle",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStatus {
    Queued,
    EpochPriced,
    SponsorMatched,
    Paid,
    Recycled,
    Disputed,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaRootStatus {
    Posted,
    Fresh,
    Settled,
    Stale,
    Challenged,
    Slashed,
    Superseded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingTarget {
    SponsorBudget,
    BridgeBatch,
    DaRoot,
    Voucher,
}

impl SlashingTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsorBudget => "sponsor_budget",
            Self::BridgeBatch => "bridge_batch",
            Self::DaRoot => "da_root",
            Self::Voucher => "voucher",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionClass {
    Empty,
    Low,
    Target,
    High,
    Surge,
    Emergency,
}

impl CongestionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Low => "low",
            Self::Target => "target",
            Self::High => "high",
            Self::Surge => "surge",
            Self::Emergency => "emergency",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub market_suite: String,
    pub voucher_scheme: String,
    pub rebate_scheme: String,
    pub sponsor_budget_scheme: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub quote_asset_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub target_user_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_match_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub compression_credit_bps: u64,
    pub stale_root_slash_bps: u64,
    pub challenger_reward_bps: u64,
    pub strong_quorum_bps: u64,
    pub epoch_blocks: u64,
    pub voucher_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub root_freshness_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_voucher_price_piconero: u128,
    pub min_sponsor_budget_piconero: u128,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_suite: PQ_SUITE.to_string(),
            market_suite: CONFIDENTIAL_BRIDGE_DA_REBATE_MARKET_SUITE.to_string(),
            voucher_scheme: DA_VOUCHER_SCHEME.to_string(),
            rebate_scheme: REBATE_ALLOCATION_SCHEME.to_string(),
            sponsor_budget_scheme: SPONSOR_BUDGET_SCHEME.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            target_user_fee_bps: DEFAULT_TARGET_USER_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_match_bps: DEFAULT_SPONSOR_MATCH_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            compression_credit_bps: DEFAULT_COMPRESSION_CREDIT_BPS,
            stale_root_slash_bps: DEFAULT_STALE_ROOT_SLASH_BPS,
            challenger_reward_bps: DEFAULT_CHALLENGER_REWARD_BPS,
            strong_quorum_bps: DEFAULT_STRONG_QUORUM_BPS,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            root_freshness_blocks: DEFAULT_ROOT_FRESHNESS_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_voucher_price_piconero: DEFAULT_MIN_VOUCHER_PRICE_PICONERO,
            min_sponsor_budget_piconero: DEFAULT_MIN_SPONSOR_BUDGET_PICONERO,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("hash_suite", &self.hash_suite)?;
        require_non_empty("pq_suite", &self.pq_suite)?;
        require_non_empty("market_suite", &self.market_suite)?;
        require_non_empty("voucher_scheme", &self.voucher_scheme)?;
        require_non_empty("rebate_scheme", &self.rebate_scheme)?;
        require_non_empty("sponsor_budget_scheme", &self.sponsor_budget_scheme)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("rebate_asset_id", &self.rebate_asset_id)?;
        require_non_empty("quote_asset_id", &self.quote_asset_id)?;
        ensure!(self.chain_id == CHAIN_ID, "config chain id mismatch");
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "config protocol version mismatch"
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "config schema mismatch"
        );
        ensure!(
            self.target_user_fee_bps <= self.max_user_fee_bps
                && self.max_user_fee_bps <= MAX_BPS
                && self.target_rebate_bps <= MAX_BPS
                && self.sponsor_match_bps <= MAX_BPS
                && self.sponsor_reserve_bps <= MAX_BPS
                && self.compression_credit_bps <= MAX_BPS
                && self.stale_root_slash_bps <= MAX_BPS
                && self.challenger_reward_bps <= MAX_BPS
                && self.strong_quorum_bps <= MAX_BPS,
            "config basis points out of range"
        );
        ensure!(
            self.epoch_blocks > 0
                && self.voucher_ttl_blocks > 0
                && self.batch_ttl_blocks > 0
                && self.rebate_ttl_blocks > 0
                && self.root_freshness_blocks > 0
                && self.challenge_window_blocks > 0,
            "config windows must be nonzero"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "config pq security below runtime floor"
        );
        ensure!(
            self.min_privacy_set_size > 0
                && self.batch_privacy_set_size >= self.min_privacy_set_size,
            "config privacy set invalid"
        );
        ensure!(
            self.min_voucher_price_piconero > 0 && self.min_sponsor_budget_piconero > 0,
            "config fee floors must be nonzero"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "market_suite": self.market_suite,
            "voucher_scheme": self.voucher_scheme,
            "rebate_scheme": self.rebate_scheme,
            "sponsor_budget_scheme": self.sponsor_budget_scheme,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "target_user_fee_bps": self.target_user_fee_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_match_bps": self.sponsor_match_bps,
            "sponsor_reserve_bps": self.sponsor_reserve_bps,
            "compression_credit_bps": self.compression_credit_bps,
            "stale_root_slash_bps": self.stale_root_slash_bps,
            "challenger_reward_bps": self.challenger_reward_bps,
            "strong_quorum_bps": self.strong_quorum_bps,
            "epoch_blocks": self.epoch_blocks,
            "voucher_ttl_blocks": self.voucher_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "root_freshness_blocks": self.root_freshness_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_voucher_price_piconero": self.min_voucher_price_piconero,
            "min_sponsor_budget_piconero": self.min_sponsor_budget_piconero
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionBand {
    pub class: CongestionClass,
    pub min_load_bps: u64,
    pub max_load_bps: u64,
    pub price_multiplier_bps: u64,
    pub sponsor_match_multiplier_bps: u64,
    pub max_rebate_bps: u64,
}

impl CongestionBand {
    pub fn public_record(&self) -> Value {
        json!({
            "class": self.class,
            "min_load_bps": self.min_load_bps,
            "max_load_bps": self.max_load_bps,
            "price_multiplier_bps": self.price_multiplier_bps,
            "sponsor_match_multiplier_bps": self.sponsor_match_multiplier_bps,
            "max_rebate_bps": self.max_rebate_bps
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.min_load_bps <= self.max_load_bps,
            "band load range invalid"
        );
        ensure!(
            self.max_load_bps <= MAX_BPS
                && self.price_multiplier_bps <= MAX_BPS * 4
                && self.sponsor_match_multiplier_bps <= MAX_BPS * 4
                && self.max_rebate_bps <= MAX_BPS,
            "band basis points out of range"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MarketLane {
    pub id: String,
    pub kind: BridgeLaneKind,
    pub status: LaneStatus,
    pub owner_commitment: String,
    pub base_fee_per_kb_piconero: u128,
    pub target_da_bytes: u64,
    pub current_da_bytes: u64,
    pub settlement_weight_bps: u64,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub updated_height: u64,
}

impl MarketLane {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "base_fee_per_kb_piconero": self.base_fee_per_kb_piconero,
            "target_da_bytes": self.target_da_bytes,
            "current_da_bytes": self.current_da_bytes,
            "settlement_weight_bps": self.settlement_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "updated_height": self.updated_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-MARKET-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBudget {
    pub id: String,
    pub sponsor_commitment: String,
    pub lane_id: String,
    pub status: SponsorStatus,
    pub epoch: u64,
    pub total_budget_piconero: u128,
    pub reserved_piconero: u128,
    pub paid_piconero: u128,
    pub slashed_piconero: u128,
    pub min_privacy_set_size: u64,
    pub max_user_fee_bps: u64,
    pub remaining_piconero: u128,
    pub nullifier_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl SponsorBudget {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "sponsor_commitment": self.sponsor_commitment,
            "lane_id": self.lane_id,
            "status": self.status,
            "epoch": self.epoch,
            "total_budget_piconero": self.total_budget_piconero,
            "reserved_piconero": self.reserved_piconero,
            "paid_piconero": self.paid_piconero,
            "slashed_piconero": self.slashed_piconero,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "remaining_piconero": self.remaining_piconero,
            "nullifier_root": self.nullifier_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-SPONSOR-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucher {
    pub id: String,
    pub lane_id: String,
    pub sponsor_budget_id: Option<String>,
    pub status: VoucherStatus,
    pub epoch: u64,
    pub congestion_class: CongestionClass,
    pub da_bytes: u64,
    pub base_price_piconero: u128,
    pub congestion_surcharge_piconero: u128,
    pub proof_credit_piconero: u128,
    pub sponsor_match_piconero: u128,
    pub user_price_piconero: u128,
    pub max_rebate_piconero: u128,
    pub quote_root: String,
    pub reserved_for_batch: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
}

impl DaVoucher {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "lane_id": self.lane_id,
            "sponsor_budget_id": self.sponsor_budget_id,
            "status": self.status,
            "epoch": self.epoch,
            "congestion_class": self.congestion_class,
            "da_bytes": self.da_bytes,
            "base_price_piconero": self.base_price_piconero,
            "congestion_surcharge_piconero": self.congestion_surcharge_piconero,
            "proof_credit_piconero": self.proof_credit_piconero,
            "sponsor_match_piconero": self.sponsor_match_piconero,
            "user_price_piconero": self.user_price_piconero,
            "max_rebate_piconero": self.max_rebate_piconero,
            "quote_root": self.quote_root,
            "reserved_for_batch": self.reserved_for_batch,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-VOUCHER", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeBatch {
    pub id: String,
    pub lane_id: String,
    pub voucher_id: String,
    pub status: BatchStatus,
    pub epoch: u64,
    pub bridge_batch_root: String,
    pub settlement_root: String,
    pub receipt_bundle_root: String,
    pub nullifier_root: String,
    pub da_bytes: u64,
    pub monero_exit_count: u64,
    pub token_settlement_count: u64,
    pub contract_receipt_count: u64,
    pub aggregate_user_fee_piconero: u128,
    pub posted_da_root_id: Option<String>,
    pub compression_credit_id: Option<String>,
    pub created_height: u64,
    pub expires_height: u64,
}

impl BridgeBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "lane_id": self.lane_id,
            "voucher_id": self.voucher_id,
            "status": self.status,
            "epoch": self.epoch,
            "bridge_batch_root": self.bridge_batch_root,
            "settlement_root": self.settlement_root,
            "receipt_bundle_root": self.receipt_bundle_root,
            "nullifier_root": self.nullifier_root,
            "da_bytes": self.da_bytes,
            "monero_exit_count": self.monero_exit_count,
            "token_settlement_count": self.token_settlement_count,
            "contract_receipt_count": self.contract_receipt_count,
            "aggregate_user_fee_piconero": self.aggregate_user_fee_piconero,
            "posted_da_root_id": self.posted_da_root_id,
            "compression_credit_id": self.compression_credit_id,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCompressionCredit {
    pub id: String,
    pub batch_id: String,
    pub proof_system: String,
    pub uncompressed_bytes: u64,
    pub compressed_bytes: u64,
    pub saved_bytes: u64,
    pub credit_piconero: u128,
    pub credit_bps: u64,
    pub transcript_root: String,
    pub verifier_commitment: String,
    pub created_height: u64,
}

impl ProofCompressionCredit {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "batch_id": self.batch_id,
            "proof_system": self.proof_system,
            "uncompressed_bytes": self.uncompressed_bytes,
            "compressed_bytes": self.compressed_bytes,
            "saved_bytes": self.saved_bytes,
            "credit_piconero": self.credit_piconero,
            "credit_bps": self.credit_bps,
            "transcript_root": self.transcript_root,
            "verifier_commitment": self.verifier_commitment,
            "created_height": self.created_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-PROOF-COMPRESSION-CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaRootRecord {
    pub id: String,
    pub batch_id: String,
    pub status: DaRootStatus,
    pub da_root: String,
    pub availability_root: String,
    pub provider_commitment: String,
    pub attestation_root: String,
    pub quorum_bps: u64,
    pub posted_height: u64,
    pub fresh_until_height: u64,
    pub settled_height: Option<u64>,
}

impl DaRootRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "batch_id": self.batch_id,
            "status": self.status,
            "da_root": self.da_root,
            "availability_root": self.availability_root,
            "provider_commitment": self.provider_commitment,
            "attestation_root": self.attestation_root,
            "quorum_bps": self.quorum_bps,
            "posted_height": self.posted_height,
            "fresh_until_height": self.fresh_until_height,
            "settled_height": self.settled_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-ROOT-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateEpoch {
    pub id: String,
    pub epoch: u64,
    pub status: AllocationStatus,
    pub start_height: u64,
    pub end_height: u64,
    pub total_voucher_price_piconero: u128,
    pub total_sponsor_reserved_piconero: u128,
    pub total_compression_credit_piconero: u128,
    pub total_rebate_pool_piconero: u128,
    pub paid_rebates_piconero: u128,
    pub recycled_piconero: u128,
    pub allocation_root: String,
}

impl RebateEpoch {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "epoch": self.epoch,
            "status": self.status,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "total_voucher_price_piconero": self.total_voucher_price_piconero,
            "total_sponsor_reserved_piconero": self.total_sponsor_reserved_piconero,
            "total_compression_credit_piconero": self.total_compression_credit_piconero,
            "total_rebate_pool_piconero": self.total_rebate_pool_piconero,
            "paid_rebates_piconero": self.paid_rebates_piconero,
            "recycled_piconero": self.recycled_piconero,
            "allocation_root": self.allocation_root
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-REBATE-EPOCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateAllocation {
    pub id: String,
    pub epoch_id: String,
    pub batch_id: String,
    pub settlement_kind: SettlementKind,
    pub status: AllocationStatus,
    pub recipient_commitment: String,
    pub amount_piconero: u128,
    pub sponsor_paid_piconero: u128,
    pub proof_credit_applied_piconero: u128,
    pub nullifier_hash: String,
    pub claim_root: String,
    pub created_height: u64,
    pub expires_height: u64,
}

impl RebateAllocation {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "epoch_id": self.epoch_id,
            "batch_id": self.batch_id,
            "settlement_kind": self.settlement_kind,
            "status": self.status,
            "recipient_commitment": self.recipient_commitment,
            "amount_piconero": self.amount_piconero,
            "sponsor_paid_piconero": self.sponsor_paid_piconero,
            "proof_credit_applied_piconero": self.proof_credit_applied_piconero,
            "nullifier_hash": self.nullifier_hash,
            "claim_root": self.claim_root,
            "created_height": self.created_height,
            "expires_height": self.expires_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-REBATE-ALLOCATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingRecord {
    pub id: String,
    pub target: SlashingTarget,
    pub target_id: String,
    pub evidence_root: String,
    pub challenger_commitment: String,
    pub slashed_piconero: u128,
    pub challenger_reward_piconero: u128,
    pub recycled_piconero: u128,
    pub created_height: u64,
}

impl SlashingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "target": self.target,
            "target_id": self.target_id,
            "evidence_root": self.evidence_root,
            "challenger_commitment": self.challenger_commitment,
            "slashed_piconero": self.slashed_piconero,
            "challenger_reward_piconero": self.challenger_reward_piconero,
            "recycled_piconero": self.recycled_piconero,
            "created_height": self.created_height
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-SLASHING-RECORD", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicEvent {
    pub id: String,
    pub kind: String,
    pub subject_id: String,
    pub event_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl PublicEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "kind": self.kind,
            "subject_id": self.subject_id,
            "event_root": self.event_root,
            "height": self.height,
            "sequence": self.sequence
        })
    }

    pub fn root(&self) -> String {
        payload_root("BRIDGE-DA-PUBLIC-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane: u64,
    pub next_sponsor_budget: u64,
    pub next_voucher: u64,
    pub next_batch: u64,
    pub next_compression_credit: u64,
    pub next_da_root: u64,
    pub next_rebate_epoch: u64,
    pub next_rebate_allocation: u64,
    pub next_slashing_record: u64,
    pub next_event: u64,
}

impl Counters {
    pub fn zero() -> Self {
        Self {
            next_lane: 1,
            next_sponsor_budget: 1,
            next_voucher: 1,
            next_batch: 1,
            next_compression_credit: 1,
            next_da_root: 1,
            next_rebate_epoch: 1,
            next_rebate_allocation: 1,
            next_slashing_record: 1,
            next_event: 1,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "next_lane": self.next_lane,
            "next_sponsor_budget": self.next_sponsor_budget,
            "next_voucher": self.next_voucher,
            "next_batch": self.next_batch,
            "next_compression_credit": self.next_compression_credit,
            "next_da_root": self.next_da_root,
            "next_rebate_epoch": self.next_rebate_epoch,
            "next_rebate_allocation": self.next_rebate_allocation,
            "next_slashing_record": self.next_slashing_record,
            "next_event": self.next_event
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub congestion_band_root: String,
    pub lane_root: String,
    pub sponsor_budget_root: String,
    pub voucher_root: String,
    pub bridge_batch_root: String,
    pub compression_credit_root: String,
    pub rebate_epoch_root: String,
    pub rebate_allocation_root: String,
    pub da_root_record_root: String,
    pub slashing_record_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "congestion_band_root": self.congestion_band_root,
            "lane_root": self.lane_root,
            "sponsor_budget_root": self.sponsor_budget_root,
            "voucher_root": self.voucher_root,
            "bridge_batch_root": self.bridge_batch_root,
            "compression_credit_root": self.compression_credit_root,
            "rebate_epoch_root": self.rebate_epoch_root,
            "rebate_allocation_root": self.rebate_allocation_root,
            "da_root_record_root": self.da_root_record_root,
            "slashing_record_root": self.slashing_record_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub congestion_bands: Vec<CongestionBand>,
    pub market_lanes: BTreeMap<String, MarketLane>,
    pub sponsor_budgets: BTreeMap<String, SponsorBudget>,
    pub vouchers: BTreeMap<String, DaVoucher>,
    pub bridge_batches: BTreeMap<String, BridgeBatch>,
    pub compression_credits: BTreeMap<String, ProofCompressionCredit>,
    pub rebate_epochs: BTreeMap<String, RebateEpoch>,
    pub rebate_allocations: BTreeMap<String, RebateAllocation>,
    pub da_roots: BTreeMap<String, DaRootRecord>,
    pub slashing_records: BTreeMap<String, SlashingRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_events: BTreeMap<String, PublicEvent>,
    pub counters: Counters,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            current_height: DEVNET_HEIGHT,
            current_epoch: DEVNET_EPOCH,
            congestion_bands: default_congestion_bands(),
            market_lanes: BTreeMap::new(),
            sponsor_budgets: BTreeMap::new(),
            vouchers: BTreeMap::new(),
            bridge_batches: BTreeMap::new(),
            compression_credits: BTreeMap::new(),
            rebate_epochs: BTreeMap::new(),
            rebate_allocations: BTreeMap::new(),
            da_roots: BTreeMap::new(),
            slashing_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_events: BTreeMap::new(),
            counters: Counters::zero(),
        };
        state.validate_congestion_bands()?;
        state.append_event("state_initialized", "config", DEVNET_HEIGHT)?;
        Ok(state)
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(error) => devnet_fallback_state(&error),
        };
        let lane = match state.open_market_lane(
            BridgeLaneKind::MoneroFastExit,
            "devnet-lane-owner",
            24_000,
            2_000_000,
            DEFAULT_TARGET_USER_FEE_BPS,
            DEFAULT_BATCH_PRIVACY_SET_SIZE,
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let sponsor = match state.pledge_sponsor_budget(
            &lane,
            "devnet-sponsor",
            DEFAULT_MIN_SPONSOR_BUDGET_PICONERO * 4,
            DEFAULT_MAX_USER_FEE_BPS,
            DEFAULT_MIN_PRIVACY_SET_SIZE,
            "devnet-sponsor-nullifier-root",
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let voucher = match state.price_da_voucher(
            &lane,
            Some(&sponsor),
            128_000,
            160_000,
            96_000,
            "devnet-quote-root",
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let batch = match state.bind_private_bridge_batch(
            &voucher,
            "devnet-bridge-batch-root",
            "devnet-settlement-root",
            "devnet-receipt-bundle-root",
            "devnet-batch-nullifier-root",
            128_000,
            12,
            18,
            24,
            800_000,
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let credit = match state.issue_proof_compression_credit(
            &batch,
            "devnet-recursive-proof",
            160_000,
            96_000,
            "devnet-proof-transcript-root",
            "devnet-verifier",
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let root = match state.post_da_root(
            &batch,
            "devnet-da-root",
            "devnet-availability-root",
            "devnet-provider",
            "devnet-attestation-root",
            DEFAULT_STRONG_QUORUM_BPS,
            DEVNET_HEIGHT,
        ) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let epoch = match state.open_rebate_epoch(DEVNET_EPOCH, DEVNET_HEIGHT) {
            Ok(id) => id,
            Err(_) => return state,
        };
        let _ = state.allocate_batch_rebates(
            &epoch,
            &batch,
            Some(&credit),
            vec![
                (
                    SettlementKind::MoneroExit,
                    "devnet-monero-exit-recipient".to_string(),
                    "devnet-monero-exit-claim".to_string(),
                    4_000_000,
                ),
                (
                    SettlementKind::TokenBridgeSettlement,
                    "devnet-token-recipient".to_string(),
                    "devnet-token-claim".to_string(),
                    2_000_000,
                ),
                (
                    SettlementKind::ContractReceiptBundle,
                    "devnet-contract-recipient".to_string(),
                    "devnet-contract-claim".to_string(),
                    1_000_000,
                ),
            ],
            DEVNET_HEIGHT,
        );
        let _ = state.settle_da_root(&root, DEVNET_HEIGHT + 8);
        state
    }

    pub fn set_height(&mut self, height: u64) -> Result<()> {
        ensure!(height >= self.current_height, "height cannot move backward");
        self.current_height = height;
        self.current_epoch = height / self.config.epoch_blocks;
        Ok(())
    }

    pub fn replace_congestion_bands(&mut self, bands: Vec<CongestionBand>) -> Result<()> {
        ensure!(!bands.is_empty(), "congestion bands empty");
        ensure!(
            bands.len() <= MAX_CONGESTION_BANDS,
            "too many congestion bands"
        );
        for band in &bands {
            band.validate()?;
        }
        self.congestion_bands = bands;
        self.validate_congestion_bands()?;
        self.append_event("congestion_bands_replaced", "bands", self.current_height)?;
        Ok(())
    }

    pub fn open_market_lane(
        &mut self,
        kind: BridgeLaneKind,
        owner_commitment: &str,
        base_fee_per_kb_piconero: u128,
        target_da_bytes: u64,
        settlement_weight_bps: u64,
        privacy_set_size: u64,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("owner_commitment", owner_commitment)?;
        ensure!(
            self.market_lanes.len() < MAX_MARKET_LANES,
            "market lane limit reached"
        );
        ensure!(base_fee_per_kb_piconero > 0, "base fee must be nonzero");
        ensure!(target_da_bytes > 0, "target da bytes must be nonzero");
        ensure!(settlement_weight_bps <= MAX_BPS, "lane weight out of range");
        ensure!(
            privacy_set_size >= self.config.min_privacy_set_size,
            "lane privacy set too small"
        );
        let id = lane_id(self.counters.next_lane, kind, owner_commitment);
        self.counters.next_lane += 1;
        let lane = MarketLane {
            id: id.clone(),
            kind,
            status: LaneStatus::Open,
            owner_commitment: owner_commitment.to_string(),
            base_fee_per_kb_piconero,
            target_da_bytes,
            current_da_bytes: 0,
            settlement_weight_bps,
            privacy_set_size,
            created_height: height,
            updated_height: height,
        };
        self.market_lanes.insert(id.clone(), lane);
        self.append_event("market_lane_opened", &id, height)?;
        Ok(id)
    }

    pub fn pledge_sponsor_budget(
        &mut self,
        lane_id: &str,
        sponsor_commitment: &str,
        total_budget_piconero: u128,
        max_user_fee_bps: u64,
        min_privacy_set_size: u64,
        nullifier_root: &str,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("sponsor_commitment", sponsor_commitment)?;
        require_non_empty("nullifier_root", nullifier_root)?;
        ensure_known("lane", lane_id, &self.market_lanes)?;
        ensure!(
            self.sponsor_budgets.len() < MAX_SPONSOR_BUDGETS,
            "sponsor budget limit reached"
        );
        ensure!(
            total_budget_piconero >= self.config.min_sponsor_budget_piconero,
            "sponsor budget below floor"
        );
        ensure!(
            max_user_fee_bps <= self.config.max_user_fee_bps,
            "sponsor max fee exceeds config"
        );
        ensure!(
            min_privacy_set_size >= self.config.min_privacy_set_size,
            "sponsor privacy set too small"
        );
        let id = sponsor_budget_id(
            self.counters.next_sponsor_budget,
            lane_id,
            sponsor_commitment,
            self.current_epoch,
        );
        self.counters.next_sponsor_budget += 1;
        let budget = SponsorBudget {
            id: id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            lane_id: lane_id.to_string(),
            status: SponsorStatus::Active,
            epoch: self.current_epoch,
            total_budget_piconero,
            reserved_piconero: 0,
            paid_piconero: 0,
            slashed_piconero: 0,
            min_privacy_set_size,
            max_user_fee_bps,
            remaining_piconero: total_budget_piconero,
            nullifier_root: nullifier_root.to_string(),
            created_height: height,
            expires_height: height + self.config.epoch_blocks,
        };
        self.sponsor_budgets.insert(id.clone(), budget);
        self.append_event("sponsor_budget_pledged", &id, height)?;
        Ok(id)
    }

    pub fn price_da_voucher(
        &mut self,
        lane_id: &str,
        sponsor_budget_id: Option<&str>,
        da_bytes: u64,
        uncompressed_proof_bytes: u64,
        compressed_proof_bytes: u64,
        quote_root: &str,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("quote_root", quote_root)?;
        ensure_known("lane", lane_id, &self.market_lanes)?;
        ensure!(self.vouchers.len() < MAX_VOUCHERS, "voucher limit reached");
        ensure!(da_bytes > 0, "da bytes must be nonzero");
        let lane = self
            .market_lanes
            .get(lane_id)
            .ok_or_else(|| "lane missing".to_string())?
            .clone();
        ensure!(
            lane.status.accepts_batches(),
            "lane does not accept batches"
        );
        let load_bps = load_bps(lane.current_da_bytes, lane.target_da_bytes, da_bytes);
        let band = self.band_for_load(load_bps)?;
        let kb = ceil_div_u128(da_bytes as u128, 1024);
        let raw_base = lane.base_fee_per_kb_piconero.saturating_mul(kb);
        let base_price = raw_base.max(self.config.min_voucher_price_piconero);
        let priced = mul_bps(base_price, band.price_multiplier_bps);
        let congestion_surcharge = priced.saturating_sub(base_price);
        let saved_bytes = uncompressed_proof_bytes.saturating_sub(compressed_proof_bytes);
        let proof_credit = mul_bps(
            lane.base_fee_per_kb_piconero
                .saturating_mul(ceil_div_u128(saved_bytes as u128, 1024)),
            self.config.compression_credit_bps,
        );
        let mut sponsor_match = 0;
        if let Some(id) = sponsor_budget_id {
            ensure_known("sponsor budget", id, &self.sponsor_budgets)?;
            let budget = self
                .sponsor_budgets
                .get_mut(id)
                .ok_or_else(|| "sponsor budget missing".to_string())?;
            ensure!(budget.status.usable(), "sponsor budget not usable");
            ensure!(budget.lane_id == lane_id, "sponsor budget lane mismatch");
            ensure!(budget.expires_height >= height, "sponsor budget expired");
            ensure!(
                lane.privacy_set_size >= budget.min_privacy_set_size,
                "sponsor privacy condition not met"
            );
            sponsor_match = mul_bps(
                mul_bps(priced, self.config.sponsor_match_bps),
                band.sponsor_match_multiplier_bps,
            );
            sponsor_match = sponsor_match.min(budget.remaining_piconero);
            budget.reserved_piconero = budget.reserved_piconero.saturating_add(sponsor_match);
            budget.remaining_piconero = budget.remaining_piconero.saturating_sub(sponsor_match);
            budget.status = SponsorStatus::Reserving;
        }
        let user_price = priced
            .saturating_sub(proof_credit)
            .saturating_sub(sponsor_match);
        let user_price = user_price.max(self.config.min_voucher_price_piconero);
        let max_rebate = mul_bps(
            priced
                .saturating_add(sponsor_match)
                .saturating_add(proof_credit),
            band.max_rebate_bps.min(self.config.target_rebate_bps),
        );
        let id = voucher_id(
            self.counters.next_voucher,
            lane_id,
            quote_root,
            da_bytes,
            self.current_epoch,
        );
        self.counters.next_voucher += 1;
        let voucher = DaVoucher {
            id: id.clone(),
            lane_id: lane_id.to_string(),
            sponsor_budget_id: sponsor_budget_id.map(|value| value.to_string()),
            status: VoucherStatus::Quoted,
            epoch: self.current_epoch,
            congestion_class: band.class,
            da_bytes,
            base_price_piconero: base_price,
            congestion_surcharge_piconero: congestion_surcharge,
            proof_credit_piconero: proof_credit,
            sponsor_match_piconero: sponsor_match,
            user_price_piconero: user_price,
            max_rebate_piconero: max_rebate,
            quote_root: quote_root.to_string(),
            reserved_for_batch: None,
            created_height: height,
            expires_height: height + self.config.voucher_ttl_blocks,
        };
        if let Some(lane) = self.market_lanes.get_mut(lane_id) {
            lane.current_da_bytes = lane.current_da_bytes.saturating_add(da_bytes);
            lane.updated_height = height;
        }
        self.vouchers.insert(id.clone(), voucher);
        self.append_event("da_voucher_priced", &id, height)?;
        Ok(id)
    }

    pub fn reserve_voucher_for_batch(
        &mut self,
        voucher_id: &str,
        batch_commitment: &str,
        height: u64,
    ) -> Result<()> {
        self.set_height(height)?;
        require_non_empty("batch_commitment", batch_commitment)?;
        let voucher = self
            .vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| "voucher missing".to_string())?;
        ensure!(
            voucher.status == VoucherStatus::Quoted,
            "voucher not quoted"
        );
        ensure!(voucher.expires_height >= height, "voucher expired");
        voucher.status = VoucherStatus::Reserved;
        voucher.reserved_for_batch = Some(batch_commitment.to_string());
        self.append_event("da_voucher_reserved", voucher_id, height)?;
        Ok(())
    }

    pub fn bind_private_bridge_batch(
        &mut self,
        voucher_id: &str,
        bridge_batch_root: &str,
        settlement_root: &str,
        receipt_bundle_root: &str,
        nullifier_root: &str,
        da_bytes: u64,
        monero_exit_count: u64,
        token_settlement_count: u64,
        contract_receipt_count: u64,
        aggregate_user_fee_piconero: u128,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("bridge_batch_root", bridge_batch_root)?;
        require_non_empty("settlement_root", settlement_root)?;
        require_non_empty("receipt_bundle_root", receipt_bundle_root)?;
        require_non_empty("nullifier_root", nullifier_root)?;
        ensure!(
            self.bridge_batches.len() < MAX_BRIDGE_BATCHES,
            "bridge batch limit reached"
        );
        let voucher = self
            .vouchers
            .get_mut(voucher_id)
            .ok_or_else(|| "voucher missing".to_string())?;
        ensure!(voucher.status.live(), "voucher not live");
        ensure!(voucher.expires_height >= height, "voucher expired");
        ensure!(
            da_bytes <= voucher.da_bytes,
            "batch exceeds voucher da bytes"
        );
        let lane_id = voucher.lane_id.clone();
        ensure_known("lane", &lane_id, &self.market_lanes)?;
        let id = batch_id(
            self.counters.next_batch,
            &lane_id,
            voucher_id,
            bridge_batch_root,
        );
        self.counters.next_batch += 1;
        voucher.status = VoucherStatus::BatchBound;
        voucher.reserved_for_batch = Some(id.clone());
        let batch = BridgeBatch {
            id: id.clone(),
            lane_id,
            voucher_id: voucher_id.to_string(),
            status: BatchStatus::VoucherPriced,
            epoch: self.current_epoch,
            bridge_batch_root: bridge_batch_root.to_string(),
            settlement_root: settlement_root.to_string(),
            receipt_bundle_root: receipt_bundle_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            da_bytes,
            monero_exit_count,
            token_settlement_count,
            contract_receipt_count,
            aggregate_user_fee_piconero,
            posted_da_root_id: None,
            compression_credit_id: None,
            created_height: height,
            expires_height: height + self.config.batch_ttl_blocks,
        };
        self.bridge_batches.insert(id.clone(), batch);
        self.append_event("private_bridge_batch_bound", &id, height)?;
        Ok(id)
    }

    pub fn issue_proof_compression_credit(
        &mut self,
        batch_id: &str,
        proof_system: &str,
        uncompressed_bytes: u64,
        compressed_bytes: u64,
        transcript_root: &str,
        verifier_commitment: &str,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("proof_system", proof_system)?;
        require_non_empty("transcript_root", transcript_root)?;
        require_non_empty("verifier_commitment", verifier_commitment)?;
        ensure_known("batch", batch_id, &self.bridge_batches)?;
        ensure!(
            self.compression_credits.len() < MAX_COMPRESSION_CREDITS,
            "compression credit limit reached"
        );
        ensure!(
            uncompressed_bytes >= compressed_bytes,
            "compression bytes invalid"
        );
        let batch = self
            .bridge_batches
            .get(batch_id)
            .ok_or_else(|| "batch missing".to_string())?
            .clone();
        let lane = self
            .market_lanes
            .get(&batch.lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        let saved_bytes = uncompressed_bytes - compressed_bytes;
        let saved_kb = ceil_div_u128(saved_bytes as u128, 1024);
        let raw_credit = lane.base_fee_per_kb_piconero.saturating_mul(saved_kb);
        let credit = mul_bps(raw_credit, self.config.compression_credit_bps);
        let id = compression_credit_id(
            self.counters.next_compression_credit,
            batch_id,
            proof_system,
            transcript_root,
        );
        self.counters.next_compression_credit += 1;
        let record = ProofCompressionCredit {
            id: id.clone(),
            batch_id: batch_id.to_string(),
            proof_system: proof_system.to_string(),
            uncompressed_bytes,
            compressed_bytes,
            saved_bytes,
            credit_piconero: credit,
            credit_bps: self.config.compression_credit_bps,
            transcript_root: transcript_root.to_string(),
            verifier_commitment: verifier_commitment.to_string(),
            created_height: height,
        };
        self.compression_credits.insert(id.clone(), record);
        if let Some(batch) = self.bridge_batches.get_mut(batch_id) {
            batch.compression_credit_id = Some(id.clone());
        }
        self.append_event("proof_compression_credit_issued", &id, height)?;
        Ok(id)
    }

    pub fn post_da_root(
        &mut self,
        batch_id: &str,
        da_root: &str,
        availability_root: &str,
        provider_commitment: &str,
        attestation_root: &str,
        quorum_bps: u64,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("da_root", da_root)?;
        require_non_empty("availability_root", availability_root)?;
        require_non_empty("provider_commitment", provider_commitment)?;
        require_non_empty("attestation_root", attestation_root)?;
        ensure_known("batch", batch_id, &self.bridge_batches)?;
        ensure!(self.da_roots.len() < MAX_DA_ROOTS, "da root limit reached");
        ensure!(
            quorum_bps >= self.config.strong_quorum_bps && quorum_bps <= MAX_BPS,
            "da root quorum too weak"
        );
        let id = da_root_id(
            self.counters.next_da_root,
            batch_id,
            da_root,
            availability_root,
        );
        self.counters.next_da_root += 1;
        let record = DaRootRecord {
            id: id.clone(),
            batch_id: batch_id.to_string(),
            status: DaRootStatus::Fresh,
            da_root: da_root.to_string(),
            availability_root: availability_root.to_string(),
            provider_commitment: provider_commitment.to_string(),
            attestation_root: attestation_root.to_string(),
            quorum_bps,
            posted_height: height,
            fresh_until_height: height + self.config.root_freshness_blocks,
            settled_height: None,
        };
        self.da_roots.insert(id.clone(), record);
        if let Some(batch) = self.bridge_batches.get_mut(batch_id) {
            batch.status = BatchStatus::DaRootPosted;
            batch.posted_da_root_id = Some(id.clone());
        }
        let voucher_id = self
            .bridge_batches
            .get(batch_id)
            .map(|batch| batch.voucher_id.clone())
            .ok_or_else(|| "batch missing".to_string())?;
        if let Some(voucher) = self.vouchers.get_mut(&voucher_id) {
            voucher.status = VoucherStatus::RootAttested;
        }
        self.append_event("da_root_posted", &id, height)?;
        Ok(id)
    }

    pub fn settle_da_root(&mut self, da_root_id: &str, height: u64) -> Result<()> {
        self.set_height(height)?;
        let root = self
            .da_roots
            .get_mut(da_root_id)
            .ok_or_else(|| "da root missing".to_string())?;
        ensure!(
            matches!(root.status, DaRootStatus::Fresh | DaRootStatus::Posted),
            "da root not settleable"
        );
        root.status = DaRootStatus::Settled;
        root.settled_height = Some(height);
        let batch_id = root.batch_id.clone();
        if let Some(batch) = self.bridge_batches.get_mut(&batch_id) {
            batch.status = BatchStatus::Settled;
        }
        self.append_event("da_root_settled", da_root_id, height)?;
        Ok(())
    }

    pub fn open_rebate_epoch(&mut self, epoch: u64, height: u64) -> Result<String> {
        self.set_height(height)?;
        ensure!(
            self.rebate_epochs.len() < MAX_REBATE_EPOCHS,
            "rebate epoch limit reached"
        );
        let start_height = epoch.saturating_mul(self.config.epoch_blocks);
        let end_height = start_height + self.config.epoch_blocks;
        let id = rebate_epoch_id(self.counters.next_rebate_epoch, epoch, start_height);
        self.counters.next_rebate_epoch += 1;
        let record = RebateEpoch {
            id: id.clone(),
            epoch,
            status: AllocationStatus::Queued,
            start_height,
            end_height,
            total_voucher_price_piconero: 0,
            total_sponsor_reserved_piconero: 0,
            total_compression_credit_piconero: 0,
            total_rebate_pool_piconero: 0,
            paid_rebates_piconero: 0,
            recycled_piconero: 0,
            allocation_root: collection_root("BRIDGE-DA-EMPTY-ALLOCATIONS", Vec::new()),
        };
        self.rebate_epochs.insert(id.clone(), record);
        self.append_event("rebate_epoch_opened", &id, height)?;
        Ok(id)
    }

    pub fn allocate_batch_rebates(
        &mut self,
        epoch_id: &str,
        batch_id: &str,
        compression_credit_id: Option<&str>,
        claims: Vec<(SettlementKind, String, String, u128)>,
        height: u64,
    ) -> Result<Vec<String>> {
        self.set_height(height)?;
        ensure_known("rebate epoch", epoch_id, &self.rebate_epochs)?;
        ensure_known("batch", batch_id, &self.bridge_batches)?;
        ensure!(
            self.rebate_allocations.len().saturating_add(claims.len()) <= MAX_REBATE_ALLOCATIONS,
            "rebate allocation limit reached"
        );
        ensure!(!claims.is_empty(), "rebate claims empty");
        let batch = self
            .bridge_batches
            .get(batch_id)
            .ok_or_else(|| "batch missing".to_string())?
            .clone();
        ensure!(
            batch.status.can_receive_rebate(),
            "batch cannot receive rebate"
        );
        let voucher = self
            .vouchers
            .get(&batch.voucher_id)
            .ok_or_else(|| "voucher missing".to_string())?
            .clone();
        let proof_credit = match compression_credit_id {
            Some(id) => {
                let credit = self
                    .compression_credits
                    .get(id)
                    .ok_or_else(|| "compression credit missing".to_string())?;
                ensure!(
                    credit.batch_id == batch_id,
                    "compression credit batch mismatch"
                );
                credit.credit_piconero
            }
            None => 0,
        };
        let sponsor_reserved = voucher.sponsor_match_piconero;
        let max_pool = voucher
            .max_rebate_piconero
            .saturating_add(sponsor_reserved)
            .saturating_add(proof_credit);
        let requested_total = claims
            .iter()
            .fold(0u128, |sum, (_, _, _, amount)| sum.saturating_add(*amount));
        ensure!(requested_total > 0, "requested rebate total zero");
        let payable_total = requested_total.min(max_pool);
        let mut ids = Vec::new();
        for (kind, recipient, claim_label, amount) in claims {
            require_non_empty("recipient_commitment", &recipient)?;
            require_non_empty("claim_label", &claim_label)?;
            let share = proportional_amount(payable_total, amount, requested_total);
            let nullifier = nullifier_hash(kind.as_str(), &claim_label);
            ensure!(
                !self.nullifiers.contains(&nullifier),
                "rebate nullifier already used"
            );
            self.nullifiers.insert(nullifier.clone());
            let sponsor_paid = proportional_amount(sponsor_reserved, share, payable_total.max(1));
            let proof_applied = proportional_amount(proof_credit, share, payable_total.max(1));
            let claim_root = payload_root(
                "BRIDGE-DA-REBATE-CLAIM",
                &json!({
                    "epoch_id": epoch_id,
                    "batch_id": batch_id,
                    "kind": kind,
                    "recipient_commitment": recipient,
                    "amount_piconero": share,
                    "nullifier_hash": nullifier
                }),
            );
            let id = rebate_allocation_id(
                self.counters.next_rebate_allocation,
                epoch_id,
                batch_id,
                kind,
                &nullifier,
            );
            self.counters.next_rebate_allocation += 1;
            let allocation = RebateAllocation {
                id: id.clone(),
                epoch_id: epoch_id.to_string(),
                batch_id: batch_id.to_string(),
                settlement_kind: kind,
                status: AllocationStatus::Paid,
                recipient_commitment: recipient,
                amount_piconero: share,
                sponsor_paid_piconero: sponsor_paid,
                proof_credit_applied_piconero: proof_applied,
                nullifier_hash: nullifier,
                claim_root,
                created_height: height,
                expires_height: height + self.config.rebate_ttl_blocks,
            };
            self.rebate_allocations.insert(id.clone(), allocation);
            ids.push(id);
        }
        let allocation_root = self.allocations_for_epoch_root(epoch_id);
        if let Some(epoch) = self.rebate_epochs.get_mut(epoch_id) {
            epoch.status = AllocationStatus::Paid;
            epoch.total_voucher_price_piconero = epoch
                .total_voucher_price_piconero
                .saturating_add(voucher.user_price_piconero);
            epoch.total_sponsor_reserved_piconero = epoch
                .total_sponsor_reserved_piconero
                .saturating_add(sponsor_reserved);
            epoch.total_compression_credit_piconero = epoch
                .total_compression_credit_piconero
                .saturating_add(proof_credit);
            epoch.total_rebate_pool_piconero =
                epoch.total_rebate_pool_piconero.saturating_add(max_pool);
            epoch.paid_rebates_piconero = epoch.paid_rebates_piconero.saturating_add(payable_total);
            epoch.recycled_piconero = epoch
                .recycled_piconero
                .saturating_add(max_pool.saturating_sub(payable_total));
            epoch.allocation_root = allocation_root;
        }
        if let Some(batch) = self.bridge_batches.get_mut(batch_id) {
            batch.status = BatchStatus::Rebated;
        }
        if let Some(voucher) = self.vouchers.get_mut(&batch.voucher_id) {
            voucher.status = VoucherStatus::Rebated;
        }
        if let Some(sponsor_id) = voucher.sponsor_budget_id {
            if let Some(budget) = self.sponsor_budgets.get_mut(&sponsor_id) {
                let paid = sponsor_reserved.min(payable_total);
                budget.paid_piconero = budget.paid_piconero.saturating_add(paid);
                budget.reserved_piconero = budget.reserved_piconero.saturating_sub(paid);
                if budget.remaining_piconero == 0 && budget.reserved_piconero == 0 {
                    budget.status = SponsorStatus::Exhausted;
                } else {
                    budget.status = SponsorStatus::PayingRebates;
                }
            }
        }
        self.append_event("batch_rebates_allocated", batch_id, height)?;
        Ok(ids)
    }

    pub fn slash_stale_da_root(
        &mut self,
        da_root_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        height: u64,
    ) -> Result<String> {
        self.set_height(height)?;
        require_non_empty("challenger_commitment", challenger_commitment)?;
        require_non_empty("evidence_root", evidence_root)?;
        ensure_known("da root", da_root_id, &self.da_roots)?;
        ensure!(
            self.slashing_records.len() < MAX_SLASHING_RECORDS,
            "slashing record limit reached"
        );
        let root = self
            .da_roots
            .get_mut(da_root_id)
            .ok_or_else(|| "da root missing".to_string())?;
        ensure!(height > root.fresh_until_height, "da root is still fresh");
        ensure!(
            !matches!(root.status, DaRootStatus::Settled | DaRootStatus::Slashed),
            "da root not slashable"
        );
        root.status = DaRootStatus::Slashed;
        let batch_id = root.batch_id.clone();
        let voucher_id = self
            .bridge_batches
            .get(&batch_id)
            .map(|batch| batch.voucher_id.clone())
            .ok_or_else(|| "batch missing".to_string())?;
        let voucher = self
            .vouchers
            .get(&voucher_id)
            .ok_or_else(|| "voucher missing".to_string())?
            .clone();
        let slash_base = voucher
            .sponsor_match_piconero
            .saturating_add(voucher.user_price_piconero)
            .saturating_add(voucher.proof_credit_piconero);
        let slashed = mul_bps(slash_base, self.config.stale_root_slash_bps);
        let challenger_reward = mul_bps(slashed, self.config.challenger_reward_bps);
        let recycled = slashed.saturating_sub(challenger_reward);
        if let Some(batch) = self.bridge_batches.get_mut(&batch_id) {
            batch.status = BatchStatus::Slashed;
        }
        if let Some(voucher) = self.vouchers.get_mut(&voucher_id) {
            voucher.status = VoucherStatus::Slashed;
        }
        if let Some(sponsor_id) = voucher.sponsor_budget_id {
            if let Some(budget) = self.sponsor_budgets.get_mut(&sponsor_id) {
                let sponsor_slash = slashed.min(
                    budget
                        .remaining_piconero
                        .saturating_add(budget.reserved_piconero),
                );
                budget.slashed_piconero = budget.slashed_piconero.saturating_add(sponsor_slash);
                let from_reserved = sponsor_slash.min(budget.reserved_piconero);
                budget.reserved_piconero = budget.reserved_piconero.saturating_sub(from_reserved);
                budget.remaining_piconero = budget
                    .remaining_piconero
                    .saturating_sub(sponsor_slash.saturating_sub(from_reserved));
                budget.status = SponsorStatus::Slashed;
            }
        }
        let id = slashing_record_id(
            self.counters.next_slashing_record,
            SlashingTarget::DaRoot,
            da_root_id,
            evidence_root,
        );
        self.counters.next_slashing_record += 1;
        let record = SlashingRecord {
            id: id.clone(),
            target: SlashingTarget::DaRoot,
            target_id: da_root_id.to_string(),
            evidence_root: evidence_root.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            slashed_piconero: slashed,
            challenger_reward_piconero: challenger_reward,
            recycled_piconero: recycled,
            created_height: height,
        };
        self.slashing_records.insert(id.clone(), record);
        self.append_event("stale_da_root_slashed", &id, height)?;
        Ok(id)
    }

    pub fn expire_old_records(&mut self, height: u64) -> Result<()> {
        self.set_height(height)?;
        for voucher in self.vouchers.values_mut() {
            if voucher.status.live() && voucher.expires_height < height {
                voucher.status = VoucherStatus::Expired;
            }
        }
        for batch in self.bridge_batches.values_mut() {
            if !matches!(
                batch.status,
                BatchStatus::Settled | BatchStatus::Rebated | BatchStatus::Slashed
            ) && batch.expires_height < height
            {
                batch.status = BatchStatus::Expired;
            }
        }
        for root in self.da_roots.values_mut() {
            if matches!(root.status, DaRootStatus::Fresh | DaRootStatus::Posted)
                && root.fresh_until_height < height
            {
                root.status = DaRootStatus::Stale;
            }
        }
        for budget in self.sponsor_budgets.values_mut() {
            if budget.expires_height < height && budget.status.usable() {
                budget.status = SponsorStatus::Retired;
            }
        }
        self.append_event("old_records_expired", "runtime", height)?;
        Ok(())
    }

    pub fn quote_preview(
        &self,
        lane_id: &str,
        sponsor_budget_id: Option<&str>,
        da_bytes: u64,
        uncompressed_proof_bytes: u64,
        compressed_proof_bytes: u64,
    ) -> Result<Value> {
        ensure_known("lane", lane_id, &self.market_lanes)?;
        let lane = self
            .market_lanes
            .get(lane_id)
            .ok_or_else(|| "lane missing".to_string())?;
        let load = load_bps(lane.current_da_bytes, lane.target_da_bytes, da_bytes);
        let band = self.band_for_load(load)?;
        let kb = ceil_div_u128(da_bytes as u128, 1024);
        let base_price = lane
            .base_fee_per_kb_piconero
            .saturating_mul(kb)
            .max(self.config.min_voucher_price_piconero);
        let priced = mul_bps(base_price, band.price_multiplier_bps);
        let saved_bytes = uncompressed_proof_bytes.saturating_sub(compressed_proof_bytes);
        let proof_credit = mul_bps(
            lane.base_fee_per_kb_piconero
                .saturating_mul(ceil_div_u128(saved_bytes as u128, 1024)),
            self.config.compression_credit_bps,
        );
        let sponsor_available = match sponsor_budget_id {
            Some(id) => self
                .sponsor_budgets
                .get(id)
                .map(|budget| budget.remaining_piconero)
                .unwrap_or(0u128),
            None => 0u128,
        };
        let sponsor_match = mul_bps(
            mul_bps(priced, self.config.sponsor_match_bps),
            band.sponsor_match_multiplier_bps,
        )
        .min(sponsor_available);
        let user_price = priced
            .saturating_sub(proof_credit)
            .saturating_sub(sponsor_match)
            .max(self.config.min_voucher_price_piconero);
        Ok(json!({
            "lane_id": lane_id,
            "sponsor_budget_id": sponsor_budget_id,
            "da_bytes": da_bytes,
            "load_bps": load,
            "congestion_class": band.class,
            "base_price_piconero": base_price,
            "congestion_price_piconero": priced,
            "proof_credit_piconero": proof_credit,
            "sponsor_match_piconero": sponsor_match,
            "user_price_piconero": user_price,
            "max_rebate_piconero": mul_bps(priced.saturating_add(sponsor_match).saturating_add(proof_credit), band.max_rebate_bps.min(self.config.target_rebate_bps))
        }))
    }

    pub fn roots(&self) -> Roots {
        let config_root = payload_root("BRIDGE-DA-CONFIG", &self.config.public_record());
        let counters_root = payload_root("BRIDGE-DA-COUNTERS", &self.counters.public_record());
        let congestion_band_root = collection_root(
            "BRIDGE-DA-CONGESTION-BANDS",
            self.congestion_bands
                .iter()
                .map(CongestionBand::public_record)
                .collect(),
        );
        let lane_root = map_root(
            "BRIDGE-DA-LANES",
            &self.market_lanes,
            MarketLane::public_record,
        );
        let sponsor_budget_root = map_root(
            "BRIDGE-DA-SPONSOR-BUDGETS",
            &self.sponsor_budgets,
            SponsorBudget::public_record,
        );
        let voucher_root = map_root(
            "BRIDGE-DA-VOUCHERS",
            &self.vouchers,
            DaVoucher::public_record,
        );
        let bridge_batch_root = map_root(
            "BRIDGE-DA-BATCHES",
            &self.bridge_batches,
            BridgeBatch::public_record,
        );
        let compression_credit_root = map_root(
            "BRIDGE-DA-COMPRESSION-CREDITS",
            &self.compression_credits,
            ProofCompressionCredit::public_record,
        );
        let rebate_epoch_root = map_root(
            "BRIDGE-DA-REBATE-EPOCHS",
            &self.rebate_epochs,
            RebateEpoch::public_record,
        );
        let rebate_allocation_root = map_root(
            "BRIDGE-DA-REBATE-ALLOCATIONS",
            &self.rebate_allocations,
            RebateAllocation::public_record,
        );
        let da_root_record_root = map_root(
            "BRIDGE-DA-ROOTS",
            &self.da_roots,
            DaRootRecord::public_record,
        );
        let slashing_record_root = map_root(
            "BRIDGE-DA-SLASHING-RECORDS",
            &self.slashing_records,
            SlashingRecord::public_record,
        );
        let nullifier_root = set_root("BRIDGE-DA-NULLIFIERS", &self.nullifiers);
        let event_root = map_root(
            "BRIDGE-DA-PUBLIC-EVENTS",
            &self.public_events,
            PublicEvent::public_record,
        );
        let state_root = domain_hash(
            "BRIDGE-DA-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&congestion_band_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&sponsor_budget_root),
                HashPart::Str(&voucher_root),
                HashPart::Str(&bridge_batch_root),
                HashPart::Str(&compression_credit_root),
                HashPart::Str(&rebate_epoch_root),
                HashPart::Str(&rebate_allocation_root),
                HashPart::Str(&da_root_record_root),
                HashPart::Str(&slashing_record_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&event_root),
            ],
            32,
        );
        Roots {
            config_root,
            counters_root,
            congestion_band_root,
            lane_root,
            sponsor_budget_root,
            voucher_root,
            bridge_batch_root,
            compression_credit_root,
            rebate_epoch_root,
            rebate_allocation_root,
            da_root_record_root,
            slashing_record_root,
            nullifier_root,
            event_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_state(&self) -> Value {
        self.public_record()
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "scheme": PUBLIC_STATE_SCHEME,
            "chain_id": self.config.chain_id,
            "protocol_version": self.config.protocol_version,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "counts": {
                "congestion_bands": self.congestion_bands.len(),
                "market_lanes": self.market_lanes.len(),
                "sponsor_budgets": self.sponsor_budgets.len(),
                "vouchers": self.vouchers.len(),
                "bridge_batches": self.bridge_batches.len(),
                "compression_credits": self.compression_credits.len(),
                "rebate_epochs": self.rebate_epochs.len(),
                "rebate_allocations": self.rebate_allocations.len(),
                "da_roots": self.da_roots.len(),
                "slashing_records": self.slashing_records.len(),
                "nullifiers": self.nullifiers.len(),
                "public_events": self.public_events.len()
            },
            "roots": roots.public_record()
        })
    }

    fn validate_congestion_bands(&self) -> Result<()> {
        ensure!(
            self.congestion_bands.len() <= MAX_CONGESTION_BANDS,
            "too many congestion bands"
        );
        let mut last_max: u64 = 0;
        for (index, band) in self.congestion_bands.iter().enumerate() {
            band.validate()?;
            if index == 0 {
                ensure!(
                    band.min_load_bps == 0,
                    "first congestion band must start at zero"
                );
            } else {
                ensure!(
                    band.min_load_bps <= last_max.saturating_add(1),
                    "congestion band gap"
                );
            }
            last_max = band.max_load_bps;
        }
        ensure!(last_max == MAX_BPS, "congestion bands must cover max load");
        Ok(())
    }

    fn band_for_load(&self, load_bps: u64) -> Result<CongestionBand> {
        for band in &self.congestion_bands {
            if load_bps >= band.min_load_bps && load_bps <= band.max_load_bps {
                return Ok(band.clone());
            }
        }
        Err("no congestion band for load".to_string())
    }

    fn allocations_for_epoch_root(&self, epoch_id: &str) -> String {
        let leaves = self
            .rebate_allocations
            .iter()
            .filter(|(_, allocation)| allocation.epoch_id == epoch_id)
            .map(|(id, allocation)| json!({ "id": id, "record": allocation.public_record() }))
            .collect::<Vec<_>>();
        collection_root("BRIDGE-DA-ALLOCATIONS-FOR-EPOCH", leaves)
    }

    fn append_event(&mut self, kind: &str, subject_id: &str, height: u64) -> Result<()> {
        require_non_empty("event kind", kind)?;
        require_non_empty("event subject", subject_id)?;
        ensure!(
            self.public_events.len() < MAX_PUBLIC_EVENTS,
            "public event limit reached"
        );
        let event_root = payload_root(
            "BRIDGE-DA-EVENT-PAYLOAD",
            &json!({
                "kind": kind,
                "subject_id": subject_id,
                "height": height,
                "sequence": self.counters.next_event
            }),
        );
        let id = event_id(self.counters.next_event, kind, subject_id, &event_root);
        let event = PublicEvent {
            id: id.clone(),
            kind: kind.to_string(),
            subject_id: subject_id.to_string(),
            event_root,
            height,
            sequence: self.counters.next_event,
        };
        self.counters.next_event += 1;
        self.public_events.insert(id, event);
        Ok(())
    }
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn devnet_public_state() -> Value {
    State::devnet().public_state()
}

pub fn state_root_from_public_state(record: &Value) -> String {
    payload_root("BRIDGE-DA-PUBLIC-STATE", record)
}

pub fn private_l2_low_fee_pq_confidential_bridge_da_fee_rebate_market_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_bridge_da_fee_rebate_market_runtime_public_state(
    state: &State,
) -> Value {
    state.public_state()
}

pub fn deterministic_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn collection_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn lane_id(nonce: u64, kind: BridgeLaneKind, owner_commitment: &str) -> String {
    deterministic_id(
        "BRIDGE-DA-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(kind.as_str()),
            HashPart::Str(owner_commitment),
        ],
    )
}

pub fn sponsor_budget_id(
    nonce: u64,
    lane_id: &str,
    sponsor_commitment: &str,
    epoch: u64,
) -> String {
    deterministic_id(
        "BRIDGE-DA-SPONSOR-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_commitment),
            HashPart::U64(epoch),
        ],
    )
}

pub fn voucher_id(
    nonce: u64,
    lane_id: &str,
    quote_root: &str,
    da_bytes: u64,
    epoch: u64,
) -> String {
    deterministic_id(
        "BRIDGE-DA-VOUCHER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(quote_root),
            HashPart::U64(da_bytes),
            HashPart::U64(epoch),
        ],
    )
}

pub fn batch_id(nonce: u64, lane_id: &str, voucher_id: &str, bridge_batch_root: &str) -> String {
    deterministic_id(
        "BRIDGE-DA-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(lane_id),
            HashPart::Str(voucher_id),
            HashPart::Str(bridge_batch_root),
        ],
    )
}

pub fn compression_credit_id(
    nonce: u64,
    batch_id: &str,
    proof_system: &str,
    transcript_root: &str,
) -> String {
    deterministic_id(
        "BRIDGE-DA-COMPRESSION-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(batch_id),
            HashPart::Str(proof_system),
            HashPart::Str(transcript_root),
        ],
    )
}

pub fn da_root_id(nonce: u64, batch_id: &str, da_root: &str, availability_root: &str) -> String {
    deterministic_id(
        "BRIDGE-DA-ROOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(batch_id),
            HashPart::Str(da_root),
            HashPart::Str(availability_root),
        ],
    )
}

pub fn rebate_epoch_id(nonce: u64, epoch: u64, start_height: u64) -> String {
    deterministic_id(
        "BRIDGE-DA-REBATE-EPOCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::U64(epoch),
            HashPart::U64(start_height),
        ],
    )
}

pub fn rebate_allocation_id(
    nonce: u64,
    epoch_id: &str,
    batch_id: &str,
    settlement_kind: SettlementKind,
    nullifier_hash: &str,
) -> String {
    deterministic_id(
        "BRIDGE-DA-REBATE-ALLOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(epoch_id),
            HashPart::Str(batch_id),
            HashPart::Str(settlement_kind.as_str()),
            HashPart::Str(nullifier_hash),
        ],
    )
}

pub fn slashing_record_id(
    nonce: u64,
    target: SlashingTarget,
    target_id: &str,
    evidence_root: &str,
) -> String {
    deterministic_id(
        "BRIDGE-DA-SLASHING-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(target.as_str()),
            HashPart::Str(target_id),
            HashPart::Str(evidence_root),
        ],
    )
}

pub fn event_id(nonce: u64, kind: &str, subject_id: &str, event_root: &str) -> String {
    deterministic_id(
        "BRIDGE-DA-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(nonce),
            HashPart::Str(kind),
            HashPart::Str(subject_id),
            HashPart::Str(event_root),
        ],
    )
}

pub fn nullifier_hash(kind: &str, label: &str) -> String {
    deterministic_id(
        "BRIDGE-DA-REBATE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
    )
}

pub fn default_congestion_bands() -> Vec<CongestionBand> {
    vec![
        CongestionBand {
            class: CongestionClass::Empty,
            min_load_bps: 0,
            max_load_bps: 999,
            price_multiplier_bps: 7_500,
            sponsor_match_multiplier_bps: 11_500,
            max_rebate_bps: 8_500,
        },
        CongestionBand {
            class: CongestionClass::Low,
            min_load_bps: 1_000,
            max_load_bps: 3_999,
            price_multiplier_bps: 9_000,
            sponsor_match_multiplier_bps: 10_500,
            max_rebate_bps: 8_000,
        },
        CongestionBand {
            class: CongestionClass::Target,
            min_load_bps: 4_000,
            max_load_bps: 6_999,
            price_multiplier_bps: 10_000,
            sponsor_match_multiplier_bps: 10_000,
            max_rebate_bps: 7_500,
        },
        CongestionBand {
            class: CongestionClass::High,
            min_load_bps: 7_000,
            max_load_bps: 8_499,
            price_multiplier_bps: 12_500,
            sponsor_match_multiplier_bps: 8_000,
            max_rebate_bps: 6_500,
        },
        CongestionBand {
            class: CongestionClass::Surge,
            min_load_bps: 8_500,
            max_load_bps: 9_499,
            price_multiplier_bps: 16_000,
            sponsor_match_multiplier_bps: 6_000,
            max_rebate_bps: 5_000,
        },
        CongestionBand {
            class: CongestionClass::Emergency,
            min_load_bps: 9_500,
            max_load_bps: 10_000,
            price_multiplier_bps: 22_000,
            sponsor_match_multiplier_bps: 4_000,
            max_rebate_bps: 3_000,
        },
    ]
}

pub fn load_bps(current_bytes: u64, target_bytes: u64, additional_bytes: u64) -> u64 {
    if target_bytes == 0 {
        return MAX_BPS;
    }
    let load = (current_bytes as u128)
        .saturating_add(additional_bytes as u128)
        .saturating_mul(MAX_BPS as u128)
        / target_bytes as u128;
    (load as u64).min(MAX_BPS)
}

pub fn mul_bps(value: u128, bps: u64) -> u128 {
    value.saturating_mul(bps as u128) / MAX_BPS as u128
}

pub fn proportional_amount(total: u128, part: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        total.saturating_mul(part) / denominator
    }
}

pub fn ceil_div_u128(value: u128, divisor: u128) -> u128 {
    if divisor == 0 {
        0
    } else {
        value.saturating_add(divisor - 1) / divisor
    }
}

fn devnet_fallback_state(error: &str) -> State {
    let mut events = BTreeMap::new();
    let event_root = payload_root("BRIDGE-DA-DEVNET-CONFIG-ERROR", &json!({ "error": error }));
    let event = PublicEvent {
        id: event_id(1, "devnet_config_error", "config", &event_root),
        kind: "devnet_config_error".to_string(),
        subject_id: "config".to_string(),
        event_root,
        height: DEVNET_HEIGHT,
        sequence: 1,
    };
    events.insert(event.id.clone(), event);
    State {
        config: Config::devnet(),
        current_height: DEVNET_HEIGHT,
        current_epoch: DEVNET_EPOCH,
        congestion_bands: default_congestion_bands(),
        market_lanes: BTreeMap::new(),
        sponsor_budgets: BTreeMap::new(),
        vouchers: BTreeMap::new(),
        bridge_batches: BTreeMap::new(),
        compression_credits: BTreeMap::new(),
        rebate_epochs: BTreeMap::new(),
        rebate_allocations: BTreeMap::new(),
        da_roots: BTreeMap::new(),
        slashing_records: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
        public_events: events,
        counters: Counters {
            next_event: 2,
            ..Counters::zero()
        },
    }
}

fn require_non_empty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{} must be non-empty", name))
    } else {
        Ok(())
    }
}

fn ensure_known<T>(name: &str, id: &str, map: &BTreeMap<String, T>) -> Result<()> {
    if map.contains_key(id) {
        Ok(())
    } else {
        Err(format!("unknown {} id", name))
    }
}
