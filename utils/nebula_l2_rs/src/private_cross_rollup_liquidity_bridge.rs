use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateCrossRollupLiquidityBridgeResult<T> = Result<T, String>;

pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PROTOCOL_VERSION: u32 = 1;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PROTOCOL_LABEL: &str =
    "nebula-private-cross-rollup-liquidity-bridge-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_HEIGHT: u64 = 912;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_SOURCE_ROLLUP: &str =
    "nebula-private-defi-rollup-a";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_DESTINATION_ROLLUP: &str =
    "nebula-private-contract-rollup-b";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_XMR_ASSET_ID: &str = "xmr-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_WXMR_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_STABLE_ASSET_ID: &str = "dusd-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-cross-rollup-bridge-devnet";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_QUOTE_SCHEME: &str =
    "confidential-cross-rollup-route-quote-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_LOCK_SCHEME: &str = "shielded-source-lock-note-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MINT_SCHEME: &str =
    "shielded-destination-mint-note-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_BURN_SCHEME: &str =
    "shielded-destination-burn-note-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_RELEASE_SCHEME: &str =
    "shielded-source-release-note-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_SPONSOR_SCHEME: &str =
    "low-fee-private-sponsor-rebate-v1";
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LOCK_TTL_BLOCKS: u64 = 54;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_FAST_FINALITY_BLOCKS: u64 = 6;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SAFE_FINALITY_BLOCKS: u64 = 32;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_REORG_GRACE_BLOCKS: u64 = 12;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 48;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MAX_BATCH_ITEMS: usize = 96;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 256;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2048;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_BASE_FEE_BPS: u64 = 14;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_FAST_FEE_BPS: u64 = 38;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SOLVER_BOND_BPS: u64 = 15_000;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SLASH_BPS: u64 = 12_500;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LANE_LIMIT_UNITS: u64 = 8_000_000;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_POOL_LIMIT_UNITS: u64 = 3_000_000;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_QUOTE_LIMIT_UNITS: u64 = 500_000;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_LANES: usize = 16_384;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_POOLS: usize = 65_536;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_QUOTES: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_SOLVERS: usize = 65_536;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_LOCKS: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_MINTS: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_BURNS: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_RELEASES: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_ATTESTATIONS: usize = 262_144;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_SPONSORSHIPS: usize = 131_072;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_FINALITY_WINDOWS: usize = 131_072;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_CHALLENGES: usize = 131_072;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_EVENTS: usize = 524_288;
pub const PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_PUBLIC_RECORDS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeDirection {
    MoneroToRollup,
    RollupToMonero,
    RollupToRollup,
    RollupToPrivateContract,
    PrivateContractToRollup,
}

impl BridgeDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToRollup => "monero_to_rollup",
            Self::RollupToMonero => "rollup_to_monero",
            Self::RollupToRollup => "rollup_to_rollup",
            Self::RollupToPrivateContract => "rollup_to_private_contract",
            Self::PrivateContractToRollup => "private_contract_to_rollup",
        }
    }

    pub fn touches_monero(self) -> bool {
        matches!(self, Self::MoneroToRollup | Self::RollupToMonero)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgePriority {
    LowFee,
    Normal,
    Fast,
    ContractAtomic,
    ReorgSafe,
    Emergency,
}

impl BridgePriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::ContractAtomic => "contract_atomic",
            Self::ReorgSafe => "reorg_safe",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &PrivateCrossRollupLiquidityBridgeConfig) -> u64 {
        match self {
            Self::LowFee => config.base_fee_bps / 2,
            Self::Normal | Self::ContractAtomic | Self::ReorgSafe => config.base_fee_bps,
            Self::Fast => config.fast_fee_bps,
            Self::Emergency => config.fast_fee_bps.saturating_mul(2),
        }
    }

    pub fn finality_blocks(self, config: &PrivateCrossRollupLiquidityBridgeConfig) -> u64 {
        match self {
            Self::Fast | Self::Emergency => config.fast_finality_blocks.max(1),
            Self::LowFee | Self::Normal | Self::ContractAtomic => config.safe_finality_blocks / 2,
            Self::ReorgSafe => config
                .safe_finality_blocks
                .saturating_add(config.reorg_grace_blocks)
                .max(1),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Draft,
    Active,
    Congested,
    ReorgHold,
    ChallengeOnly,
    Paused,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Congested => "congested",
            Self::ReorgHold => "reorg_hold",
            Self::ChallengeOnly => "challenge_only",
            Self::Paused => "paused",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_quotes(self) -> bool {
        matches!(self, Self::Active | Self::Congested)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Congested | Self::ReorgHold | Self::ChallengeOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Active,
    Draining,
    Rebalancing,
    ReorgProtected,
    Paused,
    Slashed,
}

impl PoolStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Rebalancing => "rebalancing",
            Self::ReorgProtected => "reorg_protected",
            Self::Paused => "paused",
            Self::Slashed => "slashed",
        }
    }

    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Active | Self::Rebalancing | Self::ReorgProtected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Offered,
    Committed,
    Locked,
    Minted,
    Burned,
    Released,
    Expired,
    Challenged,
    Slashed,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Committed => "committed",
            Self::Locked => "locked",
            Self::Minted => "minted",
            Self::Burned => "burned",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Released | Self::Expired | Self::Slashed | Self::Cancelled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    Accepted,
    Finalized,
    ReorgHeld,
    Challenged,
    Reversed,
    Spent,
    Expired,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::ReorgHeld => "reorg_held",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
            Self::Spent => "spent",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherVerdict {
    Observed,
    Finalized,
    ReorgRisk,
    Reorged,
    Invalid,
    Timeout,
}

impl WatcherVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Finalized => "finalized",
            Self::ReorgRisk => "reorg_risk",
            Self::Reorged => "reorged",
            Self::Invalid => "invalid",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    EvidenceAccepted,
    SolverSlashed,
    WatcherSlashed,
    Dismissed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceAccepted => "evidence_accepted",
            Self::SolverSlashed => "solver_slashed",
            Self::WatcherSlashed => "watcher_slashed",
            Self::Dismissed => "dismissed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossRollupLiquidityBridgeConfig {
    pub protocol_label: String,
    pub protocol_version: u32,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub quote_ttl_blocks: u64,
    pub lock_ttl_blocks: u64,
    pub fast_finality_blocks: u64,
    pub safe_finality_blocks: u64,
    pub reorg_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub batch_window_blocks: u64,
    pub max_batch_items: usize,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub solver_bond_bps: u64,
    pub slash_bps: u64,
    pub lane_limit_units: u64,
    pub pool_limit_units: u64,
    pub quote_limit_units: u64,
    pub hash_suite: String,
    pub pq_suite: String,
    pub quote_scheme: String,
    pub lock_scheme: String,
    pub mint_scheme: String,
    pub burn_scheme: String,
    pub release_scheme: String,
    pub sponsor_scheme: String,
}

impl PrivateCrossRollupLiquidityBridgeConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_label: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PROTOCOL_LABEL.to_string(),
            protocol_version: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PROTOCOL_VERSION,
            schema_version: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_MONERO_NETWORK.to_string(),
            l2_network: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_L2_NETWORK.to_string(),
            quote_ttl_blocks: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_QUOTE_TTL_BLOCKS,
            lock_ttl_blocks: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LOCK_TTL_BLOCKS,
            fast_finality_blocks:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_FAST_FINALITY_BLOCKS,
            safe_finality_blocks:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SAFE_FINALITY_BLOCKS,
            reorg_grace_blocks: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_REORG_GRACE_BLOCKS,
            challenge_window_blocks:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            batch_window_blocks: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_batch_items: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MAX_BATCH_ITEMS,
            min_privacy_set_size:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_MIN_PQ_SECURITY_BITS,
            base_fee_bps: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_FAST_FEE_BPS,
            low_fee_rebate_bps: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LOW_FEE_REBATE_BPS,
            solver_bond_bps: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SOLVER_BOND_BPS,
            slash_bps: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_SLASH_BPS,
            lane_limit_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LANE_LIMIT_UNITS,
            pool_limit_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_POOL_LIMIT_UNITS,
            quote_limit_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_QUOTE_LIMIT_UNITS,
            hash_suite: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_HASH_SUITE.to_string(),
            pq_suite: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PQ_SUITE.to_string(),
            quote_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_QUOTE_SCHEME.to_string(),
            lock_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_LOCK_SCHEME.to_string(),
            mint_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MINT_SCHEME.to_string(),
            burn_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_BURN_SCHEME.to_string(),
            release_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_RELEASE_SCHEME.to_string(),
            sponsor_scheme: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_SPONSOR_SCHEME.to_string(),
        }
    }

    pub fn validate(&self) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        ensure_nonempty("config.protocol_label", &self.protocol_label)?;
        ensure_nonempty("config.monero_network", &self.monero_network)?;
        ensure_nonempty("config.l2_network", &self.l2_network)?;
        ensure_nonempty("config.hash_suite", &self.hash_suite)?;
        ensure_nonempty("config.pq_suite", &self.pq_suite)?;
        ensure_positive("config.quote_ttl_blocks", self.quote_ttl_blocks)?;
        ensure_positive("config.lock_ttl_blocks", self.lock_ttl_blocks)?;
        ensure_positive("config.fast_finality_blocks", self.fast_finality_blocks)?;
        ensure_positive("config.safe_finality_blocks", self.safe_finality_blocks)?;
        ensure_positive(
            "config.challenge_window_blocks",
            self.challenge_window_blocks,
        )?;
        ensure_positive("config.batch_window_blocks", self.batch_window_blocks)?;
        if self.max_batch_items == 0 {
            return Err("config.max_batch_items must be positive".to_string());
        }
        if self.min_privacy_set_size > self.target_privacy_set_size {
            return Err("config.min_privacy_set_size exceeds target_privacy_set_size".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("config.min_pq_security_bits must be at least 128".to_string());
        }
        ensure_bps("config.base_fee_bps", self.base_fee_bps)?;
        ensure_bps("config.fast_fee_bps", self.fast_fee_bps)?;
        ensure_bps("config.low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        if self.solver_bond_bps < PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_BPS {
            return Err("config.solver_bond_bps must fully collateralize notional".to_string());
        }
        if self.slash_bps > self.solver_bond_bps {
            return Err("config.slash_bps cannot exceed solver_bond_bps".to_string());
        }
        ensure_positive("config.lane_limit_units", self.lane_limit_units)?;
        ensure_positive("config.pool_limit_units", self.pool_limit_units)?;
        ensure_positive("config.quote_limit_units", self.quote_limit_units)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_label": self.protocol_label,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "lock_ttl_blocks": self.lock_ttl_blocks,
            "fast_finality_blocks": self.fast_finality_blocks,
            "safe_finality_blocks": self.safe_finality_blocks,
            "reorg_grace_blocks": self.reorg_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "batch_window_blocks": self.batch_window_blocks,
            "max_batch_items": self.max_batch_items,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "solver_bond_bps": self.solver_bond_bps,
            "slash_bps": self.slash_bps,
            "lane_limit_units": self.lane_limit_units,
            "pool_limit_units": self.pool_limit_units,
            "quote_limit_units": self.quote_limit_units,
            "hash_suite": self.hash_suite,
            "pq_suite": self.pq_suite,
            "quote_scheme": self.quote_scheme,
            "lock_scheme": self.lock_scheme,
            "mint_scheme": self.mint_scheme,
            "burn_scheme": self.burn_scheme,
            "release_scheme": self.release_scheme,
            "sponsor_scheme": self.sponsor_scheme,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityLane {
    pub lane_id: String,
    pub direction: BridgeDirection,
    pub source_rollup: String,
    pub destination_rollup: String,
    pub source_asset_id: String,
    pub destination_asset_id: String,
    pub settlement_asset_id: String,
    pub status: LaneStatus,
    pub privacy_set_size: u64,
    pub active_pool_ids: BTreeSet<String>,
    pub watcher_quorum_id: String,
    pub finality_policy_id: String,
    pub lane_limit_units: u64,
    pub locked_units: u64,
    pub minted_units: u64,
    pub burned_units: u64,
    pub released_units: u64,
    pub fee_floor_units: u64,
    pub fee_ceiling_bps: u64,
    pub pq_route_key_root: String,
    pub private_contract_policy_root: String,
    pub monero_view_policy_root: String,
    pub created_height: u64,
    pub updated_height: u64,
}

impl LiquidityLane {
    pub fn devnet_rollup_to_rollup(lane_id: &str, height: u64) -> Self {
        let mut active_pool_ids = BTreeSet::new();
        active_pool_ids.insert("devnet-pool-wxmr-rollup-a-b".to_string());
        active_pool_ids.insert("devnet-pool-dusd-rollup-a-b".to_string());
        Self {
            lane_id: lane_id.to_string(),
            direction: BridgeDirection::RollupToRollup,
            source_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_SOURCE_ROLLUP.to_string(),
            destination_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_DESTINATION_ROLLUP
                .to_string(),
            source_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_WXMR_ASSET_ID.to_string(),
            destination_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_WXMR_ASSET_ID
                .to_string(),
            settlement_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_FEE_ASSET_ID
                .to_string(),
            status: LaneStatus::Active,
            privacy_set_size: 4096,
            active_pool_ids,
            watcher_quorum_id: "devnet-pq-watchers-rollup-a-b".to_string(),
            finality_policy_id: "devnet-fast-safe-hybrid-finality".to_string(),
            lane_limit_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LANE_LIMIT_UNITS,
            locked_units: 120_000,
            minted_units: 118_900,
            burned_units: 11_000,
            released_units: 10_940,
            fee_floor_units: 1,
            fee_ceiling_bps: 75,
            pq_route_key_root: devnet_commitment("lane-pq-route-key", lane_id),
            private_contract_policy_root: devnet_commitment("lane-contract-policy", lane_id),
            monero_view_policy_root: devnet_commitment("lane-monero-view-policy", lane_id),
            created_height: height,
            updated_height: height,
        }
    }

    pub fn devnet_monero_lane(lane_id: &str, direction: BridgeDirection, height: u64) -> Self {
        let mut active_pool_ids = BTreeSet::new();
        active_pool_ids.insert("devnet-pool-xmr-wxmr-monero".to_string());
        Self {
            lane_id: lane_id.to_string(),
            direction,
            source_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_MONERO_NETWORK.to_string(),
            destination_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_SOURCE_ROLLUP
                .to_string(),
            source_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_XMR_ASSET_ID.to_string(),
            destination_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_WXMR_ASSET_ID
                .to_string(),
            settlement_asset_id: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_FEE_ASSET_ID
                .to_string(),
            status: LaneStatus::Active,
            privacy_set_size: 2048,
            active_pool_ids,
            watcher_quorum_id: "devnet-pq-watchers-monero-a".to_string(),
            finality_policy_id: "devnet-monero-reorg-safe-finality".to_string(),
            lane_limit_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_LANE_LIMIT_UNITS / 2,
            locked_units: 80_000,
            minted_units: 79_300,
            burned_units: 9_000,
            released_units: 8_960,
            fee_floor_units: 1,
            fee_ceiling_bps: 90,
            pq_route_key_root: devnet_commitment("lane-pq-route-key", lane_id),
            private_contract_policy_root: devnet_commitment("lane-contract-policy", lane_id),
            monero_view_policy_root: devnet_commitment("lane-monero-view-policy", lane_id),
            created_height: height,
            updated_height: height,
        }
    }

    pub fn validate(
        &self,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        ensure_nonempty("lane.lane_id", &self.lane_id)?;
        ensure_nonempty("lane.source_rollup", &self.source_rollup)?;
        ensure_nonempty("lane.destination_rollup", &self.destination_rollup)?;
        ensure_nonempty("lane.source_asset_id", &self.source_asset_id)?;
        ensure_nonempty("lane.destination_asset_id", &self.destination_asset_id)?;
        ensure_nonempty("lane.settlement_asset_id", &self.settlement_asset_id)?;
        ensure_nonempty("lane.watcher_quorum_id", &self.watcher_quorum_id)?;
        ensure_nonempty("lane.finality_policy_id", &self.finality_policy_id)?;
        ensure_nonempty("lane.pq_route_key_root", &self.pq_route_key_root)?;
        if self.source_rollup == self.destination_rollup && !self.direction.touches_monero() {
            return Err(format!(
                "lane {} has identical rollup endpoints",
                self.lane_id
            ));
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err(format!(
                "lane {} privacy set is below configured floor",
                self.lane_id
            ));
        }
        if self.lane_limit_units == 0 || self.lane_limit_units > config.lane_limit_units {
            return Err(format!("lane {} has invalid limit", self.lane_id));
        }
        if self.locked_units > self.lane_limit_units {
            return Err(format!("lane {} locked units exceed limit", self.lane_id));
        }
        ensure_bps("lane.fee_ceiling_bps", self.fee_ceiling_bps)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "direction": self.direction.as_str(),
            "source_rollup": self.source_rollup,
            "destination_rollup": self.destination_rollup,
            "source_asset_id": self.source_asset_id,
            "destination_asset_id": self.destination_asset_id,
            "settlement_asset_id": self.settlement_asset_id,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "active_pool_ids": self.active_pool_ids.iter().cloned().collect::<Vec<_>>(),
            "watcher_quorum_id": self.watcher_quorum_id,
            "finality_policy_id": self.finality_policy_id,
            "lane_limit_units": self.lane_limit_units,
            "locked_units": self.locked_units,
            "minted_units": self.minted_units,
            "burned_units": self.burned_units,
            "released_units": self.released_units,
            "fee_floor_units": self.fee_floor_units,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "pq_route_key_root": self.pq_route_key_root,
            "private_contract_policy_root": self.private_contract_policy_root,
            "monero_view_policy_root": self.monero_view_policy_root,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("LIQUIDITY-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub pool_id: String,
    pub lane_id: String,
    pub operator_id: String,
    pub solver_id: String,
    pub asset_id: String,
    pub status: PoolStatus,
    pub capacity_commitment: String,
    pub available_commitment: String,
    pub reserved_commitment: String,
    pub rebalance_commitment: String,
    pub encrypted_inventory_root: String,
    pub max_quote_units: u64,
    pub utilization_bps: u64,
    pub fee_curve_root: String,
    pub solver_bond_units: u64,
    pub slashable_bond_units: u64,
    pub last_rebalance_height: u64,
    pub created_height: u64,
}

impl LiquidityPool {
    pub fn devnet(
        pool_id: &str,
        lane_id: &str,
        asset_id: &str,
        solver_id: &str,
        height: u64,
    ) -> Self {
        Self {
            pool_id: pool_id.to_string(),
            lane_id: lane_id.to_string(),
            operator_id: "devnet-bridge-operator-1".to_string(),
            solver_id: solver_id.to_string(),
            asset_id: asset_id.to_string(),
            status: PoolStatus::Active,
            capacity_commitment: devnet_commitment("pool-capacity", pool_id),
            available_commitment: devnet_commitment("pool-available", pool_id),
            reserved_commitment: devnet_commitment("pool-reserved", pool_id),
            rebalance_commitment: devnet_commitment("pool-rebalance", pool_id),
            encrypted_inventory_root: devnet_commitment("pool-inventory", pool_id),
            max_quote_units: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEFAULT_QUOTE_LIMIT_UNITS,
            utilization_bps: 4_200,
            fee_curve_root: devnet_commitment("pool-fee-curve", pool_id),
            solver_bond_units: 120_000,
            slashable_bond_units: 100_000,
            last_rebalance_height: height,
            created_height: height,
        }
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, LiquidityLane>,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        ensure_nonempty("pool.pool_id", &self.pool_id)?;
        ensure_nonempty("pool.lane_id", &self.lane_id)?;
        ensure_nonempty("pool.operator_id", &self.operator_id)?;
        ensure_nonempty("pool.solver_id", &self.solver_id)?;
        ensure_nonempty("pool.asset_id", &self.asset_id)?;
        ensure_nonempty("pool.capacity_commitment", &self.capacity_commitment)?;
        ensure_nonempty("pool.available_commitment", &self.available_commitment)?;
        ensure_nonempty(
            "pool.encrypted_inventory_root",
            &self.encrypted_inventory_root,
        )?;
        if !lanes.contains_key(&self.lane_id) {
            return Err(format!(
                "pool {} references missing lane {}",
                self.pool_id, self.lane_id
            ));
        }
        if self.max_quote_units == 0 || self.max_quote_units > config.quote_limit_units {
            return Err(format!("pool {} has invalid max quote units", self.pool_id));
        }
        ensure_bps("pool.utilization_bps", self.utilization_bps)?;
        if self.slashable_bond_units > self.solver_bond_units {
            return Err(format!(
                "pool {} slashable bond exceeds posted bond",
                self.pool_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "pool_id": self.pool_id,
            "lane_id": self.lane_id,
            "operator_id": self.operator_id,
            "solver_id": self.solver_id,
            "asset_id": self.asset_id,
            "status": self.status.as_str(),
            "capacity_commitment": self.capacity_commitment,
            "available_commitment": self.available_commitment,
            "reserved_commitment": self.reserved_commitment,
            "rebalance_commitment": self.rebalance_commitment,
            "encrypted_inventory_root": self.encrypted_inventory_root,
            "max_quote_units": self.max_quote_units,
            "utilization_bps": self.utilization_bps,
            "fee_curve_root": self.fee_curve_root,
            "solver_bond_units": self.solver_bond_units,
            "slashable_bond_units": self.slashable_bond_units,
            "last_rebalance_height": self.last_rebalance_height,
            "created_height": self.created_height,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("LIQUIDITY-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialRouteQuote {
    pub quote_id: String,
    pub lane_id: String,
    pub pool_id: String,
    pub solver_id: String,
    pub direction: BridgeDirection,
    pub priority: BridgePriority,
    pub source_amount_commitment: String,
    pub destination_amount_commitment: String,
    pub fee_commitment: String,
    pub spread_commitment: String,
    pub route_secret_commitment: String,
    pub encrypted_terms_root: String,
    pub pq_authorization_root: String,
    pub privacy_bucket_id: String,
    pub status: QuoteStatus,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub min_finality_blocks: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl ConfidentialRouteQuote {
    pub fn devnet(
        quote_id: &str,
        lane_id: &str,
        pool_id: &str,
        solver_id: &str,
        priority: BridgePriority,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            quote_id: quote_id.to_string(),
            lane_id: lane_id.to_string(),
            pool_id: pool_id.to_string(),
            solver_id: solver_id.to_string(),
            direction: BridgeDirection::RollupToRollup,
            priority,
            source_amount_commitment: devnet_commitment("quote-source-amount", quote_id),
            destination_amount_commitment: devnet_commitment("quote-destination-amount", quote_id),
            fee_commitment: devnet_commitment("quote-fee", quote_id),
            spread_commitment: devnet_commitment("quote-spread", quote_id),
            route_secret_commitment: devnet_commitment("quote-route-secret", quote_id),
            encrypted_terms_root: devnet_commitment("quote-terms", quote_id),
            pq_authorization_root: devnet_commitment("quote-pq-auth", quote_id),
            privacy_bucket_id: "devnet-privacy-bucket-4096".to_string(),
            status: QuoteStatus::Offered,
            fee_bps: priority.fee_bps(config),
            rebate_bps: if priority == BridgePriority::LowFee {
                config.low_fee_rebate_bps
            } else {
                0
            },
            min_finality_blocks: priority.finality_blocks(config),
            created_height: height,
            expires_height: height.saturating_add(config.quote_ttl_blocks),
        }
    }

    pub fn is_expired(&self, height: u64) -> bool {
        height > self.expires_height
    }

    pub fn validate(
        &self,
        lanes: &BTreeMap<String, LiquidityLane>,
        pools: &BTreeMap<String, LiquidityPool>,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        ensure_nonempty("quote.quote_id", &self.quote_id)?;
        ensure_nonempty("quote.lane_id", &self.lane_id)?;
        ensure_nonempty("quote.pool_id", &self.pool_id)?;
        ensure_nonempty("quote.solver_id", &self.solver_id)?;
        ensure_nonempty(
            "quote.route_secret_commitment",
            &self.route_secret_commitment,
        )?;
        ensure_nonempty("quote.encrypted_terms_root", &self.encrypted_terms_root)?;
        let lane = lanes.get(&self.lane_id).ok_or_else(|| {
            format!(
                "quote {} references missing lane {}",
                self.quote_id, self.lane_id
            )
        })?;
        if !lane.status.accepts_quotes() && !self.status.is_terminal() {
            return Err(format!(
                "quote {} is live on a lane that rejects quotes",
                self.quote_id
            ));
        }
        let pool = pools.get(&self.pool_id).ok_or_else(|| {
            format!(
                "quote {} references missing pool {}",
                self.quote_id, self.pool_id
            )
        })?;
        if pool.lane_id != self.lane_id {
            return Err(format!("quote {} pool lane mismatch", self.quote_id));
        }
        ensure_bps("quote.fee_bps", self.fee_bps)?;
        ensure_bps("quote.rebate_bps", self.rebate_bps)?;
        if self.created_height >= self.expires_height {
            return Err(format!(
                "quote {} expires before ttl elapses",
                self.quote_id
            ));
        }
        if self.expires_height.saturating_sub(self.created_height) > config.lock_ttl_blocks {
            return Err(format!("quote {} ttl exceeds lock ttl", self.quote_id));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "solver_id": self.solver_id,
            "direction": self.direction.as_str(),
            "priority": self.priority.as_str(),
            "source_amount_commitment": self.source_amount_commitment,
            "destination_amount_commitment": self.destination_amount_commitment,
            "fee_commitment": self.fee_commitment,
            "spread_commitment": self.spread_commitment,
            "route_secret_commitment": self.route_secret_commitment,
            "encrypted_terms_root": self.encrypted_terms_root,
            "pq_authorization_root": self.pq_authorization_root,
            "privacy_bucket_id": self.privacy_bucket_id,
            "status": self.status.as_str(),
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "min_finality_blocks": self.min_finality_blocks,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("CONFIDENTIAL-ROUTE-QUOTE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverCommitment {
    pub commitment_id: String,
    pub solver_id: String,
    pub lane_id: String,
    pub pool_id: String,
    pub quote_id: String,
    pub stake_commitment: String,
    pub capacity_commitment: String,
    pub execution_policy_root: String,
    pub pq_identity_root: String,
    pub fallback_solver_root: String,
    pub low_fee_policy_root: String,
    pub commitment_height: u64,
    pub unlock_height: u64,
    pub active: bool,
}

impl SolverCommitment {
    pub fn devnet(
        commitment_id: &str,
        solver_id: &str,
        lane_id: &str,
        pool_id: &str,
        quote_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            commitment_id: commitment_id.to_string(),
            solver_id: solver_id.to_string(),
            lane_id: lane_id.to_string(),
            pool_id: pool_id.to_string(),
            quote_id: quote_id.to_string(),
            stake_commitment: devnet_commitment("solver-stake", commitment_id),
            capacity_commitment: devnet_commitment("solver-capacity", commitment_id),
            execution_policy_root: devnet_commitment("solver-execution-policy", commitment_id),
            pq_identity_root: devnet_commitment("solver-pq-identity", solver_id),
            fallback_solver_root: devnet_commitment("solver-fallback", commitment_id),
            low_fee_policy_root: devnet_commitment("solver-low-fee-policy", commitment_id),
            commitment_height: height,
            unlock_height: height
                .saturating_add(config.lock_ttl_blocks)
                .saturating_add(config.challenge_window_blocks),
            active: true,
        }
    }

    pub fn validate(
        &self,
        quotes: &BTreeMap<String, ConfidentialRouteQuote>,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        ensure_nonempty("solver_commitment.commitment_id", &self.commitment_id)?;
        ensure_nonempty("solver_commitment.solver_id", &self.solver_id)?;
        ensure_nonempty("solver_commitment.lane_id", &self.lane_id)?;
        ensure_nonempty("solver_commitment.pool_id", &self.pool_id)?;
        ensure_nonempty("solver_commitment.quote_id", &self.quote_id)?;
        let quote = quotes.get(&self.quote_id).ok_or_else(|| {
            format!(
                "solver commitment {} references missing quote {}",
                self.commitment_id, self.quote_id
            )
        })?;
        if quote.lane_id != self.lane_id || quote.pool_id != self.pool_id {
            return Err(format!(
                "solver commitment {} route mismatch",
                self.commitment_id
            ));
        }
        if quote.solver_id != self.solver_id {
            return Err(format!(
                "solver commitment {} solver mismatch",
                self.commitment_id
            ));
        }
        if self.commitment_height >= self.unlock_height {
            return Err(format!(
                "solver commitment {} invalid unlock height",
                self.commitment_id
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "solver_id": self.solver_id,
            "lane_id": self.lane_id,
            "pool_id": self.pool_id,
            "quote_id": self.quote_id,
            "stake_commitment": self.stake_commitment,
            "capacity_commitment": self.capacity_commitment,
            "execution_policy_root": self.execution_policy_root,
            "pq_identity_root": self.pq_identity_root,
            "fallback_solver_root": self.fallback_solver_root,
            "low_fee_policy_root": self.low_fee_policy_root,
            "commitment_height": self.commitment_height,
            "unlock_height": self.unlock_height,
            "active": self.active,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("SOLVER-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedLockRecord {
    pub lock_id: String,
    pub quote_id: String,
    pub lane_id: String,
    pub source_rollup: String,
    pub depositor_nullifier: String,
    pub lock_note_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub encrypted_payload_root: String,
    pub source_state_root: String,
    pub pq_lock_signature_root: String,
    pub status: NoteStatus,
    pub lock_height: u64,
    pub expires_height: u64,
}

impl ShieldedLockRecord {
    pub fn devnet(
        lock_id: &str,
        quote_id: &str,
        lane_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            lock_id: lock_id.to_string(),
            quote_id: quote_id.to_string(),
            lane_id: lane_id.to_string(),
            source_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_SOURCE_ROLLUP.to_string(),
            depositor_nullifier: devnet_commitment("lock-depositor-nullifier", lock_id),
            lock_note_commitment: devnet_commitment("lock-note", lock_id),
            amount_commitment: devnet_commitment("lock-amount", lock_id),
            fee_commitment: devnet_commitment("lock-fee", lock_id),
            encrypted_payload_root: devnet_commitment("lock-payload", lock_id),
            source_state_root: devnet_commitment("lock-source-state", lock_id),
            pq_lock_signature_root: devnet_commitment("lock-pq-signature", lock_id),
            status: NoteStatus::Accepted,
            lock_height: height,
            expires_height: height.saturating_add(config.lock_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "source_rollup": self.source_rollup,
            "depositor_nullifier": self.depositor_nullifier,
            "lock_note_commitment": self.lock_note_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "encrypted_payload_root": self.encrypted_payload_root,
            "source_state_root": self.source_state_root,
            "pq_lock_signature_root": self.pq_lock_signature_root,
            "status": self.status.as_str(),
            "lock_height": self.lock_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedMintRecord {
    pub mint_id: String,
    pub lock_id: String,
    pub quote_id: String,
    pub destination_rollup: String,
    pub recipient_commitment: String,
    pub minted_note_commitment: String,
    pub amount_commitment: String,
    pub destination_state_root: String,
    pub private_contract_call_root: String,
    pub pq_mint_signature_root: String,
    pub status: NoteStatus,
    pub mint_height: u64,
}

impl ShieldedMintRecord {
    pub fn devnet(mint_id: &str, lock_id: &str, quote_id: &str, height: u64) -> Self {
        Self {
            mint_id: mint_id.to_string(),
            lock_id: lock_id.to_string(),
            quote_id: quote_id.to_string(),
            destination_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_DESTINATION_ROLLUP
                .to_string(),
            recipient_commitment: devnet_commitment("mint-recipient", mint_id),
            minted_note_commitment: devnet_commitment("mint-note", mint_id),
            amount_commitment: devnet_commitment("mint-amount", mint_id),
            destination_state_root: devnet_commitment("mint-destination-state", mint_id),
            private_contract_call_root: devnet_commitment("mint-contract-call", mint_id),
            pq_mint_signature_root: devnet_commitment("mint-pq-signature", mint_id),
            status: NoteStatus::Finalized,
            mint_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mint_id": self.mint_id,
            "lock_id": self.lock_id,
            "quote_id": self.quote_id,
            "destination_rollup": self.destination_rollup,
            "recipient_commitment": self.recipient_commitment,
            "minted_note_commitment": self.minted_note_commitment,
            "amount_commitment": self.amount_commitment,
            "destination_state_root": self.destination_state_root,
            "private_contract_call_root": self.private_contract_call_root,
            "pq_mint_signature_root": self.pq_mint_signature_root,
            "status": self.status.as_str(),
            "mint_height": self.mint_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedBurnRecord {
    pub burn_id: String,
    pub quote_id: String,
    pub lane_id: String,
    pub destination_rollup: String,
    pub spender_nullifier: String,
    pub burn_note_commitment: String,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub burn_state_root: String,
    pub pq_burn_signature_root: String,
    pub status: NoteStatus,
    pub burn_height: u64,
}

impl ShieldedBurnRecord {
    pub fn devnet(burn_id: &str, quote_id: &str, lane_id: &str, height: u64) -> Self {
        Self {
            burn_id: burn_id.to_string(),
            quote_id: quote_id.to_string(),
            lane_id: lane_id.to_string(),
            destination_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_DESTINATION_ROLLUP
                .to_string(),
            spender_nullifier: devnet_commitment("burn-spender-nullifier", burn_id),
            burn_note_commitment: devnet_commitment("burn-note", burn_id),
            amount_commitment: devnet_commitment("burn-amount", burn_id),
            fee_commitment: devnet_commitment("burn-fee", burn_id),
            burn_state_root: devnet_commitment("burn-state", burn_id),
            pq_burn_signature_root: devnet_commitment("burn-pq-signature", burn_id),
            status: NoteStatus::Accepted,
            burn_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "burn_id": self.burn_id,
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "destination_rollup": self.destination_rollup,
            "spender_nullifier": self.spender_nullifier,
            "burn_note_commitment": self.burn_note_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "burn_state_root": self.burn_state_root,
            "pq_burn_signature_root": self.pq_burn_signature_root,
            "status": self.status.as_str(),
            "burn_height": self.burn_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedReleaseRecord {
    pub release_id: String,
    pub burn_id: String,
    pub quote_id: String,
    pub source_rollup: String,
    pub recipient_commitment: String,
    pub release_note_commitment: String,
    pub amount_commitment: String,
    pub monero_stealth_root: String,
    pub source_state_root: String,
    pub pq_release_signature_root: String,
    pub status: NoteStatus,
    pub release_height: u64,
}

impl ShieldedReleaseRecord {
    pub fn devnet(release_id: &str, burn_id: &str, quote_id: &str, height: u64) -> Self {
        Self {
            release_id: release_id.to_string(),
            burn_id: burn_id.to_string(),
            quote_id: quote_id.to_string(),
            source_rollup: PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_SOURCE_ROLLUP.to_string(),
            recipient_commitment: devnet_commitment("release-recipient", release_id),
            release_note_commitment: devnet_commitment("release-note", release_id),
            amount_commitment: devnet_commitment("release-amount", release_id),
            monero_stealth_root: devnet_commitment("release-monero-stealth", release_id),
            source_state_root: devnet_commitment("release-source-state", release_id),
            pq_release_signature_root: devnet_commitment("release-pq-signature", release_id),
            status: NoteStatus::Finalized,
            release_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "release_id": self.release_id,
            "burn_id": self.burn_id,
            "quote_id": self.quote_id,
            "source_rollup": self.source_rollup,
            "recipient_commitment": self.recipient_commitment,
            "release_note_commitment": self.release_note_commitment,
            "amount_commitment": self.amount_commitment,
            "monero_stealth_root": self.monero_stealth_root,
            "source_state_root": self.source_state_root,
            "pq_release_signature_root": self.pq_release_signature_root,
            "status": self.status.as_str(),
            "release_height": self.release_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub watcher_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub verdict: WatcherVerdict,
    pub observed_rollup_root: String,
    pub observed_monero_root: String,
    pub pq_signature_root: String,
    pub watcher_stake_root: String,
    pub security_bits: u16,
    pub observed_height: u64,
    pub finality_height: u64,
}

impl PqWatcherAttestation {
    pub fn devnet(
        attestation_id: &str,
        watcher_id: &str,
        lane_id: &str,
        subject_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            attestation_id: attestation_id.to_string(),
            watcher_id: watcher_id.to_string(),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            verdict: WatcherVerdict::Finalized,
            observed_rollup_root: devnet_commitment("watcher-rollup-root", attestation_id),
            observed_monero_root: devnet_commitment("watcher-monero-root", attestation_id),
            pq_signature_root: devnet_commitment("watcher-pq-signature", attestation_id),
            watcher_stake_root: devnet_commitment("watcher-stake", watcher_id),
            security_bits: config.min_pq_security_bits,
            observed_height: height,
            finality_height: height.saturating_add(config.fast_finality_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "verdict": self.verdict.as_str(),
            "observed_rollup_root": self.observed_rollup_root,
            "observed_monero_root": self.observed_monero_root,
            "pq_signature_root": self.pq_signature_root,
            "watcher_stake_root": self.watcher_stake_root,
            "security_bits": self.security_bits,
            "observed_height": self.observed_height,
            "finality_height": self.finality_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipRecord {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub quote_id: String,
    pub lane_id: String,
    pub recipient_nullifier: String,
    pub budget_commitment: String,
    pub rebate_commitment: String,
    pub fee_credit_root: String,
    pub eligibility_proof_root: String,
    pub rebate_bps: u64,
    pub spent_units: u64,
    pub created_height: u64,
    pub expires_height: u64,
}

impl LowFeeSponsorshipRecord {
    pub fn devnet(
        sponsorship_id: &str,
        quote_id: &str,
        lane_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            sponsorship_id: sponsorship_id.to_string(),
            sponsor_id: "devnet-private-fee-sponsor-1".to_string(),
            quote_id: quote_id.to_string(),
            lane_id: lane_id.to_string(),
            recipient_nullifier: devnet_commitment("sponsor-recipient", sponsorship_id),
            budget_commitment: devnet_commitment("sponsor-budget", sponsorship_id),
            rebate_commitment: devnet_commitment("sponsor-rebate", sponsorship_id),
            fee_credit_root: devnet_commitment("sponsor-fee-credit", sponsorship_id),
            eligibility_proof_root: devnet_commitment("sponsor-eligibility", sponsorship_id),
            rebate_bps: config.low_fee_rebate_bps,
            spent_units: 3,
            created_height: height,
            expires_height: height.saturating_add(config.lock_ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "quote_id": self.quote_id,
            "lane_id": self.lane_id,
            "recipient_nullifier": self.recipient_nullifier,
            "budget_commitment": self.budget_commitment,
            "rebate_commitment": self.rebate_commitment,
            "fee_credit_root": self.fee_credit_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "rebate_bps": self.rebate_bps,
            "spent_units": self.spent_units,
            "created_height": self.created_height,
            "expires_height": self.expires_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReorgWindow {
    pub window_id: String,
    pub lane_id: String,
    pub anchor_subject_id: String,
    pub source_height: u64,
    pub destination_height: u64,
    pub fast_finality_height: u64,
    pub safe_finality_height: u64,
    pub reorg_grace_height: u64,
    pub optimistic_release_allowed: bool,
    pub reorg_proof_root: String,
    pub watcher_quorum_root: String,
}

impl FinalityReorgWindow {
    pub fn devnet(
        window_id: &str,
        lane_id: &str,
        subject_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            window_id: window_id.to_string(),
            lane_id: lane_id.to_string(),
            anchor_subject_id: subject_id.to_string(),
            source_height: height,
            destination_height: height.saturating_add(1),
            fast_finality_height: height.saturating_add(config.fast_finality_blocks),
            safe_finality_height: height.saturating_add(config.safe_finality_blocks),
            reorg_grace_height: height
                .saturating_add(config.safe_finality_blocks)
                .saturating_add(config.reorg_grace_blocks),
            optimistic_release_allowed: true,
            reorg_proof_root: devnet_commitment("finality-reorg-proof", window_id),
            watcher_quorum_root: devnet_commitment("finality-watchers", window_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "anchor_subject_id": self.anchor_subject_id,
            "source_height": self.source_height,
            "destination_height": self.destination_height,
            "fast_finality_height": self.fast_finality_height,
            "safe_finality_height": self.safe_finality_height,
            "reorg_grace_height": self.reorg_grace_height,
            "optimistic_release_allowed": self.optimistic_release_allowed,
            "reorg_proof_root": self.reorg_proof_root,
            "watcher_quorum_root": self.watcher_quorum_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeSlashEvidence {
    pub challenge_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub challenger_id: String,
    pub accused_solver_id: String,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub conflicting_root: String,
    pub pq_disclosure_root: String,
    pub slash_amount_commitment: String,
    pub reward_commitment: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub resolved_height: Option<u64>,
}

impl ChallengeSlashEvidence {
    pub fn devnet(
        challenge_id: &str,
        lane_id: &str,
        subject_id: &str,
        height: u64,
        config: &PrivateCrossRollupLiquidityBridgeConfig,
    ) -> Self {
        Self {
            challenge_id: challenge_id.to_string(),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            challenger_id: "devnet-watchtower-challenger-1".to_string(),
            accused_solver_id: "devnet-solver-a".to_string(),
            status: ChallengeStatus::EvidenceAccepted,
            evidence_root: devnet_commitment("challenge-evidence", challenge_id),
            conflicting_root: devnet_commitment("challenge-conflict", challenge_id),
            pq_disclosure_root: devnet_commitment("challenge-pq-disclosure", challenge_id),
            slash_amount_commitment: devnet_commitment("challenge-slash-amount", challenge_id),
            reward_commitment: devnet_commitment("challenge-reward", challenge_id),
            opened_height: height,
            expires_height: height.saturating_add(config.challenge_window_blocks),
            resolved_height: Some(height.saturating_add(2)),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "challenge_id": self.challenge_id,
            "lane_id": self.lane_id,
            "subject_id": self.subject_id,
            "challenger_id": self.challenger_id,
            "accused_solver_id": self.accused_solver_id,
            "status": self.status.as_str(),
            "evidence_root": self.evidence_root,
            "conflicting_root": self.conflicting_root,
            "pq_disclosure_root": self.pq_disclosure_root,
            "slash_amount_commitment": self.slash_amount_commitment,
            "reward_commitment": self.reward_commitment,
            "opened_height": self.opened_height,
            "expires_height": self.expires_height,
            "resolved_height": self.resolved_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub lane_id: String,
    pub payload_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl BridgeEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        lane_id: &str,
        payload: &Value,
        height: u64,
        sequence: u64,
    ) -> PrivateCrossRollupLiquidityBridgeResult<Self> {
        ensure_nonempty("event.event_kind", event_kind)?;
        ensure_nonempty("event.subject_id", subject_id)?;
        ensure_nonempty("event.lane_id", lane_id)?;
        let payload_root = bridge_payload_root("EVENT-PAYLOAD", payload);
        let event_id = domain_hash(
            "PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-EVENT-ID",
            &[
                HashPart::Str(event_kind),
                HashPart::Str(subject_id),
                HashPart::Str(lane_id),
                HashPart::Str(&payload_root),
                HashPart::Int(height as i128),
                HashPart::Int(sequence as i128),
            ],
            32,
        );
        Ok(Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            lane_id: lane_id.to_string(),
            payload_root,
            height,
            sequence,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "lane_id": self.lane_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeterministicBridgeRecord {
    pub record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub payload_root: String,
    pub payload: Value,
    pub created_height: u64,
}

impl DeterministicBridgeRecord {
    pub fn new(
        record_kind: &str,
        subject_id: &str,
        payload: &Value,
        created_height: u64,
    ) -> PrivateCrossRollupLiquidityBridgeResult<Self> {
        ensure_nonempty("record.record_kind", record_kind)?;
        ensure_nonempty("record.subject_id", subject_id)?;
        let payload_root = bridge_payload_root(record_kind, payload);
        let record_id = domain_hash(
            "PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-RECORD-ID",
            &[
                HashPart::Str(record_kind),
                HashPart::Str(subject_id),
                HashPart::Str(&payload_root),
                HashPart::Int(created_height as i128),
            ],
            32,
        );
        Ok(Self {
            record_id,
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            payload_root,
            payload: payload.clone(),
            created_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "payload": self.payload,
            "created_height": self.created_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossRollupLiquidityBridgeRoots {
    pub config_root: String,
    pub lane_root: String,
    pub pool_root: String,
    pub quote_root: String,
    pub solver_commitment_root: String,
    pub lock_root: String,
    pub mint_root: String,
    pub burn_root: String,
    pub release_root: String,
    pub watcher_attestation_root: String,
    pub sponsorship_root: String,
    pub finality_window_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
    pub event_root: String,
}

impl PrivateCrossRollupLiquidityBridgeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "pool_root": self.pool_root,
            "quote_root": self.quote_root,
            "solver_commitment_root": self.solver_commitment_root,
            "lock_root": self.lock_root,
            "mint_root": self.mint_root,
            "burn_root": self.burn_root,
            "release_root": self.release_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "sponsorship_root": self.sponsorship_root,
            "finality_window_root": self.finality_window_root,
            "challenge_root": self.challenge_root,
            "public_record_root": self.public_record_root,
            "event_root": self.event_root,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossRollupLiquidityBridgeCounters {
    pub lane_count: u64,
    pub pool_count: u64,
    pub quote_count: u64,
    pub solver_commitment_count: u64,
    pub lock_count: u64,
    pub mint_count: u64,
    pub burn_count: u64,
    pub release_count: u64,
    pub watcher_attestation_count: u64,
    pub sponsorship_count: u64,
    pub finality_window_count: u64,
    pub challenge_count: u64,
    pub public_record_count: u64,
    pub event_count: u64,
    pub live_quote_count: u64,
    pub finalized_note_count: u64,
    pub challenged_subject_count: u64,
}

impl PrivateCrossRollupLiquidityBridgeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count,
            "pool_count": self.pool_count,
            "quote_count": self.quote_count,
            "solver_commitment_count": self.solver_commitment_count,
            "lock_count": self.lock_count,
            "mint_count": self.mint_count,
            "burn_count": self.burn_count,
            "release_count": self.release_count,
            "watcher_attestation_count": self.watcher_attestation_count,
            "sponsorship_count": self.sponsorship_count,
            "finality_window_count": self.finality_window_count,
            "challenge_count": self.challenge_count,
            "public_record_count": self.public_record_count,
            "event_count": self.event_count,
            "live_quote_count": self.live_quote_count,
            "finalized_note_count": self.finalized_note_count,
            "challenged_subject_count": self.challenged_subject_count,
        })
    }

    pub fn root(&self) -> String {
        bridge_payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateCrossRollupLiquidityBridgeState {
    pub config: PrivateCrossRollupLiquidityBridgeConfig,
    pub height: u64,
    pub lanes: BTreeMap<String, LiquidityLane>,
    pub pools: BTreeMap<String, LiquidityPool>,
    pub quotes: BTreeMap<String, ConfidentialRouteQuote>,
    pub solver_commitments: BTreeMap<String, SolverCommitment>,
    pub locks: BTreeMap<String, ShieldedLockRecord>,
    pub mints: BTreeMap<String, ShieldedMintRecord>,
    pub burns: BTreeMap<String, ShieldedBurnRecord>,
    pub releases: BTreeMap<String, ShieldedReleaseRecord>,
    pub watcher_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorshipRecord>,
    pub finality_windows: BTreeMap<String, FinalityReorgWindow>,
    pub challenges: BTreeMap<String, ChallengeSlashEvidence>,
    pub public_records: BTreeMap<String, DeterministicBridgeRecord>,
    pub events: BTreeMap<String, BridgeEvent>,
}

impl PrivateCrossRollupLiquidityBridgeState {
    pub fn new(config: PrivateCrossRollupLiquidityBridgeConfig, height: u64) -> Self {
        Self {
            config,
            height,
            lanes: BTreeMap::new(),
            pools: BTreeMap::new(),
            quotes: BTreeMap::new(),
            solver_commitments: BTreeMap::new(),
            locks: BTreeMap::new(),
            mints: BTreeMap::new(),
            burns: BTreeMap::new(),
            releases: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            finality_windows: BTreeMap::new(),
            challenges: BTreeMap::new(),
            public_records: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateCrossRollupLiquidityBridgeResult<Self> {
        let config = PrivateCrossRollupLiquidityBridgeConfig::devnet();
        let height = PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_HEIGHT;
        let mut state = Self::new(config, height);

        state.upsert_lane(LiquidityLane::devnet_rollup_to_rollup(
            "devnet-lane-rollup-a-b-wxmr",
            height,
        ))?;
        state.upsert_lane(LiquidityLane::devnet_monero_lane(
            "devnet-lane-monero-a-wxmr",
            BridgeDirection::MoneroToRollup,
            height,
        ))?;

        state.upsert_pool(LiquidityPool::devnet(
            "devnet-pool-wxmr-rollup-a-b",
            "devnet-lane-rollup-a-b-wxmr",
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_WXMR_ASSET_ID,
            "devnet-solver-a",
            height,
        ))?;
        state.upsert_pool(LiquidityPool::devnet(
            "devnet-pool-dusd-rollup-a-b",
            "devnet-lane-rollup-a-b-wxmr",
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_STABLE_ASSET_ID,
            "devnet-solver-b",
            height,
        ))?;
        state.upsert_pool(LiquidityPool::devnet(
            "devnet-pool-xmr-wxmr-monero",
            "devnet-lane-monero-a-wxmr",
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_DEVNET_XMR_ASSET_ID,
            "devnet-solver-monero",
            height,
        ))?;

        state.upsert_quote(ConfidentialRouteQuote::devnet(
            "devnet-quote-fast-wxmr-1",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-pool-wxmr-rollup-a-b",
            "devnet-solver-a",
            BridgePriority::Fast,
            height,
            &state.config,
        ))?;
        state.upsert_quote(ConfidentialRouteQuote::devnet(
            "devnet-quote-low-fee-dusd-1",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-pool-dusd-rollup-a-b",
            "devnet-solver-b",
            BridgePriority::LowFee,
            height,
            &state.config,
        ))?;

        state.upsert_solver_commitment(SolverCommitment::devnet(
            "devnet-solver-commitment-a-1",
            "devnet-solver-a",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-pool-wxmr-rollup-a-b",
            "devnet-quote-fast-wxmr-1",
            height,
            &state.config,
        ))?;

        state.upsert_lock(ShieldedLockRecord::devnet(
            "devnet-lock-wxmr-1",
            "devnet-quote-fast-wxmr-1",
            "devnet-lane-rollup-a-b-wxmr",
            height.saturating_add(1),
            &state.config,
        ))?;
        state.upsert_mint(ShieldedMintRecord::devnet(
            "devnet-mint-wxmr-1",
            "devnet-lock-wxmr-1",
            "devnet-quote-fast-wxmr-1",
            height.saturating_add(4),
        ))?;
        state.upsert_burn(ShieldedBurnRecord::devnet(
            "devnet-burn-wxmr-1",
            "devnet-quote-fast-wxmr-1",
            "devnet-lane-rollup-a-b-wxmr",
            height.saturating_add(8),
        ))?;
        state.upsert_release(ShieldedReleaseRecord::devnet(
            "devnet-release-wxmr-1",
            "devnet-burn-wxmr-1",
            "devnet-quote-fast-wxmr-1",
            height.saturating_add(12),
        ))?;

        state.upsert_watcher_attestation(PqWatcherAttestation::devnet(
            "devnet-watch-attestation-lock-1",
            "devnet-pq-watcher-1",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-lock-wxmr-1",
            height.saturating_add(2),
            &state.config,
        ))?;
        state.upsert_sponsorship(LowFeeSponsorshipRecord::devnet(
            "devnet-low-fee-sponsor-1",
            "devnet-quote-low-fee-dusd-1",
            "devnet-lane-rollup-a-b-wxmr",
            height,
            &state.config,
        ))?;
        state.upsert_finality_window(FinalityReorgWindow::devnet(
            "devnet-finality-window-lock-1",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-lock-wxmr-1",
            height.saturating_add(1),
            &state.config,
        ))?;
        state.upsert_challenge(ChallengeSlashEvidence::devnet(
            "devnet-challenge-soft-reorg-1",
            "devnet-lane-rollup-a-b-wxmr",
            "devnet-finality-window-lock-1",
            height.saturating_add(6),
            &state.config,
        ))?;

        let boot_record = DeterministicBridgeRecord::new(
            "devnet_bootstrap",
            "private_cross_rollup_liquidity_bridge",
            &json!({
                "state_root": state.state_root(),
                "lane_count": state.lanes.len(),
                "pool_count": state.pools.len(),
                "quote_count": state.quotes.len(),
            }),
            height,
        )?;
        state.insert_public_record(boot_record)?;
        state.emit_event(
            "devnet_seeded",
            "private_cross_rollup_liquidity_bridge",
            "devnet-lane-rollup-a-b-wxmr",
            &state.public_record(),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn upsert_lane(
        &mut self,
        lane: LiquidityLane,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        lane.validate(&self.config)?;
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn upsert_pool(
        &mut self,
        pool: LiquidityPool,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        pool.validate(&self.lanes, &self.config)?;
        self.pools.insert(pool.pool_id.clone(), pool);
        Ok(())
    }

    pub fn upsert_quote(
        &mut self,
        quote: ConfidentialRouteQuote,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        quote.validate(&self.lanes, &self.pools, &self.config)?;
        self.quotes.insert(quote.quote_id.clone(), quote);
        Ok(())
    }

    pub fn upsert_solver_commitment(
        &mut self,
        commitment: SolverCommitment,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        commitment.validate(&self.quotes)?;
        self.solver_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn upsert_lock(
        &mut self,
        record: ShieldedLockRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_quote(&record.quote_id)?;
        self.require_lane(&record.lane_id)?;
        self.locks.insert(record.lock_id.clone(), record);
        Ok(())
    }

    pub fn upsert_mint(
        &mut self,
        record: ShieldedMintRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_quote(&record.quote_id)?;
        if !self.locks.contains_key(&record.lock_id) {
            return Err(format!(
                "mint {} references missing lock {}",
                record.mint_id, record.lock_id
            ));
        }
        self.mints.insert(record.mint_id.clone(), record);
        Ok(())
    }

    pub fn upsert_burn(
        &mut self,
        record: ShieldedBurnRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_quote(&record.quote_id)?;
        self.require_lane(&record.lane_id)?;
        self.burns.insert(record.burn_id.clone(), record);
        Ok(())
    }

    pub fn upsert_release(
        &mut self,
        record: ShieldedReleaseRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_quote(&record.quote_id)?;
        if !self.burns.contains_key(&record.burn_id) {
            return Err(format!(
                "release {} references missing burn {}",
                record.release_id, record.burn_id
            ));
        }
        self.releases.insert(record.release_id.clone(), record);
        Ok(())
    }

    pub fn upsert_watcher_attestation(
        &mut self,
        record: PqWatcherAttestation,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_lane(&record.lane_id)?;
        if record.security_bits < self.config.min_pq_security_bits {
            return Err(format!(
                "watcher attestation {} below pq security floor",
                record.attestation_id
            ));
        }
        self.watcher_attestations
            .insert(record.attestation_id.clone(), record);
        Ok(())
    }

    pub fn upsert_sponsorship(
        &mut self,
        record: LowFeeSponsorshipRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_quote(&record.quote_id)?;
        self.require_lane(&record.lane_id)?;
        ensure_bps("sponsorship.rebate_bps", record.rebate_bps)?;
        self.sponsorships
            .insert(record.sponsorship_id.clone(), record);
        Ok(())
    }

    pub fn upsert_finality_window(
        &mut self,
        record: FinalityReorgWindow,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_lane(&record.lane_id)?;
        if record.fast_finality_height > record.safe_finality_height {
            return Err(format!(
                "finality window {} fast height exceeds safe height",
                record.window_id
            ));
        }
        if record.safe_finality_height > record.reorg_grace_height {
            return Err(format!(
                "finality window {} safe height exceeds reorg grace",
                record.window_id
            ));
        }
        self.finality_windows
            .insert(record.window_id.clone(), record);
        Ok(())
    }

    pub fn upsert_challenge(
        &mut self,
        record: ChallengeSlashEvidence,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        self.require_lane(&record.lane_id)?;
        if record.opened_height >= record.expires_height {
            return Err(format!(
                "challenge {} has invalid expiry",
                record.challenge_id
            ));
        }
        self.challenges.insert(record.challenge_id.clone(), record);
        Ok(())
    }

    pub fn insert_public_record(
        &mut self,
        record: DeterministicBridgeRecord,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        if self.public_records.len() >= PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_PUBLIC_RECORDS
            && !self.public_records.contains_key(&record.record_id)
        {
            return Err("state.public_records exceeds configured cap".to_string());
        }
        self.public_records.insert(record.record_id.clone(), record);
        Ok(())
    }

    pub fn emit_event(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        lane_id: &str,
        payload: &Value,
    ) -> PrivateCrossRollupLiquidityBridgeResult<String> {
        if self.events.len() >= PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_EVENTS {
            return Err("state.events exceeds configured cap".to_string());
        }
        let sequence = self.events.len() as u64;
        let event = BridgeEvent::new(
            event_kind,
            subject_id,
            lane_id,
            payload,
            self.height,
            sequence,
        )?;
        let event_id = event.event_id.clone();
        self.events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn mark_quote_committed(
        &mut self,
        quote_id: &str,
        solver_commitment_id: &str,
    ) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        if !self.solver_commitments.contains_key(solver_commitment_id) {
            return Err(format!(
                "missing solver commitment {}",
                solver_commitment_id
            ));
        }
        let quote = self
            .quotes
            .get_mut(quote_id)
            .ok_or_else(|| format!("missing quote {}", quote_id))?;
        if quote.status != QuoteStatus::Offered {
            return Err(format!(
                "quote {} cannot be committed from {}",
                quote_id,
                quote.status.as_str()
            ));
        }
        quote.status = QuoteStatus::Committed;
        Ok(())
    }

    pub fn expire_quotes(&mut self, height: u64) -> u64 {
        let mut expired = 0_u64;
        for quote in self.quotes.values_mut() {
            if !quote.status.is_terminal() && quote.is_expired(height) {
                quote.status = QuoteStatus::Expired;
                expired = expired.saturating_add(1);
            }
        }
        expired
    }

    pub fn set_height(&mut self, height: u64) -> PrivateCrossRollupLiquidityBridgeResult<String> {
        if height < self.height {
            return Err(format!(
                "private cross-rollup bridge height cannot move backward from {} to {}",
                self.height, height
            ));
        }
        self.height = height;
        let expired_quotes = self.expire_quotes(height);
        if expired_quotes > 0 {
            let _ = self.emit_event(
                "quotes_expired",
                "quote_ttl",
                "all",
                &json!({"height": height, "expired_quotes": expired_quotes}),
            )?;
        }
        self.validate()
    }

    pub fn apply_reorg_hold(
        &mut self,
        lane_id: &str,
        subject_id: &str,
        height: u64,
    ) -> PrivateCrossRollupLiquidityBridgeResult<String> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("missing lane {}", lane_id))?;
        if !lane.status.accepts_settlement() {
            return Err(format!(
                "lane {} cannot enter reorg hold from {}",
                lane_id,
                lane.status.as_str()
            ));
        }
        lane.status = LaneStatus::ReorgHold;
        lane.updated_height = height;
        self.height = self.height.max(height);
        self.emit_event(
            "reorg_hold_applied",
            subject_id,
            lane_id,
            &json!({"lane_id": lane_id, "subject_id": subject_id, "height": height}),
        )
    }

    pub fn release_reorg_hold(
        &mut self,
        lane_id: &str,
        height: u64,
    ) -> PrivateCrossRollupLiquidityBridgeResult<String> {
        let lane = self
            .lanes
            .get_mut(lane_id)
            .ok_or_else(|| format!("missing lane {}", lane_id))?;
        if lane.status != LaneStatus::ReorgHold {
            return Err(format!("lane {} is not in reorg hold", lane_id));
        }
        lane.status = LaneStatus::Active;
        lane.updated_height = height;
        self.height = self.height.max(height);
        self.emit_event(
            "reorg_hold_released",
            lane_id,
            lane_id,
            &json!({"lane_id": lane_id, "height": height}),
        )
    }

    pub fn roots(&self) -> PrivateCrossRollupLiquidityBridgeRoots {
        PrivateCrossRollupLiquidityBridgeRoots {
            config_root: self.config.root(),
            lane_root: map_root("LANES", &self.lanes, LiquidityLane::public_record),
            pool_root: map_root("POOLS", &self.pools, LiquidityPool::public_record),
            quote_root: map_root(
                "QUOTES",
                &self.quotes,
                ConfidentialRouteQuote::public_record,
            ),
            solver_commitment_root: map_root(
                "SOLVER-COMMITMENTS",
                &self.solver_commitments,
                SolverCommitment::public_record,
            ),
            lock_root: map_root("LOCKS", &self.locks, ShieldedLockRecord::public_record),
            mint_root: map_root("MINTS", &self.mints, ShieldedMintRecord::public_record),
            burn_root: map_root("BURNS", &self.burns, ShieldedBurnRecord::public_record),
            release_root: map_root(
                "RELEASES",
                &self.releases,
                ShieldedReleaseRecord::public_record,
            ),
            watcher_attestation_root: map_root(
                "WATCHER-ATTESTATIONS",
                &self.watcher_attestations,
                PqWatcherAttestation::public_record,
            ),
            sponsorship_root: map_root(
                "SPONSORSHIPS",
                &self.sponsorships,
                LowFeeSponsorshipRecord::public_record,
            ),
            finality_window_root: map_root(
                "FINALITY-WINDOWS",
                &self.finality_windows,
                FinalityReorgWindow::public_record,
            ),
            challenge_root: map_root(
                "CHALLENGES",
                &self.challenges,
                ChallengeSlashEvidence::public_record,
            ),
            public_record_root: map_root(
                "PUBLIC-RECORDS",
                &self.public_records,
                DeterministicBridgeRecord::public_record,
            ),
            event_root: map_root("EVENTS", &self.events, BridgeEvent::public_record),
        }
    }

    pub fn counters(&self) -> PrivateCrossRollupLiquidityBridgeCounters {
        let finalized_note_count = self
            .locks
            .values()
            .filter(|record| record.status == NoteStatus::Finalized)
            .count()
            .saturating_add(
                self.mints
                    .values()
                    .filter(|record| record.status == NoteStatus::Finalized)
                    .count(),
            )
            .saturating_add(
                self.releases
                    .values()
                    .filter(|record| record.status == NoteStatus::Finalized)
                    .count(),
            );
        PrivateCrossRollupLiquidityBridgeCounters {
            lane_count: self.lanes.len() as u64,
            pool_count: self.pools.len() as u64,
            quote_count: self.quotes.len() as u64,
            solver_commitment_count: self.solver_commitments.len() as u64,
            lock_count: self.locks.len() as u64,
            mint_count: self.mints.len() as u64,
            burn_count: self.burns.len() as u64,
            release_count: self.releases.len() as u64,
            watcher_attestation_count: self.watcher_attestations.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            finality_window_count: self.finality_windows.len() as u64,
            challenge_count: self.challenges.len() as u64,
            public_record_count: self.public_records.len() as u64,
            event_count: self.events.len() as u64,
            live_quote_count: self
                .quotes
                .values()
                .filter(|quote| !quote.status.is_terminal())
                .count() as u64,
            finalized_note_count: finalized_note_count as u64,
            challenged_subject_count: self
                .challenges
                .values()
                .map(|challenge| challenge.subject_id.clone())
                .collect::<BTreeSet<_>>()
                .len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol": PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_PROTOCOL_LABEL,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        private_cross_rollup_liquidity_bridge_state_root_from_record(&self.public_record())
    }

    pub fn validate(&self) -> PrivateCrossRollupLiquidityBridgeResult<String> {
        self.config.validate()?;
        ensure_cap(
            "state.lanes",
            self.lanes.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_LANES,
        )?;
        ensure_cap(
            "state.pools",
            self.pools.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_POOLS,
        )?;
        ensure_cap(
            "state.quotes",
            self.quotes.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_QUOTES,
        )?;
        ensure_cap(
            "state.solver_commitments",
            self.solver_commitments.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_SOLVERS,
        )?;
        ensure_cap(
            "state.locks",
            self.locks.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_LOCKS,
        )?;
        ensure_cap(
            "state.mints",
            self.mints.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_MINTS,
        )?;
        ensure_cap(
            "state.burns",
            self.burns.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_BURNS,
        )?;
        ensure_cap(
            "state.releases",
            self.releases.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_RELEASES,
        )?;
        ensure_cap(
            "state.watcher_attestations",
            self.watcher_attestations.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_ATTESTATIONS,
        )?;
        ensure_cap(
            "state.sponsorships",
            self.sponsorships.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_SPONSORSHIPS,
        )?;
        ensure_cap(
            "state.finality_windows",
            self.finality_windows.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_FINALITY_WINDOWS,
        )?;
        ensure_cap(
            "state.challenges",
            self.challenges.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_CHALLENGES,
        )?;
        ensure_cap(
            "state.public_records",
            self.public_records.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_PUBLIC_RECORDS,
        )?;
        ensure_cap(
            "state.events",
            self.events.len(),
            PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_EVENTS,
        )?;
        for lane in self.lanes.values() {
            lane.validate(&self.config)?;
        }
        for pool in self.pools.values() {
            pool.validate(&self.lanes, &self.config)?;
        }
        for quote in self.quotes.values() {
            quote.validate(&self.lanes, &self.pools, &self.config)?;
        }
        for commitment in self.solver_commitments.values() {
            commitment.validate(&self.quotes)?;
        }
        for lock in self.locks.values() {
            self.require_quote(&lock.quote_id)?;
            self.require_lane(&lock.lane_id)?;
        }
        for mint in self.mints.values() {
            self.require_quote(&mint.quote_id)?;
            if !self.locks.contains_key(&mint.lock_id) {
                return Err(format!(
                    "mint {} references missing lock {}",
                    mint.mint_id, mint.lock_id
                ));
            }
        }
        for burn in self.burns.values() {
            self.require_quote(&burn.quote_id)?;
            self.require_lane(&burn.lane_id)?;
        }
        for release in self.releases.values() {
            self.require_quote(&release.quote_id)?;
            if !self.burns.contains_key(&release.burn_id) {
                return Err(format!(
                    "release {} references missing burn {}",
                    release.release_id, release.burn_id
                ));
            }
        }
        for attestation in self.watcher_attestations.values() {
            self.require_lane(&attestation.lane_id)?;
            if attestation.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "attestation {} below pq security floor",
                    attestation.attestation_id
                ));
            }
        }
        for sponsorship in self.sponsorships.values() {
            self.require_quote(&sponsorship.quote_id)?;
            self.require_lane(&sponsorship.lane_id)?;
            ensure_bps("sponsorship.rebate_bps", sponsorship.rebate_bps)?;
        }
        Ok(self.state_root())
    }

    fn require_lane(&self, lane_id: &str) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        if self.lanes.contains_key(lane_id) {
            Ok(())
        } else {
            Err(format!("missing lane {}", lane_id))
        }
    }

    fn require_quote(&self, quote_id: &str) -> PrivateCrossRollupLiquidityBridgeResult<()> {
        if self.quotes.contains_key(quote_id) {
            Ok(())
        } else {
            Err(format!("missing quote {}", quote_id))
        }
    }
}

pub fn private_cross_rollup_liquidity_bridge_devnet(
) -> PrivateCrossRollupLiquidityBridgeResult<PrivateCrossRollupLiquidityBridgeState> {
    PrivateCrossRollupLiquidityBridgeState::devnet()
}

pub fn private_cross_rollup_liquidity_bridge_state_root_from_record(record: &Value) -> String {
    bridge_payload_root("STATE", record)
}

pub fn private_cross_rollup_liquidity_bridge_quote_id(
    lane_id: &str,
    pool_id: &str,
    solver_id: &str,
    route_secret_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-QUOTE-ID",
        &[
            HashPart::Str(lane_id),
            HashPart::Str(pool_id),
            HashPart::Str(solver_id),
            HashPart::Str(route_secret_commitment),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn private_cross_rollup_liquidity_bridge_note_id(
    note_kind: &str,
    quote_id: &str,
    note_commitment: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-NOTE-ID",
        &[
            HashPart::Str(note_kind),
            HashPart::Str(quote_id),
            HashPart::Str(note_commitment),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn bridge_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-{domain}"),
        &[HashPart::Json(payload)],
        32,
    )
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-{domain}"),
        &leaves,
    )
}

fn devnet_commitment(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-CROSS-ROLLUP-LIQUIDITY-BRIDGE-DEVNET-{domain}"),
        &[HashPart::Str(label)],
        32,
    )
}

fn ensure_nonempty(field: &str, value: &str) -> PrivateCrossRollupLiquidityBridgeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(field: &str, value: u64) -> PrivateCrossRollupLiquidityBridgeResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> PrivateCrossRollupLiquidityBridgeResult<()> {
    if value > PRIVATE_CROSS_ROLLUP_LIQUIDITY_BRIDGE_MAX_BPS {
        Err(format!("{field} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_cap(field: &str, len: usize, cap: usize) -> PrivateCrossRollupLiquidityBridgeResult<()> {
    if len > cap {
        Err(format!("{field} length {len} exceeds cap {cap}"))
    } else {
        Ok(())
    }
}
