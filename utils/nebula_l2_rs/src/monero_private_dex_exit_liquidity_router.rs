use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPrivateDexExitLiquidityRouterResult<T> = Result<T, String>;

pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-monero-private-dex-exit-liquidity-router-v1";
pub const PROTOCOL_VERSION: &str = MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_HEIGHT: u64 = 448;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_SEALED_INTENT_SCHEME: &str =
    "sealed-xmr-exit-intent-nullifier-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_LANE_COMMITMENT_SCHEME: &str =
    "private-dex-liquidity-lane-commitment-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAKER_COMMITMENT_SCHEME: &str =
    "market-maker-reserve-commitment-shake256-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_ATOMIC_SWAP_HINT_SCHEME: &str =
    "xmr-atomic-swap-settlement-hints-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PRIVACY_CHALLENGE_SCHEME: &str =
    "privacy-challenge-receipt-delay-disclosure-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_ROUTE_SELECTION_SCHEME: &str =
    "low-fee-reserve-risk-route-selection-v1";
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS: u64 = 24;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_LOW_FEE_TTL_BLOCKS: u64 = 240;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 18;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 36;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 4096;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 =
    12_000;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_FEE_BPS: u64 = 90;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_LOW_FEE_BPS: u64 = 12;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_FAST_FEE_BPS: u64 = 55;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_EMERGENCY_FEE_BPS: u64 = 125;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_FEE_FLOOR_PICONERO: u64 = 2_500;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_MAKER_BOND_PICONERO: u64 =
    10_000_000_000;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_HOPS: usize = 4;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_LANE_LOAD_BPS: u64 = 8_500;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_RESERVE_STRESS_BPS: u64 = 1_250;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_PRIVACY_REBATE_BPS: u64 = 2_000;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS: u64 = 10_000;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_LANES: usize = 64;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_INTENTS: usize = 65_536;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_MAKERS: usize = 16_384;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_COMMITMENTS: usize = 65_536;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_QUOTES: usize = 131_072;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_ROUTES: usize = 65_536;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_SWAP_HINTS: usize = 65_536;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_RISK_SNAPSHOTS: usize = 32_768;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_CHALLENGES: usize = 32_768;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_RECEIPTS: usize = 65_536;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_EVENTS: usize = 262_144;
pub const MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_PUBLIC_RECORDS: usize = 524_288;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitLaneKind {
    LowFee,
    Standard,
    Fast,
    StablecoinBridge,
    DexArb,
    WalletRecovery,
    Emergency,
}

impl ExitLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::Standard => "standard",
            Self::Fast => "fast",
            Self::StablecoinBridge => "stablecoin_bridge",
            Self::DexArb => "dex_arb",
            Self::WalletRecovery => "wallet_recovery",
            Self::Emergency => "emergency",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee | Self::WalletRecovery => config.low_fee_bps,
            Self::Fast | Self::DexArb => config.fast_fee_bps,
            Self::Emergency => config.emergency_fee_bps,
            Self::Standard | Self::StablecoinBridge => {
                config.max_route_fee_bps.min(config.fast_fee_bps)
            }
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::LowFee => 1_000,
            Self::WalletRecovery => 940,
            Self::StablecoinBridge => 860,
            Self::Standard => 760,
            Self::Fast => 640,
            Self::DexArb => 520,
            Self::Emergency => 420,
        }
    }

    pub fn risk_weight_bps(self) -> u64 {
        match self {
            Self::LowFee => 8_500,
            Self::WalletRecovery => 9_000,
            Self::Standard => 10_000,
            Self::StablecoinBridge => 10_500,
            Self::Fast => 11_250,
            Self::DexArb => 12_500,
            Self::Emergency => 16_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    Quoted,
    Routed,
    SwapHinted,
    Settling,
    Settled,
    Challenged,
    Cancelled,
    Expired,
    Rejected,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::Quoted => "quoted",
            Self::Routed => "routed",
            Self::SwapHinted => "swap_hinted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Admitted
                | Self::Quoted
                | Self::Routed
                | Self::SwapHinted
                | Self::Settling
                | Self::Challenged
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Cancelled | Self::Expired | Self::Rejected
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    LowFeeOnly,
    Congested,
    Draining,
    Paused,
    Challenged,
    Retired,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::LowFeeOnly => "low_fee_only",
            Self::Congested => "congested",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Challenged => "challenged",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_routes(self) -> bool {
        matches!(self, Self::Open | Self::LowFeeOnly | Self::Congested)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MakerStatus {
    Candidate,
    Active,
    Throttled,
    Draining,
    Paused,
    Challenged,
    Slashed,
    Retired,
}

impl MakerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }

    pub fn can_quote(self) -> bool {
        matches!(self, Self::Active | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Advertised,
    Attested,
    QuoteOpen,
    Allocated,
    Locked,
    Settled,
    Challenged,
    Slashed,
    Expired,
    Cancelled,
}

impl CommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advertised => "advertised",
            Self::Attested => "attested",
            Self::QuoteOpen => "quote_open",
            Self::Allocated => "allocated",
            Self::Locked => "locked",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn available(self) -> bool {
        matches!(self, Self::Advertised | Self::Attested | Self::QuoteOpen)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteStatus {
    Open,
    Selected,
    Superseded,
    Settling,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

impl QuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Selected => "selected",
            Self::Superseded => "superseded",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn selectable(self) -> bool {
        matches!(self, Self::Open | Self::Selected)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Candidate,
    Selected,
    Locked,
    SwapHinted,
    Settling,
    Settled,
    Challenged,
    Expired,
    Cancelled,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Selected => "selected",
            Self::Locked => "locked",
            Self::SwapHinted => "swap_hinted",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceOpen,
    Proving,
    Upheld,
    Rejected,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceOpen => "evidence_open",
            Self::Proving => "proving",
            Self::Upheld => "upheld",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub sealed_intent_scheme: String,
    pub lane_commitment_scheme: String,
    pub maker_commitment_scheme: String,
    pub atomic_swap_hint_scheme: String,
    pub privacy_challenge_scheme: String,
    pub route_selection_scheme: String,
    pub route_ttl_blocks: u64,
    pub low_fee_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub max_route_fee_bps: u64,
    pub low_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub fee_floor_piconero: u64,
    pub min_maker_bond_piconero: u64,
    pub max_route_hops: usize,
    pub max_lane_load_bps: u64,
    pub reserve_stress_bps: u64,
    pub privacy_rebate_bps: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_MONERO_NETWORK
                .to_string(),
            asset_id: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_HASH_SUITE.to_string(),
            sealed_intent_scheme: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_SEALED_INTENT_SCHEME
                .to_string(),
            lane_commitment_scheme: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_LANE_COMMITMENT_SCHEME
                .to_string(),
            maker_commitment_scheme:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAKER_COMMITMENT_SCHEME.to_string(),
            atomic_swap_hint_scheme:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_ATOMIC_SWAP_HINT_SCHEME.to_string(),
            privacy_challenge_scheme:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PRIVACY_CHALLENGE_SCHEME.to_string(),
            route_selection_scheme: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_ROUTE_SELECTION_SCHEME
                .to_string(),
            route_ttl_blocks: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_ROUTE_TTL_BLOCKS,
            low_fee_ttl_blocks: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_LOW_FEE_TTL_BLOCKS,
            quote_ttl_blocks: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_QUOTE_TTL_BLOCKS,
            challenge_window_blocks:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_reserve_coverage_bps:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            max_route_fee_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_FEE_BPS,
            low_fee_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_LOW_FEE_BPS,
            fast_fee_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_EMERGENCY_FEE_BPS,
            fee_floor_piconero: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_FEE_FLOOR_PICONERO,
            min_maker_bond_piconero:
                MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MIN_MAKER_BOND_PICONERO,
            max_route_hops: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_ROUTE_HOPS,
            max_lane_load_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_MAX_LANE_LOAD_BPS,
            reserve_stress_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_RESERVE_STRESS_BPS,
            privacy_rebate_bps: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEFAULT_PRIVACY_REBATE_BPS,
        }
    }

    pub fn validate(&self) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_eq(
            &self.protocol_version,
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "protocol version",
        )?;
        ensure_eq(&self.chain_id, CHAIN_ID, "chain id")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.asset_id, "asset id")?;
        ensure_non_empty(&self.fee_asset_id, "fee asset id")?;
        ensure_non_zero(self.route_ttl_blocks, "route ttl blocks")?;
        ensure_non_zero(self.low_fee_ttl_blocks, "low fee ttl blocks")?;
        ensure_non_zero(self.quote_ttl_blocks, "quote ttl blocks")?;
        ensure_non_zero(self.challenge_window_blocks, "challenge window blocks")?;
        ensure_non_zero(self.min_privacy_set_size, "min privacy set size")?;
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set size below minimum".to_string());
        }
        ensure_coverage_bps(self.min_reserve_coverage_bps, "min reserve coverage bps")?;
        ensure_coverage_bps(
            self.target_reserve_coverage_bps,
            "target reserve coverage bps",
        )?;
        ensure_bps(self.max_route_fee_bps, "max route fee bps")?;
        ensure_bps(self.low_fee_bps, "low fee bps")?;
        ensure_bps(self.fast_fee_bps, "fast fee bps")?;
        ensure_bps(self.emergency_fee_bps, "emergency fee bps")?;
        ensure_bps(self.max_lane_load_bps, "max lane load bps")?;
        ensure_bps(self.reserve_stress_bps, "reserve stress bps")?;
        ensure_bps(self.privacy_rebate_bps, "privacy rebate bps")?;
        if self.target_reserve_coverage_bps < self.min_reserve_coverage_bps {
            return Err("target reserve coverage below minimum".to_string());
        }
        if self.low_fee_bps > self.max_route_fee_bps {
            return Err("low fee bps exceeds max route fee bps".to_string());
        }
        if self.fast_fee_bps > self.max_route_fee_bps {
            return Err("fast fee bps exceeds max route fee bps".to_string());
        }
        if self.max_route_hops == 0 {
            return Err("max route hops must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "sealed_intent_scheme": self.sealed_intent_scheme,
            "lane_commitment_scheme": self.lane_commitment_scheme,
            "maker_commitment_scheme": self.maker_commitment_scheme,
            "atomic_swap_hint_scheme": self.atomic_swap_hint_scheme,
            "privacy_challenge_scheme": self.privacy_challenge_scheme,
            "route_selection_scheme": self.route_selection_scheme,
            "route_ttl_blocks": self.route_ttl_blocks,
            "low_fee_ttl_blocks": self.low_fee_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "max_route_fee_bps": self.max_route_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "fee_floor_piconero": self.fee_floor_piconero,
            "min_maker_bond_piconero": self.min_maker_bond_piconero,
            "max_route_hops": self.max_route_hops,
            "max_lane_load_bps": self.max_lane_load_bps,
            "reserve_stress_bps": self.reserve_stress_bps,
            "privacy_rebate_bps": self.privacy_rebate_bps,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiquidityLane {
    pub lane_id: String,
    pub label: String,
    pub kind: ExitLaneKind,
    pub status: LaneStatus,
    pub capacity_piconero: u64,
    pub reserved_piconero: u64,
    pub min_intent_piconero: u64,
    pub max_intent_piconero: u64,
    pub target_privacy_set_size: u64,
    pub fee_bps: u64,
    pub load_shed_bps: u64,
    pub maker_set_root: String,
    pub admission_policy_root: String,
    pub created_at_height: u64,
}

impl LiquidityLane {
    pub fn new(
        label: &str,
        kind: ExitLaneKind,
        capacity_piconero: u64,
        min_intent_piconero: u64,
        max_intent_piconero: u64,
        config: &Config,
        created_at_height: u64,
    ) -> Self {
        let lane_id = lane_id(label, kind, created_at_height);
        let maker_set_root = merkle_root("MONERO-PRIVATE-DEX-LANE-MAKER-SET", &[]);
        let admission_policy_root = payload_root(
            "LANE-ADMISSION-POLICY",
            &json!({
                "label": label,
                "kind": kind.as_str(),
                "min_intent_piconero": min_intent_piconero,
                "max_intent_piconero": max_intent_piconero,
                "min_privacy_set_size": config.min_privacy_set_size,
            }),
        );
        Self {
            lane_id,
            label: label.to_string(),
            kind,
            status: LaneStatus::Open,
            capacity_piconero,
            reserved_piconero: 0,
            min_intent_piconero,
            max_intent_piconero,
            target_privacy_set_size: config.target_privacy_set_size,
            fee_bps: kind.fee_bps(config),
            load_shed_bps: 0,
            maker_set_root,
            admission_policy_root,
            created_at_height,
        }
    }

    pub fn available_piconero(&self) -> u64 {
        self.capacity_piconero
            .saturating_sub(self.reserved_piconero)
    }

    pub fn load_bps(&self) -> u64 {
        if self.capacity_piconero == 0 {
            return MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS;
        }
        self.reserved_piconero
            .saturating_mul(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS)
            / self.capacity_piconero
    }

    pub fn can_accept(&self, amount_piconero: u64, config: &Config) -> bool {
        self.status.accepts_routes()
            && amount_piconero >= self.min_intent_piconero
            && amount_piconero <= self.max_intent_piconero
            && self.available_piconero() >= amount_piconero
            && self.load_bps() <= config.max_lane_load_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "capacity_piconero": self.capacity_piconero,
            "reserved_piconero": self.reserved_piconero,
            "available_piconero": self.available_piconero(),
            "min_intent_piconero": self.min_intent_piconero,
            "max_intent_piconero": self.max_intent_piconero,
            "target_privacy_set_size": self.target_privacy_set_size,
            "fee_bps": self.fee_bps,
            "load_bps": self.load_bps(),
            "load_shed_bps": self.load_shed_bps,
            "maker_set_root": self.maker_set_root,
            "admission_policy_root": self.admission_policy_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn id(&self) -> String {
        self.lane_id.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedExitIntent {
    pub intent_id: String,
    pub owner_commitment: String,
    pub lane_id: String,
    pub status: IntentStatus,
    pub amount_commitment: String,
    pub amount_bucket: String,
    pub destination_commitment: String,
    pub refund_commitment: String,
    pub sealed_payload_root: String,
    pub nullifier: String,
    pub max_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub low_fee_eligible: bool,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl SealedExitIntent {
    pub fn new(
        label: &str,
        owner_commitment: &str,
        lane_id: &str,
        amount_bucket: &str,
        max_fee_bps: u64,
        low_fee_eligible: bool,
        config: &Config,
        height: u64,
    ) -> Self {
        let sealed_payload_root = payload_root(
            "SEALED-INTENT-PAYLOAD",
            &json!({
                "label": label,
                "owner_commitment": owner_commitment,
                "lane_id": lane_id,
                "amount_bucket": amount_bucket,
                "low_fee_eligible": low_fee_eligible,
            }),
        );
        let amount_commitment = commitment_id("amount", label, &sealed_payload_root, height);
        let destination_commitment =
            commitment_id("destination", label, &sealed_payload_root, height);
        let refund_commitment = commitment_id("refund", label, &sealed_payload_root, height);
        let nullifier = domain_hash(
            "MONERO-PRIVATE-DEX-EXIT-INTENT-NULLIFIER",
            &[
                HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(label),
                HashPart::Str(owner_commitment),
                HashPart::Str(&sealed_payload_root),
            ],
            32,
        );
        let ttl = if low_fee_eligible {
            config.low_fee_ttl_blocks
        } else {
            config.route_ttl_blocks
        };
        let intent_id = intent_id(owner_commitment, lane_id, &nullifier, height);
        Self {
            intent_id,
            owner_commitment: owner_commitment.to_string(),
            lane_id: lane_id.to_string(),
            status: IntentStatus::Sealed,
            amount_commitment,
            amount_bucket: amount_bucket.to_string(),
            destination_commitment,
            refund_commitment,
            sealed_payload_root,
            nullifier,
            max_fee_bps,
            min_privacy_set_size: config.min_privacy_set_size,
            low_fee_eligible,
            created_at_height: height,
            expires_at_height: height.saturating_add(ttl),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "owner_commitment": self.owner_commitment,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "amount_commitment": self.amount_commitment,
            "amount_bucket": self.amount_bucket,
            "destination_commitment": self.destination_commitment,
            "refund_commitment": self.refund_commitment,
            "sealed_payload_root": self.sealed_payload_root,
            "nullifier": self.nullifier,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "low_fee_eligible": self.low_fee_eligible,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketMaker {
    pub maker_id: String,
    pub label: String,
    pub status: MakerStatus,
    pub operator_commitment: String,
    pub quote_key_commitment: String,
    pub reserve_account_commitment: String,
    pub bond_piconero: u64,
    pub max_exposure_piconero: u64,
    pub active_exposure_piconero: u64,
    pub reliability_bps: u64,
    pub low_fee_score: u64,
    pub supported_lanes: BTreeSet<String>,
    pub created_at_height: u64,
}

impl MarketMaker {
    pub fn new(
        label: &str,
        lanes: BTreeSet<String>,
        bond_piconero: u64,
        max_exposure_piconero: u64,
        height: u64,
    ) -> Self {
        let maker_id = maker_id(label, &lanes, height);
        Self {
            maker_id: maker_id.clone(),
            label: label.to_string(),
            status: MakerStatus::Active,
            operator_commitment: commitment_id("maker-operator", label, &maker_id, height),
            quote_key_commitment: commitment_id("maker-quote-key", label, &maker_id, height),
            reserve_account_commitment: commitment_id("maker-reserve", label, &maker_id, height),
            bond_piconero,
            max_exposure_piconero,
            active_exposure_piconero: 0,
            reliability_bps: 9_850,
            low_fee_score: 900,
            supported_lanes: lanes,
            created_at_height: height,
        }
    }

    pub fn remaining_exposure_piconero(&self) -> u64 {
        self.max_exposure_piconero
            .saturating_sub(self.active_exposure_piconero)
    }

    pub fn can_quote(&self, lane_id: &str, amount_piconero: u64) -> bool {
        self.status.can_quote()
            && self.supported_lanes.contains(lane_id)
            && self.remaining_exposure_piconero() >= amount_piconero
    }

    pub fn public_record(&self) -> Value {
        json!({
            "maker_id": self.maker_id,
            "label": self.label,
            "status": self.status.as_str(),
            "operator_commitment": self.operator_commitment,
            "quote_key_commitment": self.quote_key_commitment,
            "reserve_account_commitment": self.reserve_account_commitment,
            "bond_piconero": self.bond_piconero,
            "max_exposure_piconero": self.max_exposure_piconero,
            "active_exposure_piconero": self.active_exposure_piconero,
            "remaining_exposure_piconero": self.remaining_exposure_piconero(),
            "reliability_bps": self.reliability_bps,
            "low_fee_score": self.low_fee_score,
            "supported_lanes": self.supported_lanes.iter().cloned().collect::<Vec<_>>(),
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MakerLiquidityCommitment {
    pub commitment_id: String,
    pub maker_id: String,
    pub lane_id: String,
    pub status: CommitmentStatus,
    pub reserve_commitment: String,
    pub capacity_piconero: u64,
    pub allocated_piconero: u64,
    pub min_fill_piconero: u64,
    pub quote_fee_bps: u64,
    pub reserve_proof_root: String,
    pub pq_attestation_root: String,
    pub published_at_height: u64,
    pub expires_at_height: u64,
}

impl MakerLiquidityCommitment {
    pub fn new(
        maker_id: &str,
        lane_id: &str,
        capacity_piconero: u64,
        min_fill_piconero: u64,
        quote_fee_bps: u64,
        config: &Config,
        height: u64,
    ) -> Self {
        let reserve_commitment = payload_root(
            "MAKER-RESERVE-COMMITMENT",
            &json!({
                "maker_id": maker_id,
                "lane_id": lane_id,
                "capacity_piconero": capacity_piconero,
                "height": height,
            }),
        );
        let commitment_id = liquidity_commitment_id(maker_id, lane_id, &reserve_commitment, height);
        let reserve_proof_root = payload_root(
            "MAKER-RESERVE-PROOF",
            &json!({
                "commitment_id": commitment_id,
                "reserve_commitment": reserve_commitment,
                "coverage_bps": config.target_reserve_coverage_bps,
            }),
        );
        let pq_attestation_root = payload_root(
            "MAKER-PQ-ATTESTATION",
            &json!({
                "commitment_id": commitment_id,
                "scheme": config.maker_commitment_scheme,
                "height": height,
            }),
        );
        Self {
            commitment_id,
            maker_id: maker_id.to_string(),
            lane_id: lane_id.to_string(),
            status: CommitmentStatus::QuoteOpen,
            reserve_commitment,
            capacity_piconero,
            allocated_piconero: 0,
            min_fill_piconero,
            quote_fee_bps,
            reserve_proof_root,
            pq_attestation_root,
            published_at_height: height,
            expires_at_height: height.saturating_add(config.quote_ttl_blocks),
        }
    }

    pub fn available_piconero(&self) -> u64 {
        self.capacity_piconero
            .saturating_sub(self.allocated_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "maker_id": self.maker_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "reserve_commitment": self.reserve_commitment,
            "capacity_piconero": self.capacity_piconero,
            "allocated_piconero": self.allocated_piconero,
            "available_piconero": self.available_piconero(),
            "min_fill_piconero": self.min_fill_piconero,
            "quote_fee_bps": self.quote_fee_bps,
            "reserve_proof_root": self.reserve_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "published_at_height": self.published_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitQuote {
    pub quote_id: String,
    pub intent_id: String,
    pub maker_id: String,
    pub commitment_id: String,
    pub lane_id: String,
    pub status: QuoteStatus,
    pub amount_piconero: u64,
    pub fee_piconero: u64,
    pub fee_bps: u64,
    pub privacy_rebate_piconero: u64,
    pub settlement_hint_root: String,
    pub valid_until_height: u64,
    pub created_at_height: u64,
}

impl ExitQuote {
    pub fn new(
        intent: &SealedExitIntent,
        maker_id: &str,
        commitment_id: &str,
        amount_piconero: u64,
        fee_bps: u64,
        config: &Config,
        height: u64,
    ) -> Self {
        let raw_fee = amount_piconero.saturating_mul(fee_bps)
            / MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS;
        let fee_piconero = raw_fee.max(config.fee_floor_piconero);
        let privacy_rebate_piconero = if intent.low_fee_eligible {
            fee_piconero.saturating_mul(config.privacy_rebate_bps)
                / MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS
        } else {
            0
        };
        let settlement_hint_root = payload_root(
            "QUOTE-SETTLEMENT-HINTS",
            &json!({
                "intent_id": intent.intent_id,
                "maker_id": maker_id,
                "commitment_id": commitment_id,
                "amount_piconero": amount_piconero,
                "fee_bps": fee_bps,
            }),
        );
        let quote_id = quote_id(
            &intent.intent_id,
            maker_id,
            commitment_id,
            &settlement_hint_root,
        );
        Self {
            quote_id,
            intent_id: intent.intent_id.clone(),
            maker_id: maker_id.to_string(),
            commitment_id: commitment_id.to_string(),
            lane_id: intent.lane_id.clone(),
            status: QuoteStatus::Open,
            amount_piconero,
            fee_piconero,
            fee_bps,
            privacy_rebate_piconero,
            settlement_hint_root,
            valid_until_height: height.saturating_add(config.quote_ttl_blocks),
            created_at_height: height,
        }
    }

    pub fn effective_fee_piconero(&self) -> u64 {
        self.fee_piconero
            .saturating_sub(self.privacy_rebate_piconero)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "intent_id": self.intent_id,
            "maker_id": self.maker_id,
            "commitment_id": self.commitment_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "amount_piconero": self.amount_piconero,
            "fee_piconero": self.fee_piconero,
            "fee_bps": self.fee_bps,
            "privacy_rebate_piconero": self.privacy_rebate_piconero,
            "effective_fee_piconero": self.effective_fee_piconero(),
            "settlement_hint_root": self.settlement_hint_root,
            "valid_until_height": self.valid_until_height,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveRiskSnapshot {
    pub snapshot_id: String,
    pub maker_id: String,
    pub lane_id: String,
    pub reserve_commitment_root: String,
    pub committed_piconero: u64,
    pub outstanding_piconero: u64,
    pub stressed_outstanding_piconero: u64,
    pub coverage_bps: u64,
    pub stress_bps: u64,
    pub risk_score_bps: u64,
    pub measured_at_height: u64,
}

impl ReserveRiskSnapshot {
    pub fn new(
        maker_id: &str,
        lane_id: &str,
        reserve_commitment_root: &str,
        committed_piconero: u64,
        outstanding_piconero: u64,
        config: &Config,
        height: u64,
    ) -> Self {
        let stressed_outstanding_piconero = outstanding_piconero.saturating_mul(
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS
                .saturating_add(config.reserve_stress_bps),
        ) / MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS;
        let coverage_bps = coverage_bps(committed_piconero, stressed_outstanding_piconero);
        let shortfall = config
            .target_reserve_coverage_bps
            .saturating_sub(coverage_bps);
        let risk_score_bps = MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS
            .saturating_sub(shortfall.min(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS));
        let snapshot_id = risk_snapshot_id(maker_id, lane_id, reserve_commitment_root, height);
        Self {
            snapshot_id,
            maker_id: maker_id.to_string(),
            lane_id: lane_id.to_string(),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            committed_piconero,
            outstanding_piconero,
            stressed_outstanding_piconero,
            coverage_bps,
            stress_bps: config.reserve_stress_bps,
            risk_score_bps,
            measured_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "maker_id": self.maker_id,
            "lane_id": self.lane_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "committed_piconero": self.committed_piconero,
            "outstanding_piconero": self.outstanding_piconero,
            "stressed_outstanding_piconero": self.stressed_outstanding_piconero,
            "coverage_bps": self.coverage_bps,
            "stress_bps": self.stress_bps,
            "risk_score_bps": self.risk_score_bps,
            "measured_at_height": self.measured_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSelection {
    pub route_id: String,
    pub intent_id: String,
    pub lane_id: String,
    pub status: RouteStatus,
    pub selected_quote_ids: Vec<String>,
    pub maker_ids: BTreeSet<String>,
    pub total_amount_piconero: u64,
    pub total_fee_piconero: u64,
    pub effective_fee_piconero: u64,
    pub weighted_risk_bps: u64,
    pub privacy_score: u64,
    pub route_score: u64,
    pub decision_root: String,
    pub selected_at_height: u64,
    pub expires_at_height: u64,
}

impl RouteSelection {
    pub fn from_quotes(
        intent_id: &str,
        lane: &LiquidityLane,
        quotes: &[ExitQuote],
        risks: &BTreeMap<String, ReserveRiskSnapshot>,
        config: &Config,
        height: u64,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<Self> {
        if quotes.is_empty() {
            return Err("route selection requires at least one quote".to_string());
        }
        if quotes.len() > config.max_route_hops {
            return Err("route selection exceeds max route hops".to_string());
        }
        let mut selected_quote_ids = Vec::new();
        let mut maker_ids = BTreeSet::new();
        let mut total_amount_piconero = 0_u64;
        let mut total_fee_piconero = 0_u64;
        let mut effective_fee_piconero = 0_u64;
        let mut weighted_risk_acc = 0_u64;
        for quote in quotes {
            selected_quote_ids.push(quote.quote_id.clone());
            maker_ids.insert(quote.maker_id.clone());
            total_amount_piconero = total_amount_piconero.saturating_add(quote.amount_piconero);
            total_fee_piconero = total_fee_piconero.saturating_add(quote.fee_piconero);
            effective_fee_piconero =
                effective_fee_piconero.saturating_add(quote.effective_fee_piconero());
            let risk_score = risks
                .values()
                .find(|snapshot| snapshot.maker_id == quote.maker_id)
                .map(|snapshot| snapshot.risk_score_bps)
                .unwrap_or(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS / 2);
            weighted_risk_acc = weighted_risk_acc
                .saturating_add(risk_score.saturating_mul(quote.amount_piconero.max(1)));
        }
        let weighted_risk_bps = if total_amount_piconero == 0 {
            0
        } else {
            weighted_risk_acc / total_amount_piconero
        };
        let privacy_score = lane.kind.privacy_weight().saturating_mul(
            lane.target_privacy_set_size
                .min(config.target_privacy_set_size),
        ) / config.target_privacy_set_size.max(1);
        let fee_penalty = if total_amount_piconero == 0 {
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS
        } else {
            effective_fee_piconero.saturating_mul(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS)
                / total_amount_piconero
        };
        let route_score = privacy_score
            .saturating_add(weighted_risk_bps / 16)
            .saturating_sub(fee_penalty.min(privacy_score));
        let decision_root = payload_root(
            "LOW-FEE-ROUTE-SELECTION",
            &json!({
                "intent_id": intent_id,
                "lane_id": lane.lane_id,
                "quote_ids": selected_quote_ids,
                "maker_ids": maker_ids.iter().cloned().collect::<Vec<_>>(),
                "total_amount_piconero": total_amount_piconero,
                "effective_fee_piconero": effective_fee_piconero,
                "weighted_risk_bps": weighted_risk_bps,
                "privacy_score": privacy_score,
                "route_score": route_score,
            }),
        );
        let route_id = route_id(intent_id, &lane.lane_id, &decision_root, height);
        Ok(Self {
            route_id,
            intent_id: intent_id.to_string(),
            lane_id: lane.lane_id.clone(),
            status: RouteStatus::Selected,
            selected_quote_ids,
            maker_ids,
            total_amount_piconero,
            total_fee_piconero,
            effective_fee_piconero,
            weighted_risk_bps,
            privacy_score,
            route_score,
            decision_root,
            selected_at_height: height,
            expires_at_height: height.saturating_add(config.route_ttl_blocks),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "selected_quote_ids": self.selected_quote_ids,
            "maker_ids": self.maker_ids.iter().cloned().collect::<Vec<_>>(),
            "total_amount_piconero": self.total_amount_piconero,
            "total_fee_piconero": self.total_fee_piconero,
            "effective_fee_piconero": self.effective_fee_piconero,
            "weighted_risk_bps": self.weighted_risk_bps,
            "privacy_score": self.privacy_score,
            "route_score": self.route_score,
            "decision_root": self.decision_root,
            "selected_at_height": self.selected_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AtomicSwapSettlementHint {
    pub hint_id: String,
    pub route_id: String,
    pub intent_id: String,
    pub swap_contract_commitment: String,
    pub monero_lock_commitment: String,
    pub adaptor_signature_root: String,
    pub refund_path_commitment: String,
    pub timeout_height: u64,
    pub settlement_policy_root: String,
    pub published_at_height: u64,
}

impl AtomicSwapSettlementHint {
    pub fn new(route: &RouteSelection, config: &Config, height: u64) -> Self {
        let swap_contract_commitment = commitment_id(
            "swap-contract",
            &route.route_id,
            &route.decision_root,
            height,
        );
        let monero_lock_commitment =
            commitment_id("monero-lock", &route.route_id, &route.decision_root, height);
        let adaptor_signature_root = payload_root(
            "ATOMIC-SWAP-ADAPTOR-SIGNATURE",
            &json!({
                "route_id": route.route_id,
                "intent_id": route.intent_id,
                "scheme": config.atomic_swap_hint_scheme,
            }),
        );
        let refund_path_commitment = commitment_id(
            "refund-path",
            &route.route_id,
            &adaptor_signature_root,
            height,
        );
        let settlement_policy_root = payload_root(
            "ATOMIC-SWAP-SETTLEMENT-POLICY",
            &json!({
                "route_id": route.route_id,
                "challenge_window_blocks": config.challenge_window_blocks,
                "max_route_hops": config.max_route_hops,
            }),
        );
        let hint_id = swap_hint_id(
            &route.route_id,
            &swap_contract_commitment,
            &settlement_policy_root,
        );
        Self {
            hint_id,
            route_id: route.route_id.clone(),
            intent_id: route.intent_id.clone(),
            swap_contract_commitment,
            monero_lock_commitment,
            adaptor_signature_root,
            refund_path_commitment,
            timeout_height: height.saturating_add(config.challenge_window_blocks),
            settlement_policy_root,
            published_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "route_id": self.route_id,
            "intent_id": self.intent_id,
            "swap_contract_commitment": self.swap_contract_commitment,
            "monero_lock_commitment": self.monero_lock_commitment,
            "adaptor_signature_root": self.adaptor_signature_root,
            "refund_path_commitment": self.refund_path_commitment,
            "timeout_height": self.timeout_height,
            "settlement_policy_root": self.settlement_policy_root,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivacyChallengeReceipt {
    pub receipt_id: String,
    pub challenge_id: String,
    pub related_object_id: String,
    pub challenger_commitment: String,
    pub status: ChallengeStatus,
    pub claim_root: String,
    pub evidence_root: String,
    pub response_root: String,
    pub filed_at_height: u64,
    pub response_due_height: u64,
}

impl PrivacyChallengeReceipt {
    pub fn new(
        related_object_id: &str,
        challenger_commitment: &str,
        claim_kind: &str,
        config: &Config,
        height: u64,
    ) -> Self {
        let claim_root = payload_root(
            "PRIVACY-CHALLENGE-CLAIM",
            &json!({
                "related_object_id": related_object_id,
                "challenger_commitment": challenger_commitment,
                "claim_kind": claim_kind,
                "scheme": config.privacy_challenge_scheme,
            }),
        );
        let challenge_id = challenge_id(
            related_object_id,
            challenger_commitment,
            &claim_root,
            height,
        );
        let evidence_root = merkle_root("PRIVACY-CHALLENGE-EVIDENCE", &[]);
        let response_root = payload_root(
            "PRIVACY-CHALLENGE-EMPTY-RESPONSE",
            &json!({
                "challenge_id": challenge_id,
                "status": ChallengeStatus::Filed.as_str(),
            }),
        );
        let receipt_id = receipt_id(&challenge_id, related_object_id, &response_root);
        Self {
            receipt_id,
            challenge_id,
            related_object_id: related_object_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            status: ChallengeStatus::Filed,
            claim_root,
            evidence_root,
            response_root,
            filed_at_height: height,
            response_due_height: height.saturating_add(config.challenge_window_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "challenge_id": self.challenge_id,
            "related_object_id": self.related_object_id,
            "challenger_commitment": self.challenger_commitment,
            "status": self.status.as_str(),
            "claim_root": self.claim_root,
            "evidence_root": self.evidence_root,
            "response_root": self.response_root,
            "filed_at_height": self.filed_at_height,
            "response_due_height": self.response_due_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterEvent {
    pub event_id: String,
    pub kind: String,
    pub object_id: String,
    pub object_root: String,
    pub height: u64,
}

impl RouterEvent {
    pub fn new(kind: &str, object_id: &str, object_root: &str, height: u64) -> Self {
        Self {
            event_id: event_id(kind, object_id, object_root, height),
            kind: kind.to_string(),
            object_id: object_id.to_string(),
            object_root: object_root.to_string(),
            height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "kind": self.kind,
            "object_id": self.object_id,
            "object_root": self.object_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub sealed_intent_root: String,
    pub maker_root: String,
    pub liquidity_commitment_root: String,
    pub quote_root: String,
    pub route_root: String,
    pub atomic_swap_hint_root: String,
    pub reserve_risk_root: String,
    pub privacy_challenge_receipt_root: String,
    pub event_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "sealed_intent_root": self.sealed_intent_root,
            "maker_root": self.maker_root,
            "liquidity_commitment_root": self.liquidity_commitment_root,
            "quote_root": self.quote_root,
            "route_root": self.route_root,
            "atomic_swap_hint_root": self.atomic_swap_hint_root,
            "reserve_risk_root": self.reserve_risk_root,
            "privacy_challenge_receipt_root": self.privacy_challenge_receipt_root,
            "event_root": self.event_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub lanes: usize,
    pub sealed_intents: usize,
    pub live_intents: usize,
    pub makers: usize,
    pub active_makers: usize,
    pub liquidity_commitments: usize,
    pub open_commitments: usize,
    pub quotes: usize,
    pub selectable_quotes: usize,
    pub routes: usize,
    pub swap_hints: usize,
    pub reserve_risk_snapshots: usize,
    pub privacy_challenge_receipts: usize,
    pub open_challenges: usize,
    pub events: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lanes": self.lanes,
            "sealed_intents": self.sealed_intents,
            "live_intents": self.live_intents,
            "makers": self.makers,
            "active_makers": self.active_makers,
            "liquidity_commitments": self.liquidity_commitments,
            "open_commitments": self.open_commitments,
            "quotes": self.quotes,
            "selectable_quotes": self.selectable_quotes,
            "routes": self.routes,
            "swap_hints": self.swap_hints,
            "reserve_risk_snapshots": self.reserve_risk_snapshots,
            "privacy_challenge_receipts": self.privacy_challenge_receipts,
            "open_challenges": self.open_challenges,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub lanes: BTreeMap<String, LiquidityLane>,
    pub sealed_intents: BTreeMap<String, SealedExitIntent>,
    pub market_makers: BTreeMap<String, MarketMaker>,
    pub liquidity_commitments: BTreeMap<String, MakerLiquidityCommitment>,
    pub quotes: BTreeMap<String, ExitQuote>,
    pub routes: BTreeMap<String, RouteSelection>,
    pub atomic_swap_hints: BTreeMap<String, AtomicSwapSettlementHint>,
    pub reserve_risk_snapshots: BTreeMap<String, ReserveRiskSnapshot>,
    pub privacy_challenge_receipts: BTreeMap<String, PrivacyChallengeReceipt>,
    pub events: BTreeMap<String, RouterEvent>,
}

impl State {
    pub fn devnet() -> MoneroPrivateDexExitLiquidityRouterResult<State> {
        let config = Config::devnet();
        config.validate()?;
        let mut state = Self {
            height: MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_DEVNET_HEIGHT,
            config,
            lanes: BTreeMap::new(),
            sealed_intents: BTreeMap::new(),
            market_makers: BTreeMap::new(),
            liquidity_commitments: BTreeMap::new(),
            quotes: BTreeMap::new(),
            routes: BTreeMap::new(),
            atomic_swap_hints: BTreeMap::new(),
            reserve_risk_snapshots: BTreeMap::new(),
            privacy_challenge_receipts: BTreeMap::new(),
            events: BTreeMap::new(),
        };
        state.install_devnet_lanes()?;
        state.install_devnet_makers_and_commitments()?;
        state.install_devnet_intents_quotes_and_routes()?;
        state.install_devnet_challenge_receipt()?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        self.config.validate()?;
        ensure_limit(
            self.lanes.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_LANES,
            "lanes",
        )?;
        ensure_limit(
            self.sealed_intents.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_INTENTS,
            "sealed intents",
        )?;
        ensure_limit(
            self.market_makers.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_MAKERS,
            "market makers",
        )?;
        ensure_limit(
            self.liquidity_commitments.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_COMMITMENTS,
            "liquidity commitments",
        )?;
        ensure_limit(
            self.quotes.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_QUOTES,
            "quotes",
        )?;
        ensure_limit(
            self.routes.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_ROUTES,
            "routes",
        )?;
        ensure_limit(
            self.atomic_swap_hints.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_SWAP_HINTS,
            "atomic swap hints",
        )?;
        ensure_limit(
            self.reserve_risk_snapshots.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_RISK_SNAPSHOTS,
            "reserve risk snapshots",
        )?;
        ensure_limit(
            self.privacy_challenge_receipts.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_RECEIPTS,
            "privacy challenge receipts",
        )?;
        ensure_limit(
            self.events.len(),
            MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_EVENTS,
            "events",
        )?;
        let mut nullifiers = BTreeSet::new();
        for (lane_id, lane) in &self.lanes {
            ensure_eq(lane_id, &lane.lane_id, "lane map key")?;
            lane.validate(&self.config)?;
        }
        for (maker_id, maker) in &self.market_makers {
            ensure_eq(maker_id, &maker.maker_id, "maker map key")?;
            maker.validate(&self.config, &self.lanes)?;
        }
        for (intent_id, intent) in &self.sealed_intents {
            ensure_eq(intent_id, &intent.intent_id, "sealed intent map key")?;
            intent.validate(&self.config, &self.lanes)?;
            if !nullifiers.insert(intent.nullifier.clone()) {
                return Err("duplicate sealed intent nullifier".to_string());
            }
        }
        for (commitment_id, commitment) in &self.liquidity_commitments {
            ensure_eq(
                commitment_id,
                &commitment.commitment_id,
                "liquidity commitment map key",
            )?;
            commitment.validate(&self.config, &self.lanes, &self.market_makers)?;
        }
        for (quote_id, quote) in &self.quotes {
            ensure_eq(quote_id, &quote.quote_id, "quote map key")?;
            quote.validate(
                &self.config,
                &self.sealed_intents,
                &self.liquidity_commitments,
            )?;
        }
        for (route_id, route) in &self.routes {
            ensure_eq(route_id, &route.route_id, "route map key")?;
            route.validate(
                &self.config,
                &self.sealed_intents,
                &self.lanes,
                &self.quotes,
            )?;
        }
        for (hint_id, hint) in &self.atomic_swap_hints {
            ensure_eq(hint_id, &hint.hint_id, "atomic swap hint map key")?;
            hint.validate(&self.routes)?;
        }
        for (snapshot_id, snapshot) in &self.reserve_risk_snapshots {
            ensure_eq(snapshot_id, &snapshot.snapshot_id, "risk snapshot map key")?;
            snapshot.validate(&self.market_makers, &self.lanes)?;
        }
        for (receipt_id, receipt) in &self.privacy_challenge_receipts {
            ensure_eq(
                receipt_id,
                &receipt.receipt_id,
                "privacy challenge receipt map key",
            )?;
            receipt.validate()?;
        }
        for (event_id, event) in &self.events {
            ensure_eq(event_id, &event.event_id, "event map key")?;
            ensure_non_empty(&event.kind, "event kind")?;
            ensure_non_empty(&event.object_id, "event object id")?;
            ensure_hash(&event.object_root, "event object root")?;
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        if height < self.height {
            return Err("height cannot move backwards".to_string());
        }
        self.height = height;
        self.refresh_expirations();
        self.validate()
    }

    pub fn roots(&self) -> Roots {
        let config_root = self.config.root();
        let lane_root = map_root("MONERO-PRIVATE-DEX-LIQUIDITY-LANE", &self.lanes);
        let sealed_intent_root = map_root(
            "MONERO-PRIVATE-DEX-SEALED-EXIT-INTENT",
            &self.sealed_intents,
        );
        let maker_root = map_root("MONERO-PRIVATE-DEX-MARKET-MAKER", &self.market_makers);
        let liquidity_commitment_root = map_root(
            "MONERO-PRIVATE-DEX-MAKER-LIQUIDITY-COMMITMENT",
            &self.liquidity_commitments,
        );
        let quote_root = map_root("MONERO-PRIVATE-DEX-EXIT-QUOTE", &self.quotes);
        let route_root = map_root("MONERO-PRIVATE-DEX-ROUTE-SELECTION", &self.routes);
        let atomic_swap_hint_root = map_root(
            "MONERO-PRIVATE-DEX-ATOMIC-SWAP-HINT",
            &self.atomic_swap_hints,
        );
        let reserve_risk_root = map_root(
            "MONERO-PRIVATE-DEX-RESERVE-RISK",
            &self.reserve_risk_snapshots,
        );
        let privacy_challenge_receipt_root = map_root(
            "MONERO-PRIVATE-DEX-PRIVACY-CHALLENGE-RECEIPT",
            &self.privacy_challenge_receipts,
        );
        let event_root = map_root("MONERO-PRIVATE-DEX-ROUTER-EVENT", &self.events);
        let state_root = domain_hash(
            "MONERO-PRIVATE-DEX-EXIT-LIQUIDITY-ROUTER-STATE",
            &[
                HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.height as i128),
                HashPart::Str(&config_root),
                HashPart::Str(&lane_root),
                HashPart::Str(&sealed_intent_root),
                HashPart::Str(&maker_root),
                HashPart::Str(&liquidity_commitment_root),
                HashPart::Str(&quote_root),
                HashPart::Str(&route_root),
                HashPart::Str(&atomic_swap_hint_root),
                HashPart::Str(&reserve_risk_root),
                HashPart::Str(&privacy_challenge_receipt_root),
                HashPart::Str(&event_root),
            ],
            32,
        );
        Roots {
            config_root,
            lane_root,
            sealed_intent_root,
            maker_root,
            liquidity_commitment_root,
            quote_root,
            route_root,
            atomic_swap_hint_root,
            reserve_risk_root,
            privacy_challenge_receipt_root,
            event_root,
            state_root,
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            lanes: self.lanes.len(),
            sealed_intents: self.sealed_intents.len(),
            live_intents: self
                .sealed_intents
                .values()
                .filter(|intent| intent.status.live())
                .count(),
            makers: self.market_makers.len(),
            active_makers: self
                .market_makers
                .values()
                .filter(|maker| maker.status.can_quote())
                .count(),
            liquidity_commitments: self.liquidity_commitments.len(),
            open_commitments: self
                .liquidity_commitments
                .values()
                .filter(|commitment| commitment.status.available())
                .count(),
            quotes: self.quotes.len(),
            selectable_quotes: self
                .quotes
                .values()
                .filter(|quote| quote.status.selectable())
                .count(),
            routes: self.routes.len(),
            swap_hints: self.atomic_swap_hints.len(),
            reserve_risk_snapshots: self.reserve_risk_snapshots.len(),
            privacy_challenge_receipts: self.privacy_challenge_receipts.len(),
            open_challenges: self
                .privacy_challenge_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        ChallengeStatus::Filed
                            | ChallengeStatus::EvidenceOpen
                            | ChallengeStatus::Proving
                    )
                })
                .count(),
            events: self.events.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "lanes": self.lanes.values().map(LiquidityLane::public_record).collect::<Vec<_>>(),
            "sealed_intents": self.sealed_intents.values().map(SealedExitIntent::public_record).collect::<Vec<_>>(),
            "market_makers": self.market_makers.values().map(MarketMaker::public_record).collect::<Vec<_>>(),
            "liquidity_commitments": self.liquidity_commitments.values().map(MakerLiquidityCommitment::public_record).collect::<Vec<_>>(),
            "quotes": self.quotes.values().map(ExitQuote::public_record).collect::<Vec<_>>(),
            "routes": self.routes.values().map(RouteSelection::public_record).collect::<Vec<_>>(),
            "atomic_swap_hints": self.atomic_swap_hints.values().map(AtomicSwapSettlementHint::public_record).collect::<Vec<_>>(),
            "reserve_risk_snapshots": self.reserve_risk_snapshots.values().map(ReserveRiskSnapshot::public_record).collect::<Vec<_>>(),
            "privacy_challenge_receipts": self.privacy_challenge_receipts.values().map(PrivacyChallengeReceipt::public_record).collect::<Vec<_>>(),
            "events": self.events.values().map(RouterEvent::public_record).collect::<Vec<_>>(),
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn add_lane(
        &mut self,
        lane: LiquidityLane,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        lane.validate(&self.config)?;
        if self.lanes.contains_key(&lane.lane_id) {
            return Err("lane already exists".to_string());
        }
        let lane_id = lane.lane_id.clone();
        let object_root = payload_root("LANE", &lane.public_record());
        self.lanes.insert(lane_id.clone(), lane);
        self.record_event("lane_added", &lane_id, &object_root);
        Ok(lane_id)
    }

    pub fn add_market_maker(
        &mut self,
        maker: MarketMaker,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        maker.validate(&self.config, &self.lanes)?;
        if self.market_makers.contains_key(&maker.maker_id) {
            return Err("market maker already exists".to_string());
        }
        let maker_id = maker.maker_id.clone();
        let object_root = payload_root("MARKET-MAKER", &maker.public_record());
        self.market_makers.insert(maker_id.clone(), maker);
        self.record_event("maker_added", &maker_id, &object_root);
        Ok(maker_id)
    }

    pub fn add_sealed_intent(
        &mut self,
        intent: SealedExitIntent,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        intent.validate(&self.config, &self.lanes)?;
        if self.sealed_intents.contains_key(&intent.intent_id) {
            return Err("sealed intent already exists".to_string());
        }
        if self
            .sealed_intents
            .values()
            .any(|existing| existing.nullifier == intent.nullifier)
        {
            return Err("sealed intent nullifier already exists".to_string());
        }
        let intent_id = intent.intent_id.clone();
        let object_root = payload_root("SEALED-INTENT", &intent.public_record());
        self.sealed_intents.insert(intent_id.clone(), intent);
        self.record_event("sealed_intent_added", &intent_id, &object_root);
        Ok(intent_id)
    }

    pub fn add_liquidity_commitment(
        &mut self,
        commitment: MakerLiquidityCommitment,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        commitment.validate(&self.config, &self.lanes, &self.market_makers)?;
        if self
            .liquidity_commitments
            .contains_key(&commitment.commitment_id)
        {
            return Err("liquidity commitment already exists".to_string());
        }
        let commitment_id = commitment.commitment_id.clone();
        let object_root = payload_root("LIQUIDITY-COMMITMENT", &commitment.public_record());
        self.liquidity_commitments
            .insert(commitment_id.clone(), commitment);
        self.record_event("liquidity_commitment_added", &commitment_id, &object_root);
        Ok(commitment_id)
    }

    pub fn add_quote(
        &mut self,
        quote: ExitQuote,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        quote.validate(
            &self.config,
            &self.sealed_intents,
            &self.liquidity_commitments,
        )?;
        if self.quotes.contains_key(&quote.quote_id) {
            return Err("quote already exists".to_string());
        }
        let quote_id = quote.quote_id.clone();
        let object_root = payload_root("EXIT-QUOTE", &quote.public_record());
        self.quotes.insert(quote_id.clone(), quote);
        self.record_event("quote_added", &quote_id, &object_root);
        Ok(quote_id)
    }

    pub fn select_low_fee_route(
        &mut self,
        intent_id: &str,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        let intent = self
            .sealed_intents
            .get(intent_id)
            .ok_or_else(|| "sealed intent not found".to_string())?;
        let lane = self
            .lanes
            .get(&intent.lane_id)
            .ok_or_else(|| "intent lane not found".to_string())?;
        let mut eligible_quotes = self
            .quotes
            .values()
            .filter(|quote| quote.intent_id == intent_id && quote.status.selectable())
            .cloned()
            .collect::<Vec<_>>();
        eligible_quotes.sort_by(|left, right| {
            left.effective_fee_piconero()
                .cmp(&right.effective_fee_piconero())
                .then(left.fee_bps.cmp(&right.fee_bps))
                .then(left.quote_id.cmp(&right.quote_id))
        });
        let selected_quotes = eligible_quotes
            .into_iter()
            .take(self.config.max_route_hops)
            .collect::<Vec<_>>();
        let route = RouteSelection::from_quotes(
            intent_id,
            lane,
            &selected_quotes,
            &self.reserve_risk_snapshots,
            &self.config,
            self.height,
        )?;
        let route_id = route.route_id.clone();
        let object_root = payload_root("ROUTE-SELECTION", &route.public_record());
        self.routes.insert(route_id.clone(), route);
        self.record_event("low_fee_route_selected", &route_id, &object_root);
        Ok(route_id)
    }

    pub fn publish_atomic_swap_hint(
        &mut self,
        route_id: &str,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        let route = self
            .routes
            .get(route_id)
            .ok_or_else(|| "route not found".to_string())?
            .clone();
        let hint = AtomicSwapSettlementHint::new(&route, &self.config, self.height);
        let hint_id = hint.hint_id.clone();
        let object_root = payload_root("ATOMIC-SWAP-HINT", &hint.public_record());
        self.atomic_swap_hints.insert(hint_id.clone(), hint);
        self.record_event("atomic_swap_hint_published", &hint_id, &object_root);
        Ok(hint_id)
    }

    pub fn file_privacy_challenge(
        &mut self,
        related_object_id: &str,
        challenger_commitment: &str,
        claim_kind: &str,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<String> {
        let receipt = PrivacyChallengeReceipt::new(
            related_object_id,
            challenger_commitment,
            claim_kind,
            &self.config,
            self.height,
        );
        receipt.validate()?;
        let receipt_id = receipt.receipt_id.clone();
        let object_root = payload_root("PRIVACY-CHALLENGE-RECEIPT", &receipt.public_record());
        self.privacy_challenge_receipts
            .insert(receipt_id.clone(), receipt);
        self.record_event("privacy_challenge_filed", &receipt_id, &object_root);
        Ok(receipt_id)
    }

    fn refresh_expirations(&mut self) {
        for intent in self.sealed_intents.values_mut() {
            if intent.status.live() && self.height > intent.expires_at_height {
                intent.status = IntentStatus::Expired;
            }
        }
        for commitment in self.liquidity_commitments.values_mut() {
            if commitment.status.available() && self.height > commitment.expires_at_height {
                commitment.status = CommitmentStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if quote.status.selectable() && self.height > quote.valid_until_height {
                quote.status = QuoteStatus::Expired;
            }
        }
        for route in self.routes.values_mut() {
            if matches!(route.status, RouteStatus::Candidate | RouteStatus::Selected)
                && self.height > route.expires_at_height
            {
                route.status = RouteStatus::Expired;
            }
        }
        for receipt in self.privacy_challenge_receipts.values_mut() {
            if matches!(
                receipt.status,
                ChallengeStatus::Filed | ChallengeStatus::EvidenceOpen | ChallengeStatus::Proving
            ) && self.height > receipt.response_due_height
            {
                receipt.status = ChallengeStatus::Expired;
            }
        }
    }

    fn install_devnet_lanes(&mut self) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        let lanes = [
            (
                "devnet-low-fee-xmr-exit",
                ExitLaneKind::LowFee,
                48_000_000_000_000_u64,
                100_000_000,
                4_000_000_000_000_u64,
            ),
            (
                "devnet-standard-xmr-exit",
                ExitLaneKind::Standard,
                96_000_000_000_000_u64,
                500_000_000,
                8_000_000_000_000_u64,
            ),
            (
                "devnet-fast-xmr-exit",
                ExitLaneKind::Fast,
                32_000_000_000_000_u64,
                250_000_000,
                3_000_000_000_000_u64,
            ),
            (
                "devnet-stablecoin-bridge",
                ExitLaneKind::StablecoinBridge,
                64_000_000_000_000_u64,
                500_000_000,
                6_000_000_000_000_u64,
            ),
            (
                "devnet-wallet-recovery",
                ExitLaneKind::WalletRecovery,
                12_000_000_000_000_u64,
                10_000_000,
                1_000_000_000_000_u64,
            ),
        ];
        for (label, kind, capacity, min_intent, max_intent) in lanes {
            let lane = LiquidityLane::new(
                label,
                kind,
                capacity,
                min_intent,
                max_intent,
                &self.config,
                self.height,
            );
            self.add_lane(lane)?;
        }
        Ok(())
    }

    fn install_devnet_makers_and_commitments(
        &mut self,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        let lane_ids = self.lanes.keys().cloned().collect::<BTreeSet<_>>();
        let maker_a = MarketMaker::new(
            "devnet-maker-north",
            lane_ids.clone(),
            self.config.min_maker_bond_piconero.saturating_mul(4),
            40_000_000_000_000,
            self.height,
        );
        let maker_b = MarketMaker::new(
            "devnet-maker-south",
            lane_ids.clone(),
            self.config.min_maker_bond_piconero.saturating_mul(3),
            28_000_000_000_000,
            self.height,
        );
        let maker_c = MarketMaker::new(
            "devnet-maker-low-fee",
            lane_ids,
            self.config.min_maker_bond_piconero.saturating_mul(5),
            52_000_000_000_000,
            self.height,
        );
        let maker_ids = [
            self.add_market_maker(maker_a)?,
            self.add_market_maker(maker_b)?,
            self.add_market_maker(maker_c)?,
        ];
        let mut planned = Vec::new();
        for maker_id in maker_ids {
            for lane in self.lanes.values() {
                let fee_bps = lane
                    .fee_bps
                    .saturating_add(if maker_id.contains("low-fee") { 0 } else { 4 });
                planned.push(MakerLiquidityCommitment::new(
                    &maker_id,
                    &lane.lane_id,
                    lane.capacity_piconero / 8,
                    lane.min_intent_piconero,
                    fee_bps,
                    &self.config,
                    self.height,
                ));
            }
        }
        for commitment in planned {
            let snapshot = ReserveRiskSnapshot::new(
                &commitment.maker_id,
                &commitment.lane_id,
                &commitment.reserve_commitment,
                commitment.capacity_piconero.saturating_mul(12) / 10,
                commitment
                    .allocated_piconero
                    .saturating_add(commitment.min_fill_piconero),
                &self.config,
                self.height,
            );
            self.reserve_risk_snapshots
                .insert(snapshot.snapshot_id.clone(), snapshot);
            self.add_liquidity_commitment(commitment)?;
        }
        Ok(())
    }

    fn install_devnet_intents_quotes_and_routes(
        &mut self,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        let low_fee_lane_id = self
            .lanes
            .values()
            .find(|lane| lane.kind == ExitLaneKind::LowFee)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "devnet low fee lane missing".to_string())?;
        let standard_lane_id = self
            .lanes
            .values()
            .find(|lane| lane.kind == ExitLaneKind::Standard)
            .map(|lane| lane.lane_id.clone())
            .ok_or_else(|| "devnet standard lane missing".to_string())?;
        let intent_a = SealedExitIntent::new(
            "devnet-sealed-intent-alice",
            "owner-commitment-alice-devnet",
            &low_fee_lane_id,
            "bucket-0.25-1.00-xmr",
            self.config.low_fee_bps.saturating_add(12),
            true,
            &self.config,
            self.height,
        );
        let intent_b = SealedExitIntent::new(
            "devnet-sealed-intent-bob",
            "owner-commitment-bob-devnet",
            &standard_lane_id,
            "bucket-1.00-4.00-xmr",
            self.config.max_route_fee_bps,
            false,
            &self.config,
            self.height,
        );
        let intent_ids = [
            self.add_sealed_intent(intent_a)?,
            self.add_sealed_intent(intent_b)?,
        ];
        for intent_id in intent_ids {
            let intent = self
                .sealed_intents
                .get(&intent_id)
                .ok_or_else(|| "devnet intent disappeared".to_string())?
                .clone();
            let commitments = self
                .liquidity_commitments
                .values()
                .filter(|commitment| {
                    commitment.lane_id == intent.lane_id && commitment.status.available()
                })
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            for (index, commitment) in commitments.into_iter().enumerate() {
                let amount = commitment
                    .min_fill_piconero
                    .saturating_mul((index as u64).saturating_add(2));
                let quote = ExitQuote::new(
                    &intent,
                    &commitment.maker_id,
                    &commitment.commitment_id,
                    amount,
                    commitment.quote_fee_bps,
                    &self.config,
                    self.height,
                );
                self.add_quote(quote)?;
            }
            let route_id = self.select_low_fee_route(&intent_id)?;
            self.publish_atomic_swap_hint(&route_id)?;
        }
        Ok(())
    }

    fn install_devnet_challenge_receipt(
        &mut self,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        let related_object_id = self
            .routes
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet route missing".to_string())?;
        self.file_privacy_challenge(
            &related_object_id,
            "watchtower-privacy-challenger-devnet",
            "delayed_reveal_consistency",
        )?;
        Ok(())
    }

    fn record_event(&mut self, kind: &str, object_id: &str, object_root: &str) {
        let event = RouterEvent::new(kind, object_id, object_root, self.height);
        self.events.insert(event.event_id.clone(), event);
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-EXIT-LIQUIDITY-ROUTER-RECORD",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> MoneroPrivateDexExitLiquidityRouterResult<State> {
    State::devnet()
}

trait PublicRecord {
    fn public_record(&self) -> Value;
}

impl PublicRecord for LiquidityLane {
    fn public_record(&self) -> Value {
        LiquidityLane::public_record(self)
    }
}

impl PublicRecord for SealedExitIntent {
    fn public_record(&self) -> Value {
        SealedExitIntent::public_record(self)
    }
}

impl PublicRecord for MarketMaker {
    fn public_record(&self) -> Value {
        MarketMaker::public_record(self)
    }
}

impl PublicRecord for MakerLiquidityCommitment {
    fn public_record(&self) -> Value {
        MakerLiquidityCommitment::public_record(self)
    }
}

impl PublicRecord for ExitQuote {
    fn public_record(&self) -> Value {
        ExitQuote::public_record(self)
    }
}

impl PublicRecord for RouteSelection {
    fn public_record(&self) -> Value {
        RouteSelection::public_record(self)
    }
}

impl PublicRecord for AtomicSwapSettlementHint {
    fn public_record(&self) -> Value {
        AtomicSwapSettlementHint::public_record(self)
    }
}

impl PublicRecord for ReserveRiskSnapshot {
    fn public_record(&self) -> Value {
        ReserveRiskSnapshot::public_record(self)
    }
}

impl PublicRecord for PrivacyChallengeReceipt {
    fn public_record(&self) -> Value {
        PrivacyChallengeReceipt::public_record(self)
    }
}

impl PublicRecord for RouterEvent {
    fn public_record(&self) -> Value {
        RouterEvent::public_record(self)
    }
}

impl LiquidityLane {
    fn validate(&self, config: &Config) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.lane_id, "lane id")?;
        ensure_non_empty(&self.label, "lane label")?;
        ensure_non_zero(self.capacity_piconero, "lane capacity")?;
        ensure_non_zero(self.min_intent_piconero, "lane min intent")?;
        ensure_non_zero(self.max_intent_piconero, "lane max intent")?;
        if self.min_intent_piconero > self.max_intent_piconero {
            return Err("lane min intent exceeds max intent".to_string());
        }
        if self.reserved_piconero > self.capacity_piconero {
            return Err("lane reserved amount exceeds capacity".to_string());
        }
        ensure_bps(self.fee_bps, "lane fee bps")?;
        ensure_bps(self.load_shed_bps, "lane load shed bps")?;
        ensure_hash(&self.maker_set_root, "lane maker set root")?;
        ensure_hash(&self.admission_policy_root, "lane admission policy root")?;
        if self.target_privacy_set_size < config.min_privacy_set_size {
            return Err("lane target privacy set below config minimum".to_string());
        }
        Ok(())
    }
}

impl SealedExitIntent {
    fn validate(
        &self,
        config: &Config,
        lanes: &BTreeMap<String, LiquidityLane>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.intent_id, "intent id")?;
        ensure_non_empty(&self.owner_commitment, "intent owner commitment")?;
        ensure_non_empty(&self.lane_id, "intent lane id")?;
        if !lanes.contains_key(&self.lane_id) {
            return Err("intent references unknown lane".to_string());
        }
        ensure_hash(&self.amount_commitment, "intent amount commitment")?;
        ensure_non_empty(&self.amount_bucket, "intent amount bucket")?;
        ensure_hash(
            &self.destination_commitment,
            "intent destination commitment",
        )?;
        ensure_hash(&self.refund_commitment, "intent refund commitment")?;
        ensure_hash(&self.sealed_payload_root, "intent sealed payload root")?;
        ensure_hash(&self.nullifier, "intent nullifier")?;
        ensure_bps(self.max_fee_bps, "intent max fee bps")?;
        if self.max_fee_bps > config.max_route_fee_bps {
            return Err("intent max fee exceeds config max route fee".to_string());
        }
        if self.expires_at_height < self.created_at_height {
            return Err("intent expiry before creation".to_string());
        }
        Ok(())
    }
}

impl MarketMaker {
    fn validate(
        &self,
        config: &Config,
        lanes: &BTreeMap<String, LiquidityLane>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.maker_id, "maker id")?;
        ensure_non_empty(&self.label, "maker label")?;
        ensure_hash(&self.operator_commitment, "maker operator commitment")?;
        ensure_hash(&self.quote_key_commitment, "maker quote key commitment")?;
        ensure_hash(
            &self.reserve_account_commitment,
            "maker reserve account commitment",
        )?;
        if self.bond_piconero < config.min_maker_bond_piconero {
            return Err("maker bond below minimum".to_string());
        }
        if self.active_exposure_piconero > self.max_exposure_piconero {
            return Err("maker active exposure exceeds maximum".to_string());
        }
        ensure_bps(self.reliability_bps, "maker reliability bps")?;
        if self.supported_lanes.is_empty() {
            return Err("maker must support at least one lane".to_string());
        }
        for lane_id in &self.supported_lanes {
            if !lanes.contains_key(lane_id) {
                return Err("maker references unknown lane".to_string());
            }
        }
        Ok(())
    }
}

impl MakerLiquidityCommitment {
    fn validate(
        &self,
        config: &Config,
        lanes: &BTreeMap<String, LiquidityLane>,
        makers: &BTreeMap<String, MarketMaker>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.commitment_id, "commitment id")?;
        let maker = makers
            .get(&self.maker_id)
            .ok_or_else(|| "commitment references unknown maker".to_string())?;
        let lane = lanes
            .get(&self.lane_id)
            .ok_or_else(|| "commitment references unknown lane".to_string())?;
        if !maker.supported_lanes.contains(&self.lane_id) {
            return Err("commitment maker does not support lane".to_string());
        }
        ensure_hash(&self.reserve_commitment, "commitment reserve commitment")?;
        ensure_non_zero(self.capacity_piconero, "commitment capacity")?;
        if self.allocated_piconero > self.capacity_piconero {
            return Err("commitment allocated amount exceeds capacity".to_string());
        }
        if self.min_fill_piconero < lane.min_intent_piconero {
            return Err("commitment min fill below lane min intent".to_string());
        }
        if self.quote_fee_bps > config.max_route_fee_bps {
            return Err("commitment quote fee exceeds config maximum".to_string());
        }
        ensure_hash(&self.reserve_proof_root, "commitment reserve proof root")?;
        ensure_hash(&self.pq_attestation_root, "commitment pq attestation root")?;
        if self.expires_at_height < self.published_at_height {
            return Err("commitment expiry before publication".to_string());
        }
        Ok(())
    }
}

impl ExitQuote {
    fn validate(
        &self,
        config: &Config,
        intents: &BTreeMap<String, SealedExitIntent>,
        commitments: &BTreeMap<String, MakerLiquidityCommitment>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.quote_id, "quote id")?;
        let intent = intents
            .get(&self.intent_id)
            .ok_or_else(|| "quote references unknown intent".to_string())?;
        let commitment = commitments
            .get(&self.commitment_id)
            .ok_or_else(|| "quote references unknown commitment".to_string())?;
        ensure_eq(&self.maker_id, &commitment.maker_id, "quote maker id")?;
        ensure_eq(&self.lane_id, &intent.lane_id, "quote lane id")?;
        ensure_non_zero(self.amount_piconero, "quote amount")?;
        ensure_bps(self.fee_bps, "quote fee bps")?;
        if self.fee_bps > intent.max_fee_bps || self.fee_bps > config.max_route_fee_bps {
            return Err("quote fee exceeds intent or config maximum".to_string());
        }
        if self.fee_piconero < config.fee_floor_piconero {
            return Err("quote fee below floor".to_string());
        }
        ensure_hash(&self.settlement_hint_root, "quote settlement hint root")?;
        if self.valid_until_height < self.created_at_height {
            return Err("quote expiry before creation".to_string());
        }
        Ok(())
    }
}

impl RouteSelection {
    fn validate(
        &self,
        config: &Config,
        intents: &BTreeMap<String, SealedExitIntent>,
        lanes: &BTreeMap<String, LiquidityLane>,
        quotes: &BTreeMap<String, ExitQuote>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.route_id, "route id")?;
        let intent = intents
            .get(&self.intent_id)
            .ok_or_else(|| "route references unknown intent".to_string())?;
        let lane = lanes
            .get(&self.lane_id)
            .ok_or_else(|| "route references unknown lane".to_string())?;
        ensure_eq(&intent.lane_id, &lane.lane_id, "route intent lane")?;
        if self.selected_quote_ids.is_empty() {
            return Err("route must include at least one quote".to_string());
        }
        if self.selected_quote_ids.len() > config.max_route_hops {
            return Err("route quote count exceeds max hops".to_string());
        }
        for quote_id in &self.selected_quote_ids {
            let quote = quotes
                .get(quote_id)
                .ok_or_else(|| "route references unknown quote".to_string())?;
            ensure_eq(&quote.intent_id, &self.intent_id, "route quote intent")?;
            ensure_eq(&quote.lane_id, &self.lane_id, "route quote lane")?;
        }
        ensure_non_zero(self.total_amount_piconero, "route total amount")?;
        ensure_bps(self.weighted_risk_bps, "route weighted risk bps")?;
        ensure_hash(&self.decision_root, "route decision root")?;
        if self.expires_at_height < self.selected_at_height {
            return Err("route expiry before selection".to_string());
        }
        Ok(())
    }
}

impl AtomicSwapSettlementHint {
    fn validate(
        &self,
        routes: &BTreeMap<String, RouteSelection>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.hint_id, "swap hint id")?;
        let route = routes
            .get(&self.route_id)
            .ok_or_else(|| "swap hint references unknown route".to_string())?;
        ensure_eq(&self.intent_id, &route.intent_id, "swap hint intent id")?;
        ensure_hash(&self.swap_contract_commitment, "swap contract commitment")?;
        ensure_hash(&self.monero_lock_commitment, "monero lock commitment")?;
        ensure_hash(&self.adaptor_signature_root, "adaptor signature root")?;
        ensure_hash(&self.refund_path_commitment, "refund path commitment")?;
        ensure_hash(&self.settlement_policy_root, "settlement policy root")?;
        if self.timeout_height < self.published_at_height {
            return Err("swap hint timeout before publication".to_string());
        }
        Ok(())
    }
}

impl ReserveRiskSnapshot {
    fn validate(
        &self,
        makers: &BTreeMap<String, MarketMaker>,
        lanes: &BTreeMap<String, LiquidityLane>,
    ) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.snapshot_id, "risk snapshot id")?;
        if !makers.contains_key(&self.maker_id) {
            return Err("risk snapshot references unknown maker".to_string());
        }
        if !lanes.contains_key(&self.lane_id) {
            return Err("risk snapshot references unknown lane".to_string());
        }
        ensure_hash(
            &self.reserve_commitment_root,
            "risk reserve commitment root",
        )?;
        ensure_coverage_bps(self.coverage_bps, "risk coverage bps")?;
        ensure_bps(self.stress_bps, "risk stress bps")?;
        ensure_bps(self.risk_score_bps, "risk score bps")?;
        Ok(())
    }
}

impl PrivacyChallengeReceipt {
    fn validate(&self) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
        ensure_non_empty(&self.receipt_id, "challenge receipt id")?;
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.related_object_id, "challenge related object id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "challenge challenger commitment",
        )?;
        ensure_hash(&self.claim_root, "challenge claim root")?;
        ensure_hash(&self.evidence_root, "challenge evidence root")?;
        ensure_hash(&self.response_root, "challenge response root")?;
        if self.response_due_height < self.filed_at_height {
            return Err("challenge response due before filing".to_string());
        }
        Ok(())
    }
}

fn map_root<T: PublicRecord>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let records = values
        .values()
        .map(PublicRecord::public_record)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-PRIVATE-DEX-EXIT-LIQUIDITY-ROUTER-{domain}"),
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn lane_id(label: &str, kind: ExitLaneKind, created_at_height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-LIQUIDITY-LANE-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(kind.as_str()),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

fn maker_id(label: &str, lanes: &BTreeSet<String>, created_at_height: u64) -> String {
    let lane_record = json!(lanes.iter().cloned().collect::<Vec<_>>());
    domain_hash(
        "MONERO-PRIVATE-DEX-MARKET-MAKER-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(&lane_record),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

fn intent_id(owner_commitment: &str, lane_id: &str, nullifier: &str, height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-SEALED-EXIT-INTENT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(lane_id),
            HashPart::Str(nullifier),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn commitment_id(kind: &str, label: &str, root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-COMMITMENT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::Str(root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn liquidity_commitment_id(
    maker_id: &str,
    lane_id: &str,
    reserve_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-LIQUIDITY-COMMITMENT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(lane_id),
            HashPart::Str(reserve_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn quote_id(intent_id: &str, maker_id: &str, commitment_id: &str, hint_root: &str) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-EXIT-QUOTE-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(maker_id),
            HashPart::Str(commitment_id),
            HashPart::Str(hint_root),
        ],
        32,
    )
}

fn route_id(intent_id: &str, lane_id: &str, decision_root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-ROUTE-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(lane_id),
            HashPart::Str(decision_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn swap_hint_id(route_id: &str, swap_contract_commitment: &str, policy_root: &str) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-ATOMIC-SWAP-HINT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(route_id),
            HashPart::Str(swap_contract_commitment),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

fn risk_snapshot_id(maker_id: &str, lane_id: &str, reserve_root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-RESERVE-RISK-SNAPSHOT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(maker_id),
            HashPart::Str(lane_id),
            HashPart::Str(reserve_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn challenge_id(
    related_object_id: &str,
    challenger_commitment: &str,
    claim_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-PRIVACY-CHALLENGE-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(related_object_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(claim_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn receipt_id(challenge_id: &str, related_object_id: &str, response_root: &str) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-PRIVACY-CHALLENGE-RECEIPT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(challenge_id),
            HashPart::Str(related_object_id),
            HashPart::Str(response_root),
        ],
        32,
    )
}

fn event_id(kind: &str, object_id: &str, object_root: &str, height: u64) -> String {
    domain_hash(
        "MONERO-PRIVATE-DEX-ROUTER-EVENT-ID",
        &[
            HashPart::Str(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(object_id),
            HashPart::Str(object_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

fn coverage_bps(committed_piconero: u64, outstanding_piconero: u64) -> u64 {
    if outstanding_piconero == 0 {
        return MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS;
    }
    committed_piconero.saturating_mul(MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS)
        / outstanding_piconero
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn ensure_non_zero(value: u64, label: &str) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn ensure_bps(value: u64, label: &str) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    if value > MONERO_PRIVATE_DEX_EXIT_LIQUIDITY_ROUTER_MAX_BPS {
        return Err(format!("{label} exceeds max bps"));
    }
    Ok(())
}

fn ensure_coverage_bps(value: u64, label: &str) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    ensure_non_zero(value, label)
}

fn ensure_hash(value: &str, label: &str) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    ensure_non_empty(value, label)?;
    if value.len() != 64 {
        return Err(format!("{label} must be a 32-byte hex hash"));
    }
    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{label} must be hex encoded"));
    }
    Ok(())
}

fn ensure_limit(
    value: usize,
    limit: usize,
    label: &str,
) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    if value > limit {
        return Err(format!("{label} exceeds protocol limit"));
    }
    Ok(())
}

fn ensure_eq(
    left: &str,
    right: &str,
    label: &str,
) -> MoneroPrivateDexExitLiquidityRouterResult<()> {
    if left != right {
        return Err(format!("{label} mismatch"));
    }
    Ok(())
}
