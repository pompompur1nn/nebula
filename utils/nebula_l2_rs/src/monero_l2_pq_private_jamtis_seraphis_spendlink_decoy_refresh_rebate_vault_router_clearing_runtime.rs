use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateJamtisSeraphisSpendlinkDecoyRefreshRebateVaultRouterClearingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_REBATE_VAULT_ROUTER_CLEARING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-jamtis-seraphis-spendlink-decoy-refresh-rebate-vault-router-clearing-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_JAMTIS_SERAPHIS_SPENDLINK_DECOY_REFRESH_REBATE_VAULT_ROUTER_CLEARING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const STATE_ROOT_DOMAIN: &str =
    "MONERO-L2-PQ-PRIVATE-JAMTIS-SERAPHIS-SPENDLINK-DECOY-REFRESH-REBATE-VAULT-ROUTER-CLEARING";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_REBATE_ASSET_ID: &str = "refresh-vault-router-clearing-rebate-credit-devnet";
pub const DEVNET_ROUTE_ASSET_ID: &str = "refresh-vault-route-clearing-share-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 3_272_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_920_000;
pub const DEVNET_EPOCH: u64 = 19_328;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 64;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_TARGET_RING_SIZE: u16 = 192;
pub const DEFAULT_MIN_DECOY_POOL_OUTPUTS: u64 = 262_144;
pub const DEFAULT_TARGET_DECOY_POOL_OUTPUTS: u64 = 2_097_152;
pub const DEFAULT_MIN_DECOY_ENTROPY_BPS: u64 = 9_120;
pub const DEFAULT_MIN_SPENDLINK_SHIELD_BPS: u64 = 9_080;
pub const DEFAULT_MIN_REFRESH_UTILITY_BPS: u64 = 8_820;
pub const DEFAULT_MIN_VAULT_ROUTING_QUALITY_BPS: u64 = 9_220;
pub const DEFAULT_MIN_REBATE_COVER_BPS: u64 = 9_650;
pub const DEFAULT_MIN_SOLVER_DIVERSITY_BPS: u64 = 7_900;
pub const DEFAULT_MIN_LIQUIDITY_DEPTH_BPS: u64 = 8_950;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_REFRESH_FEE_BPS: u64 = 3;
pub const DEFAULT_MAX_VAULT_ROUTE_HOPS: u8 = 7;
pub const DEFAULT_MIN_VAULT_ROUTE_SPLIT_BPS: u64 = 400;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_VAULT_ROUTE: u64 = 40_960;
pub const DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH: u64 = 524_288;
pub const DEFAULT_MIN_REBATE_SOLVENCY_BPS: u64 = 9_480;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_ROUTE_QUOTE_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_ROUTE_PLAN_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 288;
pub const VAULT_ROUTER_INTENT_SCHEME: &str =
    "jamtis-seraphis-spendlink-decoy-refresh-rebate-vault-router-clearing-intent-root-v1";
pub const VAULT_ROUTER_POOL_SCHEME: &str =
    "pq-private-jamtis-seraphis-decoy-refresh-vault-router-clearing-pool-root-v1";
pub const VAULT_ROUTER_QUOTE_SCHEME: &str =
    "defi-style-private-refresh-rebate-vault-router-clearing-quote-root-v1";
pub const VAULT_ROUTE_PLAN_SCHEME: &str =
    "shielded-jamtis-seraphis-refresh-rebate-vault-route-clearing-plan-root-v1";
pub const VAULT_ROUTE_SPLIT_SCHEME: &str =
    "private-refresh-rebate-vault-router-clearing-split-commitment-root-v1";
pub const VAULT_ROUTE_SETTLEMENT_SCHEME: &str =
    "defi-style-private-refresh-rebate-vault-router-clearing-settlement-root-v1";
pub const VAULT_ROUTER_PQ_ATTESTATION_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-jamtis-seraphis-refresh-rebate-vault-router-clearing-attestation-v1";
pub const VAULT_ROUTER_AUDIT_SCHEME: &str =
    "low-fee-private-refresh-rebate-vault-router-clearing-audit-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "roots-only-jamtis-seraphis-spendlink-decoy-refresh-rebate-vault-router-clearing-public-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_addresses_view_keys_key_images_amounts_output_indices_viewtags_spendlinks_ring_members_decoy_graphs_solver_identities_vault_route_prices_liquidity_owner_ids_split_witnesses_or_settlement_witnesses";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouterLane {
    WalletScan,
    DexSwap,
    BridgeExit,
    MerchantReceive,
    WatchtowerRepair,
    ReorgRecovery,
    LiquidityMigration,
    EmergencyPrivacy,
}

impl VaultRouterLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletScan => "wallet_scan",
            Self::DexSwap => "dex_swap",
            Self::BridgeExit => "bridge_exit",
            Self::MerchantReceive => "merchant_receive",
            Self::WatchtowerRepair => "watchtower_repair",
            Self::ReorgRecovery => "reorg_recovery",
            Self::LiquidityMigration => "liquidity_migration",
            Self::EmergencyPrivacy => "emergency_privacy",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyPrivacy => 1_000,
            Self::ReorgRecovery => 980,
            Self::BridgeExit => 950,
            Self::LiquidityMigration => 925,
            Self::DexSwap => 900,
            Self::WatchtowerRepair => 865,
            Self::MerchantReceive => 835,
            Self::WalletScan => 810,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouteIntentStatus {
    Open,
    EntropyChecked,
    ShieldChecked,
    Routed,
    Split,
    Settled,
    Attested,
    Audited,
    Sealed,
    Quarantined,
    Rejected,
    Expired,
}

impl VaultRouteIntentStatus {
    pub fn routable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::EntropyChecked | Self::ShieldChecked | Self::Routed
        )
    }

    pub fn private_success(self) -> bool {
        matches!(
            self,
            Self::Routed
                | Self::Split
                | Self::Settled
                | Self::Attested
                | Self::Audited
                | Self::Sealed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouterPoolStatus {
    Open,
    Quoting,
    Reserving,
    Routing,
    Rebalanced,
    Exhausted,
    Slashed,
    Frozen,
    Closed,
}

impl VaultRouterPoolStatus {
    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Quoting | Self::Reserving | Self::Routing | Self::Rebalanced
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRouteQuoteStatus {
    Committed,
    Revealed,
    Eligible,
    Selected,
    PartiallyFilled,
    Filled,
    Refunded,
    Slashed,
    Rejected,
    Expired,
}

impl VaultRouteQuoteStatus {
    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::Revealed
                | Self::Eligible
                | Self::Selected
                | Self::PartiallyFilled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultRoutePlanStatus {
    Draft,
    Scored,
    Reserved,
    Split,
    Executing,
    Settled,
    Challenged,
    Quarantined,
    Rejected,
    Expired,
}

impl VaultRoutePlanStatus {
    pub fn success(self) -> bool {
        matches!(self, Self::Split | Self::Executing | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitStatus {
    Created,
    Reserved,
    Proved,
    Executed,
    RolledForward,
    Slashed,
    Challenged,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Draft,
    Netting,
    Rebating,
    Rebalanced,
    Final,
    Refunded,
    Slashed,
    Challenged,
    Rejected,
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
pub enum VaultRouterAuditStatus {
    Draft,
    Sampling,
    Published,
    Disputed,
    Accepted,
    Regression,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAudience {
    Public,
    Watchtower,
    Regulator,
    LiquidityDao,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub vault_route_asset_id: String,
    pub public_bucket_size: u64,
    pub min_ring_size: u16,
    pub target_ring_size: u16,
    pub min_decoy_pool_outputs: u64,
    pub target_decoy_pool_outputs: u64,
    pub min_decoy_entropy_bps: u64,
    pub min_spendlink_shield_bps: u64,
    pub min_refresh_utility_bps: u64,
    pub min_vault_routing_quality_bps: u64,
    pub min_rebate_cover_bps: u64,
    pub min_solver_diversity_bps: u64,
    pub min_liquidity_depth_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_refresh_fee_bps: u64,
    pub max_vault_route_hops: u8,
    pub min_vault_route_split_bps: u64,
    pub max_refresh_units_per_vault_route: u64,
    pub max_refresh_units_per_epoch: u64,
    pub min_rebate_solvency_bps: u64,
    pub intent_ttl_blocks: u64,
    pub route_quote_ttl_blocks: u64,
    pub route_plan_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub privacy_boundary: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEVNET_REBATE_ASSET_ID.to_string(),
            vault_route_asset_id: DEVNET_ROUTE_ASSET_ID.to_string(),
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            target_ring_size: DEFAULT_TARGET_RING_SIZE,
            min_decoy_pool_outputs: DEFAULT_MIN_DECOY_POOL_OUTPUTS,
            target_decoy_pool_outputs: DEFAULT_TARGET_DECOY_POOL_OUTPUTS,
            min_decoy_entropy_bps: DEFAULT_MIN_DECOY_ENTROPY_BPS,
            min_spendlink_shield_bps: DEFAULT_MIN_SPENDLINK_SHIELD_BPS,
            min_refresh_utility_bps: DEFAULT_MIN_REFRESH_UTILITY_BPS,
            min_vault_routing_quality_bps: DEFAULT_MIN_VAULT_ROUTING_QUALITY_BPS,
            min_rebate_cover_bps: DEFAULT_MIN_REBATE_COVER_BPS,
            min_solver_diversity_bps: DEFAULT_MIN_SOLVER_DIVERSITY_BPS,
            min_liquidity_depth_bps: DEFAULT_MIN_LIQUIDITY_DEPTH_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_refresh_fee_bps: DEFAULT_MAX_USER_REFRESH_FEE_BPS,
            max_vault_route_hops: DEFAULT_MAX_VAULT_ROUTE_HOPS,
            min_vault_route_split_bps: DEFAULT_MIN_VAULT_ROUTE_SPLIT_BPS,
            max_refresh_units_per_vault_route: DEFAULT_MAX_REFRESH_UNITS_PER_VAULT_ROUTE,
            max_refresh_units_per_epoch: DEFAULT_MAX_REFRESH_UNITS_PER_EPOCH,
            min_rebate_solvency_bps: DEFAULT_MIN_REBATE_SOLVENCY_BPS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            route_quote_ttl_blocks: DEFAULT_ROUTE_QUOTE_TTL_BLOCKS,
            route_plan_ttl_blocks: DEFAULT_ROUTE_PLAN_TTL_BLOCKS,
            settlement_ttl_blocks: DEFAULT_SETTLEMENT_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure(self.min_ring_size >= 11, "min ring size too small")?;
        ensure(
            self.target_ring_size >= self.min_ring_size,
            "target ring size below min",
        )?;
        ensure(
            self.target_decoy_pool_outputs >= self.min_decoy_pool_outputs,
            "target decoy pool below min",
        )?;
        ensure_bps(self.min_decoy_entropy_bps, "min decoy entropy")?;
        ensure_bps(self.min_spendlink_shield_bps, "min spendlink shield")?;
        ensure_bps(self.min_refresh_utility_bps, "min refresh utility")?;
        ensure_bps(self.min_vault_routing_quality_bps, "min routing quality")?;
        ensure_bps(self.min_rebate_cover_bps, "min rebate cover")?;
        ensure_bps(self.min_solver_diversity_bps, "min solver diversity")?;
        ensure_bps(self.min_liquidity_depth_bps, "min liquidity depth")?;
        ensure_bps(self.max_user_refresh_fee_bps, "max user refresh fee")?;
        ensure_bps(self.min_vault_route_split_bps, "min route split")?;
        ensure_bps(self.min_rebate_solvency_bps, "min rebate solvency")?;
        ensure(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below min",
        )?;
        ensure(
            self.max_vault_route_hops > 0,
            "max route hops must be positive",
        )?;
        ensure(
            self.max_refresh_units_per_epoch >= self.max_refresh_units_per_vault_route,
            "epoch refresh cap below route cap",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "vault_route_asset_id": self.vault_route_asset_id,
            "public_bucket_size": self.public_bucket_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_decoy_pool_outputs": self.min_decoy_pool_outputs,
            "target_decoy_pool_outputs": self.target_decoy_pool_outputs,
            "min_decoy_entropy_bps": self.min_decoy_entropy_bps,
            "min_spendlink_shield_bps": self.min_spendlink_shield_bps,
            "min_refresh_utility_bps": self.min_refresh_utility_bps,
            "min_vault_routing_quality_bps": self.min_vault_routing_quality_bps,
            "min_rebate_cover_bps": self.min_rebate_cover_bps,
            "min_solver_diversity_bps": self.min_solver_diversity_bps,
            "min_liquidity_depth_bps": self.min_liquidity_depth_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_refresh_fee_bps": self.max_user_refresh_fee_bps,
            "max_vault_route_hops": self.max_vault_route_hops,
            "min_vault_route_split_bps": self.min_vault_route_split_bps,
            "max_refresh_units_per_vault_route": self.max_refresh_units_per_vault_route,
            "max_refresh_units_per_epoch": self.max_refresh_units_per_epoch,
            "min_rebate_solvency_bps": self.min_rebate_solvency_bps,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "route_quote_ttl_blocks": self.route_quote_ttl_blocks,
            "route_plan_ttl_blocks": self.route_plan_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "privacy_boundary": self.privacy_boundary,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub intents: u64,
    pub pools: u64,
    pub quotes: u64,
    pub plans: u64,
    pub splits: u64,
    pub settlements: u64,
    pub attestations: u64,
    pub audits: u64,
    pub public_records: u64,
    pub routed_refresh_units_bucket: u64,
    pub settled_refresh_units_bucket: u64,
    pub reserved_rebate_bucket: u64,
    pub paid_rebate_bucket: u64,
    pub gross_user_fee_bucket: u64,
    pub net_user_fee_bucket: u64,
    pub quarantined_items: u64,
    pub expired_items: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "intents": self.intents,
            "pools": self.pools,
            "quotes": self.quotes,
            "plans": self.plans,
            "splits": self.splits,
            "settlements": self.settlements,
            "attestations": self.attestations,
            "audits": self.audits,
            "public_records": self.public_records,
            "routed_refresh_units_bucket": self.routed_refresh_units_bucket,
            "settled_refresh_units_bucket": self.settled_refresh_units_bucket,
            "reserved_rebate_bucket": self.reserved_rebate_bucket,
            "paid_rebate_bucket": self.paid_rebate_bucket,
            "gross_user_fee_bucket": self.gross_user_fee_bucket,
            "net_user_fee_bucket": self.net_user_fee_bucket,
            "quarantined_items": self.quarantined_items,
            "expired_items": self.expired_items,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub route_intent_root: String,
    pub vault_router_pool_root: String,
    pub route_quote_root: String,
    pub route_plan_root: String,
    pub route_split_root: String,
    pub route_settlement_root: String,
    pub pq_attestation_root: String,
    pub low_fee_audit_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        Self {
            config_root: config.state_root(),
            counters_root: counters.state_root(),
            route_intent_root: empty_root("route-intents"),
            vault_router_pool_root: empty_root("vault_router-pools"),
            route_quote_root: empty_root("route-quotes"),
            route_plan_root: empty_root("route-plans"),
            route_split_root: empty_root("route-splits"),
            route_settlement_root: empty_root("route-settlements"),
            pq_attestation_root: empty_root("pq-attestations"),
            low_fee_audit_root: empty_root("low-fee-audits"),
            nullifier_root: empty_root("nullifiers"),
            public_record_root: empty_root("public-records"),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "route_intent_root": self.route_intent_root,
            "vault_router_pool_root": self.vault_router_pool_root,
            "route_quote_root": self.route_quote_root,
            "route_plan_root": self.route_plan_root,
            "route_split_root": self.route_split_root,
            "route_settlement_root": self.route_settlement_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_audit_root": self.low_fee_audit_root,
            "nullifier_root": self.nullifier_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRouteIntentInput {
    pub intent_id: String,
    pub lane: VaultRouterLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub max_user_fee_bps: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_hint_root: String,
    pub rebate_preference_root: String,
    pub routing_constraint_root: String,
    pub expires_at_height: u64,
    pub status: VaultRouteIntentStatus,
}

impl VaultRouteIntentInput {
    pub fn into_entry(self, config: &Config) -> Result<RouteIntentEntry> {
        ensure(!self.intent_id.is_empty(), "intent id empty")?;
        ensure(
            self.ring_size >= config.min_ring_size,
            "ring size below configured minimum",
        )?;
        ensure(
            self.output_count_bucket >= config.min_decoy_pool_outputs,
            "decoy pool below configured minimum",
        )?;
        ensure_bps(self.max_user_fee_bps, "intent max user fee")?;
        ensure(
            self.max_user_fee_bps <= config.max_user_refresh_fee_bps,
            "intent user fee exceeds vault_router max",
        )?;
        ensure(
            self.decoy_entropy_bps >= config.min_decoy_entropy_bps,
            "intent decoy entropy below min",
        )?;
        ensure(
            self.spendlink_shield_bps >= config.min_spendlink_shield_bps,
            "intent spendlink shield below min",
        )?;
        ensure(
            self.refresh_utility_bps >= config.min_refresh_utility_bps,
            "intent refresh utility below min",
        )?;
        Ok(RouteIntentEntry {
            intent_id: self.intent_id,
            lane: self.lane,
            epoch: self.epoch,
            monero_height_bucket: self.monero_height_bucket,
            output_count_bucket: self.output_count_bucket,
            ring_size: self.ring_size,
            refresh_unit_bucket: self.refresh_unit_bucket,
            max_user_fee_bps: self.max_user_fee_bps,
            decoy_entropy_bps: self.decoy_entropy_bps,
            spendlink_shield_bps: self.spendlink_shield_bps,
            refresh_utility_bps: self.refresh_utility_bps,
            decoy_pool_root: self.decoy_pool_root,
            spendlink_shield_root: self.spendlink_shield_root,
            refresh_plan_hint_root: self.refresh_plan_hint_root,
            rebate_preference_root: self.rebate_preference_root,
            routing_constraint_root: self.routing_constraint_root,
            expires_at_height: self.expires_at_height,
            status: self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteIntentEntry {
    pub intent_id: String,
    pub lane: VaultRouterLane,
    pub epoch: u64,
    pub monero_height_bucket: u64,
    pub output_count_bucket: u64,
    pub ring_size: u16,
    pub refresh_unit_bucket: u64,
    pub max_user_fee_bps: u64,
    pub decoy_entropy_bps: u64,
    pub spendlink_shield_bps: u64,
    pub refresh_utility_bps: u64,
    pub decoy_pool_root: String,
    pub spendlink_shield_root: String,
    pub refresh_plan_hint_root: String,
    pub rebate_preference_root: String,
    pub routing_constraint_root: String,
    pub expires_at_height: u64,
    pub status: VaultRouteIntentStatus,
}

impl RouteIntentEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTER_INTENT_SCHEME,
            "intent_id": self.intent_id,
            "lane": self.lane,
            "epoch": self.epoch,
            "monero_height_bucket": self.monero_height_bucket,
            "output_count_bucket": self.output_count_bucket,
            "ring_size": self.ring_size,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "max_user_fee_bps": self.max_user_fee_bps,
            "decoy_entropy_bps": self.decoy_entropy_bps,
            "spendlink_shield_bps": self.spendlink_shield_bps,
            "refresh_utility_bps": self.refresh_utility_bps,
            "decoy_pool_root": self.decoy_pool_root,
            "spendlink_shield_root": self.spendlink_shield_root,
            "refresh_plan_hint_root": self.refresh_plan_hint_root,
            "rebate_preference_root": self.rebate_preference_root,
            "routing_constraint_root": self.routing_constraint_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("route-intent", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRouterPoolInput {
    pub pool_id: String,
    pub provider_bucket: String,
    pub lane: VaultRouterLane,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub vault_route_asset_id: String,
    pub available_rebate_bucket: u64,
    pub reserved_rebate_bucket: u64,
    pub refresh_unit_capacity_bucket: u64,
    pub max_user_fee_bps: u64,
    pub rebate_cover_bps: u64,
    pub solvency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub solver_diversity_bps: u64,
    pub pool_commitment_root: String,
    pub liquidity_policy_root: String,
    pub rebalance_proof_root: String,
    pub mev_resistance_root: String,
    pub status: VaultRouterPoolStatus,
}

impl VaultRouterPoolInput {
    pub fn into_entry(self, config: &Config) -> Result<VaultRouterPoolEntry> {
        ensure(!self.pool_id.is_empty(), "vault vault_router pool id empty")?;
        ensure(
            self.fee_asset_id == config.fee_asset_id,
            "vault vault_router pool fee asset mismatch",
        )?;
        ensure(
            self.rebate_asset_id == config.rebate_asset_id,
            "vault vault_router pool rebate asset mismatch",
        )?;
        ensure(
            self.vault_route_asset_id == config.vault_route_asset_id,
            "vault vault_router pool route asset mismatch",
        )?;
        ensure_bps(
            self.max_user_fee_bps,
            "vault vault_router pool max user fee",
        )?;
        ensure(
            self.max_user_fee_bps <= config.max_user_refresh_fee_bps,
            "vault vault_router pool user fee above max",
        )?;
        ensure(
            self.rebate_cover_bps >= config.min_rebate_cover_bps,
            "vault vault_router pool rebate cover below min",
        )?;
        ensure(
            self.solvency_bps >= config.min_rebate_solvency_bps,
            "vault vault_router pool solvency below min",
        )?;
        ensure(
            self.liquidity_depth_bps >= config.min_liquidity_depth_bps,
            "vault vault_router pool liquidity depth below min",
        )?;
        ensure(
            self.solver_diversity_bps >= config.min_solver_diversity_bps,
            "vault vault_router pool solver diversity below min",
        )?;
        Ok(VaultRouterPoolEntry {
            pool_id: self.pool_id,
            provider_bucket: self.provider_bucket,
            lane: self.lane,
            fee_asset_id: self.fee_asset_id,
            rebate_asset_id: self.rebate_asset_id,
            vault_route_asset_id: self.vault_route_asset_id,
            available_rebate_bucket: self.available_rebate_bucket,
            reserved_rebate_bucket: self.reserved_rebate_bucket,
            refresh_unit_capacity_bucket: self.refresh_unit_capacity_bucket,
            max_user_fee_bps: self.max_user_fee_bps,
            rebate_cover_bps: self.rebate_cover_bps,
            solvency_bps: self.solvency_bps,
            liquidity_depth_bps: self.liquidity_depth_bps,
            solver_diversity_bps: self.solver_diversity_bps,
            pool_commitment_root: self.pool_commitment_root,
            liquidity_policy_root: self.liquidity_policy_root,
            rebalance_proof_root: self.rebalance_proof_root,
            mev_resistance_root: self.mev_resistance_root,
            status: self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRouterPoolEntry {
    pub pool_id: String,
    pub provider_bucket: String,
    pub lane: VaultRouterLane,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub vault_route_asset_id: String,
    pub available_rebate_bucket: u64,
    pub reserved_rebate_bucket: u64,
    pub refresh_unit_capacity_bucket: u64,
    pub max_user_fee_bps: u64,
    pub rebate_cover_bps: u64,
    pub solvency_bps: u64,
    pub liquidity_depth_bps: u64,
    pub solver_diversity_bps: u64,
    pub pool_commitment_root: String,
    pub liquidity_policy_root: String,
    pub rebalance_proof_root: String,
    pub mev_resistance_root: String,
    pub status: VaultRouterPoolStatus,
}

impl VaultRouterPoolEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTER_POOL_SCHEME,
            "pool_id": self.pool_id,
            "provider_bucket": self.provider_bucket,
            "lane": self.lane,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "vault_route_asset_id": self.vault_route_asset_id,
            "available_rebate_bucket": self.available_rebate_bucket,
            "reserved_rebate_bucket": self.reserved_rebate_bucket,
            "refresh_unit_capacity_bucket": self.refresh_unit_capacity_bucket,
            "max_user_fee_bps": self.max_user_fee_bps,
            "rebate_cover_bps": self.rebate_cover_bps,
            "solvency_bps": self.solvency_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "solver_diversity_bps": self.solver_diversity_bps,
            "pool_commitment_root": self.pool_commitment_root,
            "liquidity_policy_root": self.liquidity_policy_root,
            "rebalance_proof_root": self.rebalance_proof_root,
            "mev_resistance_root": self.mev_resistance_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("vault_router-pool", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRouteQuoteInput {
    pub quote_id: String,
    pub pool_id: String,
    pub solver_bucket: String,
    pub route_nullifier: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub max_user_fee_bps: u64,
    pub route_rebate_bps: u64,
    pub rebate_cover_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub rebate_budget_bucket: u64,
    pub quote_commitment_root: String,
    pub solver_policy_root: String,
    pub route_cost_curve_root: String,
    pub liquidity_reservation_root: String,
    pub expires_at_height: u64,
    pub status: VaultRouteQuoteStatus,
}

impl VaultRouteQuoteInput {
    pub fn into_entry(self, config: &Config) -> Result<RouteQuoteEntry> {
        ensure(!self.quote_id.is_empty(), "route quote id empty")?;
        ensure(
            !self.route_nullifier.is_empty(),
            "route quote nullifier empty",
        )?;
        ensure(
            self.fee_asset_id == config.fee_asset_id,
            "route quote fee asset mismatch",
        )?;
        ensure(
            self.rebate_asset_id == config.rebate_asset_id,
            "route quote rebate asset mismatch",
        )?;
        ensure_bps(self.max_user_fee_bps, "route quote max user fee")?;
        ensure_bps(self.route_rebate_bps, "route quote rebate")?;
        ensure(
            self.max_user_fee_bps <= config.max_user_refresh_fee_bps,
            "route quote user fee above max",
        )?;
        ensure(
            self.rebate_cover_bps >= config.min_rebate_cover_bps,
            "route quote rebate cover below min",
        )?;
        ensure(
            self.vault_routing_quality_bps >= config.min_vault_routing_quality_bps,
            "route quote quality below min",
        )?;
        ensure(
            self.liquidity_depth_bps >= config.min_liquidity_depth_bps,
            "route quote liquidity depth below min",
        )?;
        Ok(RouteQuoteEntry {
            quote_id: self.quote_id,
            pool_id: self.pool_id,
            solver_bucket: self.solver_bucket,
            route_nullifier: self.route_nullifier,
            fee_asset_id: self.fee_asset_id,
            rebate_asset_id: self.rebate_asset_id,
            max_user_fee_bps: self.max_user_fee_bps,
            route_rebate_bps: self.route_rebate_bps,
            rebate_cover_bps: self.rebate_cover_bps,
            vault_routing_quality_bps: self.vault_routing_quality_bps,
            liquidity_depth_bps: self.liquidity_depth_bps,
            refresh_unit_budget_bucket: self.refresh_unit_budget_bucket,
            rebate_budget_bucket: self.rebate_budget_bucket,
            quote_commitment_root: self.quote_commitment_root,
            solver_policy_root: self.solver_policy_root,
            route_cost_curve_root: self.route_cost_curve_root,
            liquidity_reservation_root: self.liquidity_reservation_root,
            expires_at_height: self.expires_at_height,
            status: self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteQuoteEntry {
    pub quote_id: String,
    pub pool_id: String,
    pub solver_bucket: String,
    pub route_nullifier: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub max_user_fee_bps: u64,
    pub route_rebate_bps: u64,
    pub rebate_cover_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_budget_bucket: u64,
    pub rebate_budget_bucket: u64,
    pub quote_commitment_root: String,
    pub solver_policy_root: String,
    pub route_cost_curve_root: String,
    pub liquidity_reservation_root: String,
    pub expires_at_height: u64,
    pub status: VaultRouteQuoteStatus,
}

impl RouteQuoteEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTER_QUOTE_SCHEME,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "solver_bucket": self.solver_bucket,
            "route_nullifier_root": root_from_parts("route-quote-nullifier", &[HashPart::Str(&self.route_nullifier)]),
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "max_user_fee_bps": self.max_user_fee_bps,
            "route_rebate_bps": self.route_rebate_bps,
            "rebate_cover_bps": self.rebate_cover_bps,
            "vault_routing_quality_bps": self.vault_routing_quality_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "refresh_unit_budget_bucket": self.refresh_unit_budget_bucket,
            "rebate_budget_bucket": self.rebate_budget_bucket,
            "quote_commitment_root": self.quote_commitment_root,
            "solver_policy_root": self.solver_policy_root,
            "route_cost_curve_root": self.route_cost_curve_root,
            "liquidity_reservation_root": self.liquidity_reservation_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("route-quote", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultRoutePlanInput {
    pub plan_id: String,
    pub intent_id: String,
    pub lane: VaultRouterLane,
    pub epoch: u64,
    pub intent_root: String,
    pub quote_root: String,
    pub pool_root: String,
    pub split_root: String,
    pub hop_count: u8,
    pub route_split_count_bucket: u64,
    pub route_weight_bps: u64,
    pub solver_diversity_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub rebate_cover_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_bucket: u64,
    pub gross_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub net_user_fee_bps: u64,
    pub route_transcript_root: String,
    pub privacy_budget_root: String,
    pub mev_resistance_root: String,
    pub expires_at_height: u64,
    pub status: VaultRoutePlanStatus,
}

impl VaultRoutePlanInput {
    pub fn into_entry(self, config: &Config) -> Result<RoutePlanEntry> {
        ensure(!self.plan_id.is_empty(), "route plan id empty")?;
        ensure(self.hop_count > 0, "route plan needs at least one hop")?;
        ensure(
            self.hop_count <= config.max_vault_route_hops,
            "route plan exceeds max hops",
        )?;
        ensure_bps(self.route_weight_bps, "route plan weight")?;
        ensure(
            self.route_weight_bps >= config.min_vault_route_split_bps,
            "route plan split below min",
        )?;
        ensure(
            self.solver_diversity_bps >= config.min_solver_diversity_bps,
            "route plan solver diversity below min",
        )?;
        ensure(
            self.vault_routing_quality_bps >= config.min_vault_routing_quality_bps,
            "route plan quality below min",
        )?;
        ensure(
            self.rebate_cover_bps >= config.min_rebate_cover_bps,
            "route plan rebate cover below min",
        )?;
        ensure(
            self.liquidity_depth_bps >= config.min_liquidity_depth_bps,
            "route plan liquidity below min",
        )?;
        ensure(
            self.refresh_unit_bucket <= config.max_refresh_units_per_vault_route,
            "route plan refresh units above cap",
        )?;
        ensure(
            self.net_user_fee_bps <= config.max_user_refresh_fee_bps,
            "route plan user fee above max",
        )?;
        Ok(RoutePlanEntry {
            plan_id: self.plan_id,
            intent_id: self.intent_id,
            lane: self.lane,
            epoch: self.epoch,
            intent_root: self.intent_root,
            quote_root: self.quote_root,
            pool_root: self.pool_root,
            split_root: self.split_root,
            hop_count: self.hop_count,
            route_split_count_bucket: self.route_split_count_bucket,
            route_weight_bps: self.route_weight_bps,
            solver_diversity_bps: self.solver_diversity_bps,
            vault_routing_quality_bps: self.vault_routing_quality_bps,
            rebate_cover_bps: self.rebate_cover_bps,
            liquidity_depth_bps: self.liquidity_depth_bps,
            refresh_unit_bucket: self.refresh_unit_bucket,
            gross_fee_bucket: self.gross_fee_bucket,
            rebate_bucket: self.rebate_bucket,
            net_user_fee_bps: self.net_user_fee_bps,
            route_transcript_root: self.route_transcript_root,
            privacy_budget_root: self.privacy_budget_root,
            mev_resistance_root: self.mev_resistance_root,
            expires_at_height: self.expires_at_height,
            status: self.status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePlanEntry {
    pub plan_id: String,
    pub intent_id: String,
    pub lane: VaultRouterLane,
    pub epoch: u64,
    pub intent_root: String,
    pub quote_root: String,
    pub pool_root: String,
    pub split_root: String,
    pub hop_count: u8,
    pub route_split_count_bucket: u64,
    pub route_weight_bps: u64,
    pub solver_diversity_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub rebate_cover_bps: u64,
    pub liquidity_depth_bps: u64,
    pub refresh_unit_bucket: u64,
    pub gross_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub net_user_fee_bps: u64,
    pub route_transcript_root: String,
    pub privacy_budget_root: String,
    pub mev_resistance_root: String,
    pub expires_at_height: u64,
    pub status: VaultRoutePlanStatus,
}

impl RoutePlanEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTE_PLAN_SCHEME,
            "plan_id": self.plan_id,
            "intent_id": self.intent_id,
            "lane": self.lane,
            "epoch": self.epoch,
            "intent_root": self.intent_root,
            "quote_root": self.quote_root,
            "pool_root": self.pool_root,
            "split_root": self.split_root,
            "hop_count": self.hop_count,
            "route_split_count_bucket": self.route_split_count_bucket,
            "route_weight_bps": self.route_weight_bps,
            "solver_diversity_bps": self.solver_diversity_bps,
            "vault_routing_quality_bps": self.vault_routing_quality_bps,
            "rebate_cover_bps": self.rebate_cover_bps,
            "liquidity_depth_bps": self.liquidity_depth_bps,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "gross_fee_bucket": self.gross_fee_bucket,
            "rebate_bucket": self.rebate_bucket,
            "net_user_fee_bps": self.net_user_fee_bps,
            "route_transcript_root": self.route_transcript_root,
            "privacy_budget_root": self.privacy_budget_root,
            "mev_resistance_root": self.mev_resistance_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("route-plan", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteSplitEntry {
    pub split_id: String,
    pub plan_id: String,
    pub quote_id: String,
    pub pool_id: String,
    pub split_nullifier: String,
    pub split_weight_bps: u64,
    pub refresh_unit_bucket: u64,
    pub rebate_bucket: u64,
    pub user_fee_bps: u64,
    pub route_position_bucket: u64,
    pub split_commitment_root: String,
    pub execution_receipt_root: String,
    pub roll_forward_root: String,
    pub expires_at_height: u64,
    pub status: SplitStatus,
}

impl RouteSplitEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.split_id.is_empty(), "route split id empty")?;
        ensure(
            !self.split_nullifier.is_empty(),
            "route split nullifier empty",
        )?;
        ensure_bps(self.split_weight_bps, "route split weight")?;
        ensure(
            self.split_weight_bps >= config.min_vault_route_split_bps,
            "route split weight below min",
        )?;
        ensure(
            self.user_fee_bps <= config.max_user_refresh_fee_bps,
            "route split user fee above max",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTE_SPLIT_SCHEME,
            "split_id": self.split_id,
            "plan_id": self.plan_id,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "split_nullifier_root": root_from_parts("route-split-nullifier", &[HashPart::Str(&self.split_nullifier)]),
            "split_weight_bps": self.split_weight_bps,
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "rebate_bucket": self.rebate_bucket,
            "user_fee_bps": self.user_fee_bps,
            "route_position_bucket": self.route_position_bucket,
            "split_commitment_root": self.split_commitment_root,
            "execution_receipt_root": self.execution_receipt_root,
            "roll_forward_root": self.roll_forward_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("route-split", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteSettlementEntry {
    pub settlement_id: String,
    pub plan_id: String,
    pub intent_id: String,
    pub split_root: String,
    pub pool_root: String,
    pub quote_root: String,
    pub settlement_nullifier: String,
    pub refresh_unit_bucket: u64,
    pub gross_fee_bucket: u64,
    pub rebate_bucket: u64,
    pub net_user_fee_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub liquidity_efficiency_bps: u64,
    pub settlement_receipt_root: String,
    pub defi_accounting_root: String,
    pub rebalance_root: String,
    pub privacy_receipt_root: String,
    pub expires_at_height: u64,
    pub status: SettlementStatus,
}

impl RouteSettlementEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.settlement_id.is_empty(), "settlement id empty")?;
        ensure(
            !self.settlement_nullifier.is_empty(),
            "settlement nullifier empty",
        )?;
        ensure(
            self.net_user_fee_bps <= config.max_user_refresh_fee_bps,
            "settlement user fee above max",
        )?;
        ensure(
            self.vault_routing_quality_bps >= config.min_vault_routing_quality_bps,
            "settlement routing quality below min",
        )?;
        ensure_bps(self.liquidity_efficiency_bps, "liquidity efficiency")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTE_SETTLEMENT_SCHEME,
            "settlement_id": self.settlement_id,
            "plan_id": self.plan_id,
            "intent_id": self.intent_id,
            "split_root": self.split_root,
            "pool_root": self.pool_root,
            "quote_root": self.quote_root,
            "settlement_nullifier_root": root_from_parts("route-settlement-nullifier", &[HashPart::Str(&self.settlement_nullifier)]),
            "refresh_unit_bucket": self.refresh_unit_bucket,
            "gross_fee_bucket": self.gross_fee_bucket,
            "rebate_bucket": self.rebate_bucket,
            "net_user_fee_bps": self.net_user_fee_bps,
            "vault_routing_quality_bps": self.vault_routing_quality_bps,
            "liquidity_efficiency_bps": self.liquidity_efficiency_bps,
            "settlement_receipt_root": self.settlement_receipt_root,
            "defi_accounting_root": self.defi_accounting_root,
            "rebalance_root": self.rebalance_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("route-settlement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqVaultRouterAttestationEntry {
    pub attestation_id: String,
    pub plan_id: String,
    pub settlement_id: String,
    pub signer_set_root: String,
    pub pq_transcript_root: String,
    pub route_integrity_root: String,
    pub spendlink_absence_root: String,
    pub pq_security_bits: u16,
    pub classical_fallback_disabled: bool,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: AttestationStatus,
}

impl PqVaultRouterAttestationEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.attestation_id.is_empty(), "attestation id empty")?;
        ensure(
            self.pq_security_bits >= config.min_pq_security_bits,
            "attestation pq bits below min",
        )?;
        ensure(
            self.classical_fallback_disabled,
            "classical fallback must remain disabled",
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTER_PQ_ATTESTATION_SCHEME,
            "attestation_id": self.attestation_id,
            "plan_id": self.plan_id,
            "settlement_id": self.settlement_id,
            "signer_set_root": self.signer_set_root,
            "pq_transcript_root": self.pq_transcript_root,
            "route_integrity_root": self.route_integrity_root,
            "spendlink_absence_root": self.spendlink_absence_root,
            "pq_security_bits": self.pq_security_bits,
            "classical_fallback_disabled": self.classical_fallback_disabled,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("pq-vault-router-attestation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeVaultRouterAuditEntry {
    pub audit_id: String,
    pub plan_id: String,
    pub settlement_id: String,
    pub measured_user_fee_bps: u64,
    pub target_user_fee_bps: u64,
    pub vault_routing_quality_bps: u64,
    pub rebate_efficiency_bps: u64,
    pub liquidity_efficiency_bps: u64,
    pub refresh_latency_blocks: u64,
    pub fee_sample_root: String,
    pub rebate_sample_root: String,
    pub route_fairness_root: String,
    pub privacy_regression_root: String,
    pub accounting_evidence_root: String,
    pub status: VaultRouterAuditStatus,
}

impl LowFeeVaultRouterAuditEntry {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure(!self.audit_id.is_empty(), "audit id empty")?;
        ensure(
            self.measured_user_fee_bps <= config.max_user_refresh_fee_bps,
            "audit fee above target",
        )?;
        ensure(
            self.target_user_fee_bps <= config.max_user_refresh_fee_bps,
            "audit target fee above max",
        )?;
        ensure(
            self.vault_routing_quality_bps >= config.min_vault_routing_quality_bps,
            "audit routing quality below min",
        )?;
        ensure_bps(self.rebate_efficiency_bps, "audit rebate efficiency")?;
        ensure_bps(self.liquidity_efficiency_bps, "audit liquidity efficiency")
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scheme": VAULT_ROUTER_AUDIT_SCHEME,
            "audit_id": self.audit_id,
            "plan_id": self.plan_id,
            "settlement_id": self.settlement_id,
            "measured_user_fee_bps": self.measured_user_fee_bps,
            "target_user_fee_bps": self.target_user_fee_bps,
            "vault_routing_quality_bps": self.vault_routing_quality_bps,
            "rebate_efficiency_bps": self.rebate_efficiency_bps,
            "liquidity_efficiency_bps": self.liquidity_efficiency_bps,
            "refresh_latency_blocks": self.refresh_latency_blocks,
            "fee_sample_root": self.fee_sample_root,
            "rebate_sample_root": self.rebate_sample_root,
            "route_fairness_root": self.route_fairness_root,
            "privacy_regression_root": self.privacy_regression_root,
            "accounting_evidence_root": self.accounting_evidence_root,
            "status": self.status,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("low-fee-vault_router-audit", &self.public_record())
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
    pub counters_root: String,
    pub route_health_root: String,
    pub low_fee_health_root: String,
    pub privacy_boundary: String,
}

impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "scheme": PUBLIC_RECORD_SCHEME,
            "record_id": self.record_id,
            "audience": self.audience,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": self.monero_height_bucket,
            "roots": self.roots.public_record(),
            "counters_root": self.counters_root,
            "route_health_root": self.route_health_root,
            "low_fee_health_root": self.low_fee_health_root,
            "privacy_boundary": self.privacy_boundary,
        })
    }

    pub fn state_root(&self) -> String {
        root_from_record("roots-only-public-record", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub route_intents: BTreeMap<String, RouteIntentEntry>,
    pub vault_router_pools: BTreeMap<String, VaultRouterPoolEntry>,
    pub vault_route_quotes: BTreeMap<String, RouteQuoteEntry>,
    pub vault_route_plans: BTreeMap<String, RoutePlanEntry>,
    pub vault_route_splits: BTreeMap<String, RouteSplitEntry>,
    pub vault_route_settlements: BTreeMap<String, RouteSettlementEntry>,
    pub pq_attestations: BTreeMap<String, PqVaultRouterAttestationEntry>,
    pub low_fee_audits: BTreeMap<String, LowFeeVaultRouterAuditEntry>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
}

impl State {
    pub fn new(config: Config, l2_height: u64, monero_height: u64, epoch: u64) -> Result<Self> {
        config.validate()?;
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Ok(Self {
            config,
            counters,
            roots,
            l2_height,
            monero_height,
            epoch,
            route_intents: BTreeMap::new(),
            vault_router_pools: BTreeMap::new(),
            vault_route_quotes: BTreeMap::new(),
            vault_route_plans: BTreeMap::new(),
            vault_route_splits: BTreeMap::new(),
            vault_route_settlements: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            low_fee_audits: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(
            Config::devnet(),
            DEVNET_L2_HEIGHT,
            DEVNET_MONERO_HEIGHT,
            DEVNET_EPOCH,
        )
        .expect("devnet vault_router_clearing config is valid");
        state.seed_devnet();
        state
    }

    pub fn insert_route_intent(&mut self, input: VaultRouteIntentInput) -> Result<String> {
        let entry = input.into_entry(&self.config)?;
        ensure(
            !self.route_intents.contains_key(&entry.intent_id),
            "route intent already exists",
        )?;
        let root = entry.state_root();
        self.counters.intents += 1;
        if entry.status.private_success() {
            self.counters.routed_refresh_units_bucket = self
                .counters
                .routed_refresh_units_bucket
                .saturating_add(entry.refresh_unit_bucket);
        }
        self.route_intents.insert(entry.intent_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_vault_router_pool(&mut self, input: VaultRouterPoolInput) -> Result<String> {
        let entry = input.into_entry(&self.config)?;
        ensure(
            !self.vault_router_pools.contains_key(&entry.pool_id),
            "vault vault_router pool already exists",
        )?;
        let root = entry.state_root();
        self.counters.pools += 1;
        self.counters.reserved_rebate_bucket = self
            .counters
            .reserved_rebate_bucket
            .saturating_add(entry.reserved_rebate_bucket);
        self.vault_router_pools.insert(entry.pool_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_route_quote(&mut self, input: VaultRouteQuoteInput) -> Result<String> {
        let entry = input.into_entry(&self.config)?;
        ensure(
            !self.vault_route_quotes.contains_key(&entry.quote_id),
            "route quote already exists",
        )?;
        ensure(
            !self.nullifiers.contains(&entry.route_nullifier),
            "route quote nullifier already used",
        )?;
        let root = entry.state_root();
        self.nullifiers.insert(entry.route_nullifier.clone());
        self.counters.quotes += 1;
        self.counters.reserved_rebate_bucket = self
            .counters
            .reserved_rebate_bucket
            .saturating_add(entry.rebate_budget_bucket);
        self.vault_route_quotes
            .insert(entry.quote_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_route_plan(&mut self, input: VaultRoutePlanInput) -> Result<String> {
        let entry = input.into_entry(&self.config)?;
        ensure(
            !self.vault_route_plans.contains_key(&entry.plan_id),
            "route plan already exists",
        )?;
        let root = entry.state_root();
        self.counters.plans += 1;
        if entry.status.success() {
            self.counters.routed_refresh_units_bucket = self
                .counters
                .routed_refresh_units_bucket
                .saturating_add(entry.refresh_unit_bucket);
        }
        self.counters.gross_user_fee_bucket = self
            .counters
            .gross_user_fee_bucket
            .saturating_add(entry.gross_fee_bucket);
        self.counters.net_user_fee_bucket = self
            .counters
            .net_user_fee_bucket
            .saturating_add(entry.gross_fee_bucket.saturating_sub(entry.rebate_bucket));
        self.vault_route_plans.insert(entry.plan_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_route_split(&mut self, entry: RouteSplitEntry) -> Result<String> {
        entry.validate(&self.config)?;
        ensure(
            !self.vault_route_splits.contains_key(&entry.split_id),
            "route split already exists",
        )?;
        ensure(
            !self.nullifiers.contains(&entry.split_nullifier),
            "route split nullifier already used",
        )?;
        let root = entry.state_root();
        self.nullifiers.insert(entry.split_nullifier.clone());
        self.counters.splits += 1;
        self.counters.reserved_rebate_bucket = self
            .counters
            .reserved_rebate_bucket
            .saturating_add(entry.rebate_bucket);
        self.vault_route_splits
            .insert(entry.split_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_route_settlement(&mut self, entry: RouteSettlementEntry) -> Result<String> {
        entry.validate(&self.config)?;
        ensure(
            !self
                .vault_route_settlements
                .contains_key(&entry.settlement_id),
            "route settlement already exists",
        )?;
        ensure(
            !self.nullifiers.contains(&entry.settlement_nullifier),
            "route settlement nullifier already used",
        )?;
        let root = entry.state_root();
        self.nullifiers.insert(entry.settlement_nullifier.clone());
        self.counters.settlements += 1;
        if entry.status == SettlementStatus::Final {
            self.counters.settled_refresh_units_bucket = self
                .counters
                .settled_refresh_units_bucket
                .saturating_add(entry.refresh_unit_bucket);
            self.counters.paid_rebate_bucket = self
                .counters
                .paid_rebate_bucket
                .saturating_add(entry.rebate_bucket);
        }
        self.vault_route_settlements
            .insert(entry.settlement_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_pq_attestation(
        &mut self,
        entry: PqVaultRouterAttestationEntry,
    ) -> Result<String> {
        entry.validate(&self.config)?;
        ensure(
            !self.pq_attestations.contains_key(&entry.attestation_id),
            "vault_router attestation already exists",
        )?;
        let root = entry.state_root();
        self.counters.attestations += 1;
        self.pq_attestations
            .insert(entry.attestation_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn insert_low_fee_audit(&mut self, entry: LowFeeVaultRouterAuditEntry) -> Result<String> {
        entry.validate(&self.config)?;
        ensure(
            !self.low_fee_audits.contains_key(&entry.audit_id),
            "vault_router audit already exists",
        )?;
        let root = entry.state_root();
        self.counters.audits += 1;
        if entry.status == VaultRouterAuditStatus::Quarantined
            || entry.status == VaultRouterAuditStatus::Regression
        {
            self.counters.quarantined_items += 1;
        }
        self.low_fee_audits.insert(entry.audit_id.clone(), entry);
        self.refresh_roots();
        Ok(root)
    }

    pub fn intake_refresh_request(&mut self, input: VaultRouteIntentInput) -> Result<String> {
        self.insert_route_intent(input)
    }

    pub fn check_decoy_quality(
        &self,
        ring_size: u16,
        decoy_pool_outputs: u64,
        decoy_entropy_bps: u64,
        spendlink_shield_bps: u64,
        refresh_utility_bps: u64,
    ) -> Result<String> {
        ensure(
            ring_size >= self.config.min_ring_size,
            "decoy ring below freshness floor",
        )?;
        ensure(
            decoy_pool_outputs >= self.config.min_decoy_pool_outputs,
            "decoy pool below freshness floor",
        )?;
        ensure_bps(decoy_entropy_bps, "decoy entropy")?;
        ensure_bps(spendlink_shield_bps, "spendlink shield")?;
        ensure_bps(refresh_utility_bps, "refresh utility")?;
        ensure(
            decoy_entropy_bps >= self.config.min_decoy_entropy_bps,
            "decoy entropy below floor",
        )?;
        ensure(
            spendlink_shield_bps >= self.config.min_spendlink_shield_bps,
            "spendlink shield below floor",
        )?;
        ensure(
            refresh_utility_bps >= self.config.min_refresh_utility_bps,
            "refresh utility below floor",
        )?;
        let record = json!({
            "scheme": "confidential-decoy-quality-check-vault-router-clearing-v1",
            "ring_size_bucket": bucket(ring_size as u64, self.config.public_bucket_size),
            "decoy_pool_outputs_bucket": bucket(decoy_pool_outputs, self.config.public_bucket_size),
            "decoy_entropy_bps": decoy_entropy_bps,
            "spendlink_shield_bps": spendlink_shield_bps,
            "refresh_utility_bps": refresh_utility_bps,
            "freshness_floor_bps": self.config.min_decoy_entropy_bps,
        });
        Ok(root_from_record("decoy-quality-check", &record))
    }

    pub fn viewtag_privacy_budget_root(
        &self,
        cohort_root: &str,
        viewtag_hint_root: &str,
        seraphis_membership_root: &str,
        jamtis_scan_budget_bps: u64,
        spendlink_leakage_budget_bps: u64,
    ) -> Result<String> {
        ensure(!cohort_root.is_empty(), "cohort root empty")?;
        ensure(!viewtag_hint_root.is_empty(), "viewtag hint root empty")?;
        ensure(
            !seraphis_membership_root.is_empty(),
            "seraphis membership root empty",
        )?;
        ensure_bps(jamtis_scan_budget_bps, "jamtis scan budget")?;
        ensure_bps(spendlink_leakage_budget_bps, "spendlink leakage budget")?;
        ensure(
            spendlink_leakage_budget_bps <= MAX_BPS - self.config.min_spendlink_shield_bps,
            "spendlink leakage budget exceeds shield allowance",
        )?;
        let record = json!({
            "scheme": "jamtis-seraphis-viewtag-privacy-budget-vault-router-clearing-v1",
            "cohort_root": cohort_root,
            "viewtag_hint_root": viewtag_hint_root,
            "seraphis_membership_root": seraphis_membership_root,
            "jamtis_scan_budget_bps": jamtis_scan_budget_bps,
            "spendlink_leakage_budget_bps": spendlink_leakage_budget_bps,
            "privacy_boundary": self.config.privacy_boundary,
        });
        Ok(root_from_record("viewtag-privacy-budget", &record))
    }

    pub fn anti_linkability_score_root(
        &self,
        cohort_root: &str,
        decoy_entropy_bps: u64,
        spendlink_shield_bps: u64,
        solver_diversity_bps: u64,
        liquidity_depth_bps: u64,
    ) -> Result<String> {
        ensure(
            !cohort_root.is_empty(),
            "anti-linkability cohort root empty",
        )?;
        ensure_bps(decoy_entropy_bps, "anti-linkability decoy entropy")?;
        ensure_bps(spendlink_shield_bps, "anti-linkability spendlink shield")?;
        ensure_bps(solver_diversity_bps, "anti-linkability solver diversity")?;
        ensure_bps(liquidity_depth_bps, "anti-linkability liquidity depth")?;
        ensure(
            decoy_entropy_bps >= self.config.min_decoy_entropy_bps,
            "anti-linkability decoy entropy below floor",
        )?;
        ensure(
            spendlink_shield_bps >= self.config.min_spendlink_shield_bps,
            "anti-linkability spendlink shield below floor",
        )?;
        ensure(
            solver_diversity_bps >= self.config.min_solver_diversity_bps,
            "anti-linkability solver diversity below floor",
        )?;
        ensure(
            liquidity_depth_bps >= self.config.min_liquidity_depth_bps,
            "anti-linkability liquidity below floor",
        )?;
        let blended_score_bps = decoy_entropy_bps
            .saturating_add(spendlink_shield_bps)
            .saturating_add(solver_diversity_bps)
            .saturating_add(liquidity_depth_bps)
            / 4;
        let record = json!({
            "scheme": "anti-linkability-score-vault-router-clearing-v1",
            "cohort_root": cohort_root,
            "decoy_entropy_bps": decoy_entropy_bps,
            "spendlink_shield_bps": spendlink_shield_bps,
            "solver_diversity_bps": solver_diversity_bps,
            "liquidity_depth_bps": liquidity_depth_bps,
            "blended_score_bps": blended_score_bps,
        });
        Ok(root_from_record("anti-linkability-score", &record))
    }

    pub fn run_clearing_round(
        &mut self,
        round_id: impl Into<String>,
        cohort_root: impl Into<String>,
        quote_root: impl Into<String>,
        plan_root: impl Into<String>,
        clearing_quality_bps: u64,
    ) -> Result<String> {
        let round_id = round_id.into();
        let cohort_root = cohort_root.into();
        let quote_root = quote_root.into();
        let plan_root = plan_root.into();
        ensure(!round_id.is_empty(), "clearing round id empty")?;
        ensure(!cohort_root.is_empty(), "clearing cohort root empty")?;
        ensure(!quote_root.is_empty(), "clearing quote root empty")?;
        ensure(!plan_root.is_empty(), "clearing plan root empty")?;
        ensure_bps(clearing_quality_bps, "clearing quality")?;
        ensure(
            clearing_quality_bps >= self.config.min_vault_routing_quality_bps,
            "clearing quality below vault routing floor",
        )?;
        let record = json!({
            "scheme": "confidential-refresh-cohort-vault-router-clearing-round-v1",
            "round_id": round_id,
            "epoch": self.epoch,
            "l2_height": self.l2_height,
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "cohort_root": cohort_root,
            "quote_root": quote_root,
            "plan_root": plan_root,
            "clearing_quality_bps": clearing_quality_bps,
            "vault_router_pool_root": self.roots.vault_router_pool_root,
            "nullifier_root": self.roots.nullifier_root,
        });
        let root = root_from_record("clearing-round", &record);
        self.refresh_roots();
        Ok(root)
    }

    pub fn debit_rebate_vault(
        &mut self,
        vault_id: &str,
        debit_bucket: u64,
        reason_root: &str,
    ) -> Result<String> {
        ensure(!vault_id.is_empty(), "rebate vault id empty")?;
        ensure(debit_bucket > 0, "rebate vault debit empty")?;
        ensure(!reason_root.is_empty(), "rebate vault debit reason empty")?;
        ensure(
            self.counters.reserved_rebate_bucket >= debit_bucket,
            "rebate vault debit exceeds reserved bucket",
        )?;
        self.counters.reserved_rebate_bucket = self
            .counters
            .reserved_rebate_bucket
            .saturating_sub(debit_bucket);
        self.counters.paid_rebate_bucket = self
            .counters
            .paid_rebate_bucket
            .saturating_add(debit_bucket);
        let record = json!({
            "scheme": "private-rebate-vault-clearing-debit-v1",
            "vault_id": vault_id,
            "debit_bucket": debit_bucket,
            "reason_root": reason_root,
            "paid_rebate_bucket": self.counters.paid_rebate_bucket,
        });
        self.refresh_roots();
        Ok(root_from_record("rebate-vault-debit", &record))
    }

    pub fn credit_rebate_vault(
        &mut self,
        vault_id: &str,
        credit_bucket: u64,
        source_root: &str,
    ) -> Result<String> {
        ensure(!vault_id.is_empty(), "rebate vault id empty")?;
        ensure(credit_bucket > 0, "rebate vault credit empty")?;
        ensure(!source_root.is_empty(), "rebate vault credit source empty")?;
        self.counters.reserved_rebate_bucket = self
            .counters
            .reserved_rebate_bucket
            .saturating_add(credit_bucket);
        let record = json!({
            "scheme": "private-rebate-vault-clearing-credit-v1",
            "vault_id": vault_id,
            "credit_bucket": credit_bucket,
            "source_root": source_root,
            "reserved_rebate_bucket": self.counters.reserved_rebate_bucket,
        });
        self.refresh_roots();
        Ok(root_from_record("rebate-vault-credit", &record))
    }

    pub fn apply_low_fee_rebate(
        &mut self,
        gross_fee_bucket: u64,
        rebate_bucket: u64,
        rebate_policy_root: &str,
    ) -> Result<String> {
        ensure(gross_fee_bucket > 0, "gross fee bucket empty")?;
        ensure(
            rebate_bucket <= gross_fee_bucket,
            "rebate exceeds gross fee",
        )?;
        ensure(!rebate_policy_root.is_empty(), "rebate policy root empty")?;
        let effective_fee_bps = ratio_bps(
            gross_fee_bucket.saturating_sub(rebate_bucket),
            gross_fee_bucket,
        );
        ensure(
            effective_fee_bps <= self.config.max_user_refresh_fee_bps,
            "effective user refresh fee above max",
        )?;
        self.counters.gross_user_fee_bucket = self
            .counters
            .gross_user_fee_bucket
            .saturating_add(gross_fee_bucket);
        self.counters.net_user_fee_bucket = self
            .counters
            .net_user_fee_bucket
            .saturating_add(gross_fee_bucket.saturating_sub(rebate_bucket));
        self.counters.paid_rebate_bucket = self
            .counters
            .paid_rebate_bucket
            .saturating_add(rebate_bucket);
        let record = json!({
            "scheme": "low-fee-refresh-rebate-vault-router-clearing-v1",
            "gross_fee_bucket": gross_fee_bucket,
            "rebate_bucket": rebate_bucket,
            "effective_fee_bps": effective_fee_bps,
            "rebate_policy_root": rebate_policy_root,
        });
        self.refresh_roots();
        Ok(root_from_record("low-fee-rebate", &record))
    }

    pub fn quarantine_clearing_item(
        &mut self,
        item_id: &str,
        item_root: &str,
        reason_root: &str,
    ) -> Result<String> {
        ensure(!item_id.is_empty(), "quarantine item id empty")?;
        ensure(!item_root.is_empty(), "quarantine item root empty")?;
        ensure(!reason_root.is_empty(), "quarantine reason root empty")?;
        self.counters.quarantined_items = self.counters.quarantined_items.saturating_add(1);
        let quarantine_nullifier = root_from_parts(
            "quarantine-nullifier",
            &[
                HashPart::Str(item_id),
                HashPart::Str(item_root),
                HashPart::Str(reason_root),
            ],
        );
        self.nullifiers.insert(quarantine_nullifier.clone());
        let record = json!({
            "scheme": "privacy-preserving-vault-router-clearing-quarantine-v1",
            "item_id": item_id,
            "item_root": item_root,
            "reason_root": reason_root,
            "quarantine_nullifier_root": root_from_parts("quarantine-nullifier-root", &[HashPart::Str(&quarantine_nullifier)]),
            "quarantined_items": self.counters.quarantined_items,
        });
        self.refresh_roots();
        Ok(root_from_record("clearing-quarantine", &record))
    }

    pub fn publish_roots_only_record(
        &mut self,
        record_id: impl Into<String>,
        audience: PublicAudience,
    ) -> Result<String> {
        let record_id = record_id.into();
        ensure(!record_id.is_empty(), "public record id empty")?;
        ensure(
            !self.public_records.contains_key(&record_id),
            "public record already exists",
        )?;
        self.refresh_roots();
        let record = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            audience,
            epoch: self.epoch,
            l2_height: self.l2_height,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            roots: self.roots.clone(),
            counters_root: self.counters.state_root(),
            route_health_root: self.route_health_root(),
            low_fee_health_root: self.low_fee_health_root(),
            privacy_boundary: self.config.privacy_boundary.clone(),
        };
        let root = record.state_root();
        self.counters.public_records += 1;
        self.public_records.insert(record_id, record);
        self.refresh_roots();
        Ok(root)
    }

    pub fn expire_height_sensitive_entries(&mut self, monero_height: u64) -> u64 {
        self.monero_height = monero_height;
        let mut expired = 0_u64;
        for intent in self.route_intents.values_mut() {
            if intent.expires_at_height <= monero_height && intent.status.routable() {
                intent.status = VaultRouteIntentStatus::Expired;
                expired += 1;
            }
        }
        for quote in self.vault_route_quotes.values_mut() {
            if quote.expires_at_height <= monero_height && quote.status.active() {
                quote.status = VaultRouteQuoteStatus::Expired;
                expired += 1;
            }
        }
        for plan in self.vault_route_plans.values_mut() {
            if plan.expires_at_height <= monero_height
                && matches!(
                    plan.status,
                    VaultRoutePlanStatus::Draft
                        | VaultRoutePlanStatus::Scored
                        | VaultRoutePlanStatus::Reserved
                        | VaultRoutePlanStatus::Split
                        | VaultRoutePlanStatus::Executing
                )
            {
                plan.status = VaultRoutePlanStatus::Expired;
                expired += 1;
            }
        }
        for split in self.vault_route_splits.values_mut() {
            if split.expires_at_height <= monero_height
                && matches!(
                    split.status,
                    SplitStatus::Created | SplitStatus::Reserved | SplitStatus::Proved
                )
            {
                split.status = SplitStatus::Expired;
                expired += 1;
            }
        }
        self.counters.expired_items = self.counters.expired_items.saturating_add(expired);
        self.refresh_roots();
        expired
    }

    pub fn route_health_root(&self) -> String {
        let record = json!({
            "routed_refresh_units_bucket": self.counters.routed_refresh_units_bucket,
            "settled_refresh_units_bucket": self.counters.settled_refresh_units_bucket,
            "reserved_rebate_bucket": self.counters.reserved_rebate_bucket,
            "paid_rebate_bucket": self.counters.paid_rebate_bucket,
            "solver_diversity_floor_bps": self.config.min_solver_diversity_bps,
            "routing_quality_floor_bps": self.config.min_vault_routing_quality_bps,
            "max_vault_route_hops": self.config.max_vault_route_hops,
        });
        root_from_record("route-health", &record)
    }

    pub fn low_fee_health_root(&self) -> String {
        let effective_fee_bps = ratio_bps(
            self.counters.net_user_fee_bucket,
            self.counters.gross_user_fee_bucket.max(1),
        );
        let record = json!({
            "max_user_refresh_fee_bps": self.config.max_user_refresh_fee_bps,
            "effective_fee_ratio_bps": effective_fee_bps,
            "gross_user_fee_bucket": self.counters.gross_user_fee_bucket,
            "net_user_fee_bucket": self.counters.net_user_fee_bucket,
            "paid_rebate_bucket": self.counters.paid_rebate_bucket,
        });
        root_from_record("low-fee-health", &record)
    }

    pub fn state_root(&self) -> String {
        root_from_parts(
            "state",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.roots.state_root()),
                HashPart::U64(self.l2_height),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.epoch),
            ],
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "state_root": self.state_root(),
            "l2_height": self.l2_height,
            "monero_height_bucket": bucket(self.monero_height, self.config.public_bucket_size),
            "epoch": self.epoch,
            "config_root": self.config.state_root(),
            "counters_root": self.counters.state_root(),
            "roots": self.roots.public_record(),
            "route_health_root": self.route_health_root(),
            "low_fee_health_root": self.low_fee_health_root(),
            "privacy_boundary": self.config.privacy_boundary,
        })
    }

    fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            route_intent_root: map_root(
                "route-intents",
                self.route_intents
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            vault_router_pool_root: map_root(
                "vault_router-pools",
                self.vault_router_pools
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            route_quote_root: map_root(
                "route-quotes",
                self.vault_route_quotes
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            route_plan_root: map_root(
                "route-plans",
                self.vault_route_plans
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            route_split_root: map_root(
                "route-splits",
                self.vault_route_splits
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            route_settlement_root: map_root(
                "route-settlements",
                self.vault_route_settlements
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            pq_attestation_root: map_root(
                "pq-attestations",
                self.pq_attestations
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            low_fee_audit_root: map_root(
                "low-fee-audits",
                self.low_fee_audits
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
            nullifier_root: set_root("nullifiers", &self.nullifiers),
            public_record_root: map_root(
                "public-records",
                self.public_records
                    .iter()
                    .map(|(id, entry)| (id.as_str(), entry.state_root())),
            ),
        };
    }

    fn seed_devnet(&mut self) {
        let intent_id = "rebate-vault_router_clearing-intent-devnet-0".to_string();
        let pool_id = "rebate-vault_router_clearing-pool-devnet-0".to_string();
        let quote_id = "rebate-vault_router_clearing-quote-devnet-0".to_string();
        let plan_id = "rebate-vault_router_clearing-plan-devnet-0".to_string();
        let split_id = "rebate-vault_router_clearing-split-devnet-0".to_string();
        let settlement_id = "rebate-vault_router_clearing-settlement-devnet-0".to_string();

        self.insert_route_intent(VaultRouteIntentInput {
            intent_id: intent_id.clone(),
            lane: VaultRouterLane::DexSwap,
            epoch: self.epoch,
            monero_height_bucket: bucket(self.monero_height, self.config.public_bucket_size),
            output_count_bucket: self.config.target_decoy_pool_outputs,
            ring_size: self.config.target_ring_size,
            refresh_unit_bucket: 12_288,
            max_user_fee_bps: 2,
            decoy_entropy_bps: 9_520,
            spendlink_shield_bps: 9_430,
            refresh_utility_bps: 9_160,
            decoy_pool_root: root_from_parts(
                "devnet-vault_router-decoy-pool",
                &[HashPart::Str(&intent_id)],
            ),
            spendlink_shield_root: root_from_parts(
                "devnet-vault_router-spendlink-shield",
                &[HashPart::Str(&intent_id)],
            ),
            refresh_plan_hint_root: root_from_parts(
                "devnet-vault_router-refresh-hint",
                &[HashPart::Str(&intent_id)],
            ),
            rebate_preference_root: root_from_parts(
                "devnet-vault_router-rebate-preference",
                &[HashPart::Str(&intent_id)],
            ),
            routing_constraint_root: root_from_parts(
                "devnet-vault_router-constraints",
                &[HashPart::Str(&intent_id)],
            ),
            expires_at_height: self.monero_height + self.config.intent_ttl_blocks,
            status: VaultRouteIntentStatus::Routed,
        })
        .expect("devnet route intent inserts");

        self.insert_vault_router_pool(VaultRouterPoolInput {
            pool_id: pool_id.clone(),
            provider_bucket: "devnet-vault_router-provider-bucket-0".to_string(),
            lane: VaultRouterLane::DexSwap,
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            vault_route_asset_id: self.config.vault_route_asset_id.clone(),
            available_rebate_bucket: 24_576,
            reserved_rebate_bucket: 512,
            refresh_unit_capacity_bucket: 131_072,
            max_user_fee_bps: 2,
            rebate_cover_bps: 9_880,
            solvency_bps: 9_940,
            liquidity_depth_bps: 9_760,
            solver_diversity_bps: 8_320,
            pool_commitment_root: root_from_parts(
                "devnet-vault_router-pool",
                &[HashPart::Str(&pool_id)],
            ),
            liquidity_policy_root: root_from_parts(
                "devnet-vault_router-liquidity-policy",
                &[HashPart::Str(&pool_id)],
            ),
            rebalance_proof_root: root_from_parts(
                "devnet-vault_router-rebalance",
                &[HashPart::Str(&pool_id)],
            ),
            mev_resistance_root: root_from_parts(
                "devnet-vault_router-pool-mev",
                &[HashPart::Str(&pool_id)],
            ),
            status: VaultRouterPoolStatus::Rebalanced,
        })
        .expect("devnet vault vault_router pool inserts");

        self.insert_route_quote(VaultRouteQuoteInput {
            quote_id: quote_id.clone(),
            pool_id: pool_id.clone(),
            solver_bucket: "devnet-vault_router-solver-bucket-0".to_string(),
            route_nullifier: "devnet-private-route-quote-nullifier-0".to_string(),
            fee_asset_id: self.config.fee_asset_id.clone(),
            rebate_asset_id: self.config.rebate_asset_id.clone(),
            max_user_fee_bps: 2,
            route_rebate_bps: 90,
            rebate_cover_bps: 9_880,
            vault_routing_quality_bps: 9_420,
            liquidity_depth_bps: 9_760,
            refresh_unit_budget_bucket: 98_304,
            rebate_budget_bucket: 512,
            quote_commitment_root: root_from_parts(
                "devnet-vault_router-quote-commitment",
                &[HashPart::Str(&quote_id)],
            ),
            solver_policy_root: root_from_parts(
                "devnet-vault_router-solver-policy",
                &[HashPart::Str(&quote_id)],
            ),
            route_cost_curve_root: root_from_parts(
                "devnet-vault_router-cost-curve",
                &[HashPart::Str(&quote_id)],
            ),
            liquidity_reservation_root: root_from_parts(
                "devnet-vault_router-liquidity-reservation",
                &[HashPart::Str(&quote_id)],
            ),
            expires_at_height: self.monero_height + self.config.route_quote_ttl_blocks,
            status: VaultRouteQuoteStatus::Filled,
        })
        .expect("devnet route quote inserts");

        let intent_root = self.route_intents[&intent_id].state_root();
        let quote_root = self.vault_route_quotes[&quote_id].state_root();
        let pool_root = self.vault_router_pools[&pool_id].state_root();
        self.insert_route_plan(VaultRoutePlanInput {
            plan_id: plan_id.clone(),
            intent_id: intent_id.clone(),
            lane: VaultRouterLane::DexSwap,
            epoch: self.epoch,
            intent_root,
            quote_root,
            pool_root,
            split_root: root_from_parts(
                "devnet-vault_router-planned-splits",
                &[HashPart::Str(&plan_id)],
            ),
            hop_count: 3,
            route_split_count_bucket: 4,
            route_weight_bps: 10_000,
            solver_diversity_bps: 8_320,
            vault_routing_quality_bps: 9_420,
            rebate_cover_bps: 9_880,
            liquidity_depth_bps: 9_760,
            refresh_unit_bucket: 12_288,
            gross_fee_bucket: 36,
            rebate_bucket: 12,
            net_user_fee_bps: 2,
            route_transcript_root: root_from_parts(
                "devnet-vault_router-transcript",
                &[HashPart::Str(&plan_id)],
            ),
            privacy_budget_root: root_from_parts(
                "devnet-vault_router-privacy-budget",
                &[HashPart::Str(&plan_id)],
            ),
            mev_resistance_root: root_from_parts(
                "devnet-vault_router-mev",
                &[HashPart::Str(&plan_id)],
            ),
            expires_at_height: self.monero_height + self.config.route_plan_ttl_blocks,
            status: VaultRoutePlanStatus::Settled,
        })
        .expect("devnet route plan inserts");

        self.insert_route_split(RouteSplitEntry {
            split_id: split_id.clone(),
            plan_id: plan_id.clone(),
            quote_id: quote_id.clone(),
            pool_id: pool_id.clone(),
            split_nullifier: "devnet-private-route-split-nullifier-0".to_string(),
            split_weight_bps: 10_000,
            refresh_unit_bucket: 12_288,
            rebate_bucket: 12,
            user_fee_bps: 2,
            route_position_bucket: 0,
            split_commitment_root: root_from_parts(
                "devnet-vault_router-split-commitment",
                &[HashPart::Str(&split_id)],
            ),
            execution_receipt_root: root_from_parts(
                "devnet-vault_router-split-execution",
                &[HashPart::Str(&split_id)],
            ),
            roll_forward_root: root_from_parts(
                "devnet-vault_router-split-roll-forward",
                &[HashPart::Str(&split_id)],
            ),
            expires_at_height: self.monero_height + self.config.settlement_ttl_blocks,
            status: SplitStatus::Executed,
        })
        .expect("devnet route split inserts");

        self.insert_route_settlement(RouteSettlementEntry {
            settlement_id: settlement_id.clone(),
            plan_id: plan_id.clone(),
            intent_id: intent_id.clone(),
            split_root: map_root(
                "devnet-vault_router-settlement-splits",
                [(
                    &split_id as &str,
                    self.vault_route_splits[&split_id].state_root(),
                )],
            ),
            pool_root: map_root(
                "devnet-vault_router-settlement-pools",
                [(
                    &pool_id as &str,
                    self.vault_router_pools[&pool_id].state_root(),
                )],
            ),
            quote_root: map_root(
                "devnet-vault_router-settlement-quotes",
                [(
                    &quote_id as &str,
                    self.vault_route_quotes[&quote_id].state_root(),
                )],
            ),
            settlement_nullifier: "devnet-private-route-settlement-nullifier-0".to_string(),
            refresh_unit_bucket: 12_288,
            gross_fee_bucket: 36,
            rebate_bucket: 12,
            net_user_fee_bps: 2,
            vault_routing_quality_bps: 9_420,
            liquidity_efficiency_bps: 9_510,
            settlement_receipt_root: root_from_parts(
                "devnet-vault_router-settlement-receipt",
                &[HashPart::Str(&settlement_id)],
            ),
            defi_accounting_root: root_from_parts(
                "devnet-vault_router-defi-accounting",
                &[HashPart::Str(&settlement_id)],
            ),
            rebalance_root: root_from_parts(
                "devnet-vault_router-settlement-rebalance",
                &[HashPart::Str(&settlement_id)],
            ),
            privacy_receipt_root: root_from_parts(
                "devnet-vault_router-privacy-receipt",
                &[HashPart::Str(&settlement_id)],
            ),
            expires_at_height: self.monero_height + self.config.settlement_ttl_blocks,
            status: SettlementStatus::Final,
        })
        .expect("devnet route settlement inserts");

        self.insert_pq_attestation(PqVaultRouterAttestationEntry {
            attestation_id: "pq-refresh-rebate-vault-router-attestation-devnet-0".to_string(),
            plan_id: plan_id.clone(),
            settlement_id: settlement_id.clone(),
            signer_set_root: root_from_parts(
                "devnet-vault_router-pq-signers",
                &[HashPart::Str("0")],
            ),
            pq_transcript_root: root_from_parts(
                "devnet-vault_router-pq-transcript",
                &[HashPart::Str(&settlement_id)],
            ),
            route_integrity_root: root_from_parts(
                "devnet-vault_router-integrity",
                &[HashPart::Str(&settlement_id)],
            ),
            spendlink_absence_root: root_from_parts(
                "devnet-vault_router-spendlink-absence",
                &[HashPart::Str(&settlement_id)],
            ),
            pq_security_bits: self.config.target_pq_security_bits,
            classical_fallback_disabled: true,
            attested_at_height: self.monero_height + 12,
            expires_at_height: self.monero_height + self.config.attestation_ttl_blocks,
            status: AttestationStatus::StrongQuorum,
        })
        .expect("devnet pq vault_router attestation inserts");

        self.insert_low_fee_audit(LowFeeVaultRouterAuditEntry {
            audit_id: "refresh-rebate-vault-router-low-fee-audit-devnet-0".to_string(),
            plan_id,
            settlement_id,
            measured_user_fee_bps: 2,
            target_user_fee_bps: self.config.max_user_refresh_fee_bps,
            vault_routing_quality_bps: 9_420,
            rebate_efficiency_bps: 9_360,
            liquidity_efficiency_bps: 9_510,
            refresh_latency_blocks: 9,
            fee_sample_root: root_from_parts(
                "devnet-vault_router-fee-samples",
                &[HashPart::Str("0")],
            ),
            rebate_sample_root: root_from_parts(
                "devnet-vault_router-rebate-samples",
                &[HashPart::Str("0")],
            ),
            route_fairness_root: root_from_parts(
                "devnet-vault_router-fairness",
                &[HashPart::Str("0")],
            ),
            privacy_regression_root: root_from_parts(
                "devnet-vault_router-privacy-regression",
                &[HashPart::Str("0")],
            ),
            accounting_evidence_root: root_from_parts(
                "devnet-vault_router-accounting-evidence",
                &[HashPart::Str("0")],
            ),
            status: VaultRouterAuditStatus::Accepted,
        })
        .expect("devnet low fee vault_router audit inserts");

        self.publish_roots_only_record(
            "roots-only-refresh-rebate-vault-router-public-record-devnet-0",
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

fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(MAX_BPS) / denominator
    }
}

fn empty_root(domain: &str) -> String {
    root_from_parts(domain, &[HashPart::Str("empty")])
}

fn root_from_record(domain: &str, record: &Value) -> String {
    root_from_parts(domain, &[HashPart::Json(record)])
}

fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(&format!("{STATE_ROOT_DOMAIN}-{domain}"), parts, 32)
}

fn map_root<'a>(domain: &str, entries: impl IntoIterator<Item = (&'a str, String)>) -> String {
    let leaves = entries
        .into_iter()
        .map(|(id, root)| json!({ "id": id, "root": root }))
        .collect::<Vec<_>>();
    if leaves.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
    }
}

fn set_root(domain: &str, entries: &BTreeSet<String>) -> String {
    let leaves = entries
        .iter()
        .map(|id| json!({ "id": id }))
        .collect::<Vec<_>>();
    if leaves.is_empty() {
        empty_root(domain)
    } else {
        merkle_root(&format!("{STATE_ROOT_DOMAIN}-{domain}"), &leaves)
    }
}
