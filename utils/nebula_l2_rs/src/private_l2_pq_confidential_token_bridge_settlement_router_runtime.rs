use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-token-bridge-settlement-router-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_BRIDGE_SETTLEMENT_ROUTER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-bridge-router-v1";
pub const CONFIDENTIAL_PROOF_SUITE: &str =
    "RingCT-amount-conservation+membership-nullifier+route-balance-v1";
pub const MONERO_PAIRING_SUITE: &str = "monero-view-key-output-key-image-pairing-root-v1";
pub const COVENANT_SUITE: &str = "private-l2-confidential-token-covenant-check-root-v1";
pub const INVENTORY_SUITE: &str = "confidential-token-bridge-liquidity-inventory-root-v1";
pub const NETTING_SUITE: &str = "deterministic-confidential-mint-burn-netting-root-v1";
pub const SPONSOR_SUITE: &str = "low-fee-confidential-bridge-fee-sponsor-link-root-v1";
pub const PUBLIC_RECORD_SUITE: &str = "roots-only-bridge-settlement-router-public-record-v1";
pub const DEVNET_L2_HEIGHT: u64 = 1_836_000;
pub const DEVNET_MONERO_HEIGHT: u64 = 3_584_000;
pub const DEVNET_ROUTER_ID: &str =
    "private-l2-pq-confidential-token-bridge-settlement-router-devnet";
pub const DEVNET_REPLAY_DOMAIN: &str =
    "nebula-private-l2-pq-confidential-token-bridge-settlement-router-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_ROUTE_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_PAIRING_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_NETTING_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_MAX_ROUTER_FEE_BPS: u64 = 12;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_100;
pub const DEFAULT_MIN_INVENTORY_HEADROOM_BPS: u64 = 250;
pub const DEFAULT_MAX_ROUTE_HOPS: usize = 8;
pub const DEFAULT_MAX_INTENTS_PER_NETTING: usize = 4_096;
pub const DEFAULT_MAX_MONERO_CONFIRMATION_GAP: u64 = 24;
pub const DEFAULT_REPLAY_GRACE_BLOCKS: u64 = 8_640;
pub const MAX_ASSETS: usize = 262_144;
pub const MAX_INTENTS: usize = 1_048_576;
pub const MAX_DEPENDENCIES: usize = 2_097_152;
pub const MAX_INVENTORIES: usize = 262_144;
pub const MAX_COVENANTS: usize = 524_288;
pub const MAX_PAIRINGS: usize = 1_048_576;
pub const MAX_ROUTES: usize = 1_048_576;
pub const MAX_NETTINGS: usize = 262_144;
pub const MAX_SPONSORS: usize = 524_288;
pub const MAX_REPLAY_KEYS: usize = 4_194_304;
pub const MAX_ACCOUNTING_BUCKETS: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainKind {
    NebulaL2,
    MoneroMainnet,
    MoneroDevnet,
    Ethereum,
    Bitcoin,
    Solana,
    Cosmos,
    Arbitrum,
    Optimism,
    Polygon,
    ExternalPrivateRuntime,
}

impl ChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NebulaL2 => "nebula_l2",
            Self::MoneroMainnet => "monero_mainnet",
            Self::MoneroDevnet => "monero_devnet",
            Self::Ethereum => "ethereum",
            Self::Bitcoin => "bitcoin",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Arbitrum => "arbitrum",
            Self::Optimism => "optimism",
            Self::Polygon => "polygon",
            Self::ExternalPrivateRuntime => "external_private_runtime",
        }
    }

    pub fn is_monero(self) -> bool {
        matches!(self, Self::MoneroMainnet | Self::MoneroDevnet)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeIntentKind {
    ShieldedMint,
    ShieldedBurn,
    MintThenSwap,
    SwapThenBurn,
    ReserveRebalance,
    EmergencyExit,
    SponsorFeeOnly,
}

impl BridgeIntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedMint => "shielded_mint",
            Self::ShieldedBurn => "shielded_burn",
            Self::MintThenSwap => "mint_then_swap",
            Self::SwapThenBurn => "swap_then_burn",
            Self::ReserveRebalance => "reserve_rebalance",
            Self::EmergencyExit => "emergency_exit",
            Self::SponsorFeeOnly => "sponsor_fee_only",
        }
    }

    pub fn mints(self) -> bool {
        matches!(
            self,
            Self::ShieldedMint | Self::MintThenSwap | Self::ReserveRebalance
        )
    }

    pub fn burns(self) -> bool {
        matches!(
            self,
            Self::ShieldedBurn | Self::SwapThenBurn | Self::EmergencyExit
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Sealed,
    Admitted,
    DependencyLocked,
    Paired,
    CovenantChecked,
    Routed,
    Netted,
    Settled,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Admitted => "admitted",
            Self::DependencyLocked => "dependency_locked",
            Self::Paired => "paired",
            Self::CovenantChecked => "covenant_checked",
            Self::Routed => "routed",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Sealed
                | Self::Admitted
                | Self::DependencyLocked
                | Self::Paired
                | Self::CovenantChecked
                | Self::Routed
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    AssetRegistryRoot,
    MintBurnAuditorRoot,
    BatchNettingRoot,
    ContractReceiptRoot,
    ReserveAttestationRoot,
    CovenantHookRoot,
    SponsorPolicyRoot,
    LiquidityInventoryRoot,
}

impl DependencyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AssetRegistryRoot => "asset_registry_root",
            Self::MintBurnAuditorRoot => "mint_burn_auditor_root",
            Self::BatchNettingRoot => "batch_netting_root",
            Self::ContractReceiptRoot => "contract_receipt_root",
            Self::ReserveAttestationRoot => "reserve_attestation_root",
            Self::CovenantHookRoot => "covenant_hook_root",
            Self::SponsorPolicyRoot => "sponsor_policy_root",
            Self::LiquidityInventoryRoot => "liquidity_inventory_root",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyStatus {
    Posted,
    Locked,
    Consumed,
    Revoked,
    Expired,
}

impl DependencyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Locked => "locked",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Posted | Self::Locked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryStatus {
    Active,
    Constrained,
    Draining,
    Paused,
    Frozen,
}

impl InventoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Constrained => "constrained",
            Self::Draining => "draining",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
        }
    }

    pub fn can_route(self) -> bool {
        matches!(self, Self::Active | Self::Constrained | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantVerdict {
    Pass,
    PassWithLimit,
    SponsorRequired,
    Quarantine,
    Reject,
}

impl CovenantVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::PassWithLimit => "pass_with_limit",
            Self::SponsorRequired => "sponsor_required",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
        }
    }

    pub fn accepts_route(self) -> bool {
        matches!(
            self,
            Self::Pass | Self::PassWithLimit | Self::SponsorRequired
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingStatus {
    Observed,
    Confirmed,
    Matched,
    Consumed,
    Disputed,
    Expired,
}

impl PairingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Confirmed => "confirmed",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Observed | Self::Confirmed | Self::Matched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Proposed,
    InventoryReserved,
    SponsorLinked,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::InventoryReserved => "inventory_reserved",
            Self::SponsorLinked => "sponsor_linked",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NettingStatus {
    Built,
    DependencyChecked,
    InventoryBalanced,
    SettlementReady,
    Settled,
    Disputed,
    Expired,
}

impl NettingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::DependencyChecked => "dependency_checked",
            Self::InventoryBalanced => "inventory_balanced",
            Self::SettlementReady => "settlement_ready",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Offered,
    Linked,
    Applied,
    Reimbursed,
    Revoked,
    Expired,
}

impl SponsorStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Linked => "linked",
            Self::Applied => "applied",
            Self::Reimbursed => "reimbursed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Offered | Self::Linked)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    Intent,
    Dependency,
    Inventory,
    Covenant,
    MoneroPairing,
    Route,
    NettingBatch,
    SponsorLink,
    ReplayKey,
    Accounting,
    Settlement,
}

impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Dependency => "dependency",
            Self::Inventory => "inventory",
            Self::Covenant => "covenant",
            Self::MoneroPairing => "monero_pairing",
            Self::Route => "route",
            Self::NettingBatch => "netting_batch",
            Self::SponsorLink => "sponsor_link",
            Self::ReplayKey => "replay_key",
            Self::Accounting => "accounting",
            Self::Settlement => "settlement",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub router_id: String,
    pub protocol_version: String,
    pub replay_domain: String,
    pub fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub intent_ttl_blocks: u64,
    pub route_ttl_blocks: u64,
    pub pairing_ttl_blocks: u64,
    pub netting_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub max_user_fee_bps: u64,
    pub max_router_fee_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub min_inventory_headroom_bps: u64,
    pub max_route_hops: usize,
    pub max_intents_per_netting: usize,
    pub max_monero_confirmation_gap: u64,
    pub replay_grace_blocks: u64,
    pub require_monero_pairing: bool,
    pub require_covenant_check: bool,
    pub require_dependency_lock: bool,
    pub allow_fee_sponsorship: bool,
    pub allow_cross_runtime_dependencies: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            router_id: DEVNET_ROUTER_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            replay_domain: DEVNET_REPLAY_DOMAIN.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            route_ttl_blocks: DEFAULT_ROUTE_TTL_BLOCKS,
            pairing_ttl_blocks: DEFAULT_PAIRING_TTL_BLOCKS,
            netting_ttl_blocks: DEFAULT_NETTING_TTL_BLOCKS,
            sponsor_ttl_blocks: DEFAULT_SPONSOR_TTL_BLOCKS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            max_router_fee_bps: DEFAULT_MAX_ROUTER_FEE_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            min_inventory_headroom_bps: DEFAULT_MIN_INVENTORY_HEADROOM_BPS,
            max_route_hops: DEFAULT_MAX_ROUTE_HOPS,
            max_intents_per_netting: DEFAULT_MAX_INTENTS_PER_NETTING,
            max_monero_confirmation_gap: DEFAULT_MAX_MONERO_CONFIRMATION_GAP,
            replay_grace_blocks: DEFAULT_REPLAY_GRACE_BLOCKS,
            require_monero_pairing: true,
            require_covenant_check: true,
            require_dependency_lock: true,
            allow_fee_sponsorship: true,
            allow_cross_runtime_dependencies: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("router_id", &self.router_id)?;
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("replay_domain", &self.replay_domain)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("max_router_fee_bps", self.max_router_fee_bps)?;
        require(
            self.min_reserve_coverage_bps >= MAX_BPS,
            "min_reserve_coverage_bps must cover liabilities",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min_privacy_set_size must be positive",
        )?;
        require(
            self.min_pq_security_bits >= 192,
            "min_pq_security_bits must be at least 192",
        )?;
        require(
            self.intent_ttl_blocks > 0,
            "intent_ttl_blocks must be positive",
        )?;
        require(
            self.route_ttl_blocks > 0,
            "route_ttl_blocks must be positive",
        )?;
        require(
            self.pairing_ttl_blocks > 0,
            "pairing_ttl_blocks must be positive",
        )?;
        require(
            self.netting_ttl_blocks > 0,
            "netting_ttl_blocks must be positive",
        )?;
        require(
            self.sponsor_ttl_blocks > 0,
            "sponsor_ttl_blocks must be positive",
        )?;
        require(self.max_route_hops > 0, "max_route_hops must be positive")?;
        require(
            self.max_intents_per_netting > 0,
            "max_intents_per_netting must be positive",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_intent_index: u64,
    pub next_dependency_index: u64,
    pub next_inventory_index: u64,
    pub next_covenant_index: u64,
    pub next_pairing_index: u64,
    pub next_route_index: u64,
    pub next_netting_index: u64,
    pub next_sponsor_index: u64,
    pub next_public_record_index: u64,
    pub intents_admitted: u64,
    pub intents_settled: u64,
    pub intents_rejected: u64,
    pub replay_rejections: u64,
    pub nettings_settled: u64,
    pub total_minted_units: u128,
    pub total_burned_units: u128,
    pub total_router_fee_units: u128,
    pub total_sponsored_fee_units: u128,
}

impl Counters {
    pub fn new() -> Self {
        Self {
            next_intent_index: 1,
            next_dependency_index: 1,
            next_inventory_index: 1,
            next_covenant_index: 1,
            next_pairing_index: 1,
            next_route_index: 1,
            next_netting_index: 1,
            next_sponsor_index: 1,
            next_public_record_index: 1,
            intents_admitted: 0,
            intents_settled: 0,
            intents_rejected: 0,
            replay_rejections: 0,
            nettings_settled: 0,
            total_minted_units: 0,
            total_burned_units: 0,
            total_router_fee_units: 0,
            total_sponsored_fee_units: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        stable_record(self)
    }

    pub fn root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

impl Default for Counters {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeAssetRecord {
    pub asset_id: String,
    pub asset_commitment_root: String,
    pub origin_chain: ChainKind,
    pub settlement_chain: ChainKind,
    pub decimals: u8,
    pub min_bridge_units: u64,
    pub max_bridge_units: u64,
    pub reserve_commitment_root: String,
    pub covenant_root: String,
    pub active: bool,
}

impl BridgeAssetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_asset",
            "asset_id": self.asset_id,
            "asset_commitment_root": self.asset_commitment_root,
            "origin_chain": self.origin_chain.as_str(),
            "settlement_chain": self.settlement_chain.as_str(),
            "decimals": self.decimals,
            "min_bridge_units": self.min_bridge_units,
            "max_bridge_units": self.max_bridge_units,
            "reserve_commitment_root": self.reserve_commitment_root,
            "covenant_root": self.covenant_root,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialBridgeIntentRecord {
    pub intent_id: String,
    pub intent_index: u64,
    pub account_commitment: String,
    pub asset_id: String,
    pub intent_kind: BridgeIntentKind,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub sealed_intent_root: String,
    pub amount_commitment_root: String,
    pub recipient_commitment_root: String,
    pub refund_note_commitment: String,
    pub nullifier_root: String,
    pub replay_key: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: IntentStatus,
    pub dependency_ids: BTreeSet<String>,
    pub pairing_id: Option<String>,
    pub covenant_check_id: Option<String>,
    pub route_id: Option<String>,
    pub netting_id: Option<String>,
    pub sponsor_id: Option<String>,
    pub settlement_receipt_root: Option<String>,
}

impl ConfidentialBridgeIntentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_intent",
            "intent_id": self.intent_id,
            "intent_index": self.intent_index,
            "account_commitment": self.account_commitment,
            "asset_id": self.asset_id,
            "intent_kind": self.intent_kind.as_str(),
            "source_chain": self.source_chain.as_str(),
            "destination_chain": self.destination_chain.as_str(),
            "sealed_intent_root": self.sealed_intent_root,
            "amount_commitment_root": self.amount_commitment_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "refund_note_commitment": self.refund_note_commitment,
            "nullifier_root": self.nullifier_root,
            "replay_key": self.replay_key,
            "max_user_fee_bps": self.max_user_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "dependency_ids": self.dependency_ids,
            "pairing_id": self.pairing_id,
            "covenant_check_id": self.covenant_check_id,
            "route_id": self.route_id,
            "netting_id": self.netting_id,
            "sponsor_id": self.sponsor_id,
            "settlement_receipt_root": self.settlement_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CrossRuntimeDependencyRecord {
    pub dependency_id: String,
    pub dependency_index: u64,
    pub intent_id: String,
    pub dependency_kind: DependencyKind,
    pub runtime_id: String,
    pub runtime_state_root: String,
    pub commitment_root: String,
    pub witness_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub status: DependencyStatus,
}

impl CrossRuntimeDependencyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_dependency",
            "dependency_id": self.dependency_id,
            "dependency_index": self.dependency_index,
            "intent_id": self.intent_id,
            "dependency_kind": self.dependency_kind.as_str(),
            "runtime_id": self.runtime_id,
            "runtime_state_root": self.runtime_state_root,
            "commitment_root": self.commitment_root,
            "witness_root": self.witness_root,
            "posted_at_height": self.posted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityInventoryRecord {
    pub inventory_id: String,
    pub inventory_index: u64,
    pub asset_id: String,
    pub custodian_commitment: String,
    pub available_units: u128,
    pub reserved_units: u128,
    pub pending_mint_units: u128,
    pub pending_burn_units: u128,
    pub reserve_coverage_bps: u64,
    pub headroom_bps: u64,
    pub inventory_root: String,
    pub updated_at_height: u64,
    pub status: InventoryStatus,
}

impl LiquidityInventoryRecord {
    pub fn free_units(&self) -> u128 {
        self.available_units.saturating_sub(self.reserved_units)
    }

    pub fn can_reserve(&self, units: u128, min_coverage_bps: u64) -> bool {
        self.status.can_route()
            && self.reserve_coverage_bps >= min_coverage_bps
            && self.free_units() >= units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_inventory",
            "inventory_id": self.inventory_id,
            "inventory_index": self.inventory_index,
            "asset_id": self.asset_id,
            "custodian_commitment": self.custodian_commitment,
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "pending_mint_units": self.pending_mint_units,
            "pending_burn_units": self.pending_burn_units,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "headroom_bps": self.headroom_bps,
            "inventory_root": self.inventory_root,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CovenantCheckRecord {
    pub covenant_check_id: String,
    pub covenant_index: u64,
    pub intent_id: String,
    pub asset_id: String,
    pub covenant_root: String,
    pub policy_root: String,
    pub hook_execution_root: String,
    pub verdict: CovenantVerdict,
    pub max_settlement_units: u128,
    pub fee_limit_bps: u64,
    pub checked_at_height: u64,
}

impl CovenantCheckRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_covenant",
            "covenant_check_id": self.covenant_check_id,
            "covenant_index": self.covenant_index,
            "intent_id": self.intent_id,
            "asset_id": self.asset_id,
            "covenant_root": self.covenant_root,
            "policy_root": self.policy_root,
            "hook_execution_root": self.hook_execution_root,
            "verdict": self.verdict.as_str(),
            "max_settlement_units": self.max_settlement_units,
            "fee_limit_bps": self.fee_limit_bps,
            "checked_at_height": self.checked_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MoneroBridgePairingRecord {
    pub pairing_id: String,
    pub pairing_index: u64,
    pub intent_id: String,
    pub monero_network: ChainKind,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub tx_prefix_root: String,
    pub reserve_proof_root: String,
    pub view_tag_root: String,
    pub observed_height: u64,
    pub confirmation_height: u64,
    pub expires_at_height: u64,
    pub status: PairingStatus,
}

impl MoneroBridgePairingRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_monero_pairing",
            "pairing_id": self.pairing_id,
            "pairing_index": self.pairing_index,
            "intent_id": self.intent_id,
            "monero_network": self.monero_network.as_str(),
            "output_commitment_root": self.output_commitment_root,
            "key_image_root": self.key_image_root,
            "tx_prefix_root": self.tx_prefix_root,
            "reserve_proof_root": self.reserve_proof_root,
            "view_tag_root": self.view_tag_root,
            "observed_height": self.observed_height,
            "confirmation_height": self.confirmation_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementRouteRecord {
    pub route_id: String,
    pub route_index: u64,
    pub intent_id: String,
    pub asset_id: String,
    pub inventory_id: String,
    pub router_commitment: String,
    pub route_commitment_root: String,
    pub route_witness_root: String,
    pub settlement_units: u128,
    pub router_fee_bps: u64,
    pub sponsor_id: Option<String>,
    pub hop_roots: Vec<String>,
    pub score: u128,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
    pub status: RouteStatus,
}

impl SettlementRouteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_route",
            "route_id": self.route_id,
            "route_index": self.route_index,
            "intent_id": self.intent_id,
            "asset_id": self.asset_id,
            "inventory_id": self.inventory_id,
            "router_commitment": self.router_commitment,
            "route_commitment_root": self.route_commitment_root,
            "route_witness_root": self.route_witness_root,
            "settlement_units": self.settlement_units,
            "router_fee_bps": self.router_fee_bps,
            "sponsor_id": self.sponsor_id,
            "hop_roots": self.hop_roots,
            "score": self.score,
            "proposed_at_height": self.proposed_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementNettingBatchRecord {
    pub netting_id: String,
    pub netting_index: u64,
    pub asset_id: String,
    pub intent_ids: Vec<String>,
    pub route_ids: Vec<String>,
    pub mint_units: u128,
    pub burn_units: u128,
    pub net_mint_units: u128,
    pub net_burn_units: u128,
    pub fee_units: u128,
    pub dependency_root: String,
    pub inventory_delta_root: String,
    pub accounting_root: String,
    pub settlement_receipt_root: Option<String>,
    pub built_at_height: u64,
    pub expires_at_height: u64,
    pub status: NettingStatus,
}

impl SettlementNettingBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_netting",
            "netting_id": self.netting_id,
            "netting_index": self.netting_index,
            "asset_id": self.asset_id,
            "intent_ids": self.intent_ids,
            "route_ids": self.route_ids,
            "mint_units": self.mint_units,
            "burn_units": self.burn_units,
            "net_mint_units": self.net_mint_units,
            "net_burn_units": self.net_burn_units,
            "fee_units": self.fee_units,
            "dependency_root": self.dependency_root,
            "inventory_delta_root": self.inventory_delta_root,
            "accounting_root": self.accounting_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "built_at_height": self.built_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSponsorLinkRecord {
    pub sponsor_id: String,
    pub sponsor_index: u64,
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub sponsored_asset_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u128,
    pub reimbursement_commitment: String,
    pub sponsor_policy_root: String,
    pub nullifier_root: String,
    pub linked_route_id: Option<String>,
    pub offered_at_height: u64,
    pub expires_at_height: u64,
    pub status: SponsorStatus,
}

impl FeeSponsorLinkRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_sponsor",
            "sponsor_id": self.sponsor_id,
            "sponsor_index": self.sponsor_index,
            "intent_id": self.intent_id,
            "sponsor_commitment": self.sponsor_commitment,
            "sponsored_asset_id": self.sponsored_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "reimbursement_commitment": self.reimbursement_commitment,
            "sponsor_policy_root": self.sponsor_policy_root,
            "nullifier_root": self.nullifier_root,
            "linked_route_id": self.linked_route_id,
            "offered_at_height": self.offered_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReplayProtectionRecord {
    pub replay_key: String,
    pub intent_id: String,
    pub nullifier_root: String,
    pub domain: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub consumed: bool,
}

impl ReplayProtectionRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetAccountingRecord {
    pub accounting_id: String,
    pub asset_id: String,
    pub minted_units: u128,
    pub burned_units: u128,
    pub net_supply_units: i128,
    pub reserved_units: u128,
    pub fee_units: u128,
    pub sponsored_fee_units: u128,
    pub last_netting_id: Option<String>,
    pub updated_at_height: u64,
}

impl AssetAccountingRecord {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicRecord {
    pub record_id: String,
    pub record_index: u64,
    pub record_kind: PublicRecordKind,
    pub subject_id: String,
    pub payload_root: String,
    pub state_root: String,
    pub height: u64,
}

impl PublicRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_public_record",
            "record_id": self.record_id,
            "record_index": self.record_index,
            "record_kind": self.record_kind.as_str(),
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "state_root": self.state_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub asset_root: String,
    pub intent_root: String,
    pub dependency_root: String,
    pub inventory_root: String,
    pub covenant_root: String,
    pub monero_pairing_root: String,
    pub route_root: String,
    pub netting_root: String,
    pub sponsor_root: String,
    pub replay_root: String,
    pub accounting_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        stable_record(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitBridgeIntentRequest {
    pub account_commitment: String,
    pub asset_id: String,
    pub intent_kind: BridgeIntentKind,
    pub source_chain: ChainKind,
    pub destination_chain: ChainKind,
    pub sealed_intent_root: String,
    pub amount_commitment_root: String,
    pub recipient_commitment_root: String,
    pub refund_note_commitment: String,
    pub nullifier_root: String,
    pub max_user_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterAssetRequest {
    pub asset_id: String,
    pub asset_commitment_root: String,
    pub origin_chain: ChainKind,
    pub settlement_chain: ChainKind,
    pub decimals: u8,
    pub min_bridge_units: u64,
    pub max_bridge_units: u64,
    pub reserve_commitment_root: String,
    pub covenant_root: String,
    pub active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttachDependencyRequest {
    pub intent_id: String,
    pub dependency_kind: DependencyKind,
    pub runtime_id: String,
    pub runtime_state_root: String,
    pub commitment_root: String,
    pub witness_root: String,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpsertLiquidityInventoryRequest {
    pub asset_id: String,
    pub custodian_commitment: String,
    pub available_units: u128,
    pub reserved_units: u128,
    pub pending_mint_units: u128,
    pub pending_burn_units: u128,
    pub reserve_coverage_bps: u64,
    pub headroom_bps: u64,
    pub inventory_root: String,
    pub updated_at_height: u64,
    pub status: InventoryStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordCovenantCheckRequest {
    pub intent_id: String,
    pub covenant_root: String,
    pub policy_root: String,
    pub hook_execution_root: String,
    pub verdict: CovenantVerdict,
    pub max_settlement_units: u128,
    pub fee_limit_bps: u64,
    pub checked_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordMoneroPairingRequest {
    pub intent_id: String,
    pub monero_network: ChainKind,
    pub output_commitment_root: String,
    pub key_image_root: String,
    pub tx_prefix_root: String,
    pub reserve_proof_root: String,
    pub view_tag_root: String,
    pub observed_height: u64,
    pub confirmation_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfferFeeSponsorRequest {
    pub intent_id: String,
    pub sponsor_commitment: String,
    pub sponsored_asset_id: String,
    pub fee_asset_id: String,
    pub max_fee_units: u128,
    pub reimbursement_commitment: String,
    pub sponsor_policy_root: String,
    pub nullifier_root: String,
    pub offered_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposeSettlementRouteRequest {
    pub intent_id: String,
    pub inventory_id: String,
    pub router_commitment: String,
    pub route_commitment_root: String,
    pub route_witness_root: String,
    pub settlement_units: u128,
    pub router_fee_bps: u64,
    pub sponsor_id: Option<String>,
    pub hop_roots: Vec<String>,
    pub proposed_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildSettlementNettingRequest {
    pub asset_id: String,
    pub intent_ids: Vec<String>,
    pub route_ids: Vec<String>,
    pub dependency_root: String,
    pub inventory_delta_root: String,
    pub accounting_root: String,
    pub built_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleNettingBatchRequest {
    pub netting_id: String,
    pub settlement_receipt_root: String,
    pub settlement_tx_root: String,
    pub proof_root: String,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub runtime_root: String,
    pub assets: BTreeMap<String, BridgeAssetRecord>,
    pub intents: BTreeMap<String, ConfidentialBridgeIntentRecord>,
    pub dependencies: BTreeMap<String, CrossRuntimeDependencyRecord>,
    pub inventories: BTreeMap<String, LiquidityInventoryRecord>,
    pub covenants: BTreeMap<String, CovenantCheckRecord>,
    pub monero_pairings: BTreeMap<String, MoneroBridgePairingRecord>,
    pub routes: BTreeMap<String, SettlementRouteRecord>,
    pub nettings: BTreeMap<String, SettlementNettingBatchRecord>,
    pub sponsors: BTreeMap<String, FeeSponsorLinkRecord>,
    pub replay_keys: BTreeMap<String, ReplayProtectionRecord>,
    pub accounting: BTreeMap<String, AssetAccountingRecord>,
    pub public_records: BTreeMap<String, PublicRecord>,
}

impl State {
    pub fn new(config: Config, current_l2_height: u64, current_monero_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            current_l2_height,
            current_monero_height,
            runtime_root: deterministic_root("RUNTIME", "genesis"),
            assets: BTreeMap::new(),
            intents: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            inventories: BTreeMap::new(),
            covenants: BTreeMap::new(),
            monero_pairings: BTreeMap::new(),
            routes: BTreeMap::new(),
            nettings: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            replay_keys: BTreeMap::new(),
            accounting: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet(), DEVNET_L2_HEIGHT, DEVNET_MONERO_HEIGHT) {
            Ok(state) => state,
            Err(_) => Self::empty_devnet(),
        }
    }

    fn empty_devnet() -> Self {
        Self {
            config: Config::devnet(),
            counters: Counters::default(),
            current_l2_height: DEVNET_L2_HEIGHT,
            current_monero_height: DEVNET_MONERO_HEIGHT,
            runtime_root: deterministic_root("RUNTIME", "fallback-genesis"),
            assets: BTreeMap::new(),
            intents: BTreeMap::new(),
            dependencies: BTreeMap::new(),
            inventories: BTreeMap::new(),
            covenants: BTreeMap::new(),
            monero_pairings: BTreeMap::new(),
            routes: BTreeMap::new(),
            nettings: BTreeMap::new(),
            sponsors: BTreeMap::new(),
            replay_keys: BTreeMap::new(),
            accounting: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn register_asset(&mut self, request: RegisterAssetRequest) -> Result<String> {
        self.ensure_capacity(self.assets.len(), MAX_ASSETS, "assets")?;
        validate_asset_request(&request)?;
        require(
            !self.assets.contains_key(&request.asset_id),
            "asset already registered",
        )?;
        let record = BridgeAssetRecord {
            asset_id: request.asset_id.clone(),
            asset_commitment_root: request.asset_commitment_root,
            origin_chain: request.origin_chain,
            settlement_chain: request.settlement_chain,
            decimals: request.decimals,
            min_bridge_units: request.min_bridge_units,
            max_bridge_units: request.max_bridge_units,
            reserve_commitment_root: request.reserve_commitment_root,
            covenant_root: request.covenant_root,
            active: request.active,
        };
        let asset_id = record.asset_id.clone();
        self.assets.insert(asset_id.clone(), record.clone());
        self.ensure_accounting(&asset_id, self.current_l2_height);
        self.record_public(
            PublicRecordKind::Accounting,
            &asset_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(asset_id)
    }

    pub fn submit_bridge_intent(&mut self, request: SubmitBridgeIntentRequest) -> Result<String> {
        self.ensure_capacity(self.intents.len(), MAX_INTENTS, "intents")?;
        validate_intent_request(&self.config, &request)?;
        let asset = self
            .assets
            .get(&request.asset_id)
            .ok_or_else(|| "asset is not registered".to_string())?;
        require(asset.active, "asset is not active")?;
        let replay_key = replay_key(&self.config.replay_domain, &request.nullifier_root);
        if self.replay_keys.contains_key(&replay_key) {
            self.counters.replay_rejections = self.counters.replay_rejections.saturating_add(1);
            return Err("replay key already observed".to_string());
        }
        let intent_index = self.counters.next_intent_index;
        let intent_id = bridge_intent_id(&request, &replay_key, intent_index);
        let replay = ReplayProtectionRecord {
            replay_key: replay_key.clone(),
            intent_id: intent_id.clone(),
            nullifier_root: request.nullifier_root.clone(),
            domain: self.config.replay_domain.clone(),
            first_seen_height: request.submitted_at_height,
            expires_at_height: request
                .expires_at_height
                .saturating_add(self.config.replay_grace_blocks),
            consumed: false,
        };
        let replay_payload = replay.public_record();
        let record = ConfidentialBridgeIntentRecord {
            intent_id: intent_id.clone(),
            intent_index,
            account_commitment: request.account_commitment,
            asset_id: request.asset_id,
            intent_kind: request.intent_kind,
            source_chain: request.source_chain,
            destination_chain: request.destination_chain,
            sealed_intent_root: request.sealed_intent_root,
            amount_commitment_root: request.amount_commitment_root,
            recipient_commitment_root: request.recipient_commitment_root,
            refund_note_commitment: request.refund_note_commitment,
            nullifier_root: request.nullifier_root,
            replay_key: replay_key.clone(),
            max_user_fee_bps: request.max_user_fee_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.expires_at_height,
            status: IntentStatus::Admitted,
            dependency_ids: BTreeSet::new(),
            pairing_id: None,
            covenant_check_id: None,
            route_id: None,
            netting_id: None,
            sponsor_id: None,
            settlement_receipt_root: None,
        };
        self.counters.next_intent_index = self.counters.next_intent_index.saturating_add(1);
        self.counters.intents_admitted = self.counters.intents_admitted.saturating_add(1);
        self.replay_keys.insert(replay_key.clone(), replay);
        self.intents.insert(intent_id.clone(), record.clone());
        self.record_public(
            PublicRecordKind::Intent,
            &intent_id,
            &record.public_record(),
        )?;
        self.record_public(PublicRecordKind::ReplayKey, &replay_key, &replay_payload)?;
        self.refresh_runtime_root();
        Ok(intent_id)
    }

    pub fn attach_dependency(&mut self, request: AttachDependencyRequest) -> Result<String> {
        self.ensure_capacity(self.dependencies.len(), MAX_DEPENDENCIES, "dependencies")?;
        validate_dependency_request(&request)?;
        require(
            self.config.allow_cross_runtime_dependencies,
            "cross-runtime dependencies disabled",
        )?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?;
        require(intent.status.live(), "intent is not live")?;
        let dependency_index = self.counters.next_dependency_index;
        let dependency_id = dependency_id(&request, dependency_index);
        let record = CrossRuntimeDependencyRecord {
            dependency_id: dependency_id.clone(),
            dependency_index,
            intent_id: request.intent_id.clone(),
            dependency_kind: request.dependency_kind,
            runtime_id: request.runtime_id,
            runtime_state_root: request.runtime_state_root,
            commitment_root: request.commitment_root,
            witness_root: request.witness_root,
            posted_at_height: request.posted_at_height,
            expires_at_height: request.expires_at_height,
            status: DependencyStatus::Locked,
        };
        self.counters.next_dependency_index = self.counters.next_dependency_index.saturating_add(1);
        self.dependencies
            .insert(dependency_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.dependency_ids.insert(dependency_id.clone());
            intent.status = IntentStatus::DependencyLocked;
        }
        self.record_public(
            PublicRecordKind::Dependency,
            &dependency_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(dependency_id)
    }

    pub fn upsert_liquidity_inventory(
        &mut self,
        request: UpsertLiquidityInventoryRequest,
    ) -> Result<String> {
        self.ensure_capacity(self.inventories.len(), MAX_INVENTORIES, "inventories")?;
        validate_inventory_request(&self.config, &request)?;
        require(
            self.assets.contains_key(&request.asset_id),
            "inventory asset is not registered",
        )?;
        let inventory_id = liquidity_inventory_id(&request);
        let inventory_index = match self.inventories.get(&inventory_id) {
            Some(existing) => existing.inventory_index,
            None => {
                let next = self.counters.next_inventory_index;
                self.counters.next_inventory_index =
                    self.counters.next_inventory_index.saturating_add(1);
                next
            }
        };
        let record = LiquidityInventoryRecord {
            inventory_id: inventory_id.clone(),
            inventory_index,
            asset_id: request.asset_id,
            custodian_commitment: request.custodian_commitment,
            available_units: request.available_units,
            reserved_units: request.reserved_units,
            pending_mint_units: request.pending_mint_units,
            pending_burn_units: request.pending_burn_units,
            reserve_coverage_bps: request.reserve_coverage_bps,
            headroom_bps: request.headroom_bps,
            inventory_root: request.inventory_root,
            updated_at_height: request.updated_at_height,
            status: request.status,
        };
        self.inventories
            .insert(inventory_id.clone(), record.clone());
        self.record_public(
            PublicRecordKind::Inventory,
            &inventory_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(inventory_id)
    }

    pub fn record_covenant_check(&mut self, request: RecordCovenantCheckRequest) -> Result<String> {
        self.ensure_capacity(self.covenants.len(), MAX_COVENANTS, "covenants")?;
        validate_covenant_request(&request)?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?;
        require(intent.status.live(), "intent is not live")?;
        let covenant_index = self.counters.next_covenant_index;
        let covenant_check_id = covenant_check_id(&request, covenant_index);
        let record = CovenantCheckRecord {
            covenant_check_id: covenant_check_id.clone(),
            covenant_index,
            intent_id: request.intent_id.clone(),
            asset_id: intent.asset_id.clone(),
            covenant_root: request.covenant_root,
            policy_root: request.policy_root,
            hook_execution_root: request.hook_execution_root,
            verdict: request.verdict,
            max_settlement_units: request.max_settlement_units,
            fee_limit_bps: request.fee_limit_bps,
            checked_at_height: request.checked_at_height,
        };
        self.counters.next_covenant_index = self.counters.next_covenant_index.saturating_add(1);
        self.covenants
            .insert(covenant_check_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.covenant_check_id = Some(covenant_check_id.clone());
            intent.status = if record.verdict.accepts_route() {
                IntentStatus::CovenantChecked
            } else {
                self.counters.intents_rejected = self.counters.intents_rejected.saturating_add(1);
                IntentStatus::Rejected
            };
        }
        self.record_public(
            PublicRecordKind::Covenant,
            &covenant_check_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(covenant_check_id)
    }

    pub fn record_monero_pairing(&mut self, request: RecordMoneroPairingRequest) -> Result<String> {
        self.ensure_capacity(self.monero_pairings.len(), MAX_PAIRINGS, "monero_pairings")?;
        validate_pairing_request(&self.config, &request)?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?;
        require(intent.status.live(), "intent is not live")?;
        require(
            intent.source_chain.is_monero() || intent.destination_chain.is_monero(),
            "intent does not touch Monero",
        )?;
        let pairing_index = self.counters.next_pairing_index;
        let pairing_id = monero_pairing_id(&request, pairing_index);
        let record = MoneroBridgePairingRecord {
            pairing_id: pairing_id.clone(),
            pairing_index,
            intent_id: request.intent_id.clone(),
            monero_network: request.monero_network,
            output_commitment_root: request.output_commitment_root,
            key_image_root: request.key_image_root,
            tx_prefix_root: request.tx_prefix_root,
            reserve_proof_root: request.reserve_proof_root,
            view_tag_root: request.view_tag_root,
            observed_height: request.observed_height,
            confirmation_height: request.confirmation_height,
            expires_at_height: request.expires_at_height,
            status: PairingStatus::Matched,
        };
        self.counters.next_pairing_index = self.counters.next_pairing_index.saturating_add(1);
        self.monero_pairings
            .insert(pairing_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.pairing_id = Some(pairing_id.clone());
            intent.status = IntentStatus::Paired;
        }
        self.record_public(
            PublicRecordKind::MoneroPairing,
            &pairing_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(pairing_id)
    }

    pub fn offer_fee_sponsor(&mut self, request: OfferFeeSponsorRequest) -> Result<String> {
        self.ensure_capacity(self.sponsors.len(), MAX_SPONSORS, "sponsors")?;
        validate_sponsor_request(&self.config, &request)?;
        require(
            self.config.allow_fee_sponsorship,
            "fee sponsorship disabled",
        )?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?;
        require(intent.status.live(), "intent is not live")?;
        require(
            intent.asset_id == request.sponsored_asset_id,
            "sponsor asset must match intent asset",
        )?;
        let sponsor_index = self.counters.next_sponsor_index;
        let sponsor_id = sponsor_id(&request, sponsor_index);
        let record = FeeSponsorLinkRecord {
            sponsor_id: sponsor_id.clone(),
            sponsor_index,
            intent_id: request.intent_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            sponsored_asset_id: request.sponsored_asset_id,
            fee_asset_id: request.fee_asset_id,
            max_fee_units: request.max_fee_units,
            reimbursement_commitment: request.reimbursement_commitment,
            sponsor_policy_root: request.sponsor_policy_root,
            nullifier_root: request.nullifier_root,
            linked_route_id: None,
            offered_at_height: request.offered_at_height,
            expires_at_height: request.expires_at_height,
            status: SponsorStatus::Offered,
        };
        self.counters.next_sponsor_index = self.counters.next_sponsor_index.saturating_add(1);
        self.sponsors.insert(sponsor_id.clone(), record.clone());
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.sponsor_id = Some(sponsor_id.clone());
        }
        self.record_public(
            PublicRecordKind::SponsorLink,
            &sponsor_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(sponsor_id)
    }

    pub fn propose_settlement_route(
        &mut self,
        request: ProposeSettlementRouteRequest,
    ) -> Result<String> {
        self.ensure_capacity(self.routes.len(), MAX_ROUTES, "routes")?;
        validate_route_request(&self.config, &request)?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?
            .clone();
        require(intent.status.live(), "intent is not live")?;
        self.require_intent_ready_for_route(&intent)?;
        let inventory = self
            .inventories
            .get(&request.inventory_id)
            .ok_or_else(|| "inventory not found".to_string())?;
        require(
            inventory.asset_id == intent.asset_id,
            "inventory asset mismatch",
        )?;
        require(
            inventory.can_reserve(
                request.settlement_units,
                self.config.min_reserve_coverage_bps,
            ),
            "inventory cannot reserve settlement units",
        )?;
        if let Some(sponsor_id) = &request.sponsor_id {
            let sponsor = self
                .sponsors
                .get(sponsor_id)
                .ok_or_else(|| "sponsor not found".to_string())?;
            require(
                sponsor.intent_id == request.intent_id,
                "sponsor intent mismatch",
            )?;
            require(sponsor.status.usable(), "sponsor is not usable")?;
        }
        let score = route_score(&request, inventory);
        let route_index = self.counters.next_route_index;
        let route_id = route_id(&request, score, route_index);
        let status = if request.sponsor_id.is_some() {
            RouteStatus::SponsorLinked
        } else {
            RouteStatus::InventoryReserved
        };
        let record = SettlementRouteRecord {
            route_id: route_id.clone(),
            route_index,
            intent_id: request.intent_id.clone(),
            asset_id: intent.asset_id.clone(),
            inventory_id: request.inventory_id.clone(),
            router_commitment: request.router_commitment,
            route_commitment_root: request.route_commitment_root,
            route_witness_root: request.route_witness_root,
            settlement_units: request.settlement_units,
            router_fee_bps: request.router_fee_bps,
            sponsor_id: request.sponsor_id.clone(),
            hop_roots: request.hop_roots,
            score,
            proposed_at_height: request.proposed_at_height,
            expires_at_height: request.expires_at_height,
            status,
        };
        self.counters.next_route_index = self.counters.next_route_index.saturating_add(1);
        self.routes.insert(route_id.clone(), record.clone());
        if let Some(inventory) = self.inventories.get_mut(&request.inventory_id) {
            inventory.reserved_units = inventory
                .reserved_units
                .saturating_add(request.settlement_units);
            if intent.intent_kind.mints() {
                inventory.pending_mint_units = inventory
                    .pending_mint_units
                    .saturating_add(request.settlement_units);
            }
            if intent.intent_kind.burns() {
                inventory.pending_burn_units = inventory
                    .pending_burn_units
                    .saturating_add(request.settlement_units);
            }
        }
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.route_id = Some(route_id.clone());
            intent.status = IntentStatus::Routed;
        }
        if let Some(sponsor_id) = &request.sponsor_id {
            if let Some(sponsor) = self.sponsors.get_mut(sponsor_id) {
                sponsor.linked_route_id = Some(route_id.clone());
                sponsor.status = SponsorStatus::Linked;
            }
        }
        self.record_public(PublicRecordKind::Route, &route_id, &record.public_record())?;
        self.refresh_runtime_root();
        Ok(route_id)
    }

    pub fn build_settlement_netting(
        &mut self,
        request: BuildSettlementNettingRequest,
    ) -> Result<String> {
        self.ensure_capacity(self.nettings.len(), MAX_NETTINGS, "nettings")?;
        validate_netting_request(&self.config, &request)?;
        require(
            request.intent_ids.len() == request.route_ids.len(),
            "intent_ids and route_ids length mismatch",
        )?;
        require(
            unique_strings(&request.intent_ids),
            "intent_ids must be unique",
        )?;
        require(
            unique_strings(&request.route_ids),
            "route_ids must be unique",
        )?;
        let mut mint_units = 0_u128;
        let mut burn_units = 0_u128;
        let mut fee_units = 0_u128;
        for (intent_id, route_id) in request.intent_ids.iter().zip(request.route_ids.iter()) {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("intent {intent_id} not found"))?;
            let route = self
                .routes
                .get(route_id)
                .ok_or_else(|| format!("route {route_id} not found"))?;
            require(intent.asset_id == request.asset_id, "intent asset mismatch")?;
            require(route.asset_id == request.asset_id, "route asset mismatch")?;
            require(route.intent_id == *intent_id, "route intent mismatch")?;
            require(
                matches!(
                    route.status,
                    RouteStatus::InventoryReserved
                        | RouteStatus::SponsorLinked
                        | RouteStatus::Selected
                ),
                "route is not nettable",
            )?;
            if intent.intent_kind.mints() {
                mint_units = mint_units.saturating_add(route.settlement_units);
            }
            if intent.intent_kind.burns() {
                burn_units = burn_units.saturating_add(route.settlement_units);
            }
            fee_units = fee_units.saturating_add(
                route
                    .settlement_units
                    .saturating_mul(route.router_fee_bps as u128)
                    / MAX_BPS as u128,
            );
        }
        let net_mint_units = mint_units.saturating_sub(burn_units);
        let net_burn_units = burn_units.saturating_sub(mint_units);
        let netting_index = self.counters.next_netting_index;
        let netting_id = netting_id(&request, net_mint_units, net_burn_units, netting_index);
        let record = SettlementNettingBatchRecord {
            netting_id: netting_id.clone(),
            netting_index,
            asset_id: request.asset_id.clone(),
            intent_ids: request.intent_ids.clone(),
            route_ids: request.route_ids.clone(),
            mint_units,
            burn_units,
            net_mint_units,
            net_burn_units,
            fee_units,
            dependency_root: request.dependency_root,
            inventory_delta_root: request.inventory_delta_root,
            accounting_root: request.accounting_root,
            settlement_receipt_root: None,
            built_at_height: request.built_at_height,
            expires_at_height: request.expires_at_height,
            status: NettingStatus::SettlementReady,
        };
        self.counters.next_netting_index = self.counters.next_netting_index.saturating_add(1);
        self.nettings.insert(netting_id.clone(), record.clone());
        for intent_id in &request.intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.netting_id = Some(netting_id.clone());
                intent.status = IntentStatus::Netted;
            }
        }
        for route_id in &request.route_ids {
            if let Some(route) = self.routes.get_mut(route_id) {
                route.status = RouteStatus::Selected;
            }
        }
        self.apply_accounting_delta(
            &request.asset_id,
            mint_units,
            burn_units,
            fee_units,
            0,
            Some(netting_id.clone()),
            request.built_at_height,
        );
        self.record_public(
            PublicRecordKind::NettingBatch,
            &netting_id,
            &record.public_record(),
        )?;
        self.refresh_runtime_root();
        Ok(netting_id)
    }

    pub fn settle_netting_batch(&mut self, request: SettleNettingBatchRequest) -> Result<String> {
        validate_settlement_request(&request)?;
        let state_root_before = self.root();
        let netting = self
            .nettings
            .get(&request.netting_id)
            .ok_or_else(|| "netting batch not found".to_string())?
            .clone();
        require(
            matches!(netting.status, NettingStatus::SettlementReady),
            "netting batch is not settlement ready",
        )?;
        let receipt_root = netting_settlement_receipt_root(&request, &state_root_before);
        require(
            receipt_root == request.settlement_receipt_root,
            "settlement receipt root mismatch",
        )?;
        if let Some(netting) = self.nettings.get_mut(&request.netting_id) {
            netting.status = NettingStatus::Settled;
            netting.settlement_receipt_root = Some(request.settlement_receipt_root.clone());
        }
        for intent_id in netting.intent_ids {
            if let Some(intent) = self.intents.get_mut(&intent_id) {
                intent.status = IntentStatus::Settled;
                intent.settlement_receipt_root = Some(request.settlement_receipt_root.clone());
                if let Some(replay) = self.replay_keys.get_mut(&intent.replay_key) {
                    replay.consumed = true;
                }
            }
            self.counters.intents_settled = self.counters.intents_settled.saturating_add(1);
        }
        for route_id in netting.route_ids {
            if let Some(route) = self.routes.get_mut(&route_id) {
                route.status = RouteStatus::Settled;
            }
        }
        self.counters.nettings_settled = self.counters.nettings_settled.saturating_add(1);
        self.counters.total_minted_units = self
            .counters
            .total_minted_units
            .saturating_add(netting.mint_units);
        self.counters.total_burned_units = self
            .counters
            .total_burned_units
            .saturating_add(netting.burn_units);
        self.counters.total_router_fee_units = self
            .counters
            .total_router_fee_units
            .saturating_add(netting.fee_units);
        let payload = json!({
            "netting_id": request.netting_id,
            "settlement_receipt_root": request.settlement_receipt_root,
            "settlement_tx_root": request.settlement_tx_root,
            "proof_root": request.proof_root,
            "settled_at_height": request.settled_at_height,
        });
        self.record_public(PublicRecordKind::Settlement, &request.netting_id, &payload)?;
        self.refresh_runtime_root();
        Ok(receipt_root)
    }

    pub fn expire_height(&mut self, l2_height: u64, monero_height: u64) -> Result<usize> {
        self.current_l2_height = l2_height;
        self.current_monero_height = monero_height;
        let mut changed = 0_usize;
        for intent in self.intents.values_mut() {
            if intent.status.live() && intent.expires_at_height < l2_height {
                intent.status = IntentStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for dependency in self.dependencies.values_mut() {
            if dependency.status.usable() && dependency.expires_at_height < l2_height {
                dependency.status = DependencyStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for pairing in self.monero_pairings.values_mut() {
            if pairing.status.usable() && pairing.expires_at_height < l2_height {
                pairing.status = PairingStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for route in self.routes.values_mut() {
            if matches!(
                route.status,
                RouteStatus::Proposed | RouteStatus::InventoryReserved | RouteStatus::SponsorLinked
            ) && route.expires_at_height < l2_height
            {
                route.status = RouteStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for sponsor in self.sponsors.values_mut() {
            if sponsor.status.usable() && sponsor.expires_at_height < l2_height {
                sponsor.status = SponsorStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        for netting in self.nettings.values_mut() {
            if matches!(
                netting.status,
                NettingStatus::Built
                    | NettingStatus::DependencyChecked
                    | NettingStatus::InventoryBalanced
                    | NettingStatus::SettlementReady
            ) && netting.expires_at_height < l2_height
            {
                netting.status = NettingStatus::Expired;
                changed = changed.saturating_add(1);
            }
        }
        self.refresh_runtime_root();
        Ok(changed)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            asset_root: map_root("ASSETS", &self.assets),
            intent_root: map_root("INTENTS", &self.intents),
            dependency_root: map_root("DEPENDENCIES", &self.dependencies),
            inventory_root: map_root("INVENTORIES", &self.inventories),
            covenant_root: map_root("COVENANTS", &self.covenants),
            monero_pairing_root: map_root("MONERO-PAIRINGS", &self.monero_pairings),
            route_root: map_root("ROUTES", &self.routes),
            netting_root: map_root("NETTINGS", &self.nettings),
            sponsor_root: map_root("SPONSORS", &self.sponsors),
            replay_root: map_root("REPLAY-KEYS", &self.replay_keys),
            accounting_root: map_root("ACCOUNTING", &self.accounting),
            public_record_root: map_root("PUBLIC-RECORDS", &self.public_records),
            state_root: String::new(),
        };
        roots.state_root = payload_root(
            "STATE",
            &json!({
                "config_root": roots.config_root,
                "counters_root": roots.counters_root,
                "asset_root": roots.asset_root,
                "intent_root": roots.intent_root,
                "dependency_root": roots.dependency_root,
                "inventory_root": roots.inventory_root,
                "covenant_root": roots.covenant_root,
                "monero_pairing_root": roots.monero_pairing_root,
                "route_root": roots.route_root,
                "netting_root": roots.netting_root,
                "sponsor_root": roots.sponsor_root,
                "replay_root": roots.replay_root,
                "accounting_root": roots.accounting_root,
                "public_record_root": roots.public_record_root,
                "current_l2_height": self.current_l2_height,
                "current_monero_height": self.current_monero_height,
            }),
        );
        roots
    }

    pub fn root(&self) -> String {
        self.roots().state_root
    }

    pub fn state_root(&self) -> String {
        self.root()
    }

    pub fn public_state(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_token_bridge_settlement_router_public_state",
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "confidential_proof_suite": CONFIDENTIAL_PROOF_SUITE,
            "monero_pairing_suite": MONERO_PAIRING_SUITE,
            "covenant_suite": COVENANT_SUITE,
            "inventory_suite": INVENTORY_SUITE,
            "netting_suite": NETTING_SUITE,
            "sponsor_suite": SPONSOR_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "chain_id": self.config.chain_id,
            "router_id": self.config.router_id,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "runtime_root": self.runtime_root,
            "roots": roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        self.public_state()
    }

    fn require_intent_ready_for_route(
        &self,
        intent: &ConfidentialBridgeIntentRecord,
    ) -> Result<()> {
        if self.config.require_dependency_lock {
            require(
                !intent.dependency_ids.is_empty(),
                "intent has no dependency lock",
            )?;
            for dependency_id in &intent.dependency_ids {
                let dependency = self
                    .dependencies
                    .get(dependency_id)
                    .ok_or_else(|| "intent dependency missing".to_string())?;
                require(
                    dependency.status.usable(),
                    "intent dependency is not usable",
                )?;
            }
        }
        if self.config.require_monero_pairing
            && (intent.source_chain.is_monero() || intent.destination_chain.is_monero())
        {
            let pairing_id = intent
                .pairing_id
                .as_ref()
                .ok_or_else(|| "intent requires Monero pairing".to_string())?;
            let pairing = self
                .monero_pairings
                .get(pairing_id)
                .ok_or_else(|| "Monero pairing missing".to_string())?;
            require(pairing.status.usable(), "Monero pairing is not usable")?;
        }
        if self.config.require_covenant_check {
            let covenant_id = intent
                .covenant_check_id
                .as_ref()
                .ok_or_else(|| "intent requires covenant check".to_string())?;
            let covenant = self
                .covenants
                .get(covenant_id)
                .ok_or_else(|| "covenant check missing".to_string())?;
            require(covenant.verdict.accepts_route(), "covenant rejects route")?;
        }
        Ok(())
    }

    fn apply_accounting_delta(
        &mut self,
        asset_id: &str,
        mint_units: u128,
        burn_units: u128,
        fee_units: u128,
        sponsored_fee_units: u128,
        last_netting_id: Option<String>,
        height: u64,
    ) {
        self.ensure_accounting(asset_id, height);
        if let Some(record) = self.accounting.get_mut(asset_id) {
            record.minted_units = record.minted_units.saturating_add(mint_units);
            record.burned_units = record.burned_units.saturating_add(burn_units);
            record.fee_units = record.fee_units.saturating_add(fee_units);
            record.sponsored_fee_units = record
                .sponsored_fee_units
                .saturating_add(sponsored_fee_units);
            let net = record.minted_units.saturating_sub(record.burned_units);
            let reverse = record.burned_units.saturating_sub(record.minted_units);
            record.net_supply_units = if net > 0 {
                saturating_u128_to_i128(net)
            } else {
                -saturating_u128_to_i128(reverse)
            };
            record.last_netting_id = last_netting_id;
            record.updated_at_height = height;
        }
    }

    fn ensure_accounting(&mut self, asset_id: &str, height: u64) {
        if self.accounting.contains_key(asset_id) || self.accounting.len() >= MAX_ACCOUNTING_BUCKETS
        {
            return;
        }
        let record = AssetAccountingRecord {
            accounting_id: accounting_id(asset_id),
            asset_id: asset_id.to_string(),
            minted_units: 0,
            burned_units: 0,
            net_supply_units: 0,
            reserved_units: 0,
            fee_units: 0,
            sponsored_fee_units: 0,
            last_netting_id: None,
            updated_at_height: height,
        };
        self.accounting.insert(asset_id.to_string(), record);
    }

    fn record_public(
        &mut self,
        record_kind: PublicRecordKind,
        subject_id: &str,
        payload: &Value,
    ) -> Result<String> {
        self.ensure_capacity(
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
            "public_records",
        )?;
        let payload_root = payload_root("PUBLIC-PAYLOAD", payload);
        let state_root = self.root();
        let record_index = self.counters.next_public_record_index;
        let record_id = public_record_id(record_kind, subject_id, &payload_root, &state_root);
        let record = PublicRecord {
            record_id: record_id.clone(),
            record_index,
            record_kind,
            subject_id: subject_id.to_string(),
            payload_root,
            state_root,
            height: self.current_l2_height,
        };
        self.counters.next_public_record_index =
            self.counters.next_public_record_index.saturating_add(1);
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    fn refresh_runtime_root(&mut self) {
        self.runtime_root = self.root();
    }

    fn ensure_capacity(&self, len: usize, max: usize, label: &str) -> Result<()> {
        require(len < max, &format!("{label} capacity exceeded"))
    }
}

pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn replay_key(replay_domain: &str, nullifier_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:REPLAY-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(replay_domain),
            HashPart::Str(nullifier_root),
        ],
        32,
    )
}

pub fn bridge_intent_id(
    request: &SubmitBridgeIntentRequest,
    replay_key: &str,
    index: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.asset_id),
            HashPart::Str(request.intent_kind.as_str()),
            HashPart::Str(request.source_chain.as_str()),
            HashPart::Str(request.destination_chain.as_str()),
            HashPart::Str(&request.sealed_intent_root),
            HashPart::Str(replay_key),
        ],
        32,
    )
}

pub fn dependency_id(request: &AttachDependencyRequest, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:DEPENDENCY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.intent_id),
            HashPart::Str(request.dependency_kind.as_str()),
            HashPart::Str(&request.runtime_id),
            HashPart::Str(&request.runtime_state_root),
            HashPart::Str(&request.commitment_root),
        ],
        32,
    )
}

pub fn liquidity_inventory_id(request: &UpsertLiquidityInventoryRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:INVENTORY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&request.custodian_commitment),
        ],
        32,
    )
}

pub fn covenant_check_id(request: &RecordCovenantCheckRequest, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:COVENANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&request.covenant_root),
            HashPart::Str(&request.policy_root),
            HashPart::Str(request.verdict.as_str()),
        ],
        32,
    )
}

pub fn monero_pairing_id(request: &RecordMoneroPairingRequest, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:MONERO-PAIRING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.intent_id),
            HashPart::Str(request.monero_network.as_str()),
            HashPart::Str(&request.output_commitment_root),
            HashPart::Str(&request.key_image_root),
            HashPart::Str(&request.tx_prefix_root),
        ],
        32,
    )
}

pub fn sponsor_id(request: &OfferFeeSponsorRequest, index: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.sponsored_asset_id),
            HashPart::Str(&request.fee_asset_id),
            HashPart::Str(&request.nullifier_root),
        ],
        32,
    )
}

pub fn route_id(request: &ProposeSettlementRouteRequest, score: u128, index: u64) -> String {
    let hop_root = list_root(
        "ROUTE-ID-HOPS",
        request
            .hop_roots
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:ROUTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.intent_id),
            HashPart::Str(&request.inventory_id),
            HashPart::Str(&request.router_commitment),
            HashPart::Str(&request.route_commitment_root),
            HashPart::Str(&hop_root),
            HashPart::Int(score as i128),
        ],
        32,
    )
}

pub fn netting_id(
    request: &BuildSettlementNettingRequest,
    net_mint_units: u128,
    net_burn_units: u128,
    index: u64,
) -> String {
    let intent_root = list_root(
        "NETTING-ID-INTENTS",
        request
            .intent_ids
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    let route_root = list_root(
        "NETTING-ID-ROUTES",
        request
            .route_ids
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:NETTING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(index),
            HashPart::Str(&request.asset_id),
            HashPart::Str(&intent_root),
            HashPart::Str(&route_root),
            HashPart::Str(&request.dependency_root),
            HashPart::Int(saturating_u128_to_i128(net_mint_units)),
            HashPart::Int(saturating_u128_to_i128(net_burn_units)),
        ],
        32,
    )
}

pub fn netting_settlement_receipt_root(
    request: &SettleNettingBatchRequest,
    state_root_before: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:SETTLEMENT-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.netting_id),
            HashPart::Str(&request.settlement_tx_root),
            HashPart::Str(&request.proof_root),
            HashPart::Str(state_root_before),
            HashPart::U64(request.settled_at_height),
        ],
        32,
    )
}

pub fn accounting_id(asset_id: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:ACCOUNTING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(asset_id),
        ],
        32,
    )
}

pub fn public_record_id(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload_root: &str,
    state_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(payload_root),
            HashPart::Str(state_root),
        ],
        32,
    )
}

pub fn roots_only_payload(
    record_kind: PublicRecordKind,
    subject_id: &str,
    payload: &Value,
) -> Value {
    json!({
        "kind": "private_l2_pq_confidential_token_bridge_settlement_router_roots_only_payload",
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "record_kind": record_kind.as_str(),
        "subject_id": subject_id,
        "payload_root": payload_root("ROOTS-ONLY", payload),
    })
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn value_root<T: Serialize>(domain: &str, value: &T) -> String {
    payload_root(domain, &stable_record(value))
}

pub fn list_root(domain: &str, values: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:{domain}"),
        &values,
    )
}

pub fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": stable_record(value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-PQ-BRIDGE-SETTLEMENT-ROUTER:{domain}"),
        &leaves,
    )
}

pub fn stable_record<T: Serialize>(value: &T) -> Value {
    match serde_json::to_value(value) {
        Ok(value) => value,
        Err(error) => json!({
            "serialization_error": error.to_string(),
        }),
    }
}

fn validate_asset_request(request: &RegisterAssetRequest) -> Result<()> {
    require_non_empty("asset_id", &request.asset_id)?;
    require_root("asset_commitment_root", &request.asset_commitment_root)?;
    require_root("reserve_commitment_root", &request.reserve_commitment_root)?;
    require_root("covenant_root", &request.covenant_root)?;
    require(
        request.max_bridge_units >= request.min_bridge_units,
        "max_bridge_units must be at least min_bridge_units",
    )?;
    Ok(())
}

fn validate_intent_request(config: &Config, request: &SubmitBridgeIntentRequest) -> Result<()> {
    require_non_empty("account_commitment", &request.account_commitment)?;
    require_non_empty("asset_id", &request.asset_id)?;
    require_root("sealed_intent_root", &request.sealed_intent_root)?;
    require_root("amount_commitment_root", &request.amount_commitment_root)?;
    require_root(
        "recipient_commitment_root",
        &request.recipient_commitment_root,
    )?;
    require_root("refund_note_commitment", &request.refund_note_commitment)?;
    require_root("nullifier_root", &request.nullifier_root)?;
    require_bps("max_user_fee_bps", request.max_user_fee_bps)?;
    require(
        request.max_user_fee_bps <= config.max_user_fee_bps,
        "user fee exceeds router policy",
    )?;
    require(
        request.privacy_set_size >= config.min_privacy_set_size,
        "privacy set is too small",
    )?;
    require(
        request.pq_security_bits >= config.min_pq_security_bits,
        "post-quantum security bits too low",
    )?;
    require(
        request.expires_at_height > request.submitted_at_height,
        "intent expiry must be after submission",
    )?;
    require(
        request
            .expires_at_height
            .saturating_sub(request.submitted_at_height)
            <= config.intent_ttl_blocks,
        "intent ttl exceeds policy",
    )?;
    Ok(())
}

fn validate_dependency_request(request: &AttachDependencyRequest) -> Result<()> {
    require_non_empty("intent_id", &request.intent_id)?;
    require_non_empty("runtime_id", &request.runtime_id)?;
    require_root("runtime_state_root", &request.runtime_state_root)?;
    require_root("commitment_root", &request.commitment_root)?;
    require_root("witness_root", &request.witness_root)?;
    require(
        request.expires_at_height > request.posted_at_height,
        "dependency expiry must be after posting",
    )?;
    Ok(())
}

fn validate_inventory_request(
    config: &Config,
    request: &UpsertLiquidityInventoryRequest,
) -> Result<()> {
    require_non_empty("asset_id", &request.asset_id)?;
    require_root("custodian_commitment", &request.custodian_commitment)?;
    require_root("inventory_root", &request.inventory_root)?;
    require(
        request.reserved_units <= request.available_units,
        "reserved inventory exceeds available inventory",
    )?;
    require(
        request.reserve_coverage_bps >= config.min_reserve_coverage_bps,
        "reserve coverage below policy",
    )?;
    require(
        request.headroom_bps >= config.min_inventory_headroom_bps,
        "inventory headroom below policy",
    )?;
    Ok(())
}

fn validate_covenant_request(request: &RecordCovenantCheckRequest) -> Result<()> {
    require_non_empty("intent_id", &request.intent_id)?;
    require_root("covenant_root", &request.covenant_root)?;
    require_root("policy_root", &request.policy_root)?;
    require_root("hook_execution_root", &request.hook_execution_root)?;
    require_bps("fee_limit_bps", request.fee_limit_bps)?;
    require(
        request.max_settlement_units > 0,
        "max_settlement_units must be positive",
    )?;
    Ok(())
}

fn validate_pairing_request(config: &Config, request: &RecordMoneroPairingRequest) -> Result<()> {
    require_non_empty("intent_id", &request.intent_id)?;
    require(
        request.monero_network.is_monero(),
        "pairing network must be Monero",
    )?;
    require_root("output_commitment_root", &request.output_commitment_root)?;
    require_root("key_image_root", &request.key_image_root)?;
    require_root("tx_prefix_root", &request.tx_prefix_root)?;
    require_root("reserve_proof_root", &request.reserve_proof_root)?;
    require_root("view_tag_root", &request.view_tag_root)?;
    require(
        request.confirmation_height >= request.observed_height,
        "confirmation height must be at least observed height",
    )?;
    require(
        request
            .confirmation_height
            .saturating_sub(request.observed_height)
            <= config.max_monero_confirmation_gap,
        "Monero confirmation gap exceeds policy",
    )?;
    Ok(())
}

fn validate_sponsor_request(config: &Config, request: &OfferFeeSponsorRequest) -> Result<()> {
    require_non_empty("intent_id", &request.intent_id)?;
    require_root("sponsor_commitment", &request.sponsor_commitment)?;
    require_non_empty("sponsored_asset_id", &request.sponsored_asset_id)?;
    require_non_empty("fee_asset_id", &request.fee_asset_id)?;
    require_root(
        "reimbursement_commitment",
        &request.reimbursement_commitment,
    )?;
    require_root("sponsor_policy_root", &request.sponsor_policy_root)?;
    require_root("nullifier_root", &request.nullifier_root)?;
    require(request.max_fee_units > 0, "max_fee_units must be positive")?;
    require(
        request.expires_at_height > request.offered_at_height,
        "sponsor expiry must be after offer",
    )?;
    require(
        request
            .expires_at_height
            .saturating_sub(request.offered_at_height)
            <= config.sponsor_ttl_blocks,
        "sponsor ttl exceeds policy",
    )?;
    Ok(())
}

fn validate_route_request(config: &Config, request: &ProposeSettlementRouteRequest) -> Result<()> {
    require_non_empty("intent_id", &request.intent_id)?;
    require_non_empty("inventory_id", &request.inventory_id)?;
    require_root("router_commitment", &request.router_commitment)?;
    require_root("route_commitment_root", &request.route_commitment_root)?;
    require_root("route_witness_root", &request.route_witness_root)?;
    require(
        request.settlement_units > 0,
        "settlement_units must be positive",
    )?;
    require_bps("router_fee_bps", request.router_fee_bps)?;
    require(
        request.router_fee_bps <= config.max_router_fee_bps,
        "router fee exceeds policy",
    )?;
    require(
        !request.hop_roots.is_empty(),
        "route must include at least one hop root",
    )?;
    require(
        request.hop_roots.len() <= config.max_route_hops,
        "route hop count exceeds policy",
    )?;
    for hop_root in &request.hop_roots {
        require_root("hop_root", hop_root)?;
    }
    require(
        request.expires_at_height > request.proposed_at_height,
        "route expiry must be after proposal",
    )?;
    require(
        request
            .expires_at_height
            .saturating_sub(request.proposed_at_height)
            <= config.route_ttl_blocks,
        "route ttl exceeds policy",
    )?;
    Ok(())
}

fn validate_netting_request(
    config: &Config,
    request: &BuildSettlementNettingRequest,
) -> Result<()> {
    require_non_empty("asset_id", &request.asset_id)?;
    require(
        !request.intent_ids.is_empty(),
        "netting batch must include at least one intent",
    )?;
    require(
        request.intent_ids.len() <= config.max_intents_per_netting,
        "netting batch exceeds intent policy",
    )?;
    require_root("dependency_root", &request.dependency_root)?;
    require_root("inventory_delta_root", &request.inventory_delta_root)?;
    require_root("accounting_root", &request.accounting_root)?;
    require(
        request.expires_at_height > request.built_at_height,
        "netting expiry must be after build height",
    )?;
    require(
        request
            .expires_at_height
            .saturating_sub(request.built_at_height)
            <= config.netting_ttl_blocks,
        "netting ttl exceeds policy",
    )?;
    Ok(())
}

fn validate_settlement_request(request: &SettleNettingBatchRequest) -> Result<()> {
    require_non_empty("netting_id", &request.netting_id)?;
    require_root("settlement_receipt_root", &request.settlement_receipt_root)?;
    require_root("settlement_tx_root", &request.settlement_tx_root)?;
    require_root("proof_root", &request.proof_root)?;
    Ok(())
}

fn route_score(
    request: &ProposeSettlementRouteRequest,
    inventory: &LiquidityInventoryRecord,
) -> u128 {
    let fee_penalty = request.router_fee_bps as u128 * 1_000_000;
    let hop_penalty = request.hop_roots.len() as u128 * 75_000;
    let headroom_bonus = inventory.headroom_bps as u128 * 10_000;
    let coverage_bonus = inventory.reserve_coverage_bps.saturating_sub(MAX_BPS) as u128 * 5_000;
    10_000_000_000_u128
        .saturating_add(headroom_bonus)
        .saturating_add(coverage_bonus)
        .saturating_sub(fee_penalty)
        .saturating_sub(hop_penalty)
}

fn unique_strings(values: &[String]) -> bool {
    values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn saturating_u128_to_i128(value: u128) -> i128 {
    if value > i128::MAX as u128 {
        i128::MAX
    } else {
        value as i128
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if !condition {
        return Err(message.to_string());
    }
    Ok(())
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} cannot exceed {MAX_BPS}"));
    }
    Ok(())
}

fn require_root(label: &str, value: &str) -> Result<()> {
    if value.len() < 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!(
            "{label} must be a hex commitment/root of at least 32 chars"
        ));
    }
    Ok(())
}
