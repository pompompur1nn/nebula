use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<T> = Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-multichain-bridge-router-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PQ_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_ROUTE_SCHEME: &str =
    "roots-only-confidential-multichain-route-manifest-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_TICKET_SCHEME: &str =
    "sealed-deposit-exit-ticket-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_COMMITTEE_SCHEME: &str =
    "pq-threshold-bridge-committee-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_RELAY_SCHEME: &str =
    "low-fee-private-multichain-relay-quote-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_FINALITY_SCHEME: &str =
    "multichain-finality-attestation-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "bridge-router-privacy-fence-nullifier-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_REBATE_SCHEME: &str =
    "bridge-router-low-fee-rebate-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_SLASHING_SCHEME: &str =
    "bridge-router-slashing-evidence-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEVNET_HEIGHT: u64 = 728_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE:
    u64 = 16_384;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS:
    u16 = 256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS:
    u64 = 6_700;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_FAST_QUORUM_BPS: u64 =
    7_500;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS:
    u64 = 18;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS:
    u64 = 7;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_ROUTE_TTL_BLOCKS:
    u64 = 96;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS:
    u64 = 12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS:
    u64 = 144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_FINALITY_BLOCKS: u64 =
    24;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_CHAINS: usize =
    64;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_COMMITTEES:
    usize = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_MANIFESTS: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_TICKETS: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_QUOTES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_ATTESTATIONS:
    usize = 2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_FENCES: usize =
    2_097_152;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_REBATES: usize =
    1_048_576;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_SLASHING_EVENTS:
    usize = 524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeChainKind {
    MoneroL2,
    MoneroMainnet,
    Bitcoin,
    Ethereum,
    Solana,
    Cosmos,
    Celestia,
    Arbitrum,
    Optimism,
    Polygon,
}

impl BridgeChainKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroL2 => "monero_l2",
            Self::MoneroMainnet => "monero_mainnet",
            Self::Bitcoin => "bitcoin",
            Self::Ethereum => "ethereum",
            Self::Solana => "solana",
            Self::Cosmos => "cosmos",
            Self::Celestia => "celestia",
            Self::Arbitrum => "arbitrum",
            Self::Optimism => "optimism",
            Self::Polygon => "polygon",
        }
    }

    pub fn finality_weight(self) -> u64 {
        match self {
            Self::MoneroL2 => 9_800,
            Self::MoneroMainnet => 9_600,
            Self::Bitcoin => 9_500,
            Self::Ethereum => 9_200,
            Self::Celestia => 8_900,
            Self::Arbitrum => 8_700,
            Self::Optimism => 8_600,
            Self::Cosmos => 8_400,
            Self::Solana => 8_200,
            Self::Polygon => 8_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLane {
    ShieldedDeposit,
    ShieldedExit,
    AtomicSwap,
    LiquidityRebalance,
    EmergencyEscape,
    CommitteeRotation,
}

impl RouteLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedDeposit => "shielded_deposit",
            Self::ShieldedExit => "shielded_exit",
            Self::AtomicSwap => "atomic_swap",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::EmergencyEscape => "emergency_escape",
            Self::CommitteeRotation => "committee_rotation",
        }
    }

    pub fn priority_score(self) -> u64 {
        match self {
            Self::EmergencyEscape => 10_000,
            Self::ShieldedExit => 9_600,
            Self::ShieldedDeposit => 9_200,
            Self::AtomicSwap => 8_900,
            Self::LiquidityRebalance => 8_500,
            Self::CommitteeRotation => 8_100,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Draft,
    Quoted,
    Ticketed,
    Relaying,
    FinalityPending,
    Finalized,
    Expired,
    Cancelled,
    Disputed,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Quoted => "quoted",
            Self::Ticketed => "ticketed",
            Self::Relaying => "relaying",
            Self::FinalityPending => "finality_pending",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Quoted | Self::Ticketed | Self::Relaying | Self::FinalityPending
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Forming,
    Active,
    Rotating,
    Paused,
    Retired,
    Slashed,
}

impl CommitteeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forming => "forming",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Paused => "paused",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_route(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketKind {
    Deposit,
    Exit,
    Refund,
    Rebalance,
    EmergencyExit,
}

impl TicketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Exit => "exit",
            Self::Refund => "refund",
            Self::Rebalance => "rebalance",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Sealed,
    BoundToRoute,
    RelayReserved,
    Submitted,
    Finalized,
    Refunded,
    Expired,
    Rejected,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::BoundToRoute => "bound_to_route",
            Self::RelayReserved => "relay_reserved",
            Self::Submitted => "submitted",
            Self::Finalized => "finalized",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayQuoteStatus {
    Open,
    Selected,
    Published,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl RelayQuoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Selected => "selected",
            Self::Published => "published",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityVerdict {
    Pending,
    SourceFinal,
    DestinationFinal,
    BothFinal,
    ReorgDetected,
    InvalidRoute,
}

impl FinalityVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::SourceFinal => "source_final",
            Self::DestinationFinal => "destination_final",
            Self::BothFinal => "both_final",
            Self::ReorgDetected => "reorg_detected",
            Self::InvalidRoute => "invalid_route",
        }
    }

    pub fn finalizes(self) -> bool {
        matches!(self, Self::BothFinal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    RouteNullifier,
    TicketNullifier,
    DepositCommitment,
    ExitCommitment,
    RelayReplay,
    AddressLinkage,
    ViewKeyLeak,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RouteNullifier => "route_nullifier",
            Self::TicketNullifier => "ticket_nullifier",
            Self::DepositCommitment => "deposit_commitment",
            Self::ExitCommitment => "exit_commitment",
            Self::RelayReplay => "relay_replay",
            Self::AddressLinkage => "address_linkage",
            Self::ViewKeyLeak => "view_key_leak",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Open,
    Consumed,
    Released,
    Expired,
    Challenged,
}

impl FenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accrued,
    Claimable,
    Paid,
    Cancelled,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accrued => "accrued",
            Self::Claimable => "claimable",
            Self::Paid => "paid",
            Self::Cancelled => "cancelled",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashingReason {
    DoubleRoute,
    FalseFinality,
    RelayCensorship,
    TicketReplay,
    PrivacyFenceBypass,
    InvalidCommitteeSignature,
    DataUnavailable,
}

impl SlashingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoubleRoute => "double_route",
            Self::FalseFinality => "false_finality",
            Self::RelayCensorship => "relay_censorship",
            Self::TicketReplay => "ticket_replay",
            Self::PrivacyFenceBypass => "privacy_fence_bypass",
            Self::InvalidCommitteeSignature => "invalid_committee_signature",
            Self::DataUnavailable => "data_unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Submitted,
    Accepted,
    Rejected,
    Executed,
    Appealed,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
            Self::Appealed => "appealed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub quorum_weight_bps: u64,
    pub fast_quorum_bps: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub route_ttl_blocks: u64,
    pub quote_ttl_blocks: u64,
    pub ticket_ttl_blocks: u64,
    pub finality_blocks: u64,
    pub max_chains: usize,
    pub max_committees: usize,
    pub max_manifests: usize,
    pub max_tickets: usize,
    pub max_quotes: usize,
    pub max_attestations: usize,
    pub max_fences: usize,
    pub max_rebates: usize,
    pub max_slashing_events: usize,
    pub require_roots_only: bool,
    pub allow_emergency_routes: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            quorum_weight_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_QUORUM_WEIGHT_BPS,
            fast_quorum_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_FAST_QUORUM_BPS,
            max_user_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            route_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_ROUTE_TTL_BLOCKS,
            quote_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_QUOTE_TTL_BLOCKS,
            ticket_ttl_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_TICKET_TTL_BLOCKS,
            finality_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_FINALITY_BLOCKS,
            max_chains:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_CHAINS,
            max_committees:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_COMMITTEES,
            max_manifests:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_MANIFESTS,
            max_tickets:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_TICKETS,
            max_quotes:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_QUOTES,
            max_attestations:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_ATTESTATIONS,
            max_fences:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_FENCES,
            max_rebates:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_REBATES,
            max_slashing_events:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEFAULT_MAX_SLASHING_EVENTS,
            require_roots_only: true,
            allow_emergency_routes: true,
        }
    }

    pub fn validate(&self) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
        required("chain_id", &self.chain_id)?;
        validate_bps("quorum_weight_bps", self.quorum_weight_bps)?;
        validate_bps("fast_quorum_bps", self.fast_quorum_bps)?;
        validate_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        validate_bps("target_rebate_bps", self.target_rebate_bps)?;
        if self.quorum_weight_bps == 0 || self.fast_quorum_bps < self.quorum_weight_bps {
            return Err("bridge router quorum thresholds are invalid".to_string());
        }
        if self.route_ttl_blocks == 0 || self.quote_ttl_blocks == 0 || self.ticket_ttl_blocks == 0 {
            return Err("bridge router TTL values must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "quorum_weight_bps": self.quorum_weight_bps,
            "fast_quorum_bps": self.fast_quorum_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "route_ttl_blocks": self.route_ttl_blocks,
            "quote_ttl_blocks": self.quote_ttl_blocks,
            "ticket_ttl_blocks": self.ticket_ttl_blocks,
            "finality_blocks": self.finality_blocks,
            "max_chains": self.max_chains,
            "max_committees": self.max_committees,
            "max_manifests": self.max_manifests,
            "max_tickets": self.max_tickets,
            "max_quotes": self.max_quotes,
            "max_attestations": self.max_attestations,
            "max_fences": self.max_fences,
            "max_rebates": self.max_rebates,
            "max_slashing_events": self.max_slashing_events,
            "require_roots_only": self.require_roots_only,
            "allow_emergency_routes": self.allow_emergency_routes,
        })
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub chain_count: u64,
    pub committee_count: u64,
    pub manifest_count: u64,
    pub ticket_count: u64,
    pub quote_count: u64,
    pub attestation_count: u64,
    pub fence_count: u64,
    pub rebate_count: u64,
    pub slashing_event_count: u64,
    pub consumed_nullifier_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_count": self.chain_count,
            "committee_count": self.committee_count,
            "manifest_count": self.manifest_count,
            "ticket_count": self.ticket_count,
            "quote_count": self.quote_count,
            "attestation_count": self.attestation_count,
            "fence_count": self.fence_count,
            "rebate_count": self.rebate_count,
            "slashing_event_count": self.slashing_event_count,
            "consumed_nullifier_count": self.consumed_nullifier_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterChainRequest {
    pub chain_kind: BridgeChainKind,
    pub chain_namespace: String,
    pub finality_verifier_root: String,
    pub bridge_adapter_root: String,
    pub fee_asset_id: String,
    pub min_confirmations: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRecord {
    pub chain_id: String,
    pub chain_kind: BridgeChainKind,
    pub chain_namespace: String,
    pub finality_verifier_root: String,
    pub bridge_adapter_root: String,
    pub fee_asset_id: String,
    pub min_confirmations: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub active: bool,
}

impl ChainRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "chain_kind": self.chain_kind.as_str(),
            "chain_namespace": self.chain_namespace,
            "finality_verifier_root": self.finality_verifier_root,
            "bridge_adapter_root": self.bridge_adapter_root,
            "fee_asset_id": self.fee_asset_id,
            "min_confirmations": self.min_confirmations,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "registered_at_height": self.registered_at_height,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterBridgeCommitteeRequest {
    pub route_lane: RouteLane,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub operator_set_root: String,
    pub threshold_key_root: String,
    pub stake_root: String,
    pub epoch: u64,
    pub quorum_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeCommitteeRecord {
    pub committee_id: String,
    pub route_lane: RouteLane,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub operator_set_root: String,
    pub threshold_key_root: String,
    pub stake_root: String,
    pub epoch: u64,
    pub quorum_weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: CommitteeStatus,
    pub registered_at_height: u64,
}

impl BridgeCommitteeRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "committee_id": self.committee_id,
            "route_lane": self.route_lane.as_str(),
            "source_chain_id": self.source_chain_id,
            "destination_chain_id": self.destination_chain_id,
            "operator_set_root": self.operator_set_root,
            "threshold_key_root": self.threshold_key_root,
            "stake_root": self.stake_root,
            "epoch": self.epoch,
            "quorum_weight_bps": self.quorum_weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "registered_at_height": self.registered_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishRouteManifestRequest {
    pub route_lane: RouteLane,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub committee_id: String,
    pub route_commitment_root: String,
    pub encrypted_path_root: String,
    pub asset_commitment_root: String,
    pub amount_commitment_root: String,
    pub route_nullifier: String,
    pub max_fee_bps: u64,
    pub expiry_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub metadata: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteManifestRecord {
    pub manifest_id: String,
    pub route_lane: RouteLane,
    pub source_chain_id: String,
    pub destination_chain_id: String,
    pub committee_id: String,
    pub route_commitment_root: String,
    pub encrypted_path_root: String,
    pub asset_commitment_root: String,
    pub amount_commitment_root: String,
    pub route_nullifier_root: String,
    pub max_fee_bps: u64,
    pub expiry_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: RouteStatus,
    pub created_at_height: u64,
    pub selected_quote_id: Option<String>,
    pub ticket_ids: Vec<String>,
    pub finality_attestation_ids: Vec<String>,
    pub metadata_root: String,
}

impl RouteManifestRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "route_lane": self.route_lane.as_str(),
            "source_chain_id": self.source_chain_id,
            "destination_chain_id": self.destination_chain_id,
            "committee_id": self.committee_id,
            "route_commitment_root": self.route_commitment_root,
            "encrypted_path_root": self.encrypted_path_root,
            "asset_commitment_root": self.asset_commitment_root,
            "amount_commitment_root": self.amount_commitment_root,
            "route_nullifier_root": self.route_nullifier_root,
            "max_fee_bps": self.max_fee_bps,
            "expiry_height": self.expiry_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "selected_quote_id": self.selected_quote_id,
            "ticket_ids": self.ticket_ids,
            "finality_attestation_ids": self.finality_attestation_ids,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealBridgeTicketRequest {
    pub manifest_id: String,
    pub ticket_kind: TicketKind,
    pub ticket_commitment_root: String,
    pub sealed_payload_root: String,
    pub spender_key_commitment_root: String,
    pub recipient_commitment_root: String,
    pub ticket_nullifier: String,
    pub expiry_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTicketRecord {
    pub ticket_id: String,
    pub manifest_id: String,
    pub ticket_kind: TicketKind,
    pub ticket_commitment_root: String,
    pub sealed_payload_root: String,
    pub spender_key_commitment_root: String,
    pub recipient_commitment_root: String,
    pub ticket_nullifier_root: String,
    pub expiry_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: TicketStatus,
    pub sealed_at_height: u64,
}

impl BridgeTicketRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "manifest_id": self.manifest_id,
            "ticket_kind": self.ticket_kind.as_str(),
            "ticket_commitment_root": self.ticket_commitment_root,
            "sealed_payload_root": self.sealed_payload_root,
            "spender_key_commitment_root": self.spender_key_commitment_root,
            "recipient_commitment_root": self.recipient_commitment_root,
            "ticket_nullifier_root": self.ticket_nullifier_root,
            "expiry_height": self.expiry_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "sealed_at_height": self.sealed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRelayQuoteRequest {
    pub manifest_id: String,
    pub relayer_commitment: String,
    pub relay_path_root: String,
    pub quote_terms_root: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub valid_until_height: u64,
    pub relay_nullifier: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayQuoteRecord {
    pub quote_id: String,
    pub manifest_id: String,
    pub relayer_commitment_root: String,
    pub relay_path_root: String,
    pub quote_terms_root: String,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub valid_until_height: u64,
    pub relay_nullifier_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: RelayQuoteStatus,
    pub submitted_at_height: u64,
}

impl RelayQuoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "manifest_id": self.manifest_id,
            "relayer_commitment_root": self.relayer_commitment_root,
            "relay_path_root": self.relay_path_root,
            "quote_terms_root": self.quote_terms_root,
            "fee_bps": self.fee_bps,
            "rebate_bps": self.rebate_bps,
            "valid_until_height": self.valid_until_height,
            "relay_nullifier_root": self.relay_nullifier_root,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectRelayQuoteRequest {
    pub manifest_id: String,
    pub quote_id: String,
    pub selector_commitment: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitFinalityAttestationRequest {
    pub manifest_id: String,
    pub quote_id: Option<String>,
    pub committee_id: String,
    pub attester_commitment: String,
    pub source_block_root: String,
    pub destination_block_root: String,
    pub observed_state_root: String,
    pub verdict: FinalityVerdict,
    pub signature_bundle_root: String,
    pub attestation_nullifier: String,
    pub weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityAttestationRecord {
    pub attestation_id: String,
    pub manifest_id: String,
    pub quote_id: Option<String>,
    pub committee_id: String,
    pub attester_commitment_root: String,
    pub source_block_root: String,
    pub destination_block_root: String,
    pub observed_state_root: String,
    pub verdict: FinalityVerdict,
    pub signature_bundle_root: String,
    pub attestation_nullifier_root: String,
    pub weight_bps: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
}

impl FinalityAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "manifest_id": self.manifest_id,
            "quote_id": self.quote_id,
            "committee_id": self.committee_id,
            "attester_commitment_root": self.attester_commitment_root,
            "source_block_root": self.source_block_root,
            "destination_block_root": self.destination_block_root,
            "observed_state_root": self.observed_state_root,
            "verdict": self.verdict.as_str(),
            "signature_bundle_root": self.signature_bundle_root,
            "attestation_nullifier_root": self.attestation_nullifier_root,
            "weight_bps": self.weight_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenPrivacyFenceRequest {
    pub manifest_id: Option<String>,
    pub ticket_id: Option<String>,
    pub fence_kind: FenceKind,
    pub fence_commitment_root: String,
    pub nullifier: String,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub manifest_id: Option<String>,
    pub ticket_id: Option<String>,
    pub fence_kind: FenceKind,
    pub fence_commitment_root: String,
    pub nullifier_root: String,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub status: FenceStatus,
    pub opened_at_height: u64,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "manifest_id": self.manifest_id,
            "ticket_id": self.ticket_id,
            "fence_kind": self.fence_kind.as_str(),
            "fence_commitment_root": self.fence_commitment_root,
            "nullifier_root": self.nullifier_root,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccrueFeeRebateRequest {
    pub manifest_id: String,
    pub quote_id: String,
    pub beneficiary_commitment: String,
    pub rebate_asset_id: String,
    pub rebate_amount_commitment_root: String,
    pub rebate_bps: u64,
    pub claim_nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRebateRecord {
    pub rebate_id: String,
    pub manifest_id: String,
    pub quote_id: String,
    pub beneficiary_commitment_root: String,
    pub rebate_asset_id: String,
    pub rebate_amount_commitment_root: String,
    pub rebate_bps: u64,
    pub claim_nullifier_root: String,
    pub status: RebateStatus,
    pub accrued_at_height: u64,
    pub paid_at_height: Option<u64>,
}

impl FeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "manifest_id": self.manifest_id,
            "quote_id": self.quote_id,
            "beneficiary_commitment_root": self.beneficiary_commitment_root,
            "rebate_asset_id": self.rebate_asset_id,
            "rebate_amount_commitment_root": self.rebate_amount_commitment_root,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier_root": self.claim_nullifier_root,
            "status": self.status.as_str(),
            "accrued_at_height": self.accrued_at_height,
            "paid_at_height": self.paid_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSlashingEvidenceRequest {
    pub accused_committee_id: Option<String>,
    pub accused_quote_id: Option<String>,
    pub manifest_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub reporter_commitment: String,
    pub penalty_asset_id: String,
    pub penalty_amount_commitment_root: String,
    pub evidence_nullifier: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidenceRecord {
    pub evidence_id: String,
    pub accused_committee_id: Option<String>,
    pub accused_quote_id: Option<String>,
    pub manifest_id: Option<String>,
    pub reason: SlashingReason,
    pub evidence_root: String,
    pub reporter_commitment_root: String,
    pub penalty_asset_id: String,
    pub penalty_amount_commitment_root: String,
    pub evidence_nullifier_root: String,
    pub status: EvidenceStatus,
    pub submitted_at_height: u64,
}

impl SlashingEvidenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "accused_committee_id": self.accused_committee_id,
            "accused_quote_id": self.accused_quote_id,
            "manifest_id": self.manifest_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "reporter_commitment_root": self.reporter_commitment_root,
            "penalty_asset_id": self.penalty_asset_id,
            "penalty_amount_commitment_root": self.penalty_amount_commitment_root,
            "evidence_nullifier_root": self.evidence_nullifier_root,
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub chain_root: String,
    pub committee_root: String,
    pub manifest_root: String,
    pub ticket_root: String,
    pub quote_root: String,
    pub attestation_root: String,
    pub fence_root: String,
    pub rebate_root: String,
    pub slashing_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "chain_root": self.chain_root,
            "committee_root": self.committee_root,
            "manifest_root": self.manifest_root,
            "ticket_root": self.ticket_root,
            "quote_root": self.quote_root,
            "attestation_root": self.attestation_root,
            "fence_root": self.fence_root,
            "rebate_root": self.rebate_root,
            "slashing_root": self.slashing_root,
            "nullifier_root": self.nullifier_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub chain_id: String,
    pub protocol_version: String,
    pub current_height: u64,
    pub config: Config,
    pub counters: Counters,
    pub chains: BTreeMap<String, ChainRecord>,
    pub committees: BTreeMap<String, BridgeCommitteeRecord>,
    pub manifests: BTreeMap<String, RouteManifestRecord>,
    pub tickets: BTreeMap<String, BridgeTicketRecord>,
    pub quotes: BTreeMap<String, RelayQuoteRecord>,
    pub attestations: BTreeMap<String, FinalityAttestationRecord>,
    pub fences: BTreeMap<String, PrivacyFenceRecord>,
    pub rebates: BTreeMap<String, FeeRebateRecord>,
    pub slashing_events: BTreeMap<String, SlashingEvidenceRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(
        config: Config,
        current_height: u64,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            chain_id: config.chain_id.clone(),
            protocol_version:
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PROTOCOL_VERSION
                    .to_string(),
            current_height,
            config,
            counters: Counters::default(),
            chains: BTreeMap::new(),
            committees: BTreeMap::new(),
            manifests: BTreeMap::new(),
            tickets: BTreeMap::new(),
            quotes: BTreeMap::new(),
            attestations: BTreeMap::new(),
            fences: BTreeMap::new(),
            rebates: BTreeMap::new(),
            slashing_events: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<Self> {
        let mut state = Self::new(
            Config::devnet(),
            PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_DEVNET_HEIGHT,
        )?;
        let monero_l2 = state.register_chain(RegisterChainRequest {
            chain_kind: BridgeChainKind::MoneroL2,
            chain_namespace: "nebula-monero-l2-devnet".to_string(),
            finality_verifier_root: payload_root(
                "DEVNET-MONERO-L2-FINALITY",
                &json!({ "verifier": "monero-l2-fast-finality" }),
            ),
            bridge_adapter_root: payload_root(
                "DEVNET-MONERO-L2-ADAPTER",
                &json!({ "adapter": "confidential-monero-l2" }),
            ),
            fee_asset_id: "asset:wxmr".to_string(),
            min_confirmations: 8,
            privacy_set_size: 65_536,
            pq_security_bits: 256,
        })?;
        let ethereum = state.register_chain(RegisterChainRequest {
            chain_kind: BridgeChainKind::Ethereum,
            chain_namespace: "ethereum-sepolia-confidential-bridge".to_string(),
            finality_verifier_root: payload_root(
                "DEVNET-ETHEREUM-FINALITY",
                &json!({ "verifier": "ethereum-light-client-finality" }),
            ),
            bridge_adapter_root: payload_root(
                "DEVNET-ETHEREUM-ADAPTER",
                &json!({ "adapter": "shielded-evm-router" }),
            ),
            fee_asset_id: "asset:eth".to_string(),
            min_confirmations: 64,
            privacy_set_size: 65_536,
            pq_security_bits: 256,
        })?;
        let committee_id = state.register_bridge_committee(RegisterBridgeCommitteeRequest {
            route_lane: RouteLane::ShieldedDeposit,
            source_chain_id: ethereum,
            destination_chain_id: monero_l2,
            operator_set_root: payload_root(
                "DEVNET-COMMITTEE-OPERATORS",
                &json!({ "operators": ["router-a", "router-b", "router-c"] }),
            ),
            threshold_key_root: payload_root(
                "DEVNET-COMMITTEE-THRESHOLD-KEY",
                &json!({ "key": "ml-dsa-threshold-devnet" }),
            ),
            stake_root: payload_root(
                "DEVNET-COMMITTEE-STAKE",
                &json!({ "stake_asset": "asset:wxmr" }),
            ),
            epoch: 1,
            quorum_weight_bps: state.config.quorum_weight_bps,
            privacy_set_size: 65_536,
            pq_security_bits: 256,
        })?;
        let manifest_id = state.publish_route_manifest(PublishRouteManifestRequest {
            route_lane: RouteLane::ShieldedDeposit,
            source_chain_id: state
                .committees
                .get(&committee_id)
                .map(|committee| committee.source_chain_id.clone())
                .unwrap_or_default(),
            destination_chain_id: state
                .committees
                .get(&committee_id)
                .map(|committee| committee.destination_chain_id.clone())
                .unwrap_or_default(),
            committee_id,
            route_commitment_root: payload_root(
                "DEVNET-ROUTE-COMMITMENT",
                &json!({ "route": "ethereum-to-monero-l2" }),
            ),
            encrypted_path_root: payload_root(
                "DEVNET-ENCRYPTED-PATH",
                &json!({ "path": "ml-kem-sealed-hop-list" }),
            ),
            asset_commitment_root: payload_root("DEVNET-ASSET", &json!({ "asset": "weth" })),
            amount_commitment_root: payload_root("DEVNET-AMOUNT", &json!({ "amount": "sealed" })),
            route_nullifier: "devnet-route-nullifier-0".to_string(),
            max_fee_bps: 12,
            expiry_height: state.current_height + state.config.route_ttl_blocks,
            privacy_set_size: 65_536,
            pq_security_bits: 256,
            metadata: json!({ "devnet": true, "lane": "shielded_deposit" }),
        })?;
        let quote_id = state.submit_relay_quote(SubmitRelayQuoteRequest {
            manifest_id: manifest_id.clone(),
            relayer_commitment: "devnet-relayer-commitment".to_string(),
            relay_path_root: payload_root("DEVNET-RELAY-PATH", &json!({ "relay": "low-fee" })),
            quote_terms_root: payload_root("DEVNET-QUOTE-TERMS", &json!({ "fee_bps": 8 })),
            fee_bps: 8,
            rebate_bps: 4,
            valid_until_height: state.current_height + state.config.quote_ttl_blocks,
            relay_nullifier: "devnet-relay-nullifier-0".to_string(),
            privacy_set_size: 65_536,
            pq_security_bits: 256,
        })?;
        state.select_relay_quote(SelectRelayQuoteRequest {
            manifest_id,
            quote_id,
            selector_commitment: "devnet-selector".to_string(),
        })?;
        Ok(state)
    }

    pub fn register_chain(
        &mut self,
        request: RegisterChainRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.chains.len() >= self.config.max_chains {
            return Err("bridge router chain capacity exceeded".to_string());
        }
        required("chain_namespace", &request.chain_namespace)?;
        required("finality_verifier_root", &request.finality_verifier_root)?;
        required("bridge_adapter_root", &request.bridge_adapter_root)?;
        required("fee_asset_id", &request.fee_asset_id)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let counter = self.counters.chain_count.saturating_add(1);
        let chain_id = bridge_chain_id(&request, counter);
        if self.chains.contains_key(&chain_id) {
            return Err("bridge router chain already registered".to_string());
        }
        let record = ChainRecord {
            chain_id: chain_id.clone(),
            chain_kind: request.chain_kind,
            chain_namespace: request.chain_namespace,
            finality_verifier_root: request.finality_verifier_root,
            bridge_adapter_root: request.bridge_adapter_root,
            fee_asset_id: request.fee_asset_id,
            min_confirmations: request.min_confirmations,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            registered_at_height: self.current_height,
            active: true,
        };
        self.chains.insert(chain_id.clone(), record);
        self.counters.chain_count = counter;
        Ok(chain_id)
    }

    pub fn register_bridge_committee(
        &mut self,
        request: RegisterBridgeCommitteeRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.committees.len() >= self.config.max_committees {
            return Err("bridge router committee capacity exceeded".to_string());
        }
        self.require_chain(&request.source_chain_id)?;
        self.require_chain(&request.destination_chain_id)?;
        if request.source_chain_id == request.destination_chain_id {
            return Err(
                "bridge router committee requires distinct source and destination".to_string(),
            );
        }
        required("operator_set_root", &request.operator_set_root)?;
        required("threshold_key_root", &request.threshold_key_root)?;
        required("stake_root", &request.stake_root)?;
        validate_bps("quorum_weight_bps", request.quorum_weight_bps)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let counter = self.counters.committee_count.saturating_add(1);
        let committee_id = bridge_committee_id(&request, counter);
        let record = BridgeCommitteeRecord {
            committee_id: committee_id.clone(),
            route_lane: request.route_lane,
            source_chain_id: request.source_chain_id,
            destination_chain_id: request.destination_chain_id,
            operator_set_root: request.operator_set_root,
            threshold_key_root: request.threshold_key_root,
            stake_root: request.stake_root,
            epoch: request.epoch,
            quorum_weight_bps: request.quorum_weight_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: CommitteeStatus::Active,
            registered_at_height: self.current_height,
        };
        self.committees.insert(committee_id.clone(), record);
        self.counters.committee_count = counter;
        Ok(committee_id)
    }

    pub fn publish_route_manifest(
        &mut self,
        request: PublishRouteManifestRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.manifests.len() >= self.config.max_manifests {
            return Err("bridge router manifest capacity exceeded".to_string());
        }
        self.require_chain(&request.source_chain_id)?;
        self.require_chain(&request.destination_chain_id)?;
        let committee = self.require_committee(&request.committee_id)?;
        if !committee.status.can_route() {
            return Err("bridge router committee cannot route".to_string());
        }
        if committee.source_chain_id != request.source_chain_id
            || committee.destination_chain_id != request.destination_chain_id
        {
            return Err("bridge router committee route pair mismatch".to_string());
        }
        if !self.config.allow_emergency_routes && request.route_lane == RouteLane::EmergencyEscape {
            return Err("bridge router emergency routes disabled".to_string());
        }
        required("route_commitment_root", &request.route_commitment_root)?;
        required("encrypted_path_root", &request.encrypted_path_root)?;
        required("asset_commitment_root", &request.asset_commitment_root)?;
        required("amount_commitment_root", &request.amount_commitment_root)?;
        required("route_nullifier", &request.route_nullifier)?;
        validate_bps("max_fee_bps", request.max_fee_bps)?;
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err("bridge router manifest fee exceeds configured maximum".to_string());
        }
        validate_future_height("expiry_height", request.expiry_height, self.current_height)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTE-NULLIFIER",
            &request.route_nullifier,
        )?;
        let counter = self.counters.manifest_count.saturating_add(1);
        let manifest_id = route_manifest_id(&request, counter);
        let metadata_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-MANIFEST-METADATA",
            &request.metadata,
        );
        let record = RouteManifestRecord {
            manifest_id: manifest_id.clone(),
            route_lane: request.route_lane,
            source_chain_id: request.source_chain_id,
            destination_chain_id: request.destination_chain_id,
            committee_id: request.committee_id,
            route_commitment_root: request.route_commitment_root,
            encrypted_path_root: request.encrypted_path_root,
            asset_commitment_root: request.asset_commitment_root,
            amount_commitment_root: request.amount_commitment_root,
            route_nullifier_root: nullifier_root,
            max_fee_bps: request.max_fee_bps,
            expiry_height: request.expiry_height,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: RouteStatus::Draft,
            created_at_height: self.current_height,
            selected_quote_id: None,
            ticket_ids: Vec::new(),
            finality_attestation_ids: Vec::new(),
            metadata_root,
        };
        self.manifests.insert(manifest_id.clone(), record);
        self.counters.manifest_count = counter;
        Ok(manifest_id)
    }

    pub fn seal_bridge_ticket(
        &mut self,
        request: SealBridgeTicketRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.tickets.len() >= self.config.max_tickets {
            return Err("bridge router ticket capacity exceeded".to_string());
        }
        {
            let manifest = self.require_manifest(&request.manifest_id)?;
            if !manifest.status.live() {
                return Err("bridge router manifest is not live for ticket sealing".to_string());
            }
        }
        required("ticket_commitment_root", &request.ticket_commitment_root)?;
        required("sealed_payload_root", &request.sealed_payload_root)?;
        required(
            "spender_key_commitment_root",
            &request.spender_key_commitment_root,
        )?;
        required(
            "recipient_commitment_root",
            &request.recipient_commitment_root,
        )?;
        required("ticket_nullifier", &request.ticket_nullifier)?;
        validate_future_height("expiry_height", request.expiry_height, self.current_height)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-TICKET-NULLIFIER",
            &request.ticket_nullifier,
        )?;
        let counter = self.counters.ticket_count.saturating_add(1);
        let ticket_id = sealed_bridge_ticket_id(&request, counter);
        let record = BridgeTicketRecord {
            ticket_id: ticket_id.clone(),
            manifest_id: request.manifest_id.clone(),
            ticket_kind: request.ticket_kind,
            ticket_commitment_root: request.ticket_commitment_root,
            sealed_payload_root: request.sealed_payload_root,
            spender_key_commitment_root: request.spender_key_commitment_root,
            recipient_commitment_root: request.recipient_commitment_root,
            ticket_nullifier_root: nullifier_root,
            expiry_height: request.expiry_height,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: TicketStatus::BoundToRoute,
            sealed_at_height: self.current_height,
        };
        self.tickets.insert(ticket_id.clone(), record);
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.ticket_ids.push(ticket_id.clone());
            manifest.status = RouteStatus::Ticketed;
        }
        self.counters.ticket_count = counter;
        Ok(ticket_id)
    }

    pub fn submit_relay_quote(
        &mut self,
        request: SubmitRelayQuoteRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.quotes.len() >= self.config.max_quotes {
            return Err("bridge router quote capacity exceeded".to_string());
        }
        {
            let manifest = self.require_manifest(&request.manifest_id)?;
            if !manifest.status.live() {
                return Err("bridge router manifest is not live for quote".to_string());
            }
            if request.fee_bps > manifest.max_fee_bps {
                return Err("bridge router quote fee exceeds manifest maximum".to_string());
            }
        }
        required("relayer_commitment", &request.relayer_commitment)?;
        required("relay_path_root", &request.relay_path_root)?;
        required("quote_terms_root", &request.quote_terms_root)?;
        required("relay_nullifier", &request.relay_nullifier)?;
        validate_bps("fee_bps", request.fee_bps)?;
        validate_bps("rebate_bps", request.rebate_bps)?;
        validate_future_height(
            "valid_until_height",
            request.valid_until_height,
            self.current_height,
        )?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-RELAY-NULLIFIER",
            &request.relay_nullifier,
        )?;
        let counter = self.counters.quote_count.saturating_add(1);
        let quote_id = relay_quote_id(&request, counter);
        let record = RelayQuoteRecord {
            quote_id: quote_id.clone(),
            manifest_id: request.manifest_id.clone(),
            relayer_commitment_root: root_from_record(
                "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-RELAYER-COMMITMENT",
                &json!({ "relayer_commitment": request.relayer_commitment }),
            ),
            relay_path_root: request.relay_path_root,
            quote_terms_root: request.quote_terms_root,
            fee_bps: request.fee_bps,
            rebate_bps: request.rebate_bps,
            valid_until_height: request.valid_until_height,
            relay_nullifier_root: nullifier_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: RelayQuoteStatus::Open,
            submitted_at_height: self.current_height,
        };
        self.quotes.insert(quote_id.clone(), record);
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest.status = RouteStatus::Quoted;
        }
        self.counters.quote_count = counter;
        Ok(quote_id)
    }

    pub fn select_relay_quote(
        &mut self,
        request: SelectRelayQuoteRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
        required("selector_commitment", &request.selector_commitment)?;
        let quote = self
            .quotes
            .get_mut(&request.quote_id)
            .ok_or_else(|| "bridge router quote not found".to_string())?;
        if quote.manifest_id != request.manifest_id {
            return Err("bridge router quote manifest mismatch".to_string());
        }
        if quote.status != RelayQuoteStatus::Open {
            return Err("bridge router quote is not open".to_string());
        }
        if quote.valid_until_height <= self.current_height {
            quote.status = RelayQuoteStatus::Expired;
            return Err("bridge router quote expired".to_string());
        }
        quote.status = RelayQuoteStatus::Selected;
        let manifest = self
            .manifests
            .get_mut(&request.manifest_id)
            .ok_or_else(|| "bridge router manifest not found".to_string())?;
        manifest.selected_quote_id = Some(request.quote_id);
        manifest.status = RouteStatus::Relaying;
        Ok(())
    }

    pub fn submit_finality_attestation(
        &mut self,
        request: SubmitFinalityAttestationRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.attestations.len() >= self.config.max_attestations {
            return Err("bridge router attestation capacity exceeded".to_string());
        }
        self.require_manifest(&request.manifest_id)?;
        self.require_committee(&request.committee_id)?;
        if let Some(quote_id) = request.quote_id.as_ref() {
            self.require_quote(quote_id)?;
        }
        required("attester_commitment", &request.attester_commitment)?;
        required("source_block_root", &request.source_block_root)?;
        required("destination_block_root", &request.destination_block_root)?;
        required("observed_state_root", &request.observed_state_root)?;
        required("signature_bundle_root", &request.signature_bundle_root)?;
        required("attestation_nullifier", &request.attestation_nullifier)?;
        validate_bps("weight_bps", request.weight_bps)?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ATTESTATION-NULLIFIER",
            &request.attestation_nullifier,
        )?;
        let counter = self.counters.attestation_count.saturating_add(1);
        let attestation_id = finality_attestation_id(&request, counter);
        let record = FinalityAttestationRecord {
            attestation_id: attestation_id.clone(),
            manifest_id: request.manifest_id.clone(),
            quote_id: request.quote_id.clone(),
            committee_id: request.committee_id,
            attester_commitment_root: root_from_record(
                "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ATTESTER-COMMITMENT",
                &json!({ "attester_commitment": request.attester_commitment }),
            ),
            source_block_root: request.source_block_root,
            destination_block_root: request.destination_block_root,
            observed_state_root: request.observed_state_root,
            verdict: request.verdict,
            signature_bundle_root: request.signature_bundle_root,
            attestation_nullifier_root: nullifier_root,
            weight_bps: request.weight_bps,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: self.current_height,
        };
        self.attestations.insert(attestation_id.clone(), record);
        if let Some(manifest) = self.manifests.get_mut(&request.manifest_id) {
            manifest
                .finality_attestation_ids
                .push(attestation_id.clone());
            if request.verdict.finalizes() && request.weight_bps >= self.config.quorum_weight_bps {
                manifest.status = RouteStatus::Finalized;
            } else {
                manifest.status = RouteStatus::FinalityPending;
            }
        }
        if let Some(quote_id) = request.quote_id.as_ref() {
            if request.verdict.finalizes() {
                if let Some(quote) = self.quotes.get_mut(quote_id) {
                    quote.status = RelayQuoteStatus::Settled;
                }
            }
        }
        self.counters.attestation_count = counter;
        Ok(attestation_id)
    }

    pub fn open_privacy_fence(
        &mut self,
        request: OpenPrivacyFenceRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.fences.len() >= self.config.max_fences {
            return Err("bridge router privacy fence capacity exceeded".to_string());
        }
        if let Some(manifest_id) = request.manifest_id.as_ref() {
            self.require_manifest(manifest_id)?;
        }
        if let Some(ticket_id) = request.ticket_id.as_ref() {
            self.require_ticket(ticket_id)?;
        }
        required("fence_commitment_root", &request.fence_commitment_root)?;
        required("nullifier", &request.nullifier)?;
        validate_future_height(
            "expires_at_height",
            request.expires_at_height,
            self.current_height,
        )?;
        validate_privacy_and_pq(
            request.privacy_set_size,
            request.pq_security_bits,
            &self.config,
        )?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-FENCE-NULLIFIER",
            &request.nullifier,
        )?;
        let counter = self.counters.fence_count.saturating_add(1);
        let fence_id = privacy_fence_id(&request, counter);
        let record = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            manifest_id: request.manifest_id,
            ticket_id: request.ticket_id,
            fence_kind: request.fence_kind,
            fence_commitment_root: request.fence_commitment_root,
            nullifier_root,
            expires_at_height: request.expires_at_height,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            status: FenceStatus::Open,
            opened_at_height: self.current_height,
        };
        self.fences.insert(fence_id.clone(), record);
        self.counters.fence_count = counter;
        Ok(fence_id)
    }

    pub fn consume_privacy_fence(
        &mut self,
        fence_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
        let fence = self
            .fences
            .get_mut(fence_id)
            .ok_or_else(|| "bridge router privacy fence not found".to_string())?;
        if fence.status != FenceStatus::Open {
            return Err("bridge router privacy fence is not open".to_string());
        }
        if fence.expires_at_height <= self.current_height {
            fence.status = FenceStatus::Expired;
            return Err("bridge router privacy fence expired".to_string());
        }
        fence.status = FenceStatus::Consumed;
        Ok(())
    }

    pub fn accrue_fee_rebate(
        &mut self,
        request: AccrueFeeRebateRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.rebates.len() >= self.config.max_rebates {
            return Err("bridge router rebate capacity exceeded".to_string());
        }
        self.require_manifest(&request.manifest_id)?;
        self.require_quote(&request.quote_id)?;
        required("beneficiary_commitment", &request.beneficiary_commitment)?;
        required("rebate_asset_id", &request.rebate_asset_id)?;
        required(
            "rebate_amount_commitment_root",
            &request.rebate_amount_commitment_root,
        )?;
        required("claim_nullifier", &request.claim_nullifier)?;
        validate_bps("rebate_bps", request.rebate_bps)?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-REBATE-NULLIFIER",
            &request.claim_nullifier,
        )?;
        let counter = self.counters.rebate_count.saturating_add(1);
        let rebate_id = fee_rebate_id(&request, counter);
        let record = FeeRebateRecord {
            rebate_id: rebate_id.clone(),
            manifest_id: request.manifest_id,
            quote_id: request.quote_id,
            beneficiary_commitment_root: root_from_record(
                "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-REBATE-BENEFICIARY",
                &json!({ "beneficiary_commitment": request.beneficiary_commitment }),
            ),
            rebate_asset_id: request.rebate_asset_id,
            rebate_amount_commitment_root: request.rebate_amount_commitment_root,
            rebate_bps: request.rebate_bps,
            claim_nullifier_root: nullifier_root,
            status: RebateStatus::Accrued,
            accrued_at_height: self.current_height,
            paid_at_height: None,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebate_count = counter;
        Ok(rebate_id)
    }

    pub fn mark_rebate_paid(
        &mut self,
        rebate_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "bridge router rebate not found".to_string())?;
        if matches!(rebate.status, RebateStatus::Paid | RebateStatus::Cancelled) {
            return Err("bridge router rebate is terminal".to_string());
        }
        rebate.status = RebateStatus::Paid;
        rebate.paid_at_height = Some(self.current_height);
        Ok(())
    }

    pub fn submit_slashing_evidence(
        &mut self,
        request: SubmitSlashingEvidenceRequest,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        if self.slashing_events.len() >= self.config.max_slashing_events {
            return Err("bridge router slashing evidence capacity exceeded".to_string());
        }
        if let Some(committee_id) = request.accused_committee_id.as_ref() {
            self.require_committee(committee_id)?;
        }
        if let Some(quote_id) = request.accused_quote_id.as_ref() {
            self.require_quote(quote_id)?;
        }
        if let Some(manifest_id) = request.manifest_id.as_ref() {
            self.require_manifest(manifest_id)?;
        }
        required("evidence_root", &request.evidence_root)?;
        required("reporter_commitment", &request.reporter_commitment)?;
        required("penalty_asset_id", &request.penalty_asset_id)?;
        required(
            "penalty_amount_commitment_root",
            &request.penalty_amount_commitment_root,
        )?;
        required("evidence_nullifier", &request.evidence_nullifier)?;
        let nullifier_root = self.insert_nullifier(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-EVIDENCE-NULLIFIER",
            &request.evidence_nullifier,
        )?;
        let counter = self.counters.slashing_event_count.saturating_add(1);
        let evidence_id = slashing_evidence_id(&request, counter);
        let record = SlashingEvidenceRecord {
            evidence_id: evidence_id.clone(),
            accused_committee_id: request.accused_committee_id,
            accused_quote_id: request.accused_quote_id,
            manifest_id: request.manifest_id,
            reason: request.reason,
            evidence_root: request.evidence_root,
            reporter_commitment_root: root_from_record(
                "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-EVIDENCE-REPORTER",
                &json!({ "reporter_commitment": request.reporter_commitment }),
            ),
            penalty_asset_id: request.penalty_asset_id,
            penalty_amount_commitment_root: request.penalty_amount_commitment_root,
            evidence_nullifier_root: nullifier_root,
            status: EvidenceStatus::Submitted,
            submitted_at_height: self.current_height,
        };
        self.slashing_events.insert(evidence_id.clone(), record);
        self.counters.slashing_event_count = counter;
        Ok(evidence_id)
    }

    pub fn accept_slashing_evidence(
        &mut self,
        evidence_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
        let evidence = self
            .slashing_events
            .get_mut(evidence_id)
            .ok_or_else(|| "bridge router slashing evidence not found".to_string())?;
        evidence.status = EvidenceStatus::Accepted;
        if let Some(committee_id) = evidence.accused_committee_id.as_ref() {
            if let Some(committee) = self.committees.get_mut(committee_id) {
                committee.status = CommitteeStatus::Slashed;
            }
        }
        if let Some(quote_id) = evidence.accused_quote_id.as_ref() {
            if let Some(quote) = self.quotes.get_mut(quote_id) {
                quote.status = RelayQuoteStatus::Slashed;
            }
        }
        Ok(())
    }

    pub fn advance_height(&mut self, new_height: u64) {
        if new_height > self.current_height {
            self.current_height = new_height;
        }
    }

    pub fn expire_stale_records(&mut self) {
        for manifest in self.manifests.values_mut() {
            if manifest.status.live() && manifest.expiry_height <= self.current_height {
                manifest.status = RouteStatus::Expired;
            }
        }
        for ticket in self.tickets.values_mut() {
            if matches!(
                ticket.status,
                TicketStatus::Sealed | TicketStatus::BoundToRoute | TicketStatus::RelayReserved
            ) && ticket.expiry_height <= self.current_height
            {
                ticket.status = TicketStatus::Expired;
            }
        }
        for quote in self.quotes.values_mut() {
            if matches!(
                quote.status,
                RelayQuoteStatus::Open | RelayQuoteStatus::Selected
            ) && quote.valid_until_height <= self.current_height
            {
                quote.status = RelayQuoteStatus::Expired;
            }
        }
        for fence in self.fences.values_mut() {
            if fence.status == FenceStatus::Open && fence.expires_at_height <= self.current_height {
                fence.status = FenceStatus::Expired;
            }
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-CONFIG",
            &self.config.public_record(),
        );
        let counter_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-COUNTERS",
            &self.counters.public_record(),
        );
        let chain_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-CHAINS",
            &self
                .chains
                .values()
                .map(ChainRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let committee_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-COMMITTEES",
            &self
                .committees
                .values()
                .map(BridgeCommitteeRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let manifest_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-MANIFESTS",
            &self
                .manifests
                .values()
                .map(RouteManifestRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let ticket_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-TICKETS",
            &self
                .tickets
                .values()
                .map(BridgeTicketRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let quote_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-QUOTES",
            &self
                .quotes
                .values()
                .map(RelayQuoteRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let attestation_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-ATTESTATIONS",
            &self
                .attestations
                .values()
                .map(FinalityAttestationRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let fence_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-FENCES",
            &self
                .fences
                .values()
                .map(PrivacyFenceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let rebate_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-REBATES",
            &self
                .rebates
                .values()
                .map(FeeRebateRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let slashing_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-SLASHING",
            &self
                .slashing_events
                .values()
                .map(SlashingEvidenceRecord::public_record)
                .collect::<Vec<_>>(),
        );
        let nullifier_root = merkle_root(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-NULLIFIERS",
            &self
                .consumed_nullifiers
                .iter()
                .map(|nullifier| json!({ "nullifier": nullifier }))
                .collect::<Vec<_>>(),
        );
        let state_root = root_from_record(
            "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-STATE",
            &json!({
                "chain_id": self.chain_id,
                "protocol_version": self.protocol_version,
                "current_height": self.current_height,
                "config_root": config_root,
                "counter_root": counter_root,
                "chain_root": chain_root,
                "committee_root": committee_root,
                "manifest_root": manifest_root,
                "ticket_root": ticket_root,
                "quote_root": quote_root,
                "attestation_root": attestation_root,
                "fence_root": fence_root,
                "rebate_root": rebate_root,
                "slashing_root": slashing_root,
                "nullifier_root": nullifier_root,
            }),
        );
        Roots {
            config_root,
            counter_root,
            chain_root,
            committee_root,
            manifest_root,
            ticket_root,
            quote_root,
            attestation_root,
            fence_root,
            rebate_root,
            slashing_root,
            nullifier_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_pq_confidential_multichain_bridge_router_runtime",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_SCHEMA_VERSION,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_HASH_SUITE,
            "pq_suite": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PQ_SUITE,
            "route_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_ROUTE_SCHEME,
            "ticket_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_TICKET_SCHEME,
            "committee_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_COMMITTEE_SCHEME,
            "relay_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_RELAY_SCHEME,
            "finality_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_FINALITY_SCHEME,
            "privacy_fence_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PRIVACY_FENCE_SCHEME,
            "rebate_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_REBATE_SCHEME,
            "slashing_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_SLASHING_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "chain_ids": self.chains.keys().cloned().collect::<Vec<_>>(),
            "committee_ids": self.committees.keys().cloned().collect::<Vec<_>>(),
            "manifest_ids": self.manifests.keys().cloned().collect::<Vec<_>>(),
            "ticket_ids": self.tickets.keys().cloned().collect::<Vec<_>>(),
            "quote_ids": self.quotes.keys().cloned().collect::<Vec<_>>(),
            "attestation_ids": self.attestations.keys().cloned().collect::<Vec<_>>(),
            "fence_ids": self.fences.keys().cloned().collect::<Vec<_>>(),
            "rebate_ids": self.rebates.keys().cloned().collect::<Vec<_>>(),
            "slashing_event_ids": self.slashing_events.keys().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_chain(
        &self,
        chain_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<&ChainRecord> {
        self.chains
            .get(chain_id)
            .filter(|chain| chain.active)
            .ok_or_else(|| "bridge router chain not found or inactive".to_string())
    }

    fn require_committee(
        &self,
        committee_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<&BridgeCommitteeRecord> {
        self.committees
            .get(committee_id)
            .ok_or_else(|| "bridge router committee not found".to_string())
    }

    fn require_manifest(
        &self,
        manifest_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<&RouteManifestRecord> {
        self.manifests
            .get(manifest_id)
            .ok_or_else(|| "bridge router manifest not found".to_string())
    }

    fn require_ticket(
        &self,
        ticket_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<&BridgeTicketRecord> {
        self.tickets
            .get(ticket_id)
            .ok_or_else(|| "bridge router ticket not found".to_string())
    }

    fn require_quote(
        &self,
        quote_id: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<&RelayQuoteRecord> {
        self.quotes
            .get(quote_id)
            .ok_or_else(|| "bridge router quote not found".to_string())
    }

    fn insert_nullifier(
        &mut self,
        domain: &str,
        nullifier: &str,
    ) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<String> {
        let nullifier_root = root_from_record(domain, &json!({ "nullifier": nullifier }));
        if !self.consumed_nullifiers.insert(nullifier_root.clone()) {
            return Err("bridge router nullifier already consumed".to_string());
        }
        self.counters.consumed_nullifier_count =
            self.counters.consumed_nullifier_count.saturating_add(1);
        Ok(nullifier_root)
    }
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_PROTOCOL_VERSION,
            ),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(
        &format!("PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTER-PAYLOAD-{domain}"),
        payload,
    )
}

pub fn private_l2_pq_confidential_multichain_bridge_router_state_root(state: &State) -> String {
    state.state_root()
}

pub fn devnet() -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<State> {
    State::devnet()
}

pub fn bridge_chain_id(request: &RegisterChainRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-CHAIN-ID",
        &json!({
            "counter": counter,
            "chain_kind": request.chain_kind.as_str(),
            "chain_namespace": request.chain_namespace,
            "finality_verifier_root": request.finality_verifier_root,
            "bridge_adapter_root": request.bridge_adapter_root,
        }),
    )
}

pub fn bridge_committee_id(request: &RegisterBridgeCommitteeRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-COMMITTEE-ID",
        &json!({
            "counter": counter,
            "route_lane": request.route_lane.as_str(),
            "source_chain_id": request.source_chain_id,
            "destination_chain_id": request.destination_chain_id,
            "operator_set_root": request.operator_set_root,
            "threshold_key_root": request.threshold_key_root,
            "epoch": request.epoch,
        }),
    )
}

pub fn route_manifest_id(request: &PublishRouteManifestRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-ROUTE-MANIFEST-ID",
        &json!({
            "counter": counter,
            "route_lane": request.route_lane.as_str(),
            "source_chain_id": request.source_chain_id,
            "destination_chain_id": request.destination_chain_id,
            "committee_id": request.committee_id,
            "route_commitment_root": request.route_commitment_root,
            "encrypted_path_root": request.encrypted_path_root,
            "route_nullifier": request.route_nullifier,
        }),
    )
}

pub fn sealed_bridge_ticket_id(request: &SealBridgeTicketRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-SEALED-TICKET-ID",
        &json!({
            "counter": counter,
            "manifest_id": request.manifest_id,
            "ticket_kind": request.ticket_kind.as_str(),
            "ticket_commitment_root": request.ticket_commitment_root,
            "sealed_payload_root": request.sealed_payload_root,
            "ticket_nullifier": request.ticket_nullifier,
        }),
    )
}

pub fn relay_quote_id(request: &SubmitRelayQuoteRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-RELAY-QUOTE-ID",
        &json!({
            "counter": counter,
            "manifest_id": request.manifest_id,
            "relayer_commitment": request.relayer_commitment,
            "relay_path_root": request.relay_path_root,
            "quote_terms_root": request.quote_terms_root,
            "fee_bps": request.fee_bps,
            "relay_nullifier": request.relay_nullifier,
        }),
    )
}

pub fn finality_attestation_id(request: &SubmitFinalityAttestationRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-FINALITY-ATTESTATION-ID",
        &json!({
            "counter": counter,
            "manifest_id": request.manifest_id,
            "quote_id": request.quote_id,
            "committee_id": request.committee_id,
            "attester_commitment": request.attester_commitment,
            "source_block_root": request.source_block_root,
            "destination_block_root": request.destination_block_root,
            "verdict": request.verdict.as_str(),
            "attestation_nullifier": request.attestation_nullifier,
        }),
    )
}

pub fn privacy_fence_id(request: &OpenPrivacyFenceRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-PRIVACY-FENCE-ID",
        &json!({
            "counter": counter,
            "manifest_id": request.manifest_id,
            "ticket_id": request.ticket_id,
            "fence_kind": request.fence_kind.as_str(),
            "fence_commitment_root": request.fence_commitment_root,
            "nullifier": request.nullifier,
        }),
    )
}

pub fn fee_rebate_id(request: &AccrueFeeRebateRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-FEE-REBATE-ID",
        &json!({
            "counter": counter,
            "manifest_id": request.manifest_id,
            "quote_id": request.quote_id,
            "beneficiary_commitment": request.beneficiary_commitment,
            "rebate_asset_id": request.rebate_asset_id,
            "claim_nullifier": request.claim_nullifier,
        }),
    )
}

pub fn slashing_evidence_id(request: &SubmitSlashingEvidenceRequest, counter: u64) -> String {
    root_from_record(
        "PRIVATE-L2-PQ-CONFIDENTIAL-MULTICHAIN-BRIDGE-SLASHING-EVIDENCE-ID",
        &json!({
            "counter": counter,
            "accused_committee_id": request.accused_committee_id,
            "accused_quote_id": request.accused_quote_id,
            "manifest_id": request.manifest_id,
            "reason": request.reason.as_str(),
            "evidence_root": request.evidence_root,
            "evidence_nullifier": request.evidence_nullifier,
        }),
    )
}

fn validate_privacy_and_pq(
    privacy_set_size: u64,
    pq_security_bits: u16,
    config: &Config,
) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
    if privacy_set_size < config.min_privacy_set_size {
        return Err("bridge router privacy set below minimum".to_string());
    }
    if pq_security_bits < config.min_pq_security_bits {
        return Err("bridge router PQ security bits below minimum".to_string());
    }
    Ok(())
}

fn validate_bps(
    field: &str,
    value: u64,
) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
    if value > PRIVATE_L2_PQ_CONFIDENTIAL_MULTICHAIN_BRIDGE_ROUTER_RUNTIME_MAX_BPS {
        return Err(format!("bridge router {field} exceeds max bps"));
    }
    Ok(())
}

fn validate_future_height(
    field: &str,
    value: u64,
    current_height: u64,
) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
    if value <= current_height {
        return Err(format!("bridge router {field} must be in the future"));
    }
    Ok(())
}

fn required(
    field: &str,
    value: &str,
) -> PrivateL2PqConfidentialMultichainBridgeRouterRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("bridge router field {field} is required"));
    }
    Ok(())
}
