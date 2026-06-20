use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateBridgeRelaySchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-relay-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_DEVNET_HEIGHT: u64 = 744_320;
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_INTENT_SCHEME: &str =
    "ml-kem-1024-sealed-private-monero-bridge-relay-intent-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_HEADER_SCHEME: &str =
    "compact-monero-header-commitment-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_PRIVACY_FENCE_SCHEME: &str =
    "subaddress-viewtag-nullifier-privacy-fence-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-low-fee-relay-sponsor-slot-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_AUCTION_SCHEME: &str =
    "commit-reveal-private-bridge-relay-route-auction-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_WATCHER_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-relay-watcher-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_RECEIPT_SCHEME: &str =
    "zk-pq-private-bridge-finality-receipt-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_QUARANTINE_SCHEME: &str =
    "monero-l2-private-bridge-reorg-quarantine-root-v1";
pub const MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_BATCH_SCHEME: &str =
    "low-fee-private-bridge-relay-batch-schedule-v1";
pub const DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const DEFAULT_AUCTION_WINDOW_BLOCKS: u64 = 8;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_FINALITY_DEPTH: u64 = 20;
pub const DEFAULT_REORG_QUARANTINE_BLOCKS: u64 = 64;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_WATCHER_QUORUM: u16 = 5;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_RELAY_FEE_BPS: u64 = 16;
pub const DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 12;
pub const DEFAULT_LOW_FEE_TARGET_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_SPONSOR_BUDGET_MICRO_UNITS: u64 = 250_000_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_INTENTS: usize = 1_048_576;
pub const MAX_HEADER_COMMITMENTS: usize = 2_097_152;
pub const MAX_PRIVACY_FENCES: usize = 2_097_152;
pub const MAX_SPONSOR_SLOTS: usize = 524_288;
pub const MAX_ROUTE_AUCTIONS: usize = 524_288;
pub const MAX_ROUTE_BIDS: usize = 1_048_576;
pub const MAX_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_FINALITY_RECEIPTS: usize = 1_048_576;
pub const MAX_REORG_QUARANTINES: usize = 262_144;
pub const MAX_BATCHES: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayDirection {
    MoneroToL2,
    L2ToMonero,
    VaultRebalanceIn,
    VaultRebalanceOut,
    WatchtowerSweep,
    EmergencyExit,
}

impl RelayDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroToL2 => "monero_to_l2",
            Self::L2ToMonero => "l2_to_monero",
            Self::VaultRebalanceIn => "vault_rebalance_in",
            Self::VaultRebalanceOut => "vault_rebalance_out",
            Self::WatchtowerSweep => "watchtower_sweep",
            Self::EmergencyExit => "emergency_exit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayIntentStatus {
    Sealed,
    Fenced,
    AuctionOpen,
    Sponsored,
    Scheduled,
    Relayed,
    Finalized,
    Quarantined,
    Expired,
    Cancelled,
}

impl RelayIntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Fenced => "fenced",
            Self::AuctionOpen => "auction_open",
            Self::Sponsored => "sponsored",
            Self::Scheduled => "scheduled",
            Self::Relayed => "relayed",
            Self::Finalized => "finalized",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn schedulable(self) -> bool {
        matches!(
            self,
            Self::Fenced | Self::AuctionOpen | Self::Sponsored | Self::Scheduled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderCommitmentStatus {
    Observed,
    QuorumAttested,
    Canonical,
    Superseded,
    Quarantined,
}

impl HeaderCommitmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::QuorumAttested => "quorum_attested",
            Self::Canonical => "canonical",
            Self::Superseded => "superseded",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Subaddress,
    ViewTag,
    OneTimeAddress,
    KeyImage,
    TxPrefix,
    Nullifier,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subaddress => "subaddress",
            Self::ViewTag => "view_tag",
            Self::OneTimeAddress => "one_time_address",
            Self::KeyImage => "key_image",
            Self::TxPrefix => "tx_prefix",
            Self::Nullifier => "nullifier",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorSlotStatus {
    Open,
    Reserved,
    Attached,
    Spent,
    Released,
    Expired,
}

impl SponsorSlotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reserved => "reserved",
            Self::Attached => "attached",
            Self::Spent => "spent",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Open,
    Sealed,
    Selected,
    Expired,
    Cancelled,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Selected => "selected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteBidStatus {
    Committed,
    Revealed,
    Selected,
    Slashed,
    Rejected,
    Expired,
}

impl RouteBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Revealed => "revealed",
            Self::Selected => "selected",
            Self::Slashed => "slashed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherAttestationKind {
    HeaderObserved,
    TxSeen,
    OutputMatched,
    NoDoubleSpend,
    FinalityDepth,
    ReorgAlarm,
}

impl WatcherAttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderObserved => "header_observed",
            Self::TxSeen => "tx_seen",
            Self::OutputMatched => "output_matched",
            Self::NoDoubleSpend => "no_double_spend",
            Self::FinalityDepth => "finality_depth",
            Self::ReorgAlarm => "reorg_alarm",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityReceiptStatus {
    Proposed,
    WatcherQuorum,
    Finalized,
    Reorged,
    Disputed,
}

impl FinalityReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::WatcherQuorum => "watcher_quorum",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    Extending,
    Released,
    Slashed,
    Escalated,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Extending => "extending",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Escalated => "escalated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Draft,
    Open,
    Sealed,
    Relayed,
    Finalized,
    Quarantined,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Relayed => "relayed",
            Self::Finalized => "finalized",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub hash_suite: String,
    pub relay_intent_scheme: String,
    pub header_commitment_scheme: String,
    pub privacy_fence_scheme: String,
    pub sponsor_slot_scheme: String,
    pub route_auction_scheme: String,
    pub watcher_attestation_scheme: String,
    pub finality_receipt_scheme: String,
    pub reorg_quarantine_scheme: String,
    pub batch_scheme: String,
    pub default_intent_ttl_blocks: u64,
    pub default_auction_window_blocks: u64,
    pub default_batch_ttl_blocks: u64,
    pub finality_depth: u64,
    pub reorg_quarantine_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_watcher_quorum: u16,
    pub target_pq_security_bits: u16,
    pub max_relay_fee_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub low_fee_target_micro_units: u64,
    pub sponsor_budget_micro_units: u64,
    pub max_intents: usize,
    pub max_header_commitments: usize,
    pub max_privacy_fences: usize,
    pub max_sponsor_slots: usize,
    pub max_route_auctions: usize,
    pub max_route_bids: usize,
    pub max_watcher_attestations: usize,
    pub max_finality_receipts: usize,
    pub max_reorg_quarantines: usize,
    pub max_batches: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_L2_NETWORK.to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_HASH_SUITE.to_string(),
            relay_intent_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_INTENT_SCHEME
                .to_string(),
            header_commitment_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_HEADER_SCHEME.to_string(),
            privacy_fence_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_PRIVACY_FENCE_SCHEME.to_string(),
            sponsor_slot_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            route_auction_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_AUCTION_SCHEME.to_string(),
            watcher_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_WATCHER_SCHEME.to_string(),
            finality_receipt_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_RECEIPT_SCHEME.to_string(),
            reorg_quarantine_scheme:
                MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_QUARANTINE_SCHEME.to_string(),
            batch_scheme: MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_BATCH_SCHEME
                .to_string(),
            default_intent_ttl_blocks: DEFAULT_INTENT_TTL_BLOCKS,
            default_auction_window_blocks: DEFAULT_AUCTION_WINDOW_BLOCKS,
            default_batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            finality_depth: DEFAULT_FINALITY_DEPTH,
            reorg_quarantine_blocks: DEFAULT_REORG_QUARANTINE_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_relay_fee_bps: DEFAULT_MAX_RELAY_FEE_BPS,
            max_sponsor_rebate_bps: DEFAULT_MAX_SPONSOR_REBATE_BPS,
            low_fee_target_micro_units: DEFAULT_LOW_FEE_TARGET_MICRO_UNITS,
            sponsor_budget_micro_units: DEFAULT_SPONSOR_BUDGET_MICRO_UNITS,
            max_intents: MAX_INTENTS,
            max_header_commitments: MAX_HEADER_COMMITMENTS,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_sponsor_slots: MAX_SPONSOR_SLOTS,
            max_route_auctions: MAX_ROUTE_AUCTIONS,
            max_route_bids: MAX_ROUTE_BIDS,
            max_watcher_attestations: MAX_WATCHER_ATTESTATIONS,
            max_finality_receipts: MAX_FINALITY_RECEIPTS,
            max_reorg_quarantines: MAX_REORG_QUARANTINES,
            max_batches: MAX_BATCHES,
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
            "chain_id": CHAIN_ID,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "hash_suite": self.hash_suite,
            "relay_intent_scheme": self.relay_intent_scheme,
            "header_commitment_scheme": self.header_commitment_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "sponsor_slot_scheme": self.sponsor_slot_scheme,
            "route_auction_scheme": self.route_auction_scheme,
            "watcher_attestation_scheme": self.watcher_attestation_scheme,
            "finality_receipt_scheme": self.finality_receipt_scheme,
            "reorg_quarantine_scheme": self.reorg_quarantine_scheme,
            "batch_scheme": self.batch_scheme,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_auction_window_blocks": self.default_auction_window_blocks,
            "default_batch_ttl_blocks": self.default_batch_ttl_blocks,
            "finality_depth": self.finality_depth,
            "reorg_quarantine_blocks": self.reorg_quarantine_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_watcher_quorum": self.min_watcher_quorum,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "low_fee_target_micro_units": self.low_fee_target_micro_units,
            "sponsor_budget_micro_units": self.sponsor_budget_micro_units,
            "max_intents": self.max_intents,
            "max_header_commitments": self.max_header_commitments,
            "max_privacy_fences": self.max_privacy_fences,
            "max_sponsor_slots": self.max_sponsor_slots,
            "max_route_auctions": self.max_route_auctions,
            "max_route_bids": self.max_route_bids,
            "max_watcher_attestations": self.max_watcher_attestations,
            "max_finality_receipts": self.max_finality_receipts,
            "max_reorg_quarantines": self.max_reorg_quarantines,
            "max_batches": self.max_batches,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayIntent {
    pub intent_id: String,
    pub direction: RelayDirection,
    pub status: RelayIntentStatus,
    pub account_commitment: String,
    pub sealed_intent_root: String,
    pub amount_commitment_root: String,
    pub fee_limit_micro_units: u64,
    pub max_relay_fee_bps: u64,
    pub min_finality_depth: u64,
    pub preferred_batch_size: u16,
    pub privacy_set_size: u64,
    pub header_commitment_id: String,
    pub subaddress_fence_id: String,
    pub viewtag_fence_id: String,
    pub sponsor_slot_id: String,
    pub route_auction_id: String,
    pub batch_id: String,
    pub finality_receipt_id: String,
    pub nullifier_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl RelayIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "direction": self.direction.as_str(),
            "status": self.status.as_str(),
            "account_commitment": self.account_commitment,
            "sealed_intent_root": self.sealed_intent_root,
            "amount_commitment_root": self.amount_commitment_root,
            "fee_limit_micro_units": self.fee_limit_micro_units,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "min_finality_depth": self.min_finality_depth,
            "preferred_batch_size": self.preferred_batch_size,
            "privacy_set_size": self.privacy_set_size,
            "header_commitment_id": self.header_commitment_id,
            "subaddress_fence_id": self.subaddress_fence_id,
            "viewtag_fence_id": self.viewtag_fence_id,
            "sponsor_slot_id": self.sponsor_slot_id,
            "route_auction_id": self.route_auction_id,
            "batch_id": self.batch_id,
            "finality_receipt_id": self.finality_receipt_id,
            "nullifier_root": self.nullifier_root,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactHeaderCommitment {
    pub header_commitment_id: String,
    pub monero_height: u64,
    pub l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub merkle_tree_root: String,
    pub tx_count: u64,
    pub cumulative_difficulty_root: String,
    pub pow_aux_root: String,
    pub status: HeaderCommitmentStatus,
    pub watcher_quorum: u16,
    pub observed_at_height: u64,
}

impl CompactHeaderCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "header_commitment_id": self.header_commitment_id,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "block_hash_root": self.block_hash_root,
            "previous_block_hash_root": self.previous_block_hash_root,
            "merkle_tree_root": self.merkle_tree_root,
            "tx_count": self.tx_count,
            "cumulative_difficulty_root": self.cumulative_difficulty_root,
            "pow_aux_root": self.pow_aux_root,
            "status": self.status.as_str(),
            "watcher_quorum": self.watcher_quorum,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub inserted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "nullifier_root": self.nullifier_root,
            "replay_domain": self.replay_domain,
            "privacy_set_size": self.privacy_set_size,
            "inserted_at_height": self.inserted_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorSlot {
    pub sponsor_slot_id: String,
    pub sponsor_commitment: String,
    pub intent_id: String,
    pub batch_id: String,
    pub budget_root: String,
    pub reserved_micro_units: u64,
    pub spent_micro_units: u64,
    pub rebate_bps: u64,
    pub max_fee_micro_units: u64,
    pub status: SponsorSlotStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl FeeSponsorSlot {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_slot_id": self.sponsor_slot_id,
            "sponsor_commitment": self.sponsor_commitment,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "budget_root": self.budget_root,
            "reserved_micro_units": self.reserved_micro_units,
            "spent_micro_units": self.spent_micro_units,
            "rebate_bps": self.rebate_bps,
            "max_fee_micro_units": self.max_fee_micro_units,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteAuction {
    pub auction_id: String,
    pub intent_id: String,
    pub direction: RelayDirection,
    pub status: AuctionStatus,
    pub auctioneer_commitment: String,
    pub sealed_route_root: String,
    pub reserve_fee_root: String,
    pub min_watcher_quorum: u16,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub selected_bid_id: String,
}

impl RouteAuction {
    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "intent_id": self.intent_id,
            "direction": self.direction.as_str(),
            "status": self.status.as_str(),
            "auctioneer_commitment": self.auctioneer_commitment,
            "sealed_route_root": self.sealed_route_root,
            "reserve_fee_root": self.reserve_fee_root,
            "min_watcher_quorum": self.min_watcher_quorum,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "selected_bid_id": self.selected_bid_id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteBid {
    pub route_bid_id: String,
    pub auction_id: String,
    pub intent_id: String,
    pub relayer_commitment: String,
    pub status: RouteBidStatus,
    pub route_commitment_root: String,
    pub fee_quote_micro_units: u64,
    pub relay_fee_bps: u64,
    pub expected_latency_blocks: u64,
    pub reliability_score_bps: u64,
    pub stake_commitment_root: String,
    pub pq_signature_root: String,
    pub committed_at_height: u64,
    pub reveal_root: String,
}

impl RouteBid {
    pub fn public_record(&self) -> Value {
        json!({
            "route_bid_id": self.route_bid_id,
            "auction_id": self.auction_id,
            "intent_id": self.intent_id,
            "relayer_commitment": self.relayer_commitment,
            "status": self.status.as_str(),
            "route_commitment_root": self.route_commitment_root,
            "fee_quote_micro_units": self.fee_quote_micro_units,
            "relay_fee_bps": self.relay_fee_bps,
            "expected_latency_blocks": self.expected_latency_blocks,
            "reliability_score_bps": self.reliability_score_bps,
            "stake_commitment_root": self.stake_commitment_root,
            "pq_signature_root": self.pq_signature_root,
            "committed_at_height": self.committed_at_height,
            "reveal_root": self.reveal_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub kind: WatcherAttestationKind,
    pub watcher_commitment: String,
    pub subject_id: String,
    pub header_commitment_id: String,
    pub evidence_root: String,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub confidence_bps: u64,
    pub pq_signature_root: String,
    pub signed_at_height: u64,
}

impl WatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "kind": self.kind.as_str(),
            "watcher_commitment": self.watcher_commitment,
            "subject_id": self.subject_id,
            "header_commitment_id": self.header_commitment_id,
            "evidence_root": self.evidence_root,
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "confidence_bps": self.confidence_bps,
            "pq_signature_root": self.pq_signature_root,
            "signed_at_height": self.signed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelayBatch {
    pub batch_id: String,
    pub status: BatchStatus,
    pub direction: RelayDirection,
    pub intent_ids: Vec<String>,
    pub selected_bid_ids: Vec<String>,
    pub sponsor_slot_ids: Vec<String>,
    pub aggregate_intent_root: String,
    pub aggregate_route_root: String,
    pub aggregate_privacy_fence_root: String,
    pub aggregate_header_root: String,
    pub aggregate_nullifier_root: String,
    pub estimated_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub scheduled_at_height: u64,
    pub expires_at_height: u64,
    pub relay_tx_root: String,
}

impl LowFeeRelayBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "direction": self.direction.as_str(),
            "intent_ids": self.intent_ids,
            "selected_bid_ids": self.selected_bid_ids,
            "sponsor_slot_ids": self.sponsor_slot_ids,
            "aggregate_intent_root": self.aggregate_intent_root,
            "aggregate_route_root": self.aggregate_route_root,
            "aggregate_privacy_fence_root": self.aggregate_privacy_fence_root,
            "aggregate_header_root": self.aggregate_header_root,
            "aggregate_nullifier_root": self.aggregate_nullifier_root,
            "estimated_fee_micro_units": self.estimated_fee_micro_units,
            "target_fee_micro_units": self.target_fee_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "scheduled_at_height": self.scheduled_at_height,
            "expires_at_height": self.expires_at_height,
            "relay_tx_root": self.relay_tx_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityReceipt {
    pub receipt_id: String,
    pub intent_id: String,
    pub batch_id: String,
    pub header_commitment_id: String,
    pub status: FinalityReceiptStatus,
    pub finality_depth: u64,
    pub watcher_attestation_root: String,
    pub relay_tx_root: String,
    pub output_commitment_root: String,
    pub fee_paid_micro_units: u64,
    pub sponsor_rebate_micro_units: u64,
    pub proof_root: String,
    pub finalized_at_height: u64,
}

impl FinalityReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "header_commitment_id": self.header_commitment_id,
            "status": self.status.as_str(),
            "finality_depth": self.finality_depth,
            "watcher_attestation_root": self.watcher_attestation_root,
            "relay_tx_root": self.relay_tx_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_paid_micro_units": self.fee_paid_micro_units,
            "sponsor_rebate_micro_units": self.sponsor_rebate_micro_units,
            "proof_root": self.proof_root,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgQuarantine {
    pub quarantine_id: String,
    pub subject_id: String,
    pub batch_id: String,
    pub old_header_commitment_id: String,
    pub replacement_header_commitment_id: String,
    pub status: QuarantineStatus,
    pub reorg_depth: u64,
    pub evidence_root: String,
    pub affected_intent_root: String,
    pub opened_at_height: u64,
    pub release_at_height: u64,
}

impl ReorgQuarantine {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "batch_id": self.batch_id,
            "old_header_commitment_id": self.old_header_commitment_id,
            "replacement_header_commitment_id": self.replacement_header_commitment_id,
            "status": self.status.as_str(),
            "reorg_depth": self.reorg_depth,
            "evidence_root": self.evidence_root,
            "affected_intent_root": self.affected_intent_root,
            "opened_at_height": self.opened_at_height,
            "release_at_height": self.release_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub height: u64,
    pub sequence: u64,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub relay_intents: u64,
    pub active_intents: u64,
    pub header_commitments: u64,
    pub privacy_fences: u64,
    pub sponsor_slots: u64,
    pub route_auctions: u64,
    pub route_bids: u64,
    pub watcher_attestations: u64,
    pub finality_receipts: u64,
    pub reorg_quarantines: u64,
    pub relay_batches: u64,
    pub finalized_intents: u64,
    pub quarantined_intents: u64,
    pub events: u64,
    pub total_fee_limit_micro_units: u128,
    pub total_reserved_sponsor_micro_units: u128,
    pub total_paid_fee_micro_units: u128,
    pub total_sponsor_rebate_micro_units: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "relay_intents": self.relay_intents,
            "active_intents": self.active_intents,
            "header_commitments": self.header_commitments,
            "privacy_fences": self.privacy_fences,
            "sponsor_slots": self.sponsor_slots,
            "route_auctions": self.route_auctions,
            "route_bids": self.route_bids,
            "watcher_attestations": self.watcher_attestations,
            "finality_receipts": self.finality_receipts,
            "reorg_quarantines": self.reorg_quarantines,
            "relay_batches": self.relay_batches,
            "finalized_intents": self.finalized_intents,
            "quarantined_intents": self.quarantined_intents,
            "events": self.events,
            "total_fee_limit_micro_units": self.total_fee_limit_micro_units.to_string(),
            "total_reserved_sponsor_micro_units": self.total_reserved_sponsor_micro_units.to_string(),
            "total_paid_fee_micro_units": self.total_paid_fee_micro_units.to_string(),
            "total_sponsor_rebate_micro_units": self.total_sponsor_rebate_micro_units.to_string(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub relay_intent_root: String,
    pub header_commitment_root: String,
    pub privacy_fence_root: String,
    pub sponsor_slot_root: String,
    pub route_auction_root: String,
    pub route_bid_root: String,
    pub watcher_attestation_root: String,
    pub finality_receipt_root: String,
    pub reorg_quarantine_root: String,
    pub relay_batch_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "relay_intent_root": self.relay_intent_root,
            "header_commitment_root": self.header_commitment_root,
            "privacy_fence_root": self.privacy_fence_root,
            "sponsor_slot_root": self.sponsor_slot_root,
            "route_auction_root": self.route_auction_root,
            "route_bid_root": self.route_bid_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "finality_receipt_root": self.finality_receipt_root,
            "reorg_quarantine_root": self.reorg_quarantine_root,
            "relay_batch_root": self.relay_batch_root,
            "event_root": self.event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitRelayIntentRequest {
    pub direction: RelayDirection,
    pub account_commitment: String,
    pub sealed_intent_root: String,
    pub amount_commitment_root: String,
    pub fee_limit_micro_units: u64,
    pub max_relay_fee_bps: u64,
    pub min_finality_depth: u64,
    pub preferred_batch_size: u16,
    pub privacy_set_size: u64,
    pub header_commitment_id: String,
    pub nullifier_root: String,
    pub metadata_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitHeaderRequest {
    pub monero_height: u64,
    pub l2_height: u64,
    pub block_hash_root: String,
    pub previous_block_hash_root: String,
    pub merkle_tree_root: String,
    pub tx_count: u64,
    pub cumulative_difficulty_root: String,
    pub pow_aux_root: String,
    pub watcher_quorum: u16,
    pub observed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertPrivacyFenceRequest {
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub nullifier_root: String,
    pub replay_domain: String,
    pub privacy_set_size: u64,
    pub inserted_at_height: u64,
    pub ttl_blocks: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveSponsorSlotRequest {
    pub sponsor_commitment: String,
    pub intent_id: String,
    pub budget_root: String,
    pub reserved_micro_units: u64,
    pub rebate_bps: u64,
    pub max_fee_micro_units: u64,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenRouteAuctionRequest {
    pub intent_id: String,
    pub auctioneer_commitment: String,
    pub sealed_route_root: String,
    pub reserve_fee_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRouteBidRequest {
    pub auction_id: String,
    pub intent_id: String,
    pub relayer_commitment: String,
    pub route_commitment_root: String,
    pub fee_quote_micro_units: u64,
    pub relay_fee_bps: u64,
    pub expected_latency_blocks: u64,
    pub reliability_score_bps: u64,
    pub stake_commitment_root: String,
    pub pq_signature_root: String,
    pub committed_at_height: u64,
    pub reveal_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectRouteBidRequest {
    pub auction_id: String,
    pub route_bid_id: String,
    pub selected_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordWatcherAttestationRequest {
    pub kind: WatcherAttestationKind,
    pub watcher_commitment: String,
    pub subject_id: String,
    pub header_commitment_id: String,
    pub evidence_root: String,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub confidence_bps: u64,
    pub pq_signature_root: String,
    pub signed_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduleLowFeeBatchRequest {
    pub direction: RelayDirection,
    pub intent_ids: Vec<String>,
    pub selected_bid_ids: Vec<String>,
    pub sponsor_slot_ids: Vec<String>,
    pub aggregate_intent_root: String,
    pub aggregate_route_root: String,
    pub aggregate_privacy_fence_root: String,
    pub aggregate_header_root: String,
    pub aggregate_nullifier_root: String,
    pub estimated_fee_micro_units: u64,
    pub target_fee_micro_units: u64,
    pub privacy_set_size: u64,
    pub scheduled_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordFinalityReceiptRequest {
    pub intent_id: String,
    pub batch_id: String,
    pub header_commitment_id: String,
    pub finality_depth: u64,
    pub watcher_attestation_ids: Vec<String>,
    pub relay_tx_root: String,
    pub output_commitment_root: String,
    pub fee_paid_micro_units: u64,
    pub sponsor_rebate_micro_units: u64,
    pub proof_root: String,
    pub finalized_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenReorgQuarantineRequest {
    pub subject_id: String,
    pub batch_id: String,
    pub old_header_commitment_id: String,
    pub replacement_header_commitment_id: String,
    pub reorg_depth: u64,
    pub evidence_root: String,
    pub affected_intent_root: String,
    pub opened_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub sponsor_budget_remaining_micro_units: u64,
    pub relay_intents: BTreeMap<String, RelayIntent>,
    pub header_commitments: BTreeMap<String, CompactHeaderCommitment>,
    pub privacy_fences: BTreeMap<String, PrivacyFence>,
    pub sponsor_slots: BTreeMap<String, FeeSponsorSlot>,
    pub route_auctions: BTreeMap<String, RouteAuction>,
    pub route_bids: BTreeMap<String, RouteBid>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub finality_receipts: BTreeMap<String, FinalityReceipt>,
    pub reorg_quarantines: BTreeMap<String, ReorgQuarantine>,
    pub relay_batches: BTreeMap<String, LowFeeRelayBatch>,
    pub events: BTreeMap<String, RuntimeEvent>,
}

impl Default for State {
    fn default() -> Self {
        let config = Config::default();
        Self::empty(
            config.clone(),
            MONERO_L2_PQ_PRIVATE_BRIDGE_RELAY_SCHEDULER_RUNTIME_DEVNET_HEIGHT,
        )
    }
}

impl State {
    pub fn empty(config: Config, height: u64) -> Self {
        Self {
            sponsor_budget_remaining_micro_units: config.sponsor_budget_micro_units,
            config,
            height,
            relay_intents: BTreeMap::new(),
            header_commitments: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            sponsor_slots: BTreeMap::new(),
            route_auctions: BTreeMap::new(),
            route_bids: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            finality_receipts: BTreeMap::new(),
            reorg_quarantines: BTreeMap::new(),
            relay_batches: BTreeMap::new(),
            events: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::default();
        let header_id = state
            .commit_header(CommitHeaderRequest {
                monero_height: 3_104_224,
                l2_height: state.height,
                block_hash_root: string_root("DEVNET-MONERO-BLOCK", "relay-scheduler-head"),
                previous_block_hash_root: string_root(
                    "DEVNET-MONERO-BLOCK",
                    "relay-scheduler-prev",
                ),
                merkle_tree_root: string_root("DEVNET-MONERO-TX-MERKLE", "compact-tree"),
                tx_count: 19,
                cumulative_difficulty_root: string_root("DEVNET-MONERO-DIFFICULTY", "compact-diff"),
                pow_aux_root: string_root("DEVNET-MONERO-POW", "aux-proof"),
                watcher_quorum: 7,
                observed_at_height: state.height,
            })
            .expect("devnet header");

        let intent_id = state
            .submit_relay_intent(SubmitRelayIntentRequest {
                direction: RelayDirection::MoneroToL2,
                account_commitment: commitment("alice-private-bridge-account"),
                sealed_intent_root: string_root("DEVNET-RELAY-INTENT", "alice-sealed-intent"),
                amount_commitment_root: string_root("DEVNET-RELAY-AMOUNT", "alice-42-xmr"),
                fee_limit_micro_units: 4_500,
                max_relay_fee_bps: 11,
                min_finality_depth: state.config.finality_depth,
                preferred_batch_size: 32,
                privacy_set_size: 32_768,
                header_commitment_id: header_id.clone(),
                nullifier_root: string_root("DEVNET-RELAY-NULLIFIER", "alice-intent"),
                metadata_root: string_root("DEVNET-RELAY-METADATA", "alice-fast-low-fee"),
                created_at_height: state.height,
            })
            .expect("devnet intent");

        let subaddress_fence = state
            .insert_privacy_fence(InsertPrivacyFenceRequest {
                kind: FenceKind::Subaddress,
                subject_id: intent_id.clone(),
                commitment_root: string_root("DEVNET-SUBADDRESS", "alice-subaddress-fence"),
                nullifier_root: string_root("DEVNET-SUBADDRESS-NULLIFIER", "alice-subaddress"),
                replay_domain: "monero-l2-relay-scheduler-devnet".to_string(),
                privacy_set_size: 32_768,
                inserted_at_height: state.height,
                ttl_blocks: 192,
            })
            .expect("devnet subaddress fence");
        let viewtag_fence = state
            .insert_privacy_fence(InsertPrivacyFenceRequest {
                kind: FenceKind::ViewTag,
                subject_id: intent_id.clone(),
                commitment_root: string_root("DEVNET-VIEWTAG", "alice-viewtag-fence"),
                nullifier_root: string_root("DEVNET-VIEWTAG-NULLIFIER", "alice-viewtag"),
                replay_domain: "monero-l2-relay-scheduler-devnet".to_string(),
                privacy_set_size: 32_768,
                inserted_at_height: state.height,
                ttl_blocks: 192,
            })
            .expect("devnet viewtag fence");
        if let Some(intent) = state.relay_intents.get_mut(&intent_id) {
            intent.subaddress_fence_id = subaddress_fence;
            intent.viewtag_fence_id = viewtag_fence;
            intent.status = RelayIntentStatus::Fenced;
        }

        let sponsor_slot = state
            .reserve_sponsor_slot(ReserveSponsorSlotRequest {
                sponsor_commitment: commitment("nebula-low-fee-relay-sponsor"),
                intent_id: intent_id.clone(),
                budget_root: string_root("DEVNET-SPONSOR-BUDGET", "relay-sponsor-budget"),
                reserved_micro_units: 3_000,
                rebate_bps: 8,
                max_fee_micro_units: 4_500,
                opened_at_height: state.height + 1,
            })
            .expect("devnet sponsor");

        let auction_id = state
            .open_route_auction(OpenRouteAuctionRequest {
                intent_id: intent_id.clone(),
                auctioneer_commitment: commitment("relay-auctioneer-cobalt"),
                sealed_route_root: string_root("DEVNET-ROUTE-AUCTION", "sealed-routes"),
                reserve_fee_root: string_root("DEVNET-ROUTE-RESERVE", "low-fee-reserve"),
                opened_at_height: state.height + 1,
            })
            .expect("devnet auction");

        let bid_id = state
            .commit_route_bid(CommitRouteBidRequest {
                auction_id: auction_id.clone(),
                intent_id: intent_id.clone(),
                relayer_commitment: commitment("relayer-mlkem-alpha"),
                route_commitment_root: string_root("DEVNET-ROUTE", "alpha-private-route"),
                fee_quote_micro_units: 2_300,
                relay_fee_bps: 7,
                expected_latency_blocks: 3,
                reliability_score_bps: 9_850,
                stake_commitment_root: string_root("DEVNET-RELAYER-STAKE", "alpha-stake"),
                pq_signature_root: string_root("DEVNET-PQ-SIGNATURE", "alpha-bid"),
                committed_at_height: state.height + 2,
                reveal_root: string_root("DEVNET-ROUTE-REVEAL", "alpha-reveal"),
            })
            .expect("devnet bid");
        state
            .select_route_bid(SelectRouteBidRequest {
                auction_id,
                route_bid_id: bid_id.clone(),
                selected_at_height: state.height + 3,
            })
            .expect("devnet select bid");

        let attestation_ids = (0..7)
            .map(|idx| {
                state.record_watcher_attestation(RecordWatcherAttestationRequest {
                    kind: WatcherAttestationKind::FinalityDepth,
                    watcher_commitment: commitment(&format!("watcher-{idx}")),
                    subject_id: intent_id.clone(),
                    header_commitment_id: header_id.clone(),
                    evidence_root: string_root(
                        "DEVNET-WATCHER-EVIDENCE",
                        &format!("watcher-{idx}"),
                    ),
                    observed_monero_height: 3_104_244,
                    observed_l2_height: state.height + 20,
                    confidence_bps: 9_900,
                    pq_signature_root: string_root(
                        "DEVNET-WATCHER-PQ-SIGNATURE",
                        &format!("watcher-{idx}"),
                    ),
                    signed_at_height: state.height + 20,
                })
            })
            .collect::<Result<Vec<_>>>()
            .expect("devnet attestations");

        let batch_id = state
            .schedule_low_fee_batch(ScheduleLowFeeBatchRequest {
                direction: RelayDirection::MoneroToL2,
                intent_ids: vec![intent_id.clone()],
                selected_bid_ids: vec![bid_id],
                sponsor_slot_ids: vec![sponsor_slot],
                aggregate_intent_root: string_root("DEVNET-BATCH-INTENTS", "batch-0"),
                aggregate_route_root: string_root("DEVNET-BATCH-ROUTES", "batch-0"),
                aggregate_privacy_fence_root: string_root("DEVNET-BATCH-FENCES", "batch-0"),
                aggregate_header_root: string_root("DEVNET-BATCH-HEADERS", "batch-0"),
                aggregate_nullifier_root: string_root("DEVNET-BATCH-NULLIFIERS", "batch-0"),
                estimated_fee_micro_units: 2_250,
                target_fee_micro_units: state.config.low_fee_target_micro_units,
                privacy_set_size: 32_768,
                scheduled_at_height: state.height + 4,
            })
            .expect("devnet batch");

        let _ = state.record_finality_receipt(RecordFinalityReceiptRequest {
            intent_id,
            batch_id,
            header_commitment_id: header_id,
            finality_depth: state.config.finality_depth,
            watcher_attestation_ids: attestation_ids,
            relay_tx_root: string_root("DEVNET-RELAY-TX", "batch-0-relay"),
            output_commitment_root: string_root("DEVNET-RELAY-OUTPUT", "alice-output"),
            fee_paid_micro_units: 2_210,
            sponsor_rebate_micro_units: 176,
            proof_root: string_root("DEVNET-FINALITY-PROOF", "batch-0"),
            finalized_at_height: state.height + 24,
        });

        state
    }

    pub fn counters(&self) -> Counters {
        Counters {
            relay_intents: self.relay_intents.len() as u64,
            active_intents: self
                .relay_intents
                .values()
                .filter(|intent| intent.status.schedulable())
                .count() as u64,
            header_commitments: self.header_commitments.len() as u64,
            privacy_fences: self.privacy_fences.len() as u64,
            sponsor_slots: self.sponsor_slots.len() as u64,
            route_auctions: self.route_auctions.len() as u64,
            route_bids: self.route_bids.len() as u64,
            watcher_attestations: self.watcher_attestations.len() as u64,
            finality_receipts: self.finality_receipts.len() as u64,
            reorg_quarantines: self.reorg_quarantines.len() as u64,
            relay_batches: self.relay_batches.len() as u64,
            finalized_intents: self
                .relay_intents
                .values()
                .filter(|intent| intent.status == RelayIntentStatus::Finalized)
                .count() as u64,
            quarantined_intents: self
                .relay_intents
                .values()
                .filter(|intent| intent.status == RelayIntentStatus::Quarantined)
                .count() as u64,
            events: self.events.len() as u64,
            total_fee_limit_micro_units: self
                .relay_intents
                .values()
                .map(|intent| intent.fee_limit_micro_units as u128)
                .sum(),
            total_reserved_sponsor_micro_units: self
                .sponsor_slots
                .values()
                .map(|slot| slot.reserved_micro_units as u128)
                .sum(),
            total_paid_fee_micro_units: self
                .finality_receipts
                .values()
                .map(|receipt| receipt.fee_paid_micro_units as u128)
                .sum(),
            total_sponsor_rebate_micro_units: self
                .finality_receipts
                .values()
                .map(|receipt| receipt.sponsor_rebate_micro_units as u128)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: payload_root(
                "MONERO-L2-RELAY-SCHEDULER-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: payload_root(
                "MONERO-L2-RELAY-SCHEDULER-COUNTERS",
                &self.counters().public_record(),
            ),
            relay_intent_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-INTENT",
                self.relay_intents
                    .values()
                    .map(RelayIntent::public_record)
                    .collect(),
            ),
            header_commitment_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-HEADER",
                self.header_commitments
                    .values()
                    .map(CompactHeaderCommitment::public_record)
                    .collect(),
            ),
            privacy_fence_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-PRIVACY-FENCE",
                self.privacy_fences
                    .values()
                    .map(PrivacyFence::public_record)
                    .collect(),
            ),
            sponsor_slot_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-SPONSOR-SLOT",
                self.sponsor_slots
                    .values()
                    .map(FeeSponsorSlot::public_record)
                    .collect(),
            ),
            route_auction_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-AUCTION",
                self.route_auctions
                    .values()
                    .map(RouteAuction::public_record)
                    .collect(),
            ),
            route_bid_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-ROUTE-BID",
                self.route_bids
                    .values()
                    .map(RouteBid::public_record)
                    .collect(),
            ),
            watcher_attestation_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-WATCHER",
                self.watcher_attestations
                    .values()
                    .map(WatcherAttestation::public_record)
                    .collect(),
            ),
            finality_receipt_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-FINALITY-RECEIPT",
                self.finality_receipts
                    .values()
                    .map(FinalityReceipt::public_record)
                    .collect(),
            ),
            reorg_quarantine_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-REORG-QUARANTINE",
                self.reorg_quarantines
                    .values()
                    .map(ReorgQuarantine::public_record)
                    .collect(),
            ),
            relay_batch_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-BATCH",
                self.relay_batches
                    .values()
                    .map(LowFeeRelayBatch::public_record)
                    .collect(),
            ),
            event_root: root_from_records(
                "MONERO-L2-RELAY-SCHEDULER-EVENT",
                self.events
                    .values()
                    .map(RuntimeEvent::public_record)
                    .collect(),
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_l2_pq_private_bridge_relay_scheduler_runtime_state",
            "chain_id": CHAIN_ID,
            "height": self.height,
            "protocol_version": self.config.protocol_version,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
            "sponsor_budget_remaining_micro_units": self.sponsor_budget_remaining_micro_units,
            "relay_intents": self.relay_intents.values().map(RelayIntent::public_record).collect::<Vec<_>>(),
            "header_commitments": self.header_commitments.values().map(CompactHeaderCommitment::public_record).collect::<Vec<_>>(),
            "privacy_fences": self.privacy_fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "sponsor_slots": self.sponsor_slots.values().map(FeeSponsorSlot::public_record).collect::<Vec<_>>(),
            "route_auctions": self.route_auctions.values().map(RouteAuction::public_record).collect::<Vec<_>>(),
            "route_bids": self.route_bids.values().map(RouteBid::public_record).collect::<Vec<_>>(),
            "watcher_attestations": self.watcher_attestations.values().map(WatcherAttestation::public_record).collect::<Vec<_>>(),
            "finality_receipts": self.finality_receipts.values().map(FinalityReceipt::public_record).collect::<Vec<_>>(),
            "reorg_quarantines": self.reorg_quarantines.values().map(ReorgQuarantine::public_record).collect::<Vec<_>>(),
            "relay_batches": self.relay_batches.values().map(LowFeeRelayBatch::public_record).collect::<Vec<_>>(),
            "events": self.events.values().map(RuntimeEvent::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn commit_header(&mut self, request: CommitHeaderRequest) -> Result<String> {
        require_root("block_hash_root", &request.block_hash_root)?;
        require_root(
            "previous_block_hash_root",
            &request.previous_block_hash_root,
        )?;
        require_root("merkle_tree_root", &request.merkle_tree_root)?;
        require_root(
            "cumulative_difficulty_root",
            &request.cumulative_difficulty_root,
        )?;
        require_capacity(
            "header commitments",
            self.header_commitments.len(),
            self.config.max_header_commitments,
        )?;
        if request.watcher_quorum < self.config.min_watcher_quorum {
            return Err("header watcher quorum below configured minimum".to_string());
        }
        let header_commitment_id = compact_header_commitment_id(
            request.monero_height,
            &request.block_hash_root,
            &request.merkle_tree_root,
            request.observed_at_height,
        );
        let header = CompactHeaderCommitment {
            header_commitment_id: header_commitment_id.clone(),
            monero_height: request.monero_height,
            l2_height: request.l2_height,
            block_hash_root: request.block_hash_root,
            previous_block_hash_root: request.previous_block_hash_root,
            merkle_tree_root: request.merkle_tree_root,
            tx_count: request.tx_count,
            cumulative_difficulty_root: request.cumulative_difficulty_root,
            pow_aux_root: request.pow_aux_root,
            status: HeaderCommitmentStatus::QuorumAttested,
            watcher_quorum: request.watcher_quorum,
            observed_at_height: request.observed_at_height,
        };
        self.header_commitments
            .insert(header_commitment_id.clone(), header);
        self.record_event("header_committed", &header_commitment_id)?;
        Ok(header_commitment_id)
    }

    pub fn submit_relay_intent(&mut self, request: SubmitRelayIntentRequest) -> Result<String> {
        require_non_empty("account commitment", &request.account_commitment)?;
        require_root("sealed_intent_root", &request.sealed_intent_root)?;
        require_root("amount_commitment_root", &request.amount_commitment_root)?;
        require_root("nullifier_root", &request.nullifier_root)?;
        require_capacity(
            "relay intents",
            self.relay_intents.len(),
            self.config.max_intents,
        )?;
        require_bps("max relay fee bps", request.max_relay_fee_bps)?;
        if request.max_relay_fee_bps > self.config.max_relay_fee_bps {
            return Err("relay fee bps exceeds configured maximum".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("relay intent privacy set below configured minimum".to_string());
        }
        if !self
            .header_commitments
            .contains_key(&request.header_commitment_id)
        {
            return Err("relay intent references unknown header commitment".to_string());
        }
        let intent_id = relay_intent_id(
            request.direction,
            &request.account_commitment,
            &request.sealed_intent_root,
            &request.nullifier_root,
            request.created_at_height,
        );
        let intent = RelayIntent {
            intent_id: intent_id.clone(),
            direction: request.direction,
            status: RelayIntentStatus::Sealed,
            account_commitment: request.account_commitment,
            sealed_intent_root: request.sealed_intent_root,
            amount_commitment_root: request.amount_commitment_root,
            fee_limit_micro_units: request.fee_limit_micro_units,
            max_relay_fee_bps: request.max_relay_fee_bps,
            min_finality_depth: request.min_finality_depth,
            preferred_batch_size: request.preferred_batch_size,
            privacy_set_size: request.privacy_set_size,
            header_commitment_id: request.header_commitment_id,
            subaddress_fence_id: String::new(),
            viewtag_fence_id: String::new(),
            sponsor_slot_id: String::new(),
            route_auction_id: String::new(),
            batch_id: String::new(),
            finality_receipt_id: String::new(),
            nullifier_root: request.nullifier_root,
            metadata_root: request.metadata_root,
            created_at_height: request.created_at_height,
            expires_at_height: request.created_at_height + self.config.default_intent_ttl_blocks,
        };
        self.relay_intents.insert(intent_id.clone(), intent);
        self.record_event("relay_intent_submitted", &intent_id)?;
        Ok(intent_id)
    }

    pub fn insert_privacy_fence(&mut self, request: InsertPrivacyFenceRequest) -> Result<String> {
        require_non_empty("subject id", &request.subject_id)?;
        require_root("commitment_root", &request.commitment_root)?;
        require_root("nullifier_root", &request.nullifier_root)?;
        require_capacity(
            "privacy fences",
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
        )?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy fence set below configured minimum".to_string());
        }
        if self
            .privacy_fences
            .values()
            .any(|fence| fence.nullifier_root == request.nullifier_root)
        {
            return Err("privacy fence nullifier already inserted".to_string());
        }
        let fence_id = privacy_fence_id(
            request.kind,
            &request.subject_id,
            &request.nullifier_root,
            request.inserted_at_height,
        );
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind: request.kind,
            subject_id: request.subject_id.clone(),
            commitment_root: request.commitment_root,
            nullifier_root: request.nullifier_root,
            replay_domain: request.replay_domain,
            privacy_set_size: request.privacy_set_size,
            inserted_at_height: request.inserted_at_height,
            expires_at_height: request.inserted_at_height + request.ttl_blocks,
        };
        self.privacy_fences.insert(fence_id.clone(), fence);
        if let Some(intent) = self.relay_intents.get_mut(&request.subject_id) {
            match request.kind {
                FenceKind::Subaddress => intent.subaddress_fence_id = fence_id.clone(),
                FenceKind::ViewTag => intent.viewtag_fence_id = fence_id.clone(),
                _ => {}
            }
            if !intent.subaddress_fence_id.is_empty() && !intent.viewtag_fence_id.is_empty() {
                intent.status = RelayIntentStatus::Fenced;
            }
        }
        self.record_event("privacy_fence_inserted", &fence_id)?;
        Ok(fence_id)
    }

    pub fn reserve_sponsor_slot(&mut self, request: ReserveSponsorSlotRequest) -> Result<String> {
        require_non_empty("sponsor commitment", &request.sponsor_commitment)?;
        require_known_intent(&self.relay_intents, &request.intent_id)?;
        require_root("budget_root", &request.budget_root)?;
        require_bps("rebate bps", request.rebate_bps)?;
        require_capacity(
            "sponsor slots",
            self.sponsor_slots.len(),
            self.config.max_sponsor_slots,
        )?;
        if request.rebate_bps > self.config.max_sponsor_rebate_bps {
            return Err("sponsor rebate bps exceeds configured maximum".to_string());
        }
        if request.reserved_micro_units > self.sponsor_budget_remaining_micro_units {
            return Err("insufficient sponsor budget remaining".to_string());
        }
        let sponsor_slot_id = sponsor_slot_id(
            &request.sponsor_commitment,
            &request.intent_id,
            request.reserved_micro_units,
            request.opened_at_height,
        );
        let slot = FeeSponsorSlot {
            sponsor_slot_id: sponsor_slot_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            intent_id: request.intent_id.clone(),
            batch_id: String::new(),
            budget_root: request.budget_root,
            reserved_micro_units: request.reserved_micro_units,
            spent_micro_units: 0,
            rebate_bps: request.rebate_bps,
            max_fee_micro_units: request.max_fee_micro_units,
            status: SponsorSlotStatus::Reserved,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.default_batch_ttl_blocks,
        };
        self.sponsor_budget_remaining_micro_units -= request.reserved_micro_units;
        self.sponsor_slots.insert(sponsor_slot_id.clone(), slot);
        if let Some(intent) = self.relay_intents.get_mut(&request.intent_id) {
            intent.sponsor_slot_id = sponsor_slot_id.clone();
            intent.status = RelayIntentStatus::Sponsored;
        }
        self.record_event("sponsor_slot_reserved", &sponsor_slot_id)?;
        Ok(sponsor_slot_id)
    }

    pub fn open_route_auction(&mut self, request: OpenRouteAuctionRequest) -> Result<String> {
        let direction = self
            .relay_intents
            .get(&request.intent_id)
            .ok_or_else(|| "route auction references unknown intent".to_string())?
            .direction;
        require_non_empty("auctioneer commitment", &request.auctioneer_commitment)?;
        require_root("sealed route root", &request.sealed_route_root)?;
        require_root("reserve fee root", &request.reserve_fee_root)?;
        require_capacity(
            "route auctions",
            self.route_auctions.len(),
            self.config.max_route_auctions,
        )?;
        let auction_id = route_auction_id(
            &request.intent_id,
            &request.auctioneer_commitment,
            &request.sealed_route_root,
            request.opened_at_height,
        );
        let auction = RouteAuction {
            auction_id: auction_id.clone(),
            intent_id: request.intent_id.clone(),
            direction,
            status: AuctionStatus::Open,
            auctioneer_commitment: request.auctioneer_commitment,
            sealed_route_root: request.sealed_route_root,
            reserve_fee_root: request.reserve_fee_root,
            min_watcher_quorum: self.config.min_watcher_quorum,
            opened_at_height: request.opened_at_height,
            closes_at_height: request.opened_at_height + self.config.default_auction_window_blocks,
            selected_bid_id: String::new(),
        };
        self.route_auctions.insert(auction_id.clone(), auction);
        if let Some(intent) = self.relay_intents.get_mut(&request.intent_id) {
            intent.route_auction_id = auction_id.clone();
            intent.status = RelayIntentStatus::AuctionOpen;
        }
        self.record_event("route_auction_opened", &auction_id)?;
        Ok(auction_id)
    }

    pub fn commit_route_bid(&mut self, request: CommitRouteBidRequest) -> Result<String> {
        require_non_empty("relayer commitment", &request.relayer_commitment)?;
        require_root("route commitment root", &request.route_commitment_root)?;
        require_root("stake commitment root", &request.stake_commitment_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_bps("relay fee bps", request.relay_fee_bps)?;
        require_bps("reliability score bps", request.reliability_score_bps)?;
        require_capacity(
            "route bids",
            self.route_bids.len(),
            self.config.max_route_bids,
        )?;
        let auction = self
            .route_auctions
            .get(&request.auction_id)
            .ok_or_else(|| "route bid references unknown auction".to_string())?;
        if auction.intent_id != request.intent_id {
            return Err("route bid intent does not match auction".to_string());
        }
        if request.relay_fee_bps > self.config.max_relay_fee_bps {
            return Err("route bid relay fee bps exceeds configured maximum".to_string());
        }
        let route_bid_id = route_bid_id(
            &request.auction_id,
            &request.intent_id,
            &request.relayer_commitment,
            &request.route_commitment_root,
            request.committed_at_height,
        );
        let bid = RouteBid {
            route_bid_id: route_bid_id.clone(),
            auction_id: request.auction_id,
            intent_id: request.intent_id,
            relayer_commitment: request.relayer_commitment,
            status: RouteBidStatus::Committed,
            route_commitment_root: request.route_commitment_root,
            fee_quote_micro_units: request.fee_quote_micro_units,
            relay_fee_bps: request.relay_fee_bps,
            expected_latency_blocks: request.expected_latency_blocks,
            reliability_score_bps: request.reliability_score_bps,
            stake_commitment_root: request.stake_commitment_root,
            pq_signature_root: request.pq_signature_root,
            committed_at_height: request.committed_at_height,
            reveal_root: request.reveal_root,
        };
        self.route_bids.insert(route_bid_id.clone(), bid);
        self.record_event("route_bid_committed", &route_bid_id)?;
        Ok(route_bid_id)
    }

    pub fn select_route_bid(&mut self, request: SelectRouteBidRequest) -> Result<()> {
        let bid = self
            .route_bids
            .get_mut(&request.route_bid_id)
            .ok_or_else(|| "selected route bid is unknown".to_string())?;
        if bid.auction_id != request.auction_id {
            return Err("selected route bid does not belong to auction".to_string());
        }
        bid.status = RouteBidStatus::Selected;
        let auction = self
            .route_auctions
            .get_mut(&request.auction_id)
            .ok_or_else(|| "selected route bid references unknown auction".to_string())?;
        auction.status = AuctionStatus::Selected;
        auction.selected_bid_id = request.route_bid_id.clone();
        if let Some(intent) = self.relay_intents.get_mut(&auction.intent_id) {
            intent.status = RelayIntentStatus::Scheduled;
        }
        self.height = self.height.max(request.selected_at_height);
        self.record_event("route_bid_selected", &request.route_bid_id)
    }

    pub fn record_watcher_attestation(
        &mut self,
        request: RecordWatcherAttestationRequest,
    ) -> Result<String> {
        require_non_empty("watcher commitment", &request.watcher_commitment)?;
        require_non_empty("subject id", &request.subject_id)?;
        require_known_header(&self.header_commitments, &request.header_commitment_id)?;
        require_root("evidence root", &request.evidence_root)?;
        require_root("pq signature root", &request.pq_signature_root)?;
        require_bps("confidence bps", request.confidence_bps)?;
        require_capacity(
            "watcher attestations",
            self.watcher_attestations.len(),
            self.config.max_watcher_attestations,
        )?;
        let attestation_id = watcher_attestation_id(
            request.kind,
            &request.watcher_commitment,
            &request.subject_id,
            &request.evidence_root,
            request.signed_at_height,
        );
        let attestation = WatcherAttestation {
            attestation_id: attestation_id.clone(),
            kind: request.kind,
            watcher_commitment: request.watcher_commitment,
            subject_id: request.subject_id,
            header_commitment_id: request.header_commitment_id,
            evidence_root: request.evidence_root,
            observed_monero_height: request.observed_monero_height,
            observed_l2_height: request.observed_l2_height,
            confidence_bps: request.confidence_bps,
            pq_signature_root: request.pq_signature_root,
            signed_at_height: request.signed_at_height,
        };
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation);
        self.record_event("watcher_attestation_recorded", &attestation_id)?;
        Ok(attestation_id)
    }

    pub fn schedule_low_fee_batch(
        &mut self,
        request: ScheduleLowFeeBatchRequest,
    ) -> Result<String> {
        if request.intent_ids.is_empty() {
            return Err("batch must include at least one relay intent".to_string());
        }
        require_capacity(
            "relay batches",
            self.relay_batches.len(),
            self.config.max_batches,
        )?;
        require_root("aggregate intent root", &request.aggregate_intent_root)?;
        require_root("aggregate route root", &request.aggregate_route_root)?;
        require_root(
            "aggregate privacy fence root",
            &request.aggregate_privacy_fence_root,
        )?;
        require_root("aggregate header root", &request.aggregate_header_root)?;
        require_root(
            "aggregate nullifier root",
            &request.aggregate_nullifier_root,
        )?;
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("batch privacy set below configured minimum".to_string());
        }
        let mut seen = BTreeSet::new();
        for intent_id in &request.intent_ids {
            if !seen.insert(intent_id.clone()) {
                return Err("batch contains duplicate relay intent".to_string());
            }
            let intent = self
                .relay_intents
                .get(intent_id)
                .ok_or_else(|| "batch references unknown relay intent".to_string())?;
            if intent.direction != request.direction {
                return Err("batch direction does not match intent".to_string());
            }
            if !intent.status.schedulable() {
                return Err("batch references unschedulable intent".to_string());
            }
        }
        for bid_id in &request.selected_bid_ids {
            let bid = self
                .route_bids
                .get(bid_id)
                .ok_or_else(|| "batch references unknown route bid".to_string())?;
            if bid.status != RouteBidStatus::Selected {
                return Err("batch route bid is not selected".to_string());
            }
        }
        let batch_id = relay_batch_id(
            request.direction,
            &request.aggregate_intent_root,
            &request.aggregate_route_root,
            request.scheduled_at_height,
        );
        let batch = LowFeeRelayBatch {
            batch_id: batch_id.clone(),
            status: BatchStatus::Sealed,
            direction: request.direction,
            intent_ids: request.intent_ids.clone(),
            selected_bid_ids: request.selected_bid_ids,
            sponsor_slot_ids: request.sponsor_slot_ids.clone(),
            aggregate_intent_root: request.aggregate_intent_root,
            aggregate_route_root: request.aggregate_route_root,
            aggregate_privacy_fence_root: request.aggregate_privacy_fence_root,
            aggregate_header_root: request.aggregate_header_root,
            aggregate_nullifier_root: request.aggregate_nullifier_root,
            estimated_fee_micro_units: request.estimated_fee_micro_units,
            target_fee_micro_units: request.target_fee_micro_units,
            privacy_set_size: request.privacy_set_size,
            scheduled_at_height: request.scheduled_at_height,
            expires_at_height: request.scheduled_at_height + self.config.default_batch_ttl_blocks,
            relay_tx_root: String::new(),
        };
        self.relay_batches.insert(batch_id.clone(), batch);
        for intent_id in request.intent_ids {
            if let Some(intent) = self.relay_intents.get_mut(&intent_id) {
                intent.batch_id = batch_id.clone();
                intent.status = RelayIntentStatus::Scheduled;
            }
        }
        for slot_id in request.sponsor_slot_ids {
            if let Some(slot) = self.sponsor_slots.get_mut(&slot_id) {
                slot.batch_id = batch_id.clone();
                slot.status = SponsorSlotStatus::Attached;
            }
        }
        self.record_event("low_fee_batch_scheduled", &batch_id)?;
        Ok(batch_id)
    }

    pub fn record_finality_receipt(
        &mut self,
        request: RecordFinalityReceiptRequest,
    ) -> Result<String> {
        require_known_intent(&self.relay_intents, &request.intent_id)?;
        require_known_header(&self.header_commitments, &request.header_commitment_id)?;
        require_root("relay tx root", &request.relay_tx_root)?;
        require_root("output commitment root", &request.output_commitment_root)?;
        require_root("proof root", &request.proof_root)?;
        require_capacity(
            "finality receipts",
            self.finality_receipts.len(),
            self.config.max_finality_receipts,
        )?;
        if request.finality_depth < self.config.finality_depth {
            return Err("finality receipt depth below configured minimum".to_string());
        }
        let unique_watchers = request
            .watcher_attestation_ids
            .iter()
            .filter_map(|id| self.watcher_attestations.get(id))
            .map(|attestation| attestation.watcher_commitment.clone())
            .collect::<BTreeSet<_>>();
        if unique_watchers.len() < self.config.min_watcher_quorum as usize {
            return Err("finality receipt watcher quorum below configured minimum".to_string());
        }
        let watcher_records = request
            .watcher_attestation_ids
            .iter()
            .map(|id| json!(id))
            .collect::<Vec<_>>();
        let watcher_attestation_root = merkle_root(
            "MONERO-L2-RELAY-SCHEDULER-FINALITY-WATCHER-ID",
            &watcher_records,
        );
        let receipt_id = finality_receipt_id(
            &request.intent_id,
            &request.batch_id,
            &request.relay_tx_root,
            request.finalized_at_height,
        );
        let receipt = FinalityReceipt {
            receipt_id: receipt_id.clone(),
            intent_id: request.intent_id.clone(),
            batch_id: request.batch_id.clone(),
            header_commitment_id: request.header_commitment_id,
            status: FinalityReceiptStatus::Finalized,
            finality_depth: request.finality_depth,
            watcher_attestation_root,
            relay_tx_root: request.relay_tx_root.clone(),
            output_commitment_root: request.output_commitment_root,
            fee_paid_micro_units: request.fee_paid_micro_units,
            sponsor_rebate_micro_units: request.sponsor_rebate_micro_units,
            proof_root: request.proof_root,
            finalized_at_height: request.finalized_at_height,
        };
        self.finality_receipts.insert(receipt_id.clone(), receipt);
        if let Some(intent) = self.relay_intents.get_mut(&request.intent_id) {
            intent.finality_receipt_id = receipt_id.clone();
            intent.status = RelayIntentStatus::Finalized;
        }
        if let Some(batch) = self.relay_batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Finalized;
            batch.relay_tx_root = request.relay_tx_root;
        }
        self.record_event("finality_receipt_recorded", &receipt_id)?;
        Ok(receipt_id)
    }

    pub fn open_reorg_quarantine(&mut self, request: OpenReorgQuarantineRequest) -> Result<String> {
        require_non_empty("subject id", &request.subject_id)?;
        require_known_header(&self.header_commitments, &request.old_header_commitment_id)?;
        require_known_header(
            &self.header_commitments,
            &request.replacement_header_commitment_id,
        )?;
        require_root("evidence root", &request.evidence_root)?;
        require_root("affected intent root", &request.affected_intent_root)?;
        require_capacity(
            "reorg quarantines",
            self.reorg_quarantines.len(),
            self.config.max_reorg_quarantines,
        )?;
        let quarantine_id = reorg_quarantine_id(
            &request.subject_id,
            &request.old_header_commitment_id,
            &request.replacement_header_commitment_id,
            request.opened_at_height,
        );
        let quarantine = ReorgQuarantine {
            quarantine_id: quarantine_id.clone(),
            subject_id: request.subject_id.clone(),
            batch_id: request.batch_id.clone(),
            old_header_commitment_id: request.old_header_commitment_id.clone(),
            replacement_header_commitment_id: request.replacement_header_commitment_id.clone(),
            status: QuarantineStatus::Open,
            reorg_depth: request.reorg_depth,
            evidence_root: request.evidence_root,
            affected_intent_root: request.affected_intent_root,
            opened_at_height: request.opened_at_height,
            release_at_height: request.opened_at_height + self.config.reorg_quarantine_blocks,
        };
        self.reorg_quarantines
            .insert(quarantine_id.clone(), quarantine);
        if let Some(intent) = self.relay_intents.get_mut(&request.subject_id) {
            intent.status = RelayIntentStatus::Quarantined;
        }
        if let Some(batch) = self.relay_batches.get_mut(&request.batch_id) {
            batch.status = BatchStatus::Quarantined;
        }
        if let Some(header) = self
            .header_commitments
            .get_mut(&request.old_header_commitment_id)
        {
            header.status = HeaderCommitmentStatus::Quarantined;
        }
        self.record_event("reorg_quarantine_opened", &quarantine_id)?;
        Ok(quarantine_id)
    }

    fn record_event(&mut self, event_kind: &str, subject_id: &str) -> Result<()> {
        let subject_root = self.subject_root(subject_id);
        let sequence = self.events.len() as u64;
        let event_id =
            runtime_event_id(event_kind, subject_id, &subject_root, self.height, sequence);
        let event = RuntimeEvent {
            event_id: event_id.clone(),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            height: self.height,
            sequence,
        };
        self.events.insert(event_id, event);
        Ok(())
    }

    fn subject_root(&self, subject_id: &str) -> String {
        if let Some(value) = self.relay_intents.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-INTENT",
                &value.public_record(),
            );
        }
        if let Some(value) = self.header_commitments.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-HEADER",
                &value.public_record(),
            );
        }
        if let Some(value) = self.privacy_fences.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-FENCE",
                &value.public_record(),
            );
        }
        if let Some(value) = self.sponsor_slots.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-SPONSOR",
                &value.public_record(),
            );
        }
        if let Some(value) = self.route_auctions.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-AUCTION",
                &value.public_record(),
            );
        }
        if let Some(value) = self.route_bids.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-BID",
                &value.public_record(),
            );
        }
        if let Some(value) = self.watcher_attestations.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-WATCHER",
                &value.public_record(),
            );
        }
        if let Some(value) = self.finality_receipts.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-RECEIPT",
                &value.public_record(),
            );
        }
        if let Some(value) = self.reorg_quarantines.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-QUARANTINE",
                &value.public_record(),
            );
        }
        if let Some(value) = self.relay_batches.get(subject_id) {
            return payload_root(
                "MONERO-L2-RELAY-SCHEDULER-EVENT-BATCH",
                &value.public_record(),
            );
        }
        string_root("MONERO-L2-RELAY-SCHEDULER-EVENT-UNKNOWN", subject_id)
    }
}

pub fn relay_intent_id(
    direction: RelayDirection,
    account_commitment: &str,
    sealed_intent_root: &str,
    nullifier_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(direction.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(sealed_intent_root),
            HashPart::Str(nullifier_root),
            HashPart::U64(created_at_height),
        ],
        32,
    )
}

pub fn compact_header_commitment_id(
    monero_height: u64,
    block_hash_root: &str,
    merkle_tree_root: &str,
    observed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-HEADER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(monero_height),
            HashPart::Str(block_hash_root),
            HashPart::Str(merkle_tree_root),
            HashPart::U64(observed_at_height),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    nullifier_root: &str,
    inserted_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-PRIVACY-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier_root),
            HashPart::U64(inserted_at_height),
        ],
        32,
    )
}

pub fn sponsor_slot_id(
    sponsor_commitment: &str,
    intent_id: &str,
    reserved_micro_units: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-SPONSOR-SLOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(intent_id),
            HashPart::U64(reserved_micro_units),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn route_auction_id(
    intent_id: &str,
    auctioneer_commitment: &str,
    sealed_route_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(auctioneer_commitment),
            HashPart::Str(sealed_route_root),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn route_bid_id(
    auction_id: &str,
    intent_id: &str,
    relayer_commitment: &str,
    route_commitment_root: &str,
    committed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-ROUTE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(intent_id),
            HashPart::Str(relayer_commitment),
            HashPart::Str(route_commitment_root),
            HashPart::U64(committed_at_height),
        ],
        32,
    )
}

pub fn watcher_attestation_id(
    kind: WatcherAttestationKind,
    watcher_commitment: &str,
    subject_id: &str,
    evidence_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-WATCHER-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(watcher_commitment),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::U64(signed_at_height),
        ],
        32,
    )
}

pub fn relay_batch_id(
    direction: RelayDirection,
    aggregate_intent_root: &str,
    aggregate_route_root: &str,
    scheduled_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(direction.as_str()),
            HashPart::Str(aggregate_intent_root),
            HashPart::Str(aggregate_route_root),
            HashPart::U64(scheduled_at_height),
        ],
        32,
    )
}

pub fn finality_receipt_id(
    intent_id: &str,
    batch_id: &str,
    relay_tx_root: &str,
    finalized_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-FINALITY-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(intent_id),
            HashPart::Str(batch_id),
            HashPart::Str(relay_tx_root),
            HashPart::U64(finalized_at_height),
        ],
        32,
    )
}

pub fn reorg_quarantine_id(
    subject_id: &str,
    old_header_commitment_id: &str,
    replacement_header_commitment_id: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-REORG-QUARANTINE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(old_header_commitment_id),
            HashPart::Str(replacement_header_commitment_id),
            HashPart::U64(opened_at_height),
        ],
        32,
    )
}

pub fn runtime_event_id(
    event_kind: &str,
    subject_id: &str,
    subject_root: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(subject_root),
            HashPart::U64(height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    root_from_records(domain, records.to_vec())
}

pub fn root_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-RELAY-SCHEDULER-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn commitment(label: &str) -> String {
    string_root("MONERO-L2-RELAY-SCHEDULER-COMMITMENT", label)
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn require_root(label: &str, value: &str) -> Result<()> {
    require_non_empty(label, value)?;
    if value.len() < 32 {
        return Err(format!("{label} must be a commitment root"));
    }
    Ok(())
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn require_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    if len >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_known_intent(intents: &BTreeMap<String, RelayIntent>, intent_id: &str) -> Result<()> {
    if intents.contains_key(intent_id) {
        Ok(())
    } else {
        Err("unknown relay intent".to_string())
    }
}

fn require_known_header(
    headers: &BTreeMap<String, CompactHeaderCommitment>,
    header_commitment_id: &str,
) -> Result<()> {
    if headers.contains_key(header_commitment_id) {
        Ok(())
    } else {
        Err("unknown compact header commitment".to_string())
    }
}
