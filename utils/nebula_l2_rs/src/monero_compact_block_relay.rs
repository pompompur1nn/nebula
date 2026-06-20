use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroCompactBlockRelayResult<T> = Result<T, String>;

pub const MONERO_COMPACT_BLOCK_RELAY_PROTOCOL_VERSION: &str =
    "nebula-monero-compact-block-relay-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_SCHEMA_VERSION: u64 = 1;
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_NETWORK: &str = "monero-devnet";
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_COMMITTEE_ID: &str =
    "monero-compact-block-relay-devnet-committee";
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_L2_HEIGHT: u64 = 14_400;
pub const MONERO_COMPACT_BLOCK_RELAY_DEVNET_MONERO_HEIGHT: u64 = 96_000;
pub const MONERO_COMPACT_BLOCK_RELAY_HASH_SUITE: &str = "SHAKE256";
pub const MONERO_COMPACT_BLOCK_RELAY_SECURITY_MODEL: &str =
    "deterministic-devnet-records-not-real-crypto";
pub const MONERO_COMPACT_BLOCK_RELAY_BLOCK_COMMITMENT_SCHEME: &str =
    "monero-compact-block-commitment-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_TX_PREFIX_SKETCH_SCHEME: &str =
    "monero-tx-prefix-minisketch-shake256-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_VIEW_TAG_HINT_SCHEME: &str = "monero-view-tag-sync-hint-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_PQ_SIGNATURE_SCHEME: &str = "ML-DSA-65";
pub const MONERO_COMPACT_BLOCK_RELAY_BACKUP_SIGNATURE_SCHEME: &str = "SLH-DSA-SHAKE-192s";
pub const MONERO_COMPACT_BLOCK_RELAY_WATCHER_ACK_SCHEME: &str =
    "sealed-private-watcher-ack-ml-kem-aead-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_REORG_BATCH_SCHEME: &str =
    "monero-compact-relay-reorg-repair-batch-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_SLASHING_EVIDENCE_SCHEME: &str =
    "monero-compact-relay-slashing-evidence-v1";
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_EPOCH_BLOCKS: u64 = 120;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_FINALITY_DEPTH: u64 = 10;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_REORG_WINDOW_BLOCKS: u64 = 64;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_TX_PREFIXES_PER_BLOCK: u64 = 4_096;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_SKETCH_BYTES: u64 = 16_384;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_VIEW_TAG_HINTS: u64 = 8_192;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_REPAIR_BLOCKS: u64 = 32;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_PRIVATE_ACK_TTL_BLOCKS: u64 = 96;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 144;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_SLASHING_TTL_BLOCKS: u64 = 720;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_RELAY_WEIGHT: u64 = 3;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_WATCHER_QUORUM: u64 = 2;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_LOW_FEE_UNIT_PRICE: u64 = 275;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_LOW_FEE_BUDGET: u64 = 500_000_000;
pub const MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_ACKS_PER_BLOCK: u64 = 256;
pub const MONERO_COMPACT_BLOCK_RELAY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactRelayNodeRole {
    BlockProducer,
    BridgeWatcher,
    PrefixSketcher,
    ViewTagIndexer,
    ReorgRepairer,
    FeeSponsor,
    SlashingGuardian,
}

impl CompactRelayNodeRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlockProducer => "block_producer",
            Self::BridgeWatcher => "bridge_watcher",
            Self::PrefixSketcher => "prefix_sketcher",
            Self::ViewTagIndexer => "view_tag_indexer",
            Self::ReorgRepairer => "reorg_repairer",
            Self::FeeSponsor => "fee_sponsor",
            Self::SlashingGuardian => "slashing_guardian",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactRelayNodeStatus {
    Pending,
    Active,
    Rotating,
    RateLimited,
    Jailed,
    Retired,
}

impl CompactRelayNodeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::RateLimited => "rate_limited",
            Self::Jailed => "jailed",
            Self::Retired => "retired",
        }
    }

    pub fn can_relay(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactBlockStatus {
    Draft,
    Observed,
    Sketched,
    Attested,
    Repaired,
    Finalized,
    Reorged,
    Rejected,
}

impl CompactBlockStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observed => "observed",
            Self::Sketched => "sketched",
            Self::Attested => "attested",
            Self::Repaired => "repaired",
            Self::Finalized => "finalized",
            Self::Reorged => "reorged",
            Self::Rejected => "rejected",
        }
    }

    pub fn usable_for_fast_sync(self) -> bool {
        matches!(
            self,
            Self::Sketched | Self::Attested | Self::Repaired | Self::Finalized
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxPrefixSketchKind {
    MinerTxOnly,
    FullPrefixSet,
    BridgeRelevant,
    MempoolDelta,
    RepairPatch,
    SponsorPriority,
}

impl TxPrefixSketchKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinerTxOnly => "miner_tx_only",
            Self::FullPrefixSet => "full_prefix_set",
            Self::BridgeRelevant => "bridge_relevant",
            Self::MempoolDelta => "mempool_delta",
            Self::RepairPatch => "repair_patch",
            Self::SponsorPriority => "sponsor_priority",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewTagHintKind {
    DepositCandidate,
    WithdrawalChange,
    ReserveOutput,
    WalletSync,
    ContractIngress,
    ReorgReplay,
}

impl ViewTagHintKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositCandidate => "deposit_candidate",
            Self::WithdrawalChange => "withdrawal_change",
            Self::ReserveOutput => "reserve_output",
            Self::WalletSync => "wallet_sync",
            Self::ContractIngress => "contract_ingress",
            Self::ReorgReplay => "reorg_replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySignatureStatus {
    Prepared,
    Submitted,
    Counted,
    Superseded,
    Rejected,
    Expired,
}

impl RelaySignatureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Counted => "counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Submitted | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateWatcherAckKind {
    DepositSeen,
    WithdrawalSeen,
    ReserveSeen,
    SketchReceived,
    RepairReceived,
    SlashingSeen,
}

impl PrivateWatcherAckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositSeen => "deposit_seen",
            Self::WithdrawalSeen => "withdrawal_seen",
            Self::ReserveSeen => "reserve_seen",
            Self::SketchReceived => "sketch_received",
            Self::RepairReceived => "repair_received",
            Self::SlashingSeen => "slashing_seen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateWatcherAckStatus {
    Sealed,
    Delivered,
    Counted,
    Replayed,
    Expired,
    Rejected,
}

impl PrivateWatcherAckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Counted => "counted",
            Self::Replayed => "replayed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Sealed | Self::Delivered | Self::Counted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySponsorshipStatus {
    Offered,
    Reserved,
    Consumed,
    Refunded,
    Slashed,
    Expired,
}

impl RelaySponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Offered | Self::Reserved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgRepairStatus {
    Proposed,
    Fetching,
    Replaying,
    Applied,
    Challenged,
    Rejected,
    Expired,
}

impl ReorgRepairStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Fetching => "fetching",
            Self::Replaying => "replaying",
            Self::Applied => "applied",
            Self::Challenged => "challenged",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn is_open(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Fetching | Self::Replaying | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySlashingEvidenceKind {
    InvalidBlockCommitment,
    InvalidTxPrefixSketch,
    EquivocatedBlockRoot,
    MissingPrivateAck,
    SponsoredSpam,
    BadReorgRepair,
}

impl RelaySlashingEvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidBlockCommitment => "invalid_block_commitment",
            Self::InvalidTxPrefixSketch => "invalid_tx_prefix_sketch",
            Self::EquivocatedBlockRoot => "equivocated_block_root",
            Self::MissingPrivateAck => "missing_private_ack",
            Self::SponsoredSpam => "sponsored_spam",
            Self::BadReorgRepair => "bad_reorg_repair",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelaySlashingEvidenceStatus {
    Prepared,
    Submitted,
    Accepted,
    Rejected,
    Executed,
    Expired,
}

impl RelaySlashingEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
            Self::Expired => "expired",
        }
    }

    pub fn actionable(self) -> bool {
        matches!(self, Self::Prepared | Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroCompactBlockRelayConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub committee_id: String,
    pub epoch_blocks: u64,
    pub finality_depth: u64,
    pub reorg_window_blocks: u64,
    pub max_tx_prefixes_per_block: u64,
    pub max_sketch_bytes: u64,
    pub max_view_tag_hints: u64,
    pub max_repair_blocks: u64,
    pub private_ack_ttl_blocks: u64,
    pub sponsorship_ttl_blocks: u64,
    pub slashing_ttl_blocks: u64,
    pub min_relay_weight: u64,
    pub min_watcher_quorum: u64,
    pub min_pq_security_bits: u16,
    pub low_fee_unit_price: u64,
    pub low_fee_budget: u64,
    pub max_acks_per_block: u64,
    pub block_commitment_scheme: String,
    pub tx_prefix_sketch_scheme: String,
    pub view_tag_hint_scheme: String,
    pub pq_signature_scheme: String,
    pub backup_signature_scheme: String,
    pub watcher_ack_scheme: String,
    pub reorg_batch_scheme: String,
    pub slashing_evidence_scheme: String,
}

impl MoneroCompactBlockRelayConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_COMPACT_BLOCK_RELAY_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_COMPACT_BLOCK_RELAY_SCHEMA_VERSION,
            monero_network: MONERO_COMPACT_BLOCK_RELAY_DEVNET_NETWORK.to_string(),
            asset_id: MONERO_COMPACT_BLOCK_RELAY_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_COMPACT_BLOCK_RELAY_DEVNET_FEE_ASSET_ID.to_string(),
            committee_id: MONERO_COMPACT_BLOCK_RELAY_DEVNET_COMMITTEE_ID.to_string(),
            epoch_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_EPOCH_BLOCKS,
            finality_depth: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_FINALITY_DEPTH,
            reorg_window_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_REORG_WINDOW_BLOCKS,
            max_tx_prefixes_per_block: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_TX_PREFIXES_PER_BLOCK,
            max_sketch_bytes: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_SKETCH_BYTES,
            max_view_tag_hints: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_VIEW_TAG_HINTS,
            max_repair_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_REPAIR_BLOCKS,
            private_ack_ttl_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_PRIVATE_ACK_TTL_BLOCKS,
            sponsorship_ttl_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            slashing_ttl_blocks: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_SLASHING_TTL_BLOCKS,
            min_relay_weight: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_RELAY_WEIGHT,
            min_watcher_quorum: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_WATCHER_QUORUM,
            min_pq_security_bits: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_unit_price: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_LOW_FEE_UNIT_PRICE,
            low_fee_budget: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_LOW_FEE_BUDGET,
            max_acks_per_block: MONERO_COMPACT_BLOCK_RELAY_DEFAULT_MAX_ACKS_PER_BLOCK,
            block_commitment_scheme: MONERO_COMPACT_BLOCK_RELAY_BLOCK_COMMITMENT_SCHEME.to_string(),
            tx_prefix_sketch_scheme: MONERO_COMPACT_BLOCK_RELAY_TX_PREFIX_SKETCH_SCHEME.to_string(),
            view_tag_hint_scheme: MONERO_COMPACT_BLOCK_RELAY_VIEW_TAG_HINT_SCHEME.to_string(),
            pq_signature_scheme: MONERO_COMPACT_BLOCK_RELAY_PQ_SIGNATURE_SCHEME.to_string(),
            backup_signature_scheme: MONERO_COMPACT_BLOCK_RELAY_BACKUP_SIGNATURE_SCHEME.to_string(),
            watcher_ack_scheme: MONERO_COMPACT_BLOCK_RELAY_WATCHER_ACK_SCHEME.to_string(),
            reorg_batch_scheme: MONERO_COMPACT_BLOCK_RELAY_REORG_BATCH_SCHEME.to_string(),
            slashing_evidence_scheme: MONERO_COMPACT_BLOCK_RELAY_SLASHING_EVIDENCE_SCHEME
                .to_string(),
        }
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<()> {
        ensure_non_empty(
            &self.protocol_version,
            "compact block relay protocol version",
        )?;
        ensure_non_empty(&self.monero_network, "compact block relay monero network")?;
        ensure_non_empty(&self.asset_id, "compact block relay asset id")?;
        ensure_non_empty(&self.fee_asset_id, "compact block relay fee asset id")?;
        ensure_non_empty(&self.committee_id, "compact block relay committee id")?;
        ensure_non_empty(&self.block_commitment_scheme, "block commitment scheme")?;
        ensure_non_empty(&self.tx_prefix_sketch_scheme, "tx prefix sketch scheme")?;
        ensure_non_empty(&self.view_tag_hint_scheme, "view tag hint scheme")?;
        ensure_non_empty(&self.pq_signature_scheme, "pq signature scheme")?;
        ensure_non_empty(&self.backup_signature_scheme, "backup signature scheme")?;
        ensure_non_empty(&self.watcher_ack_scheme, "watcher ack scheme")?;
        ensure_non_empty(&self.reorg_batch_scheme, "reorg batch scheme")?;
        ensure_non_empty(&self.slashing_evidence_scheme, "slashing evidence scheme")?;
        ensure_positive(self.schema_version, "schema version")?;
        ensure_positive(self.epoch_blocks, "epoch blocks")?;
        ensure_positive(self.finality_depth, "finality depth")?;
        ensure_positive(self.reorg_window_blocks, "reorg window blocks")?;
        ensure_positive(self.max_tx_prefixes_per_block, "max tx prefixes per block")?;
        ensure_positive(self.max_sketch_bytes, "max sketch bytes")?;
        ensure_positive(self.max_view_tag_hints, "max view tag hints")?;
        ensure_positive(self.max_repair_blocks, "max repair blocks")?;
        ensure_positive(self.private_ack_ttl_blocks, "private ack ttl blocks")?;
        ensure_positive(self.sponsorship_ttl_blocks, "sponsorship ttl blocks")?;
        ensure_positive(self.slashing_ttl_blocks, "slashing ttl blocks")?;
        ensure_positive(self.min_relay_weight, "minimum relay weight")?;
        ensure_positive(self.min_watcher_quorum, "minimum watcher quorum")?;
        ensure_positive(self.low_fee_unit_price, "low fee unit price")?;
        ensure_positive(self.low_fee_budget, "low fee budget")?;
        ensure_positive(self.max_acks_per_block, "max acks per block")?;
        if self.max_repair_blocks > self.reorg_window_blocks {
            return Err("max repair blocks cannot exceed reorg window".to_string());
        }
        if self.min_pq_security_bits < 128 {
            return Err("minimum pq security bits below relay floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_compact_block_relay_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "committee_id": self.committee_id,
            "epoch_blocks": self.epoch_blocks,
            "finality_depth": self.finality_depth,
            "reorg_window_blocks": self.reorg_window_blocks,
            "max_tx_prefixes_per_block": self.max_tx_prefixes_per_block,
            "max_sketch_bytes": self.max_sketch_bytes,
            "max_view_tag_hints": self.max_view_tag_hints,
            "max_repair_blocks": self.max_repair_blocks,
            "private_ack_ttl_blocks": self.private_ack_ttl_blocks,
            "sponsorship_ttl_blocks": self.sponsorship_ttl_blocks,
            "slashing_ttl_blocks": self.slashing_ttl_blocks,
            "min_relay_weight": self.min_relay_weight,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_pq_security_bits": self.min_pq_security_bits,
            "low_fee_unit_price": self.low_fee_unit_price,
            "low_fee_budget": self.low_fee_budget,
            "max_acks_per_block": self.max_acks_per_block,
            "block_commitment_scheme": self.block_commitment_scheme,
            "tx_prefix_sketch_scheme": self.tx_prefix_sketch_scheme,
            "view_tag_hint_scheme": self.view_tag_hint_scheme,
            "pq_signature_scheme": self.pq_signature_scheme,
            "backup_signature_scheme": self.backup_signature_scheme,
            "watcher_ack_scheme": self.watcher_ack_scheme,
            "reorg_batch_scheme": self.reorg_batch_scheme,
            "slashing_evidence_scheme": self.slashing_evidence_scheme,
            "security_model": MONERO_COMPACT_BLOCK_RELAY_SECURITY_MODEL,
            "hash_suite": MONERO_COMPACT_BLOCK_RELAY_HASH_SUITE,
            "max_bps": MONERO_COMPACT_BLOCK_RELAY_MAX_BPS,
        })
    }

    pub fn config_root(&self) -> String {
        compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactRelayNode {
    pub node_id: String,
    pub operator_id: String,
    pub role: CompactRelayNodeRole,
    pub status: CompactRelayNodeStatus,
    pub relay_weight: u64,
    pub pq_public_key_commitment: String,
    pub backup_public_key_commitment: String,
    pub registered_at_l2_height: u64,
    pub last_seen_l2_height: u64,
    pub slashable_stake_units: u64,
}

impl CompactRelayNode {
    pub fn new(
        operator_id: &str,
        role: CompactRelayNodeRole,
        relay_weight: u64,
        pq_public_key_commitment: &str,
        backup_public_key_commitment: &str,
        registered_at_l2_height: u64,
        slashable_stake_units: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(operator_id, "relay node operator id")?;
        ensure_non_empty(
            pq_public_key_commitment,
            "relay node pq public key commitment",
        )?;
        ensure_non_empty(
            backup_public_key_commitment,
            "relay node backup public key commitment",
        )?;
        ensure_positive(relay_weight, "relay node weight")?;
        ensure_positive(registered_at_l2_height, "relay node registration height")?;
        let node_id = compact_relay_id(
            "node",
            &[
                HashPart::Str(operator_id),
                HashPart::Str(role.as_str()),
                HashPart::Str(pq_public_key_commitment),
                HashPart::Int(registered_at_l2_height as i128),
            ],
        );
        Ok(Self {
            node_id,
            operator_id: operator_id.to_string(),
            role,
            status: CompactRelayNodeStatus::Active,
            relay_weight,
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            backup_public_key_commitment: backup_public_key_commitment.to_string(),
            registered_at_l2_height,
            last_seen_l2_height: registered_at_l2_height,
            slashable_stake_units,
        })
    }

    pub fn devnet(
        index: u64,
        role: CompactRelayNodeRole,
        relay_weight: u64,
        height: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let operator_id = format!("devnet-compact-relay-operator-{index}");
        let pq = devnet_root("relay-node-pq-key", &operator_id);
        let backup = devnet_root("relay-node-backup-key", &operator_id);
        Self::new(
            &operator_id,
            role,
            relay_weight,
            &pq,
            &backup,
            height,
            relay_weight.saturating_mul(1_000_000),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_relay_node",
            "chain_id": CHAIN_ID,
            "node_id": self.node_id,
            "operator_id": self.operator_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "relay_weight": self.relay_weight,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_public_key_commitment": self.backup_public_key_commitment,
            "registered_at_l2_height": self.registered_at_l2_height,
            "last_seen_l2_height": self.last_seen_l2_height,
            "slashable_stake_units": self.slashable_stake_units,
        })
    }

    pub fn node_root(&self) -> String {
        compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-NODE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.node_id, "relay node id")?;
        ensure_non_empty(&self.operator_id, "relay node operator id")?;
        ensure_non_empty(
            &self.pq_public_key_commitment,
            "relay node pq public key commitment",
        )?;
        ensure_non_empty(
            &self.backup_public_key_commitment,
            "relay node backup public key commitment",
        )?;
        ensure_positive(self.relay_weight, "relay node weight")?;
        ensure_positive(
            self.registered_at_l2_height,
            "relay node registration height",
        )?;
        if self.last_seen_l2_height < self.registered_at_l2_height {
            return Err("relay node last seen height predates registration".to_string());
        }
        Ok(self.node_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompactBlockCommitment {
    pub commitment_id: String,
    pub block_height: u64,
    pub epoch: u64,
    pub monero_block_hash: String,
    pub previous_block_hash: String,
    pub header_root: String,
    pub tx_prefix_root: String,
    pub output_root: String,
    pub key_image_root: String,
    pub fee_summary_root: String,
    pub miner_tx_commitment: String,
    pub observed_at_l2_height: u64,
    pub finalized_at_l2_height: u64,
    pub status: CompactBlockStatus,
}

impl CompactBlockCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_height: u64,
        epoch: u64,
        monero_block_hash: &str,
        previous_block_hash: &str,
        header_root: &str,
        tx_prefix_root: &str,
        output_root: &str,
        key_image_root: &str,
        fee_summary_root: &str,
        miner_tx_commitment: &str,
        observed_at_l2_height: u64,
        finalized_at_l2_height: u64,
        status: CompactBlockStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_positive(block_height, "compact block height")?;
        ensure_non_empty(monero_block_hash, "compact block hash")?;
        ensure_non_empty(previous_block_hash, "compact block previous hash")?;
        ensure_non_empty(header_root, "compact block header root")?;
        ensure_non_empty(tx_prefix_root, "compact block tx prefix root")?;
        ensure_non_empty(output_root, "compact block output root")?;
        ensure_non_empty(key_image_root, "compact block key image root")?;
        ensure_non_empty(fee_summary_root, "compact block fee summary root")?;
        ensure_non_empty(miner_tx_commitment, "compact block miner tx commitment")?;
        let commitment_id = compact_relay_id(
            "block-commitment",
            &[
                HashPart::Int(block_height as i128),
                HashPart::Str(monero_block_hash),
                HashPart::Str(tx_prefix_root),
            ],
        );
        Ok(Self {
            commitment_id,
            block_height,
            epoch,
            monero_block_hash: monero_block_hash.to_string(),
            previous_block_hash: previous_block_hash.to_string(),
            header_root: header_root.to_string(),
            tx_prefix_root: tx_prefix_root.to_string(),
            output_root: output_root.to_string(),
            key_image_root: key_image_root.to_string(),
            fee_summary_root: fee_summary_root.to_string(),
            miner_tx_commitment: miner_tx_commitment.to_string(),
            observed_at_l2_height,
            finalized_at_l2_height,
            status,
        })
    }

    pub fn devnet(
        block_height: u64,
        l2_height: u64,
        status: CompactBlockStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("devnet-compact-block-{block_height}");
        let finalized = if status == CompactBlockStatus::Finalized {
            l2_height.saturating_add(MONERO_COMPACT_BLOCK_RELAY_DEFAULT_FINALITY_DEPTH)
        } else {
            0
        };
        Self::new(
            block_height,
            block_height / MONERO_COMPACT_BLOCK_RELAY_DEFAULT_EPOCH_BLOCKS,
            &devnet_root("compact-block-hash", &seed),
            &devnet_root("compact-block-prev-hash", &seed),
            &devnet_root("compact-block-header-root", &seed),
            &devnet_root("compact-block-prefix-root", &seed),
            &devnet_root("compact-block-output-root", &seed),
            &devnet_root("compact-block-key-image-root", &seed),
            &devnet_root("compact-block-fee-root", &seed),
            &devnet_root("compact-block-miner-tx", &seed),
            l2_height,
            finalized,
            status,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compact_block_commitment",
            "chain_id": CHAIN_ID,
            "commitment_id": self.commitment_id,
            "block_height": self.block_height,
            "epoch": self.epoch,
            "monero_block_hash": self.monero_block_hash,
            "previous_block_hash": self.previous_block_hash,
            "header_root": self.header_root,
            "tx_prefix_root": self.tx_prefix_root,
            "output_root": self.output_root,
            "key_image_root": self.key_image_root,
            "fee_summary_root": self.fee_summary_root,
            "miner_tx_commitment": self.miner_tx_commitment,
            "observed_at_l2_height": self.observed_at_l2_height,
            "finalized_at_l2_height": self.finalized_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn commitment_root(&self) -> String {
        compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-BLOCK", &self.public_record())
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.commitment_id, "compact block commitment id")?;
        ensure_positive(self.block_height, "compact block height")?;
        ensure_non_empty(&self.monero_block_hash, "compact block hash")?;
        ensure_non_empty(&self.previous_block_hash, "compact block previous hash")?;
        ensure_non_empty(&self.header_root, "compact block header root")?;
        ensure_non_empty(&self.tx_prefix_root, "compact block tx prefix root")?;
        ensure_non_empty(&self.output_root, "compact block output root")?;
        ensure_non_empty(&self.key_image_root, "compact block key image root")?;
        ensure_non_empty(&self.fee_summary_root, "compact block fee summary root")?;
        ensure_non_empty(
            &self.miner_tx_commitment,
            "compact block miner tx commitment",
        )?;
        if self.finalized_at_l2_height > 0
            && self.finalized_at_l2_height < self.observed_at_l2_height
        {
            return Err("compact block finalized height predates observation".to_string());
        }
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxPrefixSketch {
    pub sketch_id: String,
    pub commitment_id: String,
    pub block_height: u64,
    pub sketch_kind: TxPrefixSketchKind,
    pub tx_prefix_count: u64,
    pub bridge_relevant_count: u64,
    pub sketch_root: String,
    pub salted_short_id_root: String,
    pub reconciliation_hint_root: String,
    pub encoded_size_bytes: u64,
    pub produced_by_node_id: String,
    pub produced_at_l2_height: u64,
}

impl TxPrefixSketch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment: &CompactBlockCommitment,
        sketch_kind: TxPrefixSketchKind,
        tx_prefix_count: u64,
        bridge_relevant_count: u64,
        sketch_root: &str,
        salted_short_id_root: &str,
        reconciliation_hint_root: &str,
        encoded_size_bytes: u64,
        produced_by_node_id: &str,
        produced_at_l2_height: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(sketch_root, "tx prefix sketch root")?;
        ensure_non_empty(salted_short_id_root, "tx prefix salted short id root")?;
        ensure_non_empty(
            reconciliation_hint_root,
            "tx prefix reconciliation hint root",
        )?;
        ensure_non_empty(produced_by_node_id, "tx prefix producer node id")?;
        ensure_positive(tx_prefix_count, "tx prefix count")?;
        ensure_positive(encoded_size_bytes, "tx prefix encoded size bytes")?;
        let sketch_id = compact_relay_id(
            "tx-prefix-sketch",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(sketch_kind.as_str()),
                HashPart::Str(sketch_root),
                HashPart::Str(produced_by_node_id),
            ],
        );
        Ok(Self {
            sketch_id,
            commitment_id: commitment.commitment_id.clone(),
            block_height: commitment.block_height,
            sketch_kind,
            tx_prefix_count,
            bridge_relevant_count,
            sketch_root: sketch_root.to_string(),
            salted_short_id_root: salted_short_id_root.to_string(),
            reconciliation_hint_root: reconciliation_hint_root.to_string(),
            encoded_size_bytes,
            produced_by_node_id: produced_by_node_id.to_string(),
            produced_at_l2_height,
        })
    }

    pub fn devnet(
        commitment: &CompactBlockCommitment,
        node_id: &str,
        offset: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{}-{node_id}-{offset}", commitment.commitment_id);
        Self::new(
            commitment,
            TxPrefixSketchKind::BridgeRelevant,
            16 + offset,
            3 + offset,
            &devnet_root("tx-prefix-sketch-root", &seed),
            &devnet_root("tx-prefix-short-id-root", &seed),
            &devnet_root("tx-prefix-reconcile-root", &seed),
            512 + offset.saturating_mul(32),
            node_id,
            commitment.observed_at_l2_height.saturating_add(offset),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "tx_prefix_sketch",
            "chain_id": CHAIN_ID,
            "sketch_id": self.sketch_id,
            "commitment_id": self.commitment_id,
            "block_height": self.block_height,
            "sketch_kind": self.sketch_kind.as_str(),
            "tx_prefix_count": self.tx_prefix_count,
            "bridge_relevant_count": self.bridge_relevant_count,
            "sketch_root": self.sketch_root,
            "salted_short_id_root": self.salted_short_id_root,
            "reconciliation_hint_root": self.reconciliation_hint_root,
            "encoded_size_bytes": self.encoded_size_bytes,
            "produced_by_node_id": self.produced_by_node_id,
            "produced_at_l2_height": self.produced_at_l2_height,
        })
    }

    pub fn sketch_commitment_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-TX-PREFIX-SKETCH",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &MoneroCompactBlockRelayConfig,
    ) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.sketch_id, "tx prefix sketch id")?;
        ensure_non_empty(&self.commitment_id, "tx prefix commitment id")?;
        ensure_positive(self.block_height, "tx prefix block height")?;
        ensure_positive(self.tx_prefix_count, "tx prefix count")?;
        ensure_non_empty(&self.sketch_root, "tx prefix sketch root")?;
        ensure_non_empty(&self.salted_short_id_root, "tx prefix salted short id root")?;
        ensure_non_empty(
            &self.reconciliation_hint_root,
            "tx prefix reconciliation hint root",
        )?;
        ensure_non_empty(&self.produced_by_node_id, "tx prefix producer node id")?;
        if self.tx_prefix_count > config.max_tx_prefixes_per_block {
            return Err("tx prefix sketch exceeds configured tx prefix limit".to_string());
        }
        if self.encoded_size_bytes > config.max_sketch_bytes {
            return Err("tx prefix sketch exceeds configured byte limit".to_string());
        }
        if self.bridge_relevant_count > self.tx_prefix_count {
            return Err("bridge relevant prefix count exceeds total prefix count".to_string());
        }
        Ok(self.sketch_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewTagSyncHint {
    pub hint_id: String,
    pub commitment_id: String,
    pub block_height: u64,
    pub hint_kind: ViewTagHintKind,
    pub view_tag: u16,
    pub output_count: u64,
    pub hint_root: String,
    pub encrypted_route_root: String,
    pub produced_by_node_id: String,
    pub produced_at_l2_height: u64,
}

impl ViewTagSyncHint {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        commitment: &CompactBlockCommitment,
        hint_kind: ViewTagHintKind,
        view_tag: u16,
        output_count: u64,
        hint_root: &str,
        encrypted_route_root: &str,
        produced_by_node_id: &str,
        produced_at_l2_height: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(hint_root, "view tag hint root")?;
        ensure_non_empty(encrypted_route_root, "view tag encrypted route root")?;
        ensure_non_empty(produced_by_node_id, "view tag producer node id")?;
        ensure_positive(output_count, "view tag output count")?;
        let hint_id = compact_relay_id(
            "view-tag-hint",
            &[
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(hint_kind.as_str()),
                HashPart::Int(view_tag as i128),
                HashPart::Str(hint_root),
            ],
        );
        Ok(Self {
            hint_id,
            commitment_id: commitment.commitment_id.clone(),
            block_height: commitment.block_height,
            hint_kind,
            view_tag,
            output_count,
            hint_root: hint_root.to_string(),
            encrypted_route_root: encrypted_route_root.to_string(),
            produced_by_node_id: produced_by_node_id.to_string(),
            produced_at_l2_height,
        })
    }

    pub fn devnet(
        commitment: &CompactBlockCommitment,
        node_id: &str,
        kind: ViewTagHintKind,
        index: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{}-{node_id}-{index}", commitment.commitment_id);
        Self::new(
            commitment,
            kind,
            (index % 256) as u16,
            1 + index,
            &devnet_root("view-tag-hint-root", &seed),
            &devnet_root("view-tag-route-root", &seed),
            node_id,
            commitment.observed_at_l2_height.saturating_add(index),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_tag_sync_hint",
            "chain_id": CHAIN_ID,
            "hint_id": self.hint_id,
            "commitment_id": self.commitment_id,
            "block_height": self.block_height,
            "hint_kind": self.hint_kind.as_str(),
            "view_tag": self.view_tag,
            "output_count": self.output_count,
            "hint_root": self.hint_root,
            "encrypted_route_root": self.encrypted_route_root,
            "produced_by_node_id": self.produced_by_node_id,
            "produced_at_l2_height": self.produced_at_l2_height,
        })
    }

    pub fn hint_commitment_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-VIEW-TAG-HINT",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &MoneroCompactBlockRelayConfig,
    ) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.hint_id, "view tag hint id")?;
        ensure_non_empty(&self.commitment_id, "view tag commitment id")?;
        ensure_positive(self.block_height, "view tag block height")?;
        ensure_positive(self.output_count, "view tag output count")?;
        ensure_non_empty(&self.hint_root, "view tag hint root")?;
        ensure_non_empty(&self.encrypted_route_root, "view tag encrypted route root")?;
        ensure_non_empty(&self.produced_by_node_id, "view tag producer node id")?;
        if self.output_count > config.max_view_tag_hints {
            return Err("view tag hint exceeds configured hint output limit".to_string());
        }
        Ok(self.hint_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRelaySignature {
    pub signature_id: String,
    pub node_id: String,
    pub commitment_id: String,
    pub signed_root: String,
    pub signature_root: String,
    pub backup_signature_root: String,
    pub relay_weight: u64,
    pub signed_at_l2_height: u64,
    pub status: RelaySignatureStatus,
}

impl PqRelaySignature {
    pub fn new(
        node: &CompactRelayNode,
        commitment: &CompactBlockCommitment,
        signed_root: &str,
        signature_root: &str,
        backup_signature_root: &str,
        signed_at_l2_height: u64,
        status: RelaySignatureStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(signed_root, "pq relay signed root")?;
        ensure_non_empty(signature_root, "pq relay signature root")?;
        ensure_non_empty(backup_signature_root, "pq relay backup signature root")?;
        let signature_id = compact_relay_id(
            "pq-relay-signature",
            &[
                HashPart::Str(&node.node_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(signed_root),
                HashPart::Int(signed_at_l2_height as i128),
            ],
        );
        Ok(Self {
            signature_id,
            node_id: node.node_id.clone(),
            commitment_id: commitment.commitment_id.clone(),
            signed_root: signed_root.to_string(),
            signature_root: signature_root.to_string(),
            backup_signature_root: backup_signature_root.to_string(),
            relay_weight: node.relay_weight,
            signed_at_l2_height,
            status,
        })
    }

    pub fn devnet(
        node: &CompactRelayNode,
        commitment: &CompactBlockCommitment,
        status: RelaySignatureStatus,
        index: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{}-{}-{index}", node.node_id, commitment.commitment_id);
        Self::new(
            node,
            commitment,
            &commitment.commitment_root(),
            &devnet_root("pq-relay-signature-root", &seed),
            &devnet_root("pq-relay-backup-signature-root", &seed),
            commitment.observed_at_l2_height.saturating_add(index),
            status,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_relay_signature",
            "chain_id": CHAIN_ID,
            "signature_id": self.signature_id,
            "node_id": self.node_id,
            "commitment_id": self.commitment_id,
            "signed_root": self.signed_root,
            "signature_root": self.signature_root,
            "backup_signature_root": self.backup_signature_root,
            "relay_weight": self.relay_weight,
            "signed_at_l2_height": self.signed_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn signature_commitment_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-PQ-SIGNATURE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.signature_id, "pq relay signature id")?;
        ensure_non_empty(&self.node_id, "pq relay node id")?;
        ensure_non_empty(&self.commitment_id, "pq relay commitment id")?;
        ensure_non_empty(&self.signed_root, "pq relay signed root")?;
        ensure_non_empty(&self.signature_root, "pq relay signature root")?;
        ensure_non_empty(
            &self.backup_signature_root,
            "pq relay backup signature root",
        )?;
        ensure_positive(self.relay_weight, "pq relay signature weight")?;
        Ok(self.signature_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWatcherAck {
    pub ack_id: String,
    pub watcher_id: String,
    pub commitment_id: String,
    pub ack_kind: PrivateWatcherAckKind,
    pub sealed_ack_root: String,
    pub nullifier_root: String,
    pub received_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: PrivateWatcherAckStatus,
}

impl PrivateWatcherAck {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        watcher_id: &str,
        commitment: &CompactBlockCommitment,
        ack_kind: PrivateWatcherAckKind,
        sealed_ack_root: &str,
        nullifier_root: &str,
        received_at_l2_height: u64,
        ttl_blocks: u64,
        status: PrivateWatcherAckStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(watcher_id, "private watcher id")?;
        ensure_non_empty(sealed_ack_root, "private watcher sealed ack root")?;
        ensure_non_empty(nullifier_root, "private watcher nullifier root")?;
        ensure_positive(ttl_blocks, "private watcher ack ttl")?;
        let ack_id = compact_relay_id(
            "private-watcher-ack",
            &[
                HashPart::Str(watcher_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(ack_kind.as_str()),
                HashPart::Str(nullifier_root),
            ],
        );
        Ok(Self {
            ack_id,
            watcher_id: watcher_id.to_string(),
            commitment_id: commitment.commitment_id.clone(),
            ack_kind,
            sealed_ack_root: sealed_ack_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            received_at_l2_height,
            expires_at_l2_height: received_at_l2_height.saturating_add(ttl_blocks),
            status,
        })
    }

    pub fn devnet(
        watcher_id: &str,
        commitment: &CompactBlockCommitment,
        kind: PrivateWatcherAckKind,
        height: u64,
        ttl: u64,
        index: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{}-{watcher_id}-{index}", commitment.commitment_id);
        Self::new(
            watcher_id,
            commitment,
            kind,
            &devnet_root("private-watcher-ack-root", &seed),
            &devnet_root("private-watcher-nullifier-root", &seed),
            height,
            ttl,
            PrivateWatcherAckStatus::Delivered,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_watcher_ack",
            "chain_id": CHAIN_ID,
            "ack_id": self.ack_id,
            "watcher_id": self.watcher_id,
            "commitment_id": self.commitment_id,
            "ack_kind": self.ack_kind.as_str(),
            "sealed_ack_root": self.sealed_ack_root,
            "nullifier_root": self.nullifier_root,
            "received_at_l2_height": self.received_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn ack_commitment_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-PRIVATE-ACK",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.ack_id, "private watcher ack id")?;
        ensure_non_empty(&self.watcher_id, "private watcher id")?;
        ensure_non_empty(&self.commitment_id, "private watcher commitment id")?;
        ensure_non_empty(&self.sealed_ack_root, "private watcher sealed ack root")?;
        ensure_non_empty(&self.nullifier_root, "private watcher nullifier root")?;
        if self.expires_at_l2_height <= self.received_at_l2_height {
            return Err("private watcher ack expiry must exceed received height".to_string());
        }
        Ok(self.ack_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeRelaySponsorship {
    pub sponsorship_id: String,
    pub sponsor_id: String,
    pub commitment_id: String,
    pub fee_asset_id: String,
    pub reserved_fee_units: u64,
    pub consumed_fee_units: u64,
    pub unit_price: u64,
    pub offered_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: RelaySponsorshipStatus,
}

impl LowFeeRelaySponsorship {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_id: &str,
        commitment: &CompactBlockCommitment,
        fee_asset_id: &str,
        reserved_fee_units: u64,
        consumed_fee_units: u64,
        unit_price: u64,
        offered_at_l2_height: u64,
        ttl_blocks: u64,
        status: RelaySponsorshipStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(sponsor_id, "relay sponsorship sponsor id")?;
        ensure_non_empty(fee_asset_id, "relay sponsorship fee asset id")?;
        ensure_positive(reserved_fee_units, "relay sponsorship reserved units")?;
        ensure_positive(unit_price, "relay sponsorship unit price")?;
        ensure_positive(ttl_blocks, "relay sponsorship ttl")?;
        if consumed_fee_units > reserved_fee_units {
            return Err("relay sponsorship consumed units exceed reserved units".to_string());
        }
        let sponsorship_id = compact_relay_id(
            "low-fee-sponsorship",
            &[
                HashPart::Str(sponsor_id),
                HashPart::Str(&commitment.commitment_id),
                HashPart::Str(fee_asset_id),
                HashPart::Int(offered_at_l2_height as i128),
            ],
        );
        Ok(Self {
            sponsorship_id,
            sponsor_id: sponsor_id.to_string(),
            commitment_id: commitment.commitment_id.clone(),
            fee_asset_id: fee_asset_id.to_string(),
            reserved_fee_units,
            consumed_fee_units,
            unit_price,
            offered_at_l2_height,
            expires_at_l2_height: offered_at_l2_height.saturating_add(ttl_blocks),
            status,
        })
    }

    pub fn devnet(
        sponsor_id: &str,
        commitment: &CompactBlockCommitment,
        fee_asset_id: &str,
        height: u64,
        ttl: u64,
        index: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        Self::new(
            sponsor_id,
            commitment,
            fee_asset_id,
            64 + index,
            index,
            MONERO_COMPACT_BLOCK_RELAY_DEFAULT_LOW_FEE_UNIT_PRICE,
            height,
            ttl,
            RelaySponsorshipStatus::Reserved,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_relay_sponsorship",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_id": self.sponsor_id,
            "commitment_id": self.commitment_id,
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
            "unit_price": self.unit_price,
            "offered_at_l2_height": self.offered_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-SPONSORSHIP",
            &self.public_record(),
        )
    }

    pub fn validate(&self, max_budget: u64) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.sponsorship_id, "relay sponsorship id")?;
        ensure_non_empty(&self.sponsor_id, "relay sponsorship sponsor id")?;
        ensure_non_empty(&self.commitment_id, "relay sponsorship commitment id")?;
        ensure_non_empty(&self.fee_asset_id, "relay sponsorship fee asset id")?;
        ensure_positive(self.reserved_fee_units, "relay sponsorship reserved units")?;
        ensure_positive(self.unit_price, "relay sponsorship unit price")?;
        if self.consumed_fee_units > self.reserved_fee_units {
            return Err("relay sponsorship consumed units exceed reserved units".to_string());
        }
        if self.reserved_fee_units.saturating_mul(self.unit_price) > max_budget {
            return Err("relay sponsorship exceeds configured budget".to_string());
        }
        if self.expires_at_l2_height <= self.offered_at_l2_height {
            return Err("relay sponsorship expiry must exceed offer height".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgRepairBatch {
    pub repair_id: String,
    pub canonical_start_height: u64,
    pub replaced_tip_height: u64,
    pub repaired_tip_height: u64,
    pub old_tip_root: String,
    pub new_tip_root: String,
    pub repair_block_count: u64,
    pub repair_batch_root: String,
    pub produced_by_node_id: String,
    pub produced_at_l2_height: u64,
    pub status: ReorgRepairStatus,
}

impl ReorgRepairBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        canonical_start_height: u64,
        replaced_tip_height: u64,
        repaired_tip_height: u64,
        old_tip_root: &str,
        new_tip_root: &str,
        repair_block_count: u64,
        repair_batch_root: &str,
        produced_by_node_id: &str,
        produced_at_l2_height: u64,
        status: ReorgRepairStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_positive(
            canonical_start_height,
            "reorg repair canonical start height",
        )?;
        ensure_positive(replaced_tip_height, "reorg repair replaced tip height")?;
        ensure_positive(repaired_tip_height, "reorg repair repaired tip height")?;
        ensure_positive(repair_block_count, "reorg repair block count")?;
        ensure_non_empty(old_tip_root, "reorg repair old tip root")?;
        ensure_non_empty(new_tip_root, "reorg repair new tip root")?;
        ensure_non_empty(repair_batch_root, "reorg repair batch root")?;
        ensure_non_empty(produced_by_node_id, "reorg repair producer node id")?;
        if canonical_start_height > replaced_tip_height {
            return Err("reorg repair canonical start exceeds replaced tip".to_string());
        }
        if canonical_start_height > repaired_tip_height {
            return Err("reorg repair canonical start exceeds repaired tip".to_string());
        }
        let repair_id = compact_relay_id(
            "reorg-repair-batch",
            &[
                HashPart::Int(canonical_start_height as i128),
                HashPart::Int(replaced_tip_height as i128),
                HashPart::Int(repaired_tip_height as i128),
                HashPart::Str(repair_batch_root),
            ],
        );
        Ok(Self {
            repair_id,
            canonical_start_height,
            replaced_tip_height,
            repaired_tip_height,
            old_tip_root: old_tip_root.to_string(),
            new_tip_root: new_tip_root.to_string(),
            repair_block_count,
            repair_batch_root: repair_batch_root.to_string(),
            produced_by_node_id: produced_by_node_id.to_string(),
            produced_at_l2_height,
            status,
        })
    }

    pub fn devnet(
        node_id: &str,
        base_height: u64,
        l2_height: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{node_id}-{base_height}-{l2_height}");
        Self::new(
            base_height,
            base_height.saturating_add(4),
            base_height.saturating_add(5),
            &devnet_root("reorg-repair-old-tip", &seed),
            &devnet_root("reorg-repair-new-tip", &seed),
            5,
            &devnet_root("reorg-repair-batch-root", &seed),
            node_id,
            l2_height,
            ReorgRepairStatus::Proposed,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reorg_repair_batch",
            "chain_id": CHAIN_ID,
            "repair_id": self.repair_id,
            "canonical_start_height": self.canonical_start_height,
            "replaced_tip_height": self.replaced_tip_height,
            "repaired_tip_height": self.repaired_tip_height,
            "old_tip_root": self.old_tip_root,
            "new_tip_root": self.new_tip_root,
            "repair_block_count": self.repair_block_count,
            "repair_batch_root": self.repair_batch_root,
            "produced_by_node_id": self.produced_by_node_id,
            "produced_at_l2_height": self.produced_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn batch_commitment_root(&self) -> String {
        compact_relay_payload_root(
            "MONERO-COMPACT-BLOCK-RELAY-REORG-REPAIR",
            &self.public_record(),
        )
    }

    pub fn validate(&self, max_repair_blocks: u64) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.repair_id, "reorg repair id")?;
        ensure_positive(
            self.canonical_start_height,
            "reorg repair canonical start height",
        )?;
        ensure_positive(self.replaced_tip_height, "reorg repair replaced tip height")?;
        ensure_positive(self.repaired_tip_height, "reorg repair repaired tip height")?;
        ensure_positive(self.repair_block_count, "reorg repair block count")?;
        ensure_non_empty(&self.old_tip_root, "reorg repair old tip root")?;
        ensure_non_empty(&self.new_tip_root, "reorg repair new tip root")?;
        ensure_non_empty(&self.repair_batch_root, "reorg repair batch root")?;
        ensure_non_empty(&self.produced_by_node_id, "reorg repair producer node id")?;
        if self.repair_block_count > max_repair_blocks {
            return Err("reorg repair batch exceeds configured block limit".to_string());
        }
        Ok(self.batch_commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySlashingEvidence {
    pub evidence_id: String,
    pub accused_node_id: String,
    pub evidence_kind: RelaySlashingEvidenceKind,
    pub commitment_id: String,
    pub conflicting_root: String,
    pub witness_root: String,
    pub slash_units: u64,
    pub opened_at_l2_height: u64,
    pub expires_at_l2_height: u64,
    pub status: RelaySlashingEvidenceStatus,
}

impl RelaySlashingEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accused_node_id: &str,
        evidence_kind: RelaySlashingEvidenceKind,
        commitment_id: &str,
        conflicting_root: &str,
        witness_root: &str,
        slash_units: u64,
        opened_at_l2_height: u64,
        ttl_blocks: u64,
        status: RelaySlashingEvidenceStatus,
    ) -> MoneroCompactBlockRelayResult<Self> {
        ensure_non_empty(accused_node_id, "relay slashing accused node id")?;
        ensure_non_empty(commitment_id, "relay slashing commitment id")?;
        ensure_non_empty(conflicting_root, "relay slashing conflicting root")?;
        ensure_non_empty(witness_root, "relay slashing witness root")?;
        ensure_positive(slash_units, "relay slashing units")?;
        ensure_positive(ttl_blocks, "relay slashing ttl")?;
        let evidence_id = compact_relay_id(
            "slashing-evidence",
            &[
                HashPart::Str(accused_node_id),
                HashPart::Str(evidence_kind.as_str()),
                HashPart::Str(commitment_id),
                HashPart::Str(conflicting_root),
            ],
        );
        Ok(Self {
            evidence_id,
            accused_node_id: accused_node_id.to_string(),
            evidence_kind,
            commitment_id: commitment_id.to_string(),
            conflicting_root: conflicting_root.to_string(),
            witness_root: witness_root.to_string(),
            slash_units,
            opened_at_l2_height,
            expires_at_l2_height: opened_at_l2_height.saturating_add(ttl_blocks),
            status,
        })
    }

    pub fn devnet(
        node_id: &str,
        commitment_id: &str,
        opened_at_l2_height: u64,
        ttl_blocks: u64,
    ) -> MoneroCompactBlockRelayResult<Self> {
        let seed = format!("{node_id}-{commitment_id}");
        Self::new(
            node_id,
            RelaySlashingEvidenceKind::InvalidTxPrefixSketch,
            commitment_id,
            &devnet_root("slashing-conflicting-root", &seed),
            &devnet_root("slashing-witness-root", &seed),
            25_000,
            opened_at_l2_height,
            ttl_blocks,
            RelaySlashingEvidenceStatus::Prepared,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relay_slashing_evidence",
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "accused_node_id": self.accused_node_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "commitment_id": self.commitment_id,
            "conflicting_root": self.conflicting_root,
            "witness_root": self.witness_root,
            "slash_units": self.slash_units,
            "opened_at_l2_height": self.opened_at_l2_height,
            "expires_at_l2_height": self.expires_at_l2_height,
            "status": self.status.as_str(),
        })
    }

    pub fn evidence_root(&self) -> String {
        compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-SLASHING", &self.public_record())
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        ensure_non_empty(&self.evidence_id, "relay slashing evidence id")?;
        ensure_non_empty(&self.accused_node_id, "relay slashing accused node id")?;
        ensure_non_empty(&self.commitment_id, "relay slashing commitment id")?;
        ensure_non_empty(&self.conflicting_root, "relay slashing conflicting root")?;
        ensure_non_empty(&self.witness_root, "relay slashing witness root")?;
        ensure_positive(self.slash_units, "relay slashing units")?;
        if self.expires_at_l2_height <= self.opened_at_l2_height {
            return Err("relay slashing expiry must exceed opened height".to_string());
        }
        Ok(self.evidence_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroCompactBlockRelayCounters {
    pub relay_nodes: u64,
    pub active_relay_nodes: u64,
    pub compact_blocks: u64,
    pub finalized_blocks: u64,
    pub tx_prefix_sketches: u64,
    pub total_tx_prefixes: u64,
    pub view_tag_hints: u64,
    pub hinted_outputs: u64,
    pub pq_relay_signatures: u64,
    pub counted_signature_weight: u64,
    pub private_watcher_acks: u64,
    pub live_private_watcher_acks: u64,
    pub low_fee_sponsorships: u64,
    pub live_low_fee_sponsorships: u64,
    pub sponsored_fee_units_reserved: u64,
    pub sponsored_fee_units_consumed: u64,
    pub reorg_repair_batches: u64,
    pub open_reorg_repair_batches: u64,
    pub slashing_evidence: u64,
    pub actionable_slashing_evidence: u64,
}

impl MoneroCompactBlockRelayCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_compact_block_relay_counters",
            "chain_id": CHAIN_ID,
            "relay_nodes": self.relay_nodes,
            "active_relay_nodes": self.active_relay_nodes,
            "compact_blocks": self.compact_blocks,
            "finalized_blocks": self.finalized_blocks,
            "tx_prefix_sketches": self.tx_prefix_sketches,
            "total_tx_prefixes": self.total_tx_prefixes,
            "view_tag_hints": self.view_tag_hints,
            "hinted_outputs": self.hinted_outputs,
            "pq_relay_signatures": self.pq_relay_signatures,
            "counted_signature_weight": self.counted_signature_weight,
            "private_watcher_acks": self.private_watcher_acks,
            "live_private_watcher_acks": self.live_private_watcher_acks,
            "low_fee_sponsorships": self.low_fee_sponsorships,
            "live_low_fee_sponsorships": self.live_low_fee_sponsorships,
            "sponsored_fee_units_reserved": self.sponsored_fee_units_reserved,
            "sponsored_fee_units_consumed": self.sponsored_fee_units_consumed,
            "reorg_repair_batches": self.reorg_repair_batches,
            "open_reorg_repair_batches": self.open_reorg_repair_batches,
            "slashing_evidence": self.slashing_evidence,
            "actionable_slashing_evidence": self.actionable_slashing_evidence,
        })
    }

    pub fn counters_root(&self) -> String {
        compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroCompactBlockRelayRoots {
    pub config_root: String,
    pub relay_node_root: String,
    pub compact_block_root: String,
    pub tx_prefix_sketch_root: String,
    pub view_tag_hint_root: String,
    pub pq_signature_root: String,
    pub private_watcher_ack_root: String,
    pub sponsorship_root: String,
    pub reorg_repair_root: String,
    pub slashing_evidence_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl MoneroCompactBlockRelayRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_compact_block_relay_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "relay_node_root": self.relay_node_root,
            "compact_block_root": self.compact_block_root,
            "tx_prefix_sketch_root": self.tx_prefix_sketch_root,
            "view_tag_hint_root": self.view_tag_hint_root,
            "pq_signature_root": self.pq_signature_root,
            "private_watcher_ack_root": self.private_watcher_ack_root,
            "sponsorship_root": self.sponsorship_root,
            "reorg_repair_root": self.reorg_repair_root,
            "slashing_evidence_root": self.slashing_evidence_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroCompactBlockRelayState {
    pub config: MoneroCompactBlockRelayConfig,
    pub current_l2_height: u64,
    pub last_monero_height: u64,
    pub finalized_monero_height: u64,
    pub latest_finalized_commitment_id: String,
    pub relay_nodes: BTreeMap<String, CompactRelayNode>,
    pub compact_blocks: BTreeMap<String, CompactBlockCommitment>,
    pub tx_prefix_sketches: BTreeMap<String, TxPrefixSketch>,
    pub view_tag_hints: BTreeMap<String, ViewTagSyncHint>,
    pub pq_relay_signatures: BTreeMap<String, PqRelaySignature>,
    pub private_watcher_acks: BTreeMap<String, PrivateWatcherAck>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeRelaySponsorship>,
    pub reorg_repair_batches: BTreeMap<String, ReorgRepairBatch>,
    pub slashing_evidence: BTreeMap<String, RelaySlashingEvidence>,
}

impl MoneroCompactBlockRelayState {
    pub fn new(
        config: MoneroCompactBlockRelayConfig,
        current_l2_height: u64,
        last_monero_height: u64,
    ) -> Self {
        Self {
            config,
            current_l2_height,
            last_monero_height,
            finalized_monero_height: 0,
            latest_finalized_commitment_id: String::new(),
            relay_nodes: BTreeMap::new(),
            compact_blocks: BTreeMap::new(),
            tx_prefix_sketches: BTreeMap::new(),
            view_tag_hints: BTreeMap::new(),
            pq_relay_signatures: BTreeMap::new(),
            private_watcher_acks: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            reorg_repair_batches: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
        }
    }

    pub fn devnet() -> MoneroCompactBlockRelayResult<Self> {
        let config = MoneroCompactBlockRelayConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            MONERO_COMPACT_BLOCK_RELAY_DEVNET_L2_HEIGHT,
            MONERO_COMPACT_BLOCK_RELAY_DEVNET_MONERO_HEIGHT,
        );
        let producer = CompactRelayNode::devnet(
            0,
            CompactRelayNodeRole::BlockProducer,
            40,
            state.current_l2_height,
        )?;
        let sketcher = CompactRelayNode::devnet(
            1,
            CompactRelayNodeRole::PrefixSketcher,
            30,
            state.current_l2_height,
        )?;
        let watcher = CompactRelayNode::devnet(
            2,
            CompactRelayNodeRole::BridgeWatcher,
            20,
            state.current_l2_height,
        )?;
        let sponsor = CompactRelayNode::devnet(
            3,
            CompactRelayNodeRole::FeeSponsor,
            10,
            state.current_l2_height,
        )?;
        state
            .relay_nodes
            .insert(producer.node_id.clone(), producer.clone());
        state
            .relay_nodes
            .insert(sketcher.node_id.clone(), sketcher.clone());
        state
            .relay_nodes
            .insert(watcher.node_id.clone(), watcher.clone());
        state
            .relay_nodes
            .insert(sponsor.node_id.clone(), sponsor.clone());

        let base_height = state.last_monero_height.saturating_sub(3);
        for offset in 0..4 {
            let status = if offset < 3 {
                CompactBlockStatus::Finalized
            } else {
                CompactBlockStatus::Attested
            };
            let block = CompactBlockCommitment::devnet(
                base_height.saturating_add(offset),
                state.current_l2_height.saturating_add(offset),
                status,
            )?;
            let sketch = TxPrefixSketch::devnet(&block, &sketcher.node_id, offset)?;
            let hint = ViewTagSyncHint::devnet(
                &block,
                &watcher.node_id,
                ViewTagHintKind::DepositCandidate,
                offset,
            )?;
            let sig_a =
                PqRelaySignature::devnet(&producer, &block, RelaySignatureStatus::Counted, offset)?;
            let sig_b =
                PqRelaySignature::devnet(&sketcher, &block, RelaySignatureStatus::Counted, offset)?;
            let ack = PrivateWatcherAck::devnet(
                &watcher.node_id,
                &block,
                PrivateWatcherAckKind::SketchReceived,
                state.current_l2_height.saturating_add(offset),
                config.private_ack_ttl_blocks,
                offset,
            )?;
            if block.status == CompactBlockStatus::Finalized {
                state.finalized_monero_height = block.block_height;
                state.latest_finalized_commitment_id = block.commitment_id.clone();
            }
            state
                .tx_prefix_sketches
                .insert(sketch.sketch_id.clone(), sketch);
            state.view_tag_hints.insert(hint.hint_id.clone(), hint);
            state
                .pq_relay_signatures
                .insert(sig_a.signature_id.clone(), sig_a);
            state
                .pq_relay_signatures
                .insert(sig_b.signature_id.clone(), sig_b);
            state.private_watcher_acks.insert(ack.ack_id.clone(), ack);
            state
                .compact_blocks
                .insert(block.commitment_id.clone(), block);
        }

        let first_block = state
            .compact_blocks
            .values()
            .next()
            .cloned()
            .ok_or_else(|| "devnet compact relay missing block".to_string())?;
        let sponsorship = LowFeeRelaySponsorship::devnet(
            &sponsor.node_id,
            &first_block,
            &config.fee_asset_id,
            state.current_l2_height,
            config.sponsorship_ttl_blocks,
            3,
        )?;
        state
            .low_fee_sponsorships
            .insert(sponsorship.sponsorship_id.clone(), sponsorship);

        let repair = ReorgRepairBatch::devnet(
            &producer.node_id,
            base_height,
            state.current_l2_height.saturating_add(8),
        )?;
        state
            .reorg_repair_batches
            .insert(repair.repair_id.clone(), repair);

        let evidence = RelaySlashingEvidence::devnet(
            &sketcher.node_id,
            &first_block.commitment_id,
            state.current_l2_height.saturating_add(9),
            config.slashing_ttl_blocks,
        )?;
        state
            .slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);

        state.validate()?;
        Ok(state)
    }

    pub fn update_height(
        &mut self,
        new_l2_height: u64,
        new_monero_height: u64,
    ) -> MoneroCompactBlockRelayResult<()> {
        if new_l2_height < self.current_l2_height {
            return Err(format!(
                "l2 height cannot move backward from {} to {}",
                self.current_l2_height, new_l2_height
            ));
        }
        if new_monero_height < self.last_monero_height {
            return Err(format!(
                "monero height cannot move backward from {} to {}",
                self.last_monero_height, new_monero_height
            ));
        }
        self.current_l2_height = new_l2_height;
        self.last_monero_height = new_monero_height;
        Ok(())
    }

    pub fn add_compact_block(
        &mut self,
        block: CompactBlockCommitment,
    ) -> MoneroCompactBlockRelayResult<String> {
        let root = block.validate()?;
        if block.block_height > self.last_monero_height {
            self.last_monero_height = block.block_height;
        }
        if block.status == CompactBlockStatus::Finalized {
            self.finalized_monero_height = self.finalized_monero_height.max(block.block_height);
            self.latest_finalized_commitment_id = block.commitment_id.clone();
        }
        self.compact_blocks
            .insert(block.commitment_id.clone(), block);
        Ok(root)
    }

    pub fn counters(&self) -> MoneroCompactBlockRelayCounters {
        MoneroCompactBlockRelayCounters {
            relay_nodes: self.relay_nodes.len() as u64,
            active_relay_nodes: self
                .relay_nodes
                .values()
                .filter(|node| node.status.can_relay())
                .count() as u64,
            compact_blocks: self.compact_blocks.len() as u64,
            finalized_blocks: self
                .compact_blocks
                .values()
                .filter(|block| block.status == CompactBlockStatus::Finalized)
                .count() as u64,
            tx_prefix_sketches: self.tx_prefix_sketches.len() as u64,
            total_tx_prefixes: self
                .tx_prefix_sketches
                .values()
                .map(|sketch| sketch.tx_prefix_count)
                .sum(),
            view_tag_hints: self.view_tag_hints.len() as u64,
            hinted_outputs: self
                .view_tag_hints
                .values()
                .map(|hint| hint.output_count)
                .sum(),
            pq_relay_signatures: self.pq_relay_signatures.len() as u64,
            counted_signature_weight: self
                .pq_relay_signatures
                .values()
                .filter(|signature| signature.status.counts_for_quorum())
                .map(|signature| signature.relay_weight)
                .sum(),
            private_watcher_acks: self.private_watcher_acks.len() as u64,
            live_private_watcher_acks: self
                .private_watcher_acks
                .values()
                .filter(|ack| ack.status.is_live())
                .count() as u64,
            low_fee_sponsorships: self.low_fee_sponsorships.len() as u64,
            live_low_fee_sponsorships: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.status.is_live())
                .count() as u64,
            sponsored_fee_units_reserved: self
                .low_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.reserved_fee_units)
                .sum(),
            sponsored_fee_units_consumed: self
                .low_fee_sponsorships
                .values()
                .map(|sponsorship| sponsorship.consumed_fee_units)
                .sum(),
            reorg_repair_batches: self.reorg_repair_batches.len() as u64,
            open_reorg_repair_batches: self
                .reorg_repair_batches
                .values()
                .filter(|batch| batch.status.is_open())
                .count() as u64,
            slashing_evidence: self.slashing_evidence.len() as u64,
            actionable_slashing_evidence: self
                .slashing_evidence
                .values()
                .filter(|evidence| evidence.status.actionable())
                .count() as u64,
        }
    }

    pub fn roots(&self) -> MoneroCompactBlockRelayRoots {
        let counters = self.counters();
        let config_root = self.config.config_root();
        let relay_node_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-NODES",
            self.relay_nodes
                .values()
                .map(CompactRelayNode::public_record),
        );
        let compact_block_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-BLOCKS",
            self.compact_blocks
                .values()
                .map(CompactBlockCommitment::public_record),
        );
        let tx_prefix_sketch_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-SKETCHES",
            self.tx_prefix_sketches
                .values()
                .map(TxPrefixSketch::public_record),
        );
        let view_tag_hint_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-HINTS",
            self.view_tag_hints
                .values()
                .map(ViewTagSyncHint::public_record),
        );
        let pq_signature_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-SIGNATURES",
            self.pq_relay_signatures
                .values()
                .map(PqRelaySignature::public_record),
        );
        let private_watcher_ack_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-ACKS",
            self.private_watcher_acks
                .values()
                .map(PrivateWatcherAck::public_record),
        );
        let sponsorship_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-SPONSORSHIPS",
            self.low_fee_sponsorships
                .values()
                .map(LowFeeRelaySponsorship::public_record),
        );
        let reorg_repair_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-REPAIRS",
            self.reorg_repair_batches
                .values()
                .map(ReorgRepairBatch::public_record),
        );
        let slashing_evidence_root = map_root(
            "MONERO-COMPACT-BLOCK-RELAY-SLASHING-EVIDENCE",
            self.slashing_evidence
                .values()
                .map(RelaySlashingEvidence::public_record),
        );
        let counters_root = counters.counters_root();
        let root_payload = json!({
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_l2_height": self.current_l2_height,
            "last_monero_height": self.last_monero_height,
            "finalized_monero_height": self.finalized_monero_height,
            "latest_finalized_commitment_id": self.latest_finalized_commitment_id,
            "config_root": config_root,
            "relay_node_root": relay_node_root,
            "compact_block_root": compact_block_root,
            "tx_prefix_sketch_root": tx_prefix_sketch_root,
            "view_tag_hint_root": view_tag_hint_root,
            "pq_signature_root": pq_signature_root,
            "private_watcher_ack_root": private_watcher_ack_root,
            "sponsorship_root": sponsorship_root,
            "reorg_repair_root": reorg_repair_root,
            "slashing_evidence_root": slashing_evidence_root,
            "counters_root": counters_root,
        });
        let state_root =
            compact_relay_payload_root("MONERO-COMPACT-BLOCK-RELAY-STATE", &root_payload);
        MoneroCompactBlockRelayRoots {
            config_root,
            relay_node_root,
            compact_block_root,
            tx_prefix_sketch_root,
            view_tag_hint_root,
            pq_signature_root,
            private_watcher_ack_root,
            sponsorship_root,
            reorg_repair_root,
            slashing_evidence_root,
            counters_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "monero_compact_block_relay_state",
            "chain_id": CHAIN_ID,
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "current_l2_height": self.current_l2_height,
            "last_monero_height": self.last_monero_height,
            "finalized_monero_height": self.finalized_monero_height,
            "latest_finalized_commitment_id": self.latest_finalized_commitment_id,
            "roots": roots.public_record(),
            "counters": self.counters().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn validate(&self) -> MoneroCompactBlockRelayResult<String> {
        self.config.validate()?;
        ensure_positive(self.current_l2_height, "compact relay l2 height")?;
        ensure_positive(self.last_monero_height, "compact relay monero height")?;
        if self.finalized_monero_height > self.last_monero_height {
            return Err("finalized monero height exceeds last monero height".to_string());
        }
        let mut canonical_heights = BTreeSet::new();
        for node in self.relay_nodes.values() {
            node.validate()?;
        }
        for block in self.compact_blocks.values() {
            block.validate()?;
            if block.status != CompactBlockStatus::Reorged
                && block.status != CompactBlockStatus::Rejected
                && !canonical_heights.insert(block.block_height)
            {
                return Err(format!(
                    "duplicate canonical compact block at height {}",
                    block.block_height
                ));
            }
        }
        for sketch in self.tx_prefix_sketches.values() {
            sketch.validate(&self.config)?;
            if !self.compact_blocks.contains_key(&sketch.commitment_id) {
                return Err(format!(
                    "tx prefix sketch {} references unknown compact block",
                    sketch.sketch_id
                ));
            }
            if !self.relay_nodes.contains_key(&sketch.produced_by_node_id) {
                return Err(format!(
                    "tx prefix sketch {} references unknown producer",
                    sketch.sketch_id
                ));
            }
        }
        for hint in self.view_tag_hints.values() {
            hint.validate(&self.config)?;
            if !self.compact_blocks.contains_key(&hint.commitment_id) {
                return Err(format!(
                    "view tag hint {} references unknown compact block",
                    hint.hint_id
                ));
            }
            if !self.relay_nodes.contains_key(&hint.produced_by_node_id) {
                return Err(format!(
                    "view tag hint {} references unknown producer",
                    hint.hint_id
                ));
            }
        }
        for signature in self.pq_relay_signatures.values() {
            signature.validate()?;
            if !self.compact_blocks.contains_key(&signature.commitment_id) {
                return Err(format!(
                    "pq relay signature {} references unknown compact block",
                    signature.signature_id
                ));
            }
            if !self.relay_nodes.contains_key(&signature.node_id) {
                return Err(format!(
                    "pq relay signature {} references unknown node",
                    signature.signature_id
                ));
            }
        }
        for ack in self.private_watcher_acks.values() {
            ack.validate()?;
            if !self.compact_blocks.contains_key(&ack.commitment_id) {
                return Err(format!(
                    "private watcher ack {} references unknown compact block",
                    ack.ack_id
                ));
            }
        }
        let acked_blocks = self
            .private_watcher_acks
            .values()
            .filter(|ack| ack.status.is_live())
            .fold(BTreeMap::<String, u64>::new(), |mut acc, ack| {
                let entry = acc.entry(ack.commitment_id.clone()).or_insert(0);
                *entry = entry.saturating_add(1);
                acc
            });
        for (commitment_id, count) in acked_blocks {
            if count > self.config.max_acks_per_block {
                return Err(format!(
                    "compact block {commitment_id} exceeds private ack limit"
                ));
            }
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate(self.config.low_fee_budget)?;
            if !self.compact_blocks.contains_key(&sponsorship.commitment_id) {
                return Err(format!(
                    "relay sponsorship {} references unknown compact block",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for repair in self.reorg_repair_batches.values() {
            repair.validate(self.config.max_repair_blocks)?;
            if !self.relay_nodes.contains_key(&repair.produced_by_node_id) {
                return Err(format!(
                    "reorg repair {} references unknown producer",
                    repair.repair_id
                ));
            }
        }
        for evidence in self.slashing_evidence.values() {
            evidence.validate()?;
            if !self.relay_nodes.contains_key(&evidence.accused_node_id) {
                return Err(format!(
                    "slashing evidence {} references unknown accused node",
                    evidence.evidence_id
                ));
            }
        }
        Ok(self.state_root())
    }
}

fn ensure_non_empty(value: &str, label: &str) -> MoneroCompactBlockRelayResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_positive(value: u64, label: &str) -> MoneroCompactBlockRelayResult<()> {
    if value == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(())
}

fn compact_relay_id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("MONERO-COMPACT-BLOCK-RELAY-ID-{domain}"),
        parts,
        32,
    )
}

fn compact_relay_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

fn map_root(domain: &str, records: impl Iterator<Item = Value>) -> String {
    let leaves = records.collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn devnet_root(domain: &str, seed: &str) -> String {
    domain_hash(
        &format!("MONERO-COMPACT-BLOCK-RELAY-DEVNET-{domain}"),
        &[HashPart::Str(seed)],
        32,
    )
}
