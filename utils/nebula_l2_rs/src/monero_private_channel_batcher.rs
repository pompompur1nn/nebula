use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroPrivateChannelBatcherResult<T> = Result<T, String>;

pub const MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION: &str =
    "nebula-monero-private-channel-batcher-v1";
pub const PROTOCOL_VERSION: &str = MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_SCHEMA_VERSION: u64 = 1;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_HEIGHT: u64 = 1_872;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_STEALTH_ENVELOPE_SCHEME: &str =
    "monero-stealth-channel-envelope-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_SUBADDRESS_ROUTE_SCHEME: &str =
    "subaddress-route-commitment-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_PQ_SIGNER_SCHEME: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-192s-private-channel-batch-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_BATCH_PROOF_SCHEME: &str =
    "private-channel-entry-exit-netting-proof-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_FEE_COMPRESSION_SCHEME: &str =
    "monero-l2-private-fee-compression-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-channel-sponsorship-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_REORG_GUARD_SCHEME: &str =
    "monero-reorg-guard-delayed-finality-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_RECEIPT_SCHEME: &str = "private-channel-batch-receipt-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DISPUTE_SCHEME: &str =
    "private-channel-dispute-evidence-v1";
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS: u64 = 4;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_BATCH_ITEMS: u64 = 512;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_BATCH_WEIGHT: u64 = 6_000_000;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_ENTRY_TTL_BLOCKS: u64 = 48;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_EXIT_TTL_BLOCKS: u64 = 72;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 36;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_REORG_FINALITY_BLOCKS: u64 = 12;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_REORG_SAFETY_MARGIN_BLOCKS: u64 = 4;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 512;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 2_048;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_TARGET_RING_SIZE: u64 = 32;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_PQ_SIGNER_WEIGHT: u64 = 3;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_DISPUTE_SIGNER_WEIGHT: u64 = 2;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_BASE_FEE_BPS: u64 = 12;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_FAST_FEE_BPS: u64 = 36;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_EMERGENCY_FEE_BPS: u64 = 90;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_FEE_FLOOR_PICONERO: u64 = 1_000;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_COMPRESSION_REBATE_BPS: u64 = 6_500;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_LOW_FEE_REBATE_BPS: u64 = 8_500;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_SPONSOR_REBATE_BPS: u64 = 9_500;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_SPONSOR_POOL_PICONERO: u64 = 120_000_000;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS: u64 = 10_000;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_CHANNELS: usize = 131_072;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_ENVELOPES: usize = 524_288;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_ROUTES: usize = 262_144;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_SIGNER_SETS: usize = 65_536;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BATCHES: usize = 262_144;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_SPONSORSHIPS: usize = 262_144;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_REORG_GUARDS: usize = 131_072;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_DISPUTES: usize = 131_072;
pub const MONERO_PRIVATE_CHANNEL_BATCHER_MAX_EVENTS: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateChannelLane {
    Payment,
    TokenTransfer,
    DefiIntent,
    ContractCall,
    LiquidityRebalance,
    FastExit,
    Emergency,
}

impl PrivateChannelLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::TokenTransfer => "token_transfer",
            Self::DefiIntent => "defi_intent",
            Self::ContractCall => "contract_call",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::FastExit => "fast_exit",
            Self::Emergency => "emergency",
        }
    }

    pub fn priority(self) -> u64 {
        match self {
            Self::Emergency => 100,
            Self::FastExit => 94,
            Self::DefiIntent => 88,
            Self::ContractCall => 84,
            Self::LiquidityRebalance => 78,
            Self::TokenTransfer => 72,
            Self::Payment => 64,
        }
    }

    pub fn default_weight(self) -> u64 {
        match self {
            Self::Payment => 1_200,
            Self::TokenTransfer => 1_500,
            Self::DefiIntent => 3_200,
            Self::ContractCall => 4_000,
            Self::LiquidityRebalance => 2_600,
            Self::FastExit => 2_400,
            Self::Emergency => 5_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelEnvelopeKind {
    Entry,
    Exit,
    Update,
    Netting,
    ReceiptHint,
    WatchtowerHint,
}

impl ChannelEnvelopeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::Exit => "exit",
            Self::Update => "update",
            Self::Netting => "netting",
            Self::ReceiptHint => "receipt_hint",
            Self::WatchtowerHint => "watchtower_hint",
        }
    }

    pub fn ttl_blocks(self, config: &MoneroPrivateChannelBatcherConfig) -> u64 {
        match self {
            Self::Entry => config.entry_ttl_blocks,
            Self::Exit => config.exit_ttl_blocks,
            Self::Update | Self::Netting => config.batch_window_blocks.saturating_mul(6).max(1),
            Self::ReceiptHint => config.receipt_ttl_blocks,
            Self::WatchtowerHint => config.dispute_window_blocks,
        }
    }

    pub fn is_settlement(self) -> bool {
        matches!(self, Self::Entry | Self::Exit | Self::Netting)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Pending,
    Routed,
    Batched,
    Settled,
    Expired,
    Cancelled,
    Disputed,
}

impl EnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Routed => "routed",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Disputed => "disputed",
        }
    }

    pub fn batchable(self) -> bool {
        matches!(self, Self::Pending | Self::Routed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelStatus {
    Opening,
    Active,
    Draining,
    Closed,
    Frozen,
    Disputed,
}

impl ChannelStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Frozen => "frozen",
            Self::Disputed => "disputed",
        }
    }

    pub fn accepts_envelopes(self) -> bool {
        matches!(self, Self::Opening | Self::Active | Self::Draining)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteStatus {
    Proposed,
    Active,
    Saturated,
    Suspended,
    Retired,
}

impl RouteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Active => "active",
            Self::Saturated => "saturated",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Saturated)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSetStatus {
    Candidate,
    Active,
    Rotating,
    Retired,
    Slashed,
}

impl SignerSetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }

    pub fn can_sign(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Open,
    Sealed,
    PqApproved,
    ReorgDelayed,
    Posted,
    Settled,
    Disputed,
    Expired,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::PqApproved => "pq_approved",
            Self::ReorgDelayed => "reorg_delayed",
            Self::Posted => "posted",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn accepts_receipt(self) -> bool {
        matches!(self, Self::Posted | Self::Settled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Reserved,
    Applied,
    Exhausted,
    Revoked,
    Slashed,
}

impl SponsorshipStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }

    pub fn spendable(self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgGuardStatus {
    Pending,
    Armed,
    Mature,
    Triggered,
    Released,
}

impl ReorgGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Armed => "armed",
            Self::Mature => "mature",
            Self::Triggered => "triggered",
            Self::Released => "released",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Published,
    Finalized,
    Disputed,
    Superseded,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeStatus {
    Open,
    EvidenceSubmitted,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl DisputeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceSubmitted => "evidence_submitted",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPrivateChannelBatcherConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub batch_window_blocks: u64,
    pub max_batch_items: u64,
    pub max_batch_weight: u64,
    pub entry_ttl_blocks: u64,
    pub exit_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub dispute_window_blocks: u64,
    pub reorg_finality_blocks: u64,
    pub reorg_safety_margin_blocks: u64,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_ring_size: u64,
    pub target_ring_size: u64,
    pub min_pq_signer_weight: u64,
    pub min_dispute_signer_weight: u64,
    pub base_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub emergency_fee_bps: u64,
    pub fee_floor_piconero: u64,
    pub compression_rebate_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_sponsor_rebate_bps: u64,
    pub sponsor_pool_piconero: u64,
    pub hash_suite: String,
    pub stealth_envelope_scheme: String,
    pub subaddress_route_scheme: String,
    pub pq_signer_scheme: String,
    pub batch_proof_scheme: String,
    pub fee_compression_scheme: String,
    pub sponsorship_scheme: String,
    pub reorg_guard_scheme: String,
    pub receipt_scheme: String,
    pub dispute_scheme: String,
}

impl Default for MoneroPrivateChannelBatcherConfig {
    fn default() -> Self {
        Self::devnet()
    }
}

impl MoneroPrivateChannelBatcherConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_PRIVATE_CHANNEL_BATCHER_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_MONERO_NETWORK.to_string(),
            asset_id: MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_FEE_ASSET_ID.to_string(),
            batch_window_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_BATCH_WINDOW_BLOCKS,
            max_batch_items: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_BATCH_ITEMS,
            max_batch_weight: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_BATCH_WEIGHT,
            entry_ttl_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_ENTRY_TTL_BLOCKS,
            exit_ttl_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_EXIT_TTL_BLOCKS,
            receipt_ttl_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_RECEIPT_TTL_BLOCKS,
            dispute_window_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_DISPUTE_WINDOW_BLOCKS,
            reorg_finality_blocks: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_REORG_FINALITY_BLOCKS,
            reorg_safety_margin_blocks:
                MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_REORG_SAFETY_MARGIN_BLOCKS,
            min_privacy_set_size: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_ring_size: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_RING_SIZE,
            target_ring_size: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_TARGET_RING_SIZE,
            min_pq_signer_weight: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_PQ_SIGNER_WEIGHT,
            min_dispute_signer_weight:
                MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MIN_DISPUTE_SIGNER_WEIGHT,
            base_fee_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_BASE_FEE_BPS,
            fast_fee_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_FAST_FEE_BPS,
            emergency_fee_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_EMERGENCY_FEE_BPS,
            fee_floor_piconero: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_FEE_FLOOR_PICONERO,
            compression_rebate_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_COMPRESSION_REBATE_BPS,
            low_fee_rebate_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_LOW_FEE_REBATE_BPS,
            max_sponsor_rebate_bps: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_MAX_SPONSOR_REBATE_BPS,
            sponsor_pool_piconero: MONERO_PRIVATE_CHANNEL_BATCHER_DEFAULT_SPONSOR_POOL_PICONERO,
            hash_suite: MONERO_PRIVATE_CHANNEL_BATCHER_HASH_SUITE.to_string(),
            stealth_envelope_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_STEALTH_ENVELOPE_SCHEME
                .to_string(),
            subaddress_route_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_SUBADDRESS_ROUTE_SCHEME
                .to_string(),
            pq_signer_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_PQ_SIGNER_SCHEME.to_string(),
            batch_proof_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_BATCH_PROOF_SCHEME.to_string(),
            fee_compression_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_FEE_COMPRESSION_SCHEME
                .to_string(),
            sponsorship_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_SPONSORSHIP_SCHEME.to_string(),
            reorg_guard_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_REORG_GUARD_SCHEME.to_string(),
            receipt_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_RECEIPT_SCHEME.to_string(),
            dispute_scheme: MONERO_PRIVATE_CHANNEL_BATCHER_DISPUTE_SCHEME.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "batch_window_blocks": self.batch_window_blocks,
            "max_batch_items": self.max_batch_items,
            "max_batch_weight": self.max_batch_weight,
            "entry_ttl_blocks": self.entry_ttl_blocks,
            "exit_ttl_blocks": self.exit_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "dispute_window_blocks": self.dispute_window_blocks,
            "reorg_finality_blocks": self.reorg_finality_blocks,
            "reorg_safety_margin_blocks": self.reorg_safety_margin_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_privacy_set_size": self.target_privacy_set_size,
            "min_ring_size": self.min_ring_size,
            "target_ring_size": self.target_ring_size,
            "min_pq_signer_weight": self.min_pq_signer_weight,
            "min_dispute_signer_weight": self.min_dispute_signer_weight,
            "base_fee_bps": self.base_fee_bps,
            "fast_fee_bps": self.fast_fee_bps,
            "emergency_fee_bps": self.emergency_fee_bps,
            "fee_floor_piconero": self.fee_floor_piconero,
            "compression_rebate_bps": self.compression_rebate_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "sponsor_pool_piconero": self.sponsor_pool_piconero,
            "hash_suite": self.hash_suite,
            "stealth_envelope_scheme": self.stealth_envelope_scheme,
            "subaddress_route_scheme": self.subaddress_route_scheme,
            "pq_signer_scheme": self.pq_signer_scheme,
            "batch_proof_scheme": self.batch_proof_scheme,
            "fee_compression_scheme": self.fee_compression_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "reorg_guard_scheme": self.reorg_guard_scheme,
            "receipt_scheme": self.receipt_scheme,
            "dispute_scheme": self.dispute_scheme,
        })
    }

    pub fn config_root(&self) -> String {
        monero_private_channel_batcher_payload_root("CONFIG", &self.public_record())
    }

    pub fn fee_for_lane(&self, lane: PrivateChannelLane, gross_units: u64, sponsored: bool) -> u64 {
        let fee_bps = match lane {
            PrivateChannelLane::FastExit => self.fast_fee_bps,
            PrivateChannelLane::Emergency => self.emergency_fee_bps,
            _ => self.base_fee_bps,
        };
        let gross_fee =
            gross_units.saturating_mul(fee_bps) / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS;
        let compressed = gross_fee.saturating_sub(
            gross_fee.saturating_mul(self.compression_rebate_bps)
                / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS,
        );
        let sponsored_fee = if sponsored {
            compressed.saturating_sub(
                compressed.saturating_mul(self.low_fee_rebate_bps)
                    / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS,
            )
        } else {
            compressed
        };
        sponsored_fee.max(self.fee_floor_piconero)
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        if self.protocol_version != MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION {
            return Err("monero private channel batcher protocol version mismatch".to_string());
        }
        if self.schema_version != MONERO_PRIVATE_CHANNEL_BATCHER_SCHEMA_VERSION {
            return Err("monero private channel batcher schema version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("monero private channel batcher chain id mismatch".to_string());
        }
        if self.monero_network.is_empty()
            || self.asset_id.is_empty()
            || self.fee_asset_id.is_empty()
        {
            return Err(
                "monero private channel batcher network and asset ids must be set".to_string(),
            );
        }
        if self.batch_window_blocks == 0
            || self.max_batch_items == 0
            || self.max_batch_weight == 0
            || self.entry_ttl_blocks == 0
            || self.exit_ttl_blocks == 0
            || self.receipt_ttl_blocks == 0
            || self.dispute_window_blocks == 0
            || self.reorg_finality_blocks == 0
        {
            return Err(
                "monero private channel batcher time and capacity limits must be positive"
                    .to_string(),
            );
        }
        if self.target_privacy_set_size < self.min_privacy_set_size
            || self.target_ring_size < self.min_ring_size
        {
            return Err(
                "monero private channel batcher target privacy parameters must exceed minimums"
                    .to_string(),
            );
        }
        if self.min_pq_signer_weight == 0 || self.min_dispute_signer_weight == 0 {
            return Err(
                "monero private channel batcher pq signer weights must be positive".to_string(),
            );
        }
        if self.base_fee_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
            || self.fast_fee_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
            || self.emergency_fee_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
            || self.compression_rebate_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
            || self.low_fee_rebate_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
            || self.max_sponsor_rebate_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS
        {
            return Err("monero private channel batcher bps values exceed max".to_string());
        }
        if self.hash_suite.is_empty()
            || self.stealth_envelope_scheme.is_empty()
            || self.subaddress_route_scheme.is_empty()
            || self.pq_signer_scheme.is_empty()
            || self.batch_proof_scheme.is_empty()
            || self.fee_compression_scheme.is_empty()
            || self.sponsorship_scheme.is_empty()
            || self.reorg_guard_scheme.is_empty()
            || self.receipt_scheme.is_empty()
            || self.dispute_scheme.is_empty()
        {
            return Err(
                "monero private channel batcher scheme labels must be populated".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateChannelDescriptor {
    pub channel_id: String,
    pub lane: PrivateChannelLane,
    pub status: ChannelStatus,
    pub owner_commitment: String,
    pub counterparty_commitment: String,
    pub channel_nullifier: String,
    pub balance_bucket_root: String,
    pub channel_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub total_entry_units: u64,
    pub total_exit_units: u64,
    pub pending_envelope_count: u64,
}

impl PrivateChannelDescriptor {
    pub fn new(
        label: &str,
        lane: PrivateChannelLane,
        owner_commitment: &str,
        counterparty_commitment: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let channel_nullifier = monero_private_channel_batcher_hash(
            "CHANNEL-NULLIFIER",
            &[
                HashPart::Str(label),
                HashPart::Str(owner_commitment),
                HashPart::Str(counterparty_commitment),
                HashPart::Int(opened_at_height as i128),
            ],
        );
        let balance_bucket_root = merkle_root("MONERO-PRIVATE-CHANNEL-BALANCE-BUCKET", &[]);
        let channel_policy_root = monero_private_channel_batcher_hash(
            "CHANNEL-POLICY",
            &[
                HashPart::Str(lane.as_str()),
                HashPart::Str(&balance_bucket_root),
                HashPart::Int(ttl_blocks as i128),
            ],
        );
        let channel_id = monero_private_channel_batcher_hash(
            "CHANNEL-ID",
            &[
                HashPart::Str(label),
                HashPart::Str(lane.as_str()),
                HashPart::Str(&channel_nullifier),
                HashPart::Str(&channel_policy_root),
            ],
        );
        Self {
            channel_id,
            lane,
            status: ChannelStatus::Opening,
            owner_commitment: owner_commitment.to_string(),
            counterparty_commitment: counterparty_commitment.to_string(),
            channel_nullifier,
            balance_bucket_root,
            channel_policy_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            total_entry_units: 0,
            total_exit_units: 0,
            pending_envelope_count: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "channel_id": self.channel_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "counterparty_commitment": self.counterparty_commitment,
            "channel_nullifier": self.channel_nullifier,
            "balance_bucket_root": self.balance_bucket_root,
            "channel_policy_root": self.channel_policy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "total_entry_units": self.total_entry_units,
            "total_exit_units": self.total_exit_units,
            "pending_envelope_count": self.pending_envelope_count,
        })
    }

    pub fn channel_root(&self) -> String {
        monero_private_channel_batcher_payload_root("CHANNEL", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("channel_id", &self.channel_id)?;
        validate_nonempty("owner_commitment", &self.owner_commitment)?;
        validate_nonempty("counterparty_commitment", &self.counterparty_commitment)?;
        validate_nonempty("channel_nullifier", &self.channel_nullifier)?;
        validate_nonempty("balance_bucket_root", &self.balance_bucket_root)?;
        validate_nonempty("channel_policy_root", &self.channel_policy_root)?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("private channel expires before it opens".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthChannelEnvelope {
    pub envelope_id: String,
    pub channel_id: String,
    pub lane: PrivateChannelLane,
    pub kind: ChannelEnvelopeKind,
    pub status: EnvelopeStatus,
    pub stealth_address_commitment: String,
    pub one_time_key_commitment: String,
    pub view_tag_commitment: String,
    pub amount_bucket: u64,
    pub asset_id: String,
    pub encrypted_payload_root: String,
    pub payload_ciphertext_hash: String,
    pub route_commitment_id: String,
    pub fee_payer_nullifier: String,
    pub sponsor_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub envelope_weight: u64,
    pub privacy_set_size: u64,
    pub ring_size: u64,
    pub sequence: u64,
}

impl StealthChannelEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        channel_id: &str,
        lane: PrivateChannelLane,
        kind: ChannelEnvelopeKind,
        asset_id: &str,
        amount_bucket: u64,
        route_commitment_id: &str,
        submitted_at_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
        sequence: u64,
    ) -> Self {
        let stealth_address_commitment =
            deterministic_commitment("STEALTH-ADDRESS", &[label, channel_id, kind.as_str()]);
        let one_time_key_commitment =
            deterministic_commitment("ONE-TIME-KEY", &[label, channel_id, lane.as_str()]);
        let view_tag_commitment =
            deterministic_commitment("VIEW-TAG", &[label, channel_id, &sequence.to_string()]);
        let encrypted_payload_root = monero_private_channel_batcher_hash(
            "ENCRYPTED-PAYLOAD",
            &[
                HashPart::Str(label),
                HashPart::Str(channel_id),
                HashPart::Str(kind.as_str()),
                HashPart::Int(amount_bucket as i128),
                HashPart::Str(route_commitment_id),
            ],
        );
        let payload_ciphertext_hash = monero_private_channel_batcher_hash(
            "PAYLOAD-CIPHERTEXT",
            &[
                HashPart::Str(&encrypted_payload_root),
                HashPart::Str(&one_time_key_commitment),
                HashPart::Str(&view_tag_commitment),
            ],
        );
        let fee_payer_nullifier =
            deterministic_commitment("FEE-PAYER", &[label, channel_id, route_commitment_id]);
        let envelope_id = channel_envelope_id(
            channel_id,
            kind,
            &stealth_address_commitment,
            &payload_ciphertext_hash,
            submitted_at_height,
            sequence,
        );
        Self {
            envelope_id,
            channel_id: channel_id.to_string(),
            lane,
            kind,
            status: EnvelopeStatus::Pending,
            stealth_address_commitment,
            one_time_key_commitment,
            view_tag_commitment,
            amount_bucket,
            asset_id: asset_id.to_string(),
            encrypted_payload_root,
            payload_ciphertext_hash,
            route_commitment_id: route_commitment_id.to_string(),
            fee_payer_nullifier,
            sponsor_id: None,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(kind.ttl_blocks(config)),
            envelope_weight: lane.default_weight(),
            privacy_set_size: config.target_privacy_set_size,
            ring_size: config.target_ring_size,
            sequence,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "envelope_id": self.envelope_id,
            "channel_id": self.channel_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "stealth_address_commitment": self.stealth_address_commitment,
            "one_time_key_commitment": self.one_time_key_commitment,
            "view_tag_commitment": self.view_tag_commitment,
            "amount_bucket": self.amount_bucket,
            "asset_id": self.asset_id,
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_ciphertext_hash": self.payload_ciphertext_hash,
            "route_commitment_id": self.route_commitment_id,
            "fee_payer_nullifier": self.fee_payer_nullifier,
            "sponsor_id": self.sponsor_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "envelope_weight": self.envelope_weight,
            "privacy_set_size": self.privacy_set_size,
            "ring_size": self.ring_size,
            "sequence": self.sequence,
        })
    }

    pub fn envelope_root(&self) -> String {
        monero_private_channel_batcher_payload_root(
            "STEALTH-CHANNEL-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(
        &self,
        config: &MoneroPrivateChannelBatcherConfig,
    ) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("envelope_id", &self.envelope_id)?;
        validate_nonempty("channel_id", &self.channel_id)?;
        validate_nonempty(
            "stealth_address_commitment",
            &self.stealth_address_commitment,
        )?;
        validate_nonempty("one_time_key_commitment", &self.one_time_key_commitment)?;
        validate_nonempty("view_tag_commitment", &self.view_tag_commitment)?;
        validate_nonempty("asset_id", &self.asset_id)?;
        validate_nonempty("encrypted_payload_root", &self.encrypted_payload_root)?;
        validate_nonempty("payload_ciphertext_hash", &self.payload_ciphertext_hash)?;
        validate_nonempty("route_commitment_id", &self.route_commitment_id)?;
        validate_nonempty("fee_payer_nullifier", &self.fee_payer_nullifier)?;
        if self.submitted_at_height >= self.expires_at_height {
            return Err("stealth channel envelope expires before submission".to_string());
        }
        if self.envelope_weight == 0 {
            return Err("stealth channel envelope weight must be positive".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size
            || self.ring_size < config.min_ring_size
        {
            return Err(
                "stealth channel envelope privacy set or ring size below config minimum"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressRouteCommitment {
    pub route_id: String,
    pub lane: PrivateChannelLane,
    pub status: RouteStatus,
    pub subaddress_commitment_root: String,
    pub route_blinding_root: String,
    pub watchtower_committee_root: String,
    pub liquidity_hint_root: String,
    pub max_amount_bucket: u64,
    pub min_privacy_set_size: u64,
    pub congestion_score: u64,
    pub opened_at_height: u64,
    pub last_rotated_height: u64,
    pub route_nonce: u64,
}

impl SubaddressRouteCommitment {
    pub fn new(
        label: &str,
        lane: PrivateChannelLane,
        max_amount_bucket: u64,
        opened_at_height: u64,
        min_privacy_set_size: u64,
        route_nonce: u64,
    ) -> Self {
        let subaddress_commitment_root =
            deterministic_commitment("SUBADDRESS-ROOT", &[label, lane.as_str()]);
        let route_blinding_root =
            deterministic_commitment("ROUTE-BLINDING", &[label, &route_nonce.to_string()]);
        let watchtower_committee_root =
            deterministic_commitment("WATCHTOWER-COMMITTEE", &[label, lane.as_str()]);
        let liquidity_hint_root =
            deterministic_commitment("LIQUIDITY-HINT", &[label, &max_amount_bucket.to_string()]);
        let route_id = subaddress_route_id(
            lane,
            &subaddress_commitment_root,
            &route_blinding_root,
            opened_at_height,
            route_nonce,
        );
        Self {
            route_id,
            lane,
            status: RouteStatus::Active,
            subaddress_commitment_root,
            route_blinding_root,
            watchtower_committee_root,
            liquidity_hint_root,
            max_amount_bucket,
            min_privacy_set_size,
            congestion_score: 0,
            opened_at_height,
            last_rotated_height: opened_at_height,
            route_nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "route_id": self.route_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "subaddress_commitment_root": self.subaddress_commitment_root,
            "route_blinding_root": self.route_blinding_root,
            "watchtower_committee_root": self.watchtower_committee_root,
            "liquidity_hint_root": self.liquidity_hint_root,
            "max_amount_bucket": self.max_amount_bucket,
            "min_privacy_set_size": self.min_privacy_set_size,
            "congestion_score": self.congestion_score,
            "opened_at_height": self.opened_at_height,
            "last_rotated_height": self.last_rotated_height,
            "route_nonce": self.route_nonce,
        })
    }

    pub fn route_root(&self) -> String {
        monero_private_channel_batcher_payload_root("SUBADDRESS-ROUTE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("route_id", &self.route_id)?;
        validate_nonempty(
            "subaddress_commitment_root",
            &self.subaddress_commitment_root,
        )?;
        validate_nonempty("route_blinding_root", &self.route_blinding_root)?;
        validate_nonempty("watchtower_committee_root", &self.watchtower_committee_root)?;
        validate_nonempty("liquidity_hint_root", &self.liquidity_hint_root)?;
        if self.max_amount_bucket == 0 || self.min_privacy_set_size == 0 {
            return Err("subaddress route amount and privacy limits must be positive".to_string());
        }
        if self.last_rotated_height < self.opened_at_height {
            return Err("subaddress route rotation height precedes open height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerMember {
    pub signer_id: String,
    pub pq_public_key_commitment: String,
    pub backup_key_commitment: String,
    pub weight: u64,
    pub joined_at_height: u64,
}

impl PqSignerMember {
    pub fn new(label: &str, joined_at_height: u64, weight: u64) -> Self {
        let pq_public_key_commitment = deterministic_commitment("PQ-PUBLIC-KEY", &[label]);
        let backup_key_commitment = deterministic_commitment("PQ-BACKUP-KEY", &[label]);
        let signer_id = monero_private_channel_batcher_hash(
            "PQ-SIGNER-ID",
            &[
                HashPart::Str(label),
                HashPart::Str(&pq_public_key_commitment),
                HashPart::Int(joined_at_height as i128),
            ],
        );
        Self {
            signer_id,
            pq_public_key_commitment,
            backup_key_commitment,
            weight,
            joined_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signer_id": self.signer_id,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "backup_key_commitment": self.backup_key_commitment,
            "weight": self.weight,
            "joined_at_height": self.joined_at_height,
        })
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("signer_id", &self.signer_id)?;
        validate_nonempty("pq_public_key_commitment", &self.pq_public_key_commitment)?;
        validate_nonempty("backup_key_commitment", &self.backup_key_commitment)?;
        if self.weight == 0 {
            return Err("pq signer member weight must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSignerSet {
    pub signer_set_id: String,
    pub status: SignerSetStatus,
    pub epoch: u64,
    pub threshold_weight: u64,
    pub total_weight: u64,
    pub members: BTreeMap<String, PqSignerMember>,
    pub aggregate_key_commitment: String,
    pub rotation_authority_root: String,
    pub activated_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSignerSet {
    pub fn new(
        label: &str,
        epoch: u64,
        threshold_weight: u64,
        members: Vec<PqSignerMember>,
        activated_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let mut member_map = BTreeMap::new();
        let mut total_weight = 0_u64;
        for member in members {
            total_weight = total_weight.saturating_add(member.weight);
            member_map.insert(member.signer_id.clone(), member);
        }
        let member_records = member_map
            .values()
            .map(PqSignerMember::public_record)
            .collect::<Vec<_>>();
        let aggregate_key_commitment =
            merkle_root("MONERO-PRIVATE-CHANNEL-PQ-SIGNER", &member_records);
        let rotation_authority_root =
            deterministic_commitment("PQ-SIGNER-ROTATION", &[label, &epoch.to_string()]);
        let signer_set_id = pq_signer_set_id(
            epoch,
            threshold_weight,
            &aggregate_key_commitment,
            activated_at_height,
        );
        Self {
            signer_set_id,
            status: SignerSetStatus::Active,
            epoch,
            threshold_weight,
            total_weight,
            members: member_map,
            aggregate_key_commitment,
            rotation_authority_root,
            activated_at_height,
            expires_at_height: activated_at_height.saturating_add(ttl_blocks),
        }
    }

    pub fn public_record(&self) -> Value {
        let members = self
            .members
            .values()
            .map(PqSignerMember::public_record)
            .collect::<Vec<_>>();
        json!({
            "chain_id": CHAIN_ID,
            "signer_set_id": self.signer_set_id,
            "status": self.status.as_str(),
            "epoch": self.epoch,
            "threshold_weight": self.threshold_weight,
            "total_weight": self.total_weight,
            "member_root": merkle_root("MONERO-PRIVATE-CHANNEL-PQ-SIGNER", &members),
            "members": members,
            "aggregate_key_commitment": self.aggregate_key_commitment,
            "rotation_authority_root": self.rotation_authority_root,
            "activated_at_height": self.activated_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn signer_set_root(&self) -> String {
        monero_private_channel_batcher_payload_root("PQ-SIGNER-SET", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &MoneroPrivateChannelBatcherConfig,
    ) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("signer_set_id", &self.signer_set_id)?;
        validate_nonempty("aggregate_key_commitment", &self.aggregate_key_commitment)?;
        validate_nonempty("rotation_authority_root", &self.rotation_authority_root)?;
        if self.threshold_weight < config.min_pq_signer_weight {
            return Err("pq signer set threshold below configured minimum".to_string());
        }
        if self.threshold_weight == 0 || self.threshold_weight > self.total_weight {
            return Err(
                "pq signer set threshold must be positive and within total weight".to_string(),
            );
        }
        if self.members.is_empty() {
            return Err("pq signer set must contain members".to_string());
        }
        let mut computed_weight = 0_u64;
        for member in self.members.values() {
            member.validate()?;
            computed_weight = computed_weight.saturating_add(member.weight);
        }
        if computed_weight != self.total_weight {
            return Err("pq signer set total weight mismatch".to_string());
        }
        if self.activated_at_height >= self.expires_at_height {
            return Err("pq signer set expires before activation".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateChannelBatch {
    pub batch_id: String,
    pub lane: PrivateChannelLane,
    pub status: BatchStatus,
    pub signer_set_id: String,
    pub envelope_ids: BTreeSet<String>,
    pub entry_envelope_count: u64,
    pub exit_envelope_count: u64,
    pub netting_envelope_count: u64,
    pub envelope_root: String,
    pub route_root: String,
    pub pq_signature_root: String,
    pub fee_compression_root: String,
    pub reorg_guard_id: String,
    pub gross_amount_units: u64,
    pub gross_fee_piconero: u64,
    pub compressed_fee_piconero: u64,
    pub sponsored_fee_piconero: u64,
    pub batch_weight: u64,
    pub opened_at_height: u64,
    pub sealed_at_height: u64,
    pub settlement_height: u64,
    pub batch_nonce: u64,
}

impl PrivateChannelBatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        lane: PrivateChannelLane,
        signer_set_id: &str,
        envelopes: &[StealthChannelEnvelope],
        route_root: &str,
        opened_at_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
        batch_nonce: u64,
    ) -> Self {
        let mut envelope_ids = BTreeSet::new();
        let mut records = Vec::new();
        let mut entry_envelope_count = 0_u64;
        let mut exit_envelope_count = 0_u64;
        let mut netting_envelope_count = 0_u64;
        let mut gross_amount_units = 0_u64;
        let mut batch_weight = 0_u64;
        let mut sponsored = false;
        for envelope in envelopes {
            envelope_ids.insert(envelope.envelope_id.clone());
            records.push(envelope.public_record());
            gross_amount_units = gross_amount_units.saturating_add(envelope.amount_bucket);
            batch_weight = batch_weight.saturating_add(envelope.envelope_weight);
            sponsored = sponsored || envelope.sponsor_id.is_some();
            match envelope.kind {
                ChannelEnvelopeKind::Entry => {
                    entry_envelope_count = entry_envelope_count.saturating_add(1)
                }
                ChannelEnvelopeKind::Exit => {
                    exit_envelope_count = exit_envelope_count.saturating_add(1)
                }
                ChannelEnvelopeKind::Netting => {
                    netting_envelope_count = netting_envelope_count.saturating_add(1)
                }
                _ => {}
            }
        }
        let envelope_root = merkle_root("MONERO-PRIVATE-CHANNEL-BATCH-ENVELOPE", &records);
        let gross_fee_piconero = gross_amount_units
            .saturating_mul(config.base_fee_bps.max(lane.priority() / 10))
            / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS;
        let compressed_fee_piconero = gross_fee_piconero.saturating_sub(
            gross_fee_piconero.saturating_mul(config.compression_rebate_bps)
                / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS,
        );
        let sponsored_fee_piconero = if sponsored {
            compressed_fee_piconero.saturating_sub(
                compressed_fee_piconero.saturating_mul(config.low_fee_rebate_bps)
                    / MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS,
            )
        } else {
            compressed_fee_piconero
        }
        .max(config.fee_floor_piconero);
        let fee_compression_root = fee_compression_commitment(
            gross_fee_piconero,
            compressed_fee_piconero,
            sponsored_fee_piconero,
            batch_weight,
        );
        let pq_signature_root = deterministic_commitment(
            "BATCH-PQ-SIGNATURE",
            &[label, signer_set_id, &envelope_root],
        );
        let reorg_guard_id =
            deterministic_commitment("BATCH-REORG-GUARD", &[label, &opened_at_height.to_string()]);
        let settlement_height = opened_at_height
            .saturating_add(config.batch_window_blocks)
            .saturating_add(config.reorg_finality_blocks)
            .saturating_add(config.reorg_safety_margin_blocks);
        let sealed_at_height = opened_at_height.saturating_add(config.batch_window_blocks);
        let batch_id = private_channel_batch_id(
            lane,
            signer_set_id,
            &envelope_root,
            opened_at_height,
            batch_nonce,
        );
        Self {
            batch_id,
            lane,
            status: BatchStatus::Open,
            signer_set_id: signer_set_id.to_string(),
            envelope_ids,
            entry_envelope_count,
            exit_envelope_count,
            netting_envelope_count,
            envelope_root,
            route_root: route_root.to_string(),
            pq_signature_root,
            fee_compression_root,
            reorg_guard_id,
            gross_amount_units,
            gross_fee_piconero,
            compressed_fee_piconero,
            sponsored_fee_piconero,
            batch_weight,
            opened_at_height,
            sealed_at_height,
            settlement_height,
            batch_nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "batch_id": self.batch_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "signer_set_id": self.signer_set_id,
            "envelope_ids": self.envelope_ids.iter().cloned().collect::<Vec<_>>(),
            "entry_envelope_count": self.entry_envelope_count,
            "exit_envelope_count": self.exit_envelope_count,
            "netting_envelope_count": self.netting_envelope_count,
            "envelope_root": self.envelope_root,
            "route_root": self.route_root,
            "pq_signature_root": self.pq_signature_root,
            "fee_compression_root": self.fee_compression_root,
            "reorg_guard_id": self.reorg_guard_id,
            "gross_amount_units": self.gross_amount_units,
            "gross_fee_piconero": self.gross_fee_piconero,
            "compressed_fee_piconero": self.compressed_fee_piconero,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "batch_weight": self.batch_weight,
            "opened_at_height": self.opened_at_height,
            "sealed_at_height": self.sealed_at_height,
            "settlement_height": self.settlement_height,
            "batch_nonce": self.batch_nonce,
        })
    }

    pub fn batch_root(&self) -> String {
        monero_private_channel_batcher_payload_root("PRIVATE-CHANNEL-BATCH", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &MoneroPrivateChannelBatcherConfig,
    ) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("batch_id", &self.batch_id)?;
        validate_nonempty("signer_set_id", &self.signer_set_id)?;
        validate_nonempty("envelope_root", &self.envelope_root)?;
        validate_nonempty("route_root", &self.route_root)?;
        validate_nonempty("pq_signature_root", &self.pq_signature_root)?;
        validate_nonempty("fee_compression_root", &self.fee_compression_root)?;
        validate_nonempty("reorg_guard_id", &self.reorg_guard_id)?;
        if self.envelope_ids.is_empty() {
            return Err("private channel batch must contain envelopes".to_string());
        }
        if self.envelope_ids.len() as u64 > config.max_batch_items {
            return Err("private channel batch exceeds max items".to_string());
        }
        if self.batch_weight == 0 || self.batch_weight > config.max_batch_weight {
            return Err("private channel batch weight invalid".to_string());
        }
        if self.compressed_fee_piconero > self.gross_fee_piconero {
            return Err("private channel batch compressed fee exceeds gross fee".to_string());
        }
        if self.sponsored_fee_piconero > self.compressed_fee_piconero.max(config.fee_floor_piconero)
        {
            return Err("private channel batch sponsored fee exceeds compressed fee".to_string());
        }
        if self.opened_at_height > self.sealed_at_height
            || self.sealed_at_height > self.settlement_height
        {
            return Err("private channel batch heights are not monotonic".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorship {
    pub sponsor_id: String,
    pub status: SponsorshipStatus,
    pub sponsor_commitment: String,
    pub budget_root: String,
    pub lane: PrivateChannelLane,
    pub max_rebate_bps: u64,
    pub reserved_piconero: u64,
    pub spent_piconero: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub sponsor_nonce: u64,
}

impl FeeSponsorship {
    pub fn new(
        label: &str,
        lane: PrivateChannelLane,
        reserved_piconero: u64,
        valid_from_height: u64,
        valid_until_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
        sponsor_nonce: u64,
    ) -> Self {
        let sponsor_commitment = deterministic_commitment("SPONSOR", &[label, lane.as_str()]);
        let budget_root = deterministic_commitment(
            "SPONSOR-BUDGET",
            &[
                label,
                &reserved_piconero.to_string(),
                &sponsor_nonce.to_string(),
            ],
        );
        let sponsor_id = sponsorship_id(
            &sponsor_commitment,
            lane,
            &budget_root,
            valid_from_height,
            sponsor_nonce,
        );
        Self {
            sponsor_id,
            status: SponsorshipStatus::Reserved,
            sponsor_commitment,
            budget_root,
            lane,
            max_rebate_bps: config.max_sponsor_rebate_bps,
            reserved_piconero,
            spent_piconero: 0,
            valid_from_height,
            valid_until_height,
            sponsor_nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "sponsor_commitment": self.sponsor_commitment,
            "budget_root": self.budget_root,
            "lane": self.lane.as_str(),
            "max_rebate_bps": self.max_rebate_bps,
            "reserved_piconero": self.reserved_piconero,
            "spent_piconero": self.spent_piconero,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "sponsor_nonce": self.sponsor_nonce,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        monero_private_channel_batcher_payload_root("FEE-SPONSORSHIP", &self.public_record())
    }

    pub fn remaining_piconero(&self) -> u64 {
        self.reserved_piconero.saturating_sub(self.spent_piconero)
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("sponsor_id", &self.sponsor_id)?;
        validate_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        validate_nonempty("budget_root", &self.budget_root)?;
        if self.valid_from_height >= self.valid_until_height {
            return Err("fee sponsorship expires before activation".to_string());
        }
        if self.max_rebate_bps > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BPS {
            return Err("fee sponsorship rebate exceeds max bps".to_string());
        }
        if self.spent_piconero > self.reserved_piconero {
            return Err("fee sponsorship spent budget exceeds reserved budget".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgGuard {
    pub guard_id: String,
    pub status: ReorgGuardStatus,
    pub batch_id: String,
    pub monero_anchor_txid: String,
    pub anchor_height: u64,
    pub l2_observed_height: u64,
    pub release_height: u64,
    pub reorg_depth_limit: u64,
    pub anchor_block_hash_root: String,
    pub delayed_receipt_root: String,
}

impl ReorgGuard {
    pub fn new(
        label: &str,
        batch_id: &str,
        monero_anchor_txid: &str,
        anchor_height: u64,
        l2_observed_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
    ) -> Self {
        let anchor_block_hash_root =
            deterministic_commitment("MONERO-ANCHOR-BLOCK", &[label, monero_anchor_txid]);
        let delayed_receipt_root = merkle_root("MONERO-PRIVATE-CHANNEL-DELAYED-RECEIPT", &[]);
        let release_height = l2_observed_height
            .saturating_add(config.reorg_finality_blocks)
            .saturating_add(config.reorg_safety_margin_blocks);
        let guard_id = reorg_guard_id(
            batch_id,
            monero_anchor_txid,
            anchor_height,
            l2_observed_height,
            &anchor_block_hash_root,
        );
        Self {
            guard_id,
            status: ReorgGuardStatus::Armed,
            batch_id: batch_id.to_string(),
            monero_anchor_txid: monero_anchor_txid.to_string(),
            anchor_height,
            l2_observed_height,
            release_height,
            reorg_depth_limit: config.reorg_finality_blocks,
            anchor_block_hash_root,
            delayed_receipt_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "guard_id": self.guard_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "monero_anchor_txid": self.monero_anchor_txid,
            "anchor_height": self.anchor_height,
            "l2_observed_height": self.l2_observed_height,
            "release_height": self.release_height,
            "reorg_depth_limit": self.reorg_depth_limit,
            "anchor_block_hash_root": self.anchor_block_hash_root,
            "delayed_receipt_root": self.delayed_receipt_root,
        })
    }

    pub fn guard_root(&self) -> String {
        monero_private_channel_batcher_payload_root("REORG-GUARD", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("guard_id", &self.guard_id)?;
        validate_nonempty("batch_id", &self.batch_id)?;
        validate_nonempty("monero_anchor_txid", &self.monero_anchor_txid)?;
        validate_nonempty("anchor_block_hash_root", &self.anchor_block_hash_root)?;
        validate_nonempty("delayed_receipt_root", &self.delayed_receipt_root)?;
        if self.release_height < self.l2_observed_height {
            return Err("reorg guard release height precedes observation".to_string());
        }
        if self.reorg_depth_limit == 0 {
            return Err("reorg guard depth limit must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub receipt_id: String,
    pub status: ReceiptStatus,
    pub batch_id: String,
    pub channel_root_after: String,
    pub envelope_root_after: String,
    pub fee_receipt_root: String,
    pub reorg_guard_id: String,
    pub monero_anchor_txid: String,
    pub settled_at_height: u64,
    pub finalizable_at_height: u64,
    pub receipt_nonce: u64,
}

impl BatchReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        batch_id: &str,
        channel_root_after: &str,
        envelope_root_after: &str,
        fee_receipt_root: &str,
        reorg_guard_id: &str,
        monero_anchor_txid: &str,
        settled_at_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
        receipt_nonce: u64,
    ) -> Self {
        let finalizable_at_height = settled_at_height.saturating_add(config.receipt_ttl_blocks);
        let receipt_id = receipt_id(
            batch_id,
            channel_root_after,
            envelope_root_after,
            reorg_guard_id,
            settled_at_height,
            receipt_nonce,
        );
        Self {
            receipt_id,
            status: ReceiptStatus::Published,
            batch_id: batch_id.to_string(),
            channel_root_after: channel_root_after.to_string(),
            envelope_root_after: envelope_root_after.to_string(),
            fee_receipt_root: fee_receipt_root.to_string(),
            reorg_guard_id: reorg_guard_id.to_string(),
            monero_anchor_txid: monero_anchor_txid.to_string(),
            settled_at_height,
            finalizable_at_height,
            receipt_nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "batch_id": self.batch_id,
            "channel_root_after": self.channel_root_after,
            "envelope_root_after": self.envelope_root_after,
            "fee_receipt_root": self.fee_receipt_root,
            "reorg_guard_id": self.reorg_guard_id,
            "monero_anchor_txid": self.monero_anchor_txid,
            "settled_at_height": self.settled_at_height,
            "finalizable_at_height": self.finalizable_at_height,
            "receipt_nonce": self.receipt_nonce,
        })
    }

    pub fn receipt_root(&self) -> String {
        monero_private_channel_batcher_payload_root("BATCH-RECEIPT", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("receipt_id", &self.receipt_id)?;
        validate_nonempty("batch_id", &self.batch_id)?;
        validate_nonempty("channel_root_after", &self.channel_root_after)?;
        validate_nonempty("envelope_root_after", &self.envelope_root_after)?;
        validate_nonempty("fee_receipt_root", &self.fee_receipt_root)?;
        validate_nonempty("reorg_guard_id", &self.reorg_guard_id)?;
        validate_nonempty("monero_anchor_txid", &self.monero_anchor_txid)?;
        if self.finalizable_at_height < self.settled_at_height {
            return Err("batch receipt finalizable height precedes settlement".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisputeEvidence {
    pub dispute_id: String,
    pub status: DisputeStatus,
    pub target_kind: String,
    pub target_id: String,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub conflicting_state_root: String,
    pub pq_attestation_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub slash_amount_piconero: u64,
    pub dispute_nonce: u64,
}

impl DisputeEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        label: &str,
        target_kind: &str,
        target_id: &str,
        conflicting_state_root: &str,
        opened_at_height: u64,
        config: &MoneroPrivateChannelBatcherConfig,
        slash_amount_piconero: u64,
        dispute_nonce: u64,
    ) -> Self {
        let reporter_commitment = deterministic_commitment("DISPUTE-REPORTER", &[label, target_id]);
        let evidence_root = deterministic_commitment(
            "DISPUTE-EVIDENCE",
            &[label, target_kind, target_id, conflicting_state_root],
        );
        let pq_attestation_root =
            deterministic_commitment("DISPUTE-PQ-ATTESTATION", &[label, &evidence_root]);
        let dispute_id = dispute_id(
            target_kind,
            target_id,
            &evidence_root,
            opened_at_height,
            dispute_nonce,
        );
        Self {
            dispute_id,
            status: DisputeStatus::Open,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            reporter_commitment,
            evidence_root,
            conflicting_state_root: conflicting_state_root.to_string(),
            pq_attestation_root,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(config.dispute_window_blocks),
            slash_amount_piconero,
            dispute_nonce,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "dispute_id": self.dispute_id,
            "status": self.status.as_str(),
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "reporter_commitment": self.reporter_commitment,
            "evidence_root": self.evidence_root,
            "conflicting_state_root": self.conflicting_state_root,
            "pq_attestation_root": self.pq_attestation_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "slash_amount_piconero": self.slash_amount_piconero,
            "dispute_nonce": self.dispute_nonce,
        })
    }

    pub fn dispute_root(&self) -> String {
        monero_private_channel_batcher_payload_root("DISPUTE-EVIDENCE", &self.public_record())
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        validate_nonempty("dispute_id", &self.dispute_id)?;
        validate_nonempty("target_kind", &self.target_kind)?;
        validate_nonempty("target_id", &self.target_id)?;
        validate_nonempty("reporter_commitment", &self.reporter_commitment)?;
        validate_nonempty("evidence_root", &self.evidence_root)?;
        validate_nonempty("conflicting_state_root", &self.conflicting_state_root)?;
        validate_nonempty("pq_attestation_root", &self.pq_attestation_root)?;
        if self.opened_at_height >= self.expires_at_height {
            return Err("dispute evidence expires before opening".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPrivateChannelBatcherRoots {
    pub config_root: String,
    pub channel_root: String,
    pub envelope_root: String,
    pub route_root: String,
    pub signer_set_root: String,
    pub batch_root: String,
    pub sponsorship_root: String,
    pub reorg_guard_root: String,
    pub receipt_root: String,
    pub dispute_root: String,
    pub event_root: String,
}

impl MoneroPrivateChannelBatcherRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "channel_root": self.channel_root,
            "envelope_root": self.envelope_root,
            "route_root": self.route_root,
            "signer_set_root": self.signer_set_root,
            "batch_root": self.batch_root,
            "sponsorship_root": self.sponsorship_root,
            "reorg_guard_root": self.reorg_guard_root,
            "receipt_root": self.receipt_root,
            "dispute_root": self.dispute_root,
            "event_root": self.event_root,
        })
    }

    pub fn root(&self) -> String {
        monero_private_channel_batcher_payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPrivateChannelBatcherCounters {
    pub channel_count: u64,
    pub envelope_count: u64,
    pub route_count: u64,
    pub signer_set_count: u64,
    pub batch_count: u64,
    pub sponsorship_count: u64,
    pub reorg_guard_count: u64,
    pub receipt_count: u64,
    pub dispute_count: u64,
    pub pending_envelope_count: u64,
    pub open_batch_count: u64,
    pub active_sponsor_count: u64,
    pub total_entry_units: u64,
    pub total_exit_units: u64,
    pub total_gross_fee_piconero: u64,
    pub total_compressed_fee_piconero: u64,
    pub total_sponsored_fee_piconero: u64,
    pub event_count: u64,
}

impl MoneroPrivateChannelBatcherCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "channel_count": self.channel_count,
            "envelope_count": self.envelope_count,
            "route_count": self.route_count,
            "signer_set_count": self.signer_set_count,
            "batch_count": self.batch_count,
            "sponsorship_count": self.sponsorship_count,
            "reorg_guard_count": self.reorg_guard_count,
            "receipt_count": self.receipt_count,
            "dispute_count": self.dispute_count,
            "pending_envelope_count": self.pending_envelope_count,
            "open_batch_count": self.open_batch_count,
            "active_sponsor_count": self.active_sponsor_count,
            "total_entry_units": self.total_entry_units,
            "total_exit_units": self.total_exit_units,
            "total_gross_fee_piconero": self.total_gross_fee_piconero,
            "total_compressed_fee_piconero": self.total_compressed_fee_piconero,
            "total_sponsored_fee_piconero": self.total_sponsored_fee_piconero,
            "event_count": self.event_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroPrivateChannelBatcherState {
    pub config: MoneroPrivateChannelBatcherConfig,
    pub current_height: u64,
    pub channels: BTreeMap<String, PrivateChannelDescriptor>,
    pub envelopes: BTreeMap<String, StealthChannelEnvelope>,
    pub routes: BTreeMap<String, SubaddressRouteCommitment>,
    pub signer_sets: BTreeMap<String, PqSignerSet>,
    pub batches: BTreeMap<String, PrivateChannelBatch>,
    pub sponsorships: BTreeMap<String, FeeSponsorship>,
    pub reorg_guards: BTreeMap<String, ReorgGuard>,
    pub receipts: BTreeMap<String, BatchReceipt>,
    pub disputes: BTreeMap<String, DisputeEvidence>,
    pub events: Vec<Value>,
}

impl Default for MoneroPrivateChannelBatcherState {
    fn default() -> Self {
        Self::new(MoneroPrivateChannelBatcherConfig::devnet(), 0)
    }
}

impl MoneroPrivateChannelBatcherState {
    pub fn new(config: MoneroPrivateChannelBatcherConfig, current_height: u64) -> Self {
        Self {
            config,
            current_height,
            channels: BTreeMap::new(),
            envelopes: BTreeMap::new(),
            routes: BTreeMap::new(),
            signer_sets: BTreeMap::new(),
            batches: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            reorg_guards: BTreeMap::new(),
            receipts: BTreeMap::new(),
            disputes: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn devnet() -> MoneroPrivateChannelBatcherResult<Self> {
        let config = MoneroPrivateChannelBatcherConfig::devnet();
        let mut state = Self::new(config, MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_HEIGHT);
        let route_payment = SubaddressRouteCommitment::new(
            "devnet-payment-route",
            PrivateChannelLane::Payment,
            25_000_000,
            state.current_height,
            state.config.target_privacy_set_size,
            1,
        );
        let route_defi = SubaddressRouteCommitment::new(
            "devnet-defi-route",
            PrivateChannelLane::DefiIntent,
            75_000_000,
            state.current_height,
            state.config.target_privacy_set_size,
            2,
        );
        state.register_route(route_payment)?;
        state.register_route(route_defi)?;

        let signer_members = vec![
            PqSignerMember::new("devnet-signer-a", state.current_height, 2),
            PqSignerMember::new("devnet-signer-b", state.current_height, 2),
            PqSignerMember::new("devnet-signer-c", state.current_height, 2),
        ];
        let signer_set = PqSignerSet::new(
            "devnet-signer-set",
            1,
            state.config.min_pq_signer_weight,
            signer_members,
            state.current_height,
            7_200,
        );
        let signer_set_id = signer_set.signer_set_id.clone();
        state.register_signer_set(signer_set)?;

        let channel_a = PrivateChannelDescriptor::new(
            "devnet-channel-alice-bob",
            PrivateChannelLane::Payment,
            &deterministic_commitment("OWNER", &["alice"]),
            &deterministic_commitment("COUNTERPARTY", &["bob"]),
            state.current_height,
            2_880,
        );
        let channel_b = PrivateChannelDescriptor::new(
            "devnet-channel-market-maker",
            PrivateChannelLane::DefiIntent,
            &deterministic_commitment("OWNER", &["maker"]),
            &deterministic_commitment("COUNTERPARTY", &["router"]),
            state.current_height,
            2_880,
        );
        let channel_a_id = channel_a.channel_id.clone();
        let channel_b_id = channel_b.channel_id.clone();
        state.open_channel(channel_a)?;
        state.open_channel(channel_b)?;

        let sponsor = FeeSponsorship::new(
            "devnet-low-fee-sponsor",
            PrivateChannelLane::Payment,
            state.config.sponsor_pool_piconero / 3,
            state.current_height,
            state.current_height.saturating_add(1_440),
            &state.config,
            1,
        );
        let sponsor_id = sponsor.sponsor_id.clone();
        state.reserve_sponsorship(sponsor)?;

        let payment_route_id = state
            .routes
            .values()
            .find(|route| route.lane == PrivateChannelLane::Payment)
            .map(|route| route.route_id.clone())
            .ok_or_else(|| "devnet payment route missing".to_string())?;
        let defi_route_id = state
            .routes
            .values()
            .find(|route| route.lane == PrivateChannelLane::DefiIntent)
            .map(|route| route.route_id.clone())
            .ok_or_else(|| "devnet defi route missing".to_string())?;

        let mut envelope_a = StealthChannelEnvelope::new(
            "devnet-payment-entry",
            &channel_a_id,
            PrivateChannelLane::Payment,
            ChannelEnvelopeKind::Entry,
            &state.config.asset_id,
            8_000_000,
            &payment_route_id,
            state.current_height,
            &state.config,
            1,
        );
        envelope_a.sponsor_id = Some(sponsor_id);
        let envelope_b = StealthChannelEnvelope::new(
            "devnet-payment-exit",
            &channel_a_id,
            PrivateChannelLane::Payment,
            ChannelEnvelopeKind::Exit,
            &state.config.asset_id,
            2_500_000,
            &payment_route_id,
            state.current_height.saturating_add(1),
            &state.config,
            2,
        );
        let envelope_c = StealthChannelEnvelope::new(
            "devnet-defi-netting",
            &channel_b_id,
            PrivateChannelLane::DefiIntent,
            ChannelEnvelopeKind::Netting,
            &state.config.asset_id,
            15_000_000,
            &defi_route_id,
            state.current_height.saturating_add(1),
            &state.config,
            3,
        );
        state.submit_envelope(envelope_a)?;
        state.submit_envelope(envelope_b)?;
        state.submit_envelope(envelope_c)?;

        let payment_envelopes = state
            .envelopes
            .values()
            .filter(|envelope| envelope.lane == PrivateChannelLane::Payment)
            .cloned()
            .collect::<Vec<_>>();
        let route_root = state.roots().route_root;
        let batch = PrivateChannelBatch::new(
            "devnet-payment-batch",
            PrivateChannelLane::Payment,
            &signer_set_id,
            &payment_envelopes,
            &route_root,
            state.current_height.saturating_add(2),
            &state.config,
            1,
        );
        let batch_id = batch.batch_id.clone();
        state.seal_batch(batch)?;
        let guard = ReorgGuard::new(
            "devnet-payment-guard",
            &batch_id,
            &deterministic_commitment("MONERO-TXID", &["payment-batch"]),
            302,
            state.current_height.saturating_add(6),
            &state.config,
        );
        let guard_id = guard.guard_id.clone();
        state.arm_reorg_guard(guard)?;
        state.publish_receipt(BatchReceipt::new(
            &batch_id,
            &state.roots().channel_root,
            &state.roots().envelope_root,
            &state.roots().sponsorship_root,
            &guard_id,
            &deterministic_commitment("MONERO-TXID", &["payment-batch"]),
            state.current_height.saturating_add(20),
            &state.config,
            1,
        ))?;
        state.validate()?;
        Ok(state)
    }

    pub fn update_height(&mut self, next_height: u64) -> MoneroPrivateChannelBatcherResult<()> {
        if next_height < self.current_height {
            return Err("monero private channel batcher height cannot decrease".to_string());
        }
        if next_height != self.current_height {
            self.current_height = next_height;
            self.record_event(
                "height_updated",
                json!({
                    "height": self.current_height,
                }),
            );
        }
        Ok(())
    }

    pub fn open_channel(
        &mut self,
        mut channel: PrivateChannelDescriptor,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        channel.validate()?;
        if channel.opened_at_height > self.current_height {
            return Err("private channel open height is in the future".to_string());
        }
        if self.channels.contains_key(&channel.channel_id) {
            return Err("private channel already exists".to_string());
        }
        channel.status = ChannelStatus::Active;
        let channel_id = channel.channel_id.clone();
        self.channels.insert(channel_id.clone(), channel);
        self.record_event("channel_opened", json!({ "channel_id": channel_id }));
        Ok(channel_id)
    }

    pub fn register_route(
        &mut self,
        route: SubaddressRouteCommitment,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        route.validate()?;
        if self.routes.contains_key(&route.route_id) {
            return Err("subaddress route already exists".to_string());
        }
        let route_id = route.route_id.clone();
        self.routes.insert(route_id.clone(), route);
        self.record_event("route_registered", json!({ "route_id": route_id }));
        Ok(route_id)
    }

    pub fn register_signer_set(
        &mut self,
        signer_set: PqSignerSet,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        signer_set.validate(&self.config)?;
        if self.signer_sets.contains_key(&signer_set.signer_set_id) {
            return Err("pq signer set already exists".to_string());
        }
        let signer_set_id = signer_set.signer_set_id.clone();
        self.signer_sets.insert(signer_set_id.clone(), signer_set);
        self.record_event(
            "signer_set_registered",
            json!({ "signer_set_id": signer_set_id }),
        );
        Ok(signer_set_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsorship: FeeSponsorship,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        sponsorship.validate()?;
        if self.sponsorships.contains_key(&sponsorship.sponsor_id) {
            return Err("fee sponsorship already exists".to_string());
        }
        let sponsor_id = sponsorship.sponsor_id.clone();
        self.sponsorships.insert(sponsor_id.clone(), sponsorship);
        self.record_event("sponsorship_reserved", json!({ "sponsor_id": sponsor_id }));
        Ok(sponsor_id)
    }

    pub fn submit_envelope(
        &mut self,
        mut envelope: StealthChannelEnvelope,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        envelope.validate(&self.config)?;
        if self.envelopes.contains_key(&envelope.envelope_id) {
            return Err("stealth channel envelope already exists".to_string());
        }
        let channel = self
            .channels
            .get_mut(&envelope.channel_id)
            .ok_or_else(|| "stealth channel envelope references unknown channel".to_string())?;
        if !channel.status.accepts_envelopes() {
            return Err("stealth channel envelope channel does not accept envelopes".to_string());
        }
        if channel.lane != envelope.lane {
            return Err("stealth channel envelope lane mismatch".to_string());
        }
        let route = self
            .routes
            .get(&envelope.route_commitment_id)
            .ok_or_else(|| "stealth channel envelope references unknown route".to_string())?;
        if !route.status.usable() || route.lane != envelope.lane {
            return Err("stealth channel envelope route unavailable or lane mismatch".to_string());
        }
        if route.max_amount_bucket < envelope.amount_bucket {
            return Err("stealth channel envelope exceeds route amount bucket".to_string());
        }
        if let Some(sponsor_id) = &envelope.sponsor_id {
            let sponsor = self
                .sponsorships
                .get(sponsor_id)
                .ok_or_else(|| "stealth channel envelope references unknown sponsor".to_string())?;
            if !sponsor.status.spendable() || sponsor.lane != envelope.lane {
                return Err(
                    "stealth channel envelope sponsor unavailable or lane mismatch".to_string(),
                );
            }
        }
        if envelope.submitted_at_height > self.current_height {
            return Err("stealth channel envelope submission height is in the future".to_string());
        }
        envelope.status = EnvelopeStatus::Routed;
        match envelope.kind {
            ChannelEnvelopeKind::Entry => {
                channel.total_entry_units = channel
                    .total_entry_units
                    .saturating_add(envelope.amount_bucket);
            }
            ChannelEnvelopeKind::Exit => {
                channel.total_exit_units = channel
                    .total_exit_units
                    .saturating_add(envelope.amount_bucket);
            }
            _ => {}
        }
        channel.pending_envelope_count = channel.pending_envelope_count.saturating_add(1);
        let envelope_id = envelope.envelope_id.clone();
        self.envelopes.insert(envelope_id.clone(), envelope);
        self.record_event("envelope_submitted", json!({ "envelope_id": envelope_id }));
        Ok(envelope_id)
    }

    pub fn seal_batch(
        &mut self,
        mut batch: PrivateChannelBatch,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        batch.validate(&self.config)?;
        if self.batches.contains_key(&batch.batch_id) {
            return Err("private channel batch already exists".to_string());
        }
        let signer_set = self
            .signer_sets
            .get(&batch.signer_set_id)
            .ok_or_else(|| "private channel batch references unknown pq signer set".to_string())?;
        if !signer_set.status.can_sign() {
            return Err("private channel batch signer set cannot sign".to_string());
        }
        let mut touched_channels = BTreeSet::new();
        for envelope_id in &batch.envelope_ids {
            let envelope = self
                .envelopes
                .get(envelope_id)
                .ok_or_else(|| "private channel batch references unknown envelope".to_string())?;
            if !envelope.status.batchable() {
                return Err("private channel batch references non-batchable envelope".to_string());
            }
            if envelope.lane != batch.lane {
                return Err("private channel batch envelope lane mismatch".to_string());
            }
            touched_channels.insert(envelope.channel_id.clone());
        }
        for envelope_id in &batch.envelope_ids {
            if let Some(envelope) = self.envelopes.get_mut(envelope_id) {
                envelope.status = EnvelopeStatus::Batched;
            }
        }
        for channel_id in touched_channels {
            if let Some(channel) = self.channels.get_mut(&channel_id) {
                channel.pending_envelope_count = channel.pending_envelope_count.saturating_sub(1);
            }
        }
        batch.status = BatchStatus::Sealed;
        let batch_id = batch.batch_id.clone();
        self.batches.insert(batch_id.clone(), batch);
        self.record_event("batch_sealed", json!({ "batch_id": batch_id }));
        Ok(batch_id)
    }

    pub fn approve_batch(&mut self, batch_id: &str) -> MoneroPrivateChannelBatcherResult<()> {
        let batch = self
            .batches
            .get_mut(batch_id)
            .ok_or_else(|| "private channel batch not found".to_string())?;
        if !matches!(batch.status, BatchStatus::Sealed) {
            return Err("private channel batch must be sealed before approval".to_string());
        }
        batch.status = BatchStatus::PqApproved;
        self.record_event("batch_pq_approved", json!({ "batch_id": batch_id }));
        Ok(())
    }

    pub fn arm_reorg_guard(
        &mut self,
        guard: ReorgGuard,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        guard.validate()?;
        if self.reorg_guards.contains_key(&guard.guard_id) {
            return Err("reorg guard already exists".to_string());
        }
        if !self.batches.contains_key(&guard.batch_id) {
            return Err("reorg guard references unknown batch".to_string());
        }
        let guard_id = guard.guard_id.clone();
        self.reorg_guards.insert(guard_id.clone(), guard);
        self.record_event("reorg_guard_armed", json!({ "guard_id": guard_id }));
        Ok(guard_id)
    }

    pub fn publish_receipt(
        &mut self,
        receipt: BatchReceipt,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        receipt.validate()?;
        if self.receipts.contains_key(&receipt.receipt_id) {
            return Err("batch receipt already exists".to_string());
        }
        let batch = self
            .batches
            .get_mut(&receipt.batch_id)
            .ok_or_else(|| "batch receipt references unknown batch".to_string())?;
        if !self.reorg_guards.contains_key(&receipt.reorg_guard_id) {
            return Err("batch receipt references unknown reorg guard".to_string());
        }
        batch.status = BatchStatus::Posted;
        for envelope_id in batch.envelope_ids.clone() {
            if let Some(envelope) = self.envelopes.get_mut(&envelope_id) {
                envelope.status = EnvelopeStatus::Settled;
            }
        }
        let receipt_id = receipt.receipt_id.clone();
        self.receipts.insert(receipt_id.clone(), receipt);
        self.record_event("receipt_published", json!({ "receipt_id": receipt_id }));
        Ok(receipt_id)
    }

    pub fn open_dispute(
        &mut self,
        dispute: DisputeEvidence,
    ) -> MoneroPrivateChannelBatcherResult<String> {
        self.ensure_capacity()?;
        dispute.validate()?;
        if self.disputes.contains_key(&dispute.dispute_id) {
            return Err("dispute evidence already exists".to_string());
        }
        if dispute.opened_at_height > self.current_height {
            return Err("dispute evidence open height is in the future".to_string());
        }
        let dispute_id = dispute.dispute_id.clone();
        match dispute.target_kind.as_str() {
            "batch" => {
                if let Some(batch) = self.batches.get_mut(&dispute.target_id) {
                    batch.status = BatchStatus::Disputed;
                }
            }
            "envelope" => {
                if let Some(envelope) = self.envelopes.get_mut(&dispute.target_id) {
                    envelope.status = EnvelopeStatus::Disputed;
                }
            }
            "channel" => {
                if let Some(channel) = self.channels.get_mut(&dispute.target_id) {
                    channel.status = ChannelStatus::Disputed;
                }
            }
            _ => {}
        }
        self.disputes.insert(dispute_id.clone(), dispute);
        self.record_event("dispute_opened", json!({ "dispute_id": dispute_id }));
        Ok(dispute_id)
    }

    pub fn roots(&self) -> MoneroPrivateChannelBatcherRoots {
        let channel_records = self
            .channels
            .values()
            .map(PrivateChannelDescriptor::public_record)
            .collect::<Vec<_>>();
        let envelope_records = self
            .envelopes
            .values()
            .map(StealthChannelEnvelope::public_record)
            .collect::<Vec<_>>();
        let route_records = self
            .routes
            .values()
            .map(SubaddressRouteCommitment::public_record)
            .collect::<Vec<_>>();
        let signer_records = self
            .signer_sets
            .values()
            .map(PqSignerSet::public_record)
            .collect::<Vec<_>>();
        let batch_records = self
            .batches
            .values()
            .map(PrivateChannelBatch::public_record)
            .collect::<Vec<_>>();
        let sponsorship_records = self
            .sponsorships
            .values()
            .map(FeeSponsorship::public_record)
            .collect::<Vec<_>>();
        let guard_records = self
            .reorg_guards
            .values()
            .map(ReorgGuard::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .receipts
            .values()
            .map(BatchReceipt::public_record)
            .collect::<Vec<_>>();
        let dispute_records = self
            .disputes
            .values()
            .map(DisputeEvidence::public_record)
            .collect::<Vec<_>>();
        MoneroPrivateChannelBatcherRoots {
            config_root: self.config.config_root(),
            channel_root: merkle_root("MONERO-PRIVATE-CHANNEL", &channel_records),
            envelope_root: merkle_root("MONERO-PRIVATE-CHANNEL-ENVELOPE", &envelope_records),
            route_root: merkle_root("MONERO-PRIVATE-CHANNEL-ROUTE", &route_records),
            signer_set_root: merkle_root("MONERO-PRIVATE-CHANNEL-SIGNER-SET", &signer_records),
            batch_root: merkle_root("MONERO-PRIVATE-CHANNEL-BATCH", &batch_records),
            sponsorship_root: merkle_root(
                "MONERO-PRIVATE-CHANNEL-SPONSORSHIP",
                &sponsorship_records,
            ),
            reorg_guard_root: merkle_root("MONERO-PRIVATE-CHANNEL-REORG-GUARD", &guard_records),
            receipt_root: merkle_root("MONERO-PRIVATE-CHANNEL-RECEIPT", &receipt_records),
            dispute_root: merkle_root("MONERO-PRIVATE-CHANNEL-DISPUTE", &dispute_records),
            event_root: merkle_root("MONERO-PRIVATE-CHANNEL-EVENT", &self.events),
        }
    }

    pub fn counters(&self) -> MoneroPrivateChannelBatcherCounters {
        let pending_envelope_count = self
            .envelopes
            .values()
            .filter(|envelope| envelope.status.batchable())
            .count() as u64;
        let open_batch_count = self
            .batches
            .values()
            .filter(|batch| {
                matches!(
                    batch.status,
                    BatchStatus::Open
                        | BatchStatus::Sealed
                        | BatchStatus::PqApproved
                        | BatchStatus::ReorgDelayed
                        | BatchStatus::Posted
                        | BatchStatus::Disputed
                )
            })
            .count() as u64;
        let active_sponsor_count = self
            .sponsorships
            .values()
            .filter(|sponsor| sponsor.status.spendable())
            .count() as u64;
        let total_entry_units = self.channels.values().fold(0_u64, |acc, channel| {
            acc.saturating_add(channel.total_entry_units)
        });
        let total_exit_units = self.channels.values().fold(0_u64, |acc, channel| {
            acc.saturating_add(channel.total_exit_units)
        });
        let total_gross_fee_piconero = self.batches.values().fold(0_u64, |acc, batch| {
            acc.saturating_add(batch.gross_fee_piconero)
        });
        let total_compressed_fee_piconero = self.batches.values().fold(0_u64, |acc, batch| {
            acc.saturating_add(batch.compressed_fee_piconero)
        });
        let total_sponsored_fee_piconero = self.batches.values().fold(0_u64, |acc, batch| {
            acc.saturating_add(batch.sponsored_fee_piconero)
        });
        MoneroPrivateChannelBatcherCounters {
            channel_count: self.channels.len() as u64,
            envelope_count: self.envelopes.len() as u64,
            route_count: self.routes.len() as u64,
            signer_set_count: self.signer_sets.len() as u64,
            batch_count: self.batches.len() as u64,
            sponsorship_count: self.sponsorships.len() as u64,
            reorg_guard_count: self.reorg_guards.len() as u64,
            receipt_count: self.receipts.len() as u64,
            dispute_count: self.disputes.len() as u64,
            pending_envelope_count,
            open_batch_count,
            active_sponsor_count,
            total_entry_units,
            total_exit_units,
            total_gross_fee_piconero,
            total_compressed_fee_piconero,
            total_sponsored_fee_piconero,
            event_count: self.events.len() as u64,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION,
            "schema_version": MONERO_PRIVATE_CHANNEL_BATCHER_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        monero_private_channel_batcher_hash(
            "STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(self.current_height as i128),
                HashPart::Json(&roots.public_record()),
                HashPart::Json(&counters.public_record()),
            ],
        )
    }

    pub fn validate(&self) -> MoneroPrivateChannelBatcherResult<()> {
        self.config.validate()?;
        if self.channels.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_CHANNELS
            || self.envelopes.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_ENVELOPES
            || self.routes.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_ROUTES
            || self.signer_sets.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_SIGNER_SETS
            || self.batches.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_BATCHES
            || self.sponsorships.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_SPONSORSHIPS
            || self.reorg_guards.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_REORG_GUARDS
            || self.receipts.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_RECEIPTS
            || self.disputes.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_DISPUTES
            || self.events.len() > MONERO_PRIVATE_CHANNEL_BATCHER_MAX_EVENTS
        {
            return Err("monero private channel batcher state exceeds capacity limits".to_string());
        }
        for channel in self.channels.values() {
            channel.validate()?;
        }
        for route in self.routes.values() {
            route.validate()?;
        }
        for signer_set in self.signer_sets.values() {
            signer_set.validate(&self.config)?;
        }
        for sponsor in self.sponsorships.values() {
            sponsor.validate()?;
        }
        for envelope in self.envelopes.values() {
            envelope.validate(&self.config)?;
            let channel = self
                .channels
                .get(&envelope.channel_id)
                .ok_or_else(|| "validated envelope references missing channel".to_string())?;
            if channel.lane != envelope.lane {
                return Err("validated envelope lane differs from channel lane".to_string());
            }
            let route = self
                .routes
                .get(&envelope.route_commitment_id)
                .ok_or_else(|| "validated envelope references missing route".to_string())?;
            if route.lane != envelope.lane {
                return Err("validated envelope lane differs from route lane".to_string());
            }
        }
        for batch in self.batches.values() {
            batch.validate(&self.config)?;
            if !self.signer_sets.contains_key(&batch.signer_set_id) {
                return Err("validated batch references missing signer set".to_string());
            }
            for envelope_id in &batch.envelope_ids {
                if !self.envelopes.contains_key(envelope_id) {
                    return Err("validated batch references missing envelope".to_string());
                }
            }
        }
        for guard in self.reorg_guards.values() {
            guard.validate()?;
            if !self.batches.contains_key(&guard.batch_id) {
                return Err("validated reorg guard references missing batch".to_string());
            }
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            if !self.batches.contains_key(&receipt.batch_id) {
                return Err("validated receipt references missing batch".to_string());
            }
            if !self.reorg_guards.contains_key(&receipt.reorg_guard_id) {
                return Err("validated receipt references missing reorg guard".to_string());
            }
        }
        for dispute in self.disputes.values() {
            dispute.validate()?;
        }
        Ok(())
    }

    fn ensure_capacity(&self) -> MoneroPrivateChannelBatcherResult<()> {
        if self.channels.len() >= MONERO_PRIVATE_CHANNEL_BATCHER_MAX_CHANNELS {
            return Err("monero private channel batcher channel capacity reached".to_string());
        }
        if self.events.len() >= MONERO_PRIVATE_CHANNEL_BATCHER_MAX_EVENTS {
            return Err("monero private channel batcher event capacity reached".to_string());
        }
        Ok(())
    }

    fn record_event(&mut self, event_kind: &str, payload: Value) {
        let event = json!({
            "chain_id": CHAIN_ID,
            "event_kind": event_kind,
            "height": self.current_height,
            "payload": payload,
            "event_index": self.events.len() as u64,
        });
        self.events.push(event);
    }
}

pub fn monero_private_channel_batcher_devnet(
) -> MoneroPrivateChannelBatcherResult<MoneroPrivateChannelBatcherState> {
    MoneroPrivateChannelBatcherState::devnet()
}

pub fn monero_private_channel_batcher_state_root(
    state: &MoneroPrivateChannelBatcherState,
) -> String {
    state.state_root()
}

pub fn monero_private_channel_batcher_validate(
    state: &MoneroPrivateChannelBatcherState,
) -> MoneroPrivateChannelBatcherResult<()> {
    state.validate()
}

pub fn monero_private_channel_batcher_hash(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("MONERO-PRIVATE-CHANNEL-BATCHER:{domain}"),
        &[
            HashPart::Str(MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&json!({
                "domain": domain,
                "part_count": parts.len(),
            })),
        ],
        16,
    ) + &domain_hash(
        &format!("MONERO-PRIVATE-CHANNEL-BATCHER:{domain}:PAYLOAD"),
        parts,
        16,
    )
}

pub fn monero_private_channel_batcher_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        &format!("MONERO-PRIVATE-CHANNEL-BATCHER:{domain}"),
        &[
            HashPart::Str(MONERO_PRIVATE_CHANNEL_BATCHER_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn channel_envelope_id(
    channel_id: &str,
    kind: ChannelEnvelopeKind,
    stealth_address_commitment: &str,
    payload_ciphertext_hash: &str,
    submitted_at_height: u64,
    sequence: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "ENVELOPE-ID",
        &[
            HashPart::Str(channel_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(stealth_address_commitment),
            HashPart::Str(payload_ciphertext_hash),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
    )
}

pub fn subaddress_route_id(
    lane: PrivateChannelLane,
    subaddress_commitment_root: &str,
    route_blinding_root: &str,
    opened_at_height: u64,
    route_nonce: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "SUBADDRESS-ROUTE-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(subaddress_commitment_root),
            HashPart::Str(route_blinding_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(route_nonce as i128),
        ],
    )
}

pub fn pq_signer_set_id(
    epoch: u64,
    threshold_weight: u64,
    aggregate_key_commitment: &str,
    activated_at_height: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "PQ-SIGNER-SET-ID",
        &[
            HashPart::Int(epoch as i128),
            HashPart::Int(threshold_weight as i128),
            HashPart::Str(aggregate_key_commitment),
            HashPart::Int(activated_at_height as i128),
        ],
    )
}

pub fn private_channel_batch_id(
    lane: PrivateChannelLane,
    signer_set_id: &str,
    envelope_root: &str,
    opened_at_height: u64,
    batch_nonce: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "BATCH-ID",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(signer_set_id),
            HashPart::Str(envelope_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(batch_nonce as i128),
        ],
    )
}

pub fn sponsorship_id(
    sponsor_commitment: &str,
    lane: PrivateChannelLane,
    budget_root: &str,
    valid_from_height: u64,
    sponsor_nonce: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "SPONSORSHIP-ID",
        &[
            HashPart::Str(sponsor_commitment),
            HashPart::Str(lane.as_str()),
            HashPart::Str(budget_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(sponsor_nonce as i128),
        ],
    )
}

pub fn reorg_guard_id(
    batch_id: &str,
    monero_anchor_txid: &str,
    anchor_height: u64,
    l2_observed_height: u64,
    anchor_block_hash_root: &str,
) -> String {
    monero_private_channel_batcher_hash(
        "REORG-GUARD-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(monero_anchor_txid),
            HashPart::Int(anchor_height as i128),
            HashPart::Int(l2_observed_height as i128),
            HashPart::Str(anchor_block_hash_root),
        ],
    )
}

pub fn receipt_id(
    batch_id: &str,
    channel_root_after: &str,
    envelope_root_after: &str,
    reorg_guard_id: &str,
    settled_at_height: u64,
    receipt_nonce: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "RECEIPT-ID",
        &[
            HashPart::Str(batch_id),
            HashPart::Str(channel_root_after),
            HashPart::Str(envelope_root_after),
            HashPart::Str(reorg_guard_id),
            HashPart::Int(settled_at_height as i128),
            HashPart::Int(receipt_nonce as i128),
        ],
    )
}

pub fn dispute_id(
    target_kind: &str,
    target_id: &str,
    evidence_root: &str,
    opened_at_height: u64,
    dispute_nonce: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "DISPUTE-ID",
        &[
            HashPart::Str(target_kind),
            HashPart::Str(target_id),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(dispute_nonce as i128),
        ],
    )
}

pub fn fee_compression_commitment(
    gross_fee_piconero: u64,
    compressed_fee_piconero: u64,
    sponsored_fee_piconero: u64,
    batch_weight: u64,
) -> String {
    monero_private_channel_batcher_hash(
        "FEE-COMPRESSION",
        &[
            HashPart::Int(gross_fee_piconero as i128),
            HashPart::Int(compressed_fee_piconero as i128),
            HashPart::Int(sponsored_fee_piconero as i128),
            HashPart::Int(batch_weight as i128),
        ],
    )
}

pub fn deterministic_commitment(domain: &str, values: &[&str]) -> String {
    let mut parts = Vec::with_capacity(values.len() + 1);
    parts.push(HashPart::Str(domain));
    for value in values {
        parts.push(HashPart::Str(value));
    }
    monero_private_channel_batcher_hash("DETERMINISTIC-COMMITMENT", &parts)
}

fn validate_nonempty(label: &str, value: &str) -> MoneroPrivateChannelBatcherResult<()> {
    if value.is_empty() {
        return Err(format!(
            "monero private channel batcher {label} must be populated"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_deterministic_root() -> MoneroPrivateChannelBatcherResult<()>
    {
        let state_a = MoneroPrivateChannelBatcherState::devnet()?;
        let state_b = MoneroPrivateChannelBatcherState::devnet()?;
        assert_eq!(state_a.state_root(), state_b.state_root());
        assert!(state_a.validate().is_ok());
        assert!(state_a.counters().channel_count >= 2);
        assert!(state_a.counters().receipt_count >= 1);
        Ok(())
    }

    #[test]
    fn height_updates_are_monotonic() {
        let mut state = MoneroPrivateChannelBatcherState::new(
            MoneroPrivateChannelBatcherConfig::devnet(),
            MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_HEIGHT,
        );
        assert!(state
            .update_height(MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_HEIGHT + 1)
            .is_ok());
        assert!(state
            .update_height(MONERO_PRIVATE_CHANNEL_BATCHER_DEVNET_HEIGHT)
            .is_err());
    }

    #[test]
    fn envelope_privacy_floor_is_enforced() {
        let config = MoneroPrivateChannelBatcherConfig::devnet();
        let mut envelope = StealthChannelEnvelope::new(
            "privacy-floor",
            "channel",
            PrivateChannelLane::Payment,
            ChannelEnvelopeKind::Entry,
            &config.asset_id,
            10,
            "route",
            1,
            &config,
            1,
        );
        envelope.privacy_set_size = config.min_privacy_set_size.saturating_sub(1);
        assert!(envelope.validate(&config).is_err());
    }
}
