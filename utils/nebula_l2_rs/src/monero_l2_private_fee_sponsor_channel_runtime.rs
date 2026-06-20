use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type MoneroL2PrivateFeeSponsorChannelRuntimeResult<T> = Result<T, String>;

pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-private-fee-sponsor-channel-runtime-v1";
pub const PROTOCOL_VERSION: &str = MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_HEIGHT: u64 = 356_000;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_CHANNEL_BOOK: &str =
    "devnet-private-fee-sponsor-channel-book";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_SPONSOR_POOL: &str =
    "devnet-private-fee-sponsor-pool";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_INTENT_SCHEME: &str =
    "ml-kem-1024-encrypted-private-fee-intent-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_PQ_ATTESTATION_SCHEME: &str =
    "ml-dsa-87-private-fee-sponsor-attestation-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_RESERVATION_SCHEME: &str =
    "roots-only-low-fee-private-channel-reservation-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SETTLEMENT_SCHEME: &str =
    "fast-private-fee-sponsor-channel-settlement-batch-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SPONSOR_RECEIPT_SCHEME: &str =
    "replay-safe-private-fee-sponsor-receipt-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_REBATE_RECEIPT_SCHEME: &str =
    "replay-safe-private-channel-fee-rebate-receipt-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-private-fee-sponsor-channel-nullifier-root-v1";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-private-fee-sponsor-channel-devnet";
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 32;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 40;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS: u64 = 96;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 4;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS: u64 = 288;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_REBATE_BPS: u64 = 750;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_SPONSOR_RESERVE_BPS: u64 =
    10_500;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_TARGET_SPONSOR_RESERVE_BPS: u64 =
    12_500;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MAX_CHANNEL_IMBALANCE_BPS: u64 =
    150;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_INTENTS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_ATTESTATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_RESERVATIONS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_SETTLEMENT_BATCHES: usize = 262_144;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_SPONSOR_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_REBATE_RECEIPTS: usize = 1_048_576;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_REPLAY_FENCES: usize = 2_097_152;
pub const MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_PUBLIC_RECORDS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelFlow {
    PrivateDeposit,
    PrivateExit,
    ChannelOpen,
    ChannelClose,
    ChannelRebalance,
    EmergencyExit,
}

impl ChannelFlow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateDeposit => "private_deposit",
            Self::PrivateExit => "private_exit",
            Self::ChannelOpen => "channel_open",
            Self::ChannelClose => "channel_close",
            Self::ChannelRebalance => "channel_rebalance",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn is_exit(self) -> bool {
        matches!(
            self,
            Self::PrivateExit | Self::ChannelClose | Self::EmergencyExit
        )
    }

    pub fn is_deposit(self) -> bool {
        matches!(self, Self::PrivateDeposit | Self::ChannelOpen)
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyExit => 10_000,
            Self::PrivateExit => 9_000,
            Self::ChannelClose => 8_400,
            Self::PrivateDeposit => 8_000,
            Self::ChannelOpen => 7_600,
            Self::ChannelRebalance => 6_900,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyLane {
    ShieldedLowFee,
    ShieldedFast,
    ShieldedBatch,
    ViewOnlyAudit,
    Emergency,
}

impl PrivacyLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShieldedLowFee => "shielded_low_fee",
            Self::ShieldedFast => "shielded_fast",
            Self::ShieldedBatch => "shielded_batch",
            Self::ViewOnlyAudit => "view_only_audit",
            Self::Emergency => "emergency",
        }
    }

    pub fn user_fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::ShieldedLowFee => config.low_fee_bps,
            Self::ShieldedBatch => config.max_user_fee_bps.saturating_mul(2) / 3,
            Self::ShieldedFast | Self::Emergency => config.max_user_fee_bps,
            Self::ViewOnlyAudit => config.low_fee_bps.saturating_add(1),
        }
    }

    pub fn requires_rebate(self) -> bool {
        matches!(self, Self::ShieldedLowFee | Self::ShieldedBatch)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicy {
    None,
    LowFeeOnly,
    FullFee,
    RebateOnly,
    EmergencySubsidy,
}

impl SponsorPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::LowFeeOnly => "low_fee_only",
            Self::FullFee => "full_fee",
            Self::RebateOnly => "rebate_only",
            Self::EmergencySubsidy => "emergency_subsidy",
        }
    }

    pub fn sponsored(self) -> bool {
        !matches!(self, Self::None)
    }

    pub fn covers_user_fee(self) -> bool {
        matches!(
            self,
            Self::LowFeeOnly | Self::FullFee | Self::EmergencySubsidy
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentStatus {
    Submitted,
    PqAttested,
    Reserved,
    Receipted,
    Batched,
    Settled,
    Replayed,
    Rejected,
    Expired,
}

impl IntentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::PqAttested => "pq_attested",
            Self::Reserved => "reserved",
            Self::Receipted => "receipted",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Replayed => "replayed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::PqAttested | Self::Reserved | Self::Receipted | Self::Batched
        )
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Replayed | Self::Rejected | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Replayed,
    Revoked,
    Expired,
}

impl PqAttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Replayed => "replayed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Submitted | Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Locked,
    ReceiptIssued,
    Batched,
    Settled,
    Released,
    Slashed,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Locked => "locked",
            Self::ReceiptIssued => "receipt_issued",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Locked | Self::ReceiptIssued | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    Submitted,
    FastFinalized,
    Settled,
    Disputed,
    Failed,
    Expired,
}

impl SettlementBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::FastFinalized => "fast_finalized",
            Self::Settled => "settled",
            Self::Disputed => "disputed",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    pub fn finalizable(self) -> bool {
        matches!(self, Self::Submitted | Self::FastFinalized)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReceiptStatus {
    Published,
    Finalized,
    Replayed,
    Settled,
    Failed,
    Disputed,
}

impl SponsorReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Finalized => "finalized",
            Self::Replayed => "replayed",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReceiptStatus {
    Queued,
    Published,
    Claimed,
    Settled,
    Expired,
    Replayed,
    Failed,
}

impl RebateReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Published => "published",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Replayed => "replayed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub channel_book: String,
    pub sponsor_pool: String,
    pub hash_suite: String,
    pub intent_scheme: String,
    pub pq_attestation_scheme: String,
    pub reservation_scheme: String,
    pub settlement_scheme: String,
    pub sponsor_receipt_scheme: String,
    pub rebate_receipt_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub genesis_height: u64,
    pub intent_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub low_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub rebate_bps: u64,
    pub min_sponsor_reserve_bps: u64,
    pub target_sponsor_reserve_bps: u64,
    pub max_channel_imbalance_bps: u64,
    pub roots_only: bool,
    pub max_intents: usize,
    pub max_attestations: usize,
    pub max_reservations: usize,
    pub max_settlement_batches: usize,
    pub max_sponsor_receipts: usize,
    pub max_rebate_receipts: usize,
    pub max_replay_fences: usize,
    pub max_public_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SCHEMA_VERSION,
            monero_network: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_L2_NETWORK.to_string(),
            asset_id: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_ASSET_ID.to_string(),
            fee_asset_id: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_FEE_ASSET_ID
                .to_string(),
            channel_book: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_CHANNEL_BOOK
                .to_string(),
            sponsor_pool: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_SPONSOR_POOL
                .to_string(),
            hash_suite: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_HASH_SUITE.to_string(),
            intent_scheme: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_INTENT_SCHEME.to_string(),
            pq_attestation_scheme:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_PQ_ATTESTATION_SCHEME.to_string(),
            reservation_scheme: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_RESERVATION_SCHEME
                .to_string(),
            settlement_scheme: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SETTLEMENT_SCHEME
                .to_string(),
            sponsor_receipt_scheme:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_SPONSOR_RECEIPT_SCHEME.to_string(),
            rebate_receipt_scheme:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_REBATE_RECEIPT_SCHEME.to_string(),
            nullifier_scheme: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_NULLIFIER_SCHEME
                .to_string(),
            replay_domain: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_REPLAY_DOMAIN.to_string(),
            genesis_height: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEVNET_HEIGHT,
            intent_ttl_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_INTENT_TTL_BLOCKS,
            attestation_ttl_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_ATTESTATION_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            rebate_ttl_blocks:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_REBATE_TTL_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_batch_privacy_set_size:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_user_fee_bps:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            low_fee_bps: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_LOW_FEE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            rebate_bps: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_REBATE_BPS,
            min_sponsor_reserve_bps:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MIN_SPONSOR_RESERVE_BPS,
            target_sponsor_reserve_bps:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_TARGET_SPONSOR_RESERVE_BPS,
            max_channel_imbalance_bps:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_DEFAULT_MAX_CHANNEL_IMBALANCE_BPS,
            roots_only: true,
            max_intents: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_INTENTS,
            max_attestations: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_ATTESTATIONS,
            max_reservations: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_RESERVATIONS,
            max_settlement_batches:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_SETTLEMENT_BATCHES,
            max_sponsor_receipts:
                MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_SPONSOR_RECEIPTS,
            max_rebate_receipts: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_REBATE_RECEIPTS,
            max_replay_fences: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_REPLAY_FENCES,
            max_public_records: MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_PUBLIC_RECORDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "channel_book": self.channel_book,
            "sponsor_pool": self.sponsor_pool,
            "hash_suite": self.hash_suite,
            "intent_scheme": self.intent_scheme,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "reservation_scheme": self.reservation_scheme,
            "settlement_scheme": self.settlement_scheme,
            "sponsor_receipt_scheme": self.sponsor_receipt_scheme,
            "rebate_receipt_scheme": self.rebate_receipt_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "genesis_height": self.genesis_height,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_batch_privacy_set_size": self.min_batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "low_fee_bps": self.low_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "rebate_bps": self.rebate_bps,
            "min_sponsor_reserve_bps": self.min_sponsor_reserve_bps,
            "target_sponsor_reserve_bps": self.target_sponsor_reserve_bps,
            "max_channel_imbalance_bps": self.max_channel_imbalance_bps,
            "roots_only": self.roots_only,
            "max_intents": self.max_intents,
            "max_attestations": self.max_attestations,
            "max_reservations": self.max_reservations,
            "max_settlement_batches": self.max_settlement_batches,
            "max_sponsor_receipts": self.max_sponsor_receipts,
            "max_rebate_receipts": self.max_rebate_receipts,
            "max_replay_fences": self.max_replay_fences,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub encrypted_intents_submitted: u64,
    pub live_intents: u64,
    pub replayed_intents: u64,
    pub pq_attestations_submitted: u64,
    pub pq_attestations_accepted: u64,
    pub reservations_opened: u64,
    pub reservations_live: u64,
    pub reservations_settled: u64,
    pub settlement_batches: u64,
    pub settlement_batches_finalized: u64,
    pub sponsor_receipts_issued: u64,
    pub sponsor_receipts_finalized: u64,
    pub rebate_receipts_issued: u64,
    pub rebate_receipts_claimed: u64,
    pub rebate_receipts_settled: u64,
    pub replay_fences: u64,
    pub consumed_nullifiers: u64,
    pub sponsored_fee_piconero: u128,
    pub user_fee_piconero: u128,
    pub rebated_fee_piconero: u128,
    pub reserved_fee_piconero: u128,
    pub settled_fee_piconero: u128,
    pub reserved_channel_amount_piconero: u128,
    pub settled_channel_amount_piconero: u128,
    pub public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "encrypted_intents_submitted": self.encrypted_intents_submitted,
            "live_intents": self.live_intents,
            "replayed_intents": self.replayed_intents,
            "pq_attestations_submitted": self.pq_attestations_submitted,
            "pq_attestations_accepted": self.pq_attestations_accepted,
            "reservations_opened": self.reservations_opened,
            "reservations_live": self.reservations_live,
            "reservations_settled": self.reservations_settled,
            "settlement_batches": self.settlement_batches,
            "settlement_batches_finalized": self.settlement_batches_finalized,
            "sponsor_receipts_issued": self.sponsor_receipts_issued,
            "sponsor_receipts_finalized": self.sponsor_receipts_finalized,
            "rebate_receipts_issued": self.rebate_receipts_issued,
            "rebate_receipts_claimed": self.rebate_receipts_claimed,
            "rebate_receipts_settled": self.rebate_receipts_settled,
            "replay_fences": self.replay_fences,
            "consumed_nullifiers": self.consumed_nullifiers,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "rebated_fee_piconero": self.rebated_fee_piconero,
            "reserved_fee_piconero": self.reserved_fee_piconero,
            "settled_fee_piconero": self.settled_fee_piconero,
            "reserved_channel_amount_piconero": self.reserved_channel_amount_piconero,
            "settled_channel_amount_piconero": self.settled_channel_amount_piconero,
            "public_records": self.public_records,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub intent_root: String,
    pub live_intent_root: String,
    pub pq_attestation_root: String,
    pub accepted_pq_attestation_root: String,
    pub reservation_root: String,
    pub live_reservation_root: String,
    pub settlement_batch_root: String,
    pub pending_settlement_batch_root: String,
    pub sponsor_receipt_root: String,
    pub finalized_sponsor_receipt_root: String,
    pub rebate_receipt_root: String,
    pub claimable_rebate_root: String,
    pub consumed_nullifier_root: String,
    pub replay_fence_root: String,
    pub sponsor_privacy_root: String,
    pub channel_privacy_root: String,
    pub fee_liability_root: String,
    pub public_record_root: String,
    pub event_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "intent_root": self.intent_root,
            "live_intent_root": self.live_intent_root,
            "pq_attestation_root": self.pq_attestation_root,
            "accepted_pq_attestation_root": self.accepted_pq_attestation_root,
            "reservation_root": self.reservation_root,
            "live_reservation_root": self.live_reservation_root,
            "settlement_batch_root": self.settlement_batch_root,
            "pending_settlement_batch_root": self.pending_settlement_batch_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "finalized_sponsor_receipt_root": self.finalized_sponsor_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "claimable_rebate_root": self.claimable_rebate_root,
            "consumed_nullifier_root": self.consumed_nullifier_root,
            "replay_fence_root": self.replay_fence_root,
            "sponsor_privacy_root": self.sponsor_privacy_root,
            "channel_privacy_root": self.channel_privacy_root,
            "fee_liability_root": self.fee_liability_root,
            "public_record_root": self.public_record_root,
            "event_root": self.event_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitEncryptedFeeIntentRequest {
    pub channel_flow: ChannelFlow,
    pub privacy_lane: PrivacyLane,
    pub sponsor_policy: SponsorPolicy,
    pub intent_owner_root: String,
    pub channel_commitment: String,
    pub monero_tx_commitment: String,
    pub amount_commitment: String,
    pub fee_budget_piconero: u128,
    pub max_user_fee_bps: u64,
    pub encrypted_intent_root: String,
    pub intent_ciphertext_root: String,
    pub view_tag_root: String,
    pub spend_nullifier: String,
    pub replay_fence: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeIntentRecord {
    pub intent_id: String,
    pub channel_flow: ChannelFlow,
    pub privacy_lane: PrivacyLane,
    pub sponsor_policy: SponsorPolicy,
    pub intent_owner_root: String,
    pub channel_commitment: String,
    pub monero_tx_commitment: String,
    pub amount_commitment: String,
    pub fee_budget_piconero: u128,
    pub expected_user_fee_piconero: u128,
    pub expected_sponsor_fee_piconero: u128,
    pub max_user_fee_bps: u64,
    pub effective_user_fee_bps: u64,
    pub sponsor_cover_bps: u64,
    pub encrypted_intent_root: String,
    pub intent_ciphertext_root: String,
    pub view_tag_root: String,
    pub spend_nullifier: String,
    pub replay_fence: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub privacy_set_size: u64,
    pub status: IntentStatus,
    pub created_at_height: u64,
}

impl FeeIntentRecord {
    pub fn new(request: &SubmitEncryptedFeeIntentRequest, config: &Config, height: u64) -> Self {
        let effective_user_fee_bps = request
            .privacy_lane
            .user_fee_bps(config)
            .min(request.max_user_fee_bps)
            .min(config.max_user_fee_bps);
        let expected_user_fee_piconero =
            fee_amount(request.fee_budget_piconero, effective_user_fee_bps);
        let expected_sponsor_fee_piconero = if request.sponsor_policy.covers_user_fee() {
            fee_amount(request.fee_budget_piconero, config.sponsor_cover_bps)
        } else {
            0
        };
        let seed = json!({
            "channel_flow": request.channel_flow.as_str(),
            "privacy_lane": request.privacy_lane.as_str(),
            "sponsor_policy": request.sponsor_policy.as_str(),
            "intent_owner_root": request.intent_owner_root,
            "channel_commitment": request.channel_commitment,
            "monero_tx_commitment": request.monero_tx_commitment,
            "amount_commitment": request.amount_commitment,
            "encrypted_intent_root": request.encrypted_intent_root,
            "intent_ciphertext_root": request.intent_ciphertext_root,
            "spend_nullifier": request.spend_nullifier,
            "replay_fence": request.replay_fence,
            "opens_at_height": request.opens_at_height,
            "expires_at_height": request.expires_at_height,
        });
        Self {
            intent_id: id_from_record("FEE-INTENT-ID", &seed),
            channel_flow: request.channel_flow,
            privacy_lane: request.privacy_lane,
            sponsor_policy: request.sponsor_policy,
            intent_owner_root: request.intent_owner_root.clone(),
            channel_commitment: request.channel_commitment.clone(),
            monero_tx_commitment: request.monero_tx_commitment.clone(),
            amount_commitment: request.amount_commitment.clone(),
            fee_budget_piconero: request.fee_budget_piconero,
            expected_user_fee_piconero,
            expected_sponsor_fee_piconero,
            max_user_fee_bps: request.max_user_fee_bps,
            effective_user_fee_bps,
            sponsor_cover_bps: config.sponsor_cover_bps,
            encrypted_intent_root: request.encrypted_intent_root.clone(),
            intent_ciphertext_root: request.intent_ciphertext_root.clone(),
            view_tag_root: request.view_tag_root.clone(),
            spend_nullifier: request.spend_nullifier.clone(),
            replay_fence: request.replay_fence.clone(),
            opens_at_height: request.opens_at_height,
            expires_at_height: request.expires_at_height,
            privacy_set_size: request.privacy_set_size,
            status: IntentStatus::Submitted,
            created_at_height: height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "intent_id": self.intent_id,
            "channel_flow": self.channel_flow.as_str(),
            "privacy_lane": self.privacy_lane.as_str(),
            "sponsor_policy": self.sponsor_policy.as_str(),
            "intent_owner_root": self.intent_owner_root,
            "channel_commitment": self.channel_commitment,
            "monero_tx_commitment": self.monero_tx_commitment,
            "amount_commitment": self.amount_commitment,
            "fee_budget_piconero": self.fee_budget_piconero,
            "expected_user_fee_piconero": self.expected_user_fee_piconero,
            "expected_sponsor_fee_piconero": self.expected_sponsor_fee_piconero,
            "max_user_fee_bps": self.max_user_fee_bps,
            "effective_user_fee_bps": self.effective_user_fee_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "encrypted_intent_root": self.encrypted_intent_root,
            "intent_ciphertext_root": self.intent_ciphertext_root,
            "view_tag_root": self.view_tag_root,
            "spend_nullifier_root": root_from_record("INTENT-SPEND-NULLIFIER", &json!({ "spend_nullifier": self.spend_nullifier })),
            "replay_fence": self.replay_fence,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "privacy_set_size": self.privacy_set_size,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("FEE-INTENT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitPqSponsorAttestationRequest {
    pub intent_id: String,
    pub sponsor_id: String,
    pub sponsor_pool_root: String,
    pub sponsor_reserve_root: String,
    pub sponsor_liability_root: String,
    pub pq_public_key_root: String,
    pub pq_attestation_root: String,
    pub pq_signature_root: String,
    pub attestation_nullifier: String,
    pub reserve_coverage_bps: u64,
    pub sponsor_fee_limit_piconero: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSponsorAttestationRecord {
    pub attestation_id: String,
    pub intent_id: String,
    pub sponsor_id: String,
    pub sponsor_pool_root: String,
    pub sponsor_reserve_root: String,
    pub sponsor_liability_root: String,
    pub pq_public_key_root: String,
    pub pq_attestation_root: String,
    pub pq_signature_root: String,
    pub attestation_nullifier: String,
    pub reserve_coverage_bps: u64,
    pub sponsor_fee_limit_piconero: u128,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
    pub status: PqAttestationStatus,
}

impl PqSponsorAttestationRecord {
    pub fn new(request: &SubmitPqSponsorAttestationRequest) -> Self {
        let seed = json!({
            "intent_id": request.intent_id,
            "sponsor_id": request.sponsor_id,
            "sponsor_pool_root": request.sponsor_pool_root,
            "sponsor_reserve_root": request.sponsor_reserve_root,
            "pq_attestation_root": request.pq_attestation_root,
            "attestation_nullifier": request.attestation_nullifier,
            "attested_at_height": request.attested_at_height,
        });
        Self {
            attestation_id: id_from_record("PQ-SPONSOR-ATTESTATION-ID", &seed),
            intent_id: request.intent_id.clone(),
            sponsor_id: request.sponsor_id.clone(),
            sponsor_pool_root: request.sponsor_pool_root.clone(),
            sponsor_reserve_root: request.sponsor_reserve_root.clone(),
            sponsor_liability_root: request.sponsor_liability_root.clone(),
            pq_public_key_root: request.pq_public_key_root.clone(),
            pq_attestation_root: request.pq_attestation_root.clone(),
            pq_signature_root: request.pq_signature_root.clone(),
            attestation_nullifier: request.attestation_nullifier.clone(),
            reserve_coverage_bps: request.reserve_coverage_bps,
            sponsor_fee_limit_piconero: request.sponsor_fee_limit_piconero,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            attested_at_height: request.attested_at_height,
            expires_at_height: request.expires_at_height,
            status: PqAttestationStatus::Submitted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "intent_id": self.intent_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_pool_root": self.sponsor_pool_root,
            "sponsor_reserve_root": self.sponsor_reserve_root,
            "sponsor_liability_root": self.sponsor_liability_root,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_attestation_root": self.pq_attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "attestation_nullifier_root": root_from_record("ATTESTATION-NULLIFIER", &json!({ "attestation_nullifier": self.attestation_nullifier })),
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "sponsor_fee_limit_piconero": self.sponsor_fee_limit_piconero,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-SPONSOR-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveLowFeeChannelRequest {
    pub intent_id: String,
    pub attestation_id: String,
    pub channel_counterparty_root: String,
    pub channel_state_root: String,
    pub channel_capacity_commitment: String,
    pub reservation_amount_piconero: u128,
    pub sponsor_fee_piconero: u128,
    pub user_fee_piconero: u128,
    pub reservation_nullifier: String,
    pub reservation_proof_root: String,
    pub privacy_set_size: u64,
    pub requested_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelReservationRecord {
    pub reservation_id: String,
    pub intent_id: String,
    pub attestation_id: String,
    pub channel_flow: ChannelFlow,
    pub privacy_lane: PrivacyLane,
    pub sponsor_policy: SponsorPolicy,
    pub sponsor_id: String,
    pub channel_counterparty_root: String,
    pub channel_state_root: String,
    pub channel_capacity_commitment: String,
    pub reservation_amount_piconero: u128,
    pub sponsor_fee_piconero: u128,
    pub user_fee_piconero: u128,
    pub rebate_amount_piconero: u128,
    pub reservation_nullifier: String,
    pub reservation_proof_root: String,
    pub privacy_set_size: u64,
    pub requested_at_height: u64,
    pub expires_at_height: u64,
    pub final_after_height: u64,
    pub status: ReservationStatus,
}

impl ChannelReservationRecord {
    pub fn new(
        request: &ReserveLowFeeChannelRequest,
        intent: &FeeIntentRecord,
        attestation: &PqSponsorAttestationRecord,
        config: &Config,
    ) -> Self {
        let rebate_amount_piconero = if intent.privacy_lane.requires_rebate() {
            fee_amount(request.user_fee_piconero, config.rebate_bps)
        } else {
            0
        };
        let seed = json!({
            "intent_id": request.intent_id,
            "attestation_id": request.attestation_id,
            "channel_counterparty_root": request.channel_counterparty_root,
            "channel_state_root": request.channel_state_root,
            "reservation_nullifier": request.reservation_nullifier,
            "requested_at_height": request.requested_at_height,
        });
        Self {
            reservation_id: id_from_record("LOW-FEE-CHANNEL-RESERVATION-ID", &seed),
            intent_id: request.intent_id.clone(),
            attestation_id: request.attestation_id.clone(),
            channel_flow: intent.channel_flow,
            privacy_lane: intent.privacy_lane,
            sponsor_policy: intent.sponsor_policy,
            sponsor_id: attestation.sponsor_id.clone(),
            channel_counterparty_root: request.channel_counterparty_root.clone(),
            channel_state_root: request.channel_state_root.clone(),
            channel_capacity_commitment: request.channel_capacity_commitment.clone(),
            reservation_amount_piconero: request.reservation_amount_piconero,
            sponsor_fee_piconero: request.sponsor_fee_piconero,
            user_fee_piconero: request.user_fee_piconero,
            rebate_amount_piconero,
            reservation_nullifier: request.reservation_nullifier.clone(),
            reservation_proof_root: request.reservation_proof_root.clone(),
            privacy_set_size: request.privacy_set_size,
            requested_at_height: request.requested_at_height,
            expires_at_height: request
                .requested_at_height
                .saturating_add(config.reservation_ttl_blocks),
            final_after_height: request
                .requested_at_height
                .saturating_add(config.receipt_finality_blocks),
            status: ReservationStatus::Reserved,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "intent_id": self.intent_id,
            "attestation_id": self.attestation_id,
            "channel_flow": self.channel_flow.as_str(),
            "privacy_lane": self.privacy_lane.as_str(),
            "sponsor_policy": self.sponsor_policy.as_str(),
            "sponsor_id": self.sponsor_id,
            "channel_counterparty_root": self.channel_counterparty_root,
            "channel_state_root": self.channel_state_root,
            "channel_capacity_commitment": self.channel_capacity_commitment,
            "reservation_amount_piconero": self.reservation_amount_piconero,
            "sponsor_fee_piconero": self.sponsor_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "rebate_amount_piconero": self.rebate_amount_piconero,
            "reservation_nullifier_root": root_from_record("RESERVATION-NULLIFIER", &json!({ "reservation_nullifier": self.reservation_nullifier })),
            "reservation_proof_root": self.reservation_proof_root,
            "privacy_set_size": self.privacy_set_size,
            "requested_at_height": self.requested_at_height,
            "expires_at_height": self.expires_at_height,
            "final_after_height": self.final_after_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("CHANNEL-RESERVATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSponsorReceiptRequest {
    pub reservation_id: String,
    pub receipt_issuer_id: String,
    pub receipt_nullifier: String,
    pub sponsored_fee_root: String,
    pub preconfirmation_root: String,
    pub recipient_view_root: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReceiptRecord {
    pub receipt_id: String,
    pub reservation_id: String,
    pub intent_id: String,
    pub attestation_id: String,
    pub sponsor_id: String,
    pub receipt_issuer_id: String,
    pub receipt_nullifier: String,
    pub sponsored_fee_piconero: u128,
    pub user_fee_piconero: u128,
    pub sponsored_fee_root: String,
    pub preconfirmation_root: String,
    pub recipient_view_root: String,
    pub replay_domain: String,
    pub issued_at_height: u64,
    pub final_after_height: u64,
    pub status: SponsorReceiptStatus,
}

impl SponsorReceiptRecord {
    pub fn new(
        request: &IssueSponsorReceiptRequest,
        reservation: &ChannelReservationRecord,
        config: &Config,
    ) -> Self {
        let seed = json!({
            "reservation_id": request.reservation_id,
            "receipt_issuer_id": request.receipt_issuer_id,
            "receipt_nullifier": request.receipt_nullifier,
            "sponsored_fee_root": request.sponsored_fee_root,
            "preconfirmation_root": request.preconfirmation_root,
        });
        Self {
            receipt_id: id_from_record("SPONSOR-RECEIPT-ID", &seed),
            reservation_id: request.reservation_id.clone(),
            intent_id: reservation.intent_id.clone(),
            attestation_id: reservation.attestation_id.clone(),
            sponsor_id: reservation.sponsor_id.clone(),
            receipt_issuer_id: request.receipt_issuer_id.clone(),
            receipt_nullifier: request.receipt_nullifier.clone(),
            sponsored_fee_piconero: reservation.sponsor_fee_piconero,
            user_fee_piconero: reservation.user_fee_piconero,
            sponsored_fee_root: request.sponsored_fee_root.clone(),
            preconfirmation_root: request.preconfirmation_root.clone(),
            recipient_view_root: request.recipient_view_root.clone(),
            replay_domain: config.replay_domain.clone(),
            issued_at_height: request.issued_at_height,
            final_after_height: request
                .issued_at_height
                .saturating_add(config.receipt_finality_blocks),
            status: SponsorReceiptStatus::Published,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_id": self.reservation_id,
            "intent_id": self.intent_id,
            "attestation_id": self.attestation_id,
            "sponsor_id": self.sponsor_id,
            "receipt_issuer_id": self.receipt_issuer_id,
            "receipt_nullifier_root": root_from_record("SPONSOR-RECEIPT-NULLIFIER", &json!({ "receipt_nullifier": self.receipt_nullifier })),
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "user_fee_piconero": self.user_fee_piconero,
            "sponsored_fee_root": self.sponsored_fee_root,
            "preconfirmation_root": self.preconfirmation_root,
            "recipient_view_root": self.recipient_view_root,
            "replay_domain": self.replay_domain,
            "issued_at_height": self.issued_at_height,
            "final_after_height": self.final_after_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("SPONSOR-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRebateReceiptRequest {
    pub reservation_id: String,
    pub sponsor_receipt_id: String,
    pub rebate_issuer_id: String,
    pub rebate_nullifier: String,
    pub rebate_note_commitment: String,
    pub rebate_claim_root: String,
    pub recipient_view_root: String,
    pub issued_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebateReceiptRecord {
    pub rebate_id: String,
    pub reservation_id: String,
    pub sponsor_receipt_id: String,
    pub intent_id: String,
    pub sponsor_id: String,
    pub rebate_issuer_id: String,
    pub rebate_nullifier: String,
    pub rebate_note_commitment: String,
    pub rebate_claim_root: String,
    pub recipient_view_root: String,
    pub rebate_amount_piconero: u128,
    pub expires_at_height: u64,
    pub issued_at_height: u64,
    pub status: RebateReceiptStatus,
}

impl RebateReceiptRecord {
    pub fn new(
        request: &IssueRebateReceiptRequest,
        reservation: &ChannelReservationRecord,
        sponsor_receipt: &SponsorReceiptRecord,
        config: &Config,
    ) -> Self {
        let seed = json!({
            "reservation_id": request.reservation_id,
            "sponsor_receipt_id": request.sponsor_receipt_id,
            "rebate_issuer_id": request.rebate_issuer_id,
            "rebate_nullifier": request.rebate_nullifier,
            "rebate_note_commitment": request.rebate_note_commitment,
        });
        Self {
            rebate_id: id_from_record("REBATE-RECEIPT-ID", &seed),
            reservation_id: request.reservation_id.clone(),
            sponsor_receipt_id: request.sponsor_receipt_id.clone(),
            intent_id: reservation.intent_id.clone(),
            sponsor_id: sponsor_receipt.sponsor_id.clone(),
            rebate_issuer_id: request.rebate_issuer_id.clone(),
            rebate_nullifier: request.rebate_nullifier.clone(),
            rebate_note_commitment: request.rebate_note_commitment.clone(),
            rebate_claim_root: request.rebate_claim_root.clone(),
            recipient_view_root: request.recipient_view_root.clone(),
            rebate_amount_piconero: reservation.rebate_amount_piconero,
            expires_at_height: request
                .issued_at_height
                .saturating_add(config.rebate_ttl_blocks),
            issued_at_height: request.issued_at_height,
            status: RebateReceiptStatus::Queued,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "reservation_id": self.reservation_id,
            "sponsor_receipt_id": self.sponsor_receipt_id,
            "intent_id": self.intent_id,
            "sponsor_id": self.sponsor_id,
            "rebate_issuer_id": self.rebate_issuer_id,
            "rebate_nullifier_root": root_from_record("REBATE-NULLIFIER", &json!({ "rebate_nullifier": self.rebate_nullifier })),
            "rebate_note_commitment": self.rebate_note_commitment,
            "rebate_claim_root": self.rebate_claim_root,
            "recipient_view_root": self.recipient_view_root,
            "rebate_amount_piconero": self.rebate_amount_piconero,
            "expires_at_height": self.expires_at_height,
            "issued_at_height": self.issued_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("REBATE-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitSettlementBatchRequest {
    pub batch_coordinator_id: String,
    pub reservation_ids: Vec<String>,
    pub sponsor_receipt_ids: Vec<String>,
    pub rebate_receipt_ids: Vec<String>,
    pub settlement_root: String,
    pub channel_delta_root: String,
    pub sponsor_liability_root: String,
    pub recursive_proof_root: String,
    pub batch_replay_fence: String,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatchRecord {
    pub batch_id: String,
    pub batch_coordinator_id: String,
    pub reservation_ids: Vec<String>,
    pub sponsor_receipt_ids: Vec<String>,
    pub rebate_receipt_ids: Vec<String>,
    pub reservation_root: String,
    pub sponsor_receipt_root: String,
    pub rebate_receipt_root: String,
    pub settlement_root: String,
    pub channel_delta_root: String,
    pub sponsor_liability_root: String,
    pub recursive_proof_root: String,
    pub batch_replay_fence: String,
    pub total_reserved_amount_piconero: u128,
    pub total_sponsored_fee_piconero: u128,
    pub total_user_fee_piconero: u128,
    pub total_rebate_piconero: u128,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub final_after_height: u64,
    pub status: SettlementBatchStatus,
}

impl SettlementBatchRecord {
    pub fn new(
        request: &SubmitSettlementBatchRequest,
        reservations: Vec<&ChannelReservationRecord>,
        sponsor_receipts: Vec<&SponsorReceiptRecord>,
        rebate_receipts: Vec<&RebateReceiptRecord>,
        config: &Config,
    ) -> Self {
        let reservation_root = id_merkle_root(
            "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-BATCH-RESERVATION-IDS",
            &request.reservation_ids,
        );
        let sponsor_receipt_root = id_merkle_root(
            "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-BATCH-SPONSOR-RECEIPT-IDS",
            &request.sponsor_receipt_ids,
        );
        let rebate_receipt_root = id_merkle_root(
            "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-BATCH-REBATE-RECEIPT-IDS",
            &request.rebate_receipt_ids,
        );
        let seed = json!({
            "batch_coordinator_id": request.batch_coordinator_id,
            "reservation_root": reservation_root,
            "sponsor_receipt_root": sponsor_receipt_root,
            "rebate_receipt_root": rebate_receipt_root,
            "settlement_root": request.settlement_root,
            "channel_delta_root": request.channel_delta_root,
            "batch_replay_fence": request.batch_replay_fence,
        });
        Self {
            batch_id: id_from_record("SETTLEMENT-BATCH-ID", &seed),
            batch_coordinator_id: request.batch_coordinator_id.clone(),
            reservation_ids: request.reservation_ids.clone(),
            sponsor_receipt_ids: request.sponsor_receipt_ids.clone(),
            rebate_receipt_ids: request.rebate_receipt_ids.clone(),
            reservation_root,
            sponsor_receipt_root,
            rebate_receipt_root,
            settlement_root: request.settlement_root.clone(),
            channel_delta_root: request.channel_delta_root.clone(),
            sponsor_liability_root: request.sponsor_liability_root.clone(),
            recursive_proof_root: request.recursive_proof_root.clone(),
            batch_replay_fence: request.batch_replay_fence.clone(),
            total_reserved_amount_piconero: reservations
                .iter()
                .map(|reservation| reservation.reservation_amount_piconero)
                .sum(),
            total_sponsored_fee_piconero: sponsor_receipts
                .iter()
                .map(|receipt| receipt.sponsored_fee_piconero)
                .sum(),
            total_user_fee_piconero: reservations
                .iter()
                .map(|reservation| reservation.user_fee_piconero)
                .sum(),
            total_rebate_piconero: rebate_receipts
                .iter()
                .map(|receipt| receipt.rebate_amount_piconero)
                .sum(),
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request
                .submitted_at_height
                .saturating_add(config.settlement_ttl_blocks),
            final_after_height: request
                .submitted_at_height
                .saturating_add(config.receipt_finality_blocks),
            status: SettlementBatchStatus::Submitted,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "batch_coordinator_id": self.batch_coordinator_id,
            "reservation_root": self.reservation_root,
            "sponsor_receipt_root": self.sponsor_receipt_root,
            "rebate_receipt_root": self.rebate_receipt_root,
            "settlement_root": self.settlement_root,
            "channel_delta_root": self.channel_delta_root,
            "sponsor_liability_root": self.sponsor_liability_root,
            "recursive_proof_root": self.recursive_proof_root,
            "batch_replay_fence": self.batch_replay_fence,
            "total_reserved_amount_piconero": self.total_reserved_amount_piconero,
            "total_sponsored_fee_piconero": self.total_sponsored_fee_piconero,
            "total_user_fee_piconero": self.total_user_fee_piconero,
            "total_rebate_piconero": self.total_rebate_piconero,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "final_after_height": self.final_after_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("SETTLEMENT-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayFenceRecord {
    pub fence_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub nullifier: String,
    pub replay_domain: String,
    pub observed_at_height: u64,
}

impl ReplayFenceRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        nullifier: &str,
        replay_domain: &str,
        observed_at_height: u64,
    ) -> Self {
        let record = json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "nullifier": nullifier,
            "replay_domain": replay_domain,
            "observed_at_height": observed_at_height,
        });
        Self {
            fence_id: id_from_record("REPLAY-FENCE-ID", &record),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            nullifier: nullifier.to_string(),
            replay_domain: replay_domain.to_string(),
            observed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "nullifier_root": root_from_record("REPLAY-FENCE-NULLIFIER", &json!({ "nullifier": self.nullifier })),
            "replay_domain": self.replay_domain,
            "observed_at_height": self.observed_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub subject_root: String,
    pub disclosed: Value,
    pub disclosed_root: String,
    pub recorded_at_height: u64,
}

impl RootsOnlyPublicRecord {
    pub fn new(
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
        recorded_at_height: u64,
    ) -> Self {
        let disclosed = project_fields(subject_record, disclosed_fields);
        let subject_root = public_record_root(subject_record);
        let disclosed_root = root_from_record("DISCLOSED-PUBLIC-FIELDS", &disclosed);
        let seed = json!({
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "subject_root": subject_root,
            "disclosed_root": disclosed_root,
            "recorded_at_height": recorded_at_height,
        });
        Self {
            record_id: id_from_record("ROOTS-ONLY-PUBLIC-RECORD-ID", &seed),
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            subject_root,
            disclosed,
            disclosed_root,
            recorded_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "subject_root": self.subject_root,
            "disclosed": self.disclosed,
            "disclosed_root": self.disclosed_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub intents: BTreeMap<String, FeeIntentRecord>,
    pub pq_attestations: BTreeMap<String, PqSponsorAttestationRecord>,
    pub reservations: BTreeMap<String, ChannelReservationRecord>,
    pub settlement_batches: BTreeMap<String, SettlementBatchRecord>,
    pub sponsor_receipts: BTreeMap<String, SponsorReceiptRecord>,
    pub rebate_receipts: BTreeMap<String, RebateReceiptRecord>,
    pub replay_fences: BTreeMap<String, ReplayFenceRecord>,
    pub consumed_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub events: Vec<Value>,
    pub counters: Counters,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> Self {
        let mut state = Self {
            height: config.genesis_height,
            config,
            intents: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            sponsor_receipts: BTreeMap::new(),
            rebate_receipts: BTreeMap::new(),
            replay_fences: BTreeMap::new(),
            consumed_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
            events: Vec::new(),
            counters: Counters::default(),
        };
        state.refresh_counters();
        state.refresh_public_records();
        state
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        self.refresh_public_records();
    }

    pub fn submit_encrypted_fee_intent(
        &mut self,
        request: SubmitEncryptedFeeIntentRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("intent_owner_root", &request.intent_owner_root)?;
        require_field("channel_commitment", &request.channel_commitment)?;
        require_field("amount_commitment", &request.amount_commitment)?;
        require_field("encrypted_intent_root", &request.encrypted_intent_root)?;
        require_field("intent_ciphertext_root", &request.intent_ciphertext_root)?;
        require_field("spend_nullifier", &request.spend_nullifier)?;
        require_field("replay_fence", &request.replay_fence)?;
        require(
            self.intents.len() < self.config.max_intents,
            "intent capacity reached",
        )?;
        require(
            request.expires_at_height > request.opens_at_height,
            "intent expiry must be after open height",
        )?;
        require(
            request.expires_at_height >= self.height,
            "intent is already expired",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small",
        )?;
        require(
            request.max_user_fee_bps <= self.config.max_user_fee_bps,
            "user fee cap exceeds config",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.spend_nullifier),
            "intent spend nullifier replay",
        )?;
        let mut record = FeeIntentRecord::new(&request, &self.config, self.height);
        if self.consumed_nullifiers.contains(&record.replay_fence) {
            record.status = IntentStatus::Replayed;
        }
        let intent_id = record.intent_id.clone();
        insert_unique(&mut self.intents, intent_id.clone(), record, "intent")?;
        self.insert_replay_fence(
            "fee_intent",
            &intent_id,
            &request.spend_nullifier,
            self.height,
        )?;
        self.push_event(
            "fee_intent_submitted",
            &intent_id,
            json!({ "intent_id": intent_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(intent_id)
    }

    pub fn submit_pq_sponsor_attestation(
        &mut self,
        request: SubmitPqSponsorAttestationRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("intent_id", &request.intent_id)?;
        require_field("sponsor_id", &request.sponsor_id)?;
        require_field("sponsor_pool_root", &request.sponsor_pool_root)?;
        require_field("sponsor_reserve_root", &request.sponsor_reserve_root)?;
        require_field("pq_attestation_root", &request.pq_attestation_root)?;
        require_field("pq_signature_root", &request.pq_signature_root)?;
        require_field("attestation_nullifier", &request.attestation_nullifier)?;
        require(
            self.pq_attestations.len() < self.config.max_attestations,
            "attestation capacity reached",
        )?;
        require(
            request.reserve_coverage_bps >= self.config.min_sponsor_reserve_bps,
            "sponsor reserve coverage too low",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set too small",
        )?;
        require(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits too low",
        )?;
        require(
            request.expires_at_height >= self.height,
            "attestation is already expired",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.attestation_nullifier),
            "attestation nullifier replay",
        )?;
        let intent = self
            .intents
            .get_mut(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?;
        require(intent.status.live(), "intent is not live")?;
        require(
            request.sponsor_fee_limit_piconero >= intent.expected_sponsor_fee_piconero,
            "sponsor fee limit below intent expectation",
        )?;
        let mut record = PqSponsorAttestationRecord::new(&request);
        record.status = PqAttestationStatus::Accepted;
        let attestation_id = record.attestation_id.clone();
        intent.status = IntentStatus::PqAttested;
        insert_unique(
            &mut self.pq_attestations,
            attestation_id.clone(),
            record,
            "pq sponsor attestation",
        )?;
        self.insert_replay_fence(
            "pq_sponsor_attestation",
            &attestation_id,
            &request.attestation_nullifier,
            self.height,
        )?;
        self.push_event(
            "pq_sponsor_attestation_accepted",
            &attestation_id,
            json!({ "intent_id": request.intent_id, "attestation_id": attestation_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(attestation_id)
    }

    pub fn reserve_low_fee_channel(
        &mut self,
        request: ReserveLowFeeChannelRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("intent_id", &request.intent_id)?;
        require_field("attestation_id", &request.attestation_id)?;
        require_field("channel_state_root", &request.channel_state_root)?;
        require_field("reservation_nullifier", &request.reservation_nullifier)?;
        require_field("reservation_proof_root", &request.reservation_proof_root)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "reservation capacity reached",
        )?;
        require(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "reservation privacy set too small",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.reservation_nullifier),
            "reservation nullifier replay",
        )?;
        let intent = self
            .intents
            .get(&request.intent_id)
            .ok_or_else(|| "intent not found".to_string())?
            .clone();
        let attestation = self
            .pq_attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "attestation not found".to_string())?
            .clone();
        require(attestation.status.usable(), "attestation is not usable")?;
        require(
            attestation.intent_id == request.intent_id,
            "attestation intent mismatch",
        )?;
        require(intent.status.live(), "intent is not live")?;
        require(
            request.sponsor_fee_piconero <= attestation.sponsor_fee_limit_piconero,
            "sponsor fee exceeds attestation limit",
        )?;
        require(
            request.user_fee_piconero <= intent.expected_user_fee_piconero,
            "user fee exceeds intent cap",
        )?;
        let record = ChannelReservationRecord::new(&request, &intent, &attestation, &self.config);
        let reservation_id = record.reservation_id.clone();
        insert_unique(
            &mut self.reservations,
            reservation_id.clone(),
            record,
            "channel reservation",
        )?;
        if let Some(intent) = self.intents.get_mut(&request.intent_id) {
            intent.status = IntentStatus::Reserved;
        }
        self.insert_replay_fence(
            "channel_reservation",
            &reservation_id,
            &request.reservation_nullifier,
            self.height,
        )?;
        self.push_event(
            "low_fee_channel_reserved",
            &reservation_id,
            json!({ "intent_id": request.intent_id, "reservation_id": reservation_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(reservation_id)
    }

    pub fn issue_sponsor_receipt(
        &mut self,
        request: IssueSponsorReceiptRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("reservation_id", &request.reservation_id)?;
        require_field("receipt_issuer_id", &request.receipt_issuer_id)?;
        require_field("receipt_nullifier", &request.receipt_nullifier)?;
        require_field("sponsored_fee_root", &request.sponsored_fee_root)?;
        require_field("preconfirmation_root", &request.preconfirmation_root)?;
        require(
            self.sponsor_receipts.len() < self.config.max_sponsor_receipts,
            "sponsor receipt capacity reached",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.receipt_nullifier),
            "sponsor receipt nullifier replay",
        )?;
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?
            .clone();
        require(reservation.status.live(), "reservation is not live")?;
        let record = SponsorReceiptRecord::new(&request, &reservation, &self.config);
        let receipt_id = record.receipt_id.clone();
        insert_unique(
            &mut self.sponsor_receipts,
            receipt_id.clone(),
            record,
            "sponsor receipt",
        )?;
        if let Some(reservation) = self.reservations.get_mut(&request.reservation_id) {
            reservation.status = ReservationStatus::ReceiptIssued;
        }
        if let Some(intent) = self.intents.get_mut(&reservation.intent_id) {
            intent.status = IntentStatus::Receipted;
        }
        self.insert_replay_fence(
            "sponsor_receipt",
            &receipt_id,
            &request.receipt_nullifier,
            self.height,
        )?;
        self.push_event(
            "sponsor_receipt_issued",
            &receipt_id,
            json!({ "reservation_id": request.reservation_id, "receipt_id": receipt_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(receipt_id)
    }

    pub fn issue_rebate_receipt(
        &mut self,
        request: IssueRebateReceiptRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("reservation_id", &request.reservation_id)?;
        require_field("sponsor_receipt_id", &request.sponsor_receipt_id)?;
        require_field("rebate_issuer_id", &request.rebate_issuer_id)?;
        require_field("rebate_nullifier", &request.rebate_nullifier)?;
        require_field("rebate_note_commitment", &request.rebate_note_commitment)?;
        require(
            self.rebate_receipts.len() < self.config.max_rebate_receipts,
            "rebate receipt capacity reached",
        )?;
        require(
            !self.consumed_nullifiers.contains(&request.rebate_nullifier),
            "rebate nullifier replay",
        )?;
        let reservation = self
            .reservations
            .get(&request.reservation_id)
            .ok_or_else(|| "reservation not found".to_string())?
            .clone();
        let sponsor_receipt = self
            .sponsor_receipts
            .get(&request.sponsor_receipt_id)
            .ok_or_else(|| "sponsor receipt not found".to_string())?
            .clone();
        require(
            sponsor_receipt.reservation_id == request.reservation_id,
            "sponsor receipt reservation mismatch",
        )?;
        require(
            reservation.rebate_amount_piconero > 0,
            "reservation has no rebate",
        )?;
        let mut record =
            RebateReceiptRecord::new(&request, &reservation, &sponsor_receipt, &self.config);
        record.status = RebateReceiptStatus::Published;
        let rebate_id = record.rebate_id.clone();
        insert_unique(
            &mut self.rebate_receipts,
            rebate_id.clone(),
            record,
            "rebate receipt",
        )?;
        self.insert_replay_fence(
            "rebate_receipt",
            &rebate_id,
            &request.rebate_nullifier,
            self.height,
        )?;
        self.push_event(
            "rebate_receipt_issued",
            &rebate_id,
            json!({ "reservation_id": request.reservation_id, "rebate_id": rebate_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(rebate_id)
    }

    pub fn submit_settlement_batch(
        &mut self,
        request: SubmitSettlementBatchRequest,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<String> {
        require_field("batch_coordinator_id", &request.batch_coordinator_id)?;
        require_field("settlement_root", &request.settlement_root)?;
        require_field("channel_delta_root", &request.channel_delta_root)?;
        require_field("recursive_proof_root", &request.recursive_proof_root)?;
        require_field("batch_replay_fence", &request.batch_replay_fence)?;
        require(
            self.settlement_batches.len() < self.config.max_settlement_batches,
            "settlement batch capacity reached",
        )?;
        require(
            !request.reservation_ids.is_empty(),
            "settlement batch requires reservations",
        )?;
        require(
            request.reservation_ids.len() == request.sponsor_receipt_ids.len(),
            "settlement batch reservation and sponsor receipt count mismatch",
        )?;
        require(
            !self
                .consumed_nullifiers
                .contains(&request.batch_replay_fence),
            "settlement batch replay fence already consumed",
        )?;
        let reservations = request
            .reservation_ids
            .iter()
            .map(|id| {
                self.reservations
                    .get(id)
                    .ok_or_else(|| format!("reservation not found: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sponsor_receipts = request
            .sponsor_receipt_ids
            .iter()
            .map(|id| {
                self.sponsor_receipts
                    .get(id)
                    .ok_or_else(|| format!("sponsor receipt not found: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rebate_receipts = request
            .rebate_receipt_ids
            .iter()
            .map(|id| {
                self.rebate_receipts
                    .get(id)
                    .ok_or_else(|| format!("rebate receipt not found: {id}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for reservation in &reservations {
            require(reservation.status.live(), "reservation is not live")?;
            require(
                reservation.privacy_set_size >= self.config.min_privacy_set_size,
                "reservation privacy set too small",
            )?;
        }
        require(
            reservations.len() as u64 >= self.config.min_batch_privacy_set_size.min(1),
            "batch privacy set below configured floor",
        )?;
        let record = SettlementBatchRecord::new(
            &request,
            reservations,
            sponsor_receipts,
            rebate_receipts,
            &self.config,
        );
        let batch_id = record.batch_id.clone();
        insert_unique(
            &mut self.settlement_batches,
            batch_id.clone(),
            record,
            "settlement batch",
        )?;
        for id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(id) {
                reservation.status = ReservationStatus::Batched;
            }
        }
        for id in &request.sponsor_receipt_ids {
            if let Some(receipt) = self.sponsor_receipts.get_mut(id) {
                receipt.status = SponsorReceiptStatus::Finalized;
            }
        }
        for id in &request.rebate_receipt_ids {
            if let Some(receipt) = self.rebate_receipts.get_mut(id) {
                receipt.status = RebateReceiptStatus::Claimed;
            }
        }
        self.insert_replay_fence(
            "settlement_batch",
            &batch_id,
            &request.batch_replay_fence,
            self.height,
        )?;
        self.push_event(
            "settlement_batch_submitted",
            &batch_id,
            json!({ "batch_id": batch_id }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(batch_id)
    }

    pub fn finalize_settlement_batch(
        &mut self,
        batch_id: &str,
        finalized_height: u64,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<()> {
        let batch = self
            .settlement_batches
            .get_mut(batch_id)
            .ok_or_else(|| "settlement batch not found".to_string())?;
        require(
            batch.status.finalizable(),
            "settlement batch is not finalizable",
        )?;
        require(
            finalized_height >= batch.final_after_height,
            "settlement batch is not final yet",
        )?;
        batch.status = SettlementBatchStatus::Settled;
        let reservation_ids = batch.reservation_ids.clone();
        let sponsor_receipt_ids = batch.sponsor_receipt_ids.clone();
        let rebate_receipt_ids = batch.rebate_receipt_ids.clone();
        for id in reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(&id) {
                reservation.status = ReservationStatus::Settled;
                if let Some(intent) = self.intents.get_mut(&reservation.intent_id) {
                    intent.status = IntentStatus::Settled;
                }
            }
        }
        for id in sponsor_receipt_ids {
            if let Some(receipt) = self.sponsor_receipts.get_mut(&id) {
                receipt.status = SponsorReceiptStatus::Settled;
            }
        }
        for id in rebate_receipt_ids {
            if let Some(receipt) = self.rebate_receipts.get_mut(&id) {
                receipt.status = RebateReceiptStatus::Settled;
            }
        }
        self.push_event(
            "settlement_batch_finalized",
            batch_id,
            json!({ "batch_id": batch_id, "finalized_height": finalized_height }),
        );
        self.refresh_counters();
        self.refresh_public_records();
        Ok(())
    }

    pub fn expire_height(&mut self, height: u64) {
        self.height = height;
        for intent in self.intents.values_mut() {
            if intent.status.live() && intent.expires_at_height < height {
                intent.status = IntentStatus::Expired;
            }
        }
        for attestation in self.pq_attestations.values_mut() {
            if attestation.status.usable() && attestation.expires_at_height < height {
                attestation.status = PqAttestationStatus::Expired;
            }
        }
        for reservation in self.reservations.values_mut() {
            if reservation.status.live() && reservation.expires_at_height < height {
                reservation.status = ReservationStatus::Expired;
            }
        }
        for batch in self.settlement_batches.values_mut() {
            if batch.status.finalizable() && batch.expires_at_height < height {
                batch.status = SettlementBatchStatus::Expired;
            }
        }
        for receipt in self.rebate_receipts.values_mut() {
            if matches!(
                receipt.status,
                RebateReceiptStatus::Queued
                    | RebateReceiptStatus::Published
                    | RebateReceiptStatus::Claimed
            ) && receipt.expires_at_height < height
            {
                receipt.status = RebateReceiptStatus::Expired;
            }
        }
        self.push_event(
            "runtime_height_expired",
            "height",
            json!({ "height": height }),
        );
        self.refresh_counters();
        self.refresh_public_records();
    }

    pub fn roots(&self) -> Roots {
        let intent_records = map_records(&self.intents, FeeIntentRecord::public_record);
        let live_intent_records = self
            .intents
            .values()
            .filter(|intent| intent.status.live())
            .map(FeeIntentRecord::public_record)
            .collect::<Vec<_>>();
        let attestation_records = map_records(
            &self.pq_attestations,
            PqSponsorAttestationRecord::public_record,
        );
        let accepted_attestation_records = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.status.usable())
            .map(PqSponsorAttestationRecord::public_record)
            .collect::<Vec<_>>();
        let reservation_records =
            map_records(&self.reservations, ChannelReservationRecord::public_record);
        let live_reservation_records = self
            .reservations
            .values()
            .filter(|reservation| reservation.status.live())
            .map(ChannelReservationRecord::public_record)
            .collect::<Vec<_>>();
        let batch_records = map_records(
            &self.settlement_batches,
            SettlementBatchRecord::public_record,
        );
        let pending_batch_records = self
            .settlement_batches
            .values()
            .filter(|batch| batch.status.finalizable())
            .map(SettlementBatchRecord::public_record)
            .collect::<Vec<_>>();
        let sponsor_receipt_records =
            map_records(&self.sponsor_receipts, SponsorReceiptRecord::public_record);
        let finalized_sponsor_receipt_records = self
            .sponsor_receipts
            .values()
            .filter(|receipt| {
                matches!(
                    receipt.status,
                    SponsorReceiptStatus::Finalized | SponsorReceiptStatus::Settled
                )
            })
            .map(SponsorReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let rebate_receipt_records =
            map_records(&self.rebate_receipts, RebateReceiptRecord::public_record);
        let claimable_rebate_records = self
            .rebate_receipts
            .values()
            .filter(|receipt| {
                matches!(
                    receipt.status,
                    RebateReceiptStatus::Published | RebateReceiptStatus::Claimed
                )
            })
            .map(RebateReceiptRecord::public_record)
            .collect::<Vec<_>>();
        let replay_records = map_records(&self.replay_fences, ReplayFenceRecord::public_record);
        let sponsor_privacy_records = self
            .pq_attestations
            .values()
            .map(|attestation| {
                json!({
                    "attestation_id": attestation.attestation_id,
                    "sponsor_pool_root": attestation.sponsor_pool_root,
                    "sponsor_reserve_root": attestation.sponsor_reserve_root,
                    "sponsor_liability_root": attestation.sponsor_liability_root,
                    "pq_public_key_root": attestation.pq_public_key_root,
                })
            })
            .chain(self.sponsor_receipts.values().map(|receipt| {
                json!({
                    "receipt_id": receipt.receipt_id,
                    "sponsored_fee_root": receipt.sponsored_fee_root,
                    "recipient_view_root": receipt.recipient_view_root,
                })
            }))
            .collect::<Vec<_>>();
        let channel_privacy_records = self
            .intents
            .values()
            .map(|intent| {
                json!({
                    "intent_id": intent.intent_id,
                    "channel_commitment": intent.channel_commitment,
                    "monero_tx_commitment": intent.monero_tx_commitment,
                    "amount_commitment": intent.amount_commitment,
                    "view_tag_root": intent.view_tag_root,
                })
            })
            .chain(self.reservations.values().map(|reservation| {
                json!({
                    "reservation_id": reservation.reservation_id,
                    "channel_state_root": reservation.channel_state_root,
                    "channel_capacity_commitment": reservation.channel_capacity_commitment,
                    "reservation_proof_root": reservation.reservation_proof_root,
                })
            }))
            .collect::<Vec<_>>();
        let fee_liability_records = self
            .reservations
            .values()
            .map(|reservation| {
                json!({
                    "reservation_id": reservation.reservation_id,
                    "sponsor_id": reservation.sponsor_id,
                    "sponsor_fee_piconero": reservation.sponsor_fee_piconero,
                    "user_fee_piconero": reservation.user_fee_piconero,
                    "rebate_amount_piconero": reservation.rebate_amount_piconero,
                    "status": reservation.status.as_str(),
                })
            })
            .collect::<Vec<_>>();
        let public_records =
            map_records(&self.public_records, RootsOnlyPublicRecord::public_record);

        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters.state_root(),
            intent_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-INTENTS",
                &intent_records,
            ),
            live_intent_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-LIVE-INTENTS",
                &live_intent_records,
            ),
            pq_attestation_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-PQ-ATTESTATIONS",
                &attestation_records,
            ),
            accepted_pq_attestation_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-ACCEPTED-PQ-ATTESTATIONS",
                &accepted_attestation_records,
            ),
            reservation_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-RESERVATIONS",
                &reservation_records,
            ),
            live_reservation_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-LIVE-RESERVATIONS",
                &live_reservation_records,
            ),
            settlement_batch_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-SETTLEMENT-BATCHES",
                &batch_records,
            ),
            pending_settlement_batch_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-PENDING-SETTLEMENT-BATCHES",
                &pending_batch_records,
            ),
            sponsor_receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-SPONSOR-RECEIPTS",
                &sponsor_receipt_records,
            ),
            finalized_sponsor_receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-FINALIZED-SPONSOR-RECEIPTS",
                &finalized_sponsor_receipt_records,
            ),
            rebate_receipt_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-REBATE-RECEIPTS",
                &rebate_receipt_records,
            ),
            claimable_rebate_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-CLAIMABLE-REBATES",
                &claimable_rebate_records,
            ),
            consumed_nullifier_root: set_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-CONSUMED-NULLIFIERS",
                &self.consumed_nullifiers,
            ),
            replay_fence_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-REPLAY-FENCES",
                &replay_records,
            ),
            sponsor_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-SPONSOR-PRIVACY",
                &sponsor_privacy_records,
            ),
            channel_privacy_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-CHANNEL-PRIVACY",
                &channel_privacy_records,
            ),
            fee_liability_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-FEE-LIABILITY",
                &fee_liability_records,
            ),
            public_record_root: merkle_root(
                "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-PUBLIC-RECORDS",
                &public_records,
            ),
            event_root: merkle_root("MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-EVENTS", &self.events),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "config_root": roots.config_root,
            "counters_root": roots.counters_root,
            "roots_root": roots.state_root(),
            "roots": roots.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        set_json_field(&mut record, "state_root", json!(self.state_root()));
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn insert_replay_fence(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        nullifier: &str,
        observed_at_height: u64,
    ) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<()> {
        require(
            self.replay_fences.len() < self.config.max_replay_fences,
            "replay fence capacity reached",
        )?;
        require(
            !self.consumed_nullifiers.contains(nullifier),
            "nullifier already consumed",
        )?;
        let fence = ReplayFenceRecord::new(
            subject_kind,
            subject_id,
            nullifier,
            &self.config.replay_domain,
            observed_at_height,
        );
        self.consumed_nullifiers.insert(nullifier.to_string());
        self.replay_fences.insert(fence.fence_id.clone(), fence);
        Ok(())
    }

    fn push_event(&mut self, kind: &str, record_id: &str, payload: Value) {
        let event_id = domain_hash(
            "MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind),
                HashPart::Str(record_id),
                HashPart::Int(self.events.len() as i128),
            ],
            32,
        );
        self.events.push(json!({
            "event_id": event_id,
            "kind": kind,
            "record_id": record_id,
            "payload_root": root_from_record("EVENT-PAYLOAD", &payload),
        }));
    }

    fn refresh_counters(&mut self) {
        let encrypted_intents_submitted = self.intents.len() as u64;
        let live_intents = self
            .intents
            .values()
            .filter(|intent| intent.status.live())
            .count() as u64;
        let replayed_intents = self
            .intents
            .values()
            .filter(|intent| intent.status == IntentStatus::Replayed)
            .count() as u64;
        let pq_attestations_submitted = self.pq_attestations.len() as u64;
        let pq_attestations_accepted = self
            .pq_attestations
            .values()
            .filter(|attestation| attestation.status == PqAttestationStatus::Accepted)
            .count() as u64;
        let reservations_opened = self.reservations.len() as u64;
        let reservations_live = self
            .reservations
            .values()
            .filter(|reservation| reservation.status.live())
            .count() as u64;
        let reservations_settled = self
            .reservations
            .values()
            .filter(|reservation| reservation.status == ReservationStatus::Settled)
            .count() as u64;
        let settlement_batches = self.settlement_batches.len() as u64;
        let settlement_batches_finalized = self
            .settlement_batches
            .values()
            .filter(|batch| batch.status == SettlementBatchStatus::Settled)
            .count() as u64;
        let sponsor_receipts_issued = self.sponsor_receipts.len() as u64;
        let sponsor_receipts_finalized = self
            .sponsor_receipts
            .values()
            .filter(|receipt| {
                matches!(
                    receipt.status,
                    SponsorReceiptStatus::Finalized | SponsorReceiptStatus::Settled
                )
            })
            .count() as u64;
        let rebate_receipts_issued = self.rebate_receipts.len() as u64;
        let rebate_receipts_claimed = self
            .rebate_receipts
            .values()
            .filter(|receipt| receipt.status == RebateReceiptStatus::Claimed)
            .count() as u64;
        let rebate_receipts_settled = self
            .rebate_receipts
            .values()
            .filter(|receipt| receipt.status == RebateReceiptStatus::Settled)
            .count() as u64;
        let sponsored_fee_piconero = self
            .sponsor_receipts
            .values()
            .map(|receipt| receipt.sponsored_fee_piconero)
            .sum();
        let user_fee_piconero = self
            .reservations
            .values()
            .map(|reservation| reservation.user_fee_piconero)
            .sum();
        let rebated_fee_piconero = self
            .rebate_receipts
            .values()
            .map(|receipt| receipt.rebate_amount_piconero)
            .sum();
        let reserved_fee_piconero = self
            .reservations
            .values()
            .filter(|reservation| reservation.status.live())
            .map(|reservation| {
                reservation
                    .sponsor_fee_piconero
                    .saturating_add(reservation.user_fee_piconero)
            })
            .sum();
        let settled_fee_piconero = self
            .settlement_batches
            .values()
            .filter(|batch| batch.status == SettlementBatchStatus::Settled)
            .map(|batch| {
                batch
                    .total_sponsored_fee_piconero
                    .saturating_add(batch.total_user_fee_piconero)
            })
            .sum();
        let reserved_channel_amount_piconero = self
            .reservations
            .values()
            .filter(|reservation| reservation.status.live())
            .map(|reservation| reservation.reservation_amount_piconero)
            .sum();
        let settled_channel_amount_piconero = self
            .reservations
            .values()
            .filter(|reservation| reservation.status == ReservationStatus::Settled)
            .map(|reservation| reservation.reservation_amount_piconero)
            .sum();
        self.counters = Counters {
            encrypted_intents_submitted,
            live_intents,
            replayed_intents,
            pq_attestations_submitted,
            pq_attestations_accepted,
            reservations_opened,
            reservations_live,
            reservations_settled,
            settlement_batches,
            settlement_batches_finalized,
            sponsor_receipts_issued,
            sponsor_receipts_finalized,
            rebate_receipts_issued,
            rebate_receipts_claimed,
            rebate_receipts_settled,
            replay_fences: self.replay_fences.len() as u64,
            consumed_nullifiers: self.consumed_nullifiers.len() as u64,
            sponsored_fee_piconero,
            user_fee_piconero,
            rebated_fee_piconero,
            reserved_fee_piconero,
            settled_fee_piconero,
            reserved_channel_amount_piconero,
            settled_channel_amount_piconero,
            public_records: self.public_records.len() as u64,
        };
    }

    fn refresh_public_records(&mut self) {
        let mut records = Vec::new();
        records.push((
            "config".to_string(),
            "config".to_string(),
            self.config.public_record(),
            vec!["protocol_version", "asset_id", "fee_asset_id", "roots_only"],
        ));
        for intent in self.intents.values() {
            records.push((
                "encrypted_fee_intent".to_string(),
                intent.intent_id.clone(),
                intent.public_record(),
                vec![
                    "channel_flow",
                    "privacy_lane",
                    "sponsor_policy",
                    "fee_budget_piconero",
                    "effective_user_fee_bps",
                    "expires_at_height",
                    "status",
                ],
            ));
        }
        for attestation in self.pq_attestations.values() {
            records.push((
                "pq_sponsor_attestation".to_string(),
                attestation.attestation_id.clone(),
                attestation.public_record(),
                vec![
                    "intent_id",
                    "sponsor_id",
                    "reserve_coverage_bps",
                    "privacy_set_size",
                    "pq_security_bits",
                    "status",
                ],
            ));
        }
        for reservation in self.reservations.values() {
            records.push((
                "low_fee_channel_reservation".to_string(),
                reservation.reservation_id.clone(),
                reservation.public_record(),
                vec![
                    "intent_id",
                    "attestation_id",
                    "channel_flow",
                    "privacy_lane",
                    "reservation_amount_piconero",
                    "sponsor_fee_piconero",
                    "user_fee_piconero",
                    "rebate_amount_piconero",
                    "expires_at_height",
                    "status",
                ],
            ));
        }
        for receipt in self.sponsor_receipts.values() {
            records.push((
                "sponsor_receipt".to_string(),
                receipt.receipt_id.clone(),
                receipt.public_record(),
                vec![
                    "reservation_id",
                    "intent_id",
                    "sponsor_id",
                    "sponsored_fee_piconero",
                    "final_after_height",
                    "status",
                ],
            ));
        }
        for receipt in self.rebate_receipts.values() {
            records.push((
                "rebate_receipt".to_string(),
                receipt.rebate_id.clone(),
                receipt.public_record(),
                vec![
                    "reservation_id",
                    "sponsor_receipt_id",
                    "rebate_amount_piconero",
                    "expires_at_height",
                    "status",
                ],
            ));
        }
        for batch in self.settlement_batches.values() {
            records.push((
                "settlement_batch".to_string(),
                batch.batch_id.clone(),
                batch.public_record(),
                vec![
                    "batch_coordinator_id",
                    "reservation_root",
                    "sponsor_receipt_root",
                    "rebate_receipt_root",
                    "total_reserved_amount_piconero",
                    "total_sponsored_fee_piconero",
                    "status",
                ],
            ));
        }
        for fence in self.replay_fences.values() {
            records.push((
                "replay_fence".to_string(),
                fence.fence_id.clone(),
                fence.public_record(),
                vec![
                    "subject_kind",
                    "subject_id",
                    "nullifier_root",
                    "replay_domain",
                    "observed_at_height",
                ],
            ));
        }
        self.public_records.clear();
        for (subject_kind, subject_id, subject_record, disclosed_fields) in records {
            self.insert_public_record(
                &subject_kind,
                &subject_id,
                &subject_record,
                &disclosed_fields,
            );
        }
        self.counters.public_records = self.public_records.len() as u64;
    }

    fn insert_public_record(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        subject_record: &Value,
        disclosed_fields: &[&str],
    ) {
        if self.public_records.len() >= self.config.max_public_records {
            return;
        }
        let record = RootsOnlyPublicRecord::new(
            subject_kind,
            subject_id,
            subject_record,
            disclosed_fields,
            self.height,
        );
        self.public_records.insert(record.record_id.clone(), record);
    }
}

pub fn monero_l2_private_fee_sponsor_channel_runtime_devnet() -> State {
    State::devnet()
}

pub fn monero_l2_private_fee_sponsor_channel_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_private_fee_sponsor_channel_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn monero_l2_private_fee_sponsor_channel_runtime_roots(state: &State) -> Roots {
    state.roots()
}

pub fn monero_l2_private_fee_sponsor_channel_runtime_state_root_from_record(
    record: &Value,
) -> String {
    state_root_from_record(record)
}

pub fn encrypted_fee_intent_id(
    request: &SubmitEncryptedFeeIntentRequest,
    config: &Config,
    height: u64,
) -> String {
    FeeIntentRecord::new(request, config, height).intent_id
}

pub fn pq_sponsor_attestation_id(request: &SubmitPqSponsorAttestationRequest) -> String {
    PqSponsorAttestationRecord::new(request).attestation_id
}

pub fn low_fee_channel_reservation_id(
    request: &ReserveLowFeeChannelRequest,
    intent: &FeeIntentRecord,
    attestation: &PqSponsorAttestationRecord,
    config: &Config,
) -> String {
    ChannelReservationRecord::new(request, intent, attestation, config).reservation_id
}

pub fn sponsor_receipt_id(
    request: &IssueSponsorReceiptRequest,
    reservation: &ChannelReservationRecord,
    config: &Config,
) -> String {
    SponsorReceiptRecord::new(request, reservation, config).receipt_id
}

pub fn rebate_receipt_id(
    request: &IssueRebateReceiptRequest,
    reservation: &ChannelReservationRecord,
    sponsor_receipt: &SponsorReceiptRecord,
    config: &Config,
) -> String {
    RebateReceiptRecord::new(request, reservation, sponsor_receipt, config).rebate_id
}

pub fn settlement_batch_id(
    request: &SubmitSettlementBatchRequest,
    reservations: Vec<&ChannelReservationRecord>,
    sponsor_receipts: Vec<&SponsorReceiptRecord>,
    rebate_receipts: Vec<&RebateReceiptRecord>,
    config: &Config,
) -> String {
    SettlementBatchRecord::new(
        request,
        reservations,
        sponsor_receipts,
        rebate_receipts,
        config,
    )
    .batch_id
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn payload_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL:{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    root_from_record("PUBLIC-RECORD", record)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PRIVATE-FEE-SPONSOR-CHANNEL:{domain}"),
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

fn id_merkle_root(domain: &str, ids: &[String]) -> String {
    let leaves = ids.iter().map(|id| json!({ "id": id })).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Vec<Value>
where
    F: Fn(&T) -> Value,
{
    map.iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>()
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn project_fields(record: &Value, fields: &[&str]) -> Value {
    let mut projected = serde_json::Map::new();
    if let Some(object) = record.as_object() {
        for field in fields {
            if let Some(value) = object.get(*field) {
                projected.insert((*field).to_string(), value.clone());
            }
        }
    }
    Value::Object(projected)
}

fn fee_amount(amount: u128, fee_bps: u64) -> u128 {
    amount.saturating_mul(fee_bps as u128)
        / MONERO_L2_PRIVATE_FEE_SPONSOR_CHANNEL_RUNTIME_MAX_BPS as u128
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<()> {
    require(!key.is_empty(), &format!("{label} key is empty"))?;
    require(!map.contains_key(&key), &format!("{label} already exists"))?;
    map.insert(key, value);
    Ok(())
}

fn require_field(field: &str, value: &str) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<()> {
    require(!value.is_empty(), &format!("{field} is required"))
}

fn require(condition: bool, message: &str) -> MoneroL2PrivateFeeSponsorChannelRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn set_json_field(record: &mut Value, key: &str, value: Value) {
    record
        .as_object_mut()
        .expect("public record is a JSON object")
        .insert(key.to_string(), value);
}
