use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-reserve-rebalance-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_HEIGHT: u64 = 714_000;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_L2_NETWORK: &str =
    "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_ASSET_ID: &str =
    "wxmr-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID: &str =
    "piconero-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_STABLE_ASSET_ID: &str =
    "dusd-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SNAPSHOT_SCHEME: &str =
    "zk-roots-only-shielded-monero-l2-reserve-imbalance-snapshot-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_BID_SCHEME: &str =
    "ml-kem-1024-sealed-private-reserve-rebalance-bid-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-reserve-rebalance-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_ROUND_SCHEME: &str =
    "sealed-bid-private-reserve-rebalance-auction-round-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SETTLEMENT_SCHEME: &str =
    "zk-pq-private-reserve-rebalance-settlement-batch-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_RECEIPT_SCHEME: &str =
    "private-reserve-rebalance-receipt-rebate-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SPONSOR_SCHEME: &str =
    "roots-only-private-reserve-rebalance-sponsor-reservation-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_HEALTH_SCHEME: &str =
    "private-reserve-liquidity-health-metrics-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_NULLIFIER_SCHEME: &str =
    "monero-l2-pq-private-reserve-rebalance-nullifier-fence-v1";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_REPLAY_DOMAIN: &str =
    "monero-l2-pq-private-reserve-rebalance-auction-devnet";
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS: u64 =
    36;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS: u64 = 10;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_ROUND_TTL_BLOCKS: u64 = 16;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS:
    u64 = 48;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS:
    u64 = 24;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS:
    u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    16_384;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE:
    u64 = 65_536;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    192;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS:
    u16 = 256;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_COVERAGE_BPS: u64 =
    10_200;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_COVERAGE_BPS: u64 =
    12_500;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_CRITICAL_COVERAGE_BPS:
    u64 = 9_500;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_IMBALANCE_BPS: u64 =
    1_500;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_IMBALANCE_BPS: u64 =
    450;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS: u64 =
    20;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_REBATE_BPS: u64 = 8;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SPONSOR_COVER_BPS: u64 =
    8_000;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_ROUND_BIDS: usize =
    256;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SNAPSHOTS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BIDS: usize = 1_048_576;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_ATTESTATIONS: usize =
    1_048_576;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_ROUNDS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SETTLEMENTS: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_RECEIPTS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_REBATES: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SPONSORS: usize = 524_288;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_HEALTH: usize = 262_144;
pub const MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_FENCES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceLane {
    InboundTopUp,
    OutboundDrain,
    CrossVaultNetting,
    EmergencyBackstop,
    MakerInventory,
    SponsorLowFee,
}

impl RebalanceLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InboundTopUp => "inbound_top_up",
            Self::OutboundDrain => "outbound_drain",
            Self::CrossVaultNetting => "cross_vault_netting",
            Self::EmergencyBackstop => "emergency_backstop",
            Self::MakerInventory => "maker_inventory",
            Self::SponsorLowFee => "sponsor_low_fee",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyBackstop => 1_000,
            Self::InboundTopUp => 920,
            Self::OutboundDrain => 900,
            Self::CrossVaultNetting => 830,
            Self::SponsorLowFee => 760,
            Self::MakerInventory => 700,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImbalanceSide {
    MoneroShort,
    L2Short,
    SymmetricNet,
    EmergencyShortfall,
}

impl ImbalanceSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroShort => "monero_short",
            Self::L2Short => "l2_short",
            Self::SymmetricNet => "symmetric_net",
            Self::EmergencyShortfall => "emergency_shortfall",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Open,
    Attested,
    Auctioning,
    Settling,
    Settled,
    Superseded,
    Expired,
}

impl SnapshotStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Auctioning => "auctioning",
            Self::Settling => "settling",
            Self::Settled => "settled",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Sealed,
    Eligible,
    Selected,
    Settled,
    Rejected,
    Expired,
}

impl BidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Eligible => "eligible",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationRole {
    Custodian,
    ReserveCommittee,
    Watcher,
    Sponsor,
}

impl AttestationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Custodian => "custodian",
            Self::ReserveCommittee => "reserve_committee",
            Self::Watcher => "watcher",
            Self::Sponsor => "sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Posted,
    Accepted,
    QuorumAccepted,
    Rejected,
    Superseded,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Accepted => "accepted",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundStatus {
    Open,
    Clearing,
    WinnerSelected,
    SettlementBatched,
    Settled,
    Cancelled,
    Expired,
}

impl RoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Clearing => "clearing",
            Self::WinnerSelected => "winner_selected",
            Self::SettlementBatched => "settlement_batched",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Built,
    Attested,
    Executable,
    ReceiptsPublished,
    Finalized,
    Disputed,
    Rejected,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::Attested => "attested",
            Self::Executable => "executable",
            Self::ReceiptsPublished => "receipts_published",
            Self::Finalized => "finalized",
            Self::Disputed => "disputed",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Applied,
    Consumed,
    Released,
    Expired,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Consumed => "consumed",
            Self::Released => "released",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceKind {
    Nullifier,
    KeyImage,
    BidCommitment,
    SnapshotNonce,
    ReceiptClaim,
    SponsorReplay,
}

impl FenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nullifier => "nullifier",
            Self::KeyImage => "key_image",
            Self::BidCommitment => "bid_commitment",
            Self::SnapshotNonce => "snapshot_nonce",
            Self::ReceiptClaim => "receipt_claim",
            Self::SponsorReplay => "sponsor_replay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub reserve_asset_id: String,
    pub fee_asset_id: String,
    pub stable_asset_id: String,
    pub hash_suite: String,
    pub snapshot_scheme: String,
    pub bid_scheme: String,
    pub attestation_scheme: String,
    pub round_scheme: String,
    pub settlement_scheme: String,
    pub receipt_scheme: String,
    pub sponsor_scheme: String,
    pub health_scheme: String,
    pub nullifier_scheme: String,
    pub replay_domain: String,
    pub snapshot_ttl_blocks: u64,
    pub bid_ttl_blocks: u64,
    pub round_ttl_blocks: u64,
    pub settlement_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_coverage_bps: u64,
    pub target_coverage_bps: u64,
    pub critical_coverage_bps: u64,
    pub max_imbalance_bps: u64,
    pub target_imbalance_bps: u64,
    pub low_fee_bps: u64,
    pub max_solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub max_round_bids: usize,
    pub max_snapshots: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_rounds: usize,
    pub max_settlements: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_sponsor_reservations: usize,
    pub max_health_metrics: usize,
    pub max_fences: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_MONERO_NETWORK
                    .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_L2_NETWORK
                .to_string(),
            reserve_asset_id:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_ASSET_ID
                    .to_string(),
            fee_asset_id:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_FEE_ASSET_ID
                    .to_string(),
            stable_asset_id:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_STABLE_ASSET_ID
                    .to_string(),
            hash_suite: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_HASH_SUITE
                .to_string(),
            snapshot_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SNAPSHOT_SCHEME
                .to_string(),
            bid_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_BID_SCHEME
                .to_string(),
            attestation_scheme:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_ATTESTATION_SCHEME
                    .to_string(),
            round_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_ROUND_SCHEME
                .to_string(),
            settlement_scheme:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SETTLEMENT_SCHEME
                    .to_string(),
            receipt_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_RECEIPT_SCHEME
                .to_string(),
            sponsor_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_SPONSOR_SCHEME
                .to_string(),
            health_scheme: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_HEALTH_SCHEME
                .to_string(),
            nullifier_scheme:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_NULLIFIER_SCHEME
                    .to_string(),
            replay_domain: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_REPLAY_DOMAIN
                .to_string(),
            snapshot_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SNAPSHOT_TTL_BLOCKS,
            bid_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_BID_TTL_BLOCKS,
            round_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_ROUND_TTL_BLOCKS,
            settlement_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SETTLEMENT_TTL_BLOCKS,
            reservation_ttl_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            receipt_finality_blocks:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_RECEIPT_FINALITY_BLOCKS,
            min_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_coverage_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MIN_COVERAGE_BPS,
            target_coverage_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_COVERAGE_BPS,
            critical_coverage_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_CRITICAL_COVERAGE_BPS,
            max_imbalance_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_IMBALANCE_BPS,
            target_imbalance_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_TARGET_IMBALANCE_BPS,
            low_fee_bps: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_LOW_FEE_BPS,
            max_solver_fee_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_SOLVER_FEE_BPS,
            rebate_bps: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_cover_bps:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_SPONSOR_COVER_BPS,
            max_round_bids:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEFAULT_MAX_ROUND_BIDS,
            max_snapshots: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SNAPSHOTS,
            max_bids: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BIDS,
            max_attestations:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_ATTESTATIONS,
            max_rounds: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_ROUNDS,
            max_settlements:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SETTLEMENTS,
            max_receipts: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_RECEIPTS,
            max_rebates: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_REBATES,
            max_sponsor_reservations:
                MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_SPONSORS,
            max_health_metrics: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_HEALTH,
            max_fences: MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_FENCES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "reserve_asset_id": self.reserve_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "stable_asset_id": self.stable_asset_id,
            "hash_suite": self.hash_suite,
            "snapshot_scheme": self.snapshot_scheme,
            "bid_scheme": self.bid_scheme,
            "attestation_scheme": self.attestation_scheme,
            "round_scheme": self.round_scheme,
            "settlement_scheme": self.settlement_scheme,
            "receipt_scheme": self.receipt_scheme,
            "sponsor_scheme": self.sponsor_scheme,
            "health_scheme": self.health_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "replay_domain": self.replay_domain,
            "snapshot_ttl_blocks": self.snapshot_ttl_blocks,
            "bid_ttl_blocks": self.bid_ttl_blocks,
            "round_ttl_blocks": self.round_ttl_blocks,
            "settlement_ttl_blocks": self.settlement_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_coverage_bps": self.min_coverage_bps,
            "target_coverage_bps": self.target_coverage_bps,
            "critical_coverage_bps": self.critical_coverage_bps,
            "max_imbalance_bps": self.max_imbalance_bps,
            "target_imbalance_bps": self.target_imbalance_bps,
            "low_fee_bps": self.low_fee_bps,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "max_round_bids": self.max_round_bids,
            "max_snapshots": self.max_snapshots,
            "max_bids": self.max_bids,
            "max_attestations": self.max_attestations,
            "max_rounds": self.max_rounds,
            "max_settlements": self.max_settlements,
            "max_receipts": self.max_receipts,
            "max_rebates": self.max_rebates,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_health_metrics": self.max_health_metrics,
            "max_fences": self.max_fences,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub snapshots: u64,
    pub bids: u64,
    pub attestations: u64,
    pub rounds: u64,
    pub settlements: u64,
    pub receipts: u64,
    pub rebates: u64,
    pub sponsor_reservations: u64,
    pub health_metrics: u64,
    pub fences: u64,
    pub events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshots": self.snapshots,
            "bids": self.bids,
            "attestations": self.attestations,
            "rounds": self.rounds,
            "settlements": self.settlements,
            "receipts": self.receipts,
            "rebates": self.rebates,
            "sponsor_reservations": self.sponsor_reservations,
            "health_metrics": self.health_metrics,
            "fences": self.fences,
            "events": self.events,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub snapshot_root: String,
    pub bid_root: String,
    pub attestation_root: String,
    pub round_root: String,
    pub settlement_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub sponsor_reservation_root: String,
    pub health_metric_root: String,
    pub nullifier_fence_root: String,
    pub key_image_fence_root: String,
    pub replay_fence_root: String,
    pub event_root: String,
    pub public_record_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-CONFIG-EMPTY"),
            counter_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-COUNTER-EMPTY"),
            snapshot_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SNAPSHOT-EMPTY"),
            bid_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-BID-EMPTY"),
            attestation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ATTESTATION-EMPTY",
            ),
            round_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ROUND-EMPTY"),
            settlement_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SETTLEMENT-EMPTY"),
            receipt_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-RECEIPT-EMPTY"),
            rebate_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-REBATE-EMPTY"),
            sponsor_reservation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SPONSOR-EMPTY",
            ),
            health_metric_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-HEALTH-EMPTY"),
            nullifier_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-NULLIFIER-FENCE-EMPTY",
            ),
            key_image_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-KEY-IMAGE-FENCE-EMPTY",
            ),
            replay_fence_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-REPLAY-FENCE-EMPTY",
            ),
            event_root: empty_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-EVENT-EMPTY"),
            public_record_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-PUBLIC-RECORD-EMPTY",
            ),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "snapshot_root": self.snapshot_root,
            "bid_root": self.bid_root,
            "attestation_root": self.attestation_root,
            "round_root": self.round_root,
            "settlement_root": self.settlement_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "health_metric_root": self.health_metric_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "key_image_fence_root": self.key_image_fence_root,
            "replay_fence_root": self.replay_fence_root,
            "event_root": self.event_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReserveImbalanceSnapshot {
    pub snapshot_id: String,
    pub sequence: u64,
    pub lane: RebalanceLane,
    pub status: SnapshotStatus,
    pub side: ImbalanceSide,
    pub reserve_asset_id: String,
    pub monero_reserve_commitment_root: String,
    pub l2_reserve_commitment_root: String,
    pub shielded_liability_root: String,
    pub pending_exit_root: String,
    pub pending_deposit_root: String,
    pub imbalance_commitment_root: String,
    pub liquidity_bucket_root: String,
    pub nullifier_root: String,
    pub key_image_root: String,
    pub privacy_set_size: u64,
    pub monero_bucket_units: u64,
    pub l2_bucket_units: u64,
    pub liability_bucket_units: u64,
    pub imbalance_bps: u64,
    pub target_rebalance_units: u64,
    pub coverage_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl ReserveImbalanceSnapshot {
    pub fn public_record(&self) -> Value {
        json!({
            "snapshot_id": self.snapshot_id,
            "sequence": self.sequence,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "side": self.side.as_str(),
            "reserve_asset_id": self.reserve_asset_id,
            "monero_reserve_commitment_root": self.monero_reserve_commitment_root,
            "l2_reserve_commitment_root": self.l2_reserve_commitment_root,
            "shielded_liability_root": self.shielded_liability_root,
            "pending_exit_root": self.pending_exit_root,
            "pending_deposit_root": self.pending_deposit_root,
            "imbalance_commitment_root": self.imbalance_commitment_root,
            "liquidity_bucket_root": self.liquidity_bucket_root,
            "nullifier_root": self.nullifier_root,
            "key_image_root": self.key_image_root,
            "privacy_set_size": self.privacy_set_size,
            "monero_bucket_units": self.monero_bucket_units,
            "l2_bucket_units": self.l2_bucket_units,
            "liability_bucket_units": self.liability_bucket_units,
            "imbalance_bps": self.imbalance_bps,
            "target_rebalance_units": self.target_rebalance_units,
            "coverage_bps": self.coverage_bps,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedRebalanceBid {
    pub bid_id: String,
    pub snapshot_id: String,
    pub solver_commitment: String,
    pub status: BidStatus,
    pub lane: RebalanceLane,
    pub encrypted_bid_root: String,
    pub bid_commitment_root: String,
    pub fill_route_root: String,
    pub inventory_commitment_root: String,
    pub price_commitment_root: String,
    pub max_fill_units: u64,
    pub expected_fill_units: u64,
    pub solver_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_signature_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: String,
}

impl EncryptedRebalanceBid {
    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "snapshot_id": self.snapshot_id,
            "solver_commitment": self.solver_commitment,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "encrypted_bid_root": self.encrypted_bid_root,
            "bid_commitment_root": self.bid_commitment_root,
            "fill_route_root": self.fill_route_root,
            "inventory_commitment_root": self.inventory_commitment_root,
            "price_commitment_root": self.price_commitment_root,
            "max_fill_units": self.max_fill_units,
            "expected_fill_units": self.expected_fill_units,
            "solver_fee_bps": self.solver_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_signature_root": self.pq_signature_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqReserveAttestation {
    pub attestation_id: String,
    pub snapshot_id: String,
    pub role: AttestationRole,
    pub status: AttestationStatus,
    pub signer_commitment: String,
    pub committee_root: String,
    pub reserve_view_root: String,
    pub imbalance_view_root: String,
    pub bid_set_root: String,
    pub health_metric_root: String,
    pub pq_signature_root: String,
    pub signed_weight: u64,
    pub quorum_weight: u64,
    pub pq_security_bits: u16,
    pub signed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqReserveAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "snapshot_id": self.snapshot_id,
            "role": self.role.as_str(),
            "status": self.status.as_str(),
            "signer_commitment": self.signer_commitment,
            "committee_root": self.committee_root,
            "reserve_view_root": self.reserve_view_root,
            "imbalance_view_root": self.imbalance_view_root,
            "bid_set_root": self.bid_set_root,
            "health_metric_root": self.health_metric_root,
            "pq_signature_root": self.pq_signature_root,
            "signed_weight": self.signed_weight,
            "quorum_weight": self.quorum_weight,
            "pq_security_bits": self.pq_security_bits,
            "signed_at_height": self.signed_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuctionRound {
    pub round_id: String,
    pub snapshot_id: String,
    pub status: RoundStatus,
    pub lane: RebalanceLane,
    pub bid_root: String,
    pub eligible_bid_root: String,
    pub selected_bid_root: String,
    pub attestation_root: String,
    pub clearing_price_root: String,
    pub sponsor_reservation_root: String,
    pub round_capacity_units: u64,
    pub selected_fill_units: u64,
    pub max_solver_fee_bps: u64,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub nonce: String,
}

impl AuctionRound {
    pub fn public_record(&self) -> Value {
        json!({
            "round_id": self.round_id,
            "snapshot_id": self.snapshot_id,
            "status": self.status.as_str(),
            "lane": self.lane.as_str(),
            "bid_root": self.bid_root,
            "eligible_bid_root": self.eligible_bid_root,
            "selected_bid_root": self.selected_bid_root,
            "attestation_root": self.attestation_root,
            "clearing_price_root": self.clearing_price_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "round_capacity_units": self.round_capacity_units,
            "selected_fill_units": self.selected_fill_units,
            "max_solver_fee_bps": self.max_solver_fee_bps,
            "opened_at_height": self.opened_at_height,
            "closes_at_height": self.closes_at_height,
            "nonce": self.nonce,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBatch {
    pub settlement_id: String,
    pub round_id: String,
    pub snapshot_id: String,
    pub selected_bid_id: String,
    pub status: SettlementStatus,
    pub reserve_delta_root: String,
    pub monero_release_root: String,
    pub l2_release_root: String,
    pub nullifier_fence_root: String,
    pub key_image_fence_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub attestation_root: String,
    pub fill_units: u64,
    pub solver_fee_units: u64,
    pub sponsor_rebate_units: u64,
    pub coverage_after_bps: u64,
    pub imbalance_after_bps: u64,
    pub proposed_at_height: u64,
    pub executable_at_height: u64,
    pub finalized_at_height: u64,
}

impl SettlementBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "round_id": self.round_id,
            "snapshot_id": self.snapshot_id,
            "selected_bid_id": self.selected_bid_id,
            "status": self.status.as_str(),
            "reserve_delta_root": self.reserve_delta_root,
            "monero_release_root": self.monero_release_root,
            "l2_release_root": self.l2_release_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "key_image_fence_root": self.key_image_fence_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "attestation_root": self.attestation_root,
            "fill_units": self.fill_units,
            "solver_fee_units": self.solver_fee_units,
            "sponsor_rebate_units": self.sponsor_rebate_units,
            "coverage_after_bps": self.coverage_after_bps,
            "imbalance_after_bps": self.imbalance_after_bps,
            "proposed_at_height": self.proposed_at_height,
            "executable_at_height": self.executable_at_height,
            "finalized_at_height": self.finalized_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebalanceReceipt {
    pub receipt_id: String,
    pub settlement_id: String,
    pub owner_commitment: String,
    pub output_commitment_root: String,
    pub fee_receipt_root: String,
    pub privacy_receipt_root: String,
    pub delivered_units: u64,
    pub paid_fee_units: u64,
    pub rebate_units: u64,
    pub issued_at_height: u64,
    pub final_at_height: u64,
}

impl RebalanceReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "settlement_id": self.settlement_id,
            "owner_commitment": self.owner_commitment,
            "output_commitment_root": self.output_commitment_root,
            "fee_receipt_root": self.fee_receipt_root,
            "privacy_receipt_root": self.privacy_receipt_root,
            "delivered_units": self.delivered_units,
            "paid_fee_units": self.paid_fee_units,
            "rebate_units": self.rebate_units,
            "issued_at_height": self.issued_at_height,
            "final_at_height": self.final_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rebate {
    pub rebate_id: String,
    pub receipt_id: String,
    pub sponsor_reservation_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_units: u64,
    pub rebate_bps: u64,
    pub claim_nullifier_root: String,
    pub claim_note_root: String,
    pub expires_at_height: u64,
}

impl Rebate {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "receipt_id": self.receipt_id,
            "sponsor_reservation_id": self.sponsor_reservation_id,
            "owner_commitment": self.owner_commitment,
            "asset_id": self.asset_id,
            "amount_units": self.amount_units,
            "rebate_bps": self.rebate_bps,
            "claim_nullifier_root": self.claim_nullifier_root,
            "claim_note_root": self.claim_note_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorReservation {
    pub reservation_id: String,
    pub sponsor_commitment: String,
    pub snapshot_id: String,
    pub round_id: String,
    pub status: ReservationStatus,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub applied_fee_bps: u64,
    pub max_rebate_bps: u64,
    pub policy_root: String,
    pub privacy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl SponsorReservation {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "snapshot_id": self.snapshot_id,
            "round_id": self.round_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "applied_fee_bps": self.applied_fee_bps,
            "max_rebate_bps": self.max_rebate_bps,
            "policy_root": self.policy_root,
            "privacy_root": self.privacy_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityHealthMetric {
    pub metric_id: String,
    pub snapshot_id: String,
    pub reserve_asset_id: String,
    pub coverage_bps: u64,
    pub imbalance_bps: u64,
    pub depth_score_bps: u64,
    pub auction_pressure_bps: u64,
    pub sponsor_coverage_bps: u64,
    pub pending_exit_units: u64,
    pub pending_deposit_units: u64,
    pub target_rebalance_units: u64,
    pub health_root: String,
    pub recorded_at_height: u64,
}

impl LiquidityHealthMetric {
    pub fn public_record(&self) -> Value {
        json!({
            "metric_id": self.metric_id,
            "snapshot_id": self.snapshot_id,
            "reserve_asset_id": self.reserve_asset_id,
            "coverage_bps": self.coverage_bps,
            "imbalance_bps": self.imbalance_bps,
            "depth_score_bps": self.depth_score_bps,
            "auction_pressure_bps": self.auction_pressure_bps,
            "sponsor_coverage_bps": self.sponsor_coverage_bps,
            "pending_exit_units": self.pending_exit_units,
            "pending_deposit_units": self.pending_deposit_units,
            "target_rebalance_units": self.target_rebalance_units,
            "health_root": self.health_root,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyFence {
    pub fence_id: String,
    pub kind: FenceKind,
    pub subject_id: String,
    pub commitment_root: String,
    pub domain: String,
    pub opened_at_height: u64,
}

impl PrivacyFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "commitment_root": self.commitment_root,
            "domain": self.domain,
            "opened_at_height": self.opened_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub event_id: String,
    pub event_type: String,
    pub subject_id: String,
    pub payload_root: String,
    pub height: u64,
}

impl EventRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "event_type": self.event_type,
            "subject_id": self.subject_id,
            "payload_root": self.payload_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub snapshots: BTreeMap<String, ReserveImbalanceSnapshot>,
    pub bids: BTreeMap<String, EncryptedRebalanceBid>,
    pub attestations: BTreeMap<String, PqReserveAttestation>,
    pub rounds: BTreeMap<String, AuctionRound>,
    pub settlements: BTreeMap<String, SettlementBatch>,
    pub receipts: BTreeMap<String, RebalanceReceipt>,
    pub rebates: BTreeMap<String, Rebate>,
    pub sponsor_reservations: BTreeMap<String, SponsorReservation>,
    pub health_metrics: BTreeMap<String, LiquidityHealthMetric>,
    pub fences: BTreeMap<String, PrivacyFence>,
    pub events: Vec<Value>,
    pub used_nullifier_roots: BTreeSet<String>,
    pub used_key_image_roots: BTreeSet<String>,
    pub used_replay_fences: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            snapshots: BTreeMap::new(),
            bids: BTreeMap::new(),
            attestations: BTreeMap::new(),
            rounds: BTreeMap::new(),
            settlements: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            health_metrics: BTreeMap::new(),
            fences: BTreeMap::new(),
            events: Vec::new(),
            used_nullifier_roots: BTreeSet::new(),
            used_key_image_roots: BTreeSet::new(),
            used_replay_fences: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        let height = MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_DEVNET_HEIGHT;
        let monero_root = tagged_root("devnet-monero-shielded-reserve");
        let l2_root = tagged_root("devnet-l2-shielded-reserve");
        let liability_root = tagged_root("devnet-shielded-liability");
        let pending_exit_root = tagged_root("devnet-pending-exits");
        let pending_deposit_root = tagged_root("devnet-pending-deposits");
        let imbalance_root = value_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-DEVNET-IMBALANCE",
            vec![
                json!({"bucket": "monero_short", "amount_units": 1_250_000_000u64}),
                json!({"bucket": "l2_surplus", "amount_units": 1_420_000_000u64}),
                json!({"bucket": "net_target", "amount_units": 900_000_000u64}),
            ],
        );
        let nullifier_root = tagged_root("devnet-snapshot-nullifier");
        let key_image_root = tagged_root("devnet-snapshot-key-image");
        let snapshot_id = snapshot_id(
            1,
            RebalanceLane::InboundTopUp,
            ImbalanceSide::MoneroShort,
            &imbalance_root,
            height,
            "devnet-snapshot",
        );
        let snapshot = ReserveImbalanceSnapshot {
            snapshot_id: snapshot_id.clone(),
            sequence: 1,
            lane: RebalanceLane::InboundTopUp,
            status: SnapshotStatus::Settling,
            side: ImbalanceSide::MoneroShort,
            reserve_asset_id: state.config.reserve_asset_id.clone(),
            monero_reserve_commitment_root: monero_root.clone(),
            l2_reserve_commitment_root: l2_root.clone(),
            shielded_liability_root: liability_root.clone(),
            pending_exit_root: pending_exit_root.clone(),
            pending_deposit_root: pending_deposit_root.clone(),
            imbalance_commitment_root: imbalance_root.clone(),
            liquidity_bucket_root: tagged_root("devnet-liquidity-buckets"),
            nullifier_root: nullifier_root.clone(),
            key_image_root: key_image_root.clone(),
            privacy_set_size: state.config.batch_privacy_set_size,
            monero_bucket_units: 6_200_000_000,
            l2_bucket_units: 7_450_000_000,
            liability_bucket_units: 5_400_000_000,
            imbalance_bps: 1_125,
            target_rebalance_units: 900_000_000,
            coverage_bps: 12_120,
            opened_at_height: height,
            expires_at_height: height + state.config.snapshot_ttl_blocks,
            nonce: "devnet-snapshot".to_string(),
        };
        state.snapshots.insert(snapshot_id.clone(), snapshot);
        state.insert_fence(
            FenceKind::Nullifier,
            &snapshot_id,
            &nullifier_root,
            MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_REPLAY_DOMAIN,
            height,
        );
        state.insert_fence(
            FenceKind::KeyImage,
            &snapshot_id,
            &key_image_root,
            MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_REPLAY_DOMAIN,
            height,
        );
        let metric_id = health_metric_id(&snapshot_id, height);
        let metric = LiquidityHealthMetric {
            metric_id: metric_id.clone(),
            snapshot_id: snapshot_id.clone(),
            reserve_asset_id: state.config.reserve_asset_id.clone(),
            coverage_bps: 12_120,
            imbalance_bps: 1_125,
            depth_score_bps: 8_850,
            auction_pressure_bps: 6_200,
            sponsor_coverage_bps: 8_300,
            pending_exit_units: 2_100_000_000,
            pending_deposit_units: 1_300_000_000,
            target_rebalance_units: 900_000_000,
            health_root: tagged_root("devnet-health-proof"),
            recorded_at_height: height,
        };
        state.health_metrics.insert(metric_id.clone(), metric);
        let attestation_id = attestation_id(
            &snapshot_id,
            AttestationRole::ReserveCommittee,
            "devnet-reserve-committee",
            &monero_root,
            height + 1,
        );
        let attestation = PqReserveAttestation {
            attestation_id: attestation_id.clone(),
            snapshot_id: snapshot_id.clone(),
            role: AttestationRole::ReserveCommittee,
            status: AttestationStatus::QuorumAccepted,
            signer_commitment: "devnet-reserve-committee".to_string(),
            committee_root: tagged_root("devnet-committee-set"),
            reserve_view_root: monero_root,
            imbalance_view_root: imbalance_root.clone(),
            bid_set_root: tagged_root("devnet-bid-set-pending"),
            health_metric_root: metric_id.clone(),
            pq_signature_root: tagged_root("devnet-committee-pq-signature"),
            signed_weight: 7,
            quorum_weight: 5,
            pq_security_bits: state.config.target_pq_security_bits,
            signed_at_height: height + 1,
            expires_at_height: height + state.config.settlement_ttl_blocks,
        };
        state
            .attestations
            .insert(attestation_id.clone(), attestation);
        let round_id = round_id(&snapshot_id, 1, height + 1, "devnet-round");
        let bid_id = rebalance_bid_id(
            &snapshot_id,
            "devnet-solver-a",
            &tagged_root("devnet-bid-commitment"),
            height + 1,
            "devnet-bid",
        );
        let reservation_id = sponsor_reservation_id(
            "devnet-sponsor-a",
            &snapshot_id,
            &round_id,
            state.config.low_fee_bps,
            height + 1,
        );
        let bid = EncryptedRebalanceBid {
            bid_id: bid_id.clone(),
            snapshot_id: snapshot_id.clone(),
            solver_commitment: "devnet-solver-a".to_string(),
            status: BidStatus::Selected,
            lane: RebalanceLane::InboundTopUp,
            encrypted_bid_root: tagged_root("devnet-encrypted-rebalance-bid"),
            bid_commitment_root: tagged_root("devnet-bid-commitment"),
            fill_route_root: tagged_root("devnet-fill-route"),
            inventory_commitment_root: tagged_root("devnet-inventory"),
            price_commitment_root: tagged_root("devnet-private-price"),
            max_fill_units: 1_100_000_000,
            expected_fill_units: 900_000_000,
            solver_fee_bps: state.config.low_fee_bps,
            rebate_bps: state.config.rebate_bps,
            pq_signature_root: tagged_root("devnet-bid-pq-signature"),
            submitted_at_height: height + 1,
            expires_at_height: height + state.config.bid_ttl_blocks,
            nonce: "devnet-bid".to_string(),
        };
        state.bids.insert(bid_id.clone(), bid);
        let reservation = SponsorReservation {
            reservation_id: reservation_id.clone(),
            sponsor_commitment: "devnet-sponsor-a".to_string(),
            snapshot_id: snapshot_id.clone(),
            round_id: round_id.clone(),
            status: ReservationStatus::Applied,
            asset_id: state.config.fee_asset_id.clone(),
            budget_units: 25_000_000,
            reserved_units: 7_200_000,
            applied_fee_bps: state.config.low_fee_bps,
            max_rebate_bps: state.config.rebate_bps,
            policy_root: tagged_root("devnet-sponsor-policy"),
            privacy_root: tagged_root("devnet-sponsor-privacy"),
            opened_at_height: height + 1,
            expires_at_height: height + state.config.reservation_ttl_blocks,
        };
        state
            .sponsor_reservations
            .insert(reservation_id.clone(), reservation);
        let round = AuctionRound {
            round_id: round_id.clone(),
            snapshot_id: snapshot_id.clone(),
            status: RoundStatus::SettlementBatched,
            lane: RebalanceLane::InboundTopUp,
            bid_root: bid_id.clone(),
            eligible_bid_root: bid_id.clone(),
            selected_bid_root: bid_id.clone(),
            attestation_root: attestation_id.clone(),
            clearing_price_root: tagged_root("devnet-clearing-price"),
            sponsor_reservation_root: reservation_id.clone(),
            round_capacity_units: 1_000_000_000,
            selected_fill_units: 900_000_000,
            max_solver_fee_bps: state.config.max_solver_fee_bps,
            opened_at_height: height + 1,
            closes_at_height: height + state.config.round_ttl_blocks,
            nonce: "devnet-round".to_string(),
        };
        state.rounds.insert(round_id.clone(), round);
        let settlement_id = settlement_id(
            &round_id,
            &snapshot_id,
            &bid_id,
            height + 2,
            "devnet-settlement",
        );
        let receipt_id = receipt_id(&settlement_id, "devnet-owner", height + 3);
        let rebate_id = rebate_id(&receipt_id, &reservation_id, "devnet-owner", height + 3);
        let settlement = SettlementBatch {
            settlement_id: settlement_id.clone(),
            round_id: round_id.clone(),
            snapshot_id: snapshot_id.clone(),
            selected_bid_id: bid_id,
            status: SettlementStatus::ReceiptsPublished,
            reserve_delta_root: tagged_root("devnet-reserve-delta"),
            monero_release_root: tagged_root("devnet-monero-release"),
            l2_release_root: tagged_root("devnet-l2-release"),
            nullifier_fence_root: nullifier_root,
            key_image_fence_root: key_image_root,
            receipt_root: receipt_id.clone(),
            rebate_root: rebate_id.clone(),
            attestation_root: attestation_id,
            fill_units: 900_000_000,
            solver_fee_units: fee_units(900_000_000, state.config.low_fee_bps),
            sponsor_rebate_units: fee_units(900_000_000, state.config.rebate_bps),
            coverage_after_bps: 12_850,
            imbalance_after_bps: 420,
            proposed_at_height: height + 2,
            executable_at_height: height + 3,
            finalized_at_height: height + state.config.receipt_finality_blocks,
        };
        state.settlements.insert(settlement_id.clone(), settlement);
        let receipt = RebalanceReceipt {
            receipt_id: receipt_id.clone(),
            settlement_id: settlement_id.clone(),
            owner_commitment: "devnet-owner".to_string(),
            output_commitment_root: tagged_root("devnet-owner-output"),
            fee_receipt_root: tagged_root("devnet-fee-receipt"),
            privacy_receipt_root: tagged_root("devnet-privacy-receipt"),
            delivered_units: 900_000_000,
            paid_fee_units: fee_units(900_000_000, state.config.low_fee_bps),
            rebate_units: fee_units(900_000_000, state.config.rebate_bps),
            issued_at_height: height + 3,
            final_at_height: height + state.config.receipt_finality_blocks,
        };
        state.receipts.insert(receipt_id.clone(), receipt);
        let rebate = Rebate {
            rebate_id: rebate_id.clone(),
            receipt_id,
            sponsor_reservation_id: reservation_id,
            owner_commitment: "devnet-owner".to_string(),
            asset_id: state.config.fee_asset_id.clone(),
            amount_units: fee_units(900_000_000, state.config.rebate_bps),
            rebate_bps: state.config.rebate_bps,
            claim_nullifier_root: tagged_root("devnet-rebate-nullifier"),
            claim_note_root: tagged_root("devnet-rebate-note"),
            expires_at_height: height + 144,
        };
        state.rebates.insert(rebate_id, rebate);
        state.push_event("devnet_reserve_rebalance_ready", &settlement_id, height + 3);
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(ref mut map) = record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
    }

    pub fn refresh_counters(&mut self) {
        self.counters = Counters {
            snapshots: self.snapshots.len() as u64,
            bids: self.bids.len() as u64,
            attestations: self.attestations.len() as u64,
            rounds: self.rounds.len() as u64,
            settlements: self.settlements.len() as u64,
            receipts: self.receipts.len() as u64,
            rebates: self.rebates.len() as u64,
            sponsor_reservations: self.sponsor_reservations.len() as u64,
            health_metrics: self.health_metrics.len() as u64,
            fences: self.fences.len() as u64,
            events: self.events.len() as u64,
        };
    }

    pub fn refresh_roots(&mut self) {
        self.refresh_counters();
        self.roots.config_root = payload_root(&self.config.public_record());
        self.roots.counter_root = payload_root(&self.counters.public_record());
        self.roots.snapshot_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SNAPSHOT",
            &self.snapshots,
            ReserveImbalanceSnapshot::public_record,
        );
        self.roots.bid_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-BID",
            &self.bids,
            EncryptedRebalanceBid::public_record,
        );
        self.roots.attestation_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ATTESTATION",
            &self.attestations,
            PqReserveAttestation::public_record,
        );
        self.roots.round_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ROUND",
            &self.rounds,
            AuctionRound::public_record,
        );
        self.roots.settlement_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SETTLEMENT",
            &self.settlements,
            SettlementBatch::public_record,
        );
        self.roots.receipt_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-RECEIPT",
            &self.receipts,
            RebalanceReceipt::public_record,
        );
        self.roots.rebate_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-REBATE",
            &self.rebates,
            Rebate::public_record,
        );
        self.roots.sponsor_reservation_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SPONSOR",
            &self.sponsor_reservations,
            SponsorReservation::public_record,
        );
        self.roots.health_metric_root = map_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-HEALTH",
            &self.health_metrics,
            LiquidityHealthMetric::public_record,
        );
        self.roots.nullifier_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-NULLIFIER-FENCE",
            &self.used_nullifier_roots,
        );
        self.roots.key_image_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-KEY-IMAGE-FENCE",
            &self.used_key_image_roots,
        );
        self.roots.replay_fence_root = set_root(
            "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-REPLAY-FENCE",
            &self.used_replay_fences,
        );
        self.roots.event_root =
            merkle_root("MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-EVENT", &self.events);
        self.roots.public_record_root = public_record_root(&self.public_record_without_root());
    }

    pub fn record_snapshot(
        &mut self,
        lane: RebalanceLane,
        side: ImbalanceSide,
        monero_bucket_units: u64,
        l2_bucket_units: u64,
        liability_bucket_units: u64,
        imbalance_commitment_root: String,
        nullifier_root: String,
        key_image_root: String,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<String> {
        ensure_capacity(self.snapshots.len(), self.config.max_snapshots, "snapshots")?;
        ensure_privacy_set(self.config.batch_privacy_set_size, &self.config)?;
        self.ensure_fence_unused(&nullifier_root, &key_image_root)?;
        let sequence = self.counters.snapshots.saturating_add(1);
        let snapshot_id = snapshot_id(
            sequence,
            lane,
            side,
            &imbalance_commitment_root,
            height,
            nonce,
        );
        let target_rebalance_units = monero_bucket_units.abs_diff(l2_bucket_units);
        let imbalance_bps = imbalance_bps(monero_bucket_units, l2_bucket_units);
        let coverage_bps = coverage_bps(
            monero_bucket_units.saturating_add(l2_bucket_units),
            liability_bucket_units,
        );
        let snapshot = ReserveImbalanceSnapshot {
            snapshot_id: snapshot_id.clone(),
            sequence,
            lane,
            status: SnapshotStatus::Open,
            side,
            reserve_asset_id: self.config.reserve_asset_id.clone(),
            monero_reserve_commitment_root: tagged_root(&format!("monero-reserve-{snapshot_id}")),
            l2_reserve_commitment_root: tagged_root(&format!("l2-reserve-{snapshot_id}")),
            shielded_liability_root: tagged_root(&format!("liability-{snapshot_id}")),
            pending_exit_root: tagged_root(&format!("pending-exit-{snapshot_id}")),
            pending_deposit_root: tagged_root(&format!("pending-deposit-{snapshot_id}")),
            imbalance_commitment_root,
            liquidity_bucket_root: tagged_root(&format!("liquidity-bucket-{snapshot_id}")),
            nullifier_root: nullifier_root.clone(),
            key_image_root: key_image_root.clone(),
            privacy_set_size: self.config.batch_privacy_set_size,
            monero_bucket_units,
            l2_bucket_units,
            liability_bucket_units,
            imbalance_bps,
            target_rebalance_units,
            coverage_bps,
            opened_at_height: height,
            expires_at_height: height + self.config.snapshot_ttl_blocks,
            nonce: nonce.to_string(),
        };
        self.insert_fence(
            FenceKind::Nullifier,
            &snapshot_id,
            &nullifier_root,
            &self.config.replay_domain.clone(),
            height,
        );
        self.insert_fence(
            FenceKind::KeyImage,
            &snapshot_id,
            &key_image_root,
            &self.config.replay_domain.clone(),
            height,
        );
        self.snapshots.insert(snapshot_id.clone(), snapshot);
        self.push_event("snapshot_recorded", &snapshot_id, height);
        self.refresh_roots();
        Ok(snapshot_id)
    }

    pub fn post_bid(
        &mut self,
        snapshot_id: &str,
        solver_commitment: &str,
        encrypted_bid_root: String,
        bid_commitment_root: String,
        max_fill_units: u64,
        expected_fill_units: u64,
        solver_fee_bps: u64,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<String> {
        ensure_capacity(self.bids.len(), self.config.max_bids, "bids")?;
        ensure_fee(solver_fee_bps, self.config.max_solver_fee_bps)?;
        let snapshot = self
            .snapshots
            .get(snapshot_id)
            .ok_or_else(|| format!("unknown snapshot: {snapshot_id}"))?;
        if height > snapshot.expires_at_height {
            return Err("snapshot expired".to_string());
        }
        let bid_id = rebalance_bid_id(
            snapshot_id,
            solver_commitment,
            &bid_commitment_root,
            height,
            nonce,
        );
        let bid = EncryptedRebalanceBid {
            bid_id: bid_id.clone(),
            snapshot_id: snapshot_id.to_string(),
            solver_commitment: solver_commitment.to_string(),
            status: BidStatus::Eligible,
            lane: snapshot.lane,
            encrypted_bid_root,
            bid_commitment_root,
            fill_route_root: tagged_root(&format!("fill-route-{bid_id}")),
            inventory_commitment_root: tagged_root(&format!("inventory-{bid_id}")),
            price_commitment_root: tagged_root(&format!("price-{bid_id}")),
            max_fill_units,
            expected_fill_units,
            solver_fee_bps,
            rebate_bps: self.config.rebate_bps,
            pq_signature_root: tagged_root(&format!("bid-pq-signature-{bid_id}")),
            submitted_at_height: height,
            expires_at_height: height + self.config.bid_ttl_blocks,
            nonce: nonce.to_string(),
        };
        self.insert_fence(
            FenceKind::BidCommitment,
            &bid_id,
            &tagged_root(&bid_id),
            &self.config.replay_domain.clone(),
            height,
        );
        self.bids.insert(bid_id.clone(), bid);
        self.push_event("encrypted_bid_posted", &bid_id, height);
        self.refresh_roots();
        Ok(bid_id)
    }

    pub fn record_attestation(
        &mut self,
        snapshot_id: &str,
        role: AttestationRole,
        signer_commitment: &str,
        reserve_view_root: String,
        imbalance_view_root: String,
        signed_weight: u64,
        quorum_weight: u64,
        pq_security_bits: u16,
        height: u64,
    ) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<String> {
        ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestations",
        )?;
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security bits below minimum".to_string());
        }
        let attestation_id = attestation_id(
            snapshot_id,
            role,
            signer_commitment,
            &reserve_view_root,
            height,
        );
        let status = if signed_weight >= quorum_weight {
            AttestationStatus::QuorumAccepted
        } else {
            AttestationStatus::Accepted
        };
        let attestation = PqReserveAttestation {
            attestation_id: attestation_id.clone(),
            snapshot_id: snapshot_id.to_string(),
            role,
            status,
            signer_commitment: signer_commitment.to_string(),
            committee_root: tagged_root(&format!("committee-{snapshot_id}")),
            reserve_view_root,
            imbalance_view_root,
            bid_set_root: self.roots.bid_root.clone(),
            health_metric_root: self.roots.health_metric_root.clone(),
            pq_signature_root: tagged_root(&format!("attestation-pq-signature-{attestation_id}")),
            signed_weight,
            quorum_weight,
            pq_security_bits,
            signed_at_height: height,
            expires_at_height: height + self.config.settlement_ttl_blocks,
        };
        self.attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(snapshot) = self.snapshots.get_mut(snapshot_id) {
            snapshot.status = SnapshotStatus::Attested;
        }
        self.push_event("pq_attestation_recorded", &attestation_id, height);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_round(
        &mut self,
        snapshot_id: &str,
        height: u64,
        nonce: &str,
    ) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<String> {
        ensure_capacity(self.rounds.len(), self.config.max_rounds, "rounds")?;
        let snapshot = self
            .snapshots
            .get(snapshot_id)
            .ok_or_else(|| format!("unknown snapshot: {snapshot_id}"))?;
        let sequence = self.counters.rounds.saturating_add(1);
        let round_id = round_id(snapshot_id, sequence, height, nonce);
        let round = AuctionRound {
            round_id: round_id.clone(),
            snapshot_id: snapshot_id.to_string(),
            status: RoundStatus::Open,
            lane: snapshot.lane,
            bid_root: self.roots.bid_root.clone(),
            eligible_bid_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ELIGIBLE-BID-PENDING",
            ),
            selected_bid_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SELECTED-BID-PENDING",
            ),
            attestation_root: self.roots.attestation_root.clone(),
            clearing_price_root: tagged_root(&format!("clearing-price-{round_id}")),
            sponsor_reservation_root: empty_root(
                "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SPONSOR-PENDING",
            ),
            round_capacity_units: snapshot.target_rebalance_units,
            selected_fill_units: 0,
            max_solver_fee_bps: self.config.max_solver_fee_bps,
            opened_at_height: height,
            closes_at_height: height + self.config.round_ttl_blocks,
            nonce: nonce.to_string(),
        };
        self.rounds.insert(round_id.clone(), round);
        if let Some(snapshot) = self.snapshots.get_mut(snapshot_id) {
            snapshot.status = SnapshotStatus::Auctioning;
        }
        self.push_event("auction_round_opened", &round_id, height);
        self.refresh_roots();
        Ok(round_id)
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "snapshots": self.snapshots.values().map(ReserveImbalanceSnapshot::public_record).collect::<Vec<_>>(),
            "bids": self.bids.values().map(EncryptedRebalanceBid::public_record).collect::<Vec<_>>(),
            "attestations": self.attestations.values().map(PqReserveAttestation::public_record).collect::<Vec<_>>(),
            "rounds": self.rounds.values().map(AuctionRound::public_record).collect::<Vec<_>>(),
            "settlements": self.settlements.values().map(SettlementBatch::public_record).collect::<Vec<_>>(),
            "receipts": self.receipts.values().map(RebalanceReceipt::public_record).collect::<Vec<_>>(),
            "rebates": self.rebates.values().map(Rebate::public_record).collect::<Vec<_>>(),
            "sponsor_reservations": self.sponsor_reservations.values().map(SponsorReservation::public_record).collect::<Vec<_>>(),
            "health_metrics": self.health_metrics.values().map(LiquidityHealthMetric::public_record).collect::<Vec<_>>(),
            "fences": self.fences.values().map(PrivacyFence::public_record).collect::<Vec<_>>(),
            "events": self.events,
            "used_nullifier_roots": self.used_nullifier_roots.iter().cloned().collect::<Vec<_>>(),
            "used_key_image_roots": self.used_key_image_roots.iter().cloned().collect::<Vec<_>>(),
            "used_replay_fences": self.used_replay_fences.iter().cloned().collect::<Vec<_>>(),
        })
    }

    fn ensure_fence_unused(
        &self,
        nullifier_root: &str,
        key_image_root: &str,
    ) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<()> {
        if self.used_nullifier_roots.contains(nullifier_root) {
            return Err("nullifier root already fenced".to_string());
        }
        if self.used_key_image_roots.contains(key_image_root) {
            return Err("key image root already fenced".to_string());
        }
        Ok(())
    }

    fn insert_fence(
        &mut self,
        kind: FenceKind,
        subject_id: &str,
        commitment_root: &str,
        domain: &str,
        height: u64,
    ) {
        let fence_id = privacy_fence_id(kind, subject_id, commitment_root, domain, height);
        match kind {
            FenceKind::Nullifier | FenceKind::ReceiptClaim => {
                self.used_nullifier_roots
                    .insert(commitment_root.to_string());
            }
            FenceKind::KeyImage => {
                self.used_key_image_roots
                    .insert(commitment_root.to_string());
            }
            FenceKind::BidCommitment | FenceKind::SnapshotNonce | FenceKind::SponsorReplay => {
                self.used_replay_fences.insert(fence_id.clone());
            }
        }
        let fence = PrivacyFence {
            fence_id: fence_id.clone(),
            kind,
            subject_id: subject_id.to_string(),
            commitment_root: commitment_root.to_string(),
            domain: domain.to_string(),
            opened_at_height: height,
        };
        self.fences.insert(fence_id, fence);
    }

    fn push_event(&mut self, event_type: &str, subject_id: &str, height: u64) {
        let payload = json!({
            "event_type": event_type,
            "subject_id": subject_id,
            "height": height,
            "protocol": PROTOCOL_VERSION,
        });
        let record = EventRecord {
            event_id: event_id(event_type, subject_id, &payload, height),
            event_type: event_type.to_string(),
            subject_id: subject_id.to_string(),
            payload_root: payload_root(&payload),
            height,
        };
        self.events.push(record.public_record());
    }
}

pub fn payload_root(payload: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-PAYLOAD-ROOT",
        &[HashPart::Json(payload)],
        32,
    )
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-RECORD-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn public_record_root(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-PUBLIC-RECORD-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-STATE-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn snapshot_id(
    sequence: u64,
    lane: RebalanceLane,
    side: ImbalanceSide,
    imbalance_commitment_root: &str,
    opened_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Int(sequence as i128),
            HashPart::Str(lane.as_str()),
            HashPart::Str(side.as_str()),
            HashPart::Str(imbalance_commitment_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn rebalance_bid_id(
    snapshot_id: &str,
    solver_commitment: &str,
    bid_commitment_root: &str,
    submitted_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(snapshot_id),
            HashPart::Str(solver_commitment),
            HashPart::Str(bid_commitment_root),
            HashPart::Int(submitted_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn attestation_id(
    snapshot_id: &str,
    role: AttestationRole,
    signer_commitment: &str,
    reserve_view_root: &str,
    signed_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(snapshot_id),
            HashPart::Str(role.as_str()),
            HashPart::Str(signer_commitment),
            HashPart::Str(reserve_view_root),
            HashPart::Int(signed_at_height as i128),
        ],
        32,
    )
}

pub fn round_id(snapshot_id: &str, sequence: u64, opened_at_height: u64, nonce: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-ROUND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(snapshot_id),
            HashPart::Int(sequence as i128),
            HashPart::Int(opened_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn settlement_id(
    round_id: &str,
    snapshot_id: &str,
    selected_bid_id: &str,
    proposed_at_height: u64,
    nonce: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SETTLEMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(round_id),
            HashPart::Str(snapshot_id),
            HashPart::Str(selected_bid_id),
            HashPart::Int(proposed_at_height as i128),
            HashPart::Str(nonce),
        ],
        32,
    )
}

pub fn receipt_id(settlement_id: &str, owner_commitment: &str, issued_at_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(settlement_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn rebate_id(
    receipt_id: &str,
    sponsor_reservation_id: &str,
    owner_commitment: &str,
    issued_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_reservation_id),
            HashPart::Str(owner_commitment),
            HashPart::Int(issued_at_height as i128),
        ],
        32,
    )
}

pub fn sponsor_reservation_id(
    sponsor_commitment: &str,
    snapshot_id: &str,
    round_id: &str,
    applied_fee_bps: u64,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(snapshot_id),
            HashPart::Str(round_id),
            HashPart::Int(applied_fee_bps as i128),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn health_metric_id(snapshot_id: &str, recorded_at_height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-HEALTH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(snapshot_id),
            HashPart::Int(recorded_at_height as i128),
        ],
        32,
    )
}

pub fn privacy_fence_id(
    kind: FenceKind,
    subject_id: &str,
    commitment_root: &str,
    domain: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(commitment_root),
            HashPart::Str(domain),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn event_id(event_type: &str, subject_id: &str, payload: &Value, height: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(event_type),
            HashPart::Str(subject_id),
            HashPart::Json(payload),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn coverage_bps(reserve_units: u64, liability_units: u64) -> u64 {
    if liability_units == 0 {
        return MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BPS * 10;
    }
    reserve_units.saturating_mul(MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BPS)
        / liability_units
}

pub fn imbalance_bps(monero_units: u64, l2_units: u64) -> u64 {
    let total = monero_units.saturating_add(l2_units);
    if total == 0 {
        return 0;
    }
    monero_units
        .abs_diff(l2_units)
        .saturating_mul(MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BPS)
        / total
}

pub fn fee_units(amount_units: u64, fee_bps: u64) -> u64 {
    amount_units.saturating_mul(fee_bps)
        / MONERO_L2_PQ_PRIVATE_RESERVE_REBALANCE_AUCTION_RUNTIME_MAX_BPS
}

fn ensure_capacity(
    current: usize,
    max: usize,
    label: &str,
) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<()> {
    if current >= max {
        return Err(format!("{label} capacity exceeded"));
    }
    Ok(())
}

fn ensure_fee(
    fee_bps: u64,
    max_fee_bps: u64,
) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<()> {
    if fee_bps > max_fee_bps {
        return Err(format!("fee {fee_bps} bps exceeds max {max_fee_bps} bps"));
    }
    Ok(())
}

fn ensure_privacy_set(
    size: u64,
    config: &Config,
) -> MoneroL2PqPrivateReserveRebalanceAuctionRuntimeResult<()> {
    if size < config.min_privacy_set_size {
        return Err("privacy set below minimum".to_string());
    }
    Ok(())
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &Vec::<Value>::new())
}

fn tagged_root(tag: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-RESERVE-REBALANCE-TAGGED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(tag),
        ],
        32,
    )
}

fn value_root(domain: &str, leaves: Vec<Value>) -> String {
    merkle_root(domain, &leaves)
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves: Vec<Value> = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "record": public_record(value),
            })
        })
        .collect();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<Value> = set.iter().map(|value| json!({ "value": value })).collect();
    merkle_root(domain, &leaves)
}
