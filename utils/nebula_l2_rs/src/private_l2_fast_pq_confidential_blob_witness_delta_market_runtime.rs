use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialBlobWitnessDeltaMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BLOB_WITNESS_DELTA_MARKET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-blob-witness-delta-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_BLOB_WITNESS_DELTA_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_280_000;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ENCRYPTED_BLOB_LANE_SCHEME: &str = "ml-kem-1024-sealed-confidential-blob-lane-root-v1";
pub const WITNESS_DELTA_ORDER_SCHEME: &str = "roots-only-private-witness-delta-order-root-v1";
pub const PREFETCH_AUCTION_SCHEME: &str = "sealed-fast-witness-prefetch-auction-root-v1";
pub const PQ_AVAILABILITY_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-availability-attestation-root-v1";
pub const CACHE_LEASE_SCHEME: &str = "private-l2-confidential-blob-cache-lease-root-v1";
pub const INVALIDATION_FENCE_SCHEME: &str =
    "private-l2-confidential-blob-invalidation-fence-root-v1";
pub const LOW_FEE_PROOF_CREDIT_SCHEME: &str = "low-fee-private-witness-delta-proof-credit-root-v1";
pub const REDACTION_METADATA_SCHEME: &str =
    "view-key-safe-confidential-blob-redaction-metadata-root-v1";
pub const OPERATOR_SUMMARY_SCHEME: &str =
    "public-fast-pq-confidential-blob-operator-summary-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str =
    "deterministic-public-fast-pq-confidential-blob-witness-delta-market-record-v1";
pub const PRIVACY_BOUNDARY: &str =
    "roots_only_no_plaintext_blob_bytes_addresses_view_keys_witness_bytes_payloads_or_secret_keys";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u64 = 16;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_BLOB_CHUNK_BYTES: u64 = 16_384;
pub const DEFAULT_MAX_BLOB_CHUNKS: u64 = 2_048;
pub const DEFAULT_PREFETCH_TTL_BLOCKS: u64 = 10;
pub const DEFAULT_ORDER_TTL_BLOCKS: u64 = 24;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_LEASE_TTL_BLOCKS: u64 = 180;
pub const DEFAULT_FENCE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_LOW_FEE_BPS: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 18;
pub const DEFAULT_CREDIT_REBATE_BPS: u64 = 12;
pub const DEFAULT_PREFETCH_BOND_BPS: u64 = 250;
pub const DEFAULT_MIN_AVAILABILITY_QUORUM: u64 = 3;
pub const DEFAULT_TARGET_REPLICA_COUNT: u64 = 8;
pub const DEFAULT_PUBLIC_BUCKET_SIZE: u64 = 32;
pub const DEFAULT_MAX_LANES: usize = 262_144;
pub const DEFAULT_MAX_ORDERS: usize = 1_048_576;
pub const DEFAULT_MAX_AUCTIONS: usize = 524_288;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 2_097_152;
pub const DEFAULT_MAX_LEASES: usize = 1_048_576;
pub const DEFAULT_MAX_FENCES: usize = 1_048_576;
pub const DEFAULT_MAX_CREDITS: usize = 1_048_576;
pub const DEFAULT_MAX_REDACTIONS: usize = 1_048_576;
pub const DEFAULT_MAX_OPERATORS: usize = 262_144;
pub const DEFAULT_MAX_NULLIFIERS: usize = 4_194_304;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobLaneClass {
    SponsoredLowFee,
    FastWitness,
    BulkBackfill,
    BridgeExit,
    SettlementCritical,
    AuditSafe,
    EmergencyReplay,
}

impl BlobLaneClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::FastWitness => "fast_witness",
            Self::BulkBackfill => "bulk_backfill",
            Self::BridgeExit => "bridge_exit",
            Self::SettlementCritical => "settlement_critical",
            Self::AuditSafe => "audit_safe",
            Self::EmergencyReplay => "emergency_replay",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::EmergencyReplay => 1_050,
            Self::SettlementCritical => 1_000,
            Self::FastWitness => 940,
            Self::BridgeExit => 880,
            Self::SponsoredLowFee => 820,
            Self::AuditSafe => 700,
            Self::BulkBackfill => 540,
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::SponsoredLowFee => config.low_fee_bps,
            Self::BulkBackfill | Self::AuditSafe => config.max_user_fee_bps / 2,
            Self::FastWitness | Self::BridgeExit => config.max_user_fee_bps,
            Self::SettlementCritical | Self::EmergencyReplay => config.max_user_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneStatus {
    Open,
    Saturated,
    Degraded,
    Paused,
    Draining,
    Sealed,
}

impl LaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Saturated => "saturated",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Sealed => "sealed",
        }
    }

    pub fn accepts_orders(self) -> bool {
        matches!(self, Self::Open | Self::Degraded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaKind {
    BlobWitness,
    BlobRange,
    OutputSet,
    InclusionPath,
    AvailabilityRepair,
    ReorgReplay,
    StateDiff,
    BridgeReceipt,
}

impl DeltaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobWitness => "blob_witness",
            Self::BlobRange => "blob_range",
            Self::OutputSet => "output_set",
            Self::InclusionPath => "inclusion_path",
            Self::AvailabilityRepair => "availability_repair",
            Self::ReorgReplay => "reorg_replay",
            Self::StateDiff => "state_diff",
            Self::BridgeReceipt => "bridge_receipt",
        }
    }

    pub fn complexity_weight(self) -> u64 {
        match self {
            Self::ReorgReplay => 1_050,
            Self::StateDiff => 980,
            Self::BridgeReceipt => 920,
            Self::BlobWitness => 880,
            Self::AvailabilityRepair => 820,
            Self::InclusionPath => 760,
            Self::BlobRange => 680,
            Self::OutputSet => 620,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Open,
    Prefetching,
    Leased,
    Attested,
    CreditQueued,
    Settled,
    Expired,
    Cancelled,
    Rejected,
}

impl OrderStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Prefetching => "prefetching",
            Self::Leased => "leased",
            Self::Attested => "attested",
            Self::CreditQueued => "credit_queued",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Prefetching | Self::Leased | Self::Attested | Self::CreditQueued
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    CommitOpen,
    RevealOpen,
    Selected,
    Prefetching,
    Filled,
    Expired,
    Slashed,
    Cancelled,
}

impl AuctionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitOpen => "commit_open",
            Self::RevealOpen => "reveal_open",
            Self::Selected => "selected",
            Self::Prefetching => "prefetching",
            Self::Filled => "filled",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::CommitOpen | Self::RevealOpen | Self::Selected | Self::Prefetching
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Quorum,
    Superseded,
    Expired,
    Revoked,
    Rejected,
}

impl AttestationStatus {
    pub fn counts_for_availability(self) -> bool {
        matches!(self, Self::Accepted | Self::Quorum)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Offered,
    Active,
    Renewed,
    Released,
    Expired,
    Slashed,
}

impl LeaseStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Offered | Self::Active | Self::Renewed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    BlobRootRotated,
    AttestationExpired,
    AuctionSlashed,
    LeaseRevoked,
    NullifierReuse,
    PrivacyBudgetExceeded,
    OperatorDegraded,
    ReorgBoundary,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobRootRotated => "blob_root_rotated",
            Self::AttestationExpired => "attestation_expired",
            Self::AuctionSlashed => "auction_slashed",
            Self::LeaseRevoked => "lease_revoked",
            Self::NullifierReuse => "nullifier_reuse",
            Self::PrivacyBudgetExceeded => "privacy_budget_exceeded",
            Self::OperatorDegraded => "operator_degraded",
            Self::ReorgBoundary => "reorg_boundary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Queued,
    Sponsored,
    Applied,
    Refunded,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionScope {
    Lane,
    Order,
    Auction,
    Attestation,
    Lease,
    Operator,
    PublicRecord,
}

impl RedactionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Lane => "lane",
            Self::Order => "order",
            Self::Auction => "auction",
            Self::Attestation => "attestation",
            Self::Lease => "lease",
            Self::Operator => "operator",
            Self::PublicRecord => "public_record",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorStatus {
    Active,
    Degraded,
    Paused,
    Slashed,
    Exited,
}

impl OperatorStatus {
    pub fn serves(self) -> bool {
        matches!(self, Self::Active | Self::Degraded)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub lane_scheme: String,
    pub order_scheme: String,
    pub auction_scheme: String,
    pub pq_attestation_scheme: String,
    pub lease_scheme: String,
    pub fence_scheme: String,
    pub credit_scheme: String,
    pub redaction_scheme: String,
    pub operator_summary_scheme: String,
    pub public_record_scheme: String,
    pub privacy_boundary: String,
    pub min_ring_size: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub blob_chunk_bytes: u64,
    pub max_blob_chunks: u64,
    pub prefetch_ttl_blocks: u64,
    pub order_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub lease_ttl_blocks: u64,
    pub fence_ttl_blocks: u64,
    pub low_fee_bps: u64,
    pub max_user_fee_bps: u64,
    pub credit_rebate_bps: u64,
    pub prefetch_bond_bps: u64,
    pub min_availability_quorum: u64,
    pub target_replica_count: u64,
    pub public_bucket_size: u64,
    pub max_lanes: usize,
    pub max_orders: usize,
    pub max_auctions: usize,
    pub max_attestations: usize,
    pub max_leases: usize,
    pub max_fences: usize,
    pub max_credits: usize,
    pub max_redactions: usize,
    pub max_operators: usize,
    pub max_nullifiers: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            lane_scheme: ENCRYPTED_BLOB_LANE_SCHEME.to_string(),
            order_scheme: WITNESS_DELTA_ORDER_SCHEME.to_string(),
            auction_scheme: PREFETCH_AUCTION_SCHEME.to_string(),
            pq_attestation_scheme: PQ_AVAILABILITY_ATTESTATION_SCHEME.to_string(),
            lease_scheme: CACHE_LEASE_SCHEME.to_string(),
            fence_scheme: INVALIDATION_FENCE_SCHEME.to_string(),
            credit_scheme: LOW_FEE_PROOF_CREDIT_SCHEME.to_string(),
            redaction_scheme: REDACTION_METADATA_SCHEME.to_string(),
            operator_summary_scheme: OPERATOR_SUMMARY_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            privacy_boundary: PRIVACY_BOUNDARY.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            blob_chunk_bytes: DEFAULT_BLOB_CHUNK_BYTES,
            max_blob_chunks: DEFAULT_MAX_BLOB_CHUNKS,
            prefetch_ttl_blocks: DEFAULT_PREFETCH_TTL_BLOCKS,
            order_ttl_blocks: DEFAULT_ORDER_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            lease_ttl_blocks: DEFAULT_LEASE_TTL_BLOCKS,
            fence_ttl_blocks: DEFAULT_FENCE_TTL_BLOCKS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            credit_rebate_bps: DEFAULT_CREDIT_REBATE_BPS,
            prefetch_bond_bps: DEFAULT_PREFETCH_BOND_BPS,
            min_availability_quorum: DEFAULT_MIN_AVAILABILITY_QUORUM,
            target_replica_count: DEFAULT_TARGET_REPLICA_COUNT,
            public_bucket_size: DEFAULT_PUBLIC_BUCKET_SIZE,
            max_lanes: DEFAULT_MAX_LANES,
            max_orders: DEFAULT_MAX_ORDERS,
            max_auctions: DEFAULT_MAX_AUCTIONS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_leases: DEFAULT_MAX_LEASES,
            max_fences: DEFAULT_MAX_FENCES,
            max_credits: DEFAULT_MAX_CREDITS,
            max_redactions: DEFAULT_MAX_REDACTIONS,
            max_operators: DEFAULT_MAX_OPERATORS,
            max_nullifiers: DEFAULT_MAX_NULLIFIERS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("protocol_version", &self.protocol_version)?;
        ensure_nonempty("chain_id", &self.chain_id)?;
        ensure_positive_u64("min_ring_size", self.min_ring_size)?;
        ensure_positive_u64("min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_positive_u64("blob_chunk_bytes", self.blob_chunk_bytes)?;
        ensure_positive_u64("max_blob_chunks", self.max_blob_chunks)?;
        ensure_positive_u64("min_availability_quorum", self.min_availability_quorum)?;
        ensure_positive_u64("target_replica_count", self.target_replica_count)?;
        ensure_bps("low_fee_bps", self.low_fee_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("credit_rebate_bps", self.credit_rebate_bps)?;
        ensure_bps("prefetch_bond_bps", self.prefetch_bond_bps)?;
        ensure_positive_usize("max_lanes", self.max_lanes)?;
        ensure_positive_usize("max_orders", self.max_orders)?;
        ensure_positive_usize("max_auctions", self.max_auctions)?;
        ensure_positive_usize("max_attestations", self.max_attestations)?;
        ensure_positive_usize("max_leases", self.max_leases)?;
        ensure_positive_usize("max_fences", self.max_fences)?;
        ensure_positive_usize("max_credits", self.max_credits)?;
        ensure_positive_usize("max_redactions", self.max_redactions)?;
        ensure_positive_usize("max_operators", self.max_operators)?;
        ensure_positive_usize("max_nullifiers", self.max_nullifiers)?;
        if self.low_fee_bps > self.max_user_fee_bps {
            return Err("low_fee_bps cannot exceed max_user_fee_bps".to_string());
        }
        if self.min_pq_security_bits > self.target_pq_security_bits {
            return Err("min_pq_security_bits cannot exceed target_pq_security_bits".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_lane_sequence: u64,
    pub next_order_sequence: u64,
    pub next_auction_sequence: u64,
    pub next_attestation_sequence: u64,
    pub next_lease_sequence: u64,
    pub next_fence_sequence: u64,
    pub next_credit_sequence: u64,
    pub next_redaction_sequence: u64,
    pub next_operator_sequence: u64,
    pub lane_count: u64,
    pub order_count: u64,
    pub auction_count: u64,
    pub attestation_count: u64,
    pub lease_count: u64,
    pub fence_count: u64,
    pub credit_count: u64,
    pub redaction_count: u64,
    pub operator_count: u64,
    pub public_record_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub lane_root: String,
    pub order_root: String,
    pub auction_root: String,
    pub attestation_root: String,
    pub lease_root: String,
    pub fence_root: String,
    pub credit_root: String,
    pub redaction_root: String,
    pub operator_root: String,
    pub nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBlobLaneRequest {
    pub operator_commitment: String,
    pub class: BlobLaneClass,
    pub encrypted_blob_root: String,
    pub sealed_lane_key_root: String,
    pub witness_index_root: String,
    pub availability_set_root: String,
    pub redaction_policy_root: String,
    pub lane_nullifier: String,
    pub opened_height: u64,
    pub max_blob_chunks: u64,
    pub max_fee_bps: u64,
    pub replica_target: u64,
}

impl EncryptedBlobLaneRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_root("encrypted_blob_root", &self.encrypted_blob_root)?;
        ensure_root("sealed_lane_key_root", &self.sealed_lane_key_root)?;
        ensure_root("witness_index_root", &self.witness_index_root)?;
        ensure_root("availability_set_root", &self.availability_set_root)?;
        ensure_root("redaction_policy_root", &self.redaction_policy_root)?;
        ensure_nonempty("lane_nullifier", &self.lane_nullifier)?;
        ensure_positive_u64("max_blob_chunks", self.max_blob_chunks)?;
        ensure_bps("max_fee_bps", self.max_fee_bps)?;
        ensure_positive_u64("replica_target", self.replica_target)?;
        if self.max_blob_chunks > config.max_blob_chunks {
            return Err("lane max_blob_chunks exceeds config limit".to_string());
        }
        if self.max_fee_bps > config.max_user_fee_bps {
            return Err("lane max_fee_bps exceeds config limit".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedBlobLaneRecord {
    pub lane_id: String,
    pub operator_commitment: String,
    pub class: BlobLaneClass,
    pub status: LaneStatus,
    pub encrypted_blob_root: String,
    pub sealed_lane_key_root: String,
    pub witness_index_root: String,
    pub availability_set_root: String,
    pub redaction_policy_root: String,
    pub lane_nullifier: String,
    pub opened_height: u64,
    pub updated_height: u64,
    pub max_blob_chunks: u64,
    pub max_fee_bps: u64,
    pub replica_target: u64,
    pub active_order_count: u64,
    pub attested_replica_count: u64,
    pub priority_score: u64,
    pub public_bucket: u64,
}

impl EncryptedBlobLaneRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn accepts_orders(&self) -> bool {
        self.status.accepts_orders()
    }

    pub fn availability_gap(&self) -> u64 {
        self.replica_target
            .saturating_sub(self.attested_replica_count)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessDeltaOrderRequest {
    pub lane_id: String,
    pub owner_commitment: String,
    pub delta_kind: DeltaKind,
    pub witness_delta_root: String,
    pub encrypted_payload_root: String,
    pub availability_hint_root: String,
    pub fee_commitment_root: String,
    pub order_nullifier: String,
    pub max_fee_micro_units: u64,
    pub requested_credit_bps: u64,
    pub privacy_set_size: u64,
    pub min_ring_size: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
}

impl WitnessDeltaOrderRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_root("witness_delta_root", &self.witness_delta_root)?;
        ensure_root("encrypted_payload_root", &self.encrypted_payload_root)?;
        ensure_root("availability_hint_root", &self.availability_hint_root)?;
        ensure_root("fee_commitment_root", &self.fee_commitment_root)?;
        ensure_nonempty("order_nullifier", &self.order_nullifier)?;
        ensure_positive_u64("max_fee_micro_units", self.max_fee_micro_units)?;
        ensure_bps("requested_credit_bps", self.requested_credit_bps)?;
        if self.min_ring_size < config.min_ring_size {
            return Err("order min_ring_size below config minimum".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("order privacy_set_size below config minimum".to_string());
        }
        if self.deadline_height <= self.opened_height {
            return Err("deadline_height must be greater than opened_height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WitnessDeltaOrderRecord {
    pub order_id: String,
    pub lane_id: String,
    pub owner_commitment: String,
    pub delta_kind: DeltaKind,
    pub status: OrderStatus,
    pub witness_delta_root: String,
    pub encrypted_payload_root: String,
    pub availability_hint_root: String,
    pub fee_commitment_root: String,
    pub order_nullifier: String,
    pub max_fee_micro_units: u64,
    pub requested_credit_bps: u64,
    pub privacy_set_size: u64,
    pub min_ring_size: u64,
    pub opened_height: u64,
    pub deadline_height: u64,
    pub selected_auction_id: Option<String>,
    pub active_lease_id: Option<String>,
    pub attestation_ids: Vec<String>,
    pub priority_score: u64,
    pub public_bucket: u64,
}

impl WitnessDeltaOrderRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn live(&self) -> bool {
        self.status.live()
    }

    pub fn expires_in(&self, height: u64) -> u64 {
        self.deadline_height.saturating_sub(height)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchAuctionRequest {
    pub order_id: String,
    pub lane_id: String,
    pub solver_commitment: String,
    pub sealed_bid_root: String,
    pub prefetch_plan_root: String,
    pub cache_warm_root: String,
    pub bid_nullifier: String,
    pub max_latency_ms: u64,
    pub fee_micro_units: u64,
    pub bond_micro_units: u64,
    pub opened_height: u64,
}

impl PrefetchAuctionRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("order_id", &self.order_id)?;
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("solver_commitment", &self.solver_commitment)?;
        ensure_root("sealed_bid_root", &self.sealed_bid_root)?;
        ensure_root("prefetch_plan_root", &self.prefetch_plan_root)?;
        ensure_root("cache_warm_root", &self.cache_warm_root)?;
        ensure_nonempty("bid_nullifier", &self.bid_nullifier)?;
        ensure_positive_u64("max_latency_ms", self.max_latency_ms)?;
        ensure_positive_u64("bond_micro_units", self.bond_micro_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchAuctionRecord {
    pub auction_id: String,
    pub order_id: String,
    pub lane_id: String,
    pub solver_commitment: String,
    pub status: AuctionStatus,
    pub sealed_bid_root: String,
    pub prefetch_plan_root: String,
    pub cache_warm_root: String,
    pub bid_nullifier: String,
    pub max_latency_ms: u64,
    pub fee_micro_units: u64,
    pub bond_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub score: u64,
}

impl PrefetchAuctionRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn active(&self) -> bool {
        self.status.active()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAvailabilityAttestationRequest {
    pub lane_id: String,
    pub order_id: String,
    pub auction_id: Option<String>,
    pub attestor_commitment: String,
    pub availability_root: String,
    pub pq_signature_root: String,
    pub replica_set_root: String,
    pub sealed_receipt_root: String,
    pub attestation_nullifier: String,
    pub pq_security_bits: u16,
    pub available_chunks: u64,
    pub total_chunks: u64,
    pub observed_height: u64,
}

impl PqAvailabilityAttestationRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("order_id", &self.order_id)?;
        ensure_nonempty("attestor_commitment", &self.attestor_commitment)?;
        ensure_root("availability_root", &self.availability_root)?;
        ensure_root("pq_signature_root", &self.pq_signature_root)?;
        ensure_root("replica_set_root", &self.replica_set_root)?;
        ensure_root("sealed_receipt_root", &self.sealed_receipt_root)?;
        ensure_nonempty("attestation_nullifier", &self.attestation_nullifier)?;
        ensure_positive_u64("total_chunks", self.total_chunks)?;
        if self.available_chunks > self.total_chunks {
            return Err("available_chunks cannot exceed total_chunks".to_string());
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err("pq_security_bits below config minimum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqAvailabilityAttestationRecord {
    pub attestation_id: String,
    pub lane_id: String,
    pub order_id: String,
    pub auction_id: Option<String>,
    pub attestor_commitment: String,
    pub status: AttestationStatus,
    pub availability_root: String,
    pub pq_signature_root: String,
    pub replica_set_root: String,
    pub sealed_receipt_root: String,
    pub attestation_nullifier: String,
    pub pq_security_bits: u16,
    pub available_chunks: u64,
    pub total_chunks: u64,
    pub observed_height: u64,
    pub expires_height: u64,
    pub availability_bps: u64,
}

impl PqAvailabilityAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn counts_for_availability(&self) -> bool {
        self.status.counts_for_availability()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLeaseRequest {
    pub lane_id: String,
    pub order_id: String,
    pub auction_id: String,
    pub lessee_commitment: String,
    pub cache_key_root: String,
    pub lease_terms_root: String,
    pub encrypted_locator_root: String,
    pub lease_nullifier: String,
    pub chunk_count: u64,
    pub fee_micro_units: u64,
    pub starts_height: u64,
}

impl CacheLeaseRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("order_id", &self.order_id)?;
        ensure_nonempty("auction_id", &self.auction_id)?;
        ensure_nonempty("lessee_commitment", &self.lessee_commitment)?;
        ensure_root("cache_key_root", &self.cache_key_root)?;
        ensure_root("lease_terms_root", &self.lease_terms_root)?;
        ensure_root("encrypted_locator_root", &self.encrypted_locator_root)?;
        ensure_nonempty("lease_nullifier", &self.lease_nullifier)?;
        ensure_positive_u64("chunk_count", self.chunk_count)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheLeaseRecord {
    pub lease_id: String,
    pub lane_id: String,
    pub order_id: String,
    pub auction_id: String,
    pub lessee_commitment: String,
    pub status: LeaseStatus,
    pub cache_key_root: String,
    pub lease_terms_root: String,
    pub encrypted_locator_root: String,
    pub lease_nullifier: String,
    pub chunk_count: u64,
    pub fee_micro_units: u64,
    pub starts_height: u64,
    pub expires_height: u64,
    pub renewal_count: u64,
}

impl CacheLeaseRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFenceRequest {
    pub lane_id: String,
    pub subject_id: String,
    pub reason: FenceReason,
    pub invalidated_root: String,
    pub replacement_root: String,
    pub evidence_root: String,
    pub fence_nullifier: String,
    pub reported_height: u64,
}

impl InvalidationFenceRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("lane_id", &self.lane_id)?;
        ensure_nonempty("subject_id", &self.subject_id)?;
        ensure_root("invalidated_root", &self.invalidated_root)?;
        ensure_root("replacement_root", &self.replacement_root)?;
        ensure_root("evidence_root", &self.evidence_root)?;
        ensure_nonempty("fence_nullifier", &self.fence_nullifier)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFenceRecord {
    pub fence_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub reason: FenceReason,
    pub invalidated_root: String,
    pub replacement_root: String,
    pub evidence_root: String,
    pub fence_nullifier: String,
    pub reported_height: u64,
    pub expires_height: u64,
}

impl InvalidationFenceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofCreditRequest {
    pub order_id: String,
    pub lease_id: String,
    pub sponsor_commitment: String,
    pub credit_commitment_root: String,
    pub fee_receipt_root: String,
    pub credit_nullifier: String,
    pub fee_paid_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub opened_height: u64,
}

impl LowFeeProofCreditRequest {
    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_nonempty("order_id", &self.order_id)?;
        ensure_nonempty("lease_id", &self.lease_id)?;
        ensure_nonempty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_root("credit_commitment_root", &self.credit_commitment_root)?;
        ensure_root("fee_receipt_root", &self.fee_receipt_root)?;
        ensure_nonempty("credit_nullifier", &self.credit_nullifier)?;
        ensure_positive_u64("fee_paid_micro_units", self.fee_paid_micro_units)?;
        ensure_bps("requested_rebate_bps", self.requested_rebate_bps)?;
        if self.requested_rebate_bps > config.credit_rebate_bps {
            return Err("requested_rebate_bps exceeds config credit rebate".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeProofCreditRecord {
    pub credit_id: String,
    pub order_id: String,
    pub lease_id: String,
    pub sponsor_commitment: String,
    pub status: CreditStatus,
    pub credit_commitment_root: String,
    pub fee_receipt_root: String,
    pub credit_nullifier: String,
    pub fee_paid_micro_units: u64,
    pub requested_rebate_bps: u64,
    pub credit_micro_units: u64,
    pub opened_height: u64,
}

impl LowFeeProofCreditRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionMetadataRequest {
    pub subject_id: String,
    pub scope: RedactionScope,
    pub owner_commitment: String,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
    pub view_tag_root: String,
    pub redaction_nullifier: String,
    pub redaction_units: u64,
    pub opened_height: u64,
}

impl RedactionMetadataRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("subject_id", &self.subject_id)?;
        ensure_nonempty("owner_commitment", &self.owner_commitment)?;
        ensure_root("redacted_field_root", &self.redacted_field_root)?;
        ensure_root("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_root("view_tag_root", &self.view_tag_root)?;
        ensure_nonempty("redaction_nullifier", &self.redaction_nullifier)?;
        ensure_positive_u64("redaction_units", self.redaction_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionMetadataRecord {
    pub redaction_id: String,
    pub subject_id: String,
    pub scope: RedactionScope,
    pub owner_commitment: String,
    pub redacted_field_root: String,
    pub disclosure_policy_root: String,
    pub view_tag_root: String,
    pub redaction_nullifier: String,
    pub redaction_units: u64,
    pub opened_height: u64,
}

impl RedactionMetadataRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub operator_commitment: String,
    pub service_root: String,
    pub stake_root: String,
    pub performance_root: String,
    pub pq_key_root: String,
    pub summary_nullifier: String,
    pub served_lanes: u64,
    pub availability_bps: u64,
    pub low_fee_fill_bps: u64,
    pub updated_height: u64,
}

impl OperatorSummaryRequest {
    pub fn validate(&self) -> Result<()> {
        ensure_nonempty("operator_commitment", &self.operator_commitment)?;
        ensure_root("service_root", &self.service_root)?;
        ensure_root("stake_root", &self.stake_root)?;
        ensure_root("performance_root", &self.performance_root)?;
        ensure_root("pq_key_root", &self.pq_key_root)?;
        ensure_nonempty("summary_nullifier", &self.summary_nullifier)?;
        ensure_bps("availability_bps", self.availability_bps)?;
        ensure_bps("low_fee_fill_bps", self.low_fee_fill_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRecord {
    pub operator_id: String,
    pub operator_commitment: String,
    pub status: OperatorStatus,
    pub service_root: String,
    pub stake_root: String,
    pub performance_root: String,
    pub pq_key_root: String,
    pub summary_nullifier: String,
    pub served_lanes: u64,
    pub availability_bps: u64,
    pub low_fee_fill_bps: u64,
    pub updated_height: u64,
    pub score: u64,
}

impl OperatorSummaryRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub lanes: BTreeMap<String, EncryptedBlobLaneRecord>,
    pub orders: BTreeMap<String, WitnessDeltaOrderRecord>,
    pub auctions: BTreeMap<String, PrefetchAuctionRecord>,
    pub attestations: BTreeMap<String, PqAvailabilityAttestationRecord>,
    pub leases: BTreeMap<String, CacheLeaseRecord>,
    pub fences: BTreeMap<String, InvalidationFenceRecord>,
    pub credits: BTreeMap<String, LowFeeProofCreditRecord>,
    pub redactions: BTreeMap<String, RedactionMetadataRecord>,
    pub operators: BTreeMap<String, OperatorSummaryRecord>,
    pub nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            lanes: BTreeMap::new(),
            orders: BTreeMap::new(),
            auctions: BTreeMap::new(),
            attestations: BTreeMap::new(),
            leases: BTreeMap::new(),
            fences: BTreeMap::new(),
            credits: BTreeMap::new(),
            redactions: BTreeMap::new(),
            operators: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet()).expect("devnet private l2 blob witness delta market config")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let operator = state
            .upsert_operator_summary(OperatorSummaryRequest {
                operator_commitment: "operator:fast-pq-blob-demo".to_string(),
                service_root: demo_root("operator-service"),
                stake_root: demo_root("operator-stake"),
                performance_root: demo_root("operator-performance"),
                pq_key_root: demo_root("operator-pq-key"),
                summary_nullifier: "operator-summary-nullifier-demo".to_string(),
                served_lanes: 4,
                availability_bps: 9_960,
                low_fee_fill_bps: 9_240,
                updated_height: DEVNET_HEIGHT,
            })
            .expect("demo operator summary");
        let lane = state
            .open_encrypted_blob_lane(EncryptedBlobLaneRequest {
                operator_commitment: operator.operator_commitment.clone(),
                class: BlobLaneClass::FastWitness,
                encrypted_blob_root: demo_root("encrypted-blob"),
                sealed_lane_key_root: demo_root("sealed-lane-key"),
                witness_index_root: demo_root("witness-index"),
                availability_set_root: demo_root("availability-set"),
                redaction_policy_root: demo_root("redaction-policy"),
                lane_nullifier: "lane-nullifier-demo".to_string(),
                opened_height: DEVNET_HEIGHT,
                max_blob_chunks: 128,
                max_fee_bps: 12,
                replica_target: 6,
            })
            .expect("demo blob lane");
        let order = state
            .open_witness_delta_order(WitnessDeltaOrderRequest {
                lane_id: lane.lane_id.clone(),
                owner_commitment: "owner:wallet-session-demo".to_string(),
                delta_kind: DeltaKind::BlobWitness,
                witness_delta_root: demo_root("witness-delta"),
                encrypted_payload_root: demo_root("encrypted-payload"),
                availability_hint_root: demo_root("availability-hint"),
                fee_commitment_root: demo_root("fee-commitment"),
                order_nullifier: "order-nullifier-demo".to_string(),
                max_fee_micro_units: 22_000,
                requested_credit_bps: 8,
                privacy_set_size: 131_072,
                min_ring_size: 16,
                opened_height: DEVNET_HEIGHT + 1,
                deadline_height: DEVNET_HEIGHT + 18,
            })
            .expect("demo witness delta order");
        let auction = state
            .open_prefetch_auction(PrefetchAuctionRequest {
                order_id: order.order_id.clone(),
                lane_id: lane.lane_id.clone(),
                solver_commitment: "solver:cache-prefetch-demo".to_string(),
                sealed_bid_root: demo_root("sealed-bid"),
                prefetch_plan_root: demo_root("prefetch-plan"),
                cache_warm_root: demo_root("cache-warm"),
                bid_nullifier: "bid-nullifier-demo".to_string(),
                max_latency_ms: 250,
                fee_micro_units: 4_200,
                bond_micro_units: 700_000,
                opened_height: DEVNET_HEIGHT + 2,
            })
            .expect("demo prefetch auction");
        state
            .accept_prefetch_auction(&auction.auction_id)
            .expect("demo accept auction");
        let lease = state
            .create_cache_lease(CacheLeaseRequest {
                lane_id: lane.lane_id.clone(),
                order_id: order.order_id.clone(),
                auction_id: auction.auction_id.clone(),
                lessee_commitment: "lessee:solver-cache-demo".to_string(),
                cache_key_root: demo_root("cache-key"),
                lease_terms_root: demo_root("lease-terms"),
                encrypted_locator_root: demo_root("encrypted-locator"),
                lease_nullifier: "lease-nullifier-demo".to_string(),
                chunk_count: 64,
                fee_micro_units: 4_200,
                starts_height: DEVNET_HEIGHT + 3,
            })
            .expect("demo cache lease");
        state
            .submit_pq_availability_attestation(PqAvailabilityAttestationRequest {
                lane_id: lane.lane_id.clone(),
                order_id: order.order_id.clone(),
                auction_id: Some(auction.auction_id.clone()),
                attestor_commitment: "attestor:pq-availability-demo".to_string(),
                availability_root: demo_root("availability"),
                pq_signature_root: demo_root("pq-signature"),
                replica_set_root: demo_root("replica-set"),
                sealed_receipt_root: demo_root("sealed-receipt"),
                attestation_nullifier: "attestation-nullifier-demo".to_string(),
                pq_security_bits: 256,
                available_chunks: 64,
                total_chunks: 64,
                observed_height: DEVNET_HEIGHT + 4,
            })
            .expect("demo availability attestation");
        state
            .issue_low_fee_proof_credit(LowFeeProofCreditRequest {
                order_id: order.order_id.clone(),
                lease_id: lease.lease_id.clone(),
                sponsor_commitment: "sponsor:low-fee-demo".to_string(),
                credit_commitment_root: demo_root("credit-commitment"),
                fee_receipt_root: demo_root("fee-receipt"),
                credit_nullifier: "credit-nullifier-demo".to_string(),
                fee_paid_micro_units: 4_200,
                requested_rebate_bps: 8,
                opened_height: DEVNET_HEIGHT + 5,
            })
            .expect("demo low fee credit");
        state
            .record_redaction_metadata(RedactionMetadataRequest {
                subject_id: order.order_id.clone(),
                scope: RedactionScope::Order,
                owner_commitment: "owner:wallet-session-demo".to_string(),
                redacted_field_root: demo_root("redacted-fields"),
                disclosure_policy_root: demo_root("disclosure-policy"),
                view_tag_root: demo_root("view-tag"),
                redaction_nullifier: "redaction-nullifier-demo".to_string(),
                redaction_units: 7,
                opened_height: DEVNET_HEIGHT + 6,
            })
            .expect("demo redaction metadata");
        state.refresh_roots();
        state
    }

    pub fn open_encrypted_blob_lane(
        &mut self,
        request: EncryptedBlobLaneRequest,
    ) -> Result<EncryptedBlobLaneRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            "encrypted blob lanes",
            self.lanes.len(),
            self.config.max_lanes,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.lane_nullifier)?;
        let sequence = self.counters.next_lane_sequence;
        self.counters.next_lane_sequence = self.counters.next_lane_sequence.saturating_add(1);
        let lane_id = encrypted_blob_lane_id(&request, sequence);
        ensure_absent("encrypted blob lane", &self.lanes, &lane_id)?;
        let public_bucket = public_bucket(request.opened_height, self.config.public_bucket_size);
        let record = EncryptedBlobLaneRecord {
            lane_id: lane_id.clone(),
            operator_commitment: request.operator_commitment,
            class: request.class,
            status: LaneStatus::Open,
            encrypted_blob_root: request.encrypted_blob_root,
            sealed_lane_key_root: request.sealed_lane_key_root,
            witness_index_root: request.witness_index_root,
            availability_set_root: request.availability_set_root,
            redaction_policy_root: request.redaction_policy_root,
            lane_nullifier: request.lane_nullifier,
            opened_height: request.opened_height,
            updated_height: request.opened_height,
            max_blob_chunks: request.max_blob_chunks,
            max_fee_bps: request.max_fee_bps,
            replica_target: request.replica_target,
            active_order_count: 0,
            attested_replica_count: 0,
            priority_score: lane_priority_score(
                request.class,
                request.replica_target,
                public_bucket,
            ),
            public_bucket,
        };
        self.nullifiers.insert(record.lane_nullifier.clone());
        self.counters.lane_count = self.counters.lane_count.saturating_add(1);
        self.lanes.insert(lane_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_witness_delta_order(
        &mut self,
        request: WitnessDeltaOrderRequest,
    ) -> Result<WitnessDeltaOrderRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            "witness delta orders",
            self.orders.len(),
            self.config.max_orders,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.order_nullifier)?;
        let lane = self.require_lane(&request.lane_id)?;
        if !lane.accepts_orders() {
            return Err(format!("lane {} does not accept orders", request.lane_id));
        }
        if request.deadline_height
            > request
                .opened_height
                .saturating_add(self.config.order_ttl_blocks)
        {
            return Err("order deadline exceeds ttl".to_string());
        }
        let sequence = self.counters.next_order_sequence;
        self.counters.next_order_sequence = self.counters.next_order_sequence.saturating_add(1);
        let order_id = witness_delta_order_id(&request, sequence);
        ensure_absent("witness delta order", &self.orders, &order_id)?;
        let priority_score = witness_delta_order_score(
            request.delta_kind,
            request.privacy_set_size,
            request.max_fee_micro_units,
            request.requested_credit_bps,
        );
        let record = WitnessDeltaOrderRecord {
            order_id: order_id.clone(),
            lane_id: request.lane_id.clone(),
            owner_commitment: request.owner_commitment,
            delta_kind: request.delta_kind,
            status: OrderStatus::Open,
            witness_delta_root: request.witness_delta_root,
            encrypted_payload_root: request.encrypted_payload_root,
            availability_hint_root: request.availability_hint_root,
            fee_commitment_root: request.fee_commitment_root,
            order_nullifier: request.order_nullifier,
            max_fee_micro_units: request.max_fee_micro_units,
            requested_credit_bps: request.requested_credit_bps,
            privacy_set_size: request.privacy_set_size,
            min_ring_size: request.min_ring_size,
            opened_height: request.opened_height,
            deadline_height: request.deadline_height,
            selected_auction_id: None,
            active_lease_id: None,
            attestation_ids: Vec::new(),
            priority_score,
            public_bucket: public_bucket(request.opened_height, self.config.public_bucket_size),
        };
        self.nullifiers.insert(record.order_nullifier.clone());
        self.counters.order_count = self.counters.order_count.saturating_add(1);
        if let Some(lane) = self.lanes.get_mut(&record.lane_id) {
            lane.active_order_count = lane.active_order_count.saturating_add(1);
            lane.updated_height = record.opened_height;
        }
        self.orders.insert(order_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn open_prefetch_auction(
        &mut self,
        request: PrefetchAuctionRequest,
    ) -> Result<PrefetchAuctionRecord> {
        request.validate()?;
        ensure_capacity(
            "prefetch auctions",
            self.auctions.len(),
            self.config.max_auctions,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.bid_nullifier)?;
        self.require_lane(&request.lane_id)?;
        let order = self.require_order(&request.order_id)?;
        if order.lane_id != request.lane_id {
            return Err("auction lane_id does not match order lane_id".to_string());
        }
        if !order.live() {
            return Err("cannot auction non-live order".to_string());
        }
        if request.fee_micro_units > order.max_fee_micro_units {
            return Err("prefetch auction fee exceeds order cap".to_string());
        }
        let sequence = self.counters.next_auction_sequence;
        self.counters.next_auction_sequence = self.counters.next_auction_sequence.saturating_add(1);
        let auction_id = prefetch_auction_id(&request, sequence);
        ensure_absent("prefetch auction", &self.auctions, &auction_id)?;
        let record = PrefetchAuctionRecord {
            auction_id: auction_id.clone(),
            order_id: request.order_id,
            lane_id: request.lane_id,
            solver_commitment: request.solver_commitment,
            status: AuctionStatus::CommitOpen,
            sealed_bid_root: request.sealed_bid_root,
            prefetch_plan_root: request.prefetch_plan_root,
            cache_warm_root: request.cache_warm_root,
            bid_nullifier: request.bid_nullifier,
            max_latency_ms: request.max_latency_ms,
            fee_micro_units: request.fee_micro_units,
            bond_micro_units: request.bond_micro_units,
            opened_height: request.opened_height,
            expires_height: request
                .opened_height
                .saturating_add(self.config.prefetch_ttl_blocks),
            score: prefetch_auction_score(
                request.fee_micro_units,
                request.max_latency_ms,
                request.bond_micro_units,
            ),
        };
        self.nullifiers.insert(record.bid_nullifier.clone());
        self.counters.auction_count = self.counters.auction_count.saturating_add(1);
        self.auctions.insert(auction_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn accept_prefetch_auction(&mut self, auction_id: &str) -> Result<PrefetchAuctionRecord> {
        let (order_id, lane_id) = {
            let auction = self.require_auction(auction_id)?;
            (auction.order_id.clone(), auction.lane_id.clone())
        };
        if let Some(auction) = self.auctions.get_mut(auction_id) {
            auction.status = AuctionStatus::Selected;
        }
        if let Some(order) = self.orders.get_mut(&order_id) {
            order.status = OrderStatus::Prefetching;
            order.selected_auction_id = Some(auction_id.to_string());
        }
        if let Some(lane) = self.lanes.get_mut(&lane_id) {
            lane.status = LaneStatus::Saturated;
        }
        self.refresh_roots();
        self.require_auction(auction_id).cloned()
    }

    pub fn submit_pq_availability_attestation(
        &mut self,
        request: PqAvailabilityAttestationRequest,
    ) -> Result<PqAvailabilityAttestationRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            "pq availability attestations",
            self.attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.attestation_nullifier)?;
        self.require_lane(&request.lane_id)?;
        let order = self.require_order(&request.order_id)?;
        if order.lane_id != request.lane_id {
            return Err("attestation lane_id does not match order lane_id".to_string());
        }
        if let Some(auction_id) = request.auction_id.as_deref() {
            self.require_auction(auction_id)?;
        }
        let sequence = self.counters.next_attestation_sequence;
        self.counters.next_attestation_sequence =
            self.counters.next_attestation_sequence.saturating_add(1);
        let attestation_id = pq_availability_attestation_id(&request, sequence);
        ensure_absent(
            "pq availability attestation",
            &self.attestations,
            &attestation_id,
        )?;
        let availability_bps = ratio_bps(request.available_chunks, request.total_chunks);
        let status = if availability_bps == MAX_BPS {
            AttestationStatus::Quorum
        } else {
            AttestationStatus::Accepted
        };
        let record = PqAvailabilityAttestationRecord {
            attestation_id: attestation_id.clone(),
            lane_id: request.lane_id.clone(),
            order_id: request.order_id.clone(),
            auction_id: request.auction_id,
            attestor_commitment: request.attestor_commitment,
            status,
            availability_root: request.availability_root,
            pq_signature_root: request.pq_signature_root,
            replica_set_root: request.replica_set_root,
            sealed_receipt_root: request.sealed_receipt_root,
            attestation_nullifier: request.attestation_nullifier,
            pq_security_bits: request.pq_security_bits,
            available_chunks: request.available_chunks,
            total_chunks: request.total_chunks,
            observed_height: request.observed_height,
            expires_height: request
                .observed_height
                .saturating_add(self.config.attestation_ttl_blocks),
            availability_bps,
        };
        self.nullifiers.insert(record.attestation_nullifier.clone());
        self.counters.attestation_count = self.counters.attestation_count.saturating_add(1);
        if let Some(order) = self.orders.get_mut(&record.order_id) {
            order.status = OrderStatus::Attested;
            order.attestation_ids.push(attestation_id.clone());
        }
        if let Some(lane) = self.lanes.get_mut(&record.lane_id) {
            lane.attested_replica_count = lane.attested_replica_count.saturating_add(1);
            if lane.attested_replica_count >= self.config.min_availability_quorum {
                lane.status = LaneStatus::Open;
            }
        }
        self.attestations.insert(attestation_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn create_cache_lease(&mut self, request: CacheLeaseRequest) -> Result<CacheLeaseRecord> {
        request.validate()?;
        ensure_capacity("cache leases", self.leases.len(), self.config.max_leases)?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.lease_nullifier)?;
        self.require_lane(&request.lane_id)?;
        self.require_order(&request.order_id)?;
        self.require_auction(&request.auction_id)?;
        let sequence = self.counters.next_lease_sequence;
        self.counters.next_lease_sequence = self.counters.next_lease_sequence.saturating_add(1);
        let lease_id = cache_lease_id(&request, sequence);
        ensure_absent("cache lease", &self.leases, &lease_id)?;
        let record = CacheLeaseRecord {
            lease_id: lease_id.clone(),
            lane_id: request.lane_id,
            order_id: request.order_id,
            auction_id: request.auction_id,
            lessee_commitment: request.lessee_commitment,
            status: LeaseStatus::Active,
            cache_key_root: request.cache_key_root,
            lease_terms_root: request.lease_terms_root,
            encrypted_locator_root: request.encrypted_locator_root,
            lease_nullifier: request.lease_nullifier,
            chunk_count: request.chunk_count,
            fee_micro_units: request.fee_micro_units,
            starts_height: request.starts_height,
            expires_height: request
                .starts_height
                .saturating_add(self.config.lease_ttl_blocks),
            renewal_count: 0,
        };
        self.nullifiers.insert(record.lease_nullifier.clone());
        self.counters.lease_count = self.counters.lease_count.saturating_add(1);
        if let Some(order) = self.orders.get_mut(&record.order_id) {
            order.status = OrderStatus::Leased;
            order.active_lease_id = Some(lease_id.clone());
        }
        if let Some(auction) = self.auctions.get_mut(&record.auction_id) {
            auction.status = AuctionStatus::Prefetching;
        }
        self.leases.insert(lease_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn create_invalidation_fence(
        &mut self,
        request: InvalidationFenceRequest,
    ) -> Result<InvalidationFenceRecord> {
        request.validate()?;
        ensure_capacity(
            "invalidation fences",
            self.fences.len(),
            self.config.max_fences,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.fence_nullifier)?;
        self.require_lane(&request.lane_id)?;
        let sequence = self.counters.next_fence_sequence;
        self.counters.next_fence_sequence = self.counters.next_fence_sequence.saturating_add(1);
        let fence_id = invalidation_fence_id(&request, sequence);
        ensure_absent("invalidation fence", &self.fences, &fence_id)?;
        let record = InvalidationFenceRecord {
            fence_id: fence_id.clone(),
            lane_id: request.lane_id,
            subject_id: request.subject_id,
            reason: request.reason,
            invalidated_root: request.invalidated_root,
            replacement_root: request.replacement_root,
            evidence_root: request.evidence_root,
            fence_nullifier: request.fence_nullifier,
            reported_height: request.reported_height,
            expires_height: request
                .reported_height
                .saturating_add(self.config.fence_ttl_blocks),
        };
        self.nullifiers.insert(record.fence_nullifier.clone());
        self.counters.fence_count = self.counters.fence_count.saturating_add(1);
        self.fences.insert(fence_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn issue_low_fee_proof_credit(
        &mut self,
        request: LowFeeProofCreditRequest,
    ) -> Result<LowFeeProofCreditRecord> {
        request.validate(&self.config)?;
        ensure_capacity(
            "low fee proof credits",
            self.credits.len(),
            self.config.max_credits,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.credit_nullifier)?;
        self.require_order(&request.order_id)?;
        self.require_lease(&request.lease_id)?;
        let sequence = self.counters.next_credit_sequence;
        self.counters.next_credit_sequence = self.counters.next_credit_sequence.saturating_add(1);
        let credit_id = low_fee_proof_credit_id(&request, sequence);
        ensure_absent("low fee proof credit", &self.credits, &credit_id)?;
        let record = LowFeeProofCreditRecord {
            credit_id: credit_id.clone(),
            order_id: request.order_id,
            lease_id: request.lease_id,
            sponsor_commitment: request.sponsor_commitment,
            status: CreditStatus::Queued,
            credit_commitment_root: request.credit_commitment_root,
            fee_receipt_root: request.fee_receipt_root,
            credit_nullifier: request.credit_nullifier,
            fee_paid_micro_units: request.fee_paid_micro_units,
            requested_rebate_bps: request.requested_rebate_bps,
            credit_micro_units: proof_credit_micro_units(
                request.fee_paid_micro_units,
                request.requested_rebate_bps,
            ),
            opened_height: request.opened_height,
        };
        self.nullifiers.insert(record.credit_nullifier.clone());
        self.counters.credit_count = self.counters.credit_count.saturating_add(1);
        if let Some(order) = self.orders.get_mut(&record.order_id) {
            order.status = OrderStatus::CreditQueued;
        }
        self.credits.insert(credit_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_redaction_metadata(
        &mut self,
        request: RedactionMetadataRequest,
    ) -> Result<RedactionMetadataRecord> {
        request.validate()?;
        ensure_capacity(
            "redaction metadata",
            self.redactions.len(),
            self.config.max_redactions,
        )?;
        ensure_capacity(
            "nullifiers",
            self.nullifiers.len(),
            self.config.max_nullifiers,
        )?;
        ensure_nullifier_available(&self.nullifiers, &request.redaction_nullifier)?;
        let sequence = self.counters.next_redaction_sequence;
        self.counters.next_redaction_sequence =
            self.counters.next_redaction_sequence.saturating_add(1);
        let redaction_id = redaction_metadata_id(&request, sequence);
        ensure_absent("redaction metadata", &self.redactions, &redaction_id)?;
        let record = RedactionMetadataRecord {
            redaction_id: redaction_id.clone(),
            subject_id: request.subject_id,
            scope: request.scope,
            owner_commitment: request.owner_commitment,
            redacted_field_root: request.redacted_field_root,
            disclosure_policy_root: request.disclosure_policy_root,
            view_tag_root: request.view_tag_root,
            redaction_nullifier: request.redaction_nullifier,
            redaction_units: request.redaction_units,
            opened_height: request.opened_height,
        };
        self.nullifiers.insert(record.redaction_nullifier.clone());
        self.counters.redaction_count = self.counters.redaction_count.saturating_add(1);
        self.redactions.insert(redaction_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn upsert_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummaryRecord> {
        request.validate()?;
        ensure_capacity("operators", self.operators.len(), self.config.max_operators)?;
        let sequence = self.counters.next_operator_sequence;
        self.counters.next_operator_sequence =
            self.counters.next_operator_sequence.saturating_add(1);
        let operator_id = operator_summary_id(&request, sequence);
        let record = OperatorSummaryRecord {
            operator_id: operator_id.clone(),
            operator_commitment: request.operator_commitment,
            status: OperatorStatus::Active,
            service_root: request.service_root,
            stake_root: request.stake_root,
            performance_root: request.performance_root,
            pq_key_root: request.pq_key_root,
            summary_nullifier: request.summary_nullifier,
            served_lanes: request.served_lanes,
            availability_bps: request.availability_bps,
            low_fee_fill_bps: request.low_fee_fill_bps,
            updated_height: request.updated_height,
            score: operator_score(
                request.served_lanes,
                request.availability_bps,
                request.low_fee_fill_bps,
            ),
        };
        if !self.operators.contains_key(&operator_id) {
            self.counters.operator_count = self.counters.operator_count.saturating_add(1);
        }
        self.operators.insert(operator_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        let mut roots = Roots {
            lane_root: map_root("PRIVATE-L2-FAST-PQ-BLOB-LANE-ROOT", &self.lanes),
            order_root: map_root("PRIVATE-L2-FAST-PQ-WITNESS-DELTA-ORDER-ROOT", &self.orders),
            auction_root: map_root("PRIVATE-L2-FAST-PQ-PREFETCH-AUCTION-ROOT", &self.auctions),
            attestation_root: map_root(
                "PRIVATE-L2-FAST-PQ-AVAILABILITY-ATTESTATION-ROOT",
                &self.attestations,
            ),
            lease_root: map_root("PRIVATE-L2-FAST-PQ-CACHE-LEASE-ROOT", &self.leases),
            fence_root: map_root("PRIVATE-L2-FAST-PQ-INVALIDATION-FENCE-ROOT", &self.fences),
            credit_root: map_root("PRIVATE-L2-FAST-PQ-LOW-FEE-CREDIT-ROOT", &self.credits),
            redaction_root: map_root(
                "PRIVATE-L2-FAST-PQ-REDACTION-METADATA-ROOT",
                &self.redactions,
            ),
            operator_root: map_root("PRIVATE-L2-FAST-PQ-OPERATOR-SUMMARY-ROOT", &self.operators),
            nullifier_root: set_root("PRIVATE-L2-FAST-PQ-NULLIFIER-ROOT", &self.nullifiers),
            public_record_root: map_root(
                "PRIVATE-L2-FAST-PQ-PUBLIC-RECORD-ROOT",
                &self.public_records,
            ),
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "counters": self.counters,
            "roots": {
                "lane_root": roots.lane_root,
                "order_root": roots.order_root,
                "auction_root": roots.auction_root,
                "attestation_root": roots.attestation_root,
                "lease_root": roots.lease_root,
                "fence_root": roots.fence_root,
                "credit_root": roots.credit_root,
                "redaction_root": roots.redaction_root,
                "operator_root": roots.operator_root,
                "nullifier_root": roots.nullifier_root,
                "public_record_root": roots.public_record_root,
            },
        }));
        roots
    }

    pub fn refresh_roots(&mut self) {
        self.roots = self.roots();
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "lanes": public_values(&self.lanes),
            "orders": public_values(&self.orders),
            "auctions": public_values(&self.auctions),
            "attestations": public_values(&self.attestations),
            "leases": public_values(&self.leases),
            "fences": public_values(&self.fences),
            "credits": public_values(&self.credits),
            "redactions": public_values(&self.redactions),
            "operators": public_values(&self.operators),
            "privacy_boundary": PRIVACY_BOUNDARY,
            "state_root": roots.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    fn require_lane(&self, lane_id: &str) -> Result<&EncryptedBlobLaneRecord> {
        self.lanes
            .get(lane_id)
            .ok_or_else(|| format!("unknown encrypted blob lane {lane_id}"))
    }

    fn require_order(&self, order_id: &str) -> Result<&WitnessDeltaOrderRecord> {
        self.orders
            .get(order_id)
            .ok_or_else(|| format!("unknown witness delta order {order_id}"))
    }

    fn require_auction(&self, auction_id: &str) -> Result<&PrefetchAuctionRecord> {
        self.auctions
            .get(auction_id)
            .ok_or_else(|| format!("unknown prefetch auction {auction_id}"))
    }

    fn require_lease(&self, lease_id: &str) -> Result<&CacheLeaseRecord> {
        self.leases
            .get(lease_id)
            .ok_or_else(|| format!("unknown cache lease {lease_id}"))
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn encrypted_blob_lane_id(request: &EncryptedBlobLaneRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-BLOB-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(request.class.as_str()),
            HashPart::Str(&request.encrypted_blob_root),
            HashPart::Str(&request.sealed_lane_key_root),
            HashPart::Str(&request.lane_nullifier),
        ],
        32,
    )
}

pub fn witness_delta_order_id(request: &WitnessDeltaOrderRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-WITNESS-DELTA-ORDER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(request.delta_kind.as_str()),
            HashPart::Str(&request.witness_delta_root),
            HashPart::Str(&request.order_nullifier),
        ],
        32,
    )
}

pub fn prefetch_auction_id(request: &PrefetchAuctionRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-PREFETCH-AUCTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.solver_commitment),
            HashPart::Str(&request.sealed_bid_root),
            HashPart::Str(&request.bid_nullifier),
        ],
        32,
    )
}

pub fn pq_availability_attestation_id(
    request: &PqAvailabilityAttestationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-AVAILABILITY-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.attestor_commitment),
            HashPart::Str(&request.availability_root),
            HashPart::Str(&request.attestation_nullifier),
        ],
        32,
    )
}

pub fn cache_lease_id(request: &CacheLeaseRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-CACHE-LEASE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.auction_id),
            HashPart::Str(&request.cache_key_root),
            HashPart::Str(&request.lease_nullifier),
        ],
        32,
    )
}

pub fn invalidation_fence_id(request: &InvalidationFenceRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-INVALIDATION-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.lane_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.reason.as_str()),
            HashPart::Str(&request.invalidated_root),
            HashPart::Str(&request.fence_nullifier),
        ],
        32,
    )
}

pub fn low_fee_proof_credit_id(request: &LowFeeProofCreditRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-LOW-FEE-PROOF-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.order_id),
            HashPart::Str(&request.lease_id),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(&request.credit_commitment_root),
            HashPart::Str(&request.credit_nullifier),
        ],
        32,
    )
}

pub fn redaction_metadata_id(request: &RedactionMetadataRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-REDACTION-METADATA-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.scope.as_str()),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.redacted_field_root),
            HashPart::Str(&request.redaction_nullifier),
        ],
        32,
    )
}

pub fn operator_summary_id(request: &OperatorSummaryRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FAST-PQ-OPERATOR-SUMMARY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(&request.operator_commitment),
            HashPart::Str(&request.service_root),
            HashPart::Str(&request.pq_key_root),
            HashPart::Str(&request.summary_nullifier),
        ],
        32,
    )
}

pub fn lane_priority_score(class: BlobLaneClass, replica_target: u64, public_bucket: u64) -> u64 {
    class
        .priority_weight()
        .saturating_add(replica_target.saturating_mul(25))
        .saturating_add(public_bucket.min(10_000))
}

pub fn witness_delta_order_score(
    delta_kind: DeltaKind,
    privacy_set_size: u64,
    max_fee_micro_units: u64,
    requested_credit_bps: u64,
) -> u64 {
    delta_kind
        .complexity_weight()
        .saturating_add(privacy_set_size.min(1_048_576) / 1_024)
        .saturating_add(max_fee_micro_units.min(10_000_000) / 10_000)
        .saturating_add(requested_credit_bps.saturating_mul(12))
}

pub fn prefetch_auction_score(
    fee_micro_units: u64,
    max_latency_ms: u64,
    bond_micro_units: u64,
) -> u64 {
    25_000_u64
        .saturating_sub(
            fee_micro_units
                .min(10_000_000)
                .saturating_div(1_000)
                .saturating_add(max_latency_ms.min(25_000)),
        )
        .saturating_add(bond_micro_units.min(25_000_000).saturating_div(10_000))
}

pub fn operator_score(served_lanes: u64, availability_bps: u64, low_fee_fill_bps: u64) -> u64 {
    served_lanes
        .saturating_mul(100)
        .saturating_add(availability_bps)
        .saturating_add(low_fee_fill_bps / 2)
}

pub fn proof_credit_micro_units(fee_paid_micro_units: u64, rebate_bps: u64) -> u64 {
    fee_paid_micro_units
        .saturating_mul(rebate_bps.min(MAX_BPS))
        .saturating_div(MAX_BPS)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator
            .saturating_mul(MAX_BPS)
            .saturating_div(denominator)
            .min(MAX_BPS)
    }
}

pub fn public_bucket(height: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        height
    } else {
        height / bucket_size
    }
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    payload_root(domain, record)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-BLOB-WITNESS-DELTA-MARKET-STATE-ROOT",
        record,
    )
}

pub fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"})),
            })
        })
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    public_record_root(domain, &leaves)
}

pub fn public_values<T: Serialize>(map: &BTreeMap<String, T>) -> Vec<Value> {
    map.values()
        .map(|value| {
            serde_json::to_value(value).unwrap_or_else(|_| json!({"serialization": "failed"}))
        })
        .collect()
}

fn demo_root(label: &str) -> String {
    payload_root(
        "PRIVATE-L2-FAST-PQ-CONFIDENTIAL-BLOB-WITNESS-DELTA-DEMO-ROOT",
        &json!({ "label": label }),
    )
}

fn ensure_nonempty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_root(field: &str, value: &str) -> Result<()> {
    ensure_nonempty(field, value)?;
    if value.len() < 16 {
        return Err(format!("{field} must look like a commitment root"));
    }
    Ok(())
}

fn ensure_positive_u64(field: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_positive_usize(field: &str, value: usize) -> Result<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(field: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_absent<T>(label: &str, map: &BTreeMap<String, T>, key: &str) -> Result<()> {
    if map.contains_key(key) {
        Err(format!("{label} {key} already exists"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(label: &str, current: usize, max: usize) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exhausted"))
    } else {
        Ok(())
    }
}

fn ensure_nullifier_available(nullifiers: &BTreeSet<String>, nullifier: &str) -> Result<()> {
    if nullifiers.contains(nullifier) {
        Err(format!("nullifier {nullifier} already consumed"))
    } else {
        Ok(())
    }
}
