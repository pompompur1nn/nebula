use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateViewtagFastScanCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-viewtag-fast-scan-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_DEVNET_HEIGHT: u64 = 812_400;
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_MONERO_NETWORK: &str =
    "monero-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_L2_NETWORK: &str = "nebula-devnet";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_LANE_SCHEME: &str =
    "ml-kem-1024-sealed-private-viewtag-fast-scan-lane-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_BUCKET_SCHEME: &str =
    "encrypted-monero-viewtag-bucket-cache-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-wallet-view-attestation-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SHARD_SCHEME: &str =
    "private-viewtag-fast-scan-cache-shard-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_WINDOW_LEASE_SCHEME: &str =
    "subaddress-window-fast-scan-lease-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_COUPON_SCHEME: &str =
    "fee-sponsor-private-scan-coupon-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_RECEIPT_SCHEME: &str =
    "wallet-sync-private-viewtag-cache-receipt-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_REORG_ANCHOR_SCHEME: &str =
    "monero-reorg-window-viewtag-cache-anchor-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_NULLIFIER_FENCE_SCHEME: &str =
    "viewtag-cache-nullifier-fence-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_CHALLENGE_SCHEME: &str =
    "stale-private-viewtag-cache-challenge-root-v1";
pub const MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SLASHING_SCHEME: &str =
    "viewtag-cache-provider-slashing-evidence-root-v1";
pub const DEFAULT_LANE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_WINDOW_LEASE_BLOCKS: u64 = 720;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 12;
pub const DEFAULT_REORG_WINDOW_BLOCKS: u64 = 96;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 144;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_BUCKET_TX_COUNT: u32 = 1;
pub const DEFAULT_MAX_BUCKET_TX_COUNT: u32 = 4096;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_MICRO_UNITS: u64 = 1_500;
pub const DEFAULT_MAX_SCAN_FEE_MICRO_UNITS: u64 = 12_000;
pub const DEFAULT_PROVIDER_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_SLASH_BPS: u64 = 750;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_CACHE_LANES: usize = 524_288;
pub const MAX_VIEWTAG_BUCKETS: usize = 2_097_152;
pub const MAX_WALLET_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SCAN_SHARDS: usize = 1_048_576;
pub const MAX_WINDOW_LEASES: usize = 1_048_576;
pub const MAX_SCAN_COUPONS: usize = 1_048_576;
pub const MAX_SYNC_RECEIPTS: usize = 2_097_152;
pub const MAX_REORG_ANCHORS: usize = 262_144;
pub const MAX_NULLIFIER_FENCES: usize = 2_097_152;
pub const MAX_STALE_CHALLENGES: usize = 524_288;
pub const MAX_SLASHING_EVIDENCE: usize = 524_288;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheLaneStatus {
    Open,
    Attested,
    Leasing,
    Sealing,
    Active,
    ReorgLocked,
    Challenged,
    Slashed,
    Closed,
    Expired,
}

impl CacheLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Attested => "attested",
            Self::Leasing => "leasing",
            Self::Sealing => "sealing",
            Self::Active => "active",
            Self::ReorgLocked => "reorg_locked",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
            Self::Closed => "closed",
            Self::Expired => "expired",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Attested | Self::Leasing | Self::Sealing | Self::Active
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Sealed,
    Attested,
    Indexed,
    Receipted,
    ReorgLocked,
    Challenged,
    Stale,
    Slashed,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Attested => "attested",
            Self::Indexed => "indexed",
            Self::Receipted => "receipted",
            Self::ReorgLocked => "reorg_locked",
            Self::Challenged => "challenged",
            Self::Stale => "stale",
            Self::Slashed => "slashed",
        }
    }

    pub fn scannable(self) -> bool {
        matches!(self, Self::Attested | Self::Indexed | Self::Receipted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    WalletViewKey,
    ViewTagCompleteness,
    ShardCoverage,
    ProviderAvailability,
    ReceiptWitness,
    ReorgSafety,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletViewKey => "wallet_view_key",
            Self::ViewTagCompleteness => "viewtag_completeness",
            Self::ShardCoverage => "shard_coverage",
            Self::ProviderAvailability => "provider_availability",
            Self::ReceiptWitness => "receipt_witness",
            Self::ReorgSafety => "reorg_safety",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardStatus {
    Open,
    Assigned,
    Sealed,
    Receipted,
    ReorgLocked,
    Retired,
    Slashed,
}

impl ShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::Sealed => "sealed",
            Self::Receipted => "receipted",
            Self::ReorgLocked => "reorg_locked",
            Self::Retired => "retired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseStatus {
    Active,
    Consumed,
    Expired,
    Revoked,
    Slashed,
}

impl LeaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Settled,
    Expired,
    Revoked,
    Slashed,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Published,
    Final,
    Reorged,
    Challenged,
    Slashed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Final => "final",
            Self::Reorged => "reorged",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    ProvedFresh,
    StaleConfirmed,
    Expired,
    Slashed,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::ProvedFresh => "proved_fresh",
            Self::StaleConfirmed => "stale_confirmed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlashReason {
    MissingBucket,
    StaleBucket,
    InvalidAttestation,
    DoubleSpendCoupon,
    LeaseOverlap,
    ReorgMisreport,
    NullifierReuse,
}

impl SlashReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingBucket => "missing_bucket",
            Self::StaleBucket => "stale_bucket",
            Self::InvalidAttestation => "invalid_attestation",
            Self::DoubleSpendCoupon => "double_spend_coupon",
            Self::LeaseOverlap => "lease_overlap",
            Self::ReorgMisreport => "reorg_misreport",
            Self::NullifierReuse => "nullifier_reuse",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub lane_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub window_lease_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub reorg_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_bucket_tx_count: u32,
    pub max_bucket_tx_count: u32,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_micro_units: u64,
    pub max_scan_fee_micro_units: u64,
    pub provider_bond_micro_units: u64,
    pub slash_bps: u64,
    pub allow_sponsored_scans: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_MONERO_NETWORK
                .to_string(),
            l2_network: MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_L2_NETWORK.to_string(),
            lane_ttl_blocks: DEFAULT_LANE_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            window_lease_blocks: DEFAULT_WINDOW_LEASE_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            reorg_window_blocks: DEFAULT_REORG_WINDOW_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_bucket_tx_count: DEFAULT_MIN_BUCKET_TX_COUNT,
            max_bucket_tx_count: DEFAULT_MAX_BUCKET_TX_COUNT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_micro_units: DEFAULT_LOW_FEE_MICRO_UNITS,
            max_scan_fee_micro_units: DEFAULT_MAX_SCAN_FEE_MICRO_UNITS,
            provider_bond_micro_units: DEFAULT_PROVIDER_BOND_MICRO_UNITS,
            slash_bps: DEFAULT_SLASH_BPS,
            allow_sponsored_scans: true,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub cache_lanes_opened: u64,
    pub viewtag_buckets_sealed: u64,
    pub wallet_attestations_attached: u64,
    pub scan_shards_opened: u64,
    pub window_leases_granted: u64,
    pub scan_coupons_issued: u64,
    pub scan_coupons_settled: u64,
    pub sync_receipts_published: u64,
    pub reorg_anchors_published: u64,
    pub nullifier_fences_registered: u64,
    pub stale_challenges_opened: u64,
    pub providers_slashed: u64,
    pub public_records: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub cache_lanes_root: String,
    pub viewtag_buckets_root: String,
    pub wallet_attestations_root: String,
    pub scan_shards_root: String,
    pub window_leases_root: String,
    pub scan_coupons_root: String,
    pub sync_receipts_root: String,
    pub reorg_anchors_root: String,
    pub nullifier_fences_root: String,
    pub stale_challenges_root: String,
    pub slashing_evidence_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheLane {
    pub lane_id: String,
    pub wallet_commitment: String,
    pub provider_id: String,
    pub encrypted_route_root: String,
    pub viewtag_prefix: String,
    pub privacy_set_size: u64,
    pub max_fee_micro_units: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: CacheLaneStatus,
    pub attestation_ids: BTreeSet<String>,
    pub shard_ids: BTreeSet<String>,
    pub lease_ids: BTreeSet<String>,
    pub bucket_ids: BTreeSet<String>,
    pub coupon_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub nullifier_fence_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewtagBucket {
    pub bucket_id: String,
    pub lane_id: String,
    pub shard_id: Option<String>,
    pub provider_id: String,
    pub encrypted_bucket_root: String,
    pub viewtag_prefix: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub tx_count: u32,
    pub scan_digest: String,
    pub sealed_height: u64,
    pub expires_height: u64,
    pub status: BucketStatus,
    pub attestation_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWalletViewAttestation {
    pub attestation_id: String,
    pub lane_id: String,
    pub bucket_id: Option<String>,
    pub wallet_commitment: String,
    pub provider_id: String,
    pub kind: AttestationKind,
    pub pq_scheme: String,
    pub public_key_commitment: String,
    pub signature_commitment: String,
    pub statement_root: String,
    pub pq_security_bits: u16,
    pub attested_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCacheShard {
    pub shard_id: String,
    pub lane_id: String,
    pub provider_id: String,
    pub shard_index: u32,
    pub shard_count: u32,
    pub encrypted_index_root: String,
    pub coverage_start_height: u64,
    pub coverage_end_height: u64,
    pub status: ShardStatus,
    pub bucket_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubaddressWindowLease {
    pub lease_id: String,
    pub lane_id: String,
    pub wallet_commitment: String,
    pub subaddress_window_root: String,
    pub start_major: u32,
    pub end_major: u32,
    pub start_minor: u32,
    pub end_minor: u32,
    pub granted_height: u64,
    pub expires_height: u64,
    pub status: LeaseStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorScanCoupon {
    pub coupon_id: String,
    pub lane_id: String,
    pub sponsor_id: String,
    pub provider_id: String,
    pub fee_budget_micro_units: u64,
    pub rebate_micro_units: u64,
    pub nullifier: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub settled_receipt_id: Option<String>,
    pub status: CouponStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSyncReceipt {
    pub receipt_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub shard_id: Option<String>,
    pub wallet_commitment: String,
    pub provider_id: String,
    pub synced_scan_digest: String,
    pub synced_bucket_root: String,
    pub nullifier: String,
    pub coupon_id: Option<String>,
    pub published_height: u64,
    pub final_height: u64,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgAnchor {
    pub anchor_id: String,
    pub lane_id: String,
    pub provider_id: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub old_header_root: String,
    pub new_header_root: String,
    pub affected_bucket_ids: BTreeSet<String>,
    pub anchored_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub lane_id: String,
    pub subject_id: String,
    pub nullifier: String,
    pub fence_kind: String,
    pub registered_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaleCacheChallenge {
    pub challenge_id: String,
    pub lane_id: String,
    pub bucket_id: String,
    pub challenger_id: String,
    pub provider_id: String,
    pub stale_claim_root: String,
    pub expected_scan_digest: String,
    pub opened_height: u64,
    pub expires_height: u64,
    pub status: ChallengeStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub lane_id: String,
    pub provider_id: String,
    pub reason: SlashReason,
    pub subject_id: String,
    pub evidence_root: String,
    pub slash_amount_micro_units: u64,
    pub slashed_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub cache_lanes: BTreeMap<String, CacheLane>,
    pub viewtag_buckets: BTreeMap<String, ViewtagBucket>,
    pub wallet_attestations: BTreeMap<String, PqWalletViewAttestation>,
    pub scan_shards: BTreeMap<String, ScanCacheShard>,
    pub window_leases: BTreeMap<String, SubaddressWindowLease>,
    pub scan_coupons: BTreeMap<String, FeeSponsorScanCoupon>,
    pub sync_receipts: BTreeMap<String, WalletSyncReceipt>,
    pub reorg_anchors: BTreeMap<String, ReorgAnchor>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub nullifier_index: BTreeMap<String, String>,
    pub stale_challenges: BTreeMap<String, StaleCacheChallenge>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub public_records: Vec<Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            cache_lanes: BTreeMap::new(),
            viewtag_buckets: BTreeMap::new(),
            wallet_attestations: BTreeMap::new(),
            scan_shards: BTreeMap::new(),
            window_leases: BTreeMap::new(),
            scan_coupons: BTreeMap::new(),
            sync_receipts: BTreeMap::new(),
            reorg_anchors: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            nullifier_index: BTreeMap::new(),
            stale_challenges: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            public_records: Vec::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        Self::new(Config::default())
    }

    pub fn open_cache_lane(
        &mut self,
        wallet_commitment: impl Into<String>,
        provider_id: impl Into<String>,
        encrypted_route_root: impl Into<String>,
        viewtag_prefix: impl Into<String>,
        privacy_set_size: u64,
        max_fee_micro_units: u64,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.cache_lanes.len(), MAX_CACHE_LANES, "cache lanes")?;
        if privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured minimum".to_string());
        }
        if max_fee_micro_units > self.config.max_scan_fee_micro_units {
            return Err("scan fee exceeds configured maximum".to_string());
        }
        let wallet_commitment = wallet_commitment.into();
        let provider_id = provider_id.into();
        let encrypted_route_root = encrypted_route_root.into();
        let viewtag_prefix = viewtag_prefix.into();
        require_nonempty("wallet_commitment", &wallet_commitment)?;
        require_nonempty("provider_id", &provider_id)?;
        require_nonempty("encrypted_route_root", &encrypted_route_root)?;
        require_nonempty("viewtag_prefix", &viewtag_prefix)?;
        let lane_id = lane_id(
            &wallet_commitment,
            &provider_id,
            &encrypted_route_root,
            &viewtag_prefix,
            current_height,
            self.counters.cache_lanes_opened,
        );
        if self.cache_lanes.contains_key(&lane_id) {
            return Err("cache lane already exists".to_string());
        }
        let lane = CacheLane {
            lane_id: lane_id.clone(),
            wallet_commitment,
            provider_id,
            encrypted_route_root,
            viewtag_prefix,
            privacy_set_size,
            max_fee_micro_units,
            opened_height: current_height,
            expires_height: current_height.saturating_add(self.config.lane_ttl_blocks),
            status: CacheLaneStatus::Open,
            attestation_ids: BTreeSet::new(),
            shard_ids: BTreeSet::new(),
            lease_ids: BTreeSet::new(),
            bucket_ids: BTreeSet::new(),
            coupon_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
            nullifier_fence_ids: BTreeSet::new(),
        };
        self.cache_lanes.insert(lane_id.clone(), lane);
        self.counters.cache_lanes_opened = self.counters.cache_lanes_opened.saturating_add(1);
        self.push_public_record("cache_lane_opened", &lane_id, current_height);
        self.refresh_roots();
        Ok(lane_id)
    }

    pub fn open_scan_shard(
        &mut self,
        lane_id: &str,
        shard_index: u32,
        shard_count: u32,
        encrypted_index_root: impl Into<String>,
        coverage_start_height: u64,
        coverage_end_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.scan_shards.len(), MAX_SCAN_SHARDS, "scan shards")?;
        if shard_count == 0 || shard_index >= shard_count {
            return Err("invalid shard index/count".to_string());
        }
        if coverage_start_height > coverage_end_height {
            return Err("invalid shard coverage range".to_string());
        }
        let encrypted_index_root = encrypted_index_root.into();
        require_nonempty("encrypted_index_root", &encrypted_index_root)?;
        let provider_id = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .provider_id
            .clone();
        let shard_id = shard_id(
            lane_id,
            &provider_id,
            shard_index,
            shard_count,
            &encrypted_index_root,
        );
        if self.scan_shards.contains_key(&shard_id) {
            return Err("scan shard already exists".to_string());
        }
        let shard = ScanCacheShard {
            shard_id: shard_id.clone(),
            lane_id: lane_id.to_string(),
            provider_id,
            shard_index,
            shard_count,
            encrypted_index_root,
            coverage_start_height,
            coverage_end_height,
            status: ShardStatus::Open,
            bucket_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
        };
        self.scan_shards.insert(shard_id.clone(), shard);
        let lane = self.lane_mut(lane_id)?;
        if !lane.status.live() {
            return Err("cache lane is not live".to_string());
        }
        lane.shard_ids.insert(shard_id.clone());
        self.counters.scan_shards_opened = self.counters.scan_shards_opened.saturating_add(1);
        self.push_public_record("scan_shard_opened", &shard_id, coverage_start_height);
        self.refresh_roots();
        Ok(shard_id)
    }

    pub fn seal_viewtag_bucket(
        &mut self,
        lane_id: &str,
        shard_id: Option<&str>,
        encrypted_bucket_root: impl Into<String>,
        viewtag_prefix: impl Into<String>,
        monero_start_height: u64,
        monero_end_height: u64,
        tx_count: u32,
        scan_digest: impl Into<String>,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.viewtag_buckets.len(),
            MAX_VIEWTAG_BUCKETS,
            "viewtag buckets",
        )?;
        if monero_start_height > monero_end_height {
            return Err("invalid monero height range".to_string());
        }
        if tx_count < self.config.min_bucket_tx_count || tx_count > self.config.max_bucket_tx_count
        {
            return Err("bucket tx count outside configured bounds".to_string());
        }
        let encrypted_bucket_root = encrypted_bucket_root.into();
        let viewtag_prefix = viewtag_prefix.into();
        let scan_digest = scan_digest.into();
        require_nonempty("encrypted_bucket_root", &encrypted_bucket_root)?;
        require_nonempty("viewtag_prefix", &viewtag_prefix)?;
        require_nonempty("scan_digest", &scan_digest)?;
        let provider_id = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .provider_id
            .clone();
        if let Some(shard_id) = shard_id {
            let shard = self
                .scan_shards
                .get(shard_id)
                .ok_or_else(|| "scan shard not found".to_string())?;
            if shard.lane_id != lane_id {
                return Err("scan shard belongs to different lane".to_string());
            }
            if monero_start_height < shard.coverage_start_height
                || monero_end_height > shard.coverage_end_height
            {
                return Err("bucket outside shard coverage".to_string());
            }
        }
        let lane_prefix = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .viewtag_prefix
            .clone();
        if lane_prefix != viewtag_prefix {
            return Err("bucket viewtag prefix does not match lane".to_string());
        }
        let bucket_id = bucket_id(
            lane_id,
            shard_id.unwrap_or("unsharded"),
            &encrypted_bucket_root,
            monero_start_height,
            monero_end_height,
            &scan_digest,
        );
        if self.viewtag_buckets.contains_key(&bucket_id) {
            return Err("viewtag bucket already exists".to_string());
        }
        let bucket = ViewtagBucket {
            bucket_id: bucket_id.clone(),
            lane_id: lane_id.to_string(),
            shard_id: shard_id.map(str::to_string),
            provider_id,
            encrypted_bucket_root,
            viewtag_prefix,
            monero_start_height,
            monero_end_height,
            tx_count,
            scan_digest,
            sealed_height: current_height,
            expires_height: current_height.saturating_add(self.config.bucket_ttl_blocks),
            status: BucketStatus::Sealed,
            attestation_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
        };
        self.viewtag_buckets.insert(bucket_id.clone(), bucket);
        self.lane_mut(lane_id)?.bucket_ids.insert(bucket_id.clone());
        if let Some(shard_id) = shard_id {
            let shard = self.shard_mut(shard_id)?;
            shard.bucket_ids.insert(bucket_id.clone());
            shard.status = ShardStatus::Assigned;
        }
        self.lane_mut(lane_id)?.status = CacheLaneStatus::Sealing;
        self.counters.viewtag_buckets_sealed =
            self.counters.viewtag_buckets_sealed.saturating_add(1);
        self.push_public_record("viewtag_bucket_sealed", &bucket_id, current_height);
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn attach_pq_attestation(
        &mut self,
        lane_id: &str,
        bucket_id: Option<&str>,
        kind: AttestationKind,
        pq_scheme: impl Into<String>,
        public_key_commitment: impl Into<String>,
        signature_commitment: impl Into<String>,
        statement_root: impl Into<String>,
        pq_security_bits: u16,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.wallet_attestations.len(),
            MAX_WALLET_ATTESTATIONS,
            "wallet attestations",
        )?;
        if pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq security below configured minimum".to_string());
        }
        let pq_scheme = pq_scheme.into();
        let public_key_commitment = public_key_commitment.into();
        let signature_commitment = signature_commitment.into();
        let statement_root = statement_root.into();
        require_nonempty("pq_scheme", &pq_scheme)?;
        require_nonempty("public_key_commitment", &public_key_commitment)?;
        require_nonempty("signature_commitment", &signature_commitment)?;
        require_nonempty("statement_root", &statement_root)?;
        let lane = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .clone();
        if let Some(bucket_id) = bucket_id {
            let bucket = self
                .viewtag_buckets
                .get(bucket_id)
                .ok_or_else(|| "viewtag bucket not found".to_string())?;
            if bucket.lane_id != lane_id {
                return Err("bucket belongs to different lane".to_string());
            }
        }
        let attestation_id = attestation_id(
            lane_id,
            bucket_id.unwrap_or("lane"),
            kind,
            &public_key_commitment,
            &signature_commitment,
            &statement_root,
        );
        if self.wallet_attestations.contains_key(&attestation_id) {
            return Err("wallet/view attestation already exists".to_string());
        }
        let attestation = PqWalletViewAttestation {
            attestation_id: attestation_id.clone(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.map(str::to_string),
            wallet_commitment: lane.wallet_commitment,
            provider_id: lane.provider_id,
            kind,
            pq_scheme,
            public_key_commitment,
            signature_commitment,
            statement_root,
            pq_security_bits,
            attested_height: current_height,
        };
        self.wallet_attestations
            .insert(attestation_id.clone(), attestation);
        self.lane_mut(lane_id)?
            .attestation_ids
            .insert(attestation_id.clone());
        self.lane_mut(lane_id)?.status = CacheLaneStatus::Attested;
        if let Some(bucket_id) = bucket_id {
            let bucket = self.bucket_mut(bucket_id)?;
            bucket.attestation_ids.insert(attestation_id.clone());
            bucket.status = BucketStatus::Attested;
        }
        self.counters.wallet_attestations_attached =
            self.counters.wallet_attestations_attached.saturating_add(1);
        self.push_public_record(
            "wallet_view_attestation_attached",
            &attestation_id,
            current_height,
        );
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn lease_scan_window(
        &mut self,
        lane_id: &str,
        subaddress_window_root: impl Into<String>,
        start_major: u32,
        end_major: u32,
        start_minor: u32,
        end_minor: u32,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.window_leases.len(), MAX_WINDOW_LEASES, "window leases")?;
        if start_major > end_major || start_minor > end_minor {
            return Err("invalid subaddress window".to_string());
        }
        let lane = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .clone();
        if !lane.status.live() {
            return Err("cache lane is not live".to_string());
        }
        let subaddress_window_root = subaddress_window_root.into();
        require_nonempty("subaddress_window_root", &subaddress_window_root)?;
        for lease in self.window_leases.values() {
            if lease.lane_id == lane_id
                && lease.status == LeaseStatus::Active
                && windows_overlap(
                    start_major,
                    end_major,
                    start_minor,
                    end_minor,
                    lease.start_major,
                    lease.end_major,
                    lease.start_minor,
                    lease.end_minor,
                )
            {
                return Err("active subaddress window lease overlaps".to_string());
            }
        }
        let lease_id = lease_id(
            lane_id,
            &subaddress_window_root,
            start_major,
            end_major,
            start_minor,
            end_minor,
        );
        let lease = SubaddressWindowLease {
            lease_id: lease_id.clone(),
            lane_id: lane_id.to_string(),
            wallet_commitment: lane.wallet_commitment,
            subaddress_window_root,
            start_major,
            end_major,
            start_minor,
            end_minor,
            granted_height: current_height,
            expires_height: current_height.saturating_add(self.config.window_lease_blocks),
            status: LeaseStatus::Active,
        };
        self.window_leases.insert(lease_id.clone(), lease);
        self.lane_mut(lane_id)?.lease_ids.insert(lease_id.clone());
        self.lane_mut(lane_id)?.status = CacheLaneStatus::Leasing;
        self.counters.window_leases_granted = self.counters.window_leases_granted.saturating_add(1);
        self.push_public_record("subaddress_window_lease_granted", &lease_id, current_height);
        self.refresh_roots();
        Ok(lease_id)
    }

    pub fn issue_sponsor_coupon(
        &mut self,
        lane_id: &str,
        sponsor_id: impl Into<String>,
        fee_budget_micro_units: u64,
        rebate_micro_units: u64,
        nullifier: impl Into<String>,
        current_height: u64,
    ) -> Result<String> {
        if !self.config.allow_sponsored_scans {
            return Err("sponsored scans disabled".to_string());
        }
        self.ensure_capacity(self.scan_coupons.len(), MAX_SCAN_COUPONS, "scan coupons")?;
        if fee_budget_micro_units == 0
            || fee_budget_micro_units > self.config.max_scan_fee_micro_units
        {
            return Err("invalid scan coupon fee budget".to_string());
        }
        if rebate_micro_units > fee_budget_micro_units {
            return Err("coupon rebate exceeds fee budget".to_string());
        }
        let sponsor_id = sponsor_id.into();
        let nullifier = nullifier.into();
        require_nonempty("sponsor_id", &sponsor_id)?;
        require_nonempty("nullifier", &nullifier)?;
        self.ensure_nullifier_unused(&nullifier)?;
        let provider_id = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .provider_id
            .clone();
        let coupon_id = coupon_id(
            lane_id,
            &sponsor_id,
            &provider_id,
            &nullifier,
            current_height,
        );
        let coupon = FeeSponsorScanCoupon {
            coupon_id: coupon_id.clone(),
            lane_id: lane_id.to_string(),
            sponsor_id,
            provider_id,
            fee_budget_micro_units,
            rebate_micro_units,
            nullifier: nullifier.clone(),
            issued_height: current_height,
            expires_height: current_height.saturating_add(self.config.lane_ttl_blocks),
            settled_receipt_id: None,
            status: CouponStatus::Issued,
        };
        self.scan_coupons.insert(coupon_id.clone(), coupon);
        self.lane_mut(lane_id)?.coupon_ids.insert(coupon_id.clone());
        self.register_nullifier_fence(
            lane_id,
            &coupon_id,
            &nullifier,
            "fee_sponsor_scan_coupon",
            current_height,
        )?;
        self.counters.scan_coupons_issued = self.counters.scan_coupons_issued.saturating_add(1);
        self.push_public_record("fee_sponsor_scan_coupon_issued", &coupon_id, current_height);
        self.refresh_roots();
        Ok(coupon_id)
    }

    pub fn publish_sync_receipt(
        &mut self,
        lane_id: &str,
        bucket_id: &str,
        synced_scan_digest: impl Into<String>,
        synced_bucket_root: impl Into<String>,
        nullifier: impl Into<String>,
        coupon_id: Option<&str>,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.sync_receipts.len(), MAX_SYNC_RECEIPTS, "sync receipts")?;
        let synced_scan_digest = synced_scan_digest.into();
        let synced_bucket_root = synced_bucket_root.into();
        let nullifier = nullifier.into();
        require_nonempty("synced_scan_digest", &synced_scan_digest)?;
        require_nonempty("synced_bucket_root", &synced_bucket_root)?;
        require_nonempty("nullifier", &nullifier)?;
        self.ensure_nullifier_unused(&nullifier)?;
        let bucket = self
            .viewtag_buckets
            .get(bucket_id)
            .ok_or_else(|| "viewtag bucket not found".to_string())?
            .clone();
        if bucket.lane_id != lane_id {
            return Err("bucket belongs to different lane".to_string());
        }
        if !bucket.status.scannable() {
            return Err("bucket is not attested/scannable".to_string());
        }
        if bucket.scan_digest != synced_scan_digest {
            return Err("receipt scan digest does not match bucket".to_string());
        }
        let lane = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .clone();
        if let Some(coupon_id) = coupon_id {
            let coupon = self
                .scan_coupons
                .get(coupon_id)
                .ok_or_else(|| "scan coupon not found".to_string())?;
            if coupon.lane_id != lane_id {
                return Err("scan coupon belongs to different lane".to_string());
            }
            if !matches!(coupon.status, CouponStatus::Issued | CouponStatus::Reserved) {
                return Err("scan coupon is not spendable".to_string());
            }
        }
        let receipt_id = receipt_id(lane_id, bucket_id, &synced_bucket_root, &nullifier);
        let receipt = WalletSyncReceipt {
            receipt_id: receipt_id.clone(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            shard_id: bucket.shard_id.clone(),
            wallet_commitment: lane.wallet_commitment,
            provider_id: lane.provider_id,
            synced_scan_digest,
            synced_bucket_root,
            nullifier: nullifier.clone(),
            coupon_id: coupon_id.map(str::to_string),
            published_height: current_height,
            final_height: current_height.saturating_add(self.config.receipt_finality_blocks),
            status: ReceiptStatus::Published,
        };
        self.sync_receipts.insert(receipt_id.clone(), receipt);
        self.lane_mut(lane_id)?
            .receipt_ids
            .insert(receipt_id.clone());
        self.bucket_mut(bucket_id)?
            .receipt_ids
            .insert(receipt_id.clone());
        self.bucket_mut(bucket_id)?.status = BucketStatus::Receipted;
        if let Some(shard_id) = bucket.shard_id.as_deref() {
            self.shard_mut(shard_id)?
                .receipt_ids
                .insert(receipt_id.clone());
            self.shard_mut(shard_id)?.status = ShardStatus::Receipted;
        }
        if let Some(coupon_id) = coupon_id {
            self.scan_coupons
                .get_mut(coupon_id)
                .ok_or_else(|| "scan coupon not found".to_string())?
                .status = CouponStatus::Reserved;
        }
        self.register_nullifier_fence(
            lane_id,
            &receipt_id,
            &nullifier,
            "wallet_sync_receipt",
            current_height,
        )?;
        self.counters.sync_receipts_published =
            self.counters.sync_receipts_published.saturating_add(1);
        self.push_public_record("wallet_sync_receipt_published", &receipt_id, current_height);
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn settle_sponsor_coupon(
        &mut self,
        coupon_id: &str,
        receipt_id: &str,
        current_height: u64,
    ) -> Result<()> {
        let receipt = self
            .sync_receipts
            .get(receipt_id)
            .ok_or_else(|| "sync receipt not found".to_string())?
            .clone();
        let coupon = self
            .scan_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "scan coupon not found".to_string())?;
        if coupon.lane_id != receipt.lane_id {
            return Err("coupon and receipt lanes differ".to_string());
        }
        if receipt.coupon_id.as_deref() != Some(coupon_id) {
            return Err("receipt did not reserve this coupon".to_string());
        }
        if current_height < receipt.final_height {
            return Err("receipt is not final yet".to_string());
        }
        if coupon.status == CouponStatus::Settled {
            return Err("scan coupon already settled".to_string());
        }
        coupon.status = CouponStatus::Settled;
        coupon.settled_receipt_id = Some(receipt_id.to_string());
        self.sync_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| "sync receipt not found".to_string())?
            .status = ReceiptStatus::Final;
        self.counters.scan_coupons_settled = self.counters.scan_coupons_settled.saturating_add(1);
        self.push_public_record("fee_sponsor_scan_coupon_settled", coupon_id, current_height);
        self.refresh_roots();
        Ok(())
    }

    pub fn anchor_reorg_window(
        &mut self,
        lane_id: &str,
        monero_start_height: u64,
        monero_end_height: u64,
        old_header_root: impl Into<String>,
        new_header_root: impl Into<String>,
        affected_bucket_ids: BTreeSet<String>,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(self.reorg_anchors.len(), MAX_REORG_ANCHORS, "reorg anchors")?;
        if monero_start_height > monero_end_height {
            return Err("invalid reorg window".to_string());
        }
        if monero_end_height.saturating_sub(monero_start_height) > self.config.reorg_window_blocks {
            return Err("reorg window exceeds configured bound".to_string());
        }
        let old_header_root = old_header_root.into();
        let new_header_root = new_header_root.into();
        require_nonempty("old_header_root", &old_header_root)?;
        require_nonempty("new_header_root", &new_header_root)?;
        let provider_id = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .provider_id
            .clone();
        for bucket_id in &affected_bucket_ids {
            let bucket = self
                .viewtag_buckets
                .get(bucket_id)
                .ok_or_else(|| "affected bucket not found".to_string())?;
            if bucket.lane_id != lane_id {
                return Err("affected bucket belongs to different lane".to_string());
            }
        }
        let anchor_id = reorg_anchor_id(
            lane_id,
            monero_start_height,
            monero_end_height,
            &old_header_root,
            &new_header_root,
        );
        let anchor = ReorgAnchor {
            anchor_id: anchor_id.clone(),
            lane_id: lane_id.to_string(),
            provider_id,
            monero_start_height,
            monero_end_height,
            old_header_root,
            new_header_root,
            affected_bucket_ids: affected_bucket_ids.clone(),
            anchored_height: current_height,
        };
        self.reorg_anchors.insert(anchor_id.clone(), anchor);
        self.lane_mut(lane_id)?.status = CacheLaneStatus::ReorgLocked;
        for bucket_id in affected_bucket_ids {
            self.bucket_mut(&bucket_id)?.status = BucketStatus::ReorgLocked;
        }
        self.counters.reorg_anchors_published =
            self.counters.reorg_anchors_published.saturating_add(1);
        self.push_public_record("reorg_window_anchored", &anchor_id, current_height);
        self.refresh_roots();
        Ok(anchor_id)
    }

    pub fn challenge_stale_cache(
        &mut self,
        lane_id: &str,
        bucket_id: &str,
        challenger_id: impl Into<String>,
        stale_claim_root: impl Into<String>,
        expected_scan_digest: impl Into<String>,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.stale_challenges.len(),
            MAX_STALE_CHALLENGES,
            "stale challenges",
        )?;
        let bucket = self
            .viewtag_buckets
            .get(bucket_id)
            .ok_or_else(|| "viewtag bucket not found".to_string())?
            .clone();
        if bucket.lane_id != lane_id {
            return Err("bucket belongs to different lane".to_string());
        }
        let challenger_id = challenger_id.into();
        let stale_claim_root = stale_claim_root.into();
        let expected_scan_digest = expected_scan_digest.into();
        require_nonempty("challenger_id", &challenger_id)?;
        require_nonempty("stale_claim_root", &stale_claim_root)?;
        require_nonempty("expected_scan_digest", &expected_scan_digest)?;
        if current_height
            > bucket
                .expires_height
                .saturating_add(self.config.challenge_window_blocks)
        {
            return Err("stale cache challenge window elapsed".to_string());
        }
        let challenge_id = challenge_id(
            lane_id,
            bucket_id,
            &challenger_id,
            &stale_claim_root,
            &expected_scan_digest,
        );
        let challenge = StaleCacheChallenge {
            challenge_id: challenge_id.clone(),
            lane_id: lane_id.to_string(),
            bucket_id: bucket_id.to_string(),
            challenger_id,
            provider_id: bucket.provider_id,
            stale_claim_root,
            expected_scan_digest,
            opened_height: current_height,
            expires_height: current_height.saturating_add(self.config.challenge_window_blocks),
            status: ChallengeStatus::Open,
        };
        self.stale_challenges
            .insert(challenge_id.clone(), challenge);
        self.lane_mut(lane_id)?.status = CacheLaneStatus::Challenged;
        self.bucket_mut(bucket_id)?.status = BucketStatus::Challenged;
        self.counters.stale_challenges_opened =
            self.counters.stale_challenges_opened.saturating_add(1);
        self.push_public_record(
            "stale_cache_challenge_opened",
            &challenge_id,
            current_height,
        );
        self.refresh_roots();
        Ok(challenge_id)
    }

    pub fn slash_provider(
        &mut self,
        lane_id: &str,
        provider_id: impl Into<String>,
        reason: SlashReason,
        subject_id: impl Into<String>,
        evidence_root: impl Into<String>,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.slashing_evidence.len(),
            MAX_SLASHING_EVIDENCE,
            "slashing evidence",
        )?;
        let provider_id = provider_id.into();
        let subject_id = subject_id.into();
        let evidence_root = evidence_root.into();
        require_nonempty("provider_id", &provider_id)?;
        require_nonempty("subject_id", &subject_id)?;
        require_nonempty("evidence_root", &evidence_root)?;
        let lane_provider = self
            .cache_lanes
            .get(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())?
            .provider_id
            .clone();
        if lane_provider != provider_id {
            return Err("provider does not own lane".to_string());
        }
        let slash_amount_micro_units = self
            .config
            .provider_bond_micro_units
            .saturating_mul(self.config.slash_bps)
            / MAX_BPS;
        let evidence_id = slash_id(lane_id, &provider_id, reason, &subject_id, &evidence_root);
        let evidence = SlashingEvidence {
            evidence_id: evidence_id.clone(),
            lane_id: lane_id.to_string(),
            provider_id,
            reason,
            subject_id: subject_id.clone(),
            evidence_root,
            slash_amount_micro_units,
            slashed_height: current_height,
        };
        self.slashing_evidence.insert(evidence_id.clone(), evidence);
        self.lane_mut(lane_id)?.status = CacheLaneStatus::Slashed;
        if let Some(bucket) = self.viewtag_buckets.get_mut(&subject_id) {
            bucket.status = BucketStatus::Slashed;
        }
        if let Some(shard) = self.scan_shards.get_mut(&subject_id) {
            shard.status = ShardStatus::Slashed;
        }
        if let Some(lease) = self.window_leases.get_mut(&subject_id) {
            lease.status = LeaseStatus::Slashed;
        }
        if let Some(coupon) = self.scan_coupons.get_mut(&subject_id) {
            coupon.status = CouponStatus::Slashed;
        }
        if let Some(receipt) = self.sync_receipts.get_mut(&subject_id) {
            receipt.status = ReceiptStatus::Slashed;
        }
        if let Some(challenge) = self.stale_challenges.get_mut(&subject_id) {
            challenge.status = ChallengeStatus::Slashed;
        }
        self.counters.providers_slashed = self.counters.providers_slashed.saturating_add(1);
        self.push_public_record(
            "viewtag_cache_provider_slashed",
            &evidence_id,
            current_height,
        );
        self.refresh_roots();
        Ok(evidence_id)
    }

    pub fn expire_height(&mut self, current_height: u64) {
        for lane in self.cache_lanes.values_mut() {
            if lane.status.live() && current_height > lane.expires_height {
                lane.status = CacheLaneStatus::Expired;
            }
        }
        for lease in self.window_leases.values_mut() {
            if lease.status == LeaseStatus::Active && current_height > lease.expires_height {
                lease.status = LeaseStatus::Expired;
            }
        }
        for coupon in self.scan_coupons.values_mut() {
            if matches!(coupon.status, CouponStatus::Issued | CouponStatus::Reserved)
                && current_height > coupon.expires_height
            {
                coupon.status = CouponStatus::Expired;
            }
        }
        for challenge in self.stale_challenges.values_mut() {
            if challenge.status == ChallengeStatus::Open
                && current_height > challenge.expires_height
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        self.refresh_roots();
    }

    pub fn finalize_receipts(&mut self, current_height: u64) {
        for receipt in self.sync_receipts.values_mut() {
            if receipt.status == ReceiptStatus::Published && current_height >= receipt.final_height
            {
                receipt.status = ReceiptStatus::Final;
            }
        }
        self.refresh_roots();
    }

    pub fn state_root(&self) -> String {
        let roots = json!({
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config,
            "counters": self.counters,
            "cache_lanes_root": self.cache_lanes_root(),
            "viewtag_buckets_root": self.viewtag_buckets_root(),
            "wallet_attestations_root": self.wallet_attestations_root(),
            "scan_shards_root": self.scan_shards_root(),
            "window_leases_root": self.window_leases_root(),
            "scan_coupons_root": self.scan_coupons_root(),
            "sync_receipts_root": self.sync_receipts_root(),
            "reorg_anchors_root": self.reorg_anchors_root(),
            "nullifier_fences_root": self.nullifier_fences_root(),
            "stale_challenges_root": self.stale_challenges_root(),
            "slashing_evidence_root": self.slashing_evidence_root(),
            "public_records_root": self.public_records_root(),
        });
        domain_hash(
            "monero-l2-pq-private-viewtag-fast-scan-cache:state-root",
            &[HashPart::Json(&roots)],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        self.roots.cache_lanes_root = self.cache_lanes_root();
        self.roots.viewtag_buckets_root = self.viewtag_buckets_root();
        self.roots.wallet_attestations_root = self.wallet_attestations_root();
        self.roots.scan_shards_root = self.scan_shards_root();
        self.roots.window_leases_root = self.window_leases_root();
        self.roots.scan_coupons_root = self.scan_coupons_root();
        self.roots.sync_receipts_root = self.sync_receipts_root();
        self.roots.reorg_anchors_root = self.reorg_anchors_root();
        self.roots.nullifier_fences_root = self.nullifier_fences_root();
        self.roots.stale_challenges_root = self.stale_challenges_root();
        self.roots.slashing_evidence_root = self.slashing_evidence_root();
        self.roots.public_records_root = self.public_records_root();
        self.roots.state_root = self.state_root();
    }

    pub fn event_public_record(&self, kind: &str, subject_id: &str, height: u64) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "kind": kind,
            "subject_id": subject_id,
            "height": height,
            "state_root": self.state_root(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.config.schema_version,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "devnet_height": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_DEVNET_HEIGHT,
            "hash_suite": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_HASH_SUITE,
            "bucket_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_BUCKET_SCHEME,
            "attestation_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_ATTESTATION_SCHEME,
            "shard_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SHARD_SCHEME,
            "counters": self.counters,
            "roots": self.roots,
            "state_root": self.state_root(),
        })
    }

    pub fn devnet_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": self.config.schema_version,
            "devnet_height": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_DEVNET_HEIGHT,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "hash_suite": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_HASH_SUITE,
            "lane_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_LANE_SCHEME,
            "bucket_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_BUCKET_SCHEME,
            "attestation_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_ATTESTATION_SCHEME,
            "shard_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SHARD_SCHEME,
            "window_lease_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_WINDOW_LEASE_SCHEME,
            "coupon_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_COUPON_SCHEME,
            "receipt_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_RECEIPT_SCHEME,
            "reorg_anchor_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_REORG_ANCHOR_SCHEME,
            "nullifier_fence_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_NULLIFIER_FENCE_SCHEME,
            "challenge_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_CHALLENGE_SCHEME,
            "slashing_scheme": MONERO_L2_PQ_PRIVATE_VIEWTAG_FAST_SCAN_CACHE_RUNTIME_SLASHING_SCHEME,
            "roots": self.roots,
        })
    }

    pub fn cache_lanes_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:lanes",
            &self.cache_lanes,
        )
    }

    pub fn viewtag_buckets_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:buckets",
            &self.viewtag_buckets,
        )
    }

    pub fn wallet_attestations_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:wallet-attestations",
            &self.wallet_attestations,
        )
    }

    pub fn scan_shards_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:scan-shards",
            &self.scan_shards,
        )
    }

    pub fn window_leases_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:window-leases",
            &self.window_leases,
        )
    }

    pub fn scan_coupons_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:scan-coupons",
            &self.scan_coupons,
        )
    }

    pub fn sync_receipts_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:sync-receipts",
            &self.sync_receipts,
        )
    }

    pub fn reorg_anchors_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:reorg-anchors",
            &self.reorg_anchors,
        )
    }

    pub fn nullifier_fences_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:nullifier-fences",
            &self.nullifier_fences,
        )
    }

    pub fn stale_challenges_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:stale-challenges",
            &self.stale_challenges,
        )
    }

    pub fn slashing_evidence_root(&self) -> String {
        map_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:slashing-evidence",
            &self.slashing_evidence,
        )
    }

    pub fn public_records_root(&self) -> String {
        merkle_root(
            "monero-l2-pq-private-viewtag-fast-scan-cache:public-records",
            &self.public_records,
        )
    }

    fn register_nullifier_fence(
        &mut self,
        lane_id: &str,
        subject_id: &str,
        nullifier: &str,
        fence_kind: &str,
        current_height: u64,
    ) -> Result<String> {
        self.ensure_capacity(
            self.nullifier_fences.len(),
            MAX_NULLIFIER_FENCES,
            "nullifier fences",
        )?;
        self.ensure_nullifier_unused(nullifier)?;
        let fence_id = nullifier_fence_id(lane_id, subject_id, nullifier, fence_kind);
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            lane_id: lane_id.to_string(),
            subject_id: subject_id.to_string(),
            nullifier: nullifier.to_string(),
            fence_kind: fence_kind.to_string(),
            registered_height: current_height,
        };
        self.nullifier_fences.insert(fence_id.clone(), fence);
        self.nullifier_index
            .insert(nullifier.to_string(), fence_id.clone());
        self.lane_mut(lane_id)?
            .nullifier_fence_ids
            .insert(fence_id.clone());
        self.counters.nullifier_fences_registered =
            self.counters.nullifier_fences_registered.saturating_add(1);
        Ok(fence_id)
    }

    fn ensure_nullifier_unused(&self, nullifier: &str) -> Result<()> {
        if self.nullifier_index.contains_key(nullifier) {
            return Err("nullifier already fenced".to_string());
        }
        Ok(())
    }

    fn lane_mut(&mut self, lane_id: &str) -> Result<&mut CacheLane> {
        self.cache_lanes
            .get_mut(lane_id)
            .ok_or_else(|| "cache lane not found".to_string())
    }

    fn bucket_mut(&mut self, bucket_id: &str) -> Result<&mut ViewtagBucket> {
        self.viewtag_buckets
            .get_mut(bucket_id)
            .ok_or_else(|| "viewtag bucket not found".to_string())
    }

    fn shard_mut(&mut self, shard_id: &str) -> Result<&mut ScanCacheShard> {
        self.scan_shards
            .get_mut(shard_id)
            .ok_or_else(|| "scan shard not found".to_string())
    }

    fn ensure_capacity(&self, current: usize, max: usize, label: &str) -> Result<()> {
        if current >= max {
            return Err(format!("{label} capacity exceeded"));
        }
        Ok(())
    }

    fn push_public_record(&mut self, kind: &str, subject_id: &str, height: u64) {
        if self.public_records.len() < MAX_PUBLIC_RECORDS {
            let record = json!({
                "chain_id": self.config.chain_id,
                "protocol_version": PROTOCOL_VERSION,
                "kind": kind,
                "subject_id": subject_id,
                "height": height,
            });
            self.public_records.push(record);
            self.counters.public_records = self.counters.public_records.saturating_add(1);
        }
    }
}

pub fn lane_id(
    wallet_commitment: &str,
    provider_id: &str,
    encrypted_route_root: &str,
    viewtag_prefix: &str,
    opened_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:lane-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(wallet_commitment),
            HashPart::Str(provider_id),
            HashPart::Str(encrypted_route_root),
            HashPart::Str(viewtag_prefix),
            HashPart::U64(opened_height),
            HashPart::U64(nonce),
        ],
        32,
    )
}

pub fn shard_id(
    lane_id: &str,
    provider_id: &str,
    shard_index: u32,
    shard_count: u32,
    encrypted_index_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:shard-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(provider_id),
            HashPart::U64(shard_index as u64),
            HashPart::U64(shard_count as u64),
            HashPart::Str(encrypted_index_root),
        ],
        32,
    )
}

pub fn bucket_id(
    lane_id: &str,
    shard_id: &str,
    encrypted_bucket_root: &str,
    monero_start_height: u64,
    monero_end_height: u64,
    scan_digest: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:bucket-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(shard_id),
            HashPart::Str(encrypted_bucket_root),
            HashPart::U64(monero_start_height),
            HashPart::U64(monero_end_height),
            HashPart::Str(scan_digest),
        ],
        32,
    )
}

pub fn attestation_id(
    lane_id: &str,
    bucket_id: &str,
    kind: AttestationKind,
    public_key_commitment: &str,
    signature_commitment: &str,
    statement_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:attestation-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(public_key_commitment),
            HashPart::Str(signature_commitment),
            HashPart::Str(statement_root),
        ],
        32,
    )
}

pub fn lease_id(
    lane_id: &str,
    subaddress_window_root: &str,
    start_major: u32,
    end_major: u32,
    start_minor: u32,
    end_minor: u32,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:lease-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(subaddress_window_root),
            HashPart::U64(start_major as u64),
            HashPart::U64(end_major as u64),
            HashPart::U64(start_minor as u64),
            HashPart::U64(end_minor as u64),
        ],
        32,
    )
}

pub fn coupon_id(
    lane_id: &str,
    sponsor_id: &str,
    provider_id: &str,
    nullifier: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:coupon-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(provider_id),
            HashPart::Str(nullifier),
            HashPart::U64(issued_height),
        ],
        32,
    )
}

pub fn receipt_id(
    lane_id: &str,
    bucket_id: &str,
    synced_bucket_root: &str,
    nullifier: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:receipt-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(synced_bucket_root),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn reorg_anchor_id(
    lane_id: &str,
    monero_start_height: u64,
    monero_end_height: u64,
    old_header_root: &str,
    new_header_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:reorg-anchor-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::U64(monero_start_height),
            HashPart::U64(monero_end_height),
            HashPart::Str(old_header_root),
            HashPart::Str(new_header_root),
        ],
        32,
    )
}

pub fn nullifier_fence_id(
    lane_id: &str,
    subject_id: &str,
    nullifier: &str,
    fence_kind: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:nullifier-fence-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(subject_id),
            HashPart::Str(nullifier),
            HashPart::Str(fence_kind),
        ],
        32,
    )
}

pub fn challenge_id(
    lane_id: &str,
    bucket_id: &str,
    challenger_id: &str,
    stale_claim_root: &str,
    expected_scan_digest: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:challenge-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(bucket_id),
            HashPart::Str(challenger_id),
            HashPart::Str(stale_claim_root),
            HashPart::Str(expected_scan_digest),
        ],
        32,
    )
}

pub fn slash_id(
    lane_id: &str,
    provider_id: &str,
    reason: SlashReason,
    subject_id: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-private-viewtag-fast-scan-cache:slash-id",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane_id),
            HashPart::Str(provider_id),
            HashPart::Str(reason.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn map_root<T: Serialize>(domain: &str, values: &BTreeMap<String, T>) -> String {
    let leaves = values
        .iter()
        .map(|(key, value)| {
            json!({
                "key": key,
                "value": value,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_nonempty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    Ok(())
}

fn windows_overlap(
    a_start_major: u32,
    a_end_major: u32,
    a_start_minor: u32,
    a_end_minor: u32,
    b_start_major: u32,
    b_end_major: u32,
    b_start_minor: u32,
    b_end_minor: u32,
) -> bool {
    let a_start = ((a_start_major as u64) << 32) | a_start_minor as u64;
    let a_end = ((a_end_major as u64) << 32) | a_end_minor as u64;
    let b_start = ((b_start_major as u64) << 32) | b_start_minor as u64;
    let b_end = ((b_end_major as u64) << 32) | b_end_minor as u64;
    a_start <= b_end && b_start <= a_end
}
