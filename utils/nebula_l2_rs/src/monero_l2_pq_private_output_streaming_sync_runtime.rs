use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateOutputStreamingSyncRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const MONERO_L2_PQ_PRIVATE_OUTPUT_STREAMING_SYNC_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-output-streaming-sync-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_OUTPUT_STREAMING_SYNC_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_312_800;
pub const DEVNET_EPOCH: u64 = 1_824;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const VIEW_TAG_STREAM_SCHEME: &str = "monero-view-tag-output-stream-commitment-root-v1";
pub const SUBADDRESS_BUCKET_SCHEME: &str = "subaddress-bucketed-output-stream-root-v1";
pub const ENCRYPTED_OUTPUT_HINT_SCHEME: &str = "ml-kem-1024-sealed-encrypted-output-hint-root-v1";
pub const RING_DECOY_PRESERVATION_SCHEME: &str = "monero-ring-decoy-preservation-root-v1";
pub const PQ_WATCHER_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-output-stream-watcher-attestation-v1";
pub const MOBILE_SYNC_BATCH_SCHEME: &str = "batched-private-mobile-output-sync-root-v1";
pub const PRIVACY_BUDGET_SCHEME: &str = "private-output-streaming-sync-privacy-budget-root-v1";
pub const ROOTS_ONLY_OPERATOR_RECORD_SCHEME: &str =
    "roots-only-output-streaming-sync-operator-record-v1";
pub const DEFAULT_STREAM_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_BUCKET_SPAN_BLOCKS: u64 = 48;
pub const DEFAULT_HINT_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_BATCH_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_REORG_HOLD_BLOCKS: u64 = 36;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 32_768;
pub const DEFAULT_MIN_BUCKET_OUTPUTS: u32 = 1;
pub const DEFAULT_MAX_BUCKET_OUTPUTS: u32 = 8_192;
pub const DEFAULT_MIN_RING_SIZE: u16 = 16;
pub const DEFAULT_MIN_DECOY_PRESERVATION_BPS: u64 = 9_900;
pub const DEFAULT_MIN_WATCHER_COUNT: u16 = 3;
pub const DEFAULT_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_HINT_BYTES: u32 = 16_384;
pub const DEFAULT_MAX_MOBILE_BATCH_BYTES: u32 = 262_144;
pub const DEFAULT_DAILY_LINKABILITY_BUDGET: u64 = 128;
pub const DEFAULT_EPOCH_DISCLOSURE_BUDGET: u64 = 32;
pub const DEFAULT_MAX_OPERATOR_DELAY_BLOCKS: u64 = 12;
pub const DEFAULT_MAX_USER_FEE_MICRO_UNITS: u64 = 2_500;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 9_250;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_VIEW_TAG_STREAMS: usize = 1_048_576;
pub const MAX_SUBADDRESS_BUCKETS: usize = 2_097_152;
pub const MAX_ENCRYPTED_OUTPUT_HINTS: usize = 4_194_304;
pub const MAX_RING_DECOY_SETS: usize = 2_097_152;
pub const MAX_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_MOBILE_SYNC_BATCHES: usize = 1_048_576;
pub const MAX_PRIVACY_BUDGETS: usize = 1_048_576;
pub const MAX_OPERATOR_RECORDS: usize = 524_288;
pub const MAX_NULLIFIER_FENCES: usize = 4_194_304;
pub const MAX_PUBLIC_RECORDS: usize = 8_388_608;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamLane {
    LowFee,
    ForegroundWallet,
    BackgroundWallet,
    MerchantCheckout,
    WatchOnlyAudit,
    RecoveryBootstrap,
    ReorgRepair,
}

impl StreamLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::ForegroundWallet => "foreground_wallet",
            Self::BackgroundWallet => "background_wallet",
            Self::MerchantCheckout => "merchant_checkout",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::RecoveryBootstrap => "recovery_bootstrap",
            Self::ReorgRepair => "reorg_repair",
        }
    }

    pub fn priority_weight(self) -> u64 {
        match self {
            Self::RecoveryBootstrap => 1_000,
            Self::ReorgRepair => 980,
            Self::MerchantCheckout => 940,
            Self::ForegroundWallet => 900,
            Self::WatchOnlyAudit => 760,
            Self::BackgroundWallet => 720,
            Self::LowFee => 680,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Open,
    Bucketed,
    Hinted,
    Attested,
    Batched,
    ReorgLocked,
    Closed,
    Expired,
    Disputed,
}

impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Bucketed => "bucketed",
            Self::Hinted => "hinted",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::ReorgLocked => "reorg_locked",
            Self::Closed => "closed",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Bucketed | Self::Hinted | Self::Attested | Self::Batched
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Draft,
    Sealed,
    Hinted,
    Attested,
    Batched,
    ReorgLocked,
    Expired,
    Disputed,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Hinted => "hinted",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::ReorgLocked => "reorg_locked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }

    pub fn syncable(self) -> bool {
        matches!(self, Self::Hinted | Self::Attested | Self::Batched)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintStatus {
    Sealed,
    Delivered,
    Receipted,
    ReorgLocked,
    Expired,
    Rejected,
}

impl HintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Receipted => "receipted",
            Self::ReorgLocked => "reorg_locked",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoySetStatus {
    Proposed,
    Preserved,
    Rebalanced,
    ReorgLocked,
    Invalidated,
}

impl DecoySetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Preserved => "preserved",
            Self::Rebalanced => "rebalanced",
            Self::ReorgLocked => "reorg_locked",
            Self::Invalidated => "invalidated",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherRole {
    OutputCompleteness,
    ViewTagCoverage,
    RingDecoyPreservation,
    MobileDelivery,
    BudgetAuditor,
    OperatorDelay,
    ReorgSafety,
}

impl WatcherRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutputCompleteness => "output_completeness",
            Self::ViewTagCoverage => "view_tag_coverage",
            Self::RingDecoyPreservation => "ring_decoy_preservation",
            Self::MobileDelivery => "mobile_delivery",
            Self::BudgetAuditor => "budget_auditor",
            Self::OperatorDelay => "operator_delay",
            Self::ReorgSafety => "reorg_safety",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    QuorumCounted,
    Superseded,
    Rejected,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::QuorumCounted => "quorum_counted",
            Self::Superseded => "superseded",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileBatchStatus {
    Open,
    Sealed,
    Delivered,
    Receipted,
    Audited,
    ReorgLocked,
    Expired,
    Disputed,
}

impl MobileBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Delivered => "delivered",
            Self::Receipted => "receipted",
            Self::Audited => "audited",
            Self::ReorgLocked => "reorg_locked",
            Self::Expired => "expired",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetScope {
    Wallet,
    SubaddressBucket,
    ViewTagPrefix,
    MobileDevice,
    WatchOnlyAudit,
    OperatorCohort,
}

impl PrivacyBudgetScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::SubaddressBucket => "subaddress_bucket",
            Self::ViewTagPrefix => "view_tag_prefix",
            Self::MobileDevice => "mobile_device",
            Self::WatchOnlyAudit => "watch_only_audit",
            Self::OperatorCohort => "operator_cohort",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRecordKind {
    StreamRoot,
    BucketRoot,
    HintRoot,
    DecoyRoot,
    WatcherRoot,
    BatchRoot,
    BudgetRoot,
    StateRoot,
}

impl OperatorRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StreamRoot => "stream_root",
            Self::BucketRoot => "bucket_root",
            Self::HintRoot => "hint_root",
            Self::DecoyRoot => "decoy_root",
            Self::WatcherRoot => "watcher_root",
            Self::BatchRoot => "batch_root",
            Self::BudgetRoot => "budget_root",
            Self::StateRoot => "state_root",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub view_tag_stream_scheme: String,
    pub subaddress_bucket_scheme: String,
    pub encrypted_output_hint_scheme: String,
    pub ring_decoy_preservation_scheme: String,
    pub pq_watcher_attestation_scheme: String,
    pub mobile_sync_batch_scheme: String,
    pub privacy_budget_scheme: String,
    pub roots_only_operator_record_scheme: String,
    pub stream_window_blocks: u64,
    pub bucket_span_blocks: u64,
    pub hint_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub reorg_hold_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_bucket_outputs: u32,
    pub max_bucket_outputs: u32,
    pub min_ring_size: u16,
    pub min_decoy_preservation_bps: u64,
    pub min_watcher_count: u16,
    pub watcher_quorum_bps: u64,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub max_hint_bytes: u32,
    pub max_mobile_batch_bytes: u32,
    pub daily_linkability_budget: u64,
    pub epoch_disclosure_budget: u64,
    pub max_operator_delay_blocks: u64,
    pub max_user_fee_micro_units: u64,
    pub sponsor_cover_bps: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            view_tag_stream_scheme: VIEW_TAG_STREAM_SCHEME.to_string(),
            subaddress_bucket_scheme: SUBADDRESS_BUCKET_SCHEME.to_string(),
            encrypted_output_hint_scheme: ENCRYPTED_OUTPUT_HINT_SCHEME.to_string(),
            ring_decoy_preservation_scheme: RING_DECOY_PRESERVATION_SCHEME.to_string(),
            pq_watcher_attestation_scheme: PQ_WATCHER_ATTESTATION_SCHEME.to_string(),
            mobile_sync_batch_scheme: MOBILE_SYNC_BATCH_SCHEME.to_string(),
            privacy_budget_scheme: PRIVACY_BUDGET_SCHEME.to_string(),
            roots_only_operator_record_scheme: ROOTS_ONLY_OPERATOR_RECORD_SCHEME.to_string(),
            stream_window_blocks: DEFAULT_STREAM_WINDOW_BLOCKS,
            bucket_span_blocks: DEFAULT_BUCKET_SPAN_BLOCKS,
            hint_ttl_blocks: DEFAULT_HINT_TTL_BLOCKS,
            batch_ttl_blocks: DEFAULT_BATCH_TTL_BLOCKS,
            reorg_hold_blocks: DEFAULT_REORG_HOLD_BLOCKS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_bucket_outputs: DEFAULT_MIN_BUCKET_OUTPUTS,
            max_bucket_outputs: DEFAULT_MAX_BUCKET_OUTPUTS,
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_decoy_preservation_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            min_watcher_count: DEFAULT_MIN_WATCHER_COUNT,
            watcher_quorum_bps: DEFAULT_WATCHER_QUORUM_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            max_hint_bytes: DEFAULT_MAX_HINT_BYTES,
            max_mobile_batch_bytes: DEFAULT_MAX_MOBILE_BATCH_BYTES,
            daily_linkability_budget: DEFAULT_DAILY_LINKABILITY_BUDGET,
            epoch_disclosure_budget: DEFAULT_EPOCH_DISCLOSURE_BUDGET,
            max_operator_delay_blocks: DEFAULT_MAX_OPERATOR_DELAY_BLOCKS,
            max_user_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "unsupported protocol version {}",
            self.protocol_version
        );
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported schema version"
        );
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("monero_network", &self.monero_network)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure!(self.hash_suite == HASH_SUITE, "unsupported hash suite");
        ensure!(
            self.stream_window_blocks > 0,
            "stream window must be nonzero"
        );
        ensure!(self.bucket_span_blocks > 0, "bucket span must be nonzero");
        ensure!(
            self.stream_window_blocks >= self.bucket_span_blocks,
            "stream window must cover bucket span"
        );
        ensure!(self.hint_ttl_blocks > 0, "hint ttl must be nonzero");
        ensure!(self.batch_ttl_blocks > 0, "batch ttl must be nonzero");
        ensure!(self.reorg_hold_blocks > 0, "reorg hold must be nonzero");
        ensure!(
            self.min_privacy_set_size > 0,
            "min privacy set size must be nonzero"
        );
        ensure!(
            self.min_bucket_outputs > 0,
            "min bucket outputs must be nonzero"
        );
        ensure!(
            self.max_bucket_outputs >= self.min_bucket_outputs,
            "max bucket outputs below min"
        );
        ensure!(
            self.min_ring_size >= 2,
            "min ring size must be at least two"
        );
        ensure!(
            self.min_decoy_preservation_bps <= MAX_BPS,
            "decoy preservation bps exceeds max"
        );
        ensure!(
            self.min_watcher_count > 0,
            "min watcher count must be nonzero"
        );
        ensure!(
            self.watcher_quorum_bps <= MAX_BPS,
            "watcher quorum bps exceeds max"
        );
        ensure!(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security below minimum"
        );
        ensure!(self.max_hint_bytes > 0, "max hint bytes must be nonzero");
        ensure!(
            self.max_mobile_batch_bytes >= self.max_hint_bytes,
            "mobile batch bytes must cover at least one hint"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover bps exceeds max"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "view_tag_stream_scheme": self.view_tag_stream_scheme,
            "subaddress_bucket_scheme": self.subaddress_bucket_scheme,
            "encrypted_output_hint_scheme": self.encrypted_output_hint_scheme,
            "ring_decoy_preservation_scheme": self.ring_decoy_preservation_scheme,
            "pq_watcher_attestation_scheme": self.pq_watcher_attestation_scheme,
            "mobile_sync_batch_scheme": self.mobile_sync_batch_scheme,
            "privacy_budget_scheme": self.privacy_budget_scheme,
            "roots_only_operator_record_scheme": self.roots_only_operator_record_scheme,
            "stream_window_blocks": self.stream_window_blocks,
            "bucket_span_blocks": self.bucket_span_blocks,
            "hint_ttl_blocks": self.hint_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "reorg_hold_blocks": self.reorg_hold_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_bucket_outputs": self.min_bucket_outputs,
            "max_bucket_outputs": self.max_bucket_outputs,
            "min_ring_size": self.min_ring_size,
            "min_decoy_preservation_bps": self.min_decoy_preservation_bps,
            "min_watcher_count": self.min_watcher_count,
            "watcher_quorum_bps": self.watcher_quorum_bps,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "max_hint_bytes": self.max_hint_bytes,
            "max_mobile_batch_bytes": self.max_mobile_batch_bytes,
            "daily_linkability_budget": self.daily_linkability_budget,
            "epoch_disclosure_budget": self.epoch_disclosure_budget,
            "max_operator_delay_blocks": self.max_operator_delay_blocks,
            "max_user_fee_micro_units": self.max_user_fee_micro_units,
            "sponsor_cover_bps": self.sponsor_cover_bps,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub view_tag_streams_opened: u64,
    pub subaddress_buckets_sealed: u64,
    pub encrypted_output_hints_sealed: u64,
    pub ring_decoy_sets_preserved: u64,
    pub watcher_attestations_accepted: u64,
    pub mobile_sync_batches_sealed: u64,
    pub privacy_budgets_opened: u64,
    pub operator_records_published: u64,
    pub nullifier_fences_registered: u64,
    pub public_records: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "view_tag_streams_opened": self.view_tag_streams_opened,
            "subaddress_buckets_sealed": self.subaddress_buckets_sealed,
            "encrypted_output_hints_sealed": self.encrypted_output_hints_sealed,
            "ring_decoy_sets_preserved": self.ring_decoy_sets_preserved,
            "watcher_attestations_accepted": self.watcher_attestations_accepted,
            "mobile_sync_batches_sealed": self.mobile_sync_batches_sealed,
            "privacy_budgets_opened": self.privacy_budgets_opened,
            "operator_records_published": self.operator_records_published,
            "nullifier_fences_registered": self.nullifier_fences_registered,
            "public_records": self.public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counter_root: String,
    pub view_tag_stream_root: String,
    pub subaddress_bucket_root: String,
    pub encrypted_output_hint_root: String,
    pub ring_decoy_set_root: String,
    pub watcher_attestation_root: String,
    pub mobile_sync_batch_root: String,
    pub privacy_budget_root: String,
    pub operator_record_root: String,
    pub nullifier_fence_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counter_root": self.counter_root,
            "view_tag_stream_root": self.view_tag_stream_root,
            "subaddress_bucket_root": self.subaddress_bucket_root,
            "encrypted_output_hint_root": self.encrypted_output_hint_root,
            "ring_decoy_set_root": self.ring_decoy_set_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "mobile_sync_batch_root": self.mobile_sync_batch_root,
            "privacy_budget_root": self.privacy_budget_root,
            "operator_record_root": self.operator_record_root,
            "nullifier_fence_root": self.nullifier_fence_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagStreamRequest {
    pub wallet_commitment: String,
    pub device_commitment: String,
    pub view_tag_prefix: String,
    pub encrypted_route_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub expected_output_count: u32,
    pub privacy_set_size: u64,
    pub pq_view_key_commitment: String,
    pub max_fee_micro_units: u64,
    pub lane: StreamLane,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewTagStream {
    pub stream_id: String,
    pub sequence: u64,
    pub wallet_commitment: String,
    pub device_commitment: String,
    pub view_tag_prefix: String,
    pub encrypted_route_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub expected_output_count: u32,
    pub privacy_set_size: u64,
    pub pq_view_key_commitment: String,
    pub max_fee_micro_units: u64,
    pub lane: StreamLane,
    pub priority_weight: u64,
    pub opened_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: StreamStatus,
    pub bucket_ids: BTreeSet<String>,
    pub hint_ids: BTreeSet<String>,
    pub decoy_set_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub batch_ids: BTreeSet<String>,
}

impl ViewTagStream {
    pub fn public_record(&self) -> Value {
        json!({
            "stream_id": self.stream_id,
            "sequence": self.sequence,
            "wallet_commitment": self.wallet_commitment,
            "device_commitment": self.device_commitment,
            "view_tag_prefix": self.view_tag_prefix,
            "encrypted_route_root": self.encrypted_route_root,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "expected_output_count": self.expected_output_count,
            "privacy_set_size": self.privacy_set_size,
            "pq_view_key_commitment": self.pq_view_key_commitment,
            "max_fee_micro_units": self.max_fee_micro_units,
            "lane": self.lane.as_str(),
            "priority_weight": self.priority_weight,
            "opened_l2_height": self.opened_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "bucket_ids": sorted_strings(&self.bucket_ids),
            "hint_ids": sorted_strings(&self.hint_ids),
            "decoy_set_ids": sorted_strings(&self.decoy_set_ids),
            "attestation_ids": sorted_strings(&self.attestation_ids),
            "batch_ids": sorted_strings(&self.batch_ids),
            "scheme": VIEW_TAG_STREAM_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBucketRequest {
    pub stream_id: String,
    pub subaddress_bucket_commitment: String,
    pub view_tag_bucket_root: String,
    pub output_commitment_root: String,
    pub encrypted_bucket_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub output_count: u32,
    pub bucket_index: u32,
    pub bucket_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressBucket {
    pub bucket_id: String,
    pub stream_id: String,
    pub subaddress_bucket_commitment: String,
    pub view_tag_bucket_root: String,
    pub output_commitment_root: String,
    pub encrypted_bucket_root: String,
    pub monero_start_height: u64,
    pub monero_end_height: u64,
    pub output_count: u32,
    pub bucket_index: u32,
    pub bucket_count: u32,
    pub sealed_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: BucketStatus,
    pub hint_ids: BTreeSet<String>,
    pub decoy_set_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
}

impl SubaddressBucket {
    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "stream_id": self.stream_id,
            "subaddress_bucket_commitment": self.subaddress_bucket_commitment,
            "view_tag_bucket_root": self.view_tag_bucket_root,
            "output_commitment_root": self.output_commitment_root,
            "encrypted_bucket_root": self.encrypted_bucket_root,
            "monero_start_height": self.monero_start_height,
            "monero_end_height": self.monero_end_height,
            "output_count": self.output_count,
            "bucket_index": self.bucket_index,
            "bucket_count": self.bucket_count,
            "sealed_l2_height": self.sealed_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "hint_ids": sorted_strings(&self.hint_ids),
            "decoy_set_ids": sorted_strings(&self.decoy_set_ids),
            "attestation_ids": sorted_strings(&self.attestation_ids),
            "scheme": SUBADDRESS_BUCKET_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedOutputHintRequest {
    pub stream_id: String,
    pub bucket_id: String,
    pub recipient_device_commitment: String,
    pub encrypted_hint_root: String,
    pub ciphertext_root: String,
    pub hint_policy_root: String,
    pub output_locator_root: String,
    pub byte_size: u32,
    pub output_count: u32,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedOutputHint {
    pub hint_id: String,
    pub stream_id: String,
    pub bucket_id: String,
    pub recipient_device_commitment: String,
    pub encrypted_hint_root: String,
    pub ciphertext_root: String,
    pub hint_policy_root: String,
    pub output_locator_root: String,
    pub byte_size: u32,
    pub output_count: u32,
    pub pq_security_bits: u16,
    pub sealed_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: HintStatus,
}

impl EncryptedOutputHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "stream_id": self.stream_id,
            "bucket_id": self.bucket_id,
            "recipient_device_commitment": self.recipient_device_commitment,
            "encrypted_hint_root": self.encrypted_hint_root,
            "ciphertext_root": self.ciphertext_root,
            "hint_policy_root": self.hint_policy_root,
            "output_locator_root": self.output_locator_root,
            "byte_size": self.byte_size,
            "output_count": self.output_count,
            "pq_security_bits": self.pq_security_bits,
            "sealed_l2_height": self.sealed_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "scheme": ENCRYPTED_OUTPUT_HINT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoySetRequest {
    pub stream_id: String,
    pub bucket_id: String,
    pub ring_member_root: String,
    pub decoy_distribution_root: String,
    pub key_image_fence_root: String,
    pub ring_size: u16,
    pub real_output_hidden_count: u32,
    pub decoy_output_count: u32,
    pub preservation_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingDecoySet {
    pub decoy_set_id: String,
    pub stream_id: String,
    pub bucket_id: String,
    pub ring_member_root: String,
    pub decoy_distribution_root: String,
    pub key_image_fence_root: String,
    pub ring_size: u16,
    pub real_output_hidden_count: u32,
    pub decoy_output_count: u32,
    pub preservation_bps: u64,
    pub preserved_l2_height: u64,
    pub status: DecoySetStatus,
}

impl RingDecoySet {
    pub fn public_record(&self) -> Value {
        json!({
            "decoy_set_id": self.decoy_set_id,
            "stream_id": self.stream_id,
            "bucket_id": self.bucket_id,
            "ring_member_root": self.ring_member_root,
            "decoy_distribution_root": self.decoy_distribution_root,
            "key_image_fence_root": self.key_image_fence_root,
            "ring_size": self.ring_size,
            "real_output_hidden_count": self.real_output_hidden_count,
            "decoy_output_count": self.decoy_output_count,
            "preservation_bps": self.preservation_bps,
            "preserved_l2_height": self.preserved_l2_height,
            "status": self.status.as_str(),
            "scheme": RING_DECOY_PRESERVATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestationRequest {
    pub stream_id: String,
    pub bucket_id: Option<String>,
    pub watcher_id: String,
    pub role: WatcherRole,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub statement_root: String,
    pub coverage_root: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_commitment: String,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestation {
    pub attestation_id: String,
    pub stream_id: String,
    pub bucket_id: Option<String>,
    pub watcher_id: String,
    pub role: WatcherRole,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub statement_root: String,
    pub coverage_root: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_commitment: String,
    pub pq_security_bits: u16,
    pub accepted_l2_height: u64,
    pub status: AttestationStatus,
}

impl PqWatcherAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "stream_id": self.stream_id,
            "bucket_id": self.bucket_id,
            "watcher_id": self.watcher_id,
            "role": self.role.as_str(),
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "statement_root": self.statement_root,
            "coverage_root": self.coverage_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "pq_signature_commitment": self.pq_signature_commitment,
            "pq_security_bits": self.pq_security_bits,
            "accepted_l2_height": self.accepted_l2_height,
            "status": self.status.as_str(),
            "scheme": PQ_WATCHER_ATTESTATION_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileSyncBatchRequest {
    pub stream_id: String,
    pub device_commitment: String,
    pub bucket_ids: Vec<String>,
    pub hint_ids: Vec<String>,
    pub decoy_set_ids: Vec<String>,
    pub encrypted_batch_root: String,
    pub fec_shard_root: String,
    pub delivery_policy_root: String,
    pub byte_size: u32,
    pub max_fee_micro_units: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MobileSyncBatch {
    pub batch_id: String,
    pub sequence: u64,
    pub stream_id: String,
    pub device_commitment: String,
    pub bucket_ids: Vec<String>,
    pub hint_ids: Vec<String>,
    pub decoy_set_ids: Vec<String>,
    pub encrypted_batch_root: String,
    pub fec_shard_root: String,
    pub delivery_policy_root: String,
    pub byte_size: u32,
    pub max_fee_micro_units: u64,
    pub sealed_l2_height: u64,
    pub expires_l2_height: u64,
    pub status: MobileBatchStatus,
}

impl MobileSyncBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sequence": self.sequence,
            "stream_id": self.stream_id,
            "device_commitment": self.device_commitment,
            "bucket_ids": self.bucket_ids,
            "hint_ids": self.hint_ids,
            "decoy_set_ids": self.decoy_set_ids,
            "encrypted_batch_root": self.encrypted_batch_root,
            "fec_shard_root": self.fec_shard_root,
            "delivery_policy_root": self.delivery_policy_root,
            "byte_size": self.byte_size,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sealed_l2_height": self.sealed_l2_height,
            "expires_l2_height": self.expires_l2_height,
            "status": self.status.as_str(),
            "scheme": MOBILE_SYNC_BATCH_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRequest {
    pub subject_commitment: String,
    pub scope: PrivacyBudgetScope,
    pub epoch: u64,
    pub linkability_limit: u64,
    pub disclosure_limit: u64,
    pub consumed_linkability: u64,
    pub consumed_disclosures: u64,
    pub budget_policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub subject_commitment: String,
    pub scope: PrivacyBudgetScope,
    pub epoch: u64,
    pub linkability_limit: u64,
    pub disclosure_limit: u64,
    pub consumed_linkability: u64,
    pub consumed_disclosures: u64,
    pub budget_policy_root: String,
    pub opened_l2_height: u64,
}

impl PrivacyBudget {
    pub fn remaining_linkability(&self) -> u64 {
        self.linkability_limit
            .saturating_sub(self.consumed_linkability)
    }

    pub fn remaining_disclosures(&self) -> u64 {
        self.disclosure_limit
            .saturating_sub(self.consumed_disclosures)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_commitment": self.subject_commitment,
            "scope": self.scope.as_str(),
            "epoch": self.epoch,
            "linkability_limit": self.linkability_limit,
            "disclosure_limit": self.disclosure_limit,
            "consumed_linkability": self.consumed_linkability,
            "consumed_disclosures": self.consumed_disclosures,
            "remaining_linkability": self.remaining_linkability(),
            "remaining_disclosures": self.remaining_disclosures(),
            "budget_policy_root": self.budget_policy_root,
            "opened_l2_height": self.opened_l2_height,
            "scheme": PRIVACY_BUDGET_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyOperatorRecord {
    pub record_id: String,
    pub operator_id: String,
    pub kind: OperatorRecordKind,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub root: String,
    pub previous_root: String,
    pub delay_blocks: u64,
    pub watcher_attestation_root: String,
    pub pq_signature_commitment: String,
}

impl RootsOnlyOperatorRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "operator_id": self.operator_id,
            "kind": self.kind.as_str(),
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "root": self.root,
            "previous_root": self.previous_root,
            "delay_blocks": self.delay_blocks,
            "watcher_attestation_root": self.watcher_attestation_root,
            "pq_signature_commitment": self.pq_signature_commitment,
            "scheme": ROOTS_ONLY_OPERATOR_RECORD_SCHEME,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NullifierFence {
    pub fence_id: String,
    pub stream_id: String,
    pub key_image_root: String,
    pub output_locator_root: String,
    pub registered_l2_height: u64,
}

impl NullifierFence {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "stream_id": self.stream_id,
            "key_image_root": self.key_image_root,
            "output_locator_root": self.output_locator_root,
            "registered_l2_height": self.registered_l2_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_l2_height: u64,
    pub current_monero_height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub view_tag_streams: BTreeMap<String, ViewTagStream>,
    pub subaddress_buckets: BTreeMap<String, SubaddressBucket>,
    pub encrypted_output_hints: BTreeMap<String, EncryptedOutputHint>,
    pub ring_decoy_sets: BTreeMap<String, RingDecoySet>,
    pub watcher_attestations: BTreeMap<String, PqWatcherAttestation>,
    pub mobile_sync_batches: BTreeMap<String, MobileSyncBatch>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub operator_records: BTreeMap<String, RootsOnlyOperatorRecord>,
    pub nullifier_fences: BTreeMap<String, NullifierFence>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

impl State {
    pub fn new(
        config: Config,
        current_l2_height: u64,
        current_monero_height: u64,
        epoch: u64,
    ) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            current_l2_height,
            current_monero_height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            view_tag_streams: BTreeMap::new(),
            subaddress_buckets: BTreeMap::new(),
            encrypted_output_hints: BTreeMap::new(),
            ring_decoy_sets: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            mobile_sync_batches: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            operator_records: BTreeMap::new(),
            nullifier_fences: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Self {
        Self::new(
            Config::devnet(),
            DEVNET_HEIGHT,
            DEVNET_HEIGHT + 44,
            DEVNET_EPOCH,
        )
        .expect("devnet output streaming sync config is valid")
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let budget_id = state
            .open_privacy_budget(PrivacyBudgetRequest {
                subject_commitment: devnet_root("wallet", "alpha"),
                scope: PrivacyBudgetScope::Wallet,
                epoch: DEVNET_EPOCH,
                linkability_limit: DEFAULT_DAILY_LINKABILITY_BUDGET,
                disclosure_limit: DEFAULT_EPOCH_DISCLOSURE_BUDGET,
                consumed_linkability: 8,
                consumed_disclosures: 2,
                budget_policy_root: devnet_root("budget-policy", "alpha"),
            })
            .expect("demo privacy budget");
        let stream_id = state
            .open_view_tag_stream(ViewTagStreamRequest {
                wallet_commitment: devnet_root("wallet", "alpha"),
                device_commitment: devnet_root("device", "ios-alpha"),
                view_tag_prefix: "7f".to_string(),
                encrypted_route_root: devnet_root("route", "alpha"),
                monero_start_height: DEVNET_HEIGHT + 1,
                monero_end_height: DEVNET_HEIGHT + 48,
                expected_output_count: 64,
                privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
                pq_view_key_commitment: devnet_root("pq-view-key", "alpha"),
                max_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
                lane: StreamLane::ForegroundWallet,
            })
            .expect("demo stream");
        let bucket_id = state
            .seal_subaddress_bucket(SubaddressBucketRequest {
                stream_id: stream_id.clone(),
                subaddress_bucket_commitment: devnet_root("subaddress-bucket", "alpha-0"),
                view_tag_bucket_root: devnet_root("view-tags", "alpha-0"),
                output_commitment_root: devnet_root("outputs", "alpha-0"),
                encrypted_bucket_root: devnet_root("encrypted-bucket", "alpha-0"),
                monero_start_height: DEVNET_HEIGHT + 1,
                monero_end_height: DEVNET_HEIGHT + 48,
                output_count: 64,
                bucket_index: 0,
                bucket_count: 1,
            })
            .expect("demo bucket");
        let decoy_set_id = state
            .preserve_ring_decoys(RingDecoySetRequest {
                stream_id: stream_id.clone(),
                bucket_id: bucket_id.clone(),
                ring_member_root: devnet_root("ring-members", "alpha-0"),
                decoy_distribution_root: devnet_root("decoy-distribution", "alpha-0"),
                key_image_fence_root: devnet_root("key-image-fence", "alpha-0"),
                ring_size: DEFAULT_MIN_RING_SIZE,
                real_output_hidden_count: 64,
                decoy_output_count: 960,
                preservation_bps: DEFAULT_MIN_DECOY_PRESERVATION_BPS,
            })
            .expect("demo decoy set");
        let hint_id = state
            .seal_encrypted_output_hint(EncryptedOutputHintRequest {
                stream_id: stream_id.clone(),
                bucket_id: bucket_id.clone(),
                recipient_device_commitment: devnet_root("device", "ios-alpha"),
                encrypted_hint_root: devnet_root("hint", "alpha-0"),
                ciphertext_root: devnet_root("hint-ciphertext", "alpha-0"),
                hint_policy_root: devnet_root("hint-policy", "alpha-0"),
                output_locator_root: devnet_root("output-locators", "alpha-0"),
                byte_size: 8_192,
                output_count: 64,
                pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            })
            .expect("demo hint");
        state
            .accept_watcher_attestation(PqWatcherAttestationRequest {
                stream_id: stream_id.clone(),
                bucket_id: Some(bucket_id.clone()),
                watcher_id: "devnet-output-watcher-0".to_string(),
                role: WatcherRole::OutputCompleteness,
                observed_monero_height: DEVNET_HEIGHT + 49,
                observed_l2_height: DEVNET_HEIGHT + 4,
                statement_root: devnet_root("watcher-statement", "alpha-0"),
                coverage_root: devnet_root("watcher-coverage", "alpha-0"),
                pq_public_key_commitment: devnet_root("watcher-pq-key", "0"),
                pq_signature_commitment: devnet_root("watcher-pq-sig", "0"),
                pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            })
            .expect("demo attestation");
        state
            .seal_mobile_sync_batch(MobileSyncBatchRequest {
                stream_id: stream_id.clone(),
                device_commitment: devnet_root("device", "ios-alpha"),
                bucket_ids: vec![bucket_id.clone()],
                hint_ids: vec![hint_id],
                decoy_set_ids: vec![decoy_set_id],
                encrypted_batch_root: devnet_root("mobile-batch", "alpha-0"),
                fec_shard_root: devnet_root("mobile-fec", "alpha-0"),
                delivery_policy_root: devnet_root("delivery-policy", "alpha-0"),
                byte_size: 32_768,
                max_fee_micro_units: DEFAULT_MAX_USER_FEE_MICRO_UNITS,
            })
            .expect("demo mobile batch");
        state
            .register_nullifier_fence(
                &stream_id,
                devnet_root("key-image", "alpha-0"),
                devnet_root("output-locators", "alpha-0"),
            )
            .expect("demo nullifier fence");
        state
            .publish_operator_record(
                "devnet-output-operator-0",
                OperatorRecordKind::StateRoot,
                state.roots.state_root.clone(),
                devnet_root("previous-state-root", "alpha"),
                2,
                state.roots.watcher_attestation_root.clone(),
                devnet_root("operator-pq-sig", "alpha"),
            )
            .expect("demo operator record");
        state
            .consume_budget(&budget_id, 4, 1)
            .expect("demo budget consume");
        state.refresh_roots();
        state
    }

    pub fn advance_l2_height(&mut self, height: u64) -> Result<()> {
        ensure!(
            height >= self.current_l2_height,
            "cannot move l2 height backwards"
        );
        self.current_l2_height = height;
        self.refresh_roots();
        Ok(())
    }

    pub fn advance_monero_height(&mut self, height: u64) -> Result<()> {
        ensure!(
            height >= self.current_monero_height,
            "cannot move monero height backwards"
        );
        self.current_monero_height = height;
        self.refresh_roots();
        Ok(())
    }

    pub fn open_view_tag_stream(&mut self, request: ViewTagStreamRequest) -> Result<String> {
        ensure_capacity(
            self.view_tag_streams.len(),
            MAX_VIEW_TAG_STREAMS,
            "view tag streams",
        )?;
        require_non_empty("wallet_commitment", &request.wallet_commitment)?;
        require_non_empty("device_commitment", &request.device_commitment)?;
        require_non_empty("view_tag_prefix", &request.view_tag_prefix)?;
        require_non_empty("encrypted_route_root", &request.encrypted_route_root)?;
        require_non_empty("pq_view_key_commitment", &request.pq_view_key_commitment)?;
        ensure!(
            request.monero_start_height <= request.monero_end_height,
            "invalid monero stream range"
        );
        ensure!(
            request
                .monero_end_height
                .saturating_sub(request.monero_start_height)
                <= self.config.stream_window_blocks,
            "stream range exceeds configured window"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set below configured minimum"
        );
        ensure!(
            request.max_fee_micro_units <= self.config.max_user_fee_micro_units,
            "stream fee exceeds configured maximum"
        );
        let sequence = self.counters.view_tag_streams_opened.saturating_add(1);
        let stream_id = stream_id(&request, sequence);
        let stream = ViewTagStream {
            stream_id: stream_id.clone(),
            sequence,
            wallet_commitment: request.wallet_commitment,
            device_commitment: request.device_commitment,
            view_tag_prefix: request.view_tag_prefix,
            encrypted_route_root: request.encrypted_route_root,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            expected_output_count: request.expected_output_count,
            privacy_set_size: request.privacy_set_size,
            pq_view_key_commitment: request.pq_view_key_commitment,
            max_fee_micro_units: request.max_fee_micro_units,
            lane: request.lane,
            priority_weight: request.lane.priority_weight(),
            opened_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.stream_window_blocks,
            status: StreamStatus::Open,
            bucket_ids: BTreeSet::new(),
            hint_ids: BTreeSet::new(),
            decoy_set_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            batch_ids: BTreeSet::new(),
        };
        self.view_tag_streams.insert(stream_id.clone(), stream);
        self.counters.view_tag_streams_opened = sequence;
        self.record_event("view_tag_stream_opened", &stream_id)?;
        self.refresh_roots();
        Ok(stream_id)
    }

    pub fn seal_subaddress_bucket(&mut self, request: SubaddressBucketRequest) -> Result<String> {
        ensure_capacity(
            self.subaddress_buckets.len(),
            MAX_SUBADDRESS_BUCKETS,
            "subaddress buckets",
        )?;
        require_non_empty("stream_id", &request.stream_id)?;
        require_non_empty(
            "subaddress_bucket_commitment",
            &request.subaddress_bucket_commitment,
        )?;
        require_non_empty("view_tag_bucket_root", &request.view_tag_bucket_root)?;
        require_non_empty("output_commitment_root", &request.output_commitment_root)?;
        require_non_empty("encrypted_bucket_root", &request.encrypted_bucket_root)?;
        ensure!(
            self.view_tag_streams.contains_key(&request.stream_id),
            "unknown stream {}",
            request.stream_id
        );
        ensure!(
            request.monero_start_height <= request.monero_end_height,
            "invalid bucket monero range"
        );
        ensure!(
            request.output_count >= self.config.min_bucket_outputs
                && request.output_count <= self.config.max_bucket_outputs,
            "bucket output count outside configured range"
        );
        ensure!(
            request.bucket_count > 0 && request.bucket_index < request.bucket_count,
            "invalid bucket index/count"
        );
        let bucket_id = bucket_id(&request);
        let bucket = SubaddressBucket {
            bucket_id: bucket_id.clone(),
            stream_id: request.stream_id.clone(),
            subaddress_bucket_commitment: request.subaddress_bucket_commitment,
            view_tag_bucket_root: request.view_tag_bucket_root,
            output_commitment_root: request.output_commitment_root,
            encrypted_bucket_root: request.encrypted_bucket_root,
            monero_start_height: request.monero_start_height,
            monero_end_height: request.monero_end_height,
            output_count: request.output_count,
            bucket_index: request.bucket_index,
            bucket_count: request.bucket_count,
            sealed_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.hint_ttl_blocks,
            status: BucketStatus::Sealed,
            hint_ids: BTreeSet::new(),
            decoy_set_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
        };
        self.subaddress_buckets.insert(bucket_id.clone(), bucket);
        if let Some(stream) = self.view_tag_streams.get_mut(&request.stream_id) {
            stream.bucket_ids.insert(bucket_id.clone());
            stream.status = StreamStatus::Bucketed;
        }
        self.counters.subaddress_buckets_sealed =
            self.counters.subaddress_buckets_sealed.saturating_add(1);
        self.record_event("subaddress_bucket_sealed", &bucket_id)?;
        self.refresh_roots();
        Ok(bucket_id)
    }

    pub fn seal_encrypted_output_hint(
        &mut self,
        request: EncryptedOutputHintRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.encrypted_output_hints.len(),
            MAX_ENCRYPTED_OUTPUT_HINTS,
            "encrypted output hints",
        )?;
        require_non_empty("stream_id", &request.stream_id)?;
        require_non_empty("bucket_id", &request.bucket_id)?;
        require_non_empty(
            "recipient_device_commitment",
            &request.recipient_device_commitment,
        )?;
        require_non_empty("encrypted_hint_root", &request.encrypted_hint_root)?;
        require_non_empty("ciphertext_root", &request.ciphertext_root)?;
        require_non_empty("hint_policy_root", &request.hint_policy_root)?;
        require_non_empty("output_locator_root", &request.output_locator_root)?;
        ensure!(
            self.view_tag_streams.contains_key(&request.stream_id),
            "unknown stream {}",
            request.stream_id
        );
        ensure!(
            self.subaddress_buckets.contains_key(&request.bucket_id),
            "unknown bucket {}",
            request.bucket_id
        );
        ensure!(
            request.byte_size <= self.config.max_hint_bytes,
            "hint byte size exceeds configured max"
        );
        ensure!(
            request.output_count > 0,
            "hint output count must be nonzero"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "hint pq security below minimum"
        );
        let hint_id = hint_id(&request);
        let hint = EncryptedOutputHint {
            hint_id: hint_id.clone(),
            stream_id: request.stream_id.clone(),
            bucket_id: request.bucket_id.clone(),
            recipient_device_commitment: request.recipient_device_commitment,
            encrypted_hint_root: request.encrypted_hint_root,
            ciphertext_root: request.ciphertext_root,
            hint_policy_root: request.hint_policy_root,
            output_locator_root: request.output_locator_root,
            byte_size: request.byte_size,
            output_count: request.output_count,
            pq_security_bits: request.pq_security_bits,
            sealed_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.hint_ttl_blocks,
            status: HintStatus::Sealed,
        };
        self.encrypted_output_hints.insert(hint_id.clone(), hint);
        if let Some(stream) = self.view_tag_streams.get_mut(&request.stream_id) {
            stream.hint_ids.insert(hint_id.clone());
            stream.status = StreamStatus::Hinted;
        }
        if let Some(bucket) = self.subaddress_buckets.get_mut(&request.bucket_id) {
            bucket.hint_ids.insert(hint_id.clone());
            bucket.status = BucketStatus::Hinted;
        }
        self.counters.encrypted_output_hints_sealed = self
            .counters
            .encrypted_output_hints_sealed
            .saturating_add(1);
        self.record_event("encrypted_output_hint_sealed", &hint_id)?;
        self.refresh_roots();
        Ok(hint_id)
    }

    pub fn preserve_ring_decoys(&mut self, request: RingDecoySetRequest) -> Result<String> {
        ensure_capacity(
            self.ring_decoy_sets.len(),
            MAX_RING_DECOY_SETS,
            "ring decoy sets",
        )?;
        require_non_empty("stream_id", &request.stream_id)?;
        require_non_empty("bucket_id", &request.bucket_id)?;
        require_non_empty("ring_member_root", &request.ring_member_root)?;
        require_non_empty("decoy_distribution_root", &request.decoy_distribution_root)?;
        require_non_empty("key_image_fence_root", &request.key_image_fence_root)?;
        ensure!(
            self.view_tag_streams.contains_key(&request.stream_id),
            "unknown stream {}",
            request.stream_id
        );
        ensure!(
            self.subaddress_buckets.contains_key(&request.bucket_id),
            "unknown bucket {}",
            request.bucket_id
        );
        ensure!(
            request.ring_size >= self.config.min_ring_size,
            "ring size below configured minimum"
        );
        ensure!(
            request.real_output_hidden_count > 0,
            "real hidden output count must be nonzero"
        );
        ensure!(
            request.decoy_output_count
                >= request
                    .real_output_hidden_count
                    .saturating_mul(request.ring_size.saturating_sub(1) as u32),
            "decoy output count does not preserve ring expansion"
        );
        ensure!(
            request.preservation_bps >= self.config.min_decoy_preservation_bps,
            "decoy preservation below configured minimum"
        );
        ensure!(
            request.preservation_bps <= MAX_BPS,
            "decoy preservation bps exceeds max"
        );
        let decoy_set_id = decoy_set_id(&request);
        let decoy_set = RingDecoySet {
            decoy_set_id: decoy_set_id.clone(),
            stream_id: request.stream_id.clone(),
            bucket_id: request.bucket_id.clone(),
            ring_member_root: request.ring_member_root,
            decoy_distribution_root: request.decoy_distribution_root,
            key_image_fence_root: request.key_image_fence_root,
            ring_size: request.ring_size,
            real_output_hidden_count: request.real_output_hidden_count,
            decoy_output_count: request.decoy_output_count,
            preservation_bps: request.preservation_bps,
            preserved_l2_height: self.current_l2_height,
            status: DecoySetStatus::Preserved,
        };
        self.ring_decoy_sets.insert(decoy_set_id.clone(), decoy_set);
        if let Some(stream) = self.view_tag_streams.get_mut(&request.stream_id) {
            stream.decoy_set_ids.insert(decoy_set_id.clone());
        }
        if let Some(bucket) = self.subaddress_buckets.get_mut(&request.bucket_id) {
            bucket.decoy_set_ids.insert(decoy_set_id.clone());
        }
        self.counters.ring_decoy_sets_preserved =
            self.counters.ring_decoy_sets_preserved.saturating_add(1);
        self.record_event("ring_decoy_set_preserved", &decoy_set_id)?;
        self.refresh_roots();
        Ok(decoy_set_id)
    }

    pub fn accept_watcher_attestation(
        &mut self,
        request: PqWatcherAttestationRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.watcher_attestations.len(),
            MAX_WATCHER_ATTESTATIONS,
            "watcher attestations",
        )?;
        require_non_empty("stream_id", &request.stream_id)?;
        require_non_empty("watcher_id", &request.watcher_id)?;
        require_non_empty("statement_root", &request.statement_root)?;
        require_non_empty("coverage_root", &request.coverage_root)?;
        require_non_empty(
            "pq_public_key_commitment",
            &request.pq_public_key_commitment,
        )?;
        require_non_empty("pq_signature_commitment", &request.pq_signature_commitment)?;
        ensure!(
            self.view_tag_streams.contains_key(&request.stream_id),
            "unknown stream {}",
            request.stream_id
        );
        if let Some(bucket_id) = &request.bucket_id {
            ensure!(
                self.subaddress_buckets.contains_key(bucket_id),
                "unknown bucket {}",
                bucket_id
            );
        }
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "watcher pq security below minimum"
        );
        ensure!(
            request.observed_l2_height <= self.current_l2_height,
            "watcher observed future l2 height"
        );
        let attestation_id =
            attestation_id(&request, self.counters.watcher_attestations_accepted + 1);
        let attestation = PqWatcherAttestation {
            attestation_id: attestation_id.clone(),
            stream_id: request.stream_id.clone(),
            bucket_id: request.bucket_id.clone(),
            watcher_id: request.watcher_id,
            role: request.role,
            observed_monero_height: request.observed_monero_height,
            observed_l2_height: request.observed_l2_height,
            statement_root: request.statement_root,
            coverage_root: request.coverage_root,
            pq_public_key_commitment: request.pq_public_key_commitment,
            pq_signature_commitment: request.pq_signature_commitment,
            pq_security_bits: request.pq_security_bits,
            accepted_l2_height: self.current_l2_height,
            status: AttestationStatus::Accepted,
        };
        self.watcher_attestations
            .insert(attestation_id.clone(), attestation);
        if let Some(stream) = self.view_tag_streams.get_mut(&request.stream_id) {
            stream.attestation_ids.insert(attestation_id.clone());
            if stream.attestation_ids.len() >= self.config.min_watcher_count as usize {
                stream.status = StreamStatus::Attested;
            }
        }
        if let Some(bucket_id) = request.bucket_id {
            if let Some(bucket) = self.subaddress_buckets.get_mut(&bucket_id) {
                bucket.attestation_ids.insert(attestation_id.clone());
                bucket.status = BucketStatus::Attested;
            }
        }
        self.counters.watcher_attestations_accepted = self
            .counters
            .watcher_attestations_accepted
            .saturating_add(1);
        self.record_event("pq_watcher_attestation_accepted", &attestation_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn seal_mobile_sync_batch(&mut self, request: MobileSyncBatchRequest) -> Result<String> {
        ensure_capacity(
            self.mobile_sync_batches.len(),
            MAX_MOBILE_SYNC_BATCHES,
            "mobile sync batches",
        )?;
        require_non_empty("stream_id", &request.stream_id)?;
        require_non_empty("device_commitment", &request.device_commitment)?;
        require_non_empty("encrypted_batch_root", &request.encrypted_batch_root)?;
        require_non_empty("fec_shard_root", &request.fec_shard_root)?;
        require_non_empty("delivery_policy_root", &request.delivery_policy_root)?;
        ensure!(
            self.view_tag_streams.contains_key(&request.stream_id),
            "unknown stream {}",
            request.stream_id
        );
        ensure!(
            !request.bucket_ids.is_empty(),
            "batch needs at least one bucket"
        );
        ensure!(
            !request.hint_ids.is_empty(),
            "batch needs at least one hint"
        );
        ensure!(
            request.byte_size <= self.config.max_mobile_batch_bytes,
            "mobile batch byte size exceeds configured max"
        );
        ensure!(
            request.max_fee_micro_units <= self.config.max_user_fee_micro_units,
            "mobile batch fee exceeds configured maximum"
        );
        for bucket_id in &request.bucket_ids {
            ensure!(
                self.subaddress_buckets.contains_key(bucket_id),
                "unknown bucket {}",
                bucket_id
            );
        }
        for hint_id in &request.hint_ids {
            ensure!(
                self.encrypted_output_hints.contains_key(hint_id),
                "unknown hint {}",
                hint_id
            );
        }
        for decoy_set_id in &request.decoy_set_ids {
            ensure!(
                self.ring_decoy_sets.contains_key(decoy_set_id),
                "unknown decoy set {}",
                decoy_set_id
            );
        }
        let sequence = self.counters.mobile_sync_batches_sealed.saturating_add(1);
        let batch_id = mobile_batch_id(&request, sequence);
        let batch = MobileSyncBatch {
            batch_id: batch_id.clone(),
            sequence,
            stream_id: request.stream_id.clone(),
            device_commitment: request.device_commitment,
            bucket_ids: sorted_vec(request.bucket_ids),
            hint_ids: sorted_vec(request.hint_ids),
            decoy_set_ids: sorted_vec(request.decoy_set_ids),
            encrypted_batch_root: request.encrypted_batch_root,
            fec_shard_root: request.fec_shard_root,
            delivery_policy_root: request.delivery_policy_root,
            byte_size: request.byte_size,
            max_fee_micro_units: request.max_fee_micro_units,
            sealed_l2_height: self.current_l2_height,
            expires_l2_height: self.current_l2_height + self.config.batch_ttl_blocks,
            status: MobileBatchStatus::Sealed,
        };
        for bucket_id in &batch.bucket_ids {
            if let Some(bucket) = self.subaddress_buckets.get_mut(bucket_id) {
                bucket.status = BucketStatus::Batched;
            }
        }
        if let Some(stream) = self.view_tag_streams.get_mut(&request.stream_id) {
            stream.batch_ids.insert(batch_id.clone());
            stream.status = StreamStatus::Batched;
        }
        self.mobile_sync_batches.insert(batch_id.clone(), batch);
        self.counters.mobile_sync_batches_sealed = sequence;
        self.record_event("mobile_sync_batch_sealed", &batch_id)?;
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn open_privacy_budget(&mut self, request: PrivacyBudgetRequest) -> Result<String> {
        ensure_capacity(
            self.privacy_budgets.len(),
            MAX_PRIVACY_BUDGETS,
            "privacy budgets",
        )?;
        require_non_empty("subject_commitment", &request.subject_commitment)?;
        require_non_empty("budget_policy_root", &request.budget_policy_root)?;
        ensure!(
            request.consumed_linkability <= request.linkability_limit,
            "consumed linkability exceeds limit"
        );
        ensure!(
            request.consumed_disclosures <= request.disclosure_limit,
            "consumed disclosures exceed limit"
        );
        ensure!(
            request.linkability_limit <= self.config.daily_linkability_budget,
            "linkability limit exceeds configured daily budget"
        );
        ensure!(
            request.disclosure_limit <= self.config.epoch_disclosure_budget,
            "disclosure limit exceeds configured epoch budget"
        );
        let budget_id = privacy_budget_id(&request);
        let budget = PrivacyBudget {
            budget_id: budget_id.clone(),
            subject_commitment: request.subject_commitment,
            scope: request.scope,
            epoch: request.epoch,
            linkability_limit: request.linkability_limit,
            disclosure_limit: request.disclosure_limit,
            consumed_linkability: request.consumed_linkability,
            consumed_disclosures: request.consumed_disclosures,
            budget_policy_root: request.budget_policy_root,
            opened_l2_height: self.current_l2_height,
        };
        self.privacy_budgets.insert(budget_id.clone(), budget);
        self.counters.privacy_budgets_opened =
            self.counters.privacy_budgets_opened.saturating_add(1);
        self.record_event("privacy_budget_opened", &budget_id)?;
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn consume_budget(
        &mut self,
        budget_id: &str,
        linkability: u64,
        disclosures: u64,
    ) -> Result<()> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| format!("unknown privacy budget {budget_id}"))?;
        ensure!(
            budget.consumed_linkability.saturating_add(linkability) <= budget.linkability_limit,
            "linkability budget exceeded"
        );
        ensure!(
            budget.consumed_disclosures.saturating_add(disclosures) <= budget.disclosure_limit,
            "disclosure budget exceeded"
        );
        budget.consumed_linkability = budget.consumed_linkability.saturating_add(linkability);
        budget.consumed_disclosures = budget.consumed_disclosures.saturating_add(disclosures);
        self.record_event("privacy_budget_consumed", budget_id)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn publish_operator_record(
        &mut self,
        operator_id: &str,
        kind: OperatorRecordKind,
        root: String,
        previous_root: String,
        delay_blocks: u64,
        watcher_attestation_root: String,
        pq_signature_commitment: String,
    ) -> Result<String> {
        ensure_capacity(
            self.operator_records.len(),
            MAX_OPERATOR_RECORDS,
            "operator records",
        )?;
        require_non_empty("operator_id", operator_id)?;
        require_non_empty("root", &root)?;
        require_non_empty("previous_root", &previous_root)?;
        require_non_empty("watcher_attestation_root", &watcher_attestation_root)?;
        require_non_empty("pq_signature_commitment", &pq_signature_commitment)?;
        ensure!(
            delay_blocks <= self.config.max_operator_delay_blocks,
            "operator delay exceeds configured maximum"
        );
        let record_id =
            operator_record_id(operator_id, kind, &root, self.current_l2_height, self.epoch);
        let record = RootsOnlyOperatorRecord {
            record_id: record_id.clone(),
            operator_id: operator_id.to_string(),
            kind,
            l2_height: self.current_l2_height,
            monero_height: self.current_monero_height,
            epoch: self.epoch,
            root,
            previous_root,
            delay_blocks,
            watcher_attestation_root,
            pq_signature_commitment,
        };
        self.operator_records.insert(record_id.clone(), record);
        self.counters.operator_records_published =
            self.counters.operator_records_published.saturating_add(1);
        self.record_event("roots_only_operator_record_published", &record_id)?;
        self.refresh_roots();
        Ok(record_id)
    }

    pub fn register_nullifier_fence(
        &mut self,
        stream_id: &str,
        key_image_root: String,
        output_locator_root: String,
    ) -> Result<String> {
        ensure_capacity(
            self.nullifier_fences.len(),
            MAX_NULLIFIER_FENCES,
            "nullifier fences",
        )?;
        require_non_empty("stream_id", stream_id)?;
        require_non_empty("key_image_root", &key_image_root)?;
        require_non_empty("output_locator_root", &output_locator_root)?;
        ensure!(
            self.view_tag_streams.contains_key(stream_id),
            "unknown stream {}",
            stream_id
        );
        let fence_id = nullifier_fence_id(stream_id, &key_image_root, &output_locator_root);
        let fence = NullifierFence {
            fence_id: fence_id.clone(),
            stream_id: stream_id.to_string(),
            key_image_root,
            output_locator_root,
            registered_l2_height: self.current_l2_height,
        };
        self.nullifier_fences.insert(fence_id.clone(), fence);
        self.counters.nullifier_fences_registered =
            self.counters.nullifier_fences_registered.saturating_add(1);
        self.record_event("nullifier_fence_registered", &fence_id)?;
        self.refresh_roots();
        Ok(fence_id)
    }

    pub fn lock_reorg_window(&mut self, stream_id: &str) -> Result<()> {
        let stream = self
            .view_tag_streams
            .get_mut(stream_id)
            .ok_or_else(|| format!("unknown stream {stream_id}"))?;
        stream.status = StreamStatus::ReorgLocked;
        for bucket_id in stream.bucket_ids.clone() {
            if let Some(bucket) = self.subaddress_buckets.get_mut(&bucket_id) {
                bucket.status = BucketStatus::ReorgLocked;
            }
        }
        for hint_id in stream.hint_ids.clone() {
            if let Some(hint) = self.encrypted_output_hints.get_mut(&hint_id) {
                hint.status = HintStatus::ReorgLocked;
            }
        }
        self.record_event("stream_reorg_locked", stream_id)?;
        self.refresh_roots();
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        let mut counters = self.counters.clone();
        counters.public_records = self.public_records.len();
        counters
    }

    pub fn refresh_roots(&mut self) {
        let mut roots = Roots {
            config_root: record_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-CONFIG",
                &self.config.public_record(),
            ),
            counter_root: record_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-COUNTERS",
                &self.counters().public_record(),
            ),
            view_tag_stream_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-STREAMS",
                self.view_tag_streams
                    .values()
                    .map(ViewTagStream::public_record)
                    .collect::<Vec<_>>(),
            ),
            subaddress_bucket_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-BUCKETS",
                self.subaddress_buckets
                    .values()
                    .map(SubaddressBucket::public_record)
                    .collect::<Vec<_>>(),
            ),
            encrypted_output_hint_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-HINTS",
                self.encrypted_output_hints
                    .values()
                    .map(EncryptedOutputHint::public_record)
                    .collect::<Vec<_>>(),
            ),
            ring_decoy_set_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-DECOYS",
                self.ring_decoy_sets
                    .values()
                    .map(RingDecoySet::public_record)
                    .collect::<Vec<_>>(),
            ),
            watcher_attestation_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-WATCHERS",
                self.watcher_attestations
                    .values()
                    .map(PqWatcherAttestation::public_record)
                    .collect::<Vec<_>>(),
            ),
            mobile_sync_batch_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-MOBILE-BATCHES",
                self.mobile_sync_batches
                    .values()
                    .map(MobileSyncBatch::public_record)
                    .collect::<Vec<_>>(),
            ),
            privacy_budget_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-PRIVACY-BUDGETS",
                self.privacy_budgets
                    .values()
                    .map(PrivacyBudget::public_record)
                    .collect::<Vec<_>>(),
            ),
            operator_record_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-OPERATOR-RECORDS",
                self.operator_records
                    .values()
                    .map(RootsOnlyOperatorRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            nullifier_fence_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-NULLIFIER-FENCES",
                self.nullifier_fences
                    .values()
                    .map(NullifierFence::public_record)
                    .collect::<Vec<_>>(),
            ),
            public_record_root: value_root(
                "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-PUBLIC-RECORDS",
                self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
            state_root: String::new(),
        };
        roots.state_root = record_root(
            "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-STATE",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "schema_version": SCHEMA_VERSION,
                "chain_id": self.config.chain_id,
                "current_l2_height": self.current_l2_height,
                "current_monero_height": self.current_monero_height,
                "epoch": self.epoch,
                "roots": roots.public_record(),
                "counters": self.counters().public_record(),
            }),
        );
        self.roots = roots;
    }

    pub fn roots(&self) -> Roots {
        let mut clone = self.clone();
        clone.refresh_roots();
        clone.roots
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "epoch": self.epoch,
            "monero_network": self.config.monero_network,
            "l2_network": self.config.l2_network,
            "hash_suite": self.config.hash_suite,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn operator_roots_only_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.config.chain_id,
            "current_l2_height": self.current_l2_height,
            "current_monero_height": self.current_monero_height,
            "epoch": self.epoch,
            "scheme": ROOTS_ONLY_OPERATOR_RECORD_SCHEME,
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    fn record_event(&mut self, kind: &str, subject_id: &str) -> Result<()> {
        ensure_capacity(
            self.public_records.len(),
            MAX_PUBLIC_RECORDS,
            "public records",
        )?;
        let record = json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "kind": kind,
            "subject_id": subject_id,
            "l2_height": self.current_l2_height,
            "monero_height": self.current_monero_height,
            "epoch": self.epoch,
        });
        let event_id = domain_hash(
            "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-EVENT",
            &[
                HashPart::Str(kind),
                HashPart::Str(subject_id),
                HashPart::Json(&record),
            ],
            32,
        );
        self.public_records.insert(event_id, record);
        Ok(())
    }
}

pub fn monero_l2_pq_private_output_streaming_sync_runtime_state_root(state: &State) -> String {
    state.state_root()
}

pub fn monero_l2_pq_private_output_streaming_sync_runtime_public_record(state: &State) -> Value {
    state.public_record()
}

pub fn devnet_config() -> Config {
    Config::devnet()
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn demo_state() -> State {
    State::demo()
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let mut sorted = records.to_vec();
    sorted.sort_by_key(crate::hash::canonical_json_string);
    merkle_root(domain, &sorted)
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn value_root(domain: &str, records: Vec<Value>) -> String {
    public_record_root(domain, &records)
}

pub fn devnet_root(kind: &str, label: &str) -> String {
    let record = json!({
        "protocol_version": PROTOCOL_VERSION,
        "chain_id": CHAIN_ID,
        "kind": kind,
        "label": label,
        "devnet_height": DEVNET_HEIGHT,
        "devnet_epoch": DEVNET_EPOCH,
    });
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-DEVNET-ROOT",
        &[HashPart::Json(&record)],
        32,
    )
}

fn stream_id(request: &ViewTagStreamRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-STREAM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.wallet_commitment),
            HashPart::Str(&request.device_commitment),
            HashPart::Str(&request.view_tag_prefix),
            HashPart::U64(request.monero_start_height),
            HashPart::U64(request.monero_end_height),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn bucket_id(request: &SubaddressBucketRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.stream_id),
            HashPart::Str(&request.subaddress_bucket_commitment),
            HashPart::Str(&request.output_commitment_root),
            HashPart::U64(request.bucket_index as u64),
            HashPart::U64(request.bucket_count as u64),
        ],
        32,
    )
}

fn hint_id(request: &EncryptedOutputHintRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.stream_id),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(&request.recipient_device_commitment),
            HashPart::Str(&request.encrypted_hint_root),
            HashPart::Str(&request.ciphertext_root),
        ],
        32,
    )
}

fn decoy_set_id(request: &RingDecoySetRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-DECOY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.stream_id),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(&request.ring_member_root),
            HashPart::Str(&request.decoy_distribution_root),
            HashPart::U64(request.ring_size as u64),
        ],
        32,
    )
}

fn attestation_id(request: &PqWatcherAttestationRequest, sequence: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.stream_id),
            HashPart::Str(request.bucket_id.as_deref().unwrap_or("stream")),
            HashPart::Str(&request.watcher_id),
            HashPart::Str(request.role.as_str()),
            HashPart::Str(&request.statement_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

fn mobile_batch_id(request: &MobileSyncBatchRequest, sequence: u64) -> String {
    let record = json!({
        "chain_id": CHAIN_ID,
        "stream_id": request.stream_id,
        "device_commitment": request.device_commitment,
        "bucket_ids": sorted_vec(request.bucket_ids.clone()),
        "hint_ids": sorted_vec(request.hint_ids.clone()),
        "decoy_set_ids": sorted_vec(request.decoy_set_ids.clone()),
        "encrypted_batch_root": request.encrypted_batch_root,
        "sequence": sequence,
    });
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-MOBILE-BATCH-ID",
        &[HashPart::Json(&record)],
        32,
    )
}

fn privacy_budget_id(request: &PrivacyBudgetRequest) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.subject_commitment),
            HashPart::Str(request.scope.as_str()),
            HashPart::U64(request.epoch),
            HashPart::Str(&request.budget_policy_root),
        ],
        32,
    )
}

fn operator_record_id(
    operator_id: &str,
    kind: OperatorRecordKind,
    root: &str,
    l2_height: u64,
    epoch: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-OPERATOR-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(root),
            HashPart::U64(l2_height),
            HashPart::U64(epoch),
        ],
        32,
    )
}

fn nullifier_fence_id(stream_id: &str, key_image_root: &str, output_locator_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-PRIVATE-OUTPUT-STREAMING-SYNC-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(stream_id),
            HashPart::Str(key_image_root),
            HashPart::Str(output_locator_root),
        ],
        32,
    )
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn sorted_vec(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn require_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_has_deterministic_state_root() {
        let first = State::demo().state_root();
        let second = State::demo().state_root();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn operator_record_is_roots_only() {
        let state = State::demo();
        let record = state.operator_roots_only_record();
        assert!(record.get("roots").is_some());
        assert!(record.get("view_tag_streams").is_none());
        assert!(record.get("encrypted_output_hints").is_none());
    }
}
