use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2FastPqConfidentialZeroCopyIntentReceiptCacheRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_INTENT_RECEIPT_CACHE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-fast-pq-confidential-zero-copy-intent-receipt-cache-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_FAST_PQ_CONFIDENTIAL_ZERO_COPY_INTENT_RECEIPT_CACHE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 2_984_000;
pub const DEVNET_EPOCH: u64 = 15_552;
pub const DEFAULT_SHARD_COUNT: u16 = 16;
pub const DEFAULT_PAGE_SIZE_BYTES: u32 = 65_536;
pub const DEFAULT_MAX_PAGES_PER_SHARD: u32 = 4_096;
pub const DEFAULT_PREFETCH_LEASE_TTL_MS: u64 = 480;
pub const DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_REDACTION_BUDGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_TARGET_CACHE_HIT_BPS: u64 = 9_200;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 900;
pub const DEFAULT_MAX_USER_FEE_MICROS: u64 = 12;
pub const DEFAULT_OPERATOR_SUMMARY_WINDOW: u64 = 128;
pub const MAX_BPS: u64 = 10_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ZERO_COPY_PAGE_SUITE: &str = "zero-copy-confidential-intent-receipt-page-v1";
pub const PQ_CACHE_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-zero-copy-intent-receipt-cache-v1";
pub const ENCRYPTED_INTENT_INDEX_SUITE: &str = "ML-KEM-1024-threshold-encrypted-intent-index-v1";
pub const INVALIDATION_FENCE_SUITE: &str = "private-l2-cache-invalidation-fence-v1";
pub const PREFETCH_LEASE_SUITE: &str = "private-l2-zero-copy-prefetch-lease-v1";
pub const LOW_FEE_CACHE_REBATE_SUITE: &str = "low-fee-confidential-cache-rebate-v1";
pub const REDACTION_BUDGET_SUITE: &str = "privacy-budgeted-intent-receipt-redaction-v1";
pub const OPERATOR_SUMMARY_SUITE: &str = "operator-safe-zero-copy-cache-summary-root-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";

const D_STATE: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:STATE";
const D_CONFIG: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:CONFIG";
const D_COUNTERS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:COUNTERS";
const D_ROOTS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:ROOTS";
const D_SHARDS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:SHARDS";
const D_PAGES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:PAGES";
const D_INTENT_INDEXES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:INTENT_INDEXES";
const D_ATTESTATIONS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:ATTESTATIONS";
const D_FENCES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:FENCES";
const D_LEASES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:LEASES";
const D_REBATES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:REBATES";
const D_REDACTIONS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:REDACTIONS";
const D_SUMMARIES: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:SUMMARIES";
const D_EVENTS: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:EVENTS";
const D_PUBLIC: &str = "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:PUBLIC";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheShardKind {
    HotIntent,
    ReceiptArchive,
    LowFeeLane,
    OperatorMirror,
    BridgeSettlement,
    DefiNetting,
    WalletSync,
    ProofCarry,
}

impl CacheShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotIntent => "hot_intent",
            Self::ReceiptArchive => "receipt_archive",
            Self::LowFeeLane => "low_fee_lane",
            Self::OperatorMirror => "operator_mirror",
            Self::BridgeSettlement => "bridge_settlement",
            Self::DefiNetting => "defi_netting",
            Self::WalletSync => "wallet_sync",
            Self::ProofCarry => "proof_carry",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheShardStatus {
    Open,
    Hot,
    Throttled,
    Draining,
    Fenced,
    Suspended,
    Retired,
}

impl CacheShardStatus {
    pub fn accepts_pages(self) -> bool {
        matches!(self, Self::Open | Self::Hot | Self::Throttled)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Hot => "hot",
            Self::Throttled => "throttled",
            Self::Draining => "draining",
            Self::Fenced => "fenced",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptPageStatus {
    Allocated,
    Pinned,
    Readable,
    Sealed,
    Evictable,
    Evicted,
    Quarantined,
}

impl ReceiptPageStatus {
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Allocated | Self::Pinned | Self::Readable | Self::Sealed
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allocated => "allocated",
            Self::Pinned => "pinned",
            Self::Readable => "readable",
            Self::Sealed => "sealed",
            Self::Evictable => "evictable",
            Self::Evicted => "evicted",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentIndexKind {
    NullifierPrefix,
    CommitmentTag,
    ContractCall,
    WalletViewTag,
    BridgeOutput,
    DefiRoute,
    FeeCoupon,
    OperatorCursor,
}

impl IntentIndexKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NullifierPrefix => "nullifier_prefix",
            Self::CommitmentTag => "commitment_tag",
            Self::ContractCall => "contract_call",
            Self::WalletViewTag => "wallet_view_tag",
            Self::BridgeOutput => "bridge_output",
            Self::DefiRoute => "defi_route",
            Self::FeeCoupon => "fee_coupon",
            Self::OperatorCursor => "operator_cursor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Hold,
    Reject,
    Slash,
}

impl AttestationVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Hold => "hold",
            Self::Reject => "reject",
            Self::Slash => "slash",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceReason {
    ShardReorg,
    BadAttestation,
    ReceiptReplay,
    LeaseExpired,
    RedactionOverspend,
    OperatorRotation,
    PageCorruption,
}

impl FenceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShardReorg => "shard_reorg",
            Self::BadAttestation => "bad_attestation",
            Self::ReceiptReplay => "receipt_replay",
            Self::LeaseExpired => "lease_expired",
            Self::RedactionOverspend => "redaction_overspend",
            Self::OperatorRotation => "operator_rotation",
            Self::PageCorruption => "page_corruption",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrefetchLeaseStatus {
    Offered,
    Accepted,
    Warmed,
    Consumed,
    Expired,
    Revoked,
}

impl PrefetchLeaseStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Offered | Self::Accepted | Self::Warmed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Accepted => "accepted",
            Self::Warmed => "warmed",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Accruing,
    Claimable,
    Claimed,
    Expired,
    Slashed,
}

impl RebateStatus {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Accruing | Self::Claimable)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accruing => "accruing",
            Self::Claimable => "claimable",
            Self::Claimed => "claimed",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    PublicAggregate,
    OperatorSafe,
    WalletScoped,
    ContractScoped,
    FullyRedacted,
}

impl RedactionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicAggregate => "public_aggregate",
            Self::OperatorSafe => "operator_safe",
            Self::WalletScoped => "wallet_scoped",
            Self::ContractScoped => "contract_scoped",
            Self::FullyRedacted => "fully_redacted",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ShardOpened,
    PagePinned,
    IntentIndexed,
    AttestationVerified,
    FenceRaised,
    LeaseWarmed,
    RebateAccrued,
    RedactionCharged,
    SummaryPublished,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ShardOpened => "shard_opened",
            Self::PagePinned => "page_pinned",
            Self::IntentIndexed => "intent_indexed",
            Self::AttestationVerified => "attestation_verified",
            Self::FenceRaised => "fence_raised",
            Self::LeaseWarmed => "lease_warmed",
            Self::RebateAccrued => "rebate_accrued",
            Self::RedactionCharged => "redaction_charged",
            Self::SummaryPublished => "summary_published",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub mode: RuntimeMode,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub shard_count: u16,
    pub page_size_bytes: u32,
    pub max_pages_per_shard: u32,
    pub prefetch_lease_ttl_ms: u64,
    pub invalidation_fence_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub redaction_budget_units: u64,
    pub target_cache_hit_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub max_user_fee_micros: u64,
    pub operator_summary_window: u64,
    pub enable_zero_copy_pages: bool,
    pub enable_encrypted_intent_indexes: bool,
    pub enable_low_fee_rebates: bool,
    pub enable_operator_safe_public_summaries: bool,
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub cache_shards_opened: u64,
    pub receipt_pages_allocated: u64,
    pub receipt_pages_sealed: u64,
    pub zero_copy_reads: u64,
    pub zero_copy_bytes_served: u64,
    pub encrypted_intents_indexed: u64,
    pub pq_attestations_verified: u64,
    pub pq_attestations_rejected: u64,
    pub invalidation_fences_raised: u64,
    pub prefetch_leases_issued: u64,
    pub prefetch_leases_consumed: u64,
    pub low_fee_rebates_accrued: u64,
    pub low_fee_rebates_claimed: u64,
    pub redaction_budget_charged: u64,
    pub operator_summaries_published: u64,
    pub quarantined_pages: u64,
    pub evicted_pages: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub cache_shards_root: String,
    pub receipt_pages_root: String,
    pub encrypted_intent_indexes_root: String,
    pub pq_cache_attestations_root: String,
    pub invalidation_fences_root: String,
    pub prefetch_leases_root: String,
    pub low_fee_rebates_root: String,
    pub redaction_budgets_root: String,
    pub operator_summaries_root: String,
    pub event_log_root: String,
    pub public_log_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheShard {
    pub shard_id: String,
    pub shard_index: u16,
    pub kind: CacheShardKind,
    pub status: CacheShardStatus,
    pub operator_id: String,
    pub epoch: u64,
    pub opened_height: u64,
    pub page_count: u32,
    pub sealed_page_count: u32,
    pub resident_bytes: u64,
    pub hot_receipt_count: u64,
    pub cache_hit_bps: u64,
    pub page_root: String,
    pub intent_index_root: String,
    pub attestation_root: String,
    pub fence_root: String,
}

impl CacheShard {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:CACHESHARD",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReceiptPage {
    pub page_id: String,
    pub shard_id: String,
    pub shard_index: u16,
    pub page_number: u64,
    pub status: ReceiptPageStatus,
    pub base_receipt_sequence: u64,
    pub receipt_count: u32,
    pub page_size_bytes: u32,
    pub pinned_at_ms: u64,
    pub sealed_at_height: u64,
    pub zero_copy_region_id: String,
    pub ciphertext_commitment: String,
    pub receipt_commitment_root: String,
    pub redaction_root: String,
    pub lease_root: String,
    pub intent_index_keys: BTreeSet<String>,
}

impl ReceiptPage {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:RECEIPTPAGE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedIntentIndex {
    pub index_id: String,
    pub shard_id: String,
    pub page_id: String,
    pub kind: IntentIndexKind,
    pub encrypted_lookup_key: String,
    pub intent_ciphertext_root: String,
    pub receipt_pointer_commitment: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub pointer_count: u32,
    pub privacy_set_size: u64,
    pub pq_envelope_commitment: String,
    pub operator_visible: bool,
}

impl EncryptedIntentIndex {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:ENCRYPTEDINTENTINDEX",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqCacheAttestation {
    pub attestation_id: String,
    pub shard_id: String,
    pub page_id: String,
    pub operator_id: String,
    pub verdict: AttestationVerdict,
    pub height: u64,
    pub expires_height: u64,
    pub pq_security_bits: u16,
    pub attested_page_root: String,
    pub attested_index_root: String,
    pub ml_dsa_signature_commitment: String,
    pub slh_dsa_signature_commitment: String,
    pub transcript_root: String,
}

impl PqCacheAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:PQCACHEATTESTATION",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvalidationFence {
    pub fence_id: String,
    pub shard_id: String,
    pub page_id: Option<String>,
    pub reason: FenceReason,
    pub raised_height: u64,
    pub expires_height: u64,
    pub fenced_receipt_sequence: u64,
    pub evidence_root: String,
    pub replacement_root: String,
    pub operator_acknowledged: bool,
}

impl InvalidationFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:INVALIDATIONFENCE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrefetchLease {
    pub lease_id: String,
    pub shard_id: String,
    pub page_id: String,
    pub holder_commitment: String,
    pub status: PrefetchLeaseStatus,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub receipt_window_start: u64,
    pub receipt_window_end: u64,
    pub warmed_bytes: u64,
    pub fee_micros: u64,
    pub lease_secret_commitment: String,
    pub witness_hint_root: String,
}

impl PrefetchLease {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:PREFETCHLEASE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeCacheRebate {
    pub rebate_id: String,
    pub lease_id: String,
    pub shard_id: String,
    pub page_id: String,
    pub status: RebateStatus,
    pub accrued_micros: u64,
    pub claimed_micros: u64,
    pub eligible_receipts: u64,
    pub cache_hit_bps: u64,
    pub recipient_commitment: String,
    pub rebate_nullifier: String,
    pub claim_root: String,
}

impl LowFeeCacheRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:LOWFEECACHEREBATE",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub scope_id: String,
    pub redaction_class: RedactionClass,
    pub epoch: u64,
    pub allocated_units: u64,
    pub spent_units: u64,
    pub remaining_units: u64,
    pub min_privacy_set_size: u64,
    pub redaction_policy_root: String,
    pub audit_commitment: String,
    pub exhausted: bool,
}

impl RedactionBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:REDACTIONBUDGET",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub height: u64,
    pub epoch: u64,
    pub shard_count: u16,
    pub live_pages: u64,
    pub sealed_pages: u64,
    pub cache_hit_bps: u64,
    pub zero_copy_bytes_served: u64,
    pub low_fee_rebates_micros: u64,
    pub redaction_budget_remaining: u64,
    pub cache_shards_root: String,
    pub receipt_pages_root: String,
    pub attestation_root: String,
    pub fence_root: String,
    pub redacted: bool,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:OPERATORSUMMARY",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeEvent {
    pub event_id: String,
    pub kind: EventKind,
    pub height: u64,
    pub sequence: u64,
    pub subject_id: String,
    pub public_root: String,
    pub operator_safe: bool,
}

impl RuntimeEvent {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:RUNTIMEEVENT",
            &self.public_record(),
        )
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            mode: RuntimeMode::Devnet,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            shard_count: DEFAULT_SHARD_COUNT,
            page_size_bytes: DEFAULT_PAGE_SIZE_BYTES,
            max_pages_per_shard: DEFAULT_MAX_PAGES_PER_SHARD,
            prefetch_lease_ttl_ms: DEFAULT_PREFETCH_LEASE_TTL_MS,
            invalidation_fence_ttl_blocks: DEFAULT_INVALIDATION_FENCE_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            redaction_budget_units: DEFAULT_REDACTION_BUDGET_UNITS,
            target_cache_hit_bps: DEFAULT_TARGET_CACHE_HIT_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            max_user_fee_micros: DEFAULT_MAX_USER_FEE_MICROS,
            operator_summary_window: DEFAULT_OPERATOR_SUMMARY_WINDOW,
            enable_zero_copy_pages: true,
            enable_encrypted_intent_indexes: true,
            enable_low_fee_rebates: true,
            enable_operator_safe_public_summaries: true,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub cache_shards: BTreeMap<String, CacheShard>,
    pub receipt_pages: BTreeMap<String, ReceiptPage>,
    pub encrypted_intent_indexes: BTreeMap<String, EncryptedIntentIndex>,
    pub pq_cache_attestations: BTreeMap<String, PqCacheAttestation>,
    pub invalidation_fences: BTreeMap<String, InvalidationFence>,
    pub prefetch_leases: BTreeMap<String, PrefetchLease>,
    pub low_fee_cache_rebates: BTreeMap<String, LowFeeCacheRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub event_log: BTreeMap<String, RuntimeEvent>,
    pub public_log: BTreeMap<String, Value>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            cache_shards: BTreeMap::new(),
            receipt_pages: BTreeMap::new(),
            encrypted_intent_indexes: BTreeMap::new(),
            pq_cache_attestations: BTreeMap::new(),
            invalidation_fences: BTreeMap::new(),
            prefetch_leases: BTreeMap::new(),
            low_fee_cache_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            event_log: BTreeMap::new(),
            public_log: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        for shard_index in 0..state.config.shard_count {
            let kind = match shard_index % 8 {
                0 => CacheShardKind::HotIntent,
                1 => CacheShardKind::ReceiptArchive,
                2 => CacheShardKind::LowFeeLane,
                3 => CacheShardKind::OperatorMirror,
                4 => CacheShardKind::BridgeSettlement,
                5 => CacheShardKind::DefiNetting,
                6 => CacheShardKind::WalletSync,
                7 => CacheShardKind::ProofCarry,
                _ => CacheShardKind::ProofCarry,
            };
            let status = if shard_index % 11 == 0 {
                CacheShardStatus::Throttled
            } else {
                CacheShardStatus::Hot
            };
            let shard_id = format!("zc-shard-{shard_index:02}");
            let shard = CacheShard {
                shard_id: shard_id.clone(),
                shard_index,
                kind,
                status,
                operator_id: format!("operator-{}", shard_index % 4),
                epoch: DEVNET_EPOCH,
                opened_height: DEVNET_HEIGHT + shard_index as u64,
                page_count: 3,
                sealed_page_count: 2,
                resident_bytes: state.config.page_size_bytes as u64 * 3,
                hot_receipt_count: 768 + shard_index as u64 * 17,
                cache_hit_bps: 8_900 + shard_index as u64 * 11,
                page_root: dev_hash("shard-page-root", shard_index as u64),
                intent_index_root: dev_hash("shard-index-root", shard_index as u64),
                attestation_root: dev_hash("shard-attestation-root", shard_index as u64),
                fence_root: dev_hash("shard-fence-root", shard_index as u64),
            };
            state.cache_shards.insert(shard_id.clone(), shard);
            state.counters.cache_shards_opened += 1;
            for page_number in 0..3_u64 {
                let page_id = format!("{shard_id}:page-{page_number:04}");
                let status = if page_number == 2 {
                    ReceiptPageStatus::Pinned
                } else {
                    ReceiptPageStatus::Sealed
                };
                let mut keys = BTreeSet::new();
                keys.insert(format!("intent-key-{shard_index:02}-{page_number:04}-a"));
                keys.insert(format!("intent-key-{shard_index:02}-{page_number:04}-b"));
                let page = ReceiptPage {
                    page_id: page_id.clone(),
                    shard_id: shard_id.clone(),
                    shard_index,
                    page_number,
                    status,
                    base_receipt_sequence: 1_000_000
                        + shard_index as u64 * 10_000
                        + page_number * 512,
                    receipt_count: 512,
                    page_size_bytes: state.config.page_size_bytes,
                    pinned_at_ms: 1_720_000_000_000 + shard_index as u64 * 100 + page_number,
                    sealed_at_height: DEVNET_HEIGHT + shard_index as u64 + page_number,
                    zero_copy_region_id: format!("zcr-{shard_index:02}-{page_number:04}"),
                    ciphertext_commitment: dev_hash(
                        "page-ciphertext",
                        shard_index as u64 * 10 + page_number,
                    ),
                    receipt_commitment_root: dev_hash(
                        "page-receipt-root",
                        shard_index as u64 * 10 + page_number,
                    ),
                    redaction_root: dev_hash(
                        "page-redaction-root",
                        shard_index as u64 * 10 + page_number,
                    ),
                    lease_root: dev_hash("page-lease-root", shard_index as u64 * 10 + page_number),
                    intent_index_keys: keys,
                };
                state.receipt_pages.insert(page_id.clone(), page);
                state.counters.receipt_pages_allocated += 1;
                if status == ReceiptPageStatus::Sealed {
                    state.counters.receipt_pages_sealed += 1;
                }
                for kind_offset in 0..2_u64 {
                    let kind = if kind_offset == 0 {
                        IntentIndexKind::NullifierPrefix
                    } else {
                        IntentIndexKind::ContractCall
                    };
                    let index_id = format!("{page_id}:idx-{kind_offset}");
                    let index = EncryptedIntentIndex {
                        index_id: index_id.clone(),
                        shard_id: shard_id.clone(),
                        page_id: page_id.clone(),
                        kind,
                        encrypted_lookup_key: dev_hash(
                            "encrypted-lookup-key",
                            shard_index as u64 * 100 + page_number * 10 + kind_offset,
                        ),
                        intent_ciphertext_root: dev_hash(
                            "intent-ciphertext-root",
                            shard_index as u64 * 100 + page_number * 10 + kind_offset,
                        ),
                        receipt_pointer_commitment: dev_hash(
                            "receipt-pointer",
                            shard_index as u64 * 100 + page_number * 10 + kind_offset,
                        ),
                        first_sequence: 1_000_000 + shard_index as u64 * 10_000 + page_number * 512,
                        last_sequence: 1_000_000
                            + shard_index as u64 * 10_000
                            + page_number * 512
                            + 511,
                        pointer_count: 256,
                        privacy_set_size: state.config.min_privacy_set_size
                            + shard_index as u64 * 1024,
                        pq_envelope_commitment: dev_hash(
                            "pq-envelope",
                            shard_index as u64 * 100 + page_number * 10 + kind_offset,
                        ),
                        operator_visible: kind_offset == 1,
                    };
                    state.encrypted_intent_indexes.insert(index_id, index);
                    state.counters.encrypted_intents_indexed += 256;
                }
                let attestation_id = format!("{page_id}:attestation");
                let attestation = PqCacheAttestation {
                    attestation_id: attestation_id.clone(),
                    shard_id: shard_id.clone(),
                    page_id: page_id.clone(),
                    operator_id: format!("operator-{}", shard_index % 4),
                    verdict: AttestationVerdict::Accept,
                    height: DEVNET_HEIGHT + page_number,
                    expires_height: DEVNET_HEIGHT + page_number + 192,
                    pq_security_bits: state.config.min_pq_security_bits,
                    attested_page_root: dev_hash(
                        "attested-page",
                        shard_index as u64 * 10 + page_number,
                    ),
                    attested_index_root: dev_hash(
                        "attested-index",
                        shard_index as u64 * 10 + page_number,
                    ),
                    ml_dsa_signature_commitment: dev_hash(
                        "ml-dsa",
                        shard_index as u64 * 10 + page_number,
                    ),
                    slh_dsa_signature_commitment: dev_hash(
                        "slh-dsa",
                        shard_index as u64 * 10 + page_number,
                    ),
                    transcript_root: dev_hash(
                        "attestation-transcript",
                        shard_index as u64 * 10 + page_number,
                    ),
                };
                state
                    .pq_cache_attestations
                    .insert(attestation_id, attestation);
                state.counters.pq_attestations_verified += 1;
                let lease_id = format!("{page_id}:lease");
                let lease = PrefetchLease {
                    lease_id: lease_id.clone(),
                    shard_id: shard_id.clone(),
                    page_id: page_id.clone(),
                    holder_commitment: dev_hash(
                        "lease-holder",
                        shard_index as u64 * 10 + page_number,
                    ),
                    status: if page_number == 2 {
                        PrefetchLeaseStatus::Warmed
                    } else {
                        PrefetchLeaseStatus::Consumed
                    },
                    issued_at_ms: 1_720_000_000_000 + shard_index as u64 * 1_000 + page_number * 10,
                    expires_at_ms: 1_720_000_000_000
                        + shard_index as u64 * 1_000
                        + page_number * 10
                        + state.config.prefetch_lease_ttl_ms,
                    receipt_window_start: 1_000_000
                        + shard_index as u64 * 10_000
                        + page_number * 512,
                    receipt_window_end: 1_000_000
                        + shard_index as u64 * 10_000
                        + page_number * 512
                        + 511,
                    warmed_bytes: state.config.page_size_bytes as u64,
                    fee_micros: low_fee_for_cache_hit(
                        state.config.max_user_fee_micros,
                        state.config.low_fee_rebate_bps,
                    ),
                    lease_secret_commitment: dev_hash(
                        "lease-secret",
                        shard_index as u64 * 10 + page_number,
                    ),
                    witness_hint_root: dev_hash(
                        "lease-witness-hint",
                        shard_index as u64 * 10 + page_number,
                    ),
                };
                state.prefetch_leases.insert(lease_id.clone(), lease);
                state.counters.prefetch_leases_issued += 1;
                if page_number != 2 {
                    state.counters.prefetch_leases_consumed += 1;
                }
                let rebate_id = format!("{page_id}:rebate");
                let accrued =
                    state.config.max_user_fee_micros * 512 * state.config.low_fee_rebate_bps
                        / MAX_BPS;
                let rebate = LowFeeCacheRebate {
                    rebate_id: rebate_id.clone(),
                    lease_id,
                    shard_id: shard_id.clone(),
                    page_id: page_id.clone(),
                    status: if page_number == 2 {
                        RebateStatus::Accruing
                    } else {
                        RebateStatus::Claimable
                    },
                    accrued_micros: accrued,
                    claimed_micros: if page_number == 0 { accrued / 2 } else { 0 },
                    eligible_receipts: 512,
                    cache_hit_bps: 9_050 + shard_index as u64 * 9,
                    recipient_commitment: dev_hash(
                        "rebate-recipient",
                        shard_index as u64 * 10 + page_number,
                    ),
                    rebate_nullifier: dev_hash(
                        "rebate-nullifier",
                        shard_index as u64 * 10 + page_number,
                    ),
                    claim_root: dev_hash("rebate-claim", shard_index as u64 * 10 + page_number),
                };
                state.low_fee_cache_rebates.insert(rebate_id, rebate);
                state.counters.low_fee_rebates_accrued += accrued;
                state.counters.cache_hits += 498;
                state.counters.cache_misses += 14;
                state.counters.zero_copy_reads += 512;
                state.counters.zero_copy_bytes_served += state.config.page_size_bytes as u64;
            }
            let budget_id = format!("budget:{shard_id}");
            let spent = 4_000 + shard_index as u64 * 73;
            let budget = RedactionBudget {
                budget_id: budget_id.clone(),
                scope_id: shard_id.clone(),
                redaction_class: RedactionClass::OperatorSafe,
                epoch: DEVNET_EPOCH,
                allocated_units: state.config.redaction_budget_units,
                spent_units: spent,
                remaining_units: state.config.redaction_budget_units.saturating_sub(spent),
                min_privacy_set_size: state.config.min_privacy_set_size,
                redaction_policy_root: dev_hash("redaction-policy", shard_index as u64),
                audit_commitment: dev_hash("redaction-audit", shard_index as u64),
                exhausted: false,
            };
            state.redaction_budgets.insert(budget_id, budget);
            state.counters.redaction_budget_charged += spent;
            if shard_index % 7 == 0 {
                let fence_id = format!("fence:{shard_id}");
                let fence = InvalidationFence {
                    fence_id: fence_id.clone(),
                    shard_id: shard_id.clone(),
                    page_id: None,
                    reason: FenceReason::OperatorRotation,
                    raised_height: DEVNET_HEIGHT + shard_index as u64,
                    expires_height: DEVNET_HEIGHT
                        + shard_index as u64
                        + state.config.invalidation_fence_ttl_blocks,
                    fenced_receipt_sequence: 1_000_000 + shard_index as u64 * 10_000,
                    evidence_root: dev_hash("fence-evidence", shard_index as u64),
                    replacement_root: dev_hash("fence-replacement", shard_index as u64),
                    operator_acknowledged: true,
                };
                state.invalidation_fences.insert(fence_id, fence);
                state.counters.invalidation_fences_raised += 1;
            }
        }
        state.record_devnet_events();
        state.refresh_roots();
        state.record_operator_summary();
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "cache_shard_count": self.cache_shards.len(),
            "receipt_page_count": self.receipt_pages.len(),
            "encrypted_intent_index_count": self.encrypted_intent_indexes.len(),
            "pq_cache_attestation_count": self.pq_cache_attestations.len(),
            "invalidation_fence_count": self.invalidation_fences.len(),
            "prefetch_lease_count": self.prefetch_leases.len(),
            "low_fee_cache_rebate_count": self.low_fee_cache_rebates.len(),
            "redaction_budget_count": self.redaction_budgets.len(),
            "operator_summary_count": self.operator_summaries.len(),
            "event_count": self.event_log.len(),
            "public_log": self.public_log,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(D_STATE, &self.public_record())
    }

    pub fn refresh_roots(&mut self) {
        self.roots = Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            cache_shards_root: merkle_records(D_SHARDS, &self.cache_shards),
            receipt_pages_root: merkle_records(D_PAGES, &self.receipt_pages),
            encrypted_intent_indexes_root: merkle_records(
                D_INTENT_INDEXES,
                &self.encrypted_intent_indexes,
            ),
            pq_cache_attestations_root: merkle_records(D_ATTESTATIONS, &self.pq_cache_attestations),
            invalidation_fences_root: merkle_records(D_FENCES, &self.invalidation_fences),
            prefetch_leases_root: merkle_records(D_LEASES, &self.prefetch_leases),
            low_fee_rebates_root: merkle_records(D_REBATES, &self.low_fee_cache_rebates),
            redaction_budgets_root: merkle_records(D_REDACTIONS, &self.redaction_budgets),
            operator_summaries_root: merkle_records(D_SUMMARIES, &self.operator_summaries),
            event_log_root: merkle_records(D_EVENTS, &self.event_log),
            public_log_root: merkle_json_records(D_PUBLIC, &self.public_log),
        };
    }

    pub fn cache_hit_bps(&self) -> u64 {
        if self.counters.cache_hits + self.counters.cache_misses == 0 {
            0
        } else {
            self.counters.cache_hits * MAX_BPS
                / (self.counters.cache_hits + self.counters.cache_misses)
        }
    }

    pub fn live_page_count(&self) -> u64 {
        self.receipt_pages
            .values()
            .filter(|page| page.status.is_live())
            .count() as u64
    }

    pub fn sealed_page_count(&self) -> u64 {
        self.receipt_pages
            .values()
            .filter(|page| page.status == ReceiptPageStatus::Sealed)
            .count() as u64
    }

    pub fn total_rebate_micros(&self) -> u64 {
        self.low_fee_cache_rebates
            .values()
            .map(|rebate| rebate.accrued_micros)
            .sum()
    }

    pub fn redaction_budget_remaining(&self) -> u64 {
        self.redaction_budgets
            .values()
            .map(|budget| budget.remaining_units)
            .sum()
    }

    pub fn shard_public_summary(&self, shard_id: &str) -> Result<Value> {
        let shard = self
            .cache_shards
            .get(shard_id)
            .ok_or_else(|| format!("unknown shard {shard_id}"))?;
        let page_count = self
            .receipt_pages
            .values()
            .filter(|page| page.shard_id == shard_id)
            .count();
        let lease_count = self
            .prefetch_leases
            .values()
            .filter(|lease| lease.shard_id == shard_id)
            .count();
        Ok(json!({
            "shard_id": shard.shard_id,
            "kind": shard.kind.as_str(),
            "status": shard.status.as_str(),
            "operator_id": shard.operator_id,
            "page_count": page_count,
            "prefetch_lease_count": lease_count,
            "cache_hit_bps": shard.cache_hit_bps,
            "page_root": shard.page_root,
            "intent_index_root": shard.intent_index_root,
            "operator_safe": true,
        }))
    }

    fn record_devnet_events(&mut self) {
        let subjects = [
            (EventKind::ShardOpened, "zc-shard-00"),
            (EventKind::PagePinned, "zc-shard-00:page-0002"),
            (EventKind::IntentIndexed, "zc-shard-01:page-0000:idx-0"),
            (
                EventKind::AttestationVerified,
                "zc-shard-02:page-0001:attestation",
            ),
            (EventKind::FenceRaised, "fence:zc-shard-00"),
            (EventKind::LeaseWarmed, "zc-shard-03:page-0002:lease"),
            (EventKind::RebateAccrued, "zc-shard-04:page-0000:rebate"),
            (EventKind::RedactionCharged, "budget:zc-shard-05"),
        ];
        for (sequence, (kind, subject_id)) in subjects.into_iter().enumerate() {
            let event = RuntimeEvent {
                event_id: format!("event-{sequence:04}"),
                kind,
                height: DEVNET_HEIGHT + sequence as u64,
                sequence: sequence as u64,
                subject_id: subject_id.to_string(),
                public_root: dev_hash("event-public-root", sequence as u64),
                operator_safe: true,
            };
            self.event_log.insert(event.event_id.clone(), event);
        }
    }

    fn record_operator_summary(&mut self) {
        let summary = OperatorSummary {
            summary_id: "summary-devnet-zero-copy-intent-receipt-cache".to_string(),
            operator_id: "operator-set-devnet".to_string(),
            height: DEVNET_HEIGHT + self.counters.receipt_pages_sealed,
            epoch: DEVNET_EPOCH,
            shard_count: self.config.shard_count,
            live_pages: self.live_page_count(),
            sealed_pages: self.sealed_page_count(),
            cache_hit_bps: self.cache_hit_bps(),
            zero_copy_bytes_served: self.counters.zero_copy_bytes_served,
            low_fee_rebates_micros: self.total_rebate_micros(),
            redaction_budget_remaining: self.redaction_budget_remaining(),
            cache_shards_root: self.roots.cache_shards_root.clone(),
            receipt_pages_root: self.roots.receipt_pages_root.clone(),
            attestation_root: self.roots.pq_cache_attestations_root.clone(),
            fence_root: self.roots.invalidation_fences_root.clone(),
            redacted: true,
        };
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary.clone());
        self.counters.operator_summaries_published += 1;
        self.public_log
            .insert("operator:summary".to_string(), summary.public_record());
        self.public_log.insert(
            "operator:cache_health".to_string(),
            json!({
                "cache_hit_bps": self.cache_hit_bps(),
                "live_pages": self.live_page_count(),
                "sealed_pages": self.sealed_page_count(),
                "rebates_micros": self.total_rebate_micros(),
                "redaction_budget_remaining": self.redaction_budget_remaining(),
                "operator_safe": true,
            }),
        );
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

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

pub fn zero_copy_page_digest(record: &ReceiptPage) -> String {
    payload_root(ZERO_COPY_PAGE_SUITE, &record.public_record())
}

pub fn encrypted_intent_index_digest(record: &EncryptedIntentIndex) -> String {
    payload_root(ENCRYPTED_INTENT_INDEX_SUITE, &record.public_record())
}

pub fn pq_cache_attestation_digest(record: &PqCacheAttestation) -> String {
    payload_root(PQ_CACHE_ATTESTATION_SUITE, &record.public_record())
}

pub fn invalidation_fence_digest(record: &InvalidationFence) -> String {
    payload_root(INVALIDATION_FENCE_SUITE, &record.public_record())
}

pub fn prefetch_lease_digest(record: &PrefetchLease) -> String {
    payload_root(PREFETCH_LEASE_SUITE, &record.public_record())
}

pub fn low_fee_rebate_digest(record: &LowFeeCacheRebate) -> String {
    payload_root(LOW_FEE_CACHE_REBATE_SUITE, &record.public_record())
}

pub fn redaction_budget_digest(record: &RedactionBudget) -> String {
    payload_root(REDACTION_BUDGET_SUITE, &record.public_record())
}

pub fn operator_summary_digest(record: &OperatorSummary) -> String {
    payload_root(OPERATOR_SUMMARY_SUITE, &record.public_record())
}

fn low_fee_for_cache_hit(base_fee_micros: u64, rebate_bps: u64) -> u64 {
    base_fee_micros.saturating_mul(MAX_BPS.saturating_sub(rebate_bps)) / MAX_BPS
}

fn merkle_records<T: Serialize>(domain: &str, records: &BTreeMap<String, T>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_json_records(domain: &str, records: &BTreeMap<String, Value>) -> String {
    let leaves = records
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(value)],
        32,
    )
}

fn dev_hash(label: &str, index: u64) -> String {
    domain_hash(
        "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:DEVNET",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CacheTuningProfile {
    pub profile_id: String,
    pub lane: String,
    pub purpose: String,
    pub read_pattern: String,
    pub write_pattern: String,
    pub eviction_policy: String,
    pub redaction_policy: String,
    pub operator_policy: String,
    pub target_hit_bps: u64,
    pub max_lag_ms: u64,
    pub max_fee_micros: u64,
    pub rebate_bps: u64,
    pub prefetch_depth: u64,
    pub fence_sensitivity: u64,
    pub privacy_floor: u64,
    pub page_budget: u64,
}

impl CacheTuningProfile {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root(
            "PL2-FAST-PQ-CONF-ZC-INTENT-RECEIPT-CACHE:TUNING-PROFILE",
            &self.public_record(),
        )
    }
}

pub fn devnet_tuning_profiles() -> Vec<CacheTuningProfile> {
    vec![
        CacheTuningProfile {
            profile_id: "profile-00".to_string(),
            lane: "hot_intent".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 0".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8800,
            max_lag_ms: 40,
            max_fee_micros: 8,
            rebate_bps: 600,
            prefetch_depth: 4,
            fence_sensitivity: 1,
            privacy_floor: 262144,
            page_budget: 4096,
        },
        CacheTuningProfile {
            profile_id: "profile-01".to_string(),
            lane: "receipt_archive".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 1".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8807,
            max_lag_ms: 41,
            max_fee_micros: 9,
            rebate_bps: 601,
            prefetch_depth: 5,
            fence_sensitivity: 2,
            privacy_floor: 263168,
            page_budget: 4112,
        },
        CacheTuningProfile {
            profile_id: "profile-02".to_string(),
            lane: "low_fee_lane".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 2".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8814,
            max_lag_ms: 42,
            max_fee_micros: 10,
            rebate_bps: 602,
            prefetch_depth: 6,
            fence_sensitivity: 3,
            privacy_floor: 264192,
            page_budget: 4128,
        },
        CacheTuningProfile {
            profile_id: "profile-03".to_string(),
            lane: "operator_mirror".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 3".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8821,
            max_lag_ms: 43,
            max_fee_micros: 11,
            rebate_bps: 603,
            prefetch_depth: 7,
            fence_sensitivity: 4,
            privacy_floor: 265216,
            page_budget: 4144,
        },
        CacheTuningProfile {
            profile_id: "profile-04".to_string(),
            lane: "bridge_settlement".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 4".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8828,
            max_lag_ms: 44,
            max_fee_micros: 12,
            rebate_bps: 604,
            prefetch_depth: 8,
            fence_sensitivity: 1,
            privacy_floor: 266240,
            page_budget: 4160,
        },
        CacheTuningProfile {
            profile_id: "profile-05".to_string(),
            lane: "defi_netting".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 5".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8835,
            max_lag_ms: 45,
            max_fee_micros: 8,
            rebate_bps: 605,
            prefetch_depth: 9,
            fence_sensitivity: 2,
            privacy_floor: 267264,
            page_budget: 4176,
        },
        CacheTuningProfile {
            profile_id: "profile-06".to_string(),
            lane: "wallet_sync".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 6".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8842,
            max_lag_ms: 46,
            max_fee_micros: 9,
            rebate_bps: 606,
            prefetch_depth: 4,
            fence_sensitivity: 3,
            privacy_floor: 268288,
            page_budget: 4192,
        },
        CacheTuningProfile {
            profile_id: "profile-07".to_string(),
            lane: "proof_carry".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 7".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8849,
            max_lag_ms: 47,
            max_fee_micros: 10,
            rebate_bps: 607,
            prefetch_depth: 5,
            fence_sensitivity: 4,
            privacy_floor: 269312,
            page_budget: 4208,
        },
        CacheTuningProfile {
            profile_id: "profile-08".to_string(),
            lane: "hot_intent".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 8".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8856,
            max_lag_ms: 48,
            max_fee_micros: 11,
            rebate_bps: 608,
            prefetch_depth: 6,
            fence_sensitivity: 1,
            privacy_floor: 270336,
            page_budget: 4224,
        },
        CacheTuningProfile {
            profile_id: "profile-09".to_string(),
            lane: "receipt_archive".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 9".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8863,
            max_lag_ms: 40,
            max_fee_micros: 12,
            rebate_bps: 609,
            prefetch_depth: 7,
            fence_sensitivity: 2,
            privacy_floor: 271360,
            page_budget: 4240,
        },
        CacheTuningProfile {
            profile_id: "profile-10".to_string(),
            lane: "low_fee_lane".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 10".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8870,
            max_lag_ms: 41,
            max_fee_micros: 8,
            rebate_bps: 610,
            prefetch_depth: 8,
            fence_sensitivity: 3,
            privacy_floor: 272384,
            page_budget: 4256,
        },
        CacheTuningProfile {
            profile_id: "profile-11".to_string(),
            lane: "operator_mirror".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 11".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8877,
            max_lag_ms: 42,
            max_fee_micros: 9,
            rebate_bps: 611,
            prefetch_depth: 9,
            fence_sensitivity: 4,
            privacy_floor: 273408,
            page_budget: 4272,
        },
        CacheTuningProfile {
            profile_id: "profile-12".to_string(),
            lane: "bridge_settlement".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 12".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8884,
            max_lag_ms: 43,
            max_fee_micros: 10,
            rebate_bps: 612,
            prefetch_depth: 4,
            fence_sensitivity: 1,
            privacy_floor: 274432,
            page_budget: 4288,
        },
        CacheTuningProfile {
            profile_id: "profile-13".to_string(),
            lane: "defi_netting".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 13".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8891,
            max_lag_ms: 44,
            max_fee_micros: 11,
            rebate_bps: 600,
            prefetch_depth: 5,
            fence_sensitivity: 2,
            privacy_floor: 275456,
            page_budget: 4304,
        },
        CacheTuningProfile {
            profile_id: "profile-14".to_string(),
            lane: "wallet_sync".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 14".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8898,
            max_lag_ms: 45,
            max_fee_micros: 12,
            rebate_bps: 601,
            prefetch_depth: 6,
            fence_sensitivity: 3,
            privacy_floor: 276480,
            page_budget: 4320,
        },
        CacheTuningProfile {
            profile_id: "profile-15".to_string(),
            lane: "proof_carry".to_string(),
            purpose: "devnet zero-copy confidential receipt cache profile 15".to_string(),
            read_pattern: "bounded-zero-copy-scan".to_string(),
            write_pattern: "append-seal-prefetch".to_string(),
            eviction_policy: "attested-lru-with-fence-check".to_string(),
            redaction_policy: "operator-safe-aggregate-only".to_string(),
            operator_policy: "four-operator-rotating-summary".to_string(),
            target_hit_bps: 8905,
            max_lag_ms: 46,
            max_fee_micros: 8,
            rebate_bps: 602,
            prefetch_depth: 7,
            fence_sensitivity: 4,
            privacy_floor: 277504,
            page_budget: 4336,
        },
    ]
}
