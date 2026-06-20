use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingMembershipAgingOracleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RING_MEMBERSHIP_AGING_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ring-membership-aging-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RING_MEMBERSHIP_AGING_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_ORACLE_ID: &str = "monero-l2-pq-private-ring-membership-aging-oracle-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_DEFI_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_HEIGHT: u64 = 948_320;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-ring-membership-aging-oracle-v1";
pub const RING_AGE_BUCKET_SCHEME: &str = "monero-ring-member-age-bucket-root-v1";
pub const DECOY_FRESHNESS_SCHEME: &str = "private-decoy-freshness-root-v1";
pub const SUBADDRESS_COHORT_FLOOR_SCHEME: &str = "subaddress-cohort-privacy-floor-root-v1";
pub const WALLET_SCAN_HINT_SCHEME: &str = "sealed-wallet-scan-hint-root-v1";
pub const BRIDGE_WITHDRAWAL_DECOY_SCORE_SCHEME: &str = "bridge-withdrawal-decoy-scoring-root-v1";
pub const LOW_FEE_AGING_BATCH_SCHEME: &str = "low-fee-ring-aging-batch-update-root-v1";
pub const PRIVATE_TOKEN_RECEIPT_HINT_SCHEME: &str = "private-token-receipt-decoy-hint-root-v1";
pub const REDACTION_ROOT_SCHEME: &str = "ring-membership-aging-redaction-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "operator-safe-ring-aging-public-summary-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_BUCKET_SIZE: u64 = 65_536;
pub const DEFAULT_MIN_COHORT_SIZE: u64 = 32_768;
pub const DEFAULT_MIN_FRESH_DECOYS: u16 = 16;
pub const DEFAULT_MIN_BRIDGE_DECOYS: u16 = 64;
pub const DEFAULT_MIN_TOKEN_RECEIPT_DECOYS: u16 = 48;
pub const DEFAULT_MAX_SCAN_HINTS_PER_WALLET: u16 = 8;
pub const DEFAULT_TARGET_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_LOW_FEE_BPS: u64 = 3;
pub const DEFAULT_DEFI_FEE_BPS: u64 = 6;
pub const DEFAULT_FAST_FEE_BPS: u64 = 8;
pub const DEFAULT_BATCH_MAX_ITEMS: usize = 512;
pub const DEFAULT_FRESHNESS_HALF_LIFE_BLOCKS: u64 = 720;
pub const DEFAULT_STALE_AFTER_BLOCKS: u64 = 43_200;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 10_080;
pub const MAX_RING_AGE_BUCKETS: usize = 1_048_576;
pub const MAX_DECOY_FRESHNESS_ROOTS: usize = 1_048_576;
pub const MAX_SUBADDRESS_COHORT_FLOORS: usize = 524_288;
pub const MAX_WALLET_SCAN_HINTS: usize = 2_097_152;
pub const MAX_BRIDGE_WITHDRAWAL_DECOY_SCORES: usize = 1_048_576;
pub const MAX_PQ_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_LOW_FEE_BATCH_UPDATES: usize = 524_288;
pub const MAX_PRIVATE_TOKEN_RECEIPT_HINTS: usize = 1_048_576;
pub const MAX_REDACTION_ROOTS: usize = 524_288;
pub const MAX_PUBLIC_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeBucketKind {
    Fresh,
    Recent,
    Settled,
    Mature,
    DeepHistory,
    Archive,
}

impl AgeBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Recent => "recent",
            Self::Settled => "settled",
            Self::Mature => "mature",
            Self::DeepHistory => "deep_history",
            Self::Archive => "archive",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::Fresh => 920,
            Self::Recent => 980,
            Self::Settled => 1_000,
            Self::Mature => 940,
            Self::DeepHistory => 850,
            Self::Archive => 760,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleLane {
    LowFee,
    FastBridge,
    Defi,
    Contract,
    TokenReceipt,
    EmergencyRedaction,
}

impl OracleLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LowFee => "low_fee",
            Self::FastBridge => "fast_bridge",
            Self::Defi => "defi",
            Self::Contract => "contract",
            Self::TokenReceipt => "token_receipt",
            Self::EmergencyRedaction => "emergency_redaction",
        }
    }

    pub fn fee_bps(self, config: &Config) -> u64 {
        match self {
            Self::LowFee => config.low_fee_bps,
            Self::Defi | Self::Contract | Self::TokenReceipt => config.defi_fee_bps,
            Self::FastBridge | Self::EmergencyRedaction => config.fast_fee_bps,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HintAudience {
    Wallet,
    Bridge,
    Dex,
    LendingMarket,
    PrivateTokenContract,
    OperatorSummary,
}

impl HintAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Bridge => "bridge",
            Self::Dex => "dex",
            Self::LendingMarket => "lending_market",
            Self::PrivateTokenContract => "private_token_contract",
            Self::OperatorSummary => "operator_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    Draft,
    Submitted,
    Verified,
    Batched,
    Published,
    Redacted,
    Rejected,
    Expired,
}

impl RecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Batched => "batched",
            Self::Published => "published",
            Self::Redacted => "redacted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Verified | Self::Batched | Self::Published
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub oracle_id: String,
    pub fee_asset_id: String,
    pub defi_asset_id: String,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub min_bucket_size: u64,
    pub min_cohort_size: u64,
    pub min_fresh_decoys: u16,
    pub min_bridge_decoys: u16,
    pub min_token_receipt_decoys: u16,
    pub max_scan_hints_per_wallet: u16,
    pub target_pq_security_bits: u16,
    pub low_fee_bps: u64,
    pub defi_fee_bps: u64,
    pub fast_fee_bps: u64,
    pub batch_max_items: usize,
    pub freshness_half_life_blocks: u64,
    pub stale_after_blocks: u64,
    pub redaction_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            oracle_id: DEVNET_ORACLE_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            defi_asset_id: DEVNET_DEFI_ASSET_ID.to_string(),
            devnet_height: DEVNET_HEIGHT,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            min_bucket_size: DEFAULT_MIN_BUCKET_SIZE,
            min_cohort_size: DEFAULT_MIN_COHORT_SIZE,
            min_fresh_decoys: DEFAULT_MIN_FRESH_DECOYS,
            min_bridge_decoys: DEFAULT_MIN_BRIDGE_DECOYS,
            min_token_receipt_decoys: DEFAULT_MIN_TOKEN_RECEIPT_DECOYS,
            max_scan_hints_per_wallet: DEFAULT_MAX_SCAN_HINTS_PER_WALLET,
            target_pq_security_bits: DEFAULT_TARGET_PQ_SECURITY_BITS,
            low_fee_bps: DEFAULT_LOW_FEE_BPS,
            defi_fee_bps: DEFAULT_DEFI_FEE_BPS,
            fast_fee_bps: DEFAULT_FAST_FEE_BPS,
            batch_max_items: DEFAULT_BATCH_MAX_ITEMS,
            freshness_half_life_blocks: DEFAULT_FRESHNESS_HALF_LIFE_BLOCKS,
            stale_after_blocks: DEFAULT_STALE_AFTER_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub ring_age_buckets: usize,
    pub decoy_freshness_roots: usize,
    pub subaddress_cohort_floors: usize,
    pub wallet_scan_hints: usize,
    pub bridge_withdrawal_decoy_scores: usize,
    pub pq_oracle_attestations: usize,
    pub low_fee_batch_updates: usize,
    pub private_token_receipt_hints: usize,
    pub redaction_roots: usize,
    pub public_summaries: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub ring_age_bucket_root: String,
    pub decoy_freshness_root: String,
    pub subaddress_cohort_floor_root: String,
    pub wallet_scan_hint_root: String,
    pub bridge_withdrawal_decoy_score_root: String,
    pub pq_oracle_attestation_root: String,
    pub low_fee_batch_update_root: String,
    pub private_token_receipt_hint_root: String,
    pub redaction_root: String,
    pub public_summary_root: String,
    pub operator_safe_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingAgeBucketRequest {
    pub bucket_id: String,
    pub kind: AgeBucketKind,
    pub start_height: u64,
    pub end_height: u64,
    pub ring_member_count: u64,
    pub decoy_member_count: u64,
    pub output_commitment_root: String,
    pub age_distribution_root: String,
    pub cohort_floor_id: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RingAgeBucketRecord {
    pub bucket_id: String,
    pub sequence: u64,
    pub kind: AgeBucketKind,
    pub start_height: u64,
    pub end_height: u64,
    pub ring_member_count: u64,
    pub decoy_member_count: u64,
    pub output_commitment_root: String,
    pub age_distribution_root: String,
    pub cohort_floor_id: String,
    pub privacy_weight: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessRootRequest {
    pub freshness_id: String,
    pub bucket_id: String,
    pub anchor_height: u64,
    pub fresh_decoy_count: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub freshness_root: String,
    pub nullifier_guard_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyFreshnessRootRecord {
    pub freshness_id: String,
    pub sequence: u64,
    pub bucket_id: String,
    pub anchor_height: u64,
    pub fresh_decoy_count: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub freshness_root: String,
    pub nullifier_guard_root: String,
    pub freshness_score: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohortFloorRequest {
    pub floor_id: String,
    pub cohort_id: String,
    pub min_cohort_size: u64,
    pub min_ring_members: u64,
    pub min_fresh_decoys: u16,
    pub cohort_commitment_root: String,
    pub policy_root: String,
    pub allowed_audiences: BTreeSet<HintAudience>,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohortFloorRecord {
    pub floor_id: String,
    pub sequence: u64,
    pub cohort_id: String,
    pub min_cohort_size: u64,
    pub min_ring_members: u64,
    pub min_fresh_decoys: u16,
    pub cohort_commitment_root: String,
    pub policy_root: String,
    pub allowed_audiences: BTreeSet<HintAudience>,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHintRequest {
    pub hint_id: String,
    pub wallet_id: String,
    pub audience: HintAudience,
    pub start_height: u64,
    pub end_height: u64,
    pub sealed_hint_root: String,
    pub view_tag_hint_root: String,
    pub decoy_refresh_root: String,
    pub max_hints_in_window: u16,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WalletScanHintRecord {
    pub hint_id: String,
    pub sequence: u64,
    pub wallet_id: String,
    pub audience: HintAudience,
    pub start_height: u64,
    pub end_height: u64,
    pub sealed_hint_root: String,
    pub view_tag_hint_root: String,
    pub decoy_refresh_root: String,
    pub max_hints_in_window: u16,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeWithdrawalDecoyScoreRequest {
    pub score_id: String,
    pub withdrawal_id: String,
    pub bridge_id: String,
    pub bucket_id: String,
    pub ring_size: u16,
    pub fresh_decoy_count: u16,
    pub age_balance_score: u64,
    pub fee_quote_piconero: u64,
    pub score_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeWithdrawalDecoyScoreRecord {
    pub score_id: String,
    pub sequence: u64,
    pub withdrawal_id: String,
    pub bridge_id: String,
    pub bucket_id: String,
    pub ring_size: u16,
    pub fresh_decoy_count: u16,
    pub age_balance_score: u64,
    pub fee_quote_piconero: u64,
    pub score_root: String,
    pub low_fee_eligible: bool,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestationRequest {
    pub attestation_id: String,
    pub oracle_member_id: String,
    pub subject_id: String,
    pub lane: OracleLane,
    pub observed_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub committee_weight: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleAttestationRecord {
    pub attestation_id: String,
    pub sequence: u64,
    pub oracle_member_id: String,
    pub subject_id: String,
    pub lane: OracleLane,
    pub observed_root: String,
    pub pq_public_key_root: String,
    pub pq_signature_root: String,
    pub security_bits: u16,
    pub committee_weight: u64,
    pub fee_bps: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAgingBatchUpdateRequest {
    pub batch_id: String,
    pub aggregator_id: String,
    pub lane: OracleLane,
    pub bucket_ids: Vec<String>,
    pub freshness_ids: Vec<String>,
    pub scan_hint_ids: Vec<String>,
    pub batch_update_root: String,
    pub fee_sponsor_root: String,
    pub max_fee_piconero: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeAgingBatchUpdateRecord {
    pub batch_id: String,
    pub sequence: u64,
    pub aggregator_id: String,
    pub lane: OracleLane,
    pub bucket_ids: Vec<String>,
    pub freshness_ids: Vec<String>,
    pub scan_hint_ids: Vec<String>,
    pub batch_update_root: String,
    pub fee_sponsor_root: String,
    pub max_fee_piconero: u64,
    pub item_count: usize,
    pub fee_bps: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateTokenReceiptDecoyHintRequest {
    pub hint_id: String,
    pub token_contract_id: String,
    pub receipt_id: String,
    pub bucket_id: String,
    pub min_decoys: u16,
    pub receipt_hint_root: String,
    pub redacted_amount_class_root: String,
    pub contract_call_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateTokenReceiptDecoyHintRecord {
    pub hint_id: String,
    pub sequence: u64,
    pub token_contract_id: String,
    pub receipt_id: String,
    pub bucket_id: String,
    pub min_decoys: u16,
    pub receipt_hint_root: String,
    pub redacted_amount_class_root: String,
    pub contract_call_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionRootRequest {
    pub redaction_id: String,
    pub subject_id: String,
    pub reason_code: String,
    pub redacted_record_root: String,
    pub retained_public_fields_root: String,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionRootRecord {
    pub redaction_id: String,
    pub sequence: u64,
    pub subject_id: String,
    pub reason_code: String,
    pub redacted_record_root: String,
    pub retained_public_fields_root: String,
    pub expires_at_height: u64,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafePublicSummaryRequest {
    pub summary_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub active_bucket_count: u64,
    pub minimum_cohort_floor: u64,
    pub median_freshness_score: u64,
    pub low_fee_batch_count: u64,
    pub public_summary_root: String,
    pub suppressed_fields_root: String,
    pub status: RecordStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSafePublicSummaryRecord {
    pub summary_id: String,
    pub sequence: u64,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub active_bucket_count: u64,
    pub minimum_cohort_floor: u64,
    pub median_freshness_score: u64,
    pub low_fee_batch_count: u64,
    pub public_summary_root: String,
    pub suppressed_fields_root: String,
    pub status: RecordStatus,
}

macro_rules! impl_public_record {
    ($ty:ty, $domain:literal) => {
        impl $ty {
            pub fn public_record(&self) -> Value {
                json!(self)
            }

            pub fn digest(&self) -> String {
                stable_digest($domain, self.public_record())
            }
        }
    };
}

impl_public_record!(RingAgeBucketRequest, "RingAgeBucketRequest");
impl_public_record!(RingAgeBucketRecord, "RingAgeBucketRecord");
impl_public_record!(DecoyFreshnessRootRequest, "DecoyFreshnessRootRequest");
impl_public_record!(DecoyFreshnessRootRecord, "DecoyFreshnessRootRecord");
impl_public_record!(SubaddressCohortFloorRequest, "SubaddressCohortFloorRequest");
impl_public_record!(SubaddressCohortFloorRecord, "SubaddressCohortFloorRecord");
impl_public_record!(WalletScanHintRequest, "WalletScanHintRequest");
impl_public_record!(WalletScanHintRecord, "WalletScanHintRecord");
impl_public_record!(
    BridgeWithdrawalDecoyScoreRequest,
    "BridgeWithdrawalDecoyScoreRequest"
);
impl_public_record!(
    BridgeWithdrawalDecoyScoreRecord,
    "BridgeWithdrawalDecoyScoreRecord"
);
impl_public_record!(PqOracleAttestationRequest, "PqOracleAttestationRequest");
impl_public_record!(PqOracleAttestationRecord, "PqOracleAttestationRecord");
impl_public_record!(
    LowFeeAgingBatchUpdateRequest,
    "LowFeeAgingBatchUpdateRequest"
);
impl_public_record!(LowFeeAgingBatchUpdateRecord, "LowFeeAgingBatchUpdateRecord");
impl_public_record!(
    PrivateTokenReceiptDecoyHintRequest,
    "PrivateTokenReceiptDecoyHintRequest"
);
impl_public_record!(
    PrivateTokenReceiptDecoyHintRecord,
    "PrivateTokenReceiptDecoyHintRecord"
);
impl_public_record!(RedactionRootRequest, "RedactionRootRequest");
impl_public_record!(RedactionRootRecord, "RedactionRootRecord");
impl_public_record!(
    OperatorSafePublicSummaryRequest,
    "OperatorSafePublicSummaryRequest"
);
impl_public_record!(
    OperatorSafePublicSummaryRecord,
    "OperatorSafePublicSummaryRecord"
);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub ring_age_buckets: BTreeMap<String, RingAgeBucketRecord>,
    pub decoy_freshness_roots: BTreeMap<String, DecoyFreshnessRootRecord>,
    pub subaddress_cohort_floors: BTreeMap<String, SubaddressCohortFloorRecord>,
    pub wallet_scan_hints: BTreeMap<String, WalletScanHintRecord>,
    pub bridge_withdrawal_decoy_scores: BTreeMap<String, BridgeWithdrawalDecoyScoreRecord>,
    pub pq_oracle_attestations: BTreeMap<String, PqOracleAttestationRecord>,
    pub low_fee_batch_updates: BTreeMap<String, LowFeeAgingBatchUpdateRecord>,
    pub private_token_receipt_hints: BTreeMap<String, PrivateTokenReceiptDecoyHintRecord>,
    pub redaction_roots: BTreeMap<String, RedactionRootRecord>,
    pub public_summaries: BTreeMap<String, OperatorSafePublicSummaryRecord>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            roots: Roots::default(),
            ring_age_buckets: BTreeMap::new(),
            decoy_freshness_roots: BTreeMap::new(),
            subaddress_cohort_floors: BTreeMap::new(),
            wallet_scan_hints: BTreeMap::new(),
            bridge_withdrawal_decoy_scores: BTreeMap::new(),
            pq_oracle_attestations: BTreeMap::new(),
            low_fee_batch_updates: BTreeMap::new(),
            private_token_receipt_hints: BTreeMap::new(),
            redaction_roots: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        let mut audiences = BTreeSet::new();
        audiences.insert(HintAudience::Wallet);
        audiences.insert(HintAudience::Bridge);
        audiences.insert(HintAudience::PrivateTokenContract);

        state
            .record_subaddress_cohort_floor(SubaddressCohortFloorRequest {
                floor_id: "cohort-floor-devnet-0001".to_string(),
                cohort_id: "subaddr-cohort-pq-wallets-a".to_string(),
                min_cohort_size: 98_304,
                min_ring_members: 131_072,
                min_fresh_decoys: 24,
                cohort_commitment_root: demo_root("cohort-commitment", 1),
                policy_root: demo_root("cohort-policy", 1),
                allowed_audiences: audiences,
                status: RecordStatus::Verified,
            })
            .expect("demo cohort floor");
        state
            .record_ring_age_bucket(RingAgeBucketRequest {
                bucket_id: "ring-age-bucket-devnet-settled-0001".to_string(),
                kind: AgeBucketKind::Settled,
                start_height: DEVNET_HEIGHT - 4_320,
                end_height: DEVNET_HEIGHT - 720,
                ring_member_count: 262_144,
                decoy_member_count: 245_760,
                output_commitment_root: demo_root("output-commitments", 1),
                age_distribution_root: demo_root("age-distribution", 1),
                cohort_floor_id: "cohort-floor-devnet-0001".to_string(),
                status: RecordStatus::Verified,
            })
            .expect("demo age bucket");
        state
            .record_decoy_freshness_root(DecoyFreshnessRootRequest {
                freshness_id: "freshness-devnet-0001".to_string(),
                bucket_id: "ring-age-bucket-devnet-settled-0001".to_string(),
                anchor_height: DEVNET_HEIGHT,
                fresh_decoy_count: 52_224,
                median_age_blocks: 1_440,
                p95_age_blocks: 8_640,
                freshness_root: demo_root("freshness", 1),
                nullifier_guard_root: demo_root("freshness-nullifier-guard", 1),
                status: RecordStatus::Verified,
            })
            .expect("demo freshness");
        state
            .record_wallet_scan_hint(WalletScanHintRequest {
                hint_id: "wallet-scan-hint-devnet-0001".to_string(),
                wallet_id: "wallet-redacted-devnet-alpha".to_string(),
                audience: HintAudience::Wallet,
                start_height: DEVNET_HEIGHT - 1_024,
                end_height: DEVNET_HEIGHT,
                sealed_hint_root: demo_root("sealed-wallet-hint", 1),
                view_tag_hint_root: demo_root("view-tag-hint", 1),
                decoy_refresh_root: demo_root("decoy-refresh", 1),
                max_hints_in_window: 4,
                status: RecordStatus::Published,
            })
            .expect("demo wallet scan hint");
        state
            .record_bridge_withdrawal_decoy_score(BridgeWithdrawalDecoyScoreRequest {
                score_id: "bridge-decoy-score-devnet-0001".to_string(),
                withdrawal_id: "withdrawal-redacted-devnet-0001".to_string(),
                bridge_id: DEVNET_ORACLE_ID.to_string(),
                bucket_id: "ring-age-bucket-devnet-settled-0001".to_string(),
                ring_size: 96,
                fresh_decoy_count: 32,
                age_balance_score: 9_180,
                fee_quote_piconero: 1_200,
                score_root: demo_root("bridge-score", 1),
                status: RecordStatus::Verified,
            })
            .expect("demo bridge score");
        state
            .record_pq_oracle_attestation(PqOracleAttestationRequest {
                attestation_id: "pq-attestation-devnet-0001".to_string(),
                oracle_member_id: "oracle-member-devnet-ml-dsa-0001".to_string(),
                subject_id: "bridge-decoy-score-devnet-0001".to_string(),
                lane: OracleLane::FastBridge,
                observed_root: demo_root("observed-score", 1),
                pq_public_key_root: demo_root("pq-public-keys", 1),
                pq_signature_root: demo_root("pq-signatures", 1),
                security_bits: 256,
                committee_weight: 7,
                status: RecordStatus::Published,
            })
            .expect("demo pq attestation");
        state
            .record_low_fee_aging_batch_update(LowFeeAgingBatchUpdateRequest {
                batch_id: "low-fee-aging-batch-devnet-0001".to_string(),
                aggregator_id: "aging-aggregator-devnet-0001".to_string(),
                lane: OracleLane::LowFee,
                bucket_ids: vec!["ring-age-bucket-devnet-settled-0001".to_string()],
                freshness_ids: vec!["freshness-devnet-0001".to_string()],
                scan_hint_ids: vec!["wallet-scan-hint-devnet-0001".to_string()],
                batch_update_root: demo_root("low-fee-batch", 1),
                fee_sponsor_root: demo_root("fee-sponsor", 1),
                max_fee_piconero: 3_000,
                status: RecordStatus::Batched,
            })
            .expect("demo low fee batch");
        state
            .record_private_token_receipt_decoy_hint(PrivateTokenReceiptDecoyHintRequest {
                hint_id: "token-receipt-hint-devnet-0001".to_string(),
                token_contract_id: "private-token-contract-devnet-wxmr".to_string(),
                receipt_id: "receipt-redacted-devnet-0001".to_string(),
                bucket_id: "ring-age-bucket-devnet-settled-0001".to_string(),
                min_decoys: 64,
                receipt_hint_root: demo_root("token-receipt-hint", 1),
                redacted_amount_class_root: demo_root("redacted-amount-class", 1),
                contract_call_root: demo_root("contract-call", 1),
                status: RecordStatus::Verified,
            })
            .expect("demo token hint");
        state
            .record_redaction_root(RedactionRootRequest {
                redaction_id: "redaction-root-devnet-0001".to_string(),
                subject_id: "wallet-scan-hint-devnet-0001".to_string(),
                reason_code: "operator_safe_wallet_metadata_suppression".to_string(),
                redacted_record_root: demo_root("redacted-record", 1),
                retained_public_fields_root: demo_root("retained-public-fields", 1),
                expires_at_height: DEVNET_HEIGHT + DEFAULT_REDACTION_TTL_BLOCKS,
                status: RecordStatus::Published,
            })
            .expect("demo redaction");
        state
            .record_operator_safe_public_summary(OperatorSafePublicSummaryRequest {
                summary_id: "operator-summary-devnet-0001".to_string(),
                window_start_height: DEVNET_HEIGHT - 4_320,
                window_end_height: DEVNET_HEIGHT,
                active_bucket_count: 1,
                minimum_cohort_floor: 98_304,
                median_freshness_score: 9_375,
                low_fee_batch_count: 1,
                public_summary_root: demo_root("operator-summary", 1),
                suppressed_fields_root: demo_root("suppressed-fields", 1),
                status: RecordStatus::Published,
            })
            .expect("demo summary");
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "ring_age_buckets": self.ring_age_buckets.values().map(RingAgeBucketRecord::public_record).collect::<Vec<_>>(),
            "decoy_freshness_roots": self.decoy_freshness_roots.values().map(DecoyFreshnessRootRecord::public_record).collect::<Vec<_>>(),
            "subaddress_cohort_floors": self.subaddress_cohort_floors.values().map(SubaddressCohortFloorRecord::public_record).collect::<Vec<_>>(),
            "wallet_scan_hints": self.wallet_scan_hints.values().map(WalletScanHintRecord::public_record).collect::<Vec<_>>(),
            "bridge_withdrawal_decoy_scores": self.bridge_withdrawal_decoy_scores.values().map(BridgeWithdrawalDecoyScoreRecord::public_record).collect::<Vec<_>>(),
            "pq_oracle_attestations": self.pq_oracle_attestations.values().map(PqOracleAttestationRecord::public_record).collect::<Vec<_>>(),
            "low_fee_batch_updates": self.low_fee_batch_updates.values().map(LowFeeAgingBatchUpdateRecord::public_record).collect::<Vec<_>>(),
            "private_token_receipt_hints": self.private_token_receipt_hints.values().map(PrivateTokenReceiptDecoyHintRecord::public_record).collect::<Vec<_>>(),
            "redaction_roots": self.redaction_roots.values().map(RedactionRootRecord::public_record).collect::<Vec<_>>(),
            "public_summaries": self.public_summaries.values().map(OperatorSafePublicSummaryRecord::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn record_ring_age_bucket(
        &mut self,
        request: RingAgeBucketRequest,
    ) -> Result<RingAgeBucketRecord> {
        ensure_capacity(
            self.ring_age_buckets.len(),
            MAX_RING_AGE_BUCKETS,
            "ring age buckets",
        )?;
        ensure_range(request.start_height, request.end_height, "ring age bucket")?;
        if request.ring_member_count < self.config.min_bucket_size {
            return Err("ring age bucket below minimum privacy set size".to_string());
        }
        if request.decoy_member_count > request.ring_member_count {
            return Err("decoy member count exceeds ring member count".to_string());
        }
        let record = RingAgeBucketRecord {
            bucket_id: request.bucket_id,
            sequence: self.next_sequence(),
            kind: request.kind,
            start_height: request.start_height,
            end_height: request.end_height,
            ring_member_count: request.ring_member_count,
            decoy_member_count: request.decoy_member_count,
            output_commitment_root: request.output_commitment_root,
            age_distribution_root: request.age_distribution_root,
            cohort_floor_id: request.cohort_floor_id,
            privacy_weight: request.kind.privacy_weight(),
            status: request.status,
        };
        self.ring_age_buckets
            .insert(record.bucket_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_decoy_freshness_root(
        &mut self,
        request: DecoyFreshnessRootRequest,
    ) -> Result<DecoyFreshnessRootRecord> {
        ensure_capacity(
            self.decoy_freshness_roots.len(),
            MAX_DECOY_FRESHNESS_ROOTS,
            "decoy freshness roots",
        )?;
        if request.fresh_decoy_count < u64::from(self.config.min_fresh_decoys) {
            return Err("fresh decoy count below configured floor".to_string());
        }
        let freshness_score = freshness_score(
            request.median_age_blocks,
            request.p95_age_blocks,
            self.config.freshness_half_life_blocks,
            self.config.stale_after_blocks,
        );
        let record = DecoyFreshnessRootRecord {
            freshness_id: request.freshness_id,
            sequence: self.next_sequence(),
            bucket_id: request.bucket_id,
            anchor_height: request.anchor_height,
            fresh_decoy_count: request.fresh_decoy_count,
            median_age_blocks: request.median_age_blocks,
            p95_age_blocks: request.p95_age_blocks,
            freshness_root: request.freshness_root,
            nullifier_guard_root: request.nullifier_guard_root,
            freshness_score,
            status: request.status,
        };
        self.decoy_freshness_roots
            .insert(record.freshness_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_subaddress_cohort_floor(
        &mut self,
        request: SubaddressCohortFloorRequest,
    ) -> Result<SubaddressCohortFloorRecord> {
        ensure_capacity(
            self.subaddress_cohort_floors.len(),
            MAX_SUBADDRESS_COHORT_FLOORS,
            "subaddress cohort floors",
        )?;
        if request.min_cohort_size < self.config.min_cohort_size {
            return Err("subaddress cohort privacy floor below configured minimum".to_string());
        }
        let record = SubaddressCohortFloorRecord {
            floor_id: request.floor_id,
            sequence: self.next_sequence(),
            cohort_id: request.cohort_id,
            min_cohort_size: request.min_cohort_size,
            min_ring_members: request.min_ring_members,
            min_fresh_decoys: request.min_fresh_decoys,
            cohort_commitment_root: request.cohort_commitment_root,
            policy_root: request.policy_root,
            allowed_audiences: request.allowed_audiences,
            status: request.status,
        };
        self.subaddress_cohort_floors
            .insert(record.floor_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_wallet_scan_hint(
        &mut self,
        request: WalletScanHintRequest,
    ) -> Result<WalletScanHintRecord> {
        ensure_capacity(
            self.wallet_scan_hints.len(),
            MAX_WALLET_SCAN_HINTS,
            "wallet scan hints",
        )?;
        ensure_range(request.start_height, request.end_height, "wallet scan hint")?;
        if request.max_hints_in_window > self.config.max_scan_hints_per_wallet {
            return Err("wallet scan hint window exceeds privacy throttle".to_string());
        }
        let record = WalletScanHintRecord {
            hint_id: request.hint_id,
            sequence: self.next_sequence(),
            wallet_id: request.wallet_id,
            audience: request.audience,
            start_height: request.start_height,
            end_height: request.end_height,
            sealed_hint_root: request.sealed_hint_root,
            view_tag_hint_root: request.view_tag_hint_root,
            decoy_refresh_root: request.decoy_refresh_root,
            max_hints_in_window: request.max_hints_in_window,
            status: request.status,
        };
        self.wallet_scan_hints
            .insert(record.hint_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_bridge_withdrawal_decoy_score(
        &mut self,
        request: BridgeWithdrawalDecoyScoreRequest,
    ) -> Result<BridgeWithdrawalDecoyScoreRecord> {
        ensure_capacity(
            self.bridge_withdrawal_decoy_scores.len(),
            MAX_BRIDGE_WITHDRAWAL_DECOY_SCORES,
            "bridge withdrawal decoy scores",
        )?;
        if request.ring_size < self.config.min_bridge_decoys {
            return Err("bridge withdrawal ring size below decoy floor".to_string());
        }
        let low_fee_eligible = request.age_balance_score >= 8_000
            && request.fresh_decoy_count >= self.config.min_fresh_decoys;
        let record = BridgeWithdrawalDecoyScoreRecord {
            score_id: request.score_id,
            sequence: self.next_sequence(),
            withdrawal_id: request.withdrawal_id,
            bridge_id: request.bridge_id,
            bucket_id: request.bucket_id,
            ring_size: request.ring_size,
            fresh_decoy_count: request.fresh_decoy_count,
            age_balance_score: request.age_balance_score.min(MAX_BPS),
            fee_quote_piconero: request.fee_quote_piconero,
            score_root: request.score_root,
            low_fee_eligible,
            status: request.status,
        };
        self.bridge_withdrawal_decoy_scores
            .insert(record.score_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_pq_oracle_attestation(
        &mut self,
        request: PqOracleAttestationRequest,
    ) -> Result<PqOracleAttestationRecord> {
        ensure_capacity(
            self.pq_oracle_attestations.len(),
            MAX_PQ_ORACLE_ATTESTATIONS,
            "pq oracle attestations",
        )?;
        if request.security_bits < self.config.target_pq_security_bits {
            return Err("pq oracle attestation below target security bits".to_string());
        }
        let record = PqOracleAttestationRecord {
            attestation_id: request.attestation_id,
            sequence: self.next_sequence(),
            oracle_member_id: request.oracle_member_id,
            subject_id: request.subject_id,
            lane: request.lane,
            observed_root: request.observed_root,
            pq_public_key_root: request.pq_public_key_root,
            pq_signature_root: request.pq_signature_root,
            security_bits: request.security_bits,
            committee_weight: request.committee_weight,
            fee_bps: request.lane.fee_bps(&self.config),
            status: request.status,
        };
        self.pq_oracle_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_low_fee_aging_batch_update(
        &mut self,
        request: LowFeeAgingBatchUpdateRequest,
    ) -> Result<LowFeeAgingBatchUpdateRecord> {
        ensure_capacity(
            self.low_fee_batch_updates.len(),
            MAX_LOW_FEE_BATCH_UPDATES,
            "low fee aging batch updates",
        )?;
        let item_count =
            request.bucket_ids.len() + request.freshness_ids.len() + request.scan_hint_ids.len();
        if item_count == 0 || item_count > self.config.batch_max_items {
            return Err("low fee aging batch item count outside configured bounds".to_string());
        }
        let record = LowFeeAgingBatchUpdateRecord {
            batch_id: request.batch_id,
            sequence: self.next_sequence(),
            aggregator_id: request.aggregator_id,
            lane: request.lane,
            bucket_ids: sorted_vec(request.bucket_ids),
            freshness_ids: sorted_vec(request.freshness_ids),
            scan_hint_ids: sorted_vec(request.scan_hint_ids),
            batch_update_root: request.batch_update_root,
            fee_sponsor_root: request.fee_sponsor_root,
            max_fee_piconero: request.max_fee_piconero,
            item_count,
            fee_bps: request.lane.fee_bps(&self.config),
            status: request.status,
        };
        self.low_fee_batch_updates
            .insert(record.batch_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_private_token_receipt_decoy_hint(
        &mut self,
        request: PrivateTokenReceiptDecoyHintRequest,
    ) -> Result<PrivateTokenReceiptDecoyHintRecord> {
        ensure_capacity(
            self.private_token_receipt_hints.len(),
            MAX_PRIVATE_TOKEN_RECEIPT_HINTS,
            "private token receipt decoy hints",
        )?;
        if request.min_decoys < self.config.min_token_receipt_decoys {
            return Err("private token receipt hint below decoy floor".to_string());
        }
        let record = PrivateTokenReceiptDecoyHintRecord {
            hint_id: request.hint_id,
            sequence: self.next_sequence(),
            token_contract_id: request.token_contract_id,
            receipt_id: request.receipt_id,
            bucket_id: request.bucket_id,
            min_decoys: request.min_decoys,
            receipt_hint_root: request.receipt_hint_root,
            redacted_amount_class_root: request.redacted_amount_class_root,
            contract_call_root: request.contract_call_root,
            status: request.status,
        };
        self.private_token_receipt_hints
            .insert(record.hint_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_redaction_root(
        &mut self,
        request: RedactionRootRequest,
    ) -> Result<RedactionRootRecord> {
        ensure_capacity(
            self.redaction_roots.len(),
            MAX_REDACTION_ROOTS,
            "redaction roots",
        )?;
        if request.expires_at_height <= self.config.devnet_height {
            return Err("redaction root expiry must be in the future".to_string());
        }
        let record = RedactionRootRecord {
            redaction_id: request.redaction_id,
            sequence: self.next_sequence(),
            subject_id: request.subject_id,
            reason_code: request.reason_code,
            redacted_record_root: request.redacted_record_root,
            retained_public_fields_root: request.retained_public_fields_root,
            expires_at_height: request.expires_at_height,
            status: request.status,
        };
        self.redaction_roots
            .insert(record.redaction_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_operator_safe_public_summary(
        &mut self,
        request: OperatorSafePublicSummaryRequest,
    ) -> Result<OperatorSafePublicSummaryRecord> {
        ensure_capacity(
            self.public_summaries.len(),
            MAX_PUBLIC_SUMMARIES,
            "operator safe public summaries",
        )?;
        ensure_range(
            request.window_start_height,
            request.window_end_height,
            "operator safe public summary",
        )?;
        let record = OperatorSafePublicSummaryRecord {
            summary_id: request.summary_id,
            sequence: self.next_sequence(),
            window_start_height: request.window_start_height,
            window_end_height: request.window_end_height,
            active_bucket_count: request.active_bucket_count,
            minimum_cohort_floor: request.minimum_cohort_floor,
            median_freshness_score: request.median_freshness_score.min(MAX_BPS),
            low_fee_batch_count: request.low_fee_batch_count,
            public_summary_root: request.public_summary_root,
            suppressed_fields_root: request.suppressed_fields_root,
            status: request.status,
        };
        self.public_summaries
            .insert(record.summary_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn operator_safe_summary(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "oracle_id": self.config.oracle_id,
            "devnet_height": self.config.devnet_height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
            "active_ring_age_buckets": self.ring_age_buckets.values().filter(|record| record.status.usable()).count(),
            "published_scan_hint_windows": self.wallet_scan_hints.values().filter(|record| record.status == RecordStatus::Published).count(),
            "low_fee_batches": self.low_fee_batch_updates.len(),
            "redactions": self.redaction_roots.len(),
        })
    }

    pub fn refresh_roots(&mut self) {
        self.counters.ring_age_buckets = self.ring_age_buckets.len();
        self.counters.decoy_freshness_roots = self.decoy_freshness_roots.len();
        self.counters.subaddress_cohort_floors = self.subaddress_cohort_floors.len();
        self.counters.wallet_scan_hints = self.wallet_scan_hints.len();
        self.counters.bridge_withdrawal_decoy_scores = self.bridge_withdrawal_decoy_scores.len();
        self.counters.pq_oracle_attestations = self.pq_oracle_attestations.len();
        self.counters.low_fee_batch_updates = self.low_fee_batch_updates.len();
        self.counters.private_token_receipt_hints = self.private_token_receipt_hints.len();
        self.counters.redaction_roots = self.redaction_roots.len();
        self.counters.public_summaries = self.public_summaries.len();

        self.roots.ring_age_bucket_root = records_root(
            "ring_age_buckets",
            self.ring_age_buckets
                .values()
                .map(RingAgeBucketRecord::public_record),
        );
        self.roots.decoy_freshness_root = records_root(
            "decoy_freshness_roots",
            self.decoy_freshness_roots
                .values()
                .map(DecoyFreshnessRootRecord::public_record),
        );
        self.roots.subaddress_cohort_floor_root = records_root(
            "subaddress_cohort_floors",
            self.subaddress_cohort_floors
                .values()
                .map(SubaddressCohortFloorRecord::public_record),
        );
        self.roots.wallet_scan_hint_root = records_root(
            "wallet_scan_hints",
            self.wallet_scan_hints
                .values()
                .map(WalletScanHintRecord::public_record),
        );
        self.roots.bridge_withdrawal_decoy_score_root = records_root(
            "bridge_withdrawal_decoy_scores",
            self.bridge_withdrawal_decoy_scores
                .values()
                .map(BridgeWithdrawalDecoyScoreRecord::public_record),
        );
        self.roots.pq_oracle_attestation_root = records_root(
            "pq_oracle_attestations",
            self.pq_oracle_attestations
                .values()
                .map(PqOracleAttestationRecord::public_record),
        );
        self.roots.low_fee_batch_update_root = records_root(
            "low_fee_batch_updates",
            self.low_fee_batch_updates
                .values()
                .map(LowFeeAgingBatchUpdateRecord::public_record),
        );
        self.roots.private_token_receipt_hint_root = records_root(
            "private_token_receipt_hints",
            self.private_token_receipt_hints
                .values()
                .map(PrivateTokenReceiptDecoyHintRecord::public_record),
        );
        self.roots.redaction_root = records_root(
            "redaction_roots",
            self.redaction_roots
                .values()
                .map(RedactionRootRecord::public_record),
        );
        self.roots.public_summary_root = records_root(
            "public_summaries",
            self.public_summaries
                .values()
                .map(OperatorSafePublicSummaryRecord::public_record),
        );
        self.roots.operator_safe_index_root = stable_digest(
            PUBLIC_SUMMARY_SCHEME,
            json!({
                "root": self.roots.public_summary_root,
                "redaction_root": self.roots.redaction_root,
                "summary_count": self.public_summaries.len(),
            }),
        );
        self.roots.state_root = records_root(
            "state",
            [
                self.config.public_record(),
                self.counters.public_record(),
                self.roots_without_state_root(),
            ],
        );
    }

    fn next_sequence(&mut self) -> u64 {
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.next_sequence
    }

    fn roots_without_state_root(&self) -> Value {
        json!({
            "ring_age_bucket_root": self.roots.ring_age_bucket_root,
            "decoy_freshness_root": self.roots.decoy_freshness_root,
            "subaddress_cohort_floor_root": self.roots.subaddress_cohort_floor_root,
            "wallet_scan_hint_root": self.roots.wallet_scan_hint_root,
            "bridge_withdrawal_decoy_score_root": self.roots.bridge_withdrawal_decoy_score_root,
            "pq_oracle_attestation_root": self.roots.pq_oracle_attestation_root,
            "low_fee_batch_update_root": self.roots.low_fee_batch_update_root,
            "private_token_receipt_hint_root": self.roots.private_token_receipt_hint_root,
            "redaction_root": self.roots.redaction_root,
            "public_summary_root": self.roots.public_summary_root,
            "operator_safe_index_root": self.roots.operator_safe_index_root,
        })
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn records_root(domain: &str, records: impl IntoIterator<Item = Value>) -> String {
    let values = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &values)
}

pub fn ring_age_bucket_id(sequence: u64, request: &RingAgeBucketRequest) -> String {
    root_from_parts(
        "RING-AGE-BUCKET-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(request.kind.as_str()),
            HashPart::U64(request.start_height),
            HashPart::U64(request.end_height),
            HashPart::Str(&request.output_commitment_root),
        ],
    )
}

pub fn decoy_freshness_id(sequence: u64, request: &DecoyFreshnessRootRequest) -> String {
    root_from_parts(
        "DECOY-FRESHNESS-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.bucket_id),
            HashPart::U64(request.anchor_height),
            HashPart::Str(&request.freshness_root),
            HashPart::Str(&request.nullifier_guard_root),
        ],
    )
}

pub fn pq_attestation_id(sequence: u64, request: &PqOracleAttestationRequest) -> String {
    root_from_parts(
        "PQ-RING-AGING-ORACLE-ATTESTATION-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.oracle_member_id),
            HashPart::Str(&request.subject_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.observed_root),
            HashPart::Str(&request.pq_signature_root),
        ],
    )
}

pub fn low_fee_batch_id(sequence: u64, request: &LowFeeAgingBatchUpdateRequest) -> String {
    let buckets = json!(request.bucket_ids);
    let freshness = json!(request.freshness_ids);
    let hints = json!(request.scan_hint_ids);
    root_from_parts(
        "LOW-FEE-RING-AGING-BATCH-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.aggregator_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Json(&buckets),
            HashPart::Json(&freshness),
            HashPart::Json(&hints),
            HashPart::Str(&request.batch_update_root),
        ],
    )
}

pub fn deterministic_devnet_root(label: &str, index: u64) -> String {
    demo_root(label, index)
}

fn stable_digest(domain: &str, value: Value) -> String {
    let encoded = serde_json::to_string(&value).unwrap_or_else(|_| "null".to_string());
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Str(&encoded),
        ],
        32,
    )
}

fn demo_root(label: &str, index: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-RING-AGING-DEMO-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(DEVNET_ORACLE_ID),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
        32,
    )
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_range(start_height: u64, end_height: u64, label: &str) -> Result<()> {
    if start_height > end_height {
        Err(format!("{label} start height exceeds end height"))
    } else {
        Ok(())
    }
}

fn freshness_score(median_age: u64, p95_age: u64, half_life: u64, stale_after: u64) -> u64 {
    if p95_age >= stale_after {
        return 0;
    }
    let median_component =
        MAX_BPS.saturating_sub(median_age.saturating_mul(MAX_BPS) / half_life.max(1));
    let tail_component =
        MAX_BPS.saturating_sub(p95_age.saturating_mul(MAX_BPS) / stale_after.max(1));
    ((median_component.saturating_mul(6) + tail_component.saturating_mul(4)) / 10).min(MAX_BPS)
}

fn sorted_vec(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}
