use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-low-fee-confidential-state-rent-compression-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-state-rent-v1";
pub const COMPRESSION_SUITE: &str = "pq-private-state-diff-recursive-rent-compression-v1";
pub const STORAGE_PROOF_SUITE: &str = "recursive-storage-proof-batch-v1";
pub const PRIVACY_ACCOUNTING_SUITE: &str = "view-key-minimized-budget-ledger-v1";
pub const DEVNET_HEIGHT: u64 = 1_246_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_ANONYMITY_SET: u64 = 8_192;
pub const DEFAULT_BATCH_ANONYMITY_SET: u64 = 65_536;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 12;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_COMPRESSION_REWARD_BPS: u64 = 7_200;
pub const DEFAULT_STORAGE_COUPON_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_BUCKET_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_DIFF_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_PROOF_BATCH_TTL_BLOCKS: u64 = 128;
pub const DEFAULT_EVICTION_GRACE_BLOCKS: u64 = 2_880;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_BUCKETS: usize = 524_288;
pub const DEFAULT_MAX_DIFFS: usize = 2_097_152;
pub const DEFAULT_MAX_COUPONS: usize = 2_097_152;
pub const DEFAULT_MAX_PROOF_BATCHES: usize = 1_048_576;
pub const DEFAULT_MAX_EVICTION_RECEIPTS: usize = 1_048_576;
pub const DEFAULT_MAX_SPONSOR_BIDS: usize = 2_097_152;
pub const DEFAULT_MAX_PRIVACY_BUDGETS: usize = 2_097_152;
pub const DEFAULT_MAX_REBATES: usize = 2_097_152;
pub const DEFAULT_MAX_CHALLENGES: usize = 1_048_576;

macro_rules! ensure {
    ($condition:expr, $message:expr) => {
        if !$condition {
            return Err($message.to_string());
        }
    };
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    ContractHot,
    ContractWarm,
    ContractCold,
    DefiPool,
    LendingVault,
    PerpMargin,
    OracleCache,
    BridgeExit,
    AccountSession,
    RuntimeCheckpoint,
}

impl StorageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractHot => "contract_hot",
            Self::ContractWarm => "contract_warm",
            Self::ContractCold => "contract_cold",
            Self::DefiPool => "defi_pool",
            Self::LendingVault => "lending_vault",
            Self::PerpMargin => "perp_margin",
            Self::OracleCache => "oracle_cache",
            Self::BridgeExit => "bridge_exit",
            Self::AccountSession => "account_session",
            Self::RuntimeCheckpoint => "runtime_checkpoint",
        }
    }
}
impl StorageClass {
    pub fn priority_weight(self) -> u64 {
        match self {
            Self::BridgeExit => 10_000,
            Self::PerpMargin => 9_600,
            Self::DefiPool => 9_300,
            Self::LendingVault => 9_000,
            Self::ContractHot => 8_800,
            Self::OracleCache => 8_300,
            Self::AccountSession => 7_900,
            Self::ContractWarm => 7_600,
            Self::ContractCold => 6_800,
            Self::RuntimeCheckpoint => 6_400,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Proposed,
    Open,
    Sealed,
    Proving,
    RentPaid,
    Evictable,
    Evicted,
    Restored,
    Challenged,
    Slashed,
}

impl BucketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Proving => "proving",
            Self::RentPaid => "rent_paid",
            Self::Evictable => "evictable",
            Self::Evicted => "evicted",
            Self::Restored => "restored",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}
impl BucketStatus {
    pub fn accepts_diffs(self) -> bool {
        matches!(self, Self::Open | Self::RentPaid | Self::Restored)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    SparseMerkleDelta,
    ContractSlotSquash,
    AccessListPrune,
    CiphertextChunkPack,
    WitnessRangeFold,
    EventLogElide,
    RecursiveCheckpoint,
    DefiNettingDelta,
}

impl DiffKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SparseMerkleDelta => "sparse_merkle_delta",
            Self::ContractSlotSquash => "contract_slot_squash",
            Self::AccessListPrune => "access_list_prune",
            Self::CiphertextChunkPack => "ciphertext_chunk_pack",
            Self::WitnessRangeFold => "witness_range_fold",
            Self::EventLogElide => "event_log_elide",
            Self::RecursiveCheckpoint => "recursive_checkpoint",
            Self::DefiNettingDelta => "defi_netting_delta",
        }
    }
}
impl DiffKind {
    pub fn compression_weight_bps(self) -> u64 {
        match self {
            Self::RecursiveCheckpoint => 9_800,
            Self::ContractSlotSquash => 9_300,
            Self::SparseMerkleDelta => 9_000,
            Self::DefiNettingDelta => 8_700,
            Self::AccessListPrune => 8_300,
            Self::WitnessRangeFold => 8_000,
            Self::CiphertextChunkPack => 7_600,
            Self::EventLogElide => 7_300,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffStatus {
    Submitted,
    CouponLinked,
    Sponsored,
    ProofQueued,
    Batched,
    Settled,
    Rebated,
    Rejected,
    Expired,
    Challenged,
}

impl DiffStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CouponLinked => "coupon_linked",
            Self::Sponsored => "sponsored",
            Self::ProofQueued => "proof_queued",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}
impl DiffStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted
                | Self::CouponLinked
                | Self::Sponsored
                | Self::ProofQueued
                | Self::Batched
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Reserved,
    Applied,
    Settled,
    Rebated,
    Expired,
    Revoked,
    Slashed,
}

impl CouponStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }
}
impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Issued | Self::Reserved)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofBatchStatus {
    Proposed,
    Collecting,
    RecursiveFolded,
    Verified,
    Settled,
    Failed,
    Challenged,
    Slashed,
}

impl ProofBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Collecting => "collecting",
            Self::RecursiveFolded => "recursive_folded",
            Self::Verified => "verified",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Challenged => "challenged",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvictionStatus {
    Requested,
    GracePeriod,
    Evicted,
    RestorePending,
    Restored,
    Disputed,
    Reversed,
    Slashed,
}

impl EvictionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::GracePeriod => "grace_period",
            Self::Evicted => "evicted",
            Self::RestorePending => "restore_pending",
            Self::Restored => "restored",
            Self::Disputed => "disputed",
            Self::Reversed => "reversed",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorBidStatus {
    Posted,
    Matched,
    Reserved,
    Consumed,
    Refunded,
    Expired,
    Slashed,
}

impl SponsorBidStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Posted => "posted",
            Self::Matched => "matched",
            Self::Reserved => "reserved",
            Self::Consumed => "consumed",
            Self::Refunded => "refunded",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetStatus {
    Active,
    Throttled,
    Exhausted,
    Refilled,
    Frozen,
    Slashed,
}

impl PrivacyBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Throttled => "throttled",
            Self::Exhausted => "exhausted",
            Self::Refilled => "refilled",
            Self::Frozen => "frozen",
            Self::Slashed => "slashed",
        }
    }
}
impl PrivacyBudgetStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::Refilled)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Queued,
    Approved,
    Paid,
    Netted,
    Expired,
    Revoked,
    Slashed,
}

impl RebateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Approved => "approved",
            Self::Paid => "paid",
            Self::Netted => "netted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Slashed => "slashed",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Filed,
    EvidenceLocked,
    Accepted,
    Rejected,
    Slashed,
    Withdrawn,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Filed => "filed",
            Self::EvidenceLocked => "evidence_locked",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
        }
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set: u64,
    pub batch_anonymity_set: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub compression_reward_bps: u64,
    pub storage_coupon_ttl_blocks: u64,
    pub bucket_ttl_blocks: u64,
    pub diff_ttl_blocks: u64,
    pub proof_batch_ttl_blocks: u64,
    pub eviction_grace_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_buckets: usize,
    pub max_diffs: usize,
    pub max_coupons: usize,
    pub max_proof_batches: usize,
    pub max_eviction_receipts: usize,
    pub max_sponsor_bids: usize,
    pub max_privacy_budgets: usize,
    pub max_rebates: usize,
    pub max_challenges: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set: DEFAULT_MIN_ANONYMITY_SET,
            batch_anonymity_set: DEFAULT_BATCH_ANONYMITY_SET,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            compression_reward_bps: DEFAULT_COMPRESSION_REWARD_BPS,
            storage_coupon_ttl_blocks: DEFAULT_STORAGE_COUPON_TTL_BLOCKS,
            bucket_ttl_blocks: DEFAULT_BUCKET_TTL_BLOCKS,
            diff_ttl_blocks: DEFAULT_DIFF_TTL_BLOCKS,
            proof_batch_ttl_blocks: DEFAULT_PROOF_BATCH_TTL_BLOCKS,
            eviction_grace_blocks: DEFAULT_EVICTION_GRACE_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_buckets: DEFAULT_MAX_BUCKETS,
            max_diffs: DEFAULT_MAX_DIFFS,
            max_coupons: DEFAULT_MAX_COUPONS,
            max_proof_batches: DEFAULT_MAX_PROOF_BATCHES,
            max_eviction_receipts: DEFAULT_MAX_EVICTION_RECEIPTS,
            max_sponsor_bids: DEFAULT_MAX_SPONSOR_BIDS,
            max_privacy_budgets: DEFAULT_MAX_PRIVACY_BUDGETS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_challenges: DEFAULT_MAX_CHALLENGES,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "invalid protocol version"
        );
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below runtime floor"
        );
        ensure!(
            self.min_anonymity_set >= 128,
            "minimum anonymity set too small"
        );
        ensure!(
            self.batch_anonymity_set >= self.min_anonymity_set,
            "batch anonymity set below minimum"
        );
        ensure!(self.max_user_fee_bps <= 100, "user fee cap is not low-fee");
        ensure!(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "rebate target above fee cap"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS,
            "sponsor cover above max bps"
        );
        ensure!(
            self.compression_reward_bps <= MAX_BPS,
            "compression reward above max bps"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_auth_suite": PQ_AUTH_SUITE,
            "compression_suite": COMPRESSION_SUITE,
            "storage_proof_suite": STORAGE_PROOF_SUITE,
            "privacy_accounting_suite": PRIVACY_ACCOUNTING_SUITE,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set": self.min_anonymity_set,
            "batch_anonymity_set": self.batch_anonymity_set,
            "max_user_fee_bps": self.max_user_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "sponsor_cover_bps": self.sponsor_cover_bps,
            "compression_reward_bps": self.compression_reward_bps,
            "storage_coupon_ttl_blocks": self.storage_coupon_ttl_blocks,
            "bucket_ttl_blocks": self.bucket_ttl_blocks,
            "diff_ttl_blocks": self.diff_ttl_blocks,
            "proof_batch_ttl_blocks": self.proof_batch_ttl_blocks,
            "eviction_grace_blocks": self.eviction_grace_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "limits": {
                "max_buckets": self.max_buckets,
                "max_diffs": self.max_diffs,
                "max_coupons": self.max_coupons,
                "max_proof_batches": self.max_proof_batches,
                "max_eviction_receipts": self.max_eviction_receipts,
                "max_sponsor_bids": self.max_sponsor_bids,
                "max_privacy_budgets": self.max_privacy_budgets,
                "max_rebates": self.max_rebates,
                "max_challenges": self.max_challenges
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub buckets_opened: u64,
    pub diffs_submitted: u64,
    pub diffs_settled: u64,
    pub coupons_issued: u64,
    pub coupons_applied: u64,
    pub proof_batches_opened: u64,
    pub proof_batches_verified: u64,
    pub eviction_receipts: u64,
    pub restore_receipts: u64,
    pub sponsor_bids: u64,
    pub sponsor_matches: u64,
    pub privacy_budget_updates: u64,
    pub rebates_queued: u64,
    pub rebates_paid: u64,
    pub challenges_filed: u64,
    pub slashes: u64,
    pub total_rent_units: u128,
    pub total_compressed_units: u128,
    pub total_fee_charged: u128,
    pub total_fee_rebated: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub bucket_root: String,
    pub diff_root: String,
    pub coupon_root: String,
    pub proof_batch_root: String,
    pub eviction_root: String,
    pub sponsor_bid_root: String,
    pub privacy_budget_root: String,
    pub rebate_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedRentBucketRequest {
    pub owner_commitment: String,
    pub contract_id: String,
    pub storage_class: StorageClass,
    pub encrypted_state_root: String,
    pub ciphertext_commitment_root: String,
    pub access_nullifier_root: String,
    pub rent_units: u64,
    pub target_fee_bps: u64,
    pub anonymity_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
}

impl EncryptedRentBucketRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("encrypted_rent_bucket_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedRentBucket {
    pub bucket_id: String,
    pub owner_commitment: String,
    pub contract_id: String,
    pub storage_class: StorageClass,
    pub status: BucketStatus,
    pub encrypted_state_root: String,
    pub ciphertext_commitment_root: String,
    pub access_nullifier_root: String,
    pub latest_diff_root: String,
    pub proof_batch_root: String,
    pub rent_units: u64,
    pub target_fee_bps: u64,
    pub accumulated_rent_due: u128,
    pub paid_rent: u128,
    pub compressed_units: u128,
    pub anonymity_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub updated_at_height: u64,
}

impl EncryptedRentBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("encrypted_rent_bucket", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateDiffCompressionRequest {
    pub bucket_id: String,
    pub caller_commitment: String,
    pub diff_kind: DiffKind,
    pub prior_state_root: String,
    pub new_state_root: String,
    pub encrypted_diff_root: String,
    pub witness_commitment: String,
    pub uncompressed_units: u64,
    pub compressed_units: u64,
    pub max_fee_bps: u64,
    pub privacy_budget_id: String,
    pub coupon_id: Option<String>,
    pub sponsor_bid_id: Option<String>,
    pub submitted_at_height: u64,
}

impl StateDiffCompressionRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("state_diff_compression_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateStateDiff {
    pub diff_id: String,
    pub bucket_id: String,
    pub caller_commitment: String,
    pub diff_kind: DiffKind,
    pub status: DiffStatus,
    pub prior_state_root: String,
    pub new_state_root: String,
    pub encrypted_diff_root: String,
    pub witness_commitment: String,
    pub compression_ratio_bps: u64,
    pub uncompressed_units: u64,
    pub compressed_units: u64,
    pub fee_charged: u128,
    pub rebate_due: u128,
    pub privacy_budget_id: String,
    pub coupon_id: Option<String>,
    pub sponsor_bid_id: Option<String>,
    pub proof_batch_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
}

impl PrivateStateDiff {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("private_state_diff", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageCouponRequest {
    pub owner_commitment: String,
    pub bucket_id: String,
    pub sponsor_bid_id: Option<String>,
    pub face_value: u128,
    pub covered_rent_units: u64,
    pub privacy_floor: u64,
    pub issued_at_height: u64,
}

impl StorageCouponRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("storage_coupon_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageCoupon {
    pub coupon_id: String,
    pub owner_commitment: String,
    pub bucket_id: String,
    pub sponsor_bid_id: Option<String>,
    pub status: CouponStatus,
    pub face_value: u128,
    pub remaining_value: u128,
    pub covered_rent_units: u64,
    pub privacy_floor: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub applied_diff_id: Option<String>,
}

impl StorageCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("storage_coupon", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveStorageProofBatchRequest {
    pub prover_commitment: String,
    pub batch_label: String,
    pub bucket_ids: Vec<String>,
    pub diff_ids: Vec<String>,
    pub aggregate_witness_root: String,
    pub recursion_program_hash: String,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
}

impl RecursiveStorageProofBatchRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root(
            "recursive_storage_proof_batch_request",
            &self.public_record(),
        )
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecursiveStorageProofBatch {
    pub proof_batch_id: String,
    pub prover_commitment: String,
    pub batch_label: String,
    pub status: ProofBatchStatus,
    pub bucket_ids: Vec<String>,
    pub diff_ids: Vec<String>,
    pub aggregate_witness_root: String,
    pub recursion_program_hash: String,
    pub recursive_proof_root: Option<String>,
    pub verifier_set_root: Option<String>,
    pub max_fee_bps: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub verified_at_height: Option<u64>,
}

impl RecursiveStorageProofBatch {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("recursive_storage_proof_batch", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionRestoreRequest {
    pub bucket_id: String,
    pub actor_commitment: String,
    pub reason_code: String,
    pub sealed_state_root: String,
    pub restore_state_root: Option<String>,
    pub rent_due: u128,
    pub requested_at_height: u64,
}

impl EvictionRestoreRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("eviction_restore_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionRestoreReceipt {
    pub receipt_id: String,
    pub bucket_id: String,
    pub actor_commitment: String,
    pub status: EvictionStatus,
    pub reason_code: String,
    pub sealed_state_root: String,
    pub restore_state_root: Option<String>,
    pub rent_due: u128,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
    pub completed_at_height: Option<u64>,
}

impl EvictionRestoreReceipt {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("eviction_restore_receipt", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBidRequest {
    pub sponsor_commitment: String,
    pub target_storage_class: StorageClass,
    pub max_fee_bps: u64,
    pub cover_bps: u64,
    pub budget: u128,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub posted_at_height: u64,
}

impl SponsorBidRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("sponsor_bid_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorBid {
    pub sponsor_bid_id: String,
    pub sponsor_commitment: String,
    pub target_storage_class: StorageClass,
    pub status: SponsorBidStatus,
    pub max_fee_bps: u64,
    pub cover_bps: u64,
    pub budget: u128,
    pub remaining_budget: u128,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub posted_at_height: u64,
    pub expires_at_height: u64,
    pub matched_diff_ids: BTreeSet<String>,
}

impl SponsorBid {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("sponsor_bid", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudgetRequest {
    pub owner_commitment: String,
    pub scope_root: String,
    pub nullifier_domain: String,
    pub initial_budget_units: u64,
    pub refill_rate_per_epoch: u64,
    pub epoch: u64,
}

impl PrivacyBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("privacy_budget_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyBudget {
    pub budget_id: String,
    pub owner_commitment: String,
    pub scope_root: String,
    pub nullifier_domain: String,
    pub status: PrivacyBudgetStatus,
    pub remaining_budget_units: u64,
    pub spent_budget_units: u64,
    pub refill_rate_per_epoch: u64,
    pub last_refill_epoch: u64,
    pub linked_diff_ids: BTreeSet<String>,
}

impl PrivacyBudget {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("privacy_budget", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub owner_commitment: String,
    pub source_diff_id: String,
    pub coupon_id: Option<String>,
    pub sponsor_bid_id: Option<String>,
    pub status: RebateStatus,
    pub amount: u128,
    pub queued_at_height: u64,
    pub paid_at_height: Option<u64>,
}

impl FeeRebate {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("fee_rebate", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeEvidenceRequest {
    pub challenger_commitment: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub evidence_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub bond: u128,
    pub filed_at_height: u64,
}

impl ChallengeEvidenceRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("challenge_evidence_request", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChallengeEvidence {
    pub challenge_id: String,
    pub challenger_commitment: String,
    pub subject_id: String,
    pub subject_kind: String,
    pub status: ChallengeStatus,
    pub evidence_root: String,
    pub expected_root: String,
    pub observed_root: String,
    pub bond: u128,
    pub slash_amount: u128,
    pub filed_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl ChallengeEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn root(&self) -> String {
        payload_root("challenge_evidence", &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub buckets: BTreeMap<String, EncryptedRentBucket>,
    pub diffs: BTreeMap<String, PrivateStateDiff>,
    pub coupons: BTreeMap<String, StorageCoupon>,
    pub proof_batches: BTreeMap<String, RecursiveStorageProofBatch>,
    pub eviction_receipts: BTreeMap<String, EvictionRestoreReceipt>,
    pub sponsor_bids: BTreeMap<String, SponsorBid>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudget>,
    pub rebates: BTreeMap<String, FeeRebate>,
    pub challenges: BTreeMap<String, ChallengeEvidence>,
    pub bucket_diffs: BTreeMap<String, BTreeSet<String>>,
    pub contract_buckets: BTreeMap<String, BTreeSet<String>>,
    pub owner_buckets: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
    pub current_height: u64,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            buckets: BTreeMap::new(),
            diffs: BTreeMap::new(),
            coupons: BTreeMap::new(),
            proof_batches: BTreeMap::new(),
            eviction_receipts: BTreeMap::new(),
            sponsor_bids: BTreeMap::new(),
            privacy_budgets: BTreeMap::new(),
            rebates: BTreeMap::new(),
            challenges: BTreeMap::new(),
            bucket_diffs: BTreeMap::new(),
            contract_buckets: BTreeMap::new(),
            owner_buckets: BTreeMap::new(),
            public_records: BTreeMap::new(),
            current_height,
        })
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::new(Config::default(), DEVNET_HEIGHT)?;
        let budget = state.open_privacy_budget(PrivacyBudgetRequest {
            owner_commitment: "devnet-owner-commitment".to_string(),
            scope_root: deterministic_root("devnet-scope", "privacy"),
            nullifier_domain: "devnet-confidential-state-rent".to_string(),
            initial_budget_units: 1_000_000,
            refill_rate_per_epoch: 25_000,
            epoch: 0,
        })?;
        let bid = state.post_sponsor_bid(SponsorBidRequest {
            sponsor_commitment: "devnet-sponsor".to_string(),
            target_storage_class: StorageClass::DefiPool,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            budget: 10_000_000,
            min_privacy_set: DEFAULT_MIN_ANONYMITY_SET,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            posted_at_height: DEVNET_HEIGHT,
        })?;
        let bucket = state.open_bucket(EncryptedRentBucketRequest {
            owner_commitment: "devnet-owner-commitment".to_string(),
            contract_id: "devnet-confidential-amm".to_string(),
            storage_class: StorageClass::DefiPool,
            encrypted_state_root: deterministic_root("devnet-state", "amm"),
            ciphertext_commitment_root: deterministic_root("devnet-ciphertext", "amm"),
            access_nullifier_root: deterministic_root("devnet-nullifier", "amm"),
            rent_units: 64_000,
            target_fee_bps: DEFAULT_TARGET_REBATE_BPS,
            anonymity_set_size: DEFAULT_BATCH_ANONYMITY_SET,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            opened_at_height: DEVNET_HEIGHT,
        })?;
        let coupon = state.issue_storage_coupon(StorageCouponRequest {
            owner_commitment: "devnet-owner-commitment".to_string(),
            bucket_id: bucket.bucket_id.clone(),
            sponsor_bid_id: Some(bid.sponsor_bid_id.clone()),
            face_value: 100_000,
            covered_rent_units: 16_000,
            privacy_floor: DEFAULT_MIN_ANONYMITY_SET,
            issued_at_height: DEVNET_HEIGHT,
        })?;
        let diff = state.submit_state_diff(StateDiffCompressionRequest {
            bucket_id: bucket.bucket_id.clone(),
            caller_commitment: "devnet-owner-commitment".to_string(),
            diff_kind: DiffKind::DefiNettingDelta,
            prior_state_root: bucket.encrypted_state_root.clone(),
            new_state_root: deterministic_root("devnet-state", "amm-next"),
            encrypted_diff_root: deterministic_root("devnet-diff", "amm-next"),
            witness_commitment: deterministic_root("devnet-witness", "amm-next"),
            uncompressed_units: 8_192,
            compressed_units: 1_024,
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            privacy_budget_id: budget.budget_id.clone(),
            coupon_id: Some(coupon.coupon_id.clone()),
            sponsor_bid_id: Some(bid.sponsor_bid_id.clone()),
            submitted_at_height: DEVNET_HEIGHT + 1,
        })?;
        let batch = state.open_proof_batch(RecursiveStorageProofBatchRequest {
            prover_commitment: "devnet-prover".to_string(),
            batch_label: "devnet-fast-defi-state-rent".to_string(),
            bucket_ids: vec![bucket.bucket_id.clone()],
            diff_ids: vec![diff.diff_id.clone()],
            aggregate_witness_root: deterministic_root("devnet-aggregate-witness", "batch-0"),
            recursion_program_hash: deterministic_root("devnet-recursion-program", "state-rent"),
            max_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            opened_at_height: DEVNET_HEIGHT + 2,
        })?;
        state.verify_proof_batch(
            &batch.proof_batch_id,
            deterministic_root("devnet-recursive-proof", "batch-0"),
            deterministic_root("devnet-verifier-set", "committee-0"),
            DEVNET_HEIGHT + 3,
        )?;
        state.settle_diff(&diff.diff_id, DEVNET_HEIGHT + 4)?;
        state.refresh_public_records();
        Ok(state)
    }

    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn open_bucket(
        &mut self,
        request: EncryptedRentBucketRequest,
    ) -> Result<EncryptedRentBucket> {
        ensure!(
            self.buckets.len() < self.config.max_buckets,
            "bucket limit reached"
        );
        ensure!(
            request.target_fee_bps <= self.config.max_user_fee_bps,
            "bucket fee above cap"
        );
        ensure!(
            request.anonymity_set_size >= self.config.min_anonymity_set,
            "bucket anonymity set too small"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "bucket pq security too low"
        );
        let bucket_id = bucket_id(&request);
        ensure!(
            !self.buckets.contains_key(&bucket_id),
            "bucket already exists"
        );
        let bucket = EncryptedRentBucket {
            bucket_id: bucket_id.clone(),
            owner_commitment: request.owner_commitment.clone(),
            contract_id: request.contract_id.clone(),
            storage_class: request.storage_class,
            status: BucketStatus::Open,
            encrypted_state_root: request.encrypted_state_root,
            ciphertext_commitment_root: request.ciphertext_commitment_root,
            access_nullifier_root: request.access_nullifier_root,
            latest_diff_root: empty_root("bucket-diffs"),
            proof_batch_root: empty_root("bucket-proof-batches"),
            rent_units: request.rent_units,
            target_fee_bps: request.target_fee_bps,
            accumulated_rent_due: rent_charge(request.rent_units, request.target_fee_bps),
            paid_rent: 0,
            compressed_units: 0,
            anonymity_set_size: request.anonymity_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.bucket_ttl_blocks,
            updated_at_height: request.opened_at_height,
        };
        self.contract_buckets
            .entry(bucket.contract_id.clone())
            .or_default()
            .insert(bucket_id.clone());
        self.owner_buckets
            .entry(bucket.owner_commitment.clone())
            .or_default()
            .insert(bucket_id.clone());
        self.bucket_diffs.entry(bucket_id.clone()).or_default();
        self.counters.buckets_opened += 1;
        self.counters.total_rent_units += request.rent_units as u128;
        self.public_records
            .insert(format!("bucket:{bucket_id}"), bucket.public_record());
        self.buckets.insert(bucket_id, bucket.clone());
        Ok(bucket)
    }

    pub fn submit_state_diff(
        &mut self,
        request: StateDiffCompressionRequest,
    ) -> Result<PrivateStateDiff> {
        ensure!(
            self.diffs.len() < self.config.max_diffs,
            "diff limit reached"
        );
        ensure!(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "diff fee above cap"
        );
        let bucket = self
            .buckets
            .get(&request.bucket_id)
            .ok_or_else(|| "unknown bucket".to_string())?;
        ensure!(
            bucket.status.accepts_diffs(),
            "bucket does not accept diffs"
        );
        ensure!(
            bucket.encrypted_state_root == request.prior_state_root,
            "prior state root mismatch"
        );
        let budget = self
            .privacy_budgets
            .get(&request.privacy_budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        ensure!(budget.status.usable(), "privacy budget not usable");
        ensure!(
            budget.remaining_budget_units
                >= privacy_cost(request.uncompressed_units, request.compressed_units),
            "privacy budget exhausted"
        );
        if let Some(coupon_id) = &request.coupon_id {
            let coupon = self
                .coupons
                .get(coupon_id)
                .ok_or_else(|| "unknown coupon".to_string())?;
            ensure!(coupon.status.spendable(), "coupon not spendable");
            ensure!(
                coupon.bucket_id == request.bucket_id,
                "coupon bucket mismatch"
            );
        }
        if let Some(sponsor_bid_id) = &request.sponsor_bid_id {
            let bid = self
                .sponsor_bids
                .get(sponsor_bid_id)
                .ok_or_else(|| "unknown sponsor bid".to_string())?;
            ensure!(
                matches!(
                    bid.status,
                    SponsorBidStatus::Posted | SponsorBidStatus::Matched
                ),
                "sponsor bid unavailable"
            );
            ensure!(
                bid.min_privacy_set <= bucket.anonymity_set_size,
                "sponsor privacy floor not met"
            );
            ensure!(
                bid.pq_security_bits <= bucket.pq_security_bits,
                "sponsor pq floor not met"
            );
            ensure!(
                bid.max_fee_bps >= request.max_fee_bps,
                "sponsor fee cap mismatch"
            );
        }
        let ratio = compression_ratio_bps(request.uncompressed_units, request.compressed_units);
        let fee = rent_charge(request.compressed_units, request.max_fee_bps);
        let reward = fee.saturating_mul(request.diff_kind.compression_weight_bps() as u128)
            / MAX_BPS as u128;
        let rebate_due =
            reward.saturating_mul(self.config.compression_reward_bps as u128) / MAX_BPS as u128;
        let diff_id = diff_id(&request);
        ensure!(!self.diffs.contains_key(&diff_id), "diff already exists");
        let mut diff = PrivateStateDiff {
            diff_id: diff_id.clone(),
            bucket_id: request.bucket_id.clone(),
            caller_commitment: request.caller_commitment.clone(),
            diff_kind: request.diff_kind,
            status: DiffStatus::Submitted,
            prior_state_root: request.prior_state_root,
            new_state_root: request.new_state_root,
            encrypted_diff_root: request.encrypted_diff_root,
            witness_commitment: request.witness_commitment,
            compression_ratio_bps: ratio,
            uncompressed_units: request.uncompressed_units,
            compressed_units: request.compressed_units,
            fee_charged: fee,
            rebate_due,
            privacy_budget_id: request.privacy_budget_id.clone(),
            coupon_id: request.coupon_id.clone(),
            sponsor_bid_id: request.sponsor_bid_id.clone(),
            proof_batch_id: None,
            submitted_at_height: request.submitted_at_height,
            expires_at_height: request.submitted_at_height + self.config.diff_ttl_blocks,
            settled_at_height: None,
        };
        if request.coupon_id.is_some() {
            diff.status = DiffStatus::CouponLinked;
        }
        if request.sponsor_bid_id.is_some() {
            diff.status = DiffStatus::Sponsored;
        }
        self.consume_privacy_budget(
            &request.privacy_budget_id,
            &diff_id,
            privacy_cost(request.uncompressed_units, request.compressed_units),
        )?;
        if let Some(coupon_id) = &request.coupon_id {
            self.apply_coupon(coupon_id, &diff_id, fee)?;
        }
        if let Some(sponsor_bid_id) = &request.sponsor_bid_id {
            self.match_sponsor_bid(sponsor_bid_id, &diff_id, fee)?;
        }
        self.bucket_diffs
            .entry(request.bucket_id.clone())
            .or_default()
            .insert(diff_id.clone());
        if let Some(bucket) = self.buckets.get_mut(&request.bucket_id) {
            bucket.latest_diff_root = merkle_from_strings(
                "bucket-diff-index",
                self.bucket_diffs.get(&request.bucket_id).unwrap(),
            );
            bucket.encrypted_state_root = diff.new_state_root.clone();
            bucket.compressed_units = bucket
                .compressed_units
                .saturating_add(request.compressed_units as u128);
            bucket.updated_at_height = request.submitted_at_height;
            self.public_records.insert(
                format!("bucket:{}", bucket.bucket_id),
                bucket.public_record(),
            );
        }
        self.counters.diffs_submitted += 1;
        self.counters.total_compressed_units += request.compressed_units as u128;
        self.counters.total_fee_charged += fee;
        self.public_records
            .insert(format!("diff:{diff_id}"), diff.public_record());
        self.diffs.insert(diff_id, diff.clone());
        Ok(diff)
    }

    pub fn issue_storage_coupon(&mut self, request: StorageCouponRequest) -> Result<StorageCoupon> {
        ensure!(
            self.coupons.len() < self.config.max_coupons,
            "coupon limit reached"
        );
        ensure!(
            self.buckets.contains_key(&request.bucket_id),
            "unknown bucket"
        );
        ensure!(
            request.privacy_floor >= self.config.min_anonymity_set,
            "coupon privacy floor too small"
        );
        let coupon_id = coupon_id(&request);
        ensure!(
            !self.coupons.contains_key(&coupon_id),
            "coupon already exists"
        );
        let coupon = StorageCoupon {
            coupon_id: coupon_id.clone(),
            owner_commitment: request.owner_commitment,
            bucket_id: request.bucket_id,
            sponsor_bid_id: request.sponsor_bid_id,
            status: CouponStatus::Issued,
            face_value: request.face_value,
            remaining_value: request.face_value,
            covered_rent_units: request.covered_rent_units,
            privacy_floor: request.privacy_floor,
            issued_at_height: request.issued_at_height,
            expires_at_height: request.issued_at_height + self.config.storage_coupon_ttl_blocks,
            applied_diff_id: None,
        };
        self.counters.coupons_issued += 1;
        self.public_records
            .insert(format!("coupon:{coupon_id}"), coupon.public_record());
        self.coupons.insert(coupon_id, coupon.clone());
        Ok(coupon)
    }

    pub fn open_proof_batch(
        &mut self,
        request: RecursiveStorageProofBatchRequest,
    ) -> Result<RecursiveStorageProofBatch> {
        ensure!(
            self.proof_batches.len() < self.config.max_proof_batches,
            "proof batch limit reached"
        );
        ensure!(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "proof batch fee above cap"
        );
        ensure!(!request.bucket_ids.is_empty(), "proof batch has no buckets");
        ensure!(!request.diff_ids.is_empty(), "proof batch has no diffs");
        for bucket_id in &request.bucket_ids {
            ensure!(
                self.buckets.contains_key(bucket_id),
                "proof batch references unknown bucket"
            );
        }
        for diff_id in &request.diff_ids {
            ensure!(
                self.diffs.contains_key(diff_id),
                "proof batch references unknown diff"
            );
        }
        let proof_batch_id = proof_batch_id(&request);
        ensure!(
            !self.proof_batches.contains_key(&proof_batch_id),
            "proof batch already exists"
        );
        let batch = RecursiveStorageProofBatch {
            proof_batch_id: proof_batch_id.clone(),
            prover_commitment: request.prover_commitment,
            batch_label: request.batch_label,
            status: ProofBatchStatus::Collecting,
            bucket_ids: request.bucket_ids,
            diff_ids: request.diff_ids,
            aggregate_witness_root: request.aggregate_witness_root,
            recursion_program_hash: request.recursion_program_hash,
            recursive_proof_root: None,
            verifier_set_root: None,
            max_fee_bps: request.max_fee_bps,
            opened_at_height: request.opened_at_height,
            expires_at_height: request.opened_at_height + self.config.proof_batch_ttl_blocks,
            verified_at_height: None,
        };
        for diff_id in &batch.diff_ids {
            if let Some(diff) = self.diffs.get_mut(diff_id) {
                diff.proof_batch_id = Some(proof_batch_id.clone());
                diff.status = DiffStatus::ProofQueued;
                self.public_records
                    .insert(format!("diff:{diff_id}"), diff.public_record());
            }
        }
        self.counters.proof_batches_opened += 1;
        self.public_records.insert(
            format!("proof_batch:{proof_batch_id}"),
            batch.public_record(),
        );
        self.proof_batches.insert(proof_batch_id, batch.clone());
        Ok(batch)
    }

    pub fn verify_proof_batch(
        &mut self,
        proof_batch_id: &str,
        recursive_proof_root: String,
        verifier_set_root: String,
        verified_at_height: u64,
    ) -> Result<RecursiveStorageProofBatch> {
        let diff_ids;
        {
            let batch = self
                .proof_batches
                .get_mut(proof_batch_id)
                .ok_or_else(|| "unknown proof batch".to_string())?;
            ensure!(
                matches!(
                    batch.status,
                    ProofBatchStatus::Collecting | ProofBatchStatus::RecursiveFolded
                ),
                "proof batch cannot be verified"
            );
            batch.status = ProofBatchStatus::Verified;
            batch.recursive_proof_root = Some(recursive_proof_root);
            batch.verifier_set_root = Some(verifier_set_root);
            batch.verified_at_height = Some(verified_at_height);
            diff_ids = batch.diff_ids.clone();
            self.public_records.insert(
                format!("proof_batch:{proof_batch_id}"),
                batch.public_record(),
            );
        }
        for diff_id in diff_ids {
            if let Some(diff) = self.diffs.get_mut(&diff_id) {
                diff.status = DiffStatus::Batched;
                self.public_records
                    .insert(format!("diff:{diff_id}"), diff.public_record());
            }
        }
        self.counters.proof_batches_verified += 1;
        Ok(self.proof_batches.get(proof_batch_id).cloned().unwrap())
    }

    pub fn settle_diff(
        &mut self,
        diff_id: &str,
        settled_at_height: u64,
    ) -> Result<PrivateStateDiff> {
        let rebate;
        {
            let diff = self
                .diffs
                .get_mut(diff_id)
                .ok_or_else(|| "unknown diff".to_string())?;
            ensure!(
                matches!(
                    diff.status,
                    DiffStatus::Batched
                        | DiffStatus::ProofQueued
                        | DiffStatus::Sponsored
                        | DiffStatus::CouponLinked
                ),
                "diff cannot settle"
            );
            diff.status = DiffStatus::Settled;
            diff.settled_at_height = Some(settled_at_height);
            rebate = FeeRebate {
                rebate_id: rebate_id(diff_id, &diff.caller_commitment, settled_at_height),
                owner_commitment: diff.caller_commitment.clone(),
                source_diff_id: diff.diff_id.clone(),
                coupon_id: diff.coupon_id.clone(),
                sponsor_bid_id: diff.sponsor_bid_id.clone(),
                status: RebateStatus::Queued,
                amount: diff.rebate_due,
                queued_at_height: settled_at_height,
                paid_at_height: None,
            };
            self.public_records
                .insert(format!("diff:{diff_id}"), diff.public_record());
        }
        self.counters.diffs_settled += 1;
        self.queue_rebate(rebate)?;
        Ok(self.diffs.get(diff_id).cloned().unwrap())
    }

    pub fn request_eviction(
        &mut self,
        request: EvictionRestoreRequest,
    ) -> Result<EvictionRestoreReceipt> {
        ensure!(
            self.eviction_receipts.len() < self.config.max_eviction_receipts,
            "eviction receipt limit reached"
        );
        let bucket = self
            .buckets
            .get_mut(&request.bucket_id)
            .ok_or_else(|| "unknown bucket".to_string())?;
        ensure!(
            bucket.encrypted_state_root == request.sealed_state_root,
            "sealed root mismatch"
        );
        let receipt_id = eviction_receipt_id(&request);
        let receipt = EvictionRestoreReceipt {
            receipt_id: receipt_id.clone(),
            bucket_id: request.bucket_id.clone(),
            actor_commitment: request.actor_commitment,
            status: EvictionStatus::GracePeriod,
            reason_code: request.reason_code,
            sealed_state_root: request.sealed_state_root,
            restore_state_root: request.restore_state_root,
            rent_due: request.rent_due,
            requested_at_height: request.requested_at_height,
            executable_at_height: request.requested_at_height + self.config.eviction_grace_blocks,
            completed_at_height: None,
        };
        bucket.status = BucketStatus::Evictable;
        bucket.accumulated_rent_due = bucket.accumulated_rent_due.saturating_add(request.rent_due);
        self.counters.eviction_receipts += 1;
        self.public_records.insert(
            format!("bucket:{}", bucket.bucket_id),
            bucket.public_record(),
        );
        self.public_records
            .insert(format!("eviction:{receipt_id}"), receipt.public_record());
        self.eviction_receipts.insert(receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn restore_bucket(
        &mut self,
        receipt_id: &str,
        restore_state_root: String,
        completed_at_height: u64,
    ) -> Result<EvictionRestoreReceipt> {
        let bucket_id;
        {
            let receipt = self
                .eviction_receipts
                .get_mut(receipt_id)
                .ok_or_else(|| "unknown eviction receipt".to_string())?;
            ensure!(
                matches!(
                    receipt.status,
                    EvictionStatus::GracePeriod
                        | EvictionStatus::Evicted
                        | EvictionStatus::RestorePending
                ),
                "receipt cannot restore"
            );
            receipt.status = EvictionStatus::Restored;
            receipt.restore_state_root = Some(restore_state_root.clone());
            receipt.completed_at_height = Some(completed_at_height);
            bucket_id = receipt.bucket_id.clone();
            self.public_records
                .insert(format!("eviction:{receipt_id}"), receipt.public_record());
        }
        if let Some(bucket) = self.buckets.get_mut(&bucket_id) {
            bucket.status = BucketStatus::Restored;
            bucket.encrypted_state_root = restore_state_root;
            bucket.updated_at_height = completed_at_height;
            self.public_records
                .insert(format!("bucket:{bucket_id}"), bucket.public_record());
        }
        self.counters.restore_receipts += 1;
        Ok(self.eviction_receipts.get(receipt_id).cloned().unwrap())
    }

    pub fn post_sponsor_bid(&mut self, request: SponsorBidRequest) -> Result<SponsorBid> {
        ensure!(
            self.sponsor_bids.len() < self.config.max_sponsor_bids,
            "sponsor bid limit reached"
        );
        ensure!(
            request.max_fee_bps <= self.config.max_user_fee_bps,
            "sponsor fee above cap"
        );
        ensure!(
            request.cover_bps <= self.config.sponsor_cover_bps,
            "sponsor cover above cap"
        );
        ensure!(
            request.min_privacy_set >= self.config.min_anonymity_set,
            "sponsor privacy floor too small"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "sponsor pq security too low"
        );
        let sponsor_bid_id = sponsor_bid_id(&request);
        let bid = SponsorBid {
            sponsor_bid_id: sponsor_bid_id.clone(),
            sponsor_commitment: request.sponsor_commitment,
            target_storage_class: request.target_storage_class,
            status: SponsorBidStatus::Posted,
            max_fee_bps: request.max_fee_bps,
            cover_bps: request.cover_bps,
            budget: request.budget,
            remaining_budget: request.budget,
            min_privacy_set: request.min_privacy_set,
            pq_security_bits: request.pq_security_bits,
            posted_at_height: request.posted_at_height,
            expires_at_height: request.posted_at_height + self.config.storage_coupon_ttl_blocks,
            matched_diff_ids: BTreeSet::new(),
        };
        self.counters.sponsor_bids += 1;
        self.public_records
            .insert(format!("sponsor_bid:{sponsor_bid_id}"), bid.public_record());
        self.sponsor_bids.insert(sponsor_bid_id, bid.clone());
        Ok(bid)
    }

    pub fn open_privacy_budget(&mut self, request: PrivacyBudgetRequest) -> Result<PrivacyBudget> {
        ensure!(
            self.privacy_budgets.len() < self.config.max_privacy_budgets,
            "privacy budget limit reached"
        );
        ensure!(request.initial_budget_units > 0, "privacy budget is empty");
        let budget_id = privacy_budget_id(&request);
        let budget = PrivacyBudget {
            budget_id: budget_id.clone(),
            owner_commitment: request.owner_commitment,
            scope_root: request.scope_root,
            nullifier_domain: request.nullifier_domain,
            status: PrivacyBudgetStatus::Active,
            remaining_budget_units: request.initial_budget_units,
            spent_budget_units: 0,
            refill_rate_per_epoch: request.refill_rate_per_epoch,
            last_refill_epoch: request.epoch,
            linked_diff_ids: BTreeSet::new(),
        };
        self.counters.privacy_budget_updates += 1;
        self.public_records.insert(
            format!("privacy_budget:{budget_id}"),
            budget.public_record(),
        );
        self.privacy_budgets.insert(budget_id, budget.clone());
        Ok(budget)
    }

    pub fn refill_privacy_budget(&mut self, budget_id: &str, epoch: u64) -> Result<PrivacyBudget> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        ensure!(
            epoch > budget.last_refill_epoch,
            "privacy budget epoch not advanced"
        );
        let epochs = epoch - budget.last_refill_epoch;
        budget.remaining_budget_units = budget
            .remaining_budget_units
            .saturating_add(epochs.saturating_mul(budget.refill_rate_per_epoch));
        budget.last_refill_epoch = epoch;
        budget.status = PrivacyBudgetStatus::Refilled;
        self.counters.privacy_budget_updates += 1;
        self.public_records.insert(
            format!("privacy_budget:{budget_id}"),
            budget.public_record(),
        );
        Ok(budget.clone())
    }

    pub fn file_challenge(
        &mut self,
        request: ChallengeEvidenceRequest,
    ) -> Result<ChallengeEvidence> {
        ensure!(
            self.challenges.len() < self.config.max_challenges,
            "challenge limit reached"
        );
        ensure!(
            request.expected_root != request.observed_root,
            "challenge roots do not diverge"
        );
        let challenge_id = challenge_id(&request);
        let challenge = ChallengeEvidence {
            challenge_id: challenge_id.clone(),
            challenger_commitment: request.challenger_commitment,
            subject_id: request.subject_id,
            subject_kind: request.subject_kind,
            status: ChallengeStatus::EvidenceLocked,
            evidence_root: request.evidence_root,
            expected_root: request.expected_root,
            observed_root: request.observed_root,
            bond: request.bond,
            slash_amount: request.bond.saturating_mul(2),
            filed_at_height: request.filed_at_height,
            expires_at_height: request.filed_at_height + self.config.challenge_window_blocks,
            resolved_at_height: None,
        };
        self.counters.challenges_filed += 1;
        self.public_records.insert(
            format!("challenge:{challenge_id}"),
            challenge.public_record(),
        );
        self.challenges.insert(challenge_id, challenge.clone());
        Ok(challenge)
    }

    pub fn resolve_challenge(
        &mut self,
        challenge_id: &str,
        accepted: bool,
        resolved_at_height: u64,
    ) -> Result<ChallengeEvidence> {
        let (subject_kind, subject_id);
        {
            let challenge = self
                .challenges
                .get_mut(challenge_id)
                .ok_or_else(|| "unknown challenge".to_string())?;
            ensure!(
                matches!(
                    challenge.status,
                    ChallengeStatus::Filed | ChallengeStatus::EvidenceLocked
                ),
                "challenge already resolved"
            );
            challenge.status = if accepted {
                ChallengeStatus::Slashed
            } else {
                ChallengeStatus::Rejected
            };
            challenge.resolved_at_height = Some(resolved_at_height);
            subject_kind = challenge.subject_kind.clone();
            subject_id = challenge.subject_id.clone();
            self.public_records.insert(
                format!("challenge:{challenge_id}"),
                challenge.public_record(),
            );
        }
        if accepted {
            self.counters.slashes += 1;
            self.apply_slash_marker(&subject_kind, &subject_id)?;
        }
        Ok(self.challenges.get(challenge_id).cloned().unwrap())
    }

    pub fn pay_rebate(&mut self, rebate_id: &str, paid_at_height: u64) -> Result<FeeRebate> {
        let rebate = self
            .rebates
            .get_mut(rebate_id)
            .ok_or_else(|| "unknown rebate".to_string())?;
        ensure!(
            matches!(rebate.status, RebateStatus::Queued | RebateStatus::Approved),
            "rebate not payable"
        );
        rebate.status = RebateStatus::Paid;
        rebate.paid_at_height = Some(paid_at_height);
        self.counters.rebates_paid += 1;
        self.counters.total_fee_rebated = self
            .counters
            .total_fee_rebated
            .saturating_add(rebate.amount);
        self.public_records
            .insert(format!("rebate:{rebate_id}"), rebate.public_record());
        Ok(rebate.clone())
    }

    fn apply_coupon(&mut self, coupon_id: &str, diff_id: &str, fee: u128) -> Result<()> {
        let coupon = self
            .coupons
            .get_mut(coupon_id)
            .ok_or_else(|| "unknown coupon".to_string())?;
        let applied = coupon.remaining_value.min(fee);
        coupon.remaining_value = coupon.remaining_value.saturating_sub(applied);
        coupon.status = if coupon.remaining_value == 0 {
            CouponStatus::Applied
        } else {
            CouponStatus::Reserved
        };
        coupon.applied_diff_id = Some(diff_id.to_string());
        self.counters.coupons_applied += 1;
        self.public_records
            .insert(format!("coupon:{coupon_id}"), coupon.public_record());
        Ok(())
    }

    fn match_sponsor_bid(&mut self, sponsor_bid_id: &str, diff_id: &str, fee: u128) -> Result<()> {
        let bid = self
            .sponsor_bids
            .get_mut(sponsor_bid_id)
            .ok_or_else(|| "unknown sponsor bid".to_string())?;
        let covered = fee.saturating_mul(bid.cover_bps as u128) / MAX_BPS as u128;
        ensure!(bid.remaining_budget >= covered, "sponsor budget exhausted");
        bid.remaining_budget = bid.remaining_budget.saturating_sub(covered);
        bid.status = SponsorBidStatus::Matched;
        bid.matched_diff_ids.insert(diff_id.to_string());
        self.counters.sponsor_matches += 1;
        self.public_records
            .insert(format!("sponsor_bid:{sponsor_bid_id}"), bid.public_record());
        Ok(())
    }

    fn consume_privacy_budget(&mut self, budget_id: &str, diff_id: &str, units: u64) -> Result<()> {
        let budget = self
            .privacy_budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown privacy budget".to_string())?;
        ensure!(
            budget.remaining_budget_units >= units,
            "privacy budget exhausted"
        );
        budget.remaining_budget_units -= units;
        budget.spent_budget_units = budget.spent_budget_units.saturating_add(units);
        budget.linked_diff_ids.insert(diff_id.to_string());
        if budget.remaining_budget_units == 0 {
            budget.status = PrivacyBudgetStatus::Exhausted;
        }
        self.counters.privacy_budget_updates += 1;
        self.public_records.insert(
            format!("privacy_budget:{budget_id}"),
            budget.public_record(),
        );
        Ok(())
    }

    fn queue_rebate(&mut self, rebate: FeeRebate) -> Result<()> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate limit reached"
        );
        let rebate_id = rebate.rebate_id.clone();
        self.counters.rebates_queued += 1;
        self.public_records
            .insert(format!("rebate:{rebate_id}"), rebate.public_record());
        self.rebates.insert(rebate_id, rebate);
        Ok(())
    }

    fn apply_slash_marker(&mut self, subject_kind: &str, subject_id: &str) -> Result<()> {
        match subject_kind {
            "bucket" => {
                if let Some(bucket) = self.buckets.get_mut(subject_id) {
                    bucket.status = BucketStatus::Slashed;
                    self.public_records
                        .insert(format!("bucket:{subject_id}"), bucket.public_record());
                }
            }
            "diff" => {
                if let Some(diff) = self.diffs.get_mut(subject_id) {
                    diff.status = DiffStatus::Challenged;
                    self.public_records
                        .insert(format!("diff:{subject_id}"), diff.public_record());
                }
            }
            "coupon" => {
                if let Some(coupon) = self.coupons.get_mut(subject_id) {
                    coupon.status = CouponStatus::Slashed;
                    self.public_records
                        .insert(format!("coupon:{subject_id}"), coupon.public_record());
                }
            }
            "proof_batch" => {
                if let Some(batch) = self.proof_batches.get_mut(subject_id) {
                    batch.status = ProofBatchStatus::Slashed;
                    self.public_records
                        .insert(format!("proof_batch:{subject_id}"), batch.public_record());
                }
            }
            "sponsor_bid" => {
                if let Some(bid) = self.sponsor_bids.get_mut(subject_id) {
                    bid.status = SponsorBidStatus::Slashed;
                    self.public_records
                        .insert(format!("sponsor_bid:{subject_id}"), bid.public_record());
                }
            }
            "privacy_budget" => {
                if let Some(budget) = self.privacy_budgets.get_mut(subject_id) {
                    budget.status = PrivacyBudgetStatus::Slashed;
                    self.public_records.insert(
                        format!("privacy_budget:{subject_id}"),
                        budget.public_record(),
                    );
                }
            }
            _ => return Err("unknown slash subject kind".to_string()),
        }
        Ok(())
    }

    pub fn expire_height(&mut self, height: u64) -> Result<String> {
        self.current_height = height;
        for bucket in self.buckets.values_mut() {
            if bucket.expires_at_height <= height && bucket.status.accepts_diffs() {
                bucket.status = BucketStatus::Evictable;
            }
        }
        for diff in self.diffs.values_mut() {
            if diff.expires_at_height <= height && diff.status.live() {
                diff.status = DiffStatus::Expired;
            }
        }
        for coupon in self.coupons.values_mut() {
            if coupon.expires_at_height <= height && coupon.status.spendable() {
                coupon.status = CouponStatus::Expired;
            }
        }
        for bid in self.sponsor_bids.values_mut() {
            if bid.expires_at_height <= height
                && matches!(
                    bid.status,
                    SponsorBidStatus::Posted | SponsorBidStatus::Matched
                )
            {
                bid.status = SponsorBidStatus::Expired;
            }
        }
        for challenge in self.challenges.values_mut() {
            if challenge.expires_at_height <= height
                && matches!(
                    challenge.status,
                    ChallengeStatus::Filed | ChallengeStatus::EvidenceLocked
                )
            {
                challenge.status = ChallengeStatus::Expired;
            }
        }
        self.refresh_public_records();
        Ok(self.state_root())
    }

    pub fn roots(&self) -> Roots {
        let public_records = self.public_records.values().cloned().collect::<Vec<_>>();
        let public_record_root = public_record_root(&public_records);
        let mut roots = Roots {
            bucket_root: record_map_root(
                "bucket",
                self.buckets
                    .values()
                    .map(EncryptedRentBucket::public_record)
                    .collect(),
            ),
            diff_root: record_map_root(
                "diff",
                self.diffs
                    .values()
                    .map(PrivateStateDiff::public_record)
                    .collect(),
            ),
            coupon_root: record_map_root(
                "coupon",
                self.coupons
                    .values()
                    .map(StorageCoupon::public_record)
                    .collect(),
            ),
            proof_batch_root: record_map_root(
                "proof-batch",
                self.proof_batches
                    .values()
                    .map(RecursiveStorageProofBatch::public_record)
                    .collect(),
            ),
            eviction_root: record_map_root(
                "eviction",
                self.eviction_receipts
                    .values()
                    .map(EvictionRestoreReceipt::public_record)
                    .collect(),
            ),
            sponsor_bid_root: record_map_root(
                "sponsor-bid",
                self.sponsor_bids
                    .values()
                    .map(SponsorBid::public_record)
                    .collect(),
            ),
            privacy_budget_root: record_map_root(
                "privacy-budget",
                self.privacy_budgets
                    .values()
                    .map(PrivacyBudget::public_record)
                    .collect(),
            ),
            rebate_root: record_map_root(
                "rebate",
                self.rebates
                    .values()
                    .map(FeeRebate::public_record)
                    .collect(),
            ),
            challenge_root: record_map_root(
                "challenge",
                self.challenges
                    .values()
                    .map(ChallengeEvidence::public_record)
                    .collect(),
            ),
            public_record_root,
            state_root: String::new(),
        };
        roots.state_root = state_root_from_record(&self.public_record_without_root(&roots));
        roots
    }

    pub fn public_record_without_root(&self, roots: &Roots) -> Value {
        json!({ "protocol_version": PROTOCOL_VERSION, "schema_version": SCHEMA_VERSION, "chain_id": CHAIN_ID, "config": self.config.public_record(), "counters": self.counters.public_record(), "roots": roots.public_record(), "indexes": { "bucket_diff_root": map_set_root("bucket-diffs", &self.bucket_diffs), "contract_bucket_root": map_set_root("contract-buckets", &self.contract_buckets), "owner_bucket_root": map_set_root("owner-buckets", &self.owner_buckets) }, "current_height": self.current_height })
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_root(&roots);
        record["state_root"] = json!(roots.state_root);
        record
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    pub fn public_record_root(&self) -> String {
        self.roots().public_record_root
    }

    pub fn refresh_public_records(&mut self) {
        self.public_records.clear();
        for (id, bucket) in &self.buckets {
            self.public_records
                .insert(format!("bucket:{id}"), bucket.public_record());
        }
        for (id, diff) in &self.diffs {
            self.public_records
                .insert(format!("diff:{id}"), diff.public_record());
        }
        for (id, coupon) in &self.coupons {
            self.public_records
                .insert(format!("coupon:{id}"), coupon.public_record());
        }
        for (id, batch) in &self.proof_batches {
            self.public_records
                .insert(format!("proof_batch:{id}"), batch.public_record());
        }
        for (id, receipt) in &self.eviction_receipts {
            self.public_records
                .insert(format!("eviction:{id}"), receipt.public_record());
        }
        for (id, bid) in &self.sponsor_bids {
            self.public_records
                .insert(format!("sponsor_bid:{id}"), bid.public_record());
        }
        for (id, budget) in &self.privacy_budgets {
            self.public_records
                .insert(format!("privacy_budget:{id}"), budget.public_record());
        }
        for (id, rebate) in &self.rebates {
            self.public_records
                .insert(format!("rebate:{id}"), rebate.public_record());
        }
        for (id, challenge) in &self.challenges {
            self.public_records
                .insert(format!("challenge:{id}"), challenge.public_record());
        }
    }
}

pub fn bucket_id(request: &EncryptedRentBucketRequest) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-RENT-BUCKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.contract_id),
            HashPart::Str(request.storage_class.as_str()),
            HashPart::Str(&request.encrypted_state_root),
            HashPart::U64(request.opened_at_height),
        ],
        32,
    )
}
pub fn diff_id(request: &StateDiffCompressionRequest) -> String {
    domain_hash(
        "PRIVATE-L2-STATE-DIFF-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(request.diff_kind.as_str()),
            HashPart::Str(&request.prior_state_root),
            HashPart::Str(&request.new_state_root),
            HashPart::Str(&request.encrypted_diff_root),
            HashPart::U64(request.submitted_at_height),
        ],
        32,
    )
}
pub fn coupon_id(request: &StorageCouponRequest) -> String {
    domain_hash(
        "PRIVATE-L2-STORAGE-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.bucket_id),
            HashPart::Int(request.face_value as i128),
            HashPart::U64(request.issued_at_height),
        ],
        32,
    )
}
pub fn proof_batch_id(request: &RecursiveStorageProofBatchRequest) -> String {
    let ids = json!({"bucket_ids": request.bucket_ids, "diff_ids": request.diff_ids});
    domain_hash(
        "PRIVATE-L2-RECURSIVE-STORAGE-PROOF-BATCH-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.prover_commitment),
            HashPart::Str(&request.batch_label),
            HashPart::Json(&ids),
            HashPart::Str(&request.aggregate_witness_root),
            HashPart::U64(request.opened_at_height),
        ],
        32,
    )
}
pub fn eviction_receipt_id(request: &EvictionRestoreRequest) -> String {
    domain_hash(
        "PRIVATE-L2-EVICTION-RESTORE-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.bucket_id),
            HashPart::Str(&request.actor_commitment),
            HashPart::Str(&request.reason_code),
            HashPart::Str(&request.sealed_state_root),
            HashPart::U64(request.requested_at_height),
        ],
        32,
    )
}
pub fn sponsor_bid_id(request: &SponsorBidRequest) -> String {
    domain_hash(
        "PRIVATE-L2-SPONSOR-BID-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.sponsor_commitment),
            HashPart::Str(request.target_storage_class.as_str()),
            HashPart::Int(request.budget as i128),
            HashPart::U64(request.posted_at_height),
        ],
        32,
    )
}
pub fn privacy_budget_id(request: &PrivacyBudgetRequest) -> String {
    domain_hash(
        "PRIVATE-L2-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.owner_commitment),
            HashPart::Str(&request.scope_root),
            HashPart::Str(&request.nullifier_domain),
            HashPart::U64(request.epoch),
        ],
        32,
    )
}
pub fn rebate_id(diff_id: &str, owner_commitment: &str, queued_at_height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-FEE-REBATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(diff_id),
            HashPart::Str(owner_commitment),
            HashPart::U64(queued_at_height),
        ],
        32,
    )
}
pub fn challenge_id(request: &ChallengeEvidenceRequest) -> String {
    domain_hash(
        "PRIVATE-L2-CHALLENGE-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&request.challenger_commitment),
            HashPart::Str(&request.subject_kind),
            HashPart::Str(&request.subject_id),
            HashPart::Str(&request.evidence_root),
            HashPart::U64(request.filed_at_height),
        ],
        32,
    )
}
pub fn deterministic_root(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}
pub fn empty_root(domain: &str) -> String {
    merkle_root(&format!("PRIVATE-L2-{domain}"), &[])
}
pub fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-CONFIDENTIAL-STATE-RENT-PAYLOAD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(value),
        ],
        32,
    )
}
pub fn state_root_from_record(record: &Value) -> String {
    payload_root("state", record)
}
pub fn public_record_root(records: &[Value]) -> String {
    merkle_root("PRIVATE-L2-CONFIDENTIAL-STATE-RENT-PUBLIC-RECORD", records)
}
pub fn record_map_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-STATE-RENT-{domain}"),
        &records,
    )
}
pub fn merkle_from_strings(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values.iter().map(|value| json!(value)).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-STATE-RENT-{domain}"),
        &leaves,
    )
}
pub fn map_set_root(domain: &str, values: &BTreeMap<String, BTreeSet<String>>) -> String {
    let leaves = values.iter().map(|(key, set)| json!({"key": key, "root": merkle_from_strings(domain, set), "len": set.len()})).collect::<Vec<_>>();
    merkle_root(
        &format!("PRIVATE-L2-CONFIDENTIAL-STATE-RENT-{domain}-MAP"),
        &leaves,
    )
}
pub fn rent_charge(units: u64, bps: u64) -> u128 {
    (units as u128)
        .saturating_mul(bps as u128)
        .div_ceil(MAX_BPS as u128)
}
pub fn compression_ratio_bps(uncompressed_units: u64, compressed_units: u64) -> u64 {
    if uncompressed_units == 0 {
        return 0;
    }
    ((compressed_units as u128).saturating_mul(MAX_BPS as u128) / uncompressed_units as u128)
        .min(MAX_BPS as u128) as u64
}
pub fn privacy_cost(uncompressed_units: u64, compressed_units: u64) -> u64 {
    let saved = uncompressed_units.saturating_sub(compressed_units);
    1 + saved.div_ceil(1024)
}
