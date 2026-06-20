use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractStorageRentRebateAuctionRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_RENT_REBATE_AUCTION_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-storage-rent-rebate-auction-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_STORAGE_RENT_REBATE_AUCTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-storage-rent-attestation-v1";
pub const CONFIDENTIAL_AUCTION_SCHEME: &str =
    "sealed-confidential-contract-storage-rent-rebate-auction-v1";
pub const STORAGE_COMMITMENT_SCHEME: &str =
    "private-contract-storage-slot-vector-commitment-root-v1";
pub const RENT_COUPON_SCHEME: &str = "unlinkable-low-fee-storage-rent-coupon-nullifier-v1";
pub const EVICTION_GUARD_SCHEME: &str = "pq-contract-storage-eviction-guard-receipt-v1";
pub const DEVNET_HEIGHT: u64 = 5_640_000;
pub const MAX_BPS: u64 = 10_000;
pub const MICRO_UNIT: u64 = 1_000_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_RENT_EPOCH_BLOCKS: u64 = 43_200;
pub const DEFAULT_AUCTION_TTL_BLOCKS: u64 = 360;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 86_400;
pub const DEFAULT_EVICTION_GRACE_BLOCKS: u64 = 7_200;
pub const DEFAULT_MAX_USER_RENT_FEE_BPS: u64 = 14;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8_750;
pub const DEFAULT_OPERATOR_FEE_SHARE_BPS: u64 = 1_250;
pub const DEFAULT_DUST_RENT_MICRO_UNITS: u64 = 100;
pub const DEFAULT_MIN_BUCKET_BYTES: u64 = 1_024;
pub const DEFAULT_MAX_BUCKET_BYTES: u64 = 16_777_216;
pub const MAX_STORAGE_BUCKETS: usize = 262_144;
pub const MAX_CONTRACT_COMMITMENTS: usize = 1_048_576;
pub const MAX_AUCTIONS: usize = 1_048_576;
pub const MAX_BIDS: usize = 8_388_608;
pub const MAX_ATTESTATIONS: usize = 8_388_608;
pub const MAX_COUPONS: usize = 8_388_608;
pub const MAX_EVICTION_GUARDS: usize = 2_097_152;
pub const MAX_REDACTIONS: usize = 4_194_304;
pub const MAX_OPERATOR_SUMMARIES: usize = 262_144;
pub const MAX_REBATE_EVENTS: usize = 16_777_216;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RentBucketKind {
    TinyContract,
    StandardContract,
    HeavyContract,
    ArchiveContract,
    EphemeralScratch,
    BridgeAdapter,
    GovernanceVault,
    OracleCache,
}

impl RentBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TinyContract => "tiny_contract",
            Self::StandardContract => "standard_contract",
            Self::HeavyContract => "heavy_contract",
            Self::ArchiveContract => "archive_contract",
            Self::EphemeralScratch => "ephemeral_scratch",
            Self::BridgeAdapter => "bridge_adapter",
            Self::GovernanceVault => "governance_vault",
            Self::OracleCache => "oracle_cache",
        }
    }

    pub fn privacy_weight(self) -> u64 {
        match self {
            Self::GovernanceVault => 980,
            Self::BridgeAdapter => 940,
            Self::ArchiveContract => 880,
            Self::HeavyContract => 820,
            Self::OracleCache => 760,
            Self::StandardContract => 700,
            Self::TinyContract => 640,
            Self::EphemeralScratch => 560,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Auctioning,
    RebatePending,
    RebateSettled,
    Guarded,
    EvictionQueued,
    Evicted,
    Retired,
}

impl BucketStatus {
    pub fn billable(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Auctioning | Self::RebatePending | Self::Guarded
        )
    }

    pub fn accepts_commitment(self) -> bool {
        matches!(self, Self::Open | Self::Auctioning | Self::Guarded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuctionStatus {
    Announced,
    CommitPhase,
    RevealPhase,
    Clearing,
    RebateMinted,
    Settled,
    Expired,
    Cancelled,
    Slashed,
}

impl AuctionStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Announced | Self::CommitPhase | Self::RevealPhase | Self::Clearing
        )
    }

    pub fn accepts_bid(self) -> bool {
        matches!(self, Self::Announced | Self::CommitPhase)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BidStatus {
    Committed,
    Revealed,
    Eligible,
    Winning,
    Refunded,
    Rejected,
    Slashed,
}

impl BidStatus {
    pub fn private_visible(self) -> bool {
        !matches!(self, Self::Rejected | Self::Slashed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageAttestationStatus {
    Pending,
    Verified,
    Aggregated,
    Expired,
    Disputed,
    Slashed,
}

impl StorageAttestationStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Verified | Self::Aggregated)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Reserved,
    Redeemed,
    RolledOver,
    Expired,
    Nullified,
    Slashed,
}

impl CouponStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Minted | Self::Reserved | Self::RolledOver)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardStatus {
    Armed,
    Challenged,
    Sustained,
    Released,
    EvictionPaused,
    Expired,
}

impl GuardStatus {
    pub fn blocks_eviction(self) -> bool {
        matches!(
            self,
            Self::Armed | Self::Challenged | Self::Sustained | Self::EvictionPaused
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyRedactionKind {
    ContractAddress,
    OwnerKey,
    BidAmount,
    StorageSlot,
    RentBalance,
    CouponSecret,
    AttestationWitness,
    OperatorRoute,
}

impl PrivacyRedactionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractAddress => "contract_address",
            Self::OwnerKey => "owner_key",
            Self::BidAmount => "bid_amount",
            Self::StorageSlot => "storage_slot",
            Self::RentBalance => "rent_balance",
            Self::CouponSecret => "coupon_secret",
            Self::AttestationWitness => "attestation_witness",
            Self::OperatorRoute => "operator_route",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub confidential_auction_scheme: String,
    pub storage_commitment_scheme: String,
    pub rent_coupon_scheme: String,
    pub eviction_guard_scheme: String,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub rent_epoch_blocks: u64,
    pub auction_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub eviction_grace_blocks: u64,
    pub max_user_rent_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub operator_fee_share_bps: u64,
    pub dust_rent_micro_units: u64,
    pub min_bucket_bytes: u64,
    pub max_bucket_bytes: u64,
    pub max_storage_buckets: usize,
    pub max_contract_commitments: usize,
    pub max_auctions: usize,
    pub max_bids: usize,
    pub max_attestations: usize,
    pub max_coupons: usize,
    pub max_eviction_guards: usize,
    pub max_redactions: usize,
    pub max_operator_summaries: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            confidential_auction_scheme: CONFIDENTIAL_AUCTION_SCHEME.to_string(),
            storage_commitment_scheme: STORAGE_COMMITMENT_SCHEME.to_string(),
            rent_coupon_scheme: RENT_COUPON_SCHEME.to_string(),
            eviction_guard_scheme: EVICTION_GUARD_SCHEME.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            rent_epoch_blocks: DEFAULT_RENT_EPOCH_BLOCKS,
            auction_ttl_blocks: DEFAULT_AUCTION_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            eviction_grace_blocks: DEFAULT_EVICTION_GRACE_BLOCKS,
            max_user_rent_fee_bps: DEFAULT_MAX_USER_RENT_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            operator_fee_share_bps: DEFAULT_OPERATOR_FEE_SHARE_BPS,
            dust_rent_micro_units: DEFAULT_DUST_RENT_MICRO_UNITS,
            min_bucket_bytes: DEFAULT_MIN_BUCKET_BYTES,
            max_bucket_bytes: DEFAULT_MAX_BUCKET_BYTES,
            max_storage_buckets: MAX_STORAGE_BUCKETS,
            max_contract_commitments: MAX_CONTRACT_COMMITMENTS,
            max_auctions: MAX_AUCTIONS,
            max_bids: MAX_BIDS,
            max_attestations: MAX_ATTESTATIONS,
            max_coupons: MAX_COUPONS,
            max_eviction_guards: MAX_EVICTION_GUARDS,
            max_redactions: MAX_REDACTIONS,
            max_operator_summaries: MAX_OPERATOR_SUMMARIES,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure_eq("protocol_version", &self.protocol_version, PROTOCOL_VERSION)?;
        ensure_eq("chain_id", &self.chain_id, CHAIN_ID)?;
        ensure_min("schema_version", self.schema_version, SCHEMA_VERSION)?;
        ensure_min(
            "min_privacy_set_size",
            self.min_privacy_set_size,
            DEFAULT_MIN_PRIVACY_SET_SIZE,
        )?;
        ensure_min(
            "batch_privacy_set_size",
            self.batch_privacy_set_size,
            self.min_privacy_set_size,
        )?;
        ensure_min(
            "min_pq_security_bits",
            self.min_pq_security_bits as u64,
            DEFAULT_MIN_PQ_SECURITY_BITS as u64,
        )?;
        ensure_bps("max_user_rent_fee_bps", self.max_user_rent_fee_bps)?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("operator_fee_share_bps", self.operator_fee_share_bps)?;
        if self.target_rebate_bps + self.operator_fee_share_bps > MAX_BPS {
            return Err("target rebate plus operator fee share exceeds MAX_BPS".to_string());
        }
        if self.min_bucket_bytes == 0 || self.min_bucket_bytes > self.max_bucket_bytes {
            return Err("bucket byte bounds are invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": self.chain_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "confidential_auction_scheme": self.confidential_auction_scheme,
            "storage_commitment_scheme": self.storage_commitment_scheme,
            "rent_coupon_scheme": self.rent_coupon_scheme,
            "eviction_guard_scheme": self.eviction_guard_scheme,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "rent_epoch_blocks": self.rent_epoch_blocks,
            "auction_ttl_blocks": self.auction_ttl_blocks,
            "coupon_ttl_blocks": self.coupon_ttl_blocks,
            "eviction_grace_blocks": self.eviction_grace_blocks,
            "max_user_rent_fee_bps": self.max_user_rent_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "operator_fee_share_bps": self.operator_fee_share_bps,
            "dust_rent_micro_units": self.dust_rent_micro_units,
            "min_bucket_bytes": self.min_bucket_bytes,
            "max_bucket_bytes": self.max_bucket_bytes,
            "limits": {
                "storage_buckets": self.max_storage_buckets,
                "contract_commitments": self.max_contract_commitments,
                "auctions": self.max_auctions,
                "bids": self.max_bids,
                "attestations": self.max_attestations,
                "coupons": self.max_coupons,
                "eviction_guards": self.max_eviction_guards,
                "redactions": self.max_redactions,
                "operator_summaries": self.max_operator_summaries
            }
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub storage_bucket_count: u64,
    pub open_bucket_count: u64,
    pub guarded_bucket_count: u64,
    pub contract_commitment_count: u64,
    pub active_contract_count: u64,
    pub auction_count: u64,
    pub live_auction_count: u64,
    pub bid_count: u64,
    pub eligible_bid_count: u64,
    pub winning_bid_count: u64,
    pub attestation_count: u64,
    pub verified_attestation_count: u64,
    pub coupon_count: u64,
    pub spendable_coupon_count: u64,
    pub redeemed_coupon_count: u64,
    pub eviction_guard_count: u64,
    pub active_eviction_guard_count: u64,
    pub privacy_redaction_count: u64,
    pub operator_summary_count: u64,
    pub rebate_event_count: u64,
    pub total_bucket_bytes: u64,
    pub total_committed_slots: u64,
    pub total_reserved_rebate_micro_units: u64,
    pub total_redeemed_rebate_micro_units: u64,
    pub total_operator_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub storage_buckets_root: String,
    pub contract_commitments_root: String,
    pub confidential_auctions_root: String,
    pub bid_commitments_root: String,
    pub pq_storage_attestations_root: String,
    pub rent_coupons_root: String,
    pub eviction_guards_root: String,
    pub privacy_redactions_root: String,
    pub operator_summaries_root: String,
    pub rebate_events_root: String,
    pub spent_nullifiers_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageRentBucket {
    pub bucket_id: String,
    pub epoch_id: String,
    pub kind: RentBucketKind,
    pub status: BucketStatus,
    pub byte_lower_bound: u64,
    pub byte_upper_bound: u64,
    pub observed_bytes: u64,
    pub rent_rate_micro_units_per_kib: u64,
    pub min_rebate_micro_units: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub low_fee_lane_weight: u64,
    pub contract_count: u64,
    pub commitment_root: String,
    pub auction_id: Option<String>,
    pub guard_id: Option<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub operator_hint: String,
}

impl StorageRentBucket {
    pub fn new(
        epoch_id: &str,
        kind: RentBucketKind,
        byte_lower_bound: u64,
        byte_upper_bound: u64,
        rent_rate_micro_units_per_kib: u64,
        opened_at_height: u64,
    ) -> Self {
        let bucket_id = storage_bucket_id(epoch_id, kind, byte_lower_bound, byte_upper_bound);
        Self {
            bucket_id,
            epoch_id: epoch_id.to_string(),
            kind,
            status: BucketStatus::Open,
            byte_lower_bound,
            byte_upper_bound,
            observed_bytes: 0,
            rent_rate_micro_units_per_kib,
            min_rebate_micro_units: rent_rate_micro_units_per_kib,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            low_fee_lane_weight: kind.privacy_weight(),
            contract_count: 0,
            commitment_root: empty_root("STORAGE-BUCKET-COMMITMENTS"),
            auction_id: None,
            guard_id: None,
            opened_at_height,
            expires_at_height: opened_at_height + DEFAULT_RENT_EPOCH_BLOCKS,
            operator_hint: redacted_label("bucket-operator-route"),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("bucket_id", &self.bucket_id)?;
        ensure_min(
            "byte_lower_bound",
            self.byte_lower_bound,
            config.min_bucket_bytes,
        )?;
        ensure_min(
            "byte_upper_bound",
            self.byte_upper_bound,
            self.byte_lower_bound,
        )?;
        if self.byte_upper_bound > config.max_bucket_bytes {
            return Err("bucket exceeds configured max bytes".to_string());
        }
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        ensure_min(
            "pq_security_bits",
            self.pq_security_bits as u64,
            config.min_pq_security_bits as u64,
        )?;
        Ok(())
    }

    pub fn assign_auction(&mut self, auction_id: impl Into<String>) {
        self.auction_id = Some(auction_id.into());
        self.status = BucketStatus::Auctioning;
    }

    pub fn attach_guard(&mut self, guard_id: impl Into<String>) {
        self.guard_id = Some(guard_id.into());
        self.status = BucketStatus::Guarded;
    }

    pub fn observe_contract(&mut self, bytes: u64) {
        self.observed_bytes = self.observed_bytes.saturating_add(bytes);
        self.contract_count = self.contract_count.saturating_add(1);
    }

    pub fn projected_epoch_rent(&self) -> u64 {
        kib_rent(
            self.observed_bytes.max(self.byte_lower_bound),
            self.rent_rate_micro_units_per_kib,
        )
    }

    pub fn rebate_floor(&self, target_rebate_bps: u64) -> u64 {
        bps(self.projected_epoch_rent(), target_rebate_bps).max(self.min_rebate_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bucket_id": self.bucket_id,
            "epoch_id": self.epoch_id,
            "kind": self.kind.as_str(),
            "status": self.status,
            "byte_lower_bound": self.byte_lower_bound,
            "byte_upper_bound": self.byte_upper_bound,
            "observed_bytes": self.observed_bytes,
            "rent_rate_micro_units_per_kib": self.rent_rate_micro_units_per_kib,
            "min_rebate_micro_units": self.min_rebate_micro_units,
            "privacy_set_size": self.privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "low_fee_lane_weight": self.low_fee_lane_weight,
            "contract_count": self.contract_count,
            "commitment_root": self.commitment_root,
            "auction_id": self.auction_id,
            "guard_id": self.guard_id,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "operator_hint": self.operator_hint
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractStorageCommitment {
    pub commitment_id: String,
    pub bucket_id: String,
    pub contract_commitment: String,
    pub owner_view_tag: String,
    pub code_hash: String,
    pub storage_root: String,
    pub slot_vector_commitment: String,
    pub rent_balance_commitment: String,
    pub byte_size_commitment: String,
    pub active_slot_count: u64,
    pub charged_kib: u64,
    pub paid_through_height: u64,
    pub last_touched_height: u64,
    pub pq_verifier_key_commitment: String,
    pub privacy_set_size: u64,
    pub encrypted_metadata_root: String,
}

impl ContractStorageCommitment {
    pub fn new(
        bucket_id: &str,
        contract_label: &str,
        active_slot_count: u64,
        byte_size: u64,
        height: u64,
    ) -> Self {
        let commitment_id = contract_commitment_id(bucket_id, contract_label);
        Self {
            commitment_id,
            bucket_id: bucket_id.to_string(),
            contract_commitment: commitment("CONTRACT", contract_label),
            owner_view_tag: short_tag("OWNER", contract_label),
            code_hash: commitment("CODE-HASH", contract_label),
            storage_root: commitment("STORAGE-ROOT", contract_label),
            slot_vector_commitment: commitment("SLOT-VECTOR", contract_label),
            rent_balance_commitment: commitment("RENT-BALANCE", contract_label),
            byte_size_commitment: commitment("BYTE-SIZE", &byte_size.to_string()),
            active_slot_count,
            charged_kib: ceil_kib(byte_size),
            paid_through_height: height + DEFAULT_RENT_EPOCH_BLOCKS,
            last_touched_height: height,
            pq_verifier_key_commitment: commitment("PQ-VERIFIER", contract_label),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            encrypted_metadata_root: commitment("ENCRYPTED-METADATA", contract_label),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("commitment_id", &self.commitment_id)?;
        ensure_id("bucket_id", &self.bucket_id)?;
        ensure_min("active_slot_count", self.active_slot_count, 1)?;
        ensure_min("charged_kib", self.charged_kib, 1)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        Ok(())
    }

    pub fn rent_due(&self, bucket: &StorageRentBucket, at_height: u64) -> u64 {
        if at_height <= self.paid_through_height {
            return 0;
        }
        let elapsed_epochs = 1 + (at_height - self.paid_through_height) / DEFAULT_RENT_EPOCH_BLOCKS;
        self.charged_kib
            .saturating_mul(bucket.rent_rate_micro_units_per_kib)
            .saturating_mul(elapsed_epochs)
    }

    pub fn is_eviction_risk(&self, at_height: u64, grace_blocks: u64) -> bool {
        at_height > self.paid_through_height.saturating_add(grace_blocks)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "bucket_id": self.bucket_id,
            "contract_commitment": self.contract_commitment,
            "owner_view_tag": self.owner_view_tag,
            "code_hash": self.code_hash,
            "storage_root": self.storage_root,
            "slot_vector_commitment": self.slot_vector_commitment,
            "rent_balance_commitment": self.rent_balance_commitment,
            "byte_size_commitment": self.byte_size_commitment,
            "active_slot_count": self.active_slot_count,
            "charged_kib": self.charged_kib,
            "paid_through_height": self.paid_through_height,
            "last_touched_height": self.last_touched_height,
            "pq_verifier_key_commitment": self.pq_verifier_key_commitment,
            "privacy_set_size": self.privacy_set_size,
            "encrypted_metadata_root": self.encrypted_metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfidentialRebateAuction {
    pub auction_id: String,
    pub bucket_id: String,
    pub status: AuctionStatus,
    pub epoch_id: String,
    pub sealed_bid_root: String,
    pub reveal_root: String,
    pub clearing_price_commitment: String,
    pub rebate_pool_commitment: String,
    pub minimum_rebate_micro_units: u64,
    pub target_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub operator_fee_share_bps: u64,
    pub bid_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opens_at_height: u64,
    pub reveal_at_height: u64,
    pub closes_at_height: u64,
    pub winning_bid_count: u64,
    pub settlement_coupon_root: String,
}

impl ConfidentialRebateAuction {
    pub fn new(bucket: &StorageRentBucket, config: &Config, height: u64) -> Self {
        let auction_id = auction_id(&bucket.bucket_id, &bucket.epoch_id, height);
        Self {
            auction_id,
            bucket_id: bucket.bucket_id.clone(),
            status: AuctionStatus::Announced,
            epoch_id: bucket.epoch_id.clone(),
            sealed_bid_root: empty_root("SEALED-REBATE-BIDS"),
            reveal_root: empty_root("REVEALED-REBATE-BIDS"),
            clearing_price_commitment: commitment("CLEARING-PRICE", &bucket.bucket_id),
            rebate_pool_commitment: commitment("REBATE-POOL", &bucket.bucket_id),
            minimum_rebate_micro_units: bucket.rebate_floor(config.target_rebate_bps),
            target_rebate_bps: config.target_rebate_bps,
            max_user_fee_bps: config.max_user_rent_fee_bps,
            operator_fee_share_bps: config.operator_fee_share_bps,
            bid_privacy_set_size: config.batch_privacy_set_size,
            pq_security_bits: config.min_pq_security_bits,
            opens_at_height: height,
            reveal_at_height: height + config.auction_ttl_blocks / 2,
            closes_at_height: height + config.auction_ttl_blocks,
            winning_bid_count: 0,
            settlement_coupon_root: empty_root("AUCTION-SETTLEMENT-COUPONS"),
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("auction_id", &self.auction_id)?;
        ensure_id("bucket_id", &self.bucket_id)?;
        ensure_min(
            "bid_privacy_set_size",
            self.bid_privacy_set_size,
            config.min_privacy_set_size,
        )?;
        ensure_min(
            "pq_security_bits",
            self.pq_security_bits as u64,
            config.min_pq_security_bits as u64,
        )?;
        ensure_bps("target_rebate_bps", self.target_rebate_bps)?;
        ensure_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        ensure_bps("operator_fee_share_bps", self.operator_fee_share_bps)?;
        Ok(())
    }

    pub fn start_commit_phase(&mut self) {
        if self.status == AuctionStatus::Announced {
            self.status = AuctionStatus::CommitPhase;
        }
    }

    pub fn start_reveal_phase(&mut self) {
        if self.status == AuctionStatus::CommitPhase {
            self.status = AuctionStatus::RevealPhase;
        }
    }

    pub fn mark_settled(&mut self, winning_bid_count: u64, coupon_root: String) {
        self.status = AuctionStatus::Settled;
        self.winning_bid_count = winning_bid_count;
        self.settlement_coupon_root = coupon_root;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "auction_id": self.auction_id,
            "bucket_id": self.bucket_id,
            "status": self.status,
            "epoch_id": self.epoch_id,
            "sealed_bid_root": self.sealed_bid_root,
            "reveal_root": self.reveal_root,
            "clearing_price_commitment": self.clearing_price_commitment,
            "rebate_pool_commitment": self.rebate_pool_commitment,
            "minimum_rebate_micro_units": self.minimum_rebate_micro_units,
            "target_rebate_bps": self.target_rebate_bps,
            "max_user_fee_bps": self.max_user_fee_bps,
            "operator_fee_share_bps": self.operator_fee_share_bps,
            "bid_privacy_set_size": self.bid_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opens_at_height": self.opens_at_height,
            "reveal_at_height": self.reveal_at_height,
            "closes_at_height": self.closes_at_height,
            "winning_bid_count": self.winning_bid_count,
            "settlement_coupon_root": self.settlement_coupon_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedRebateBid {
    pub bid_id: String,
    pub auction_id: String,
    pub bidder_commitment: String,
    pub status: BidStatus,
    pub sealed_amount_commitment: String,
    pub max_fee_commitment: String,
    pub coupon_destination_commitment: String,
    pub pq_bid_signature_root: String,
    pub nullifier_commitment: String,
    pub privacy_set_size: u64,
    pub submitted_at_height: u64,
    pub revealed_at_height: Option<u64>,
    pub score_commitment: String,
}

impl SealedRebateBid {
    pub fn new(auction_id: &str, bidder_label: &str, height: u64) -> Self {
        let bid_id = bid_id(auction_id, bidder_label, height);
        Self {
            bid_id,
            auction_id: auction_id.to_string(),
            bidder_commitment: commitment("BIDDER", bidder_label),
            status: BidStatus::Committed,
            sealed_amount_commitment: commitment("SEALED-AMOUNT", bidder_label),
            max_fee_commitment: commitment("MAX-FEE", bidder_label),
            coupon_destination_commitment: commitment("COUPON-DESTINATION", bidder_label),
            pq_bid_signature_root: commitment("PQ-BID-SIGNATURE", bidder_label),
            nullifier_commitment: nullifier("BID", bidder_label),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            submitted_at_height: height,
            revealed_at_height: None,
            score_commitment: commitment("BID-SCORE", bidder_label),
        }
    }

    pub fn reveal(&mut self, height: u64) {
        if self.status == BidStatus::Committed {
            self.status = BidStatus::Revealed;
            self.revealed_at_height = Some(height);
        }
    }

    pub fn mark_winning(&mut self) {
        self.status = BidStatus::Winning;
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("bid_id", &self.bid_id)?;
        ensure_id("auction_id", &self.auction_id)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bid_id": self.bid_id,
            "auction_id": self.auction_id,
            "bidder_commitment": self.bidder_commitment,
            "status": self.status,
            "sealed_amount_commitment": self.sealed_amount_commitment,
            "max_fee_commitment": self.max_fee_commitment,
            "coupon_destination_commitment": self.coupon_destination_commitment,
            "pq_bid_signature_root": self.pq_bid_signature_root,
            "nullifier_commitment": self.nullifier_commitment,
            "privacy_set_size": self.privacy_set_size,
            "submitted_at_height": self.submitted_at_height,
            "revealed_at_height": self.revealed_at_height,
            "score_commitment": self.score_commitment
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqStorageAttestation {
    pub attestation_id: String,
    pub bucket_id: String,
    pub commitment_id: String,
    pub operator_id: String,
    pub status: StorageAttestationStatus,
    pub storage_root: String,
    pub slot_sample_root: String,
    pub rent_meter_root: String,
    pub pq_signature_root: String,
    pub kem_envelope_root: String,
    pub proof_transcript_root: String,
    pub security_bits: u16,
    pub privacy_set_size: u64,
    pub measured_bytes: u64,
    pub measured_slots: u64,
    pub attested_at_height: u64,
    pub expires_at_height: u64,
}

impl PqStorageAttestation {
    pub fn new(
        bucket_id: &str,
        commitment_id: &str,
        operator_id: &str,
        measured_bytes: u64,
        measured_slots: u64,
        height: u64,
    ) -> Self {
        let attestation_id = attestation_id(bucket_id, commitment_id, operator_id, height);
        Self {
            attestation_id,
            bucket_id: bucket_id.to_string(),
            commitment_id: commitment_id.to_string(),
            operator_id: operator_id.to_string(),
            status: StorageAttestationStatus::Verified,
            storage_root: commitment("ATTESTED-STORAGE", commitment_id),
            slot_sample_root: commitment("SLOT-SAMPLE", commitment_id),
            rent_meter_root: commitment("RENT-METER", commitment_id),
            pq_signature_root: commitment("PQ-SIGNATURE", operator_id),
            kem_envelope_root: commitment("KEM-ENVELOPE", operator_id),
            proof_transcript_root: commitment("ATTESTATION-TRANSCRIPT", commitment_id),
            security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            measured_bytes,
            measured_slots,
            attested_at_height: height,
            expires_at_height: height + DEFAULT_AUCTION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("attestation_id", &self.attestation_id)?;
        ensure_min(
            "security_bits",
            self.security_bits as u64,
            config.min_pq_security_bits as u64,
        )?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        ensure_min("measured_slots", self.measured_slots, 1)?;
        Ok(())
    }

    pub fn is_fresh(&self, height: u64) -> bool {
        self.status.usable() && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "bucket_id": self.bucket_id,
            "commitment_id": self.commitment_id,
            "operator_id": self.operator_id,
            "status": self.status,
            "storage_root": self.storage_root,
            "slot_sample_root": self.slot_sample_root,
            "rent_meter_root": self.rent_meter_root,
            "pq_signature_root": self.pq_signature_root,
            "kem_envelope_root": self.kem_envelope_root,
            "proof_transcript_root": self.proof_transcript_root,
            "security_bits": self.security_bits,
            "privacy_set_size": self.privacy_set_size,
            "measured_bytes": self.measured_bytes,
            "measured_slots": self.measured_slots,
            "attested_at_height": self.attested_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RentCoupon {
    pub coupon_id: String,
    pub auction_id: String,
    pub bucket_id: String,
    pub status: CouponStatus,
    pub value_commitment: String,
    pub rebate_micro_units: u64,
    pub owner_commitment: String,
    pub spend_nullifier: String,
    pub redemption_root: String,
    pub privacy_set_size: u64,
    pub minted_at_height: u64,
    pub expires_at_height: u64,
    pub redeemed_at_height: Option<u64>,
}

impl RentCoupon {
    pub fn new(
        auction_id: &str,
        bucket_id: &str,
        owner_label: &str,
        rebate_micro_units: u64,
        height: u64,
    ) -> Self {
        let coupon_id = coupon_id(auction_id, owner_label, height);
        Self {
            coupon_id,
            auction_id: auction_id.to_string(),
            bucket_id: bucket_id.to_string(),
            status: CouponStatus::Minted,
            value_commitment: commitment("COUPON-VALUE", &rebate_micro_units.to_string()),
            rebate_micro_units,
            owner_commitment: commitment("COUPON-OWNER", owner_label),
            spend_nullifier: nullifier("RENT-COUPON", owner_label),
            redemption_root: empty_root("COUPON-REDEMPTION"),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            minted_at_height: height,
            expires_at_height: height + DEFAULT_COUPON_TTL_BLOCKS,
            redeemed_at_height: None,
        }
    }

    pub fn redeem(&mut self, height: u64) -> Result<String> {
        if !self.status.spendable() {
            return Err("coupon is not spendable".to_string());
        }
        if height > self.expires_at_height {
            self.status = CouponStatus::Expired;
            return Err("coupon expired".to_string());
        }
        self.status = CouponStatus::Redeemed;
        self.redeemed_at_height = Some(height);
        self.redemption_root = commitment("COUPON-REDEEMED", &self.coupon_id);
        Ok(self.spend_nullifier.clone())
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("coupon_id", &self.coupon_id)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        ensure_min(
            "rebate_micro_units",
            self.rebate_micro_units,
            config.dust_rent_micro_units,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "coupon_id": self.coupon_id,
            "auction_id": self.auction_id,
            "bucket_id": self.bucket_id,
            "status": self.status,
            "value_commitment": self.value_commitment,
            "rebate_micro_units": self.rebate_micro_units,
            "owner_commitment": self.owner_commitment,
            "spend_nullifier": self.spend_nullifier,
            "redemption_root": self.redemption_root,
            "privacy_set_size": self.privacy_set_size,
            "minted_at_height": self.minted_at_height,
            "expires_at_height": self.expires_at_height,
            "redeemed_at_height": self.redeemed_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EvictionGuard {
    pub guard_id: String,
    pub bucket_id: String,
    pub commitment_id: String,
    pub status: GuardStatus,
    pub challenge_commitment: String,
    pub paid_through_commitment: String,
    pub grace_deadline_height: u64,
    pub privacy_set_size: u64,
    pub pq_signature_root: String,
    pub created_at_height: u64,
    pub released_at_height: Option<u64>,
}

impl EvictionGuard {
    pub fn new(bucket_id: &str, commitment_id: &str, owner_label: &str, height: u64) -> Self {
        let guard_id = guard_id(bucket_id, commitment_id, height);
        Self {
            guard_id,
            bucket_id: bucket_id.to_string(),
            commitment_id: commitment_id.to_string(),
            status: GuardStatus::Armed,
            challenge_commitment: commitment("EVICTION-CHALLENGE", owner_label),
            paid_through_commitment: commitment("PAID-THROUGH", owner_label),
            grace_deadline_height: height + DEFAULT_EVICTION_GRACE_BLOCKS,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            pq_signature_root: commitment("EVICTION-GUARD-PQ-SIGNATURE", owner_label),
            created_at_height: height,
            released_at_height: None,
        }
    }

    pub fn release(&mut self, height: u64) {
        self.status = GuardStatus::Released;
        self.released_at_height = Some(height);
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("guard_id", &self.guard_id)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "guard_id": self.guard_id,
            "bucket_id": self.bucket_id,
            "commitment_id": self.commitment_id,
            "status": self.status,
            "challenge_commitment": self.challenge_commitment,
            "paid_through_commitment": self.paid_through_commitment,
            "grace_deadline_height": self.grace_deadline_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_signature_root": self.pq_signature_root,
            "created_at_height": self.created_at_height,
            "released_at_height": self.released_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedaction {
    pub redaction_id: String,
    pub subject_id: String,
    pub kind: PrivacyRedactionKind,
    pub redacted_root: String,
    pub replacement_commitment: String,
    pub privacy_set_size: u64,
    pub reason_code: String,
    pub created_at_height: u64,
}

impl PrivacyRedaction {
    pub fn new(
        subject_id: &str,
        kind: PrivacyRedactionKind,
        reason_code: &str,
        height: u64,
    ) -> Self {
        let redaction_id = redaction_id(subject_id, kind, height);
        Self {
            redaction_id,
            subject_id: subject_id.to_string(),
            kind,
            redacted_root: commitment("REDACTED", subject_id),
            replacement_commitment: commitment("REDACTION-REPLACEMENT", reason_code),
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            reason_code: reason_code.to_string(),
            created_at_height: height,
        }
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        ensure_id("redaction_id", &self.redaction_id)?;
        ensure_min(
            "privacy_set_size",
            self.privacy_set_size,
            config.min_privacy_set_size,
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "redaction_id": self.redaction_id,
            "subject_id": self.subject_id,
            "kind": self.kind.as_str(),
            "redacted_root": self.redacted_root,
            "replacement_commitment": self.replacement_commitment,
            "privacy_set_size": self.privacy_set_size,
            "reason_code": self.reason_code,
            "created_at_height": self.created_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub operator_id: String,
    pub operator_commitment: String,
    pub bucket_count: u64,
    pub attestation_count: u64,
    pub settled_auction_count: u64,
    pub redeemed_coupon_count: u64,
    pub guarded_contract_count: u64,
    pub rebate_volume_micro_units: u64,
    pub operator_fee_micro_units: u64,
    pub low_fee_score: u64,
    pub privacy_score: u64,
    pub pq_security_bits: u16,
    pub last_activity_height: u64,
    pub public_note_root: String,
}

impl OperatorSummary {
    pub fn new(operator_label: &str, height: u64) -> Self {
        Self {
            operator_id: operator_id(operator_label),
            operator_commitment: commitment("OPERATOR", operator_label),
            bucket_count: 0,
            attestation_count: 0,
            settled_auction_count: 0,
            redeemed_coupon_count: 0,
            guarded_contract_count: 0,
            rebate_volume_micro_units: 0,
            operator_fee_micro_units: 0,
            low_fee_score: 900,
            privacy_score: 960,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            last_activity_height: height,
            public_note_root: commitment("OPERATOR-NOTE", operator_label),
        }
    }

    pub fn record_attestation(&mut self, height: u64) {
        self.attestation_count = self.attestation_count.saturating_add(1);
        self.last_activity_height = height;
    }

    pub fn record_settlement(
        &mut self,
        rebate_micro_units: u64,
        operator_fee_bps: u64,
        height: u64,
    ) {
        self.settled_auction_count = self.settled_auction_count.saturating_add(1);
        self.rebate_volume_micro_units = self
            .rebate_volume_micro_units
            .saturating_add(rebate_micro_units);
        self.operator_fee_micro_units = self
            .operator_fee_micro_units
            .saturating_add(bps(rebate_micro_units, operator_fee_bps));
        self.last_activity_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub commitment_root: String,
    pub amount_micro_units: u64,
    pub privacy_set_size: u64,
    pub height: u64,
}

impl RebateEvent {
    pub fn new(event_kind: &str, subject_id: &str, amount_micro_units: u64, height: u64) -> Self {
        Self {
            event_id: event_id(event_kind, subject_id, height),
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            commitment_root: commitment("REBATE-EVENT", subject_id),
            amount_micro_units,
            privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch_id: String,
    pub storage_buckets: BTreeMap<String, StorageRentBucket>,
    pub contract_commitments: BTreeMap<String, ContractStorageCommitment>,
    pub confidential_auctions: BTreeMap<String, ConfidentialRebateAuction>,
    pub bid_commitments: BTreeMap<String, SealedRebateBid>,
    pub pq_storage_attestations: BTreeMap<String, PqStorageAttestation>,
    pub rent_coupons: BTreeMap<String, RentCoupon>,
    pub eviction_guards: BTreeMap<String, EvictionGuard>,
    pub privacy_redactions: BTreeMap<String, PrivacyRedaction>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub rebate_events: Vec<RebateEvent>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch_id: impl Into<String>) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            epoch_id: epoch_id.into(),
            storage_buckets: BTreeMap::new(),
            contract_commitments: BTreeMap::new(),
            confidential_auctions: BTreeMap::new(),
            bid_commitments: BTreeMap::new(),
            pq_storage_attestations: BTreeMap::new(),
            rent_coupons: BTreeMap::new(),
            eviction_guards: BTreeMap::new(),
            privacy_redactions: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            rebate_events: Vec::new(),
            spent_nullifiers: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        demo()
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure_len(
            "storage_buckets",
            self.storage_buckets.len(),
            self.config.max_storage_buckets,
        )?;
        ensure_len(
            "contract_commitments",
            self.contract_commitments.len(),
            self.config.max_contract_commitments,
        )?;
        ensure_len(
            "confidential_auctions",
            self.confidential_auctions.len(),
            self.config.max_auctions,
        )?;
        ensure_len(
            "bid_commitments",
            self.bid_commitments.len(),
            self.config.max_bids,
        )?;
        ensure_len(
            "pq_storage_attestations",
            self.pq_storage_attestations.len(),
            self.config.max_attestations,
        )?;
        ensure_len(
            "rent_coupons",
            self.rent_coupons.len(),
            self.config.max_coupons,
        )?;
        ensure_len(
            "eviction_guards",
            self.eviction_guards.len(),
            self.config.max_eviction_guards,
        )?;
        ensure_len(
            "privacy_redactions",
            self.privacy_redactions.len(),
            self.config.max_redactions,
        )?;
        ensure_len(
            "operator_summaries",
            self.operator_summaries.len(),
            self.config.max_operator_summaries,
        )?;
        for bucket in self.storage_buckets.values() {
            bucket.validate(&self.config)?;
        }
        for commitment in self.contract_commitments.values() {
            commitment.validate(&self.config)?;
            if !self.storage_buckets.contains_key(&commitment.bucket_id) {
                return Err(format!(
                    "missing bucket for commitment {}",
                    commitment.commitment_id
                ));
            }
        }
        for auction in self.confidential_auctions.values() {
            auction.validate(&self.config)?;
            if !self.storage_buckets.contains_key(&auction.bucket_id) {
                return Err(format!("missing bucket for auction {}", auction.auction_id));
            }
        }
        for bid in self.bid_commitments.values() {
            bid.validate(&self.config)?;
            if !self.confidential_auctions.contains_key(&bid.auction_id) {
                return Err(format!("missing auction for bid {}", bid.bid_id));
            }
        }
        for attestation in self.pq_storage_attestations.values() {
            attestation.validate(&self.config)?;
        }
        for coupon in self.rent_coupons.values() {
            coupon.validate(&self.config)?;
        }
        for guard in self.eviction_guards.values() {
            guard.validate(&self.config)?;
        }
        for redaction in self.privacy_redactions.values() {
            redaction.validate(&self.config)?;
        }
        Ok(())
    }

    pub fn counters(&self) -> Counters {
        Counters {
            storage_bucket_count: self.storage_buckets.len() as u64,
            open_bucket_count: self
                .storage_buckets
                .values()
                .filter(|bucket| bucket.status.accepts_commitment())
                .count() as u64,
            guarded_bucket_count: self
                .storage_buckets
                .values()
                .filter(|bucket| bucket.status == BucketStatus::Guarded)
                .count() as u64,
            contract_commitment_count: self.contract_commitments.len() as u64,
            active_contract_count: self
                .contract_commitments
                .values()
                .filter(|commitment| commitment.paid_through_height >= self.height)
                .count() as u64,
            auction_count: self.confidential_auctions.len() as u64,
            live_auction_count: self
                .confidential_auctions
                .values()
                .filter(|auction| auction.status.live())
                .count() as u64,
            bid_count: self.bid_commitments.len() as u64,
            eligible_bid_count: self
                .bid_commitments
                .values()
                .filter(|bid| matches!(bid.status, BidStatus::Eligible | BidStatus::Winning))
                .count() as u64,
            winning_bid_count: self
                .bid_commitments
                .values()
                .filter(|bid| bid.status == BidStatus::Winning)
                .count() as u64,
            attestation_count: self.pq_storage_attestations.len() as u64,
            verified_attestation_count: self
                .pq_storage_attestations
                .values()
                .filter(|attestation| attestation.status.usable())
                .count() as u64,
            coupon_count: self.rent_coupons.len() as u64,
            spendable_coupon_count: self
                .rent_coupons
                .values()
                .filter(|coupon| coupon.status.spendable())
                .count() as u64,
            redeemed_coupon_count: self
                .rent_coupons
                .values()
                .filter(|coupon| coupon.status == CouponStatus::Redeemed)
                .count() as u64,
            eviction_guard_count: self.eviction_guards.len() as u64,
            active_eviction_guard_count: self
                .eviction_guards
                .values()
                .filter(|guard| guard.status.blocks_eviction())
                .count() as u64,
            privacy_redaction_count: self.privacy_redactions.len() as u64,
            operator_summary_count: self.operator_summaries.len() as u64,
            rebate_event_count: self.rebate_events.len() as u64,
            total_bucket_bytes: self
                .storage_buckets
                .values()
                .map(|bucket| bucket.observed_bytes)
                .sum(),
            total_committed_slots: self
                .contract_commitments
                .values()
                .map(|commitment| commitment.active_slot_count)
                .sum(),
            total_reserved_rebate_micro_units: self
                .rent_coupons
                .values()
                .filter(|coupon| coupon.status.spendable())
                .map(|coupon| coupon.rebate_micro_units)
                .sum(),
            total_redeemed_rebate_micro_units: self
                .rent_coupons
                .values()
                .filter(|coupon| coupon.status == CouponStatus::Redeemed)
                .map(|coupon| coupon.rebate_micro_units)
                .sum(),
            total_operator_fee_micro_units: self
                .operator_summaries
                .values()
                .map(|summary| summary.operator_fee_micro_units)
                .sum(),
        }
    }

    pub fn roots(&self) -> Roots {
        let storage_buckets_root = map_root("STORAGE-BUCKETS", &self.storage_buckets, |v| {
            v.public_record()
        });
        let contract_commitments_root = map_root(
            "CONTRACT-STORAGE-COMMITMENTS",
            &self.contract_commitments,
            |v| v.public_record(),
        );
        let confidential_auctions_root = map_root(
            "CONFIDENTIAL-REBATE-AUCTIONS",
            &self.confidential_auctions,
            |v| v.public_record(),
        );
        let bid_commitments_root = map_root("SEALED-REBATE-BIDS", &self.bid_commitments, |v| {
            v.public_record()
        });
        let pq_storage_attestations_root = map_root(
            "PQ-STORAGE-ATTESTATIONS",
            &self.pq_storage_attestations,
            |v| v.public_record(),
        );
        let rent_coupons_root = map_root("RENT-COUPONS", &self.rent_coupons, |v| v.public_record());
        let eviction_guards_root = map_root("EVICTION-GUARDS", &self.eviction_guards, |v| {
            v.public_record()
        });
        let privacy_redactions_root =
            map_root("PRIVACY-REDACTIONS", &self.privacy_redactions, |v| {
                v.public_record()
            });
        let operator_summaries_root =
            map_root("OPERATOR-SUMMARIES", &self.operator_summaries, |v| {
                v.public_record()
            });
        let rebate_events_root = vec_root(
            "REBATE-EVENTS",
            &self
                .rebate_events
                .iter()
                .map(RebateEvent::public_record)
                .collect::<Vec<_>>(),
        );
        let spent_nullifiers_root =
            set_root("SPENT-RENT-COUPON-NULLIFIERS", &self.spent_nullifiers);
        let public_record = self.public_record_without_roots(
            &storage_buckets_root,
            &contract_commitments_root,
            &confidential_auctions_root,
            &bid_commitments_root,
            &pq_storage_attestations_root,
            &rent_coupons_root,
            &eviction_guards_root,
            &privacy_redactions_root,
            &operator_summaries_root,
            &rebate_events_root,
            &spent_nullifiers_root,
        );
        let public_record_root = root_from_record("PUBLIC-RECORD", &public_record);
        let state_root = root_from_record(
            "STATE",
            &json!({
                "protocol_version": PROTOCOL_VERSION,
                "height": self.height,
                "epoch_id": self.epoch_id,
                "public_record_root": public_record_root
            }),
        );
        Roots {
            storage_buckets_root,
            contract_commitments_root,
            confidential_auctions_root,
            bid_commitments_root,
            pq_storage_attestations_root,
            rent_coupons_root,
            eviction_guards_root,
            privacy_redactions_root,
            operator_summaries_root,
            rebate_events_root,
            spent_nullifiers_root,
            public_record_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch_id": self.epoch_id,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": roots.public_record(),
            "storage_buckets": self.storage_buckets.values().map(StorageRentBucket::public_record).collect::<Vec<_>>(),
            "contract_commitments": self.contract_commitments.values().map(ContractStorageCommitment::public_record).collect::<Vec<_>>(),
            "confidential_auctions": self.confidential_auctions.values().map(ConfidentialRebateAuction::public_record).collect::<Vec<_>>(),
            "bid_commitments": self.bid_commitments.values().filter(|bid| bid.status.private_visible()).map(SealedRebateBid::public_record).collect::<Vec<_>>(),
            "pq_storage_attestations": self.pq_storage_attestations.values().map(PqStorageAttestation::public_record).collect::<Vec<_>>(),
            "rent_coupons": self.rent_coupons.values().map(RentCoupon::public_record).collect::<Vec<_>>(),
            "eviction_guards": self.eviction_guards.values().map(EvictionGuard::public_record).collect::<Vec<_>>(),
            "privacy_redactions": self.privacy_redactions.values().map(PrivacyRedaction::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSummary::public_record).collect::<Vec<_>>(),
            "rebate_events": self.rebate_events.iter().map(RebateEvent::public_record).collect::<Vec<_>>()
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn insert_bucket(&mut self, bucket: StorageRentBucket) -> Result<()> {
        bucket.validate(&self.config)?;
        ensure_len(
            "storage_buckets",
            self.storage_buckets.len() + 1,
            self.config.max_storage_buckets,
        )?;
        self.storage_buckets
            .insert(bucket.bucket_id.clone(), bucket);
        Ok(())
    }

    pub fn insert_commitment(&mut self, commitment: ContractStorageCommitment) -> Result<()> {
        commitment.validate(&self.config)?;
        ensure_len(
            "contract_commitments",
            self.contract_commitments.len() + 1,
            self.config.max_contract_commitments,
        )?;
        let bucket = self
            .storage_buckets
            .get_mut(&commitment.bucket_id)
            .ok_or_else(|| format!("missing bucket {}", commitment.bucket_id))?;
        bucket.observe_contract(commitment.charged_kib.saturating_mul(1024));
        self.contract_commitments
            .insert(commitment.commitment_id.clone(), commitment);
        Ok(())
    }

    pub fn open_auction_for_bucket(&mut self, bucket_id: &str) -> Result<String> {
        let bucket = self
            .storage_buckets
            .get(bucket_id)
            .ok_or_else(|| format!("missing bucket {bucket_id}"))?
            .clone();
        let auction = ConfidentialRebateAuction::new(&bucket, &self.config, self.height);
        let auction_id = auction.auction_id.clone();
        ensure_len(
            "confidential_auctions",
            self.confidential_auctions.len() + 1,
            self.config.max_auctions,
        )?;
        self.confidential_auctions
            .insert(auction_id.clone(), auction);
        if let Some(bucket) = self.storage_buckets.get_mut(bucket_id) {
            bucket.assign_auction(auction_id.clone());
        }
        self.rebate_events.push(RebateEvent::new(
            "auction_opened",
            &auction_id,
            0,
            self.height,
        ));
        Ok(auction_id)
    }

    pub fn submit_bid(&mut self, bid: SealedRebateBid) -> Result<()> {
        bid.validate(&self.config)?;
        let auction = self
            .confidential_auctions
            .get(&bid.auction_id)
            .ok_or_else(|| format!("missing auction {}", bid.auction_id))?;
        if !auction.status.accepts_bid() {
            return Err("auction no longer accepts bids".to_string());
        }
        if self.spent_nullifiers.contains(&bid.nullifier_commitment) {
            return Err("bid nullifier already spent".to_string());
        }
        ensure_len(
            "bid_commitments",
            self.bid_commitments.len() + 1,
            self.config.max_bids,
        )?;
        self.bid_commitments.insert(bid.bid_id.clone(), bid);
        Ok(())
    }

    pub fn insert_attestation(&mut self, attestation: PqStorageAttestation) -> Result<()> {
        attestation.validate(&self.config)?;
        ensure_len(
            "pq_storage_attestations",
            self.pq_storage_attestations.len() + 1,
            self.config.max_attestations,
        )?;
        let operator = self
            .operator_summaries
            .entry(attestation.operator_id.clone())
            .or_insert_with(|| OperatorSummary::new(&attestation.operator_id, self.height));
        operator.record_attestation(self.height);
        self.pq_storage_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        Ok(())
    }

    pub fn mint_coupon(&mut self, coupon: RentCoupon) -> Result<()> {
        coupon.validate(&self.config)?;
        ensure_len(
            "rent_coupons",
            self.rent_coupons.len() + 1,
            self.config.max_coupons,
        )?;
        self.rebate_events.push(RebateEvent::new(
            "coupon_minted",
            &coupon.coupon_id,
            coupon.rebate_micro_units,
            self.height,
        ));
        self.rent_coupons.insert(coupon.coupon_id.clone(), coupon);
        Ok(())
    }

    pub fn redeem_coupon(&mut self, coupon_id: &str) -> Result<String> {
        let coupon = self
            .rent_coupons
            .get_mut(coupon_id)
            .ok_or_else(|| format!("missing coupon {coupon_id}"))?;
        let nullifier = coupon.redeem(self.height)?;
        if !self.spent_nullifiers.insert(nullifier.clone()) {
            return Err("coupon nullifier already spent".to_string());
        }
        self.rebate_events.push(RebateEvent::new(
            "coupon_redeemed",
            coupon_id,
            coupon.rebate_micro_units,
            self.height,
        ));
        Ok(nullifier)
    }

    pub fn arm_eviction_guard(&mut self, guard: EvictionGuard) -> Result<()> {
        guard.validate(&self.config)?;
        ensure_len(
            "eviction_guards",
            self.eviction_guards.len() + 1,
            self.config.max_eviction_guards,
        )?;
        if let Some(bucket) = self.storage_buckets.get_mut(&guard.bucket_id) {
            bucket.attach_guard(guard.guard_id.clone());
        }
        self.eviction_guards.insert(guard.guard_id.clone(), guard);
        Ok(())
    }

    pub fn add_redaction(&mut self, redaction: PrivacyRedaction) -> Result<()> {
        redaction.validate(&self.config)?;
        ensure_len(
            "privacy_redactions",
            self.privacy_redactions.len() + 1,
            self.config.max_redactions,
        )?;
        self.privacy_redactions
            .insert(redaction.redaction_id.clone(), redaction);
        Ok(())
    }

    fn public_record_without_roots(
        &self,
        storage_buckets_root: &str,
        contract_commitments_root: &str,
        confidential_auctions_root: &str,
        bid_commitments_root: &str,
        pq_storage_attestations_root: &str,
        rent_coupons_root: &str,
        eviction_guards_root: &str,
        privacy_redactions_root: &str,
        operator_summaries_root: &str,
        rebate_events_root: &str,
        spent_nullifiers_root: &str,
    ) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "epoch_id": self.epoch_id,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "roots": {
                "storage_buckets_root": storage_buckets_root,
                "contract_commitments_root": contract_commitments_root,
                "confidential_auctions_root": confidential_auctions_root,
                "bid_commitments_root": bid_commitments_root,
                "pq_storage_attestations_root": pq_storage_attestations_root,
                "rent_coupons_root": rent_coupons_root,
                "eviction_guards_root": eviction_guards_root,
                "privacy_redactions_root": privacy_redactions_root,
                "operator_summaries_root": operator_summaries_root,
                "rebate_events_root": rebate_events_root,
                "spent_nullifiers_root": spent_nullifiers_root
            }
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    let config = Config::devnet();
    let mut state = State::new(config, DEVNET_HEIGHT, "storage-rent-epoch-devnet-001")
        .expect("devnet config validates");

    let standard = StorageRentBucket::new(
        &state.epoch_id,
        RentBucketKind::StandardContract,
        1_024,
        262_144,
        12,
        state.height,
    );
    let heavy = StorageRentBucket::new(
        &state.epoch_id,
        RentBucketKind::HeavyContract,
        262_145,
        4_194_304,
        10,
        state.height,
    );
    let governance = StorageRentBucket::new(
        &state.epoch_id,
        RentBucketKind::GovernanceVault,
        16_384,
        1_048_576,
        4,
        state.height,
    );
    let standard_bucket_id = standard.bucket_id.clone();
    let heavy_bucket_id = heavy.bucket_id.clone();
    let governance_bucket_id = governance.bucket_id.clone();
    state.insert_bucket(standard).expect("standard bucket");
    state.insert_bucket(heavy).expect("heavy bucket");
    state.insert_bucket(governance).expect("governance bucket");

    let wallet_commitment = ContractStorageCommitment::new(
        &standard_bucket_id,
        "devnet-private-wallet-contract",
        64,
        97_280,
        state.height,
    );
    let dex_commitment = ContractStorageCommitment::new(
        &heavy_bucket_id,
        "devnet-confidential-dex-contract",
        512,
        1_572_864,
        state.height,
    );
    let treasury_commitment = ContractStorageCommitment::new(
        &governance_bucket_id,
        "devnet-governance-treasury-contract",
        128,
        393_216,
        state.height,
    );
    let wallet_commitment_id = wallet_commitment.commitment_id.clone();
    let dex_commitment_id = dex_commitment.commitment_id.clone();
    let treasury_commitment_id = treasury_commitment.commitment_id.clone();
    state
        .insert_commitment(wallet_commitment)
        .expect("wallet commitment");
    state
        .insert_commitment(dex_commitment)
        .expect("dex commitment");
    state
        .insert_commitment(treasury_commitment)
        .expect("treasury commitment");

    let standard_auction_id = state
        .open_auction_for_bucket(&standard_bucket_id)
        .expect("standard auction");
    let heavy_auction_id = state
        .open_auction_for_bucket(&heavy_bucket_id)
        .expect("heavy auction");
    state
        .confidential_auctions
        .get_mut(&standard_auction_id)
        .expect("standard auction exists")
        .start_commit_phase();
    state
        .confidential_auctions
        .get_mut(&heavy_auction_id)
        .expect("heavy auction exists")
        .start_commit_phase();

    let mut bid_a =
        SealedRebateBid::new(&standard_auction_id, "storage-rebate-maker-a", state.height);
    let bid_b = SealedRebateBid::new(
        &standard_auction_id,
        "storage-rebate-maker-b",
        state.height + 1,
    );
    let mut bid_c =
        SealedRebateBid::new(&heavy_auction_id, "heavy-storage-maker-a", state.height + 2);
    bid_a.reveal(state.height + 180);
    bid_a.mark_winning();
    bid_c.reveal(state.height + 181);
    bid_c.mark_winning();
    state.submit_bid(bid_a).expect("bid a");
    state.submit_bid(bid_b).expect("bid b");
    state.submit_bid(bid_c).expect("bid c");

    let attestation_a = PqStorageAttestation::new(
        &standard_bucket_id,
        &wallet_commitment_id,
        "operator-alpha",
        97_280,
        64,
        state.height + 8,
    );
    let attestation_b = PqStorageAttestation::new(
        &heavy_bucket_id,
        &dex_commitment_id,
        "operator-beta",
        1_572_864,
        512,
        state.height + 9,
    );
    let attestation_c = PqStorageAttestation::new(
        &governance_bucket_id,
        &treasury_commitment_id,
        "operator-alpha",
        393_216,
        128,
        state.height + 10,
    );
    state
        .insert_attestation(attestation_a)
        .expect("attestation a");
    state
        .insert_attestation(attestation_b)
        .expect("attestation b");
    state
        .insert_attestation(attestation_c)
        .expect("attestation c");

    let coupon_a = RentCoupon::new(
        &standard_auction_id,
        &standard_bucket_id,
        "wallet-contract-owner",
        8_500,
        state.height + 240,
    );
    let coupon_b = RentCoupon::new(
        &heavy_auction_id,
        &heavy_bucket_id,
        "dex-contract-owner",
        122_000,
        state.height + 241,
    );
    let coupon_a_id = coupon_a.coupon_id.clone();
    state.mint_coupon(coupon_a).expect("coupon a");
    state.mint_coupon(coupon_b).expect("coupon b");
    state.height += 300;
    state.redeem_coupon(&coupon_a_id).expect("redeem coupon a");

    let guard = EvictionGuard::new(
        &governance_bucket_id,
        &treasury_commitment_id,
        "treasury-contract-owner",
        state.height,
    );
    state.arm_eviction_guard(guard).expect("eviction guard");

    state
        .add_redaction(PrivacyRedaction::new(
            &wallet_commitment_id,
            PrivacyRedactionKind::ContractAddress,
            "devnet-public-record-minimization",
            state.height,
        ))
        .expect("redaction wallet");
    state
        .add_redaction(PrivacyRedaction::new(
            &standard_auction_id,
            PrivacyRedactionKind::BidAmount,
            "sealed-auction-confidentiality",
            state.height,
        ))
        .expect("redaction auction");

    if let Some(operator) = state.operator_summaries.get_mut("operator-alpha") {
        operator.bucket_count = 2;
        operator.guarded_contract_count = 1;
        operator.record_settlement(8_500, state.config.operator_fee_share_bps, state.height);
    }
    if let Some(operator) = state.operator_summaries.get_mut("operator-beta") {
        operator.bucket_count = 1;
        operator.record_settlement(122_000, state.config.operator_fee_share_bps, state.height);
    }

    let coupon_root = map_root("DEVNET-SETTLED-COUPONS", &state.rent_coupons, |coupon| {
        coupon.public_record()
    });
    if let Some(auction) = state.confidential_auctions.get_mut(&standard_auction_id) {
        auction.mark_settled(1, coupon_root.clone());
    }
    if let Some(auction) = state.confidential_auctions.get_mut(&heavy_auction_id) {
        auction.mark_settled(1, coupon_root);
    }

    state.validate().expect("demo state validates");
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn storage_bucket_id(
    epoch_id: &str,
    kind: RentBucketKind,
    byte_lower_bound: u64,
    byte_upper_bound: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-RENT-BUCKET-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(epoch_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(byte_lower_bound),
            HashPart::U64(byte_upper_bound),
        ],
        32,
    )
}

pub fn contract_commitment_id(bucket_id: &str, contract_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-STORAGE-COMMITMENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bucket_id),
            HashPart::Str(contract_label),
        ],
        32,
    )
}

pub fn auction_id(bucket_id: &str, epoch_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-REBATE-AUCTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bucket_id),
            HashPart::Str(epoch_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn bid_id(auction_id: &str, bidder_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-REBATE-BID-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(bidder_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn attestation_id(
    bucket_id: &str,
    commitment_id: &str,
    operator_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-ATTESTATION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bucket_id),
            HashPart::Str(commitment_id),
            HashPart::Str(operator_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn coupon_id(auction_id: &str, owner_label: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-RENT-COUPON-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(auction_id),
            HashPart::Str(owner_label),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn guard_id(bucket_id: &str, commitment_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-EVICTION-GUARD-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(bucket_id),
            HashPart::Str(commitment_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn redaction_id(subject_id: &str, kind: PrivacyRedactionKind, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-PRIVACY-REDACTION-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Str(kind.as_str()),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn operator_id(operator_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-REBATE-OPERATOR-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(operator_label),
        ],
        32,
    )
}

pub fn event_id(event_kind: &str, subject_id: &str, height: u64) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-REBATE-EVENT-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::U64(height),
        ],
        32,
    )
}

pub fn nullifier(scope_id: &str, secret_label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-RENT-NULLIFIER",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(scope_id),
            HashPart::Str(secret_label),
        ],
        32,
    )
}

pub fn commitment(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-RENT-COMMITMENT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn redacted_label(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-RENT-REDACTED-LABEL",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        12,
    )
}

pub fn short_tag(domain: &str, label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-STORAGE-RENT-SHORT-TAG",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(label),
        ],
        8,
    )
}

pub fn empty_root(domain: &str) -> String {
    merkle_root(
        domain,
        &[json!(domain_hash(
            "PRIVATE-L2-PQ-STORAGE-RENT-EMPTY",
            &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(domain)],
            32
        ))],
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, project: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(id, value)| {
            json!(root_from_record(
                domain,
                &json!({"id": id, "record": project(value)})
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves = set
        .iter()
        .map(|value| {
            json!(domain_hash(
                domain,
                &[
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(value)
                ],
                32
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn vec_root(domain: &str, values: &[Value]) -> String {
    let leaves = values
        .iter()
        .map(|value| json!(root_from_record(domain, value)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_eq(label: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        return Err(format!(
            "{label} mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(())
}

fn ensure_min(label: &str, actual: u64, minimum: u64) -> Result<()> {
    if actual < minimum {
        return Err(format!("{label} below minimum {minimum}: {actual}"));
    }
    Ok(())
}

fn ensure_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        return Err(format!("{label} exceeds MAX_BPS: {value}"));
    }
    Ok(())
}

fn ensure_id(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{label} cannot be empty"));
    }
    Ok(())
}

fn ensure_len(label: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(format!("{label} exceeds configured limit {max}: {len}"));
    }
    Ok(())
}

fn ceil_kib(bytes: u64) -> u64 {
    if bytes == 0 {
        0
    } else {
        1 + (bytes - 1) / 1024
    }
}

fn kib_rent(bytes: u64, rate_micro_units_per_kib: u64) -> u64 {
    ceil_kib(bytes).saturating_mul(rate_micro_units_per_kib)
}

fn bps(amount: u64, basis_points: u64) -> u64 {
    amount.saturating_mul(basis_points) / MAX_BPS
}
