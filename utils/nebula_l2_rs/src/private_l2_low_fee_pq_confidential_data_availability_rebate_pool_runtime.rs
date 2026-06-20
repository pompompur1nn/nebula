use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DATA_AVAILABILITY_REBATE_POOL_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-low-fee-pq-confidential-data-availability-rebate-pool-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_DATA_AVAILABILITY_REBATE_POOL_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f";
pub const CONFIDENTIAL_DA_REBATE_POOL_SUITE: &str =
    "low-fee-pq-confidential-da-rebate-pool-runtime-v1";
pub const DA_VOUCHER_POOL_SCHEME: &str = "roots-only-confidential-da-voucher-pool-v1";
pub const COMPRESSED_BLOB_RECEIPT_SCHEME: &str = "pq-confidential-compressed-blob-receipt-v1";
pub const ENCRYPTED_CALLDATA_COMMITMENT_SCHEME: &str = "pq-sealed-calldata-commitment-root-v1";
pub const SPONSOR_LIQUIDITY_SCHEME: &str = "anonymous-da-rebate-sponsor-liquidity-v1";
pub const REBATE_CLAIM_SCHEME: &str = "nullifier-bound-confidential-da-rebate-claim-v1";
pub const FEE_FUTURES_SCHEME: &str = "confidential-da-fee-futures-hedge-v1";
pub const PROOF_CACHE_CREDIT_SCHEME: &str = "recursive-proof-cache-credit-root-v1";
pub const SETTLEMENT_COUPON_SCHEME: &str = "low-fee-da-settlement-coupon-v1";
pub const PRIVACY_NULLIFIER_FENCE_SCHEME: &str = "confidential-da-nullifier-fence-v1";
pub const ORACLE_ATTESTATION_SCHEME: &str = "pq-da-cost-oracle-attestation-v1";
pub const SLASHING_EVIDENCE_SCHEME: &str = "pq-confidential-da-rebate-pool-slashing-evidence-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_HEIGHT: u64 = 2_880_640;
pub const DEVNET_EPOCH: u64 = 4_001;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_REBATE_ASSET_ID: &str = "wxmr-devnet";
pub const DEFAULT_QUOTE_ASSET_ID: &str = "dusd-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MIN_FENCE_WIDTH: u64 = 4_096;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 9;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7_250;
pub const DEFAULT_SPONSOR_COVER_BPS: u64 = 8_800;
pub const DEFAULT_SPONSOR_RESERVE_BPS: u64 = 1_400;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ORACLE_QUORUM_BPS: u64 = 8_000;
pub const DEFAULT_PROVIDER_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_REBATE_CHALLENGE_BPS: u64 = 500;
pub const DEFAULT_VOUCHER_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_BLOB_RECEIPT_TTL_BLOCKS: u64 = 192;
pub const DEFAULT_CALLDATA_TTL_BLOCKS: u64 = 64;
pub const DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_WINDOW_BLOCKS: u64 = 1_440;
pub const DEFAULT_FUTURES_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_PROOF_CACHE_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_COUPON_TTL_BLOCKS: u64 = 2_400;
pub const DEFAULT_ORACLE_TTL_BLOCKS: u64 = 32;
pub const DEFAULT_CHALLENGE_WINDOW_BLOCKS: u64 = 192;
pub const MAX_DA_VOUCHER_POOLS: usize = 1_048_576;
pub const MAX_COMPRESSED_BLOB_RECEIPTS: usize = 8_388_608;
pub const MAX_ENCRYPTED_CALLDATA_COMMITMENTS: usize = 8_388_608;
pub const MAX_SPONSOR_LIQUIDITY_ACCOUNTS: usize = 2_097_152;
pub const MAX_REBATE_CLAIMS: usize = 8_388_608;
pub const MAX_FEE_FUTURES: usize = 2_097_152;
pub const MAX_PROOF_CACHE_CREDITS: usize = 4_194_304;
pub const MAX_SETTLEMENT_COUPONS: usize = 4_194_304;
pub const MAX_PRIVACY_FENCES: usize = 8_388_608;
pub const MAX_ORACLE_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SLASHING_EVIDENCE: usize = 1_048_576;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaLane {
    PrivateContractCall,
    ConfidentialTokenTransfer,
    DefiBatchSettlement,
    RecursiveProofWitness,
    MoneroFastExit,
    OracleUpdate,
    AccountSession,
    EmergencyEscape,
}

impl DaLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateContractCall => "private_contract_call",
            Self::ConfidentialTokenTransfer => "confidential_token_transfer",
            Self::DefiBatchSettlement => "defi_batch_settlement",
            Self::RecursiveProofWitness => "recursive_proof_witness",
            Self::MoneroFastExit => "monero_fast_exit",
            Self::OracleUpdate => "oracle_update",
            Self::AccountSession => "account_session",
            Self::EmergencyEscape => "emergency_escape",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolStatus {
    Proposed,
    Open,
    Sponsored,
    Throttled,
    Settling,
    Draining,
    Closed,
    Slashed,
}

impl PoolStatus {
    pub fn accepts_vouchers(self) -> bool {
        matches!(self, Self::Open | Self::Sponsored | Self::Throttled)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlobEncoding {
    CalldataCiphertext,
    ErasureCodedCiphertext,
    RecursiveWitnessCiphertext,
    StateDiffCiphertext,
    ReceiptBundleCiphertext,
    CompressedProofTrace,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Committed,
    VoucherLinked,
    AvailabilityAttested,
    CouponIssued,
    Settled,
    Rebated,
    Challenged,
    Expired,
    Slashed,
}

impl ReceiptStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::VoucherLinked
                | Self::AvailabilityAttested
                | Self::CouponIssued
                | Self::Challenged
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Sealed,
    BlobLinked,
    VoucherReserved,
    BatchIncluded,
    Settled,
    Rebated,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorStatus {
    Pledged,
    Active,
    Reserving,
    PayingRebates,
    Exhausted,
    Paused,
    Retired,
    Slashed,
}

impl SponsorStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::Reserving | Self::PayingRebates)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Queued,
    ProofLinked,
    OraclePriced,
    CouponBound,
    Paid,
    Recycled,
    Disputed,
    Expired,
    Rejected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesSide {
    LongDaFee,
    ShortDaFee,
    SponsorHedge,
    RebateFloor,
}

impl FuturesSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LongDaFee => "long_da_fee",
            Self::ShortDaFee => "short_da_fee",
            Self::SponsorHedge => "sponsor_hedge",
            Self::RebateFloor => "rebate_floor",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuturesStatus {
    Open,
    Hedged,
    Margining,
    Settling,
    Settled,
    Liquidating,
    Liquidated,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    Redeemed,
    Expired,
    Revoked,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Issued,
    Routed,
    Redeemed,
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceStatus {
    Proposed,
    Active,
    Sealed,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Submitted,
    Quorum,
    Usable,
    Superseded,
    Disputed,
    Expired,
    Slashed,
}

impl OracleStatus {
    pub fn usable(self) -> bool {
        matches!(self, Self::Quorum | Self::Usable)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    DataWithholding,
    InvalidReceipt,
    DoubleRebate,
    OracleMisprice,
    SponsorDefault,
    NullifierReuse,
    CouponReplay,
    ProofCacheFraud,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataWithholding => "data_withholding",
            Self::InvalidReceipt => "invalid_receipt",
            Self::DoubleRebate => "double_rebate",
            Self::OracleMisprice => "oracle_misprice",
            Self::SponsorDefault => "sponsor_default",
            Self::NullifierReuse => "nullifier_reuse",
            Self::CouponReplay => "coupon_replay",
            Self::ProofCacheFraud => "proof_cache_fraud",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub quote_asset_id: String,
    pub hash_suite: String,
    pub pq_suite: String,
    pub da_voucher_pool_scheme: String,
    pub compressed_blob_receipt_scheme: String,
    pub encrypted_calldata_commitment_scheme: String,
    pub sponsor_liquidity_scheme: String,
    pub rebate_claim_scheme: String,
    pub fee_futures_scheme: String,
    pub proof_cache_credit_scheme: String,
    pub settlement_coupon_scheme: String,
    pub privacy_nullifier_fence_scheme: String,
    pub oracle_attestation_scheme: String,
    pub slashing_evidence_scheme: String,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_fence_width: u64,
    pub max_user_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub sponsor_cover_bps: u64,
    pub sponsor_reserve_bps: u64,
    pub oracle_quorum_bps: u64,
    pub strong_oracle_quorum_bps: u64,
    pub provider_slash_bps: u64,
    pub rebate_challenge_bps: u64,
    pub voucher_ttl_blocks: u64,
    pub blob_receipt_ttl_blocks: u64,
    pub calldata_ttl_blocks: u64,
    pub sponsor_epoch_blocks: u64,
    pub rebate_window_blocks: u64,
    pub futures_ttl_blocks: u64,
    pub proof_cache_ttl_blocks: u64,
    pub coupon_ttl_blocks: u64,
    pub oracle_ttl_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_da_voucher_pools: usize,
    pub max_compressed_blob_receipts: usize,
    pub max_encrypted_calldata_commitments: usize,
    pub max_sponsor_liquidity_accounts: usize,
    pub max_rebate_claims: usize,
    pub max_fee_futures: usize,
    pub max_proof_cache_credits: usize,
    pub max_settlement_coupons: usize,
    pub max_privacy_fences: usize,
    pub max_oracle_attestations: usize,
    pub max_slashing_evidence: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            quote_asset_id: DEFAULT_QUOTE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_suite: PQ_SUITE.to_string(),
            da_voucher_pool_scheme: DA_VOUCHER_POOL_SCHEME.to_string(),
            compressed_blob_receipt_scheme: COMPRESSED_BLOB_RECEIPT_SCHEME.to_string(),
            encrypted_calldata_commitment_scheme: ENCRYPTED_CALLDATA_COMMITMENT_SCHEME.to_string(),
            sponsor_liquidity_scheme: SPONSOR_LIQUIDITY_SCHEME.to_string(),
            rebate_claim_scheme: REBATE_CLAIM_SCHEME.to_string(),
            fee_futures_scheme: FEE_FUTURES_SCHEME.to_string(),
            proof_cache_credit_scheme: PROOF_CACHE_CREDIT_SCHEME.to_string(),
            settlement_coupon_scheme: SETTLEMENT_COUPON_SCHEME.to_string(),
            privacy_nullifier_fence_scheme: PRIVACY_NULLIFIER_FENCE_SCHEME.to_string(),
            oracle_attestation_scheme: ORACLE_ATTESTATION_SCHEME.to_string(),
            slashing_evidence_scheme: SLASHING_EVIDENCE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_fence_width: DEFAULT_MIN_FENCE_WIDTH,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            sponsor_cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            sponsor_reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            provider_slash_bps: DEFAULT_PROVIDER_SLASH_BPS,
            rebate_challenge_bps: DEFAULT_REBATE_CHALLENGE_BPS,
            voucher_ttl_blocks: DEFAULT_VOUCHER_TTL_BLOCKS,
            blob_receipt_ttl_blocks: DEFAULT_BLOB_RECEIPT_TTL_BLOCKS,
            calldata_ttl_blocks: DEFAULT_CALLDATA_TTL_BLOCKS,
            sponsor_epoch_blocks: DEFAULT_SPONSOR_EPOCH_BLOCKS,
            rebate_window_blocks: DEFAULT_REBATE_WINDOW_BLOCKS,
            futures_ttl_blocks: DEFAULT_FUTURES_TTL_BLOCKS,
            proof_cache_ttl_blocks: DEFAULT_PROOF_CACHE_TTL_BLOCKS,
            coupon_ttl_blocks: DEFAULT_COUPON_TTL_BLOCKS,
            oracle_ttl_blocks: DEFAULT_ORACLE_TTL_BLOCKS,
            challenge_window_blocks: DEFAULT_CHALLENGE_WINDOW_BLOCKS,
            max_da_voucher_pools: MAX_DA_VOUCHER_POOLS,
            max_compressed_blob_receipts: MAX_COMPRESSED_BLOB_RECEIPTS,
            max_encrypted_calldata_commitments: MAX_ENCRYPTED_CALLDATA_COMMITMENTS,
            max_sponsor_liquidity_accounts: MAX_SPONSOR_LIQUIDITY_ACCOUNTS,
            max_rebate_claims: MAX_REBATE_CLAIMS,
            max_fee_futures: MAX_FEE_FUTURES,
            max_proof_cache_credits: MAX_PROOF_CACHE_CREDITS,
            max_settlement_coupons: MAX_SETTLEMENT_COUPONS,
            max_privacy_fences: MAX_PRIVACY_FENCES,
            max_oracle_attestations: MAX_ORACLE_ATTESTATIONS,
            max_slashing_evidence: MAX_SLASHING_EVIDENCE,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.chain_id == CHAIN_ID, "config chain_id mismatch");
        ensure!(
            self.protocol_version == PROTOCOL_VERSION,
            "config protocol version mismatch"
        );
        ensure!(self.schema_version == SCHEMA_VERSION, "schema mismatch");
        ensure!(
            self.min_pq_security_bits >= DEFAULT_MIN_PQ_SECURITY_BITS,
            "pq security below floor"
        );
        ensure!(
            self.max_user_fee_bps <= MAX_BPS && self.target_rebate_bps <= MAX_BPS,
            "fee or rebate bps above max"
        );
        ensure!(
            self.sponsor_cover_bps <= MAX_BPS
                && self.sponsor_reserve_bps <= MAX_BPS
                && self.oracle_quorum_bps <= MAX_BPS
                && self.strong_oracle_quorum_bps <= MAX_BPS
                && self.provider_slash_bps <= MAX_BPS,
            "configured bps above max"
        );
        ensure!(
            self.strong_oracle_quorum_bps >= self.oracle_quorum_bps,
            "strong quorum below quorum"
        );
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DA-REBATE-POOL-CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub da_voucher_pools: u64,
    pub compressed_blob_receipts: u64,
    pub encrypted_calldata_commitments: u64,
    pub sponsor_liquidity_accounts: u64,
    pub rebate_claims: u64,
    pub fee_futures: u64,
    pub proof_cache_credits: u64,
    pub settlement_coupons: u64,
    pub privacy_fences: u64,
    pub oracle_attestations: u64,
    pub slashing_evidence: u64,
    pub live_voucher_pools: u64,
    pub live_blob_receipts: u64,
    pub live_rebate_claims: u64,
    pub active_sponsors: u64,
    pub active_fences: u64,
    pub total_voucher_capacity_bytes: u128,
    pub total_blob_bytes: u128,
    pub total_compressed_bytes: u128,
    pub total_sponsor_liquidity: u128,
    pub total_rebate_claimed: u128,
    pub total_rebate_paid: u128,
    pub total_fee_future_notional: u128,
    pub total_proof_cache_credit_units: u128,
    pub total_coupon_face_value: u128,
    pub total_slash_amount: u128,
}

impl Counters {
    pub fn zero() -> Self {
        Self {
            da_voucher_pools: 0,
            compressed_blob_receipts: 0,
            encrypted_calldata_commitments: 0,
            sponsor_liquidity_accounts: 0,
            rebate_claims: 0,
            fee_futures: 0,
            proof_cache_credits: 0,
            settlement_coupons: 0,
            privacy_fences: 0,
            oracle_attestations: 0,
            slashing_evidence: 0,
            live_voucher_pools: 0,
            live_blob_receipts: 0,
            live_rebate_claims: 0,
            active_sponsors: 0,
            active_fences: 0,
            total_voucher_capacity_bytes: 0,
            total_blob_bytes: 0,
            total_compressed_bytes: 0,
            total_sponsor_liquidity: 0,
            total_rebate_claimed: 0,
            total_rebate_paid: 0,
            total_fee_future_notional: 0,
            total_proof_cache_credit_units: 0,
            total_coupon_face_value: 0,
            total_slash_amount: 0,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DA-REBATE-POOL-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub da_voucher_pools_root: String,
    pub compressed_blob_receipts_root: String,
    pub encrypted_calldata_commitments_root: String,
    pub sponsor_liquidity_root: String,
    pub rebate_claims_root: String,
    pub fee_futures_root: String,
    pub proof_cache_credits_root: String,
    pub settlement_coupons_root: String,
    pub privacy_fences_root: String,
    pub oracle_attestations_root: String,
    pub slashing_evidence_root: String,
    pub nullifier_set_root: String,
    pub event_index_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DA-REBATE-POOL-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DaVoucherPool {
    pub pool_id: String,
    pub lane: DaLane,
    pub status: PoolStatus,
    pub sponsor_liquidity_id: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub voucher_capacity_bytes: u128,
    pub reserved_bytes: u128,
    pub consumed_bytes: u128,
    pub target_rebate_bps: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub voucher_epoch: u64,
    pub opened_height: u64,
    pub expires_height: u64,
    pub pool_commitment: String,
    pub voucher_root: String,
    pub sponsor_policy_root: String,
    pub metadata_root: String,
}

impl DaVoucherPool {
    pub fn available_bytes(&self) -> u128 {
        self.voucher_capacity_bytes
            .saturating_sub(self.reserved_bytes)
            .saturating_sub(self.consumed_bytes)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("DA-VOUCHER-POOL", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CompressedBlobReceipt {
    pub receipt_id: String,
    pub pool_id: String,
    pub calldata_commitment_id: String,
    pub encoding: BlobEncoding,
    pub status: ReceiptStatus,
    pub original_bytes: u128,
    pub compressed_bytes: u128,
    pub erasure_shards: u64,
    pub reconstruction_threshold: u64,
    pub fee_paid_micro_units: u128,
    pub rebate_eligible_micro_units: u128,
    pub blob_commitment_root: String,
    pub compressed_blob_root: String,
    pub erasure_shard_root: String,
    pub availability_attestation_root: String,
    pub receipt_nullifier_hash: String,
    pub provider_commitment: String,
    pub posted_height: u64,
    pub expires_height: u64,
}

impl CompressedBlobReceipt {
    pub fn compression_bps(&self) -> u64 {
        if self.original_bytes == 0 {
            0
        } else {
            self.compressed_bytes.saturating_mul(MAX_BPS as u128) as u64
                / self.original_bytes as u64
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("COMPRESSED-BLOB-RECEIPT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedCalldataCommitment {
    pub commitment_id: String,
    pub lane: DaLane,
    pub status: CommitmentStatus,
    pub sender_commitment: String,
    pub contract_commitment: String,
    pub call_selector_hash: String,
    pub encrypted_calldata_root: String,
    pub ciphertext_commitment: String,
    pub pq_encapsulation_root: String,
    pub access_policy_root: String,
    pub witness_hint_root: String,
    pub calldata_bytes_upper_bound: u128,
    pub max_fee_micro_units: u128,
    pub nullifier_hash: String,
    pub privacy_set_size: u64,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl EncryptedCalldataCommitment {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("ENCRYPTED-CALLDATA-COMMITMENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsorLiquidity {
    pub sponsor_liquidity_id: String,
    pub sponsor_commitment: String,
    pub status: SponsorStatus,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub liquidity_micro_units: u128,
    pub reserved_micro_units: u128,
    pub paid_rebates_micro_units: u128,
    pub reserve_bps: u64,
    pub cover_bps: u64,
    pub risk_limit_root: String,
    pub withdrawal_nullifier_root: String,
    pub epoch: u64,
    pub opened_height: u64,
    pub expires_height: u64,
}

impl SponsorLiquidity {
    pub fn available_micro_units(&self) -> u128 {
        self.liquidity_micro_units
            .saturating_sub(self.reserved_micro_units)
            .saturating_sub(self.paid_rebates_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("SPONSOR-LIQUIDITY", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RebateClaim {
    pub claim_id: String,
    pub receipt_id: String,
    pub pool_id: String,
    pub sponsor_liquidity_id: String,
    pub status: ClaimStatus,
    pub claimant_commitment: String,
    pub fee_paid_micro_units: u128,
    pub claimable_micro_units: u128,
    pub paid_micro_units: u128,
    pub proof_root: String,
    pub nullifier_hash: String,
    pub fence_id: String,
    pub oracle_attestation_id: String,
    pub coupon_id: String,
    pub queued_height: u64,
    pub expires_height: u64,
}

impl RebateClaim {
    pub fn unpaid_micro_units(&self) -> u128 {
        self.claimable_micro_units
            .saturating_sub(self.paid_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("REBATE-CLAIM", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeFuture {
    pub future_id: String,
    pub pool_id: String,
    pub side: FuturesSide,
    pub status: FuturesStatus,
    pub notional_micro_units: u128,
    pub margin_micro_units: u128,
    pub strike_fee_per_kb_micro_units: u64,
    pub settlement_fee_per_kb_micro_units: u64,
    pub hedge_commitment: String,
    pub owner_commitment: String,
    pub oracle_attestation_id: String,
    pub opened_height: u64,
    pub maturity_height: u64,
}

impl FeeFuture {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("FEE-FUTURE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProofCacheCredit {
    pub credit_id: String,
    pub pool_id: String,
    pub status: CreditStatus,
    pub owner_commitment: String,
    pub proof_system: String,
    pub circuit_family: String,
    pub credit_units: u128,
    pub reserved_units: u128,
    pub redeemed_units: u128,
    pub recursive_verifier_root: String,
    pub cache_key_root: String,
    pub nullifier_hash: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl ProofCacheCredit {
    pub fn remaining_units(&self) -> u128 {
        self.credit_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.redeemed_units)
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PROOF-CACHE-CREDIT", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementCoupon {
    pub coupon_id: String,
    pub pool_id: String,
    pub claim_id: String,
    pub receipt_id: String,
    pub status: CouponStatus,
    pub face_value_micro_units: u128,
    pub rebate_asset_id: String,
    pub route_commitment: String,
    pub redemption_nullifier_hash: String,
    pub settlement_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
}

impl SettlementCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("SETTLEMENT-COUPON", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyNullifierFence {
    pub fence_id: String,
    pub pool_id: String,
    pub status: FenceStatus,
    pub fence_epoch: u64,
    pub nullifier_set_root: String,
    pub spent_nullifier_root: String,
    pub claimant_set_root: String,
    pub minimum_set_size: u64,
    pub observed_set_size: u64,
    pub opened_height: u64,
    pub sealed_height: u64,
}

impl PrivacyNullifierFence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("PRIVACY-NULLIFIER-FENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OracleAttestation {
    pub oracle_attestation_id: String,
    pub pool_id: String,
    pub status: OracleStatus,
    pub fee_per_kb_micro_units: u64,
    pub compression_ratio_bps: u64,
    pub rebate_rate_bps: u64,
    pub quorum_bps: u64,
    pub signer_set_root: String,
    pub sample_root: String,
    pub signature_root: String,
    pub submitted_height: u64,
    pub expires_height: u64,
}

impl OracleAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("ORACLE-ATTESTATION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SlashingEvidence {
    pub evidence_id: String,
    pub evidence_kind: EvidenceKind,
    pub target_id: String,
    pub pool_id: String,
    pub slashed_commitment: String,
    pub status: ReceiptStatus,
    pub evidence_root: String,
    pub challenge_root: String,
    pub slash_amount_micro_units: u128,
    pub reporter_commitment: String,
    pub reported_height: u64,
    pub resolution_height: u64,
}

impl SlashingEvidence {
    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn root(&self) -> String {
        payload_root("SLASHING-EVIDENCE", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub da_voucher_pools: BTreeMap<String, DaVoucherPool>,
    pub compressed_blob_receipts: BTreeMap<String, CompressedBlobReceipt>,
    pub encrypted_calldata_commitments: BTreeMap<String, EncryptedCalldataCommitment>,
    pub sponsor_liquidity: BTreeMap<String, SponsorLiquidity>,
    pub rebate_claims: BTreeMap<String, RebateClaim>,
    pub fee_futures: BTreeMap<String, FeeFuture>,
    pub proof_cache_credits: BTreeMap<String, ProofCacheCredit>,
    pub settlement_coupons: BTreeMap<String, SettlementCoupon>,
    pub privacy_fences: BTreeMap<String, PrivacyNullifierFence>,
    pub oracle_attestations: BTreeMap<String, OracleAttestation>,
    pub slashing_evidence: BTreeMap<String, SlashingEvidence>,
    pub nullifiers: BTreeSet<String>,
    pub event_index: BTreeMap<String, String>,
    pub counters: Counters,
}

impl State {
    pub fn empty(config: Config, current_height: u64, current_epoch: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            current_height,
            current_epoch,
            da_voucher_pools: BTreeMap::new(),
            compressed_blob_receipts: BTreeMap::new(),
            encrypted_calldata_commitments: BTreeMap::new(),
            sponsor_liquidity: BTreeMap::new(),
            rebate_claims: BTreeMap::new(),
            fee_futures: BTreeMap::new(),
            proof_cache_credits: BTreeMap::new(),
            settlement_coupons: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            oracle_attestations: BTreeMap::new(),
            slashing_evidence: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            event_index: BTreeMap::new(),
            counters: Counters::zero(),
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let mut state = match Self::empty(config, DEVNET_HEIGHT, DEVNET_EPOCH) {
            Ok(state) => state,
            Err(error) => devnet_fallback_state(&error),
        };

        let sponsor_id = sponsor_liquidity_id("devnet-sponsor-alpha", DEVNET_EPOCH, 0);
        let sponsor = SponsorLiquidity {
            sponsor_liquidity_id: sponsor_id.clone(),
            sponsor_commitment: deterministic_label("SPONSOR", "devnet-sponsor-alpha"),
            status: SponsorStatus::Active,
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            liquidity_micro_units: 75_000_000_000,
            reserved_micro_units: 8_000_000_000,
            paid_rebates_micro_units: 1_250_000_000,
            reserve_bps: DEFAULT_SPONSOR_RESERVE_BPS,
            cover_bps: DEFAULT_SPONSOR_COVER_BPS,
            risk_limit_root: deterministic_label("SPONSOR-RISK", "devnet-alpha-risk"),
            withdrawal_nullifier_root: deterministic_label(
                "SPONSOR-WITHDRAWAL-NULLIFIERS",
                "devnet-alpha-withdrawals",
            ),
            epoch: DEVNET_EPOCH,
            opened_height: DEVNET_HEIGHT - 720,
            expires_height: DEVNET_HEIGHT + 21_600,
        };
        state.insert_sponsor_liquidity(sponsor);

        let pool_id = da_voucher_pool_id(DaLane::PrivateContractCall, &sponsor_id, DEVNET_EPOCH, 0);
        let pool = DaVoucherPool {
            pool_id: pool_id.clone(),
            lane: DaLane::PrivateContractCall,
            status: PoolStatus::Sponsored,
            sponsor_liquidity_id: sponsor_id.clone(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            voucher_capacity_bytes: 64 * 1024 * 1024,
            reserved_bytes: 9 * 1024 * 1024,
            consumed_bytes: 7 * 1024 * 1024,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            voucher_epoch: DEVNET_EPOCH,
            opened_height: DEVNET_HEIGHT - 96,
            expires_height: DEVNET_HEIGHT + DEFAULT_VOUCHER_TTL_BLOCKS,
            pool_commitment: deterministic_label("POOL-COMMITMENT", "devnet-contract-call"),
            voucher_root: deterministic_label("VOUCHER-ROOT", "devnet-contract-call"),
            sponsor_policy_root: deterministic_label("SPONSOR-POLICY", "devnet-contract-call"),
            metadata_root: deterministic_label("POOL-METADATA", "devnet-contract-call"),
        };
        state.insert_da_voucher_pool(pool);

        let calldata_id = encrypted_calldata_commitment_id(
            DaLane::PrivateContractCall,
            "devnet-sender-alpha",
            "devnet-contract-router",
            0,
        );
        let calldata_nullifier = nullifier_hash("calldata", "devnet-contract-call-0");
        let calldata = EncryptedCalldataCommitment {
            commitment_id: calldata_id.clone(),
            lane: DaLane::PrivateContractCall,
            status: CommitmentStatus::VoucherReserved,
            sender_commitment: deterministic_label("SENDER", "devnet-sender-alpha"),
            contract_commitment: deterministic_label("CONTRACT", "devnet-contract-router"),
            call_selector_hash: deterministic_label("CALL-SELECTOR", "settle_private_batch"),
            encrypted_calldata_root: deterministic_label("ENCRYPTED-CALLDATA", "batch-0"),
            ciphertext_commitment: deterministic_label("CALLDATA-CIPHERTEXT", "batch-0"),
            pq_encapsulation_root: deterministic_label("PQ-ENCAPSULATION", "batch-0"),
            access_policy_root: deterministic_label("ACCESS-POLICY", "batch-0"),
            witness_hint_root: deterministic_label("WITNESS-HINT", "batch-0"),
            calldata_bytes_upper_bound: 196_608,
            max_fee_micro_units: 4_800_000,
            nullifier_hash: calldata_nullifier.clone(),
            privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            submitted_height: DEVNET_HEIGHT - 12,
            expires_height: DEVNET_HEIGHT + DEFAULT_CALLDATA_TTL_BLOCKS,
        };
        state.insert_encrypted_calldata_commitment(calldata);

        let receipt_nullifier = nullifier_hash("receipt", "devnet-contract-call-0");
        let receipt_id = compressed_blob_receipt_id(&pool_id, &calldata_id, 0);
        let receipt = CompressedBlobReceipt {
            receipt_id: receipt_id.clone(),
            pool_id: pool_id.clone(),
            calldata_commitment_id: calldata_id.clone(),
            encoding: BlobEncoding::ErasureCodedCiphertext,
            status: ReceiptStatus::AvailabilityAttested,
            original_bytes: 196_608,
            compressed_bytes: 55_296,
            erasure_shards: 96,
            reconstruction_threshold: 64,
            fee_paid_micro_units: 4_200_000,
            rebate_eligible_micro_units: 3_045_000,
            blob_commitment_root: deterministic_label("BLOB-COMMITMENT", "batch-0"),
            compressed_blob_root: deterministic_label("COMPRESSED-BLOB", "batch-0"),
            erasure_shard_root: deterministic_label("ERASURE-SHARDS", "batch-0"),
            availability_attestation_root: deterministic_label("DA-ATTESTATION", "batch-0"),
            receipt_nullifier_hash: receipt_nullifier.clone(),
            provider_commitment: deterministic_label("DA-PROVIDER", "edge-provider-7"),
            posted_height: DEVNET_HEIGHT - 9,
            expires_height: DEVNET_HEIGHT + DEFAULT_BLOB_RECEIPT_TTL_BLOCKS,
        };
        state.insert_compressed_blob_receipt(receipt);

        let fence_id = privacy_fence_id(&pool_id, DEVNET_EPOCH, 0);
        let fence = PrivacyNullifierFence {
            fence_id: fence_id.clone(),
            pool_id: pool_id.clone(),
            status: FenceStatus::Active,
            fence_epoch: DEVNET_EPOCH,
            nullifier_set_root: deterministic_label("FENCE-NULLIFIER-SET", "pool-0"),
            spent_nullifier_root: deterministic_label("FENCE-SPENT-SET", "pool-0"),
            claimant_set_root: deterministic_label("FENCE-CLAIMANTS", "pool-0"),
            minimum_set_size: DEFAULT_MIN_FENCE_WIDTH,
            observed_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            opened_height: DEVNET_HEIGHT - 24,
            sealed_height: DEVNET_HEIGHT + DEFAULT_REBATE_WINDOW_BLOCKS,
        };
        state.insert_privacy_fence(fence);

        let oracle_id = oracle_attestation_id(&pool_id, 22, 2_815, 0);
        let oracle = OracleAttestation {
            oracle_attestation_id: oracle_id.clone(),
            pool_id: pool_id.clone(),
            status: OracleStatus::Usable,
            fee_per_kb_micro_units: 22,
            compression_ratio_bps: 2_815,
            rebate_rate_bps: DEFAULT_TARGET_REBATE_BPS,
            quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            signer_set_root: deterministic_label("ORACLE-SIGNERS", "da-oracle-quorum-0"),
            sample_root: deterministic_label("ORACLE-SAMPLES", "da-sample-window-0"),
            signature_root: deterministic_label("ORACLE-SIGNATURES", "da-oracle-quorum-0"),
            submitted_height: DEVNET_HEIGHT - 6,
            expires_height: DEVNET_HEIGHT + DEFAULT_ORACLE_TTL_BLOCKS,
        };
        state.insert_oracle_attestation(oracle);

        let claim_id = rebate_claim_id(&receipt_id, &sponsor_id, &receipt_nullifier);
        let coupon_id = settlement_coupon_id(&claim_id, &receipt_id, 0);
        let claim = RebateClaim {
            claim_id: claim_id.clone(),
            receipt_id: receipt_id.clone(),
            pool_id: pool_id.clone(),
            sponsor_liquidity_id: sponsor_id.clone(),
            status: ClaimStatus::CouponBound,
            claimant_commitment: deterministic_label("CLAIMANT", "devnet-user-alpha"),
            fee_paid_micro_units: 4_200_000,
            claimable_micro_units: 3_045_000,
            paid_micro_units: 0,
            proof_root: deterministic_label("REBATE-PROOF", "claim-0"),
            nullifier_hash: receipt_nullifier.clone(),
            fence_id: fence_id.clone(),
            oracle_attestation_id: oracle_id.clone(),
            coupon_id: coupon_id.clone(),
            queued_height: DEVNET_HEIGHT - 4,
            expires_height: DEVNET_HEIGHT + DEFAULT_REBATE_WINDOW_BLOCKS,
        };
        state.insert_rebate_claim(claim);

        let coupon = SettlementCoupon {
            coupon_id: coupon_id.clone(),
            pool_id: pool_id.clone(),
            claim_id: claim_id.clone(),
            receipt_id: receipt_id.clone(),
            status: CouponStatus::Issued,
            face_value_micro_units: 3_045_000,
            rebate_asset_id: DEFAULT_REBATE_ASSET_ID.to_string(),
            route_commitment: deterministic_label("COUPON-ROUTE", "claim-0"),
            redemption_nullifier_hash: nullifier_hash("coupon", "claim-0"),
            settlement_root: deterministic_label("COUPON-SETTLEMENT", "claim-0"),
            issued_height: DEVNET_HEIGHT - 3,
            expires_height: DEVNET_HEIGHT + DEFAULT_COUPON_TTL_BLOCKS,
        };
        state.insert_settlement_coupon(coupon);

        let future = FeeFuture {
            future_id: fee_future_id(&pool_id, FuturesSide::SponsorHedge, 0),
            pool_id: pool_id.clone(),
            side: FuturesSide::SponsorHedge,
            status: FuturesStatus::Hedged,
            notional_micro_units: 25_000_000,
            margin_micro_units: 4_000_000,
            strike_fee_per_kb_micro_units: 24,
            settlement_fee_per_kb_micro_units: 22,
            hedge_commitment: deterministic_label("FUTURE-HEDGE", "sponsor-alpha"),
            owner_commitment: deterministic_label("FUTURE-OWNER", "devnet-sponsor-alpha"),
            oracle_attestation_id: oracle_id.clone(),
            opened_height: DEVNET_HEIGHT - 48,
            maturity_height: DEVNET_HEIGHT + DEFAULT_FUTURES_TTL_BLOCKS,
        };
        state.insert_fee_future(future);

        let credit = ProofCacheCredit {
            credit_id: proof_cache_credit_id(&pool_id, "recursive-stark", 0),
            pool_id: pool_id.clone(),
            status: CreditStatus::Reserved,
            owner_commitment: deterministic_label("PROOF-CACHE-OWNER", "devnet-user-alpha"),
            proof_system: "recursive-stark-shake256-devnet".to_string(),
            circuit_family: "confidential-da-rebate-claim".to_string(),
            credit_units: 8_192,
            reserved_units: 2_048,
            redeemed_units: 1_024,
            recursive_verifier_root: deterministic_label("RECURSIVE-VERIFIER", "rebate-v1"),
            cache_key_root: deterministic_label("PROOF-CACHE-KEYS", "claim-0"),
            nullifier_hash: nullifier_hash("proof-cache", "claim-0"),
            issued_height: DEVNET_HEIGHT - 18,
            expires_height: DEVNET_HEIGHT + DEFAULT_PROOF_CACHE_TTL_BLOCKS,
        };
        state.insert_proof_cache_credit(credit);

        let evidence = SlashingEvidence {
            evidence_id: slashing_evidence_id(
                &pool_id,
                &receipt_id,
                EvidenceKind::DataWithholding,
                0,
            ),
            evidence_kind: EvidenceKind::DataWithholding,
            target_id: receipt_id.clone(),
            pool_id: pool_id.clone(),
            slashed_commitment: deterministic_label("SLASHED-PROVIDER", "edge-provider-7"),
            status: ReceiptStatus::Challenged,
            evidence_root: deterministic_label("SLASH-EVIDENCE", "receipt-0"),
            challenge_root: deterministic_label("SLASH-CHALLENGE", "receipt-0"),
            slash_amount_micro_units: 500_000,
            reporter_commitment: deterministic_label("REPORTER", "watchtower-alpha"),
            reported_height: DEVNET_HEIGHT - 1,
            resolution_height: DEVNET_HEIGHT + DEFAULT_CHALLENGE_WINDOW_BLOCKS,
        };
        state.insert_slashing_evidence(evidence);

        state.nullifiers.insert(calldata_nullifier);
        state.nullifiers.insert(receipt_nullifier);
        state.recompute_counters();
        state
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        ensure!(
            self.da_voucher_pools.len() <= self.config.max_da_voucher_pools,
            "too many voucher pools"
        );
        ensure!(
            self.compressed_blob_receipts.len() <= self.config.max_compressed_blob_receipts,
            "too many blob receipts"
        );
        ensure!(
            self.encrypted_calldata_commitments.len()
                <= self.config.max_encrypted_calldata_commitments,
            "too many calldata commitments"
        );
        ensure!(
            self.sponsor_liquidity.len() <= self.config.max_sponsor_liquidity_accounts,
            "too many sponsor liquidity accounts"
        );
        ensure!(
            self.rebate_claims.len() <= self.config.max_rebate_claims,
            "too many rebate claims"
        );
        ensure!(
            self.fee_futures.len() <= self.config.max_fee_futures,
            "too many fee futures"
        );
        ensure!(
            self.proof_cache_credits.len() <= self.config.max_proof_cache_credits,
            "too many proof cache credits"
        );
        ensure!(
            self.settlement_coupons.len() <= self.config.max_settlement_coupons,
            "too many settlement coupons"
        );
        ensure!(
            self.privacy_fences.len() <= self.config.max_privacy_fences,
            "too many privacy fences"
        );
        ensure!(
            self.oracle_attestations.len() <= self.config.max_oracle_attestations,
            "too many oracle attestations"
        );
        ensure!(
            self.slashing_evidence.len() <= self.config.max_slashing_evidence,
            "too much slashing evidence"
        );
        Ok(())
    }

    pub fn insert_da_voucher_pool(&mut self, pool: DaVoucherPool) {
        self.event_index.insert(
            event_id("da_voucher_pool", &pool.pool_id),
            payload_root("DA-VOUCHER-POOL-EVENT", &pool.public_record()),
        );
        self.da_voucher_pools.insert(pool.pool_id.clone(), pool);
    }

    pub fn insert_compressed_blob_receipt(&mut self, receipt: CompressedBlobReceipt) {
        self.event_index.insert(
            event_id("compressed_blob_receipt", &receipt.receipt_id),
            payload_root("COMPRESSED-BLOB-RECEIPT-EVENT", &receipt.public_record()),
        );
        self.compressed_blob_receipts
            .insert(receipt.receipt_id.clone(), receipt);
    }

    pub fn insert_encrypted_calldata_commitment(
        &mut self,
        commitment: EncryptedCalldataCommitment,
    ) {
        self.event_index.insert(
            event_id("encrypted_calldata_commitment", &commitment.commitment_id),
            payload_root(
                "ENCRYPTED-CALLDATA-COMMITMENT-EVENT",
                &commitment.public_record(),
            ),
        );
        self.encrypted_calldata_commitments
            .insert(commitment.commitment_id.clone(), commitment);
    }

    pub fn insert_sponsor_liquidity(&mut self, sponsor: SponsorLiquidity) {
        self.event_index.insert(
            event_id("sponsor_liquidity", &sponsor.sponsor_liquidity_id),
            payload_root("SPONSOR-LIQUIDITY-EVENT", &sponsor.public_record()),
        );
        self.sponsor_liquidity
            .insert(sponsor.sponsor_liquidity_id.clone(), sponsor);
    }

    pub fn insert_rebate_claim(&mut self, claim: RebateClaim) {
        self.event_index.insert(
            event_id("rebate_claim", &claim.claim_id),
            payload_root("REBATE-CLAIM-EVENT", &claim.public_record()),
        );
        self.rebate_claims.insert(claim.claim_id.clone(), claim);
    }

    pub fn insert_fee_future(&mut self, future: FeeFuture) {
        self.event_index.insert(
            event_id("fee_future", &future.future_id),
            payload_root("FEE-FUTURE-EVENT", &future.public_record()),
        );
        self.fee_futures.insert(future.future_id.clone(), future);
    }

    pub fn insert_proof_cache_credit(&mut self, credit: ProofCacheCredit) {
        self.event_index.insert(
            event_id("proof_cache_credit", &credit.credit_id),
            payload_root("PROOF-CACHE-CREDIT-EVENT", &credit.public_record()),
        );
        self.proof_cache_credits
            .insert(credit.credit_id.clone(), credit);
    }

    pub fn insert_settlement_coupon(&mut self, coupon: SettlementCoupon) {
        self.event_index.insert(
            event_id("settlement_coupon", &coupon.coupon_id),
            payload_root("SETTLEMENT-COUPON-EVENT", &coupon.public_record()),
        );
        self.settlement_coupons
            .insert(coupon.coupon_id.clone(), coupon);
    }

    pub fn insert_privacy_fence(&mut self, fence: PrivacyNullifierFence) {
        self.event_index.insert(
            event_id("privacy_fence", &fence.fence_id),
            payload_root("PRIVACY-FENCE-EVENT", &fence.public_record()),
        );
        self.privacy_fences.insert(fence.fence_id.clone(), fence);
    }

    pub fn insert_oracle_attestation(&mut self, oracle: OracleAttestation) {
        self.event_index.insert(
            event_id("oracle_attestation", &oracle.oracle_attestation_id),
            payload_root("ORACLE-ATTESTATION-EVENT", &oracle.public_record()),
        );
        self.oracle_attestations
            .insert(oracle.oracle_attestation_id.clone(), oracle);
    }

    pub fn insert_slashing_evidence(&mut self, evidence: SlashingEvidence) {
        self.event_index.insert(
            event_id("slashing_evidence", &evidence.evidence_id),
            payload_root("SLASHING-EVIDENCE-EVENT", &evidence.public_record()),
        );
        self.slashing_evidence
            .insert(evidence.evidence_id.clone(), evidence);
    }

    pub fn recompute_counters(&mut self) {
        let mut counters = Counters::zero();
        counters.da_voucher_pools = self.da_voucher_pools.len() as u64;
        counters.compressed_blob_receipts = self.compressed_blob_receipts.len() as u64;
        counters.encrypted_calldata_commitments = self.encrypted_calldata_commitments.len() as u64;
        counters.sponsor_liquidity_accounts = self.sponsor_liquidity.len() as u64;
        counters.rebate_claims = self.rebate_claims.len() as u64;
        counters.fee_futures = self.fee_futures.len() as u64;
        counters.proof_cache_credits = self.proof_cache_credits.len() as u64;
        counters.settlement_coupons = self.settlement_coupons.len() as u64;
        counters.privacy_fences = self.privacy_fences.len() as u64;
        counters.oracle_attestations = self.oracle_attestations.len() as u64;
        counters.slashing_evidence = self.slashing_evidence.len() as u64;
        for pool in self.da_voucher_pools.values() {
            if pool.status.accepts_vouchers() {
                counters.live_voucher_pools += 1;
            }
            counters.total_voucher_capacity_bytes = counters
                .total_voucher_capacity_bytes
                .saturating_add(pool.voucher_capacity_bytes);
        }
        for receipt in self.compressed_blob_receipts.values() {
            if receipt.status.live() {
                counters.live_blob_receipts += 1;
            }
            counters.total_blob_bytes = counters
                .total_blob_bytes
                .saturating_add(receipt.original_bytes);
            counters.total_compressed_bytes = counters
                .total_compressed_bytes
                .saturating_add(receipt.compressed_bytes);
        }
        for sponsor in self.sponsor_liquidity.values() {
            if sponsor.status.usable() {
                counters.active_sponsors += 1;
            }
            counters.total_sponsor_liquidity = counters
                .total_sponsor_liquidity
                .saturating_add(sponsor.liquidity_micro_units);
            counters.total_rebate_paid = counters
                .total_rebate_paid
                .saturating_add(sponsor.paid_rebates_micro_units);
        }
        for claim in self.rebate_claims.values() {
            if matches!(
                claim.status,
                ClaimStatus::Queued
                    | ClaimStatus::ProofLinked
                    | ClaimStatus::OraclePriced
                    | ClaimStatus::CouponBound
                    | ClaimStatus::Disputed
            ) {
                counters.live_rebate_claims += 1;
            }
            counters.total_rebate_claimed = counters
                .total_rebate_claimed
                .saturating_add(claim.claimable_micro_units);
        }
        for future in self.fee_futures.values() {
            counters.total_fee_future_notional = counters
                .total_fee_future_notional
                .saturating_add(future.notional_micro_units);
        }
        for credit in self.proof_cache_credits.values() {
            counters.total_proof_cache_credit_units = counters
                .total_proof_cache_credit_units
                .saturating_add(credit.credit_units);
        }
        for coupon in self.settlement_coupons.values() {
            counters.total_coupon_face_value = counters
                .total_coupon_face_value
                .saturating_add(coupon.face_value_micro_units);
        }
        for fence in self.privacy_fences.values() {
            if matches!(fence.status, FenceStatus::Proposed | FenceStatus::Active) {
                counters.active_fences += 1;
            }
        }
        for evidence in self.slashing_evidence.values() {
            counters.total_slash_amount = counters
                .total_slash_amount
                .saturating_add(evidence.slash_amount_micro_units);
        }
        self.counters = counters;
    }

    pub fn roots(&self) -> Roots {
        let nullifier_leaves = self
            .nullifiers
            .iter()
            .map(|nullifier| json!({ "nullifier_hash": nullifier }))
            .collect::<Vec<_>>();
        Roots {
            config_root: self.config.root(),
            counters_root: self.counters.root(),
            da_voucher_pools_root: map_root(
                "DA-VOUCHER-POOLS",
                &self.da_voucher_pools,
                DaVoucherPool::public_record,
            ),
            compressed_blob_receipts_root: map_root(
                "COMPRESSED-BLOB-RECEIPTS",
                &self.compressed_blob_receipts,
                CompressedBlobReceipt::public_record,
            ),
            encrypted_calldata_commitments_root: map_root(
                "ENCRYPTED-CALLDATA-COMMITMENTS",
                &self.encrypted_calldata_commitments,
                EncryptedCalldataCommitment::public_record,
            ),
            sponsor_liquidity_root: map_root(
                "SPONSOR-LIQUIDITY",
                &self.sponsor_liquidity,
                SponsorLiquidity::public_record,
            ),
            rebate_claims_root: map_root(
                "REBATE-CLAIMS",
                &self.rebate_claims,
                RebateClaim::public_record,
            ),
            fee_futures_root: map_root("FEE-FUTURES", &self.fee_futures, FeeFuture::public_record),
            proof_cache_credits_root: map_root(
                "PROOF-CACHE-CREDITS",
                &self.proof_cache_credits,
                ProofCacheCredit::public_record,
            ),
            settlement_coupons_root: map_root(
                "SETTLEMENT-COUPONS",
                &self.settlement_coupons,
                SettlementCoupon::public_record,
            ),
            privacy_fences_root: map_root(
                "PRIVACY-FENCES",
                &self.privacy_fences,
                PrivacyNullifierFence::public_record,
            ),
            oracle_attestations_root: map_root(
                "ORACLE-ATTESTATIONS",
                &self.oracle_attestations,
                OracleAttestation::public_record,
            ),
            slashing_evidence_root: map_root(
                "SLASHING-EVIDENCE-SET",
                &self.slashing_evidence,
                SlashingEvidence::public_record,
            ),
            nullifier_set_root: merkle_root("DA-REBATE-NULLIFIERS", &nullifier_leaves),
            event_index_root: event_index_root(&self.event_index),
        }
    }

    pub fn state_root(&self) -> String {
        payload_root("DA-REBATE-POOL-STATE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "private_l2_low_fee_pq_confidential_data_availability_rebate_pool_runtime",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.root(),
            "counters": self.counters.public_record(),
        })
    }
}

pub fn devnet_state() -> State {
    State::devnet()
}

pub fn devnet_state_root() -> String {
    State::devnet().state_root()
}

pub fn devnet_public_record() -> Value {
    State::devnet().public_record()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    payload_root("DA-REBATE-POOL-STATE", record)
}

pub fn private_l2_low_fee_pq_confidential_data_availability_rebate_pool_runtime_state_root(
    state: &State,
) -> String {
    state.state_root()
}

pub fn private_l2_low_fee_pq_confidential_data_availability_rebate_pool_runtime_public_record(
    state: &State,
) -> Value {
    state.public_record()
}

fn devnet_fallback_state(error: &str) -> State {
    State {
        config: Config::devnet(),
        current_height: DEVNET_HEIGHT,
        current_epoch: DEVNET_EPOCH,
        da_voucher_pools: BTreeMap::new(),
        compressed_blob_receipts: BTreeMap::new(),
        encrypted_calldata_commitments: BTreeMap::new(),
        sponsor_liquidity: BTreeMap::new(),
        rebate_claims: BTreeMap::new(),
        fee_futures: BTreeMap::new(),
        proof_cache_credits: BTreeMap::new(),
        settlement_coupons: BTreeMap::new(),
        privacy_fences: BTreeMap::new(),
        oracle_attestations: BTreeMap::new(),
        slashing_evidence: BTreeMap::new(),
        nullifiers: BTreeSet::new(),
        event_index: BTreeMap::from([(
            event_id("devnet_config_error", error),
            deterministic_label("DEVNET-CONFIG-ERROR", error),
        )]),
        counters: Counters::zero(),
    }
}

fn payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(value)],
        32,
    )
}

fn deterministic_label(domain: &str, label: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(label)], 32)
}

fn map_root<T, F>(domain: &str, values: &BTreeMap<String, T>, mut record: F) -> String
where
    F: FnMut(&T) -> Value,
{
    let leaves = values
        .iter()
        .map(|(id, value)| json!({ "id": id, "record": record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn event_index_root(events: &BTreeMap<String, String>) -> String {
    let leaves = events
        .iter()
        .map(|(id, root)| json!({ "event_id": id, "event_root": root }))
        .collect::<Vec<_>>();
    merkle_root("DA-REBATE-EVENT-INDEX", &leaves)
}

fn event_id(kind: &str, id: &str) -> String {
    domain_hash(
        "DA-REBATE-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(id),
        ],
        32,
    )
}

fn nullifier_hash(kind: &str, label: &str) -> String {
    domain_hash(
        "DA-REBATE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
        ],
        32,
    )
}

fn da_voucher_pool_id(lane: DaLane, sponsor_liquidity_id: &str, epoch: u64, nonce: u64) -> String {
    domain_hash(
        "DA-VOUCHER-POOL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sponsor_liquidity_id),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn compressed_blob_receipt_id(pool_id: &str, calldata_commitment_id: &str, nonce: u64) -> String {
    domain_hash(
        "COMPRESSED-BLOB-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(calldata_commitment_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn encrypted_calldata_commitment_id(
    lane: DaLane,
    sender_label: &str,
    contract_label: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "ENCRYPTED-CALLDATA-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(sender_label),
            HashPart::Str(contract_label),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn sponsor_liquidity_id(sponsor_label: &str, epoch: u64, nonce: u64) -> String {
    domain_hash(
        "SPONSOR-LIQUIDITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_label),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn rebate_claim_id(receipt_id: &str, sponsor_liquidity_id: &str, nullifier_hash: &str) -> String {
    domain_hash(
        "REBATE-CLAIM-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_id),
            HashPart::Str(sponsor_liquidity_id),
            HashPart::Str(nullifier_hash),
        ],
        32,
    )
}

fn fee_future_id(pool_id: &str, side: FuturesSide, nonce: u64) -> String {
    domain_hash(
        "FEE-FUTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(side.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn proof_cache_credit_id(pool_id: &str, proof_system: &str, nonce: u64) -> String {
    domain_hash(
        "PROOF-CACHE-CREDIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(proof_system),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn settlement_coupon_id(claim_id: &str, receipt_id: &str, nonce: u64) -> String {
    domain_hash(
        "SETTLEMENT-COUPON-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(claim_id),
            HashPart::Str(receipt_id),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn privacy_fence_id(pool_id: &str, epoch: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVACY-NULLIFIER-FENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::U64(epoch),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn oracle_attestation_id(
    pool_id: &str,
    fee_per_kb_micro_units: u64,
    compression_ratio_bps: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "ORACLE-ATTESTATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::U64(fee_per_kb_micro_units),
            HashPart::U64(compression_ratio_bps),
            HashPart::U64(nonce),
        ],
        32,
    )
}

fn slashing_evidence_id(
    pool_id: &str,
    target_id: &str,
    evidence_kind: EvidenceKind,
    nonce: u64,
) -> String {
    domain_hash(
        "SLASHING-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(target_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::U64(nonce),
        ],
        32,
    )
}
