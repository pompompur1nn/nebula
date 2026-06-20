use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2LowFeePqConfidentialBuilderBlobFeeNettingVaultRuntimeResult<T> = Result<T>;
pub type Runtime = State;
pub const PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BUILDER_BLOB_FEE_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION: &str = "nebula-private-l2-low-fee-pq-confidential-builder-blob-fee-netting-vault-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_LOW_FEE_PQ_CONFIDENTIAL_BUILDER_BLOB_FEE_NETTING_VAULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SEALED_BUILDER_CREDIT_SUITE: &str = "ML-KEM-1024-sealed-builder-fee-credit-v1";
pub const PQ_BUILDER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-builder-blob-fee-netting-v1";
pub const BLOB_PROOF_BUCKET_SUITE: &str = "confidential-blob-proof-cost-bucket-v1";
pub const REBATE_COUPON_SUITE: &str = "private-fee-rebate-coupon-nullifier-v1";
pub const CONGESTION_SMOOTHING_SUITE: &str = "low-fee-congestion-ewma-smoothing-v1";
pub const LOW_FEE_BATCH_NETTING_SUITE: &str = "private-low-fee-builder-batch-netting-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-no-builder-addresses-no-credit-amounts-no-blob-payloads-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-monero-private-l2-devnet";
pub const DEVNET_VAULT_ID: &str = "builder-blob-fee-netting-vault-devnet";
pub const DEVNET_L2_HEIGHT: u64 = 4_880_000;
pub const DEVNET_EPOCH: u64 = 15_250;
pub const DEFAULT_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEFAULT_BLOB_FEE_ASSET_ID: &str = "blob-gas-credit-devnet";
pub const DEFAULT_PROOF_FEE_ASSET_ID: &str = "proof-gas-credit-devnet";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 131_072;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_EPOCH_SECONDS: u64 = 600;
pub const DEFAULT_NETTING_WINDOW_SLOTS: u64 = 64;
pub const DEFAULT_COUPON_TTL_SLOTS: u64 = 8_192;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 512;
pub const DEFAULT_MIN_BATCH_ITEMS: usize = 4;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 4096;
pub const DEFAULT_MAX_BUILDER_FEE_BPS: u64 = 12;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 2;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 8;
pub const DEFAULT_SMOOTHING_ALPHA_BPS: u64 = 1_250;
pub const DEFAULT_CONGESTION_TARGET_BPS: u64 = 6_000;
pub const DEFAULT_CONGESTION_MAX_MULTIPLIER_BPS: u64 = 18_000;
pub const DEFAULT_LOW_FEE_FLOOR_MICRO_UNITS: u64 = 1_000;
pub const DEFAULT_BLOB_BYTE_PRICE_MICRO_UNITS: u64 = 9;
pub const DEFAULT_PROOF_STEP_PRICE_MICRO_UNITS: u64 = 37;
pub const MAX_BPS: u64 = 10_000;
const D_STATE: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:STATE";
const D_CONFIG: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:CONFIG";
const D_COUNTERS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:COUNTERS";
const D_ROOTS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:ROOTS";
const D_BUILDERS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:BUILDERS";
const D_CREDITS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:CREDITS";
const D_BUCKETS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:BUCKETS";
const D_ATTESTATIONS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:ATTESTATIONS";
const D_COUPONS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:COUPONS";
const D_BATCHES: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:BATCHES";
const D_SMOOTHING: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:SMOOTHING";
const D_PUBLIC_RECORDS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:PUBLIC-RECORDS";
const D_NULLIFIERS: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:NULLIFIERS";
const D_POLICY: &str = "PL2-LF-PQ-CONF-BUILDER-BLOB-FEE-NETTING-VAULT:POLICY";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CostBucketKind {
    BlobBytes,
    ProofSteps,
    RecursiveProof,
    DataAvailability,
    InclusionTip,
    RebateReserve,
}
impl CostBucketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BlobBytes => "blob_bytes",
            Self::ProofSteps => "proof_steps",
            Self::RecursiveProof => "recursive_proof",
            Self::DataAvailability => "data_availability",
            Self::InclusionTip => "inclusion_tip",
            Self::RebateReserve => "rebate_reserve",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BuilderStatus {
    Candidate,
    Active,
    Throttled,
    CoolingDown,
    Suspended,
    Retired,
}
impl BuilderStatus {
    pub fn accepts_flow(self) -> bool {
        matches!(self, Self::Active | Self::Throttled | Self::CoolingDown)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Sealed,
    Reserved,
    Netted,
    RebateMinted,
    Spent,
    Expired,
    Frozen,
}
impl CreditStatus {
    pub fn can_reserve(self) -> bool {
        matches!(self, Self::Sealed | Self::Reserved)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BucketStatus {
    Open,
    Smoothing,
    Reserved,
    Netted,
    RebateEligible,
    Exhausted,
    Frozen,
}
impl BucketStatus {
    pub fn can_use(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Smoothing | Self::Reserved | Self::RebateEligible
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerdict {
    Accept,
    Discount,
    Delay,
    Rebucket,
    Quarantine,
    Reject,
}
impl AttestationVerdict {
    pub fn allows_netting(self) -> bool {
        matches!(
            self,
            Self::Accept | Self::Discount | Self::Delay | Self::Rebucket
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    Minted,
    Nettable,
    ClaimedPrivately,
    Burned,
    Donated,
    Expired,
    Disputed,
}
impl CouponStatus {
    pub fn can_claim(self) -> bool {
        matches!(self, Self::Minted | Self::Nettable)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Proposed,
    PqAttested,
    SmoothingApplied,
    Netted,
    CouponsMinted,
    PublishedRoots,
    Disputed,
    Cancelled,
}
impl BatchStatus {
    pub fn is_final(self) -> bool {
        matches!(
            self,
            Self::CouponsMinted | Self::PublishedRoots | Self::Cancelled
        )
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicRecordKind {
    BuilderSetRoot,
    CreditRoot,
    CostBucketRoot,
    AttestationRoot,
    CouponRoot,
    BatchRoot,
    CongestionRoot,
    VaultStateRoot,
}
impl PublicRecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BuilderSetRoot => "builder_set_root",
            Self::CreditRoot => "credit_root",
            Self::CostBucketRoot => "cost_bucket_root",
            Self::AttestationRoot => "attestation_root",
            Self::CouponRoot => "coupon_root",
            Self::BatchRoot => "batch_root",
            Self::CongestionRoot => "congestion_root",
            Self::VaultStateRoot => "vault_state_root",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub l2_network: String,
    pub vault_id: String,
    pub fee_asset_id: String,
    pub blob_fee_asset_id: String,
    pub proof_fee_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub epoch_seconds: u64,
    pub netting_window_slots: u64,
    pub coupon_ttl_slots: u64,
    pub attestation_ttl_slots: u64,
    pub min_batch_items: usize,
    pub max_batch_items: usize,
    pub max_builder_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub smoothing_alpha_bps: u64,
    pub congestion_target_bps: u64,
    pub congestion_max_multiplier_bps: u64,
    pub low_fee_floor_micro_units: u64,
    pub blob_byte_price_micro_units: u64,
    pub proof_step_price_micro_units: u64,
    pub devnet_l2_height: u64,
    pub devnet_epoch: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            vault_id: DEVNET_VAULT_ID.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            blob_fee_asset_id: DEFAULT_BLOB_FEE_ASSET_ID.to_string(),
            proof_fee_asset_id: DEFAULT_PROOF_FEE_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            epoch_seconds: DEFAULT_EPOCH_SECONDS,
            netting_window_slots: DEFAULT_NETTING_WINDOW_SLOTS,
            coupon_ttl_slots: DEFAULT_COUPON_TTL_SLOTS,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            min_batch_items: DEFAULT_MIN_BATCH_ITEMS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            max_builder_fee_bps: DEFAULT_MAX_BUILDER_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            smoothing_alpha_bps: DEFAULT_SMOOTHING_ALPHA_BPS,
            congestion_target_bps: DEFAULT_CONGESTION_TARGET_BPS,
            congestion_max_multiplier_bps: DEFAULT_CONGESTION_MAX_MULTIPLIER_BPS,
            low_fee_floor_micro_units: DEFAULT_LOW_FEE_FLOOR_MICRO_UNITS,
            blob_byte_price_micro_units: DEFAULT_BLOB_BYTE_PRICE_MICRO_UNITS,
            proof_step_price_micro_units: DEFAULT_PROOF_STEP_PRICE_MICRO_UNITS,
            devnet_l2_height: DEVNET_L2_HEIGHT,
            devnet_epoch: DEVNET_EPOCH,
        }
    }
}
impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }
    pub fn public_record(&self) -> Value {
        json!({"chain_id":self.chain_id,"protocol_version":self.protocol_version,"schema_version":SCHEMA_VERSION,"hash_suite":HASH_SUITE,"sealed_builder_credit_suite":SEALED_BUILDER_CREDIT_SUITE,"pq_builder_attestation_suite":PQ_BUILDER_ATTESTATION_SUITE,"blob_proof_bucket_suite":BLOB_PROOF_BUCKET_SUITE,"rebate_coupon_suite":REBATE_COUPON_SUITE,"congestion_smoothing_suite":CONGESTION_SMOOTHING_SUITE,"low_fee_batch_netting_suite":LOW_FEE_BATCH_NETTING_SUITE,"public_record_suite":PUBLIC_RECORD_SUITE,"l2_network":self.l2_network,"vault_id":self.vault_id,"fee_asset_id":self.fee_asset_id,"blob_fee_asset_id":self.blob_fee_asset_id,"proof_fee_asset_id":self.proof_fee_asset_id,"min_privacy_set_size":self.min_privacy_set_size,"target_privacy_set_size":self.target_privacy_set_size,"min_pq_security_bits":self.min_pq_security_bits,"epoch_seconds":self.epoch_seconds,"netting_window_slots":self.netting_window_slots,"coupon_ttl_slots":self.coupon_ttl_slots,"attestation_ttl_slots":self.attestation_ttl_slots,"min_batch_items":self.min_batch_items,"max_batch_items":self.max_batch_items,"max_builder_fee_bps":self.max_builder_fee_bps,"protocol_fee_bps":self.protocol_fee_bps,"target_rebate_bps":self.target_rebate_bps,"smoothing_alpha_bps":self.smoothing_alpha_bps,"congestion_target_bps":self.congestion_target_bps,"congestion_max_multiplier_bps":self.congestion_max_multiplier_bps,"low_fee_floor_micro_units":self.low_fee_floor_micro_units,"blob_byte_price_micro_units":self.blob_byte_price_micro_units,"proof_step_price_micro_units":self.proof_step_price_micro_units,"devnet_l2_height":self.devnet_l2_height,"devnet_epoch":self.devnet_epoch})
    }
    pub fn state_root(&self) -> String {
        record_root(D_CONFIG, &self.public_record())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub builders: u64,
    pub sealed_credits: u64,
    pub cost_buckets: u64,
    pub pq_attestations: u64,
    pub rebate_coupons: u64,
    pub netting_batches: u64,
    pub smoothing_samples: u64,
    pub public_records: u64,
    pub nullifiers: u64,
    pub total_blob_bytes: u64,
    pub total_proof_steps: u64,
    pub gross_fee_micro_units: u128,
    pub netted_fee_micro_units: u128,
    pub rebate_micro_units: u128,
    pub saved_fee_micro_units: u128,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_COUNTERS, &self.public_record())
    }
}
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub builder_root: String,
    pub sealed_credit_root: String,
    pub cost_bucket_root: String,
    pub pq_attestation_root: String,
    pub rebate_coupon_root: String,
    pub netting_batch_root: String,
    pub congestion_smoothing_root: String,
    pub public_record_root: String,
    pub nullifier_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_ROOTS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuilderProfile {
    pub builder_id: String,
    pub status: BuilderStatus,
    pub pq_key_commitment: String,
    pub sealed_credit_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub reputation_score_bps: u64,
    pub admitted_epoch: u64,
    pub last_attested_slot: u64,
    pub throttled_until_slot: u64,
    pub tags: BTreeSet<String>,
}
impl BuilderProfile {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_BUILDERS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedBuilderFeeCredit {
    pub credit_id: String,
    pub builder_id: String,
    pub status: CreditStatus,
    pub sealed_amount_commitment: String,
    pub fee_asset_id: String,
    pub epoch: u64,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub bucket_ids: BTreeSet<String>,
    pub nullifier_commitment: String,
    pub pq_envelope_root: String,
    pub low_fee_hint_bps: u64,
}
impl SealedBuilderFeeCredit {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_CREDITS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlobProofCostBucket {
    pub bucket_id: String,
    pub builder_id: String,
    pub kind: CostBucketKind,
    pub status: BucketStatus,
    pub slot: u64,
    pub blob_bytes: u64,
    pub proof_steps: u64,
    pub gross_cost_micro_units: u128,
    pub smoothed_cost_micro_units: u128,
    pub reserved_credit_micro_units: u128,
    pub nettable_discount_bps: u64,
    pub congestion_multiplier_bps: u64,
    pub commitment: String,
}
impl BlobProofCostBucket {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_BUCKETS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqBuilderAttestation {
    pub attestation_id: String,
    pub builder_id: String,
    pub batch_id: String,
    pub verdict: AttestationVerdict,
    pub slot: u64,
    pub expires_at_slot: u64,
    pub pq_scheme: String,
    pub pq_public_key_commitment: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub claimed_bucket_root: String,
    pub claimed_credit_root: String,
    pub claimed_privacy_set_size: u64,
    pub claimed_security_bits: u16,
}
impl PqBuilderAttestation {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_ATTESTATIONS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebateCoupon {
    pub coupon_id: String,
    pub builder_id: String,
    pub batch_id: String,
    pub status: CouponStatus,
    pub minted_slot: u64,
    pub expires_at_slot: u64,
    pub sealed_value_commitment: String,
    pub rebate_asset_id: String,
    pub nullifier_hash: String,
    pub redemption_root: String,
    pub privacy_set_size: u64,
}
impl FeeRebateCoupon {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_COUPONS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CongestionSmoothingSample {
    pub sample_id: String,
    pub slot: u64,
    pub bucket_kind: CostBucketKind,
    pub observed_load_bps: u64,
    pub ewma_load_bps: u64,
    pub multiplier_bps: u64,
    pub fee_floor_micro_units: u64,
    pub sample_root: String,
}
impl CongestionSmoothingSample {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_SMOOTHING, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeBatchNetting {
    pub batch_id: String,
    pub status: BatchStatus,
    pub epoch: u64,
    pub open_slot: u64,
    pub close_slot: u64,
    pub builder_ids: BTreeSet<String>,
    pub credit_ids: BTreeSet<String>,
    pub bucket_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub coupon_ids: BTreeSet<String>,
    pub gross_fee_micro_units: u128,
    pub netted_fee_micro_units: u128,
    pub rebate_micro_units: u128,
    pub saved_fee_micro_units: u128,
    pub batch_transcript_root: String,
    pub public_root: String,
}
impl LowFeeBatchNetting {
    pub fn public_record(&self) -> Value {
        json!({"batch_id":self.batch_id,"status":self.status,"epoch":self.epoch,"open_slot":self.open_slot,"close_slot":self.close_slot,"builder_count":self.builder_ids.len(),"credit_count":self.credit_ids.len(),"bucket_count":self.bucket_ids.len(),"attestation_count":self.attestation_ids.len(),"coupon_count":self.coupon_ids.len(),"gross_fee_micro_units":self.gross_fee_micro_units,"netted_fee_micro_units":self.netted_fee_micro_units,"rebate_micro_units":self.rebate_micro_units,"saved_fee_micro_units":self.saved_fee_micro_units,"batch_transcript_root":self.batch_transcript_root,"public_root":self.public_root})
    }
    pub fn state_root(&self) -> String {
        record_root(D_BATCHES, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RootsOnlyPublicRecord {
    pub record_id: String,
    pub kind: PublicRecordKind,
    pub slot: u64,
    pub subject_root: String,
    pub state_root: String,
    pub redaction_policy: String,
}
impl RootsOnlyPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_PUBLIC_RECORDS, &self.public_record())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterBuilderInput {
    pub builder_id: String,
    pub pq_key_commitment: String,
    pub sealed_credit_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub max_fee_bps: u64,
    pub tags: BTreeSet<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealCreditInput {
    pub credit_id: String,
    pub builder_id: String,
    pub sealed_amount_commitment: String,
    pub fee_asset_id: String,
    pub slot: u64,
    pub bucket_ids: BTreeSet<String>,
    pub nullifier_commitment: String,
    pub pq_envelope_root: String,
    pub low_fee_hint_bps: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenCostBucketInput {
    pub bucket_id: String,
    pub builder_id: String,
    pub kind: CostBucketKind,
    pub slot: u64,
    pub blob_bytes: u64,
    pub proof_steps: u64,
    pub reserved_credit_micro_units: u128,
    pub nettable_discount_bps: u64,
    pub commitment: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitAttestationInput {
    pub attestation_id: String,
    pub builder_id: String,
    pub batch_id: String,
    pub verdict: AttestationVerdict,
    pub slot: u64,
    pub pq_public_key_commitment: String,
    pub transcript_root: String,
    pub signature_root: String,
    pub claimed_bucket_root: String,
    pub claimed_credit_root: String,
    pub claimed_privacy_set_size: u64,
    pub claimed_security_bits: u16,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProposeBatchInput {
    pub batch_id: String,
    pub epoch: u64,
    pub open_slot: u64,
    pub close_slot: u64,
    pub builder_ids: BTreeSet<String>,
    pub credit_ids: BTreeSet<String>,
    pub bucket_ids: BTreeSet<String>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MintRebateCouponInput {
    pub coupon_id: String,
    pub builder_id: String,
    pub batch_id: String,
    pub minted_slot: u64,
    pub sealed_value_commitment: String,
    pub nullifier_hash: String,
    pub redemption_root: String,
    pub privacy_set_size: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub builders: BTreeMap<String, BuilderProfile>,
    pub sealed_credits: BTreeMap<String, SealedBuilderFeeCredit>,
    pub cost_buckets: BTreeMap<String, BlobProofCostBucket>,
    pub pq_attestations: BTreeMap<String, PqBuilderAttestation>,
    pub rebate_coupons: BTreeMap<String, FeeRebateCoupon>,
    pub netting_batches: BTreeMap<String, LowFeeBatchNetting>,
    pub smoothing_samples: BTreeMap<String, CongestionSmoothingSample>,
    pub public_records: BTreeMap<String, RootsOnlyPublicRecord>,
    pub nullifiers: BTreeSet<String>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            config: Config::default(),
            builders: BTreeMap::new(),
            sealed_credits: BTreeMap::new(),
            cost_buckets: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            rebate_coupons: BTreeMap::new(),
            netting_batches: BTreeMap::new(),
            smoothing_samples: BTreeMap::new(),
            public_records: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
        }
    }
}
impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }
    pub fn devnet() -> Self {
        devnet()
    }
    pub fn counters(&self) -> Counters {
        Counters {
            builders: self.builders.len() as u64,
            sealed_credits: self.sealed_credits.len() as u64,
            cost_buckets: self.cost_buckets.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            rebate_coupons: self.rebate_coupons.len() as u64,
            netting_batches: self.netting_batches.len() as u64,
            smoothing_samples: self.smoothing_samples.len() as u64,
            public_records: self.public_records.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            total_blob_bytes: self.cost_buckets.values().map(|b| b.blob_bytes).sum(),
            total_proof_steps: self.cost_buckets.values().map(|b| b.proof_steps).sum(),
            gross_fee_micro_units: self
                .netting_batches
                .values()
                .map(|b| b.gross_fee_micro_units)
                .sum(),
            netted_fee_micro_units: self
                .netting_batches
                .values()
                .map(|b| b.netted_fee_micro_units)
                .sum(),
            rebate_micro_units: self
                .netting_batches
                .values()
                .map(|b| b.rebate_micro_units)
                .sum(),
            saved_fee_micro_units: self
                .netting_batches
                .values()
                .map(|b| b.saved_fee_micro_units)
                .sum(),
        }
    }
    pub fn register_builder(&mut self, input: RegisterBuilderInput) -> Result<String> {
        if self.builders.contains_key(&input.builder_id) {
            return Err(format!("builder already registered: {}", input.builder_id));
        }
        if input.privacy_set_size < self.config.min_privacy_set_size {
            return Err("builder privacy set below minimum".to_string());
        }
        if input.pq_security_bits < self.config.min_pq_security_bits {
            return Err("builder pq security below minimum".to_string());
        }
        if input.max_fee_bps > self.config.max_builder_fee_bps {
            return Err("builder fee cap exceeds vault maximum".to_string());
        }
        let p = BuilderProfile {
            builder_id: input.builder_id.clone(),
            status: BuilderStatus::Active,
            pq_key_commitment: input.pq_key_commitment,
            sealed_credit_root: input.sealed_credit_root,
            privacy_set_size: input.privacy_set_size,
            pq_security_bits: input.pq_security_bits,
            max_fee_bps: input.max_fee_bps,
            reputation_score_bps: MAX_BPS,
            admitted_epoch: self.config.devnet_epoch,
            last_attested_slot: 0,
            throttled_until_slot: 0,
            tags: input.tags,
        };
        let root = p.state_root();
        self.builders.insert(input.builder_id, p);
        Ok(root)
    }
    pub fn seal_builder_fee_credit(&mut self, input: SealCreditInput) -> Result<String> {
        let b = self
            .builders
            .get(&input.builder_id)
            .ok_or_else(|| format!("unknown builder: {}", input.builder_id))?;
        if !b.status.accepts_flow() {
            return Err("builder cannot seal credits while inactive".to_string());
        }
        if self.sealed_credits.contains_key(&input.credit_id) {
            return Err(format!("credit already exists: {}", input.credit_id));
        }
        if self.nullifiers.contains(&input.nullifier_commitment) {
            return Err("duplicate sealed credit nullifier".to_string());
        }
        let c = SealedBuilderFeeCredit {
            credit_id: input.credit_id.clone(),
            builder_id: input.builder_id,
            status: CreditStatus::Sealed,
            sealed_amount_commitment: input.sealed_amount_commitment,
            fee_asset_id: input.fee_asset_id,
            epoch: self.config.devnet_epoch,
            slot: input.slot,
            expires_at_slot: input.slot.saturating_add(self.config.coupon_ttl_slots),
            bucket_ids: input.bucket_ids,
            nullifier_commitment: input.nullifier_commitment.clone(),
            pq_envelope_root: input.pq_envelope_root,
            low_fee_hint_bps: input.low_fee_hint_bps.min(self.config.max_builder_fee_bps),
        };
        let root = c.state_root();
        self.nullifiers.insert(input.nullifier_commitment);
        self.sealed_credits.insert(input.credit_id, c);
        Ok(root)
    }
    pub fn open_cost_bucket(&mut self, input: OpenCostBucketInput) -> Result<String> {
        if self.cost_buckets.contains_key(&input.bucket_id) {
            return Err(format!("bucket already exists: {}", input.bucket_id));
        }
        if !self.builders.contains_key(&input.builder_id) {
            return Err(format!("unknown builder: {}", input.builder_id));
        }
        let gross = self.estimate_gross_cost(input.blob_bytes, input.proof_steps, input.kind);
        let sample = self.latest_smoothing(input.kind);
        let smoothed = apply_bps(gross, sample.multiplier_bps);
        let b = BlobProofCostBucket {
            bucket_id: input.bucket_id.clone(),
            builder_id: input.builder_id,
            kind: input.kind,
            status: BucketStatus::Open,
            slot: input.slot,
            blob_bytes: input.blob_bytes,
            proof_steps: input.proof_steps,
            gross_cost_micro_units: gross,
            smoothed_cost_micro_units: smoothed.max(self.config.low_fee_floor_micro_units as u128),
            reserved_credit_micro_units: input.reserved_credit_micro_units,
            nettable_discount_bps: input.nettable_discount_bps.min(MAX_BPS),
            congestion_multiplier_bps: sample.multiplier_bps,
            commitment: input.commitment,
        };
        let root = b.state_root();
        self.cost_buckets.insert(input.bucket_id, b);
        Ok(root)
    }
    pub fn add_smoothing_sample(
        &mut self,
        slot: u64,
        kind: CostBucketKind,
        observed_load_bps: u64,
    ) -> Result<String> {
        let prev = self.latest_smoothing(kind);
        let alpha = self.config.smoothing_alpha_bps.min(MAX_BPS);
        let ewma = ((observed_load_bps as u128 * alpha as u128
            + prev.ewma_load_bps as u128 * (MAX_BPS - alpha) as u128)
            / MAX_BPS as u128) as u64;
        let pressure = if self.config.congestion_target_bps == 0 {
            MAX_BPS
        } else {
            ewma.saturating_mul(MAX_BPS) / self.config.congestion_target_bps
        };
        let multiplier = pressure.clamp(MAX_BPS / 2, self.config.congestion_max_multiplier_bps);
        let sample_id = record_root(
            D_SMOOTHING,
            &json!([slot, kind.as_str(), observed_load_bps, ewma, multiplier]),
        );
        let sample_root = record_root(
            D_SMOOTHING,
            &json!({"slot":slot,"kind":kind,"ewma":ewma,"multiplier":multiplier}),
        );
        let s = CongestionSmoothingSample {
            sample_id: sample_id.clone(),
            slot,
            bucket_kind: kind,
            observed_load_bps,
            ewma_load_bps: ewma,
            multiplier_bps: multiplier,
            fee_floor_micro_units: self.config.low_fee_floor_micro_units,
            sample_root,
        };
        let root = s.state_root();
        self.smoothing_samples.insert(sample_id, s);
        Ok(root)
    }
    pub fn submit_pq_builder_attestation(
        &mut self,
        input: SubmitAttestationInput,
    ) -> Result<String> {
        let b = self
            .builders
            .get_mut(&input.builder_id)
            .ok_or_else(|| format!("unknown builder: {}", input.builder_id))?;
        if input.claimed_privacy_set_size < self.config.min_privacy_set_size {
            return Err("attestation privacy set below minimum".to_string());
        }
        if input.claimed_security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security below minimum".to_string());
        }
        let a = PqBuilderAttestation {
            attestation_id: input.attestation_id.clone(),
            builder_id: input.builder_id,
            batch_id: input.batch_id,
            verdict: input.verdict,
            slot: input.slot,
            expires_at_slot: input.slot.saturating_add(self.config.attestation_ttl_slots),
            pq_scheme: PQ_BUILDER_ATTESTATION_SUITE.to_string(),
            pq_public_key_commitment: input.pq_public_key_commitment,
            transcript_root: input.transcript_root,
            signature_root: input.signature_root,
            claimed_bucket_root: input.claimed_bucket_root,
            claimed_credit_root: input.claimed_credit_root,
            claimed_privacy_set_size: input.claimed_privacy_set_size,
            claimed_security_bits: input.claimed_security_bits,
        };
        b.last_attested_slot = input.slot;
        let root = a.state_root();
        self.pq_attestations.insert(input.attestation_id, a);
        Ok(root)
    }
    pub fn propose_low_fee_batch(&mut self, input: ProposeBatchInput) -> Result<String> {
        if self.netting_batches.contains_key(&input.batch_id) {
            return Err(format!("batch already exists: {}", input.batch_id));
        }
        if input.bucket_ids.len() < self.config.min_batch_items {
            return Err("batch below minimum item count".to_string());
        }
        if input.bucket_ids.len() > self.config.max_batch_items {
            return Err("batch above maximum item count".to_string());
        }
        for id in &input.builder_ids {
            if !self.builders.contains_key(id) {
                return Err(format!("unknown builder in batch: {}", id));
            }
        }
        let mut gross = 0u128;
        let mut netted = 0u128;
        for id in &input.bucket_ids {
            let b = self
                .cost_buckets
                .get(id)
                .ok_or_else(|| format!("unknown bucket in batch: {}", id))?;
            if !b.status.can_use() {
                return Err(format!("bucket cannot net: {}", id));
            }
            gross = gross.saturating_add(b.gross_cost_micro_units);
            let discounted = apply_bps(
                b.smoothed_cost_micro_units,
                MAX_BPS.saturating_sub(b.nettable_discount_bps),
            );
            netted = netted.saturating_add(discounted);
        }
        let protocol = apply_bps(netted, self.config.protocol_fee_bps);
        netted = netted.saturating_add(protocol);
        let rebate = apply_bps(gross.saturating_sub(netted), self.config.target_rebate_bps);
        let saved = gross.saturating_sub(netted);
        let transcript = record_root(
            D_BATCHES,
            &json!({"batch_id":input.batch_id,"builders":input.builder_ids,"credits":input.credit_ids,"buckets":input.bucket_ids,"gross":gross,"netted":netted,"rebate":rebate}),
        );
        let public_root = record_root(
            D_BATCHES,
            &json!({"batch_id":input.batch_id,"gross_root":record_root(D_BATCHES,&json!(gross)),"netted_root":record_root(D_BATCHES,&json!(netted)),"saved_root":record_root(D_BATCHES,&json!(saved))}),
        );
        let batch = LowFeeBatchNetting {
            batch_id: input.batch_id.clone(),
            status: BatchStatus::Proposed,
            epoch: input.epoch,
            open_slot: input.open_slot,
            close_slot: input.close_slot,
            builder_ids: input.builder_ids,
            credit_ids: input.credit_ids,
            bucket_ids: input.bucket_ids,
            attestation_ids: BTreeSet::new(),
            coupon_ids: BTreeSet::new(),
            gross_fee_micro_units: gross,
            netted_fee_micro_units: netted,
            rebate_micro_units: rebate,
            saved_fee_micro_units: saved,
            batch_transcript_root: transcript,
            public_root,
        };
        let root = batch.state_root();
        self.netting_batches.insert(input.batch_id, batch);
        Ok(root)
    }
    pub fn attach_attestation_to_batch(
        &mut self,
        batch_id: &str,
        attestation_id: &str,
    ) -> Result<String> {
        let att = self
            .pq_attestations
            .get(attestation_id)
            .ok_or_else(|| format!("unknown attestation: {}", attestation_id))?;
        if !att.verdict.allows_netting() {
            return Err("attestation verdict blocks netting".to_string());
        }
        let batch = self
            .netting_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {}", batch_id))?;
        batch.attestation_ids.insert(attestation_id.to_string());
        batch.status = BatchStatus::PqAttested;
        Ok(batch.state_root())
    }
    pub fn finalize_batch_netting(&mut self, batch_id: &str) -> Result<String> {
        let batch = self
            .netting_batches
            .get_mut(batch_id)
            .ok_or_else(|| format!("unknown batch: {}", batch_id))?;
        if batch.attestation_ids.is_empty() {
            return Err("batch requires pq builder attestation".to_string());
        }
        for id in &batch.bucket_ids {
            if let Some(bucket) = self.cost_buckets.get_mut(id) {
                bucket.status = BucketStatus::Netted;
            }
        }
        for id in &batch.credit_ids {
            if let Some(credit) = self.sealed_credits.get_mut(id) {
                if credit.status.can_reserve() {
                    credit.status = CreditStatus::Netted;
                }
            }
        }
        batch.status = BatchStatus::Netted;
        Ok(batch.state_root())
    }
    pub fn mint_rebate_coupon(&mut self, input: MintRebateCouponInput) -> Result<String> {
        if self.rebate_coupons.contains_key(&input.coupon_id) {
            return Err(format!("coupon already exists: {}", input.coupon_id));
        }
        if self.nullifiers.contains(&input.nullifier_hash) {
            return Err("duplicate coupon nullifier".to_string());
        }
        let batch = self
            .netting_batches
            .get_mut(&input.batch_id)
            .ok_or_else(|| format!("unknown batch: {}", input.batch_id))?;
        if !matches!(
            batch.status,
            BatchStatus::Netted | BatchStatus::CouponsMinted
        ) {
            return Err("batch must be netted before coupon mint".to_string());
        }
        let c = FeeRebateCoupon {
            coupon_id: input.coupon_id.clone(),
            builder_id: input.builder_id,
            batch_id: input.batch_id.clone(),
            status: CouponStatus::Minted,
            minted_slot: input.minted_slot,
            expires_at_slot: input
                .minted_slot
                .saturating_add(self.config.coupon_ttl_slots),
            sealed_value_commitment: input.sealed_value_commitment,
            rebate_asset_id: self.config.fee_asset_id.clone(),
            nullifier_hash: input.nullifier_hash.clone(),
            redemption_root: input.redemption_root,
            privacy_set_size: input.privacy_set_size,
        };
        let root = c.state_root();
        batch.coupon_ids.insert(input.coupon_id.clone());
        batch.status = BatchStatus::CouponsMinted;
        self.nullifiers.insert(input.nullifier_hash);
        self.rebate_coupons.insert(input.coupon_id, c);
        Ok(root)
    }
    pub fn publish_roots_only_record(
        &mut self,
        kind: PublicRecordKind,
        slot: u64,
        subject_root: String,
    ) -> Result<String> {
        let state_root = self.state_root();
        let record_id = record_root(
            D_PUBLIC_RECORDS,
            &json!([kind.as_str(), slot, subject_root, state_root]),
        );
        let r = RootsOnlyPublicRecord {
            record_id: record_id.clone(),
            kind,
            slot,
            subject_root,
            state_root,
            redaction_policy: PUBLIC_RECORD_SUITE.to_string(),
        };
        let root = r.state_root();
        self.public_records.insert(record_id, r);
        Ok(root)
    }
    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.state_root(),
            counters_root: self.counters().state_root(),
            builder_root: map_root(D_BUILDERS, &self.builders),
            sealed_credit_root: map_root(D_CREDITS, &self.sealed_credits),
            cost_bucket_root: map_root(D_BUCKETS, &self.cost_buckets),
            pq_attestation_root: map_root(D_ATTESTATIONS, &self.pq_attestations),
            rebate_coupon_root: map_root(D_COUPONS, &self.rebate_coupons),
            netting_batch_root: map_root(D_BATCHES, &self.netting_batches),
            congestion_smoothing_root: map_root(D_SMOOTHING, &self.smoothing_samples),
            public_record_root: map_root(D_PUBLIC_RECORDS, &self.public_records),
            nullifier_root: set_root(D_NULLIFIERS, &self.nullifiers),
        }
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({"protocol_version":self.config.protocol_version,"schema_version":SCHEMA_VERSION,"privacy_boundary":PUBLIC_RECORD_SUITE,"config":self.config.public_record(),"counters":self.counters().public_record(),"roots":roots.public_record(),"state_root":roots.state_root()})
    }
    pub fn state_root(&self) -> String {
        record_root(
            D_STATE,
            &json!({"roots":self.roots().public_record(),"counters":self.counters().public_record()}),
        )
    }
    fn estimate_gross_cost(&self, blob_bytes: u64, proof_steps: u64, kind: CostBucketKind) -> u128 {
        let blob = blob_bytes as u128 * self.config.blob_byte_price_micro_units as u128;
        let proof = proof_steps as u128 * self.config.proof_step_price_micro_units as u128;
        let base = blob
            .saturating_add(proof)
            .max(self.config.low_fee_floor_micro_units as u128);
        apply_bps(base, kind_multiplier_bps(kind))
    }
    fn latest_smoothing(&self, kind: CostBucketKind) -> CongestionSmoothingSample {
        self.smoothing_samples
            .values()
            .filter(|s| s.bucket_kind == kind)
            .max_by_key(|s| s.slot)
            .cloned()
            .unwrap_or(CongestionSmoothingSample {
                sample_id: "genesis".to_string(),
                slot: 0,
                bucket_kind: kind,
                observed_load_bps: self.config.congestion_target_bps,
                ewma_load_bps: self.config.congestion_target_bps,
                multiplier_bps: MAX_BPS,
                fee_floor_micro_units: self.config.low_fee_floor_micro_units,
                sample_root: record_root(D_SMOOTHING, &json!("genesis")),
            })
    }
}
pub fn devnet() -> State {
    let mut state = State::new(Config::devnet());
    let mut tags = BTreeSet::new();
    tags.insert("devnet-builder".to_string());
    tags.insert("monero-private-l2".to_string());
    let _ = state.register_builder(RegisterBuilderInput {
        builder_id: "builder-devnet-alpha".to_string(),
        pq_key_commitment: record_root(D_BUILDERS, &json!("ml-dsa-devnet-alpha")),
        sealed_credit_root: record_root(D_CREDITS, &json!("sealed-credit-genesis")),
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        max_fee_bps: 6,
        tags,
    });
    let _ = state.add_smoothing_sample(DEVNET_L2_HEIGHT, CostBucketKind::BlobBytes, 5_200);
    let _ = state.add_smoothing_sample(DEVNET_L2_HEIGHT, CostBucketKind::ProofSteps, 4_800);
    let mut bucket_ids = BTreeSet::new();
    for i in 0..4 {
        let id = format!("bucket-devnet-alpha-{i}");
        let _ = state.open_cost_bucket(OpenCostBucketInput {
            bucket_id: id.clone(),
            builder_id: "builder-devnet-alpha".to_string(),
            kind: if i % 2 == 0 {
                CostBucketKind::BlobBytes
            } else {
                CostBucketKind::ProofSteps
            },
            slot: DEVNET_L2_HEIGHT + i,
            blob_bytes: 131_072 + (i * 2048),
            proof_steps: 4096 + (i * 128),
            reserved_credit_micro_units: 20_000,
            nettable_discount_bps: 650,
            commitment: record_root(D_BUCKETS, &json!(["devnet", i])),
        });
        bucket_ids.insert(id);
    }
    let credit_ids = BTreeSet::from(["credit-devnet-alpha-0".to_string()]);
    let _ = state.seal_builder_fee_credit(SealCreditInput {
        credit_id: "credit-devnet-alpha-0".to_string(),
        builder_id: "builder-devnet-alpha".to_string(),
        sealed_amount_commitment: record_root(D_CREDITS, &json!("sealed-amount")),
        fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
        slot: DEVNET_L2_HEIGHT,
        bucket_ids: bucket_ids.clone(),
        nullifier_commitment: record_root(D_NULLIFIERS, &json!("credit-nullifier")),
        pq_envelope_root: record_root(D_CREDITS, &json!("pq-envelope")),
        low_fee_hint_bps: 5,
    });
    let builder_ids = BTreeSet::from(["builder-devnet-alpha".to_string()]);
    let _ = state.propose_low_fee_batch(ProposeBatchInput {
        batch_id: "batch-devnet-alpha-0".to_string(),
        epoch: DEVNET_EPOCH,
        open_slot: DEVNET_L2_HEIGHT,
        close_slot: DEVNET_L2_HEIGHT + 32,
        builder_ids,
        credit_ids,
        bucket_ids,
    });
    let _ = state.submit_pq_builder_attestation(SubmitAttestationInput {
        attestation_id: "attestation-devnet-alpha-0".to_string(),
        builder_id: "builder-devnet-alpha".to_string(),
        batch_id: "batch-devnet-alpha-0".to_string(),
        verdict: AttestationVerdict::Accept,
        slot: DEVNET_L2_HEIGHT + 33,
        pq_public_key_commitment: record_root(D_ATTESTATIONS, &json!("pq-key")),
        transcript_root: record_root(D_ATTESTATIONS, &json!("transcript")),
        signature_root: record_root(D_ATTESTATIONS, &json!("signature")),
        claimed_bucket_root: state.roots().cost_bucket_root,
        claimed_credit_root: state.roots().sealed_credit_root,
        claimed_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
        claimed_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
    });
    let _ = state.attach_attestation_to_batch("batch-devnet-alpha-0", "attestation-devnet-alpha-0");
    let _ = state.finalize_batch_netting("batch-devnet-alpha-0");
    let _ = state.mint_rebate_coupon(MintRebateCouponInput {
        coupon_id: "coupon-devnet-alpha-0".to_string(),
        builder_id: "builder-devnet-alpha".to_string(),
        batch_id: "batch-devnet-alpha-0".to_string(),
        minted_slot: DEVNET_L2_HEIGHT + 40,
        sealed_value_commitment: record_root(D_COUPONS, &json!("sealed-rebate")),
        nullifier_hash: record_root(D_NULLIFIERS, &json!("coupon-nullifier")),
        redemption_root: record_root(D_COUPONS, &json!("redeem")),
        privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
    });
    let _ = state.publish_roots_only_record(
        PublicRecordKind::VaultStateRoot,
        DEVNET_L2_HEIGHT + 41,
        state.state_root(),
    );
    state
}
fn kind_multiplier_bps(kind: CostBucketKind) -> u64 {
    match kind {
        CostBucketKind::BlobBytes => 9_500,
        CostBucketKind::ProofSteps => 9_250,
        CostBucketKind::RecursiveProof => 10_500,
        CostBucketKind::DataAvailability => 11_500,
        CostBucketKind::InclusionTip => 7_500,
        CostBucketKind::RebateReserve => 5_000,
    }
}
fn apply_bps(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}
fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}
fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves: Vec<String> = map
        .iter()
        .map(|(k, v)| record_root(domain, &json!({"key":k,"value":v})))
        .collect();
    merkle_root(domain, &leaves)
}
fn set_root(domain: &str, set: &BTreeSet<String>) -> String {
    let leaves: Vec<String> = set.iter().map(|v| record_root(domain, &json!(v))).collect();
    merkle_root(domain, &leaves)
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyMarker {
    pub id: u16,
    pub name: String,
    pub bucket_kind: CostBucketKind,
    pub max_fee_bps: u64,
    pub rebate_bias_bps: u64,
    pub root: String,
}
impl PolicyMarker {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
    pub fn state_root(&self) -> String {
        record_root(D_POLICY, &self.public_record())
    }
}
pub fn default_policy_markers() -> Vec<PolicyMarker> {
    let mut markers = Vec::new();
    markers
}
pub fn policy_marker_001() -> PolicyMarker {
    default_policy_markers().remove(0)
}
pub fn policy_marker_002() -> PolicyMarker {
    default_policy_markers().remove(1)
}
pub fn policy_marker_003() -> PolicyMarker {
    default_policy_markers().remove(2)
}
pub fn policy_marker_004() -> PolicyMarker {
    default_policy_markers().remove(3)
}
pub fn policy_marker_005() -> PolicyMarker {
    default_policy_markers().remove(4)
}
pub fn policy_marker_006() -> PolicyMarker {
    default_policy_markers().remove(5)
}
pub fn policy_marker_007() -> PolicyMarker {
    default_policy_markers().remove(6)
}
pub fn policy_marker_008() -> PolicyMarker {
    default_policy_markers().remove(7)
}
pub fn policy_marker_009() -> PolicyMarker {
    default_policy_markers().remove(8)
}
pub fn policy_marker_010() -> PolicyMarker {
    default_policy_markers().remove(9)
}
pub fn policy_marker_011() -> PolicyMarker {
    default_policy_markers().remove(10)
}
pub fn policy_marker_012() -> PolicyMarker {
    default_policy_markers().remove(11)
}
pub fn policy_marker_013() -> PolicyMarker {
    default_policy_markers().remove(12)
}
pub fn policy_marker_014() -> PolicyMarker {
    default_policy_markers().remove(13)
}
pub fn policy_marker_015() -> PolicyMarker {
    default_policy_markers().remove(14)
}
pub fn policy_marker_016() -> PolicyMarker {
    default_policy_markers().remove(15)
}
pub fn policy_marker_017() -> PolicyMarker {
    default_policy_markers().remove(16)
}
pub fn policy_marker_018() -> PolicyMarker {
    default_policy_markers().remove(17)
}
pub fn policy_marker_019() -> PolicyMarker {
    default_policy_markers().remove(18)
}
pub fn policy_marker_020() -> PolicyMarker {
    default_policy_markers().remove(19)
}
pub fn policy_marker_021() -> PolicyMarker {
    default_policy_markers().remove(20)
}
pub fn policy_marker_022() -> PolicyMarker {
    default_policy_markers().remove(21)
}
pub fn policy_marker_023() -> PolicyMarker {
    default_policy_markers().remove(22)
}
pub fn policy_marker_024() -> PolicyMarker {
    default_policy_markers().remove(23)
}
pub fn policy_marker_025() -> PolicyMarker {
    default_policy_markers().remove(24)
}
pub fn policy_marker_026() -> PolicyMarker {
    default_policy_markers().remove(25)
}
pub fn policy_marker_027() -> PolicyMarker {
    default_policy_markers().remove(26)
}
pub fn policy_marker_028() -> PolicyMarker {
    default_policy_markers().remove(27)
}
pub fn policy_marker_029() -> PolicyMarker {
    default_policy_markers().remove(28)
}
pub fn policy_marker_030() -> PolicyMarker {
    default_policy_markers().remove(29)
}
pub fn policy_marker_031() -> PolicyMarker {
    default_policy_markers().remove(30)
}
pub fn policy_marker_032() -> PolicyMarker {
    default_policy_markers().remove(31)
}
pub fn policy_marker_033() -> PolicyMarker {
    default_policy_markers().remove(32)
}
pub fn policy_marker_034() -> PolicyMarker {
    default_policy_markers().remove(33)
}
pub fn policy_marker_035() -> PolicyMarker {
    default_policy_markers().remove(34)
}
pub fn policy_marker_036() -> PolicyMarker {
    default_policy_markers().remove(35)
}
pub fn policy_marker_037() -> PolicyMarker {
    default_policy_markers().remove(36)
}
pub fn policy_marker_038() -> PolicyMarker {
    default_policy_markers().remove(37)
}
pub fn policy_marker_039() -> PolicyMarker {
    default_policy_markers().remove(38)
}
pub fn policy_marker_040() -> PolicyMarker {
    default_policy_markers().remove(39)
}
pub fn policy_marker_041() -> PolicyMarker {
    default_policy_markers().remove(40)
}
pub fn policy_marker_042() -> PolicyMarker {
    default_policy_markers().remove(41)
}
pub fn policy_marker_043() -> PolicyMarker {
    default_policy_markers().remove(42)
}
pub fn policy_marker_044() -> PolicyMarker {
    default_policy_markers().remove(43)
}
pub fn policy_marker_045() -> PolicyMarker {
    default_policy_markers().remove(44)
}
pub fn policy_marker_046() -> PolicyMarker {
    default_policy_markers().remove(45)
}
pub fn policy_marker_047() -> PolicyMarker {
    default_policy_markers().remove(46)
}
pub fn policy_marker_048() -> PolicyMarker {
    default_policy_markers().remove(47)
}
pub fn policy_marker_049() -> PolicyMarker {
    default_policy_markers().remove(48)
}
pub fn policy_marker_050() -> PolicyMarker {
    default_policy_markers().remove(49)
}
pub fn policy_marker_051() -> PolicyMarker {
    default_policy_markers().remove(50)
}
pub fn policy_marker_052() -> PolicyMarker {
    default_policy_markers().remove(51)
}
pub fn policy_marker_053() -> PolicyMarker {
    default_policy_markers().remove(52)
}
pub fn policy_marker_054() -> PolicyMarker {
    default_policy_markers().remove(53)
}
pub fn policy_marker_055() -> PolicyMarker {
    default_policy_markers().remove(54)
}
pub fn policy_marker_056() -> PolicyMarker {
    default_policy_markers().remove(55)
}
pub fn policy_marker_057() -> PolicyMarker {
    default_policy_markers().remove(56)
}
pub fn policy_marker_058() -> PolicyMarker {
    default_policy_markers().remove(57)
}
pub fn policy_marker_059() -> PolicyMarker {
    default_policy_markers().remove(58)
}
pub fn policy_marker_060() -> PolicyMarker {
    default_policy_markers().remove(59)
}
pub fn policy_marker_061() -> PolicyMarker {
    default_policy_markers().remove(60)
}
pub fn policy_marker_062() -> PolicyMarker {
    default_policy_markers().remove(61)
}
pub fn policy_marker_063() -> PolicyMarker {
    default_policy_markers().remove(62)
}
pub fn policy_marker_064() -> PolicyMarker {
    default_policy_markers().remove(63)
}
pub fn policy_marker_065() -> PolicyMarker {
    default_policy_markers().remove(64)
}
pub fn policy_marker_066() -> PolicyMarker {
    default_policy_markers().remove(65)
}
pub fn policy_marker_067() -> PolicyMarker {
    default_policy_markers().remove(66)
}
pub fn policy_marker_068() -> PolicyMarker {
    default_policy_markers().remove(67)
}
pub fn policy_marker_069() -> PolicyMarker {
    default_policy_markers().remove(68)
}
pub fn policy_marker_070() -> PolicyMarker {
    default_policy_markers().remove(69)
}
pub fn policy_marker_071() -> PolicyMarker {
    default_policy_markers().remove(70)
}
pub fn policy_marker_072() -> PolicyMarker {
    default_policy_markers().remove(71)
}
pub fn policy_marker_073() -> PolicyMarker {
    default_policy_markers().remove(72)
}
pub fn policy_marker_074() -> PolicyMarker {
    default_policy_markers().remove(73)
}
pub fn policy_marker_075() -> PolicyMarker {
    default_policy_markers().remove(74)
}
pub fn policy_marker_076() -> PolicyMarker {
    default_policy_markers().remove(75)
}
pub fn policy_marker_077() -> PolicyMarker {
    default_policy_markers().remove(76)
}
pub fn policy_marker_078() -> PolicyMarker {
    default_policy_markers().remove(77)
}
pub fn policy_marker_079() -> PolicyMarker {
    default_policy_markers().remove(78)
}
pub fn policy_marker_080() -> PolicyMarker {
    default_policy_markers().remove(79)
}
pub fn policy_marker_081() -> PolicyMarker {
    default_policy_markers().remove(80)
}
pub fn policy_marker_082() -> PolicyMarker {
    default_policy_markers().remove(81)
}
pub fn policy_marker_083() -> PolicyMarker {
    default_policy_markers().remove(82)
}
pub fn policy_marker_084() -> PolicyMarker {
    default_policy_markers().remove(83)
}
pub fn policy_marker_085() -> PolicyMarker {
    default_policy_markers().remove(84)
}
pub fn policy_marker_086() -> PolicyMarker {
    default_policy_markers().remove(85)
}
pub fn policy_marker_087() -> PolicyMarker {
    default_policy_markers().remove(86)
}
pub fn policy_marker_088() -> PolicyMarker {
    default_policy_markers().remove(87)
}
pub fn policy_marker_089() -> PolicyMarker {
    default_policy_markers().remove(88)
}
pub fn policy_marker_090() -> PolicyMarker {
    default_policy_markers().remove(89)
}
pub fn policy_marker_091() -> PolicyMarker {
    default_policy_markers().remove(90)
}
pub fn policy_marker_092() -> PolicyMarker {
    default_policy_markers().remove(91)
}
pub fn policy_marker_093() -> PolicyMarker {
    default_policy_markers().remove(92)
}
pub fn policy_marker_094() -> PolicyMarker {
    default_policy_markers().remove(93)
}
pub fn policy_marker_095() -> PolicyMarker {
    default_policy_markers().remove(94)
}
pub fn policy_marker_096() -> PolicyMarker {
    default_policy_markers().remove(95)
}
pub fn policy_marker_097() -> PolicyMarker {
    default_policy_markers().remove(96)
}
pub fn policy_marker_098() -> PolicyMarker {
    default_policy_markers().remove(97)
}
pub fn policy_marker_099() -> PolicyMarker {
    default_policy_markers().remove(98)
}
pub fn policy_marker_100() -> PolicyMarker {
    default_policy_markers().remove(99)
}
pub fn roots_only_fee_netting_scenario_001() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_001"
}
pub fn roots_only_fee_netting_scenario_002() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_002"
}
pub fn roots_only_fee_netting_scenario_003() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_003"
}
pub fn roots_only_fee_netting_scenario_004() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_004"
}
pub fn roots_only_fee_netting_scenario_005() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_005"
}
pub fn roots_only_fee_netting_scenario_006() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_006"
}
pub fn roots_only_fee_netting_scenario_007() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_007"
}
pub fn roots_only_fee_netting_scenario_008() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_008"
}
pub fn roots_only_fee_netting_scenario_009() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_009"
}
pub fn roots_only_fee_netting_scenario_010() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_010"
}
pub fn roots_only_fee_netting_scenario_011() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_011"
}
pub fn roots_only_fee_netting_scenario_012() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_012"
}
pub fn roots_only_fee_netting_scenario_013() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_013"
}
pub fn roots_only_fee_netting_scenario_014() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_014"
}
pub fn roots_only_fee_netting_scenario_015() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_015"
}
pub fn roots_only_fee_netting_scenario_016() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_016"
}
pub fn roots_only_fee_netting_scenario_017() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_017"
}
pub fn roots_only_fee_netting_scenario_018() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_018"
}
pub fn roots_only_fee_netting_scenario_019() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_019"
}
pub fn roots_only_fee_netting_scenario_020() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_020"
}
pub fn roots_only_fee_netting_scenario_021() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_021"
}
pub fn roots_only_fee_netting_scenario_022() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_022"
}
pub fn roots_only_fee_netting_scenario_023() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_023"
}
pub fn roots_only_fee_netting_scenario_024() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_024"
}
pub fn roots_only_fee_netting_scenario_025() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_025"
}
pub fn roots_only_fee_netting_scenario_026() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_026"
}
pub fn roots_only_fee_netting_scenario_027() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_027"
}
pub fn roots_only_fee_netting_scenario_028() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_028"
}
pub fn roots_only_fee_netting_scenario_029() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_029"
}
pub fn roots_only_fee_netting_scenario_030() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_030"
}
pub fn roots_only_fee_netting_scenario_031() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_031"
}
pub fn roots_only_fee_netting_scenario_032() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_032"
}
pub fn roots_only_fee_netting_scenario_033() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_033"
}
pub fn roots_only_fee_netting_scenario_034() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_034"
}
pub fn roots_only_fee_netting_scenario_035() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_035"
}
pub fn roots_only_fee_netting_scenario_036() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_036"
}
pub fn roots_only_fee_netting_scenario_037() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_037"
}
pub fn roots_only_fee_netting_scenario_038() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_038"
}
pub fn roots_only_fee_netting_scenario_039() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_039"
}
pub fn roots_only_fee_netting_scenario_040() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_040"
}
pub fn roots_only_fee_netting_scenario_041() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_041"
}
pub fn roots_only_fee_netting_scenario_042() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_042"
}
pub fn roots_only_fee_netting_scenario_043() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_043"
}
pub fn roots_only_fee_netting_scenario_044() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_044"
}
pub fn roots_only_fee_netting_scenario_045() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_045"
}
pub fn roots_only_fee_netting_scenario_046() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_046"
}
pub fn roots_only_fee_netting_scenario_047() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_047"
}
pub fn roots_only_fee_netting_scenario_048() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_048"
}
pub fn roots_only_fee_netting_scenario_049() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_049"
}
pub fn roots_only_fee_netting_scenario_050() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_050"
}
pub fn roots_only_fee_netting_scenario_051() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_051"
}
pub fn roots_only_fee_netting_scenario_052() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_052"
}
pub fn roots_only_fee_netting_scenario_053() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_053"
}
pub fn roots_only_fee_netting_scenario_054() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_054"
}
pub fn roots_only_fee_netting_scenario_055() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_055"
}
pub fn roots_only_fee_netting_scenario_056() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_056"
}
pub fn roots_only_fee_netting_scenario_057() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_057"
}
pub fn roots_only_fee_netting_scenario_058() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_058"
}
pub fn roots_only_fee_netting_scenario_059() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_059"
}
pub fn roots_only_fee_netting_scenario_060() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_060"
}
pub fn roots_only_fee_netting_scenario_061() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_061"
}
pub fn roots_only_fee_netting_scenario_062() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_062"
}
pub fn roots_only_fee_netting_scenario_063() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_063"
}
pub fn roots_only_fee_netting_scenario_064() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_064"
}
pub fn roots_only_fee_netting_scenario_065() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_065"
}
pub fn roots_only_fee_netting_scenario_066() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_066"
}
pub fn roots_only_fee_netting_scenario_067() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_067"
}
pub fn roots_only_fee_netting_scenario_068() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_068"
}
pub fn roots_only_fee_netting_scenario_069() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_069"
}
pub fn roots_only_fee_netting_scenario_070() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_070"
}
pub fn roots_only_fee_netting_scenario_071() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_071"
}
pub fn roots_only_fee_netting_scenario_072() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_072"
}
pub fn roots_only_fee_netting_scenario_073() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_073"
}
pub fn roots_only_fee_netting_scenario_074() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_074"
}
pub fn roots_only_fee_netting_scenario_075() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_075"
}
pub fn roots_only_fee_netting_scenario_076() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_076"
}
pub fn roots_only_fee_netting_scenario_077() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_077"
}
pub fn roots_only_fee_netting_scenario_078() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_078"
}
pub fn roots_only_fee_netting_scenario_079() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_079"
}
pub fn roots_only_fee_netting_scenario_080() -> &'static str {
    "builder_blob_fee_netting_roots_only_scenario_080"
}
