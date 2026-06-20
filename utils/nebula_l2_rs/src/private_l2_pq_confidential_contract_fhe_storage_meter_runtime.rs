use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FHE_STORAGE_METER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-fhe-storage-meter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_FHE_STORAGE_METER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FHE_STORAGE_SUITE: &str =
    "tfhe-radix-ciphertext-slot-meter+monero-private-l2-confidential-storage-v1";
pub const PQ_CONTRACT_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-confidential-fhe-storage-attestation-v1";
pub const CIPHERTEXT_COMMITMENT_SUITE: &str =
    "fhe-ciphertext-slot-commitment+view-tag-redacted-root-v1";
pub const LOW_FEE_STORAGE_REBATE_SCHEME: &str =
    "private-l2-low-fee-confidential-fhe-storage-rebate-v1";
pub const ABUSE_QUARANTINE_SCHEME: &str =
    "pq-confidential-contract-fhe-storage-abuse-quarantine-v1";
pub const PRIVACY_REDACTION_BUDGET_SCHEME: &str =
    "private-l2-confidential-fhe-storage-redaction-budget-v1";
pub const DETERMINISTIC_PUBLIC_RECORD_SCHEME: &str =
    "deterministic-fhe-storage-meter-public-record-and-roots-v1";
pub const DEVNET_HEIGHT: u64 = 2_048_000;
pub const DEVNET_EPOCH: u64 = 2_844;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_NAMESPACE_TTL_BLOCKS: u64 = 172_800;
pub const DEFAULT_SLOT_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 21_600;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_STORAGE_BYTES_PER_SESSION: u64 = 16_777_216;
pub const DEFAULT_MAX_CIPHERTEXT_SLOTS_PER_SESSION: u64 = 65_536;
pub const DEFAULT_BASE_SLOT_PRICE_MICRO_CREDITS: u128 = 250;
pub const DEFAULT_BASE_BYTE_PRICE_MICRO_CREDITS: u128 = 8;
pub const DEFAULT_BASE_ROTATION_PRICE_MICRO_CREDITS: u128 = 2_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_500;
pub const DEFAULT_ABUSE_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_QUARANTINE_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_REDACTION_RESERVE_BPS: u64 = 500;
pub const DEFAULT_MAX_NAMESPACES: usize = 1_048_576;
pub const DEFAULT_MAX_CIPHERTEXT_SLOTS: usize = 67_108_864;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_SESSIONS: usize = 16_777_216;
pub const DEFAULT_MAX_RECEIPTS: usize = 67_108_864;
pub const DEFAULT_MAX_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_QUOTAS: usize = 33_554_432;
pub const DEFAULT_MAX_ABUSE_REPORTS: usize = 8_388_608;
pub const DEFAULT_MAX_QUARANTINES: usize = 8_388_608;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 16_777_216;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 67_108_864;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FheNamespaceKind {
    ContractState,
    ContractScratch,
    ConfidentialMap,
    ConfidentialVector,
    OracleBuffer,
    BridgeEscrow,
    AccountAbstraction,
    GovernanceVault,
    PrecompileCache,
    CustomStorage,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Proposed,
    Active,
    Congested,
    Throttled,
    Quarantined,
    Draining,
    Retired,
}

impl NamespaceStatus {
    pub fn accepts_sessions(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Active | Self::Congested | Self::Throttled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FheCiphertextScheme {
    BooleanGate,
    ShortintRadix,
    IntegerRadix,
    PackedBitset,
    EncryptedIndex,
    EncryptedBalance,
    EncryptedOrder,
    EncryptedRiskVector,
    CustomCircuit,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CiphertextSlotStatus {
    Reserved,
    Written,
    Warm,
    Rotating,
    Compacted,
    Released,
    Expired,
    Quarantined,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAttestationKind {
    ContractBinding,
    NamespaceOpening,
    CiphertextCommitment,
    MeterReading,
    KeyRotation,
    RebateEligibility,
    PrivacyRedaction,
    QuotaReview,
    AbuseReview,
    EmergencyFreeze,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterSessionKind {
    ReadOnly,
    WriteBatch,
    RotateKeys,
    CompactSlots,
    ProofQuery,
    CrossContractCall,
    BridgeSettlement,
    GovernanceAction,
    EmergencyRecovery,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeterSessionStatus {
    Sealed,
    Attested,
    Metered,
    Running,
    Suspended,
    Completed,
    Rebated,
    Expired,
    Quarantined,
    Slashed,
    Cancelled,
}

impl MeterSessionStatus {
    pub fn meterable(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Metered | Self::Running | Self::Suspended
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageReceiptStatus {
    Issued,
    Indexed,
    RebateQueued,
    RebateSettled,
    Expired,
    Disputed,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToNamespace,
    Expired,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaStatus {
    Open,
    SoftLimited,
    HardLimited,
    Quarantined,
    Exhausted,
    Released,
}

impl QuotaStatus {
    pub fn accepts_writes(self) -> bool {
        matches!(self, Self::Open | Self::SoftLimited)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseKind {
    CiphertextFlood,
    MeterForgery,
    QuotaEvasion,
    NamespaceSquat,
    RebateFraud,
    KeyRotationSpam,
    PrivacyBudgetLeak,
    MaliciousContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Proposed,
    Active,
    Review,
    Released,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    CiphertextPayload,
    SlotAccessPattern,
    ContractAddress,
    CallerCommitment,
    MeterTrace,
    RebateOwner,
    QuotaEnvelope,
    AbuseEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Open,
    Reserved,
    PartiallySpent,
    Exhausted,
    Released,
    Expired,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fhe_storage_suite: String,
    pub pq_contract_attestation_suite: String,
    pub ciphertext_commitment_suite: String,
    pub low_fee_storage_rebate_scheme: String,
    pub abuse_quarantine_scheme: String,
    pub privacy_redaction_budget_scheme: String,
    pub deterministic_public_record_scheme: String,
    pub epoch_blocks: u64,
    pub namespace_ttl_blocks: u64,
    pub slot_ttl_blocks: u64,
    pub session_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_storage_bytes_per_session: u64,
    pub max_ciphertext_slots_per_session: u64,
    pub base_slot_price_micro_credits: u128,
    pub base_byte_price_micro_credits: u128,
    pub base_rotation_price_micro_credits: u128,
    pub low_fee_rebate_bps: u64,
    pub abuse_slash_bps: u64,
    pub quarantine_reserve_bps: u64,
    pub redaction_reserve_bps: u64,
    pub max_namespaces: usize,
    pub max_ciphertext_slots: usize,
    pub max_attestations: usize,
    pub max_sessions: usize,
    pub max_receipts: usize,
    pub max_rebates: usize,
    pub max_quotas: usize,
    pub max_abuse_reports: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fhe_storage_suite: FHE_STORAGE_SUITE.to_string(),
            pq_contract_attestation_suite: PQ_CONTRACT_ATTESTATION_SUITE.to_string(),
            ciphertext_commitment_suite: CIPHERTEXT_COMMITMENT_SUITE.to_string(),
            low_fee_storage_rebate_scheme: LOW_FEE_STORAGE_REBATE_SCHEME.to_string(),
            abuse_quarantine_scheme: ABUSE_QUARANTINE_SCHEME.to_string(),
            privacy_redaction_budget_scheme: PRIVACY_REDACTION_BUDGET_SCHEME.to_string(),
            deterministic_public_record_scheme: DETERMINISTIC_PUBLIC_RECORD_SCHEME.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            namespace_ttl_blocks: DEFAULT_NAMESPACE_TTL_BLOCKS,
            slot_ttl_blocks: DEFAULT_SLOT_TTL_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            receipt_ttl_blocks: DEFAULT_RECEIPT_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_storage_bytes_per_session: DEFAULT_MAX_STORAGE_BYTES_PER_SESSION,
            max_ciphertext_slots_per_session: DEFAULT_MAX_CIPHERTEXT_SLOTS_PER_SESSION,
            base_slot_price_micro_credits: DEFAULT_BASE_SLOT_PRICE_MICRO_CREDITS,
            base_byte_price_micro_credits: DEFAULT_BASE_BYTE_PRICE_MICRO_CREDITS,
            base_rotation_price_micro_credits: DEFAULT_BASE_ROTATION_PRICE_MICRO_CREDITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            abuse_slash_bps: DEFAULT_ABUSE_SLASH_BPS,
            quarantine_reserve_bps: DEFAULT_QUARANTINE_RESERVE_BPS,
            redaction_reserve_bps: DEFAULT_REDACTION_RESERVE_BPS,
            max_namespaces: DEFAULT_MAX_NAMESPACES,
            max_ciphertext_slots: DEFAULT_MAX_CIPHERTEXT_SLOTS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_quotas: DEFAULT_MAX_QUOTAS,
            max_abuse_reports: DEFAULT_MAX_ABUSE_REPORTS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            max_public_records: DEFAULT_MAX_PUBLIC_RECORDS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub namespaces_registered: u64,
    pub ciphertext_slots_reserved: u64,
    pub pq_attestations_submitted: u64,
    pub meter_sessions_opened: u64,
    pub usage_receipts_issued: u64,
    pub low_fee_rebates_issued: u64,
    pub quotas_opened: u64,
    pub abuse_reports: u64,
    pub quarantines_opened: u64,
    pub redaction_budgets_opened: u64,
    pub storage_bytes_metered: u128,
    pub ciphertext_slot_blocks_metered: u128,
    pub rotation_count_metered: u128,
    pub gross_micro_credits_charged: u128,
    pub rebate_micro_credits_issued: u128,
    pub slashed_micro_credits: u128,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub namespace_root: String,
    pub ciphertext_slot_root: String,
    pub pq_attestation_root: String,
    pub meter_session_root: String,
    pub usage_receipt_root: String,
    pub low_fee_rebate_root: String,
    pub quota_root: String,
    pub abuse_report_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub deterministic_public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            namespace_root: empty_root("NAMESPACE"),
            ciphertext_slot_root: empty_root("CIPHERTEXT-SLOT"),
            pq_attestation_root: empty_root("PQ-ATTESTATION"),
            meter_session_root: empty_root("METER-SESSION"),
            usage_receipt_root: empty_root("USAGE-RECEIPT"),
            low_fee_rebate_root: empty_root("LOW-FEE-REBATE"),
            quota_root: empty_root("QUOTA"),
            abuse_report_root: empty_root("ABUSE-REPORT"),
            quarantine_root: empty_root("QUARANTINE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            deterministic_public_record_root: empty_root("DETERMINISTIC-PUBLIC-RECORD"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FheStorageNamespaceRecord {
    pub namespace_id: String,
    pub kind: FheNamespaceKind,
    pub status: NamespaceStatus,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub namespace_commitment_root: String,
    pub policy_root: String,
    pub slot_index_root: String,
    pub quota_id: Option<String>,
    pub allowed_callers_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
    pub slot_count: u64,
    pub live_bytes: u64,
    pub metered_slot_blocks: u128,
    pub redaction_budget_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub quarantine_ids: BTreeSet<String>,
    pub tags: BTreeSet<String>,
}

impl FheStorageNamespaceRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CiphertextSlotRecord {
    pub slot_id: String,
    pub namespace_id: String,
    pub scheme: FheCiphertextScheme,
    pub status: CiphertextSlotStatus,
    pub slot_index: u64,
    pub ciphertext_commitment: String,
    pub ciphertext_root: String,
    pub key_epoch_root: String,
    pub access_pattern_commitment: String,
    pub redacted_payload_root: String,
    pub byte_size: u64,
    pub radix_limbs: u32,
    pub rotation_count: u64,
    pub reserved_at_height: u64,
    pub last_metered_height: u64,
    pub expires_at_height: u64,
    pub meter_session_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
}

impl CiphertextSlotRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqContractAttestationRecord {
    pub attestation_id: String,
    pub kind: PqAttestationKind,
    pub status: AttestationStatus,
    pub namespace_id: Option<String>,
    pub slot_id: Option<String>,
    pub session_id: Option<String>,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub contract_code_root: String,
    pub fhe_circuit_root: String,
    pub measured_slot_count: u64,
    pub measured_bytes: u64,
    pub measured_rotations: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeterSessionRecord {
    pub session_id: String,
    pub namespace_id: String,
    pub kind: MeterSessionKind,
    pub status: MeterSessionStatus,
    pub caller_commitment: String,
    pub sealed_meter_envelope_root: String,
    pub session_nullifier: String,
    pub meter_key_commitment: String,
    pub privacy_set_root: String,
    pub redaction_policy_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub max_slots: u64,
    pub max_storage_bytes: u64,
    pub max_rotations: u64,
    pub metered_slots: u64,
    pub metered_bytes: u64,
    pub metered_rotations: u64,
    pub slot_ids: BTreeSet<String>,
    pub attestation_ids: BTreeSet<String>,
    pub receipt_ids: BTreeSet<String>,
    pub redaction_budget_ids: BTreeSet<String>,
}

impl MeterSessionRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageReceiptRecord {
    pub receipt_id: String,
    pub session_id: String,
    pub namespace_id: String,
    pub status: UsageReceiptStatus,
    pub receipt_root: String,
    pub slot_root: String,
    pub meter_transcript_root: String,
    pub slot_count: u64,
    pub storage_bytes: u64,
    pub rotations: u64,
    pub slot_price_micro_credits: u128,
    pub byte_price_micro_credits: u128,
    pub rotation_price_micro_credits: u128,
    pub gross_micro_credits: u128,
    pub redaction_units_spent: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub rebate_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeStorageRebateRecord {
    pub rebate_id: String,
    pub receipt_id: String,
    pub namespace_id: String,
    pub status: RebateStatus,
    pub owner_commitment: String,
    pub rebate_commitment: String,
    pub eligibility_root: String,
    pub amount_micro_credits: u128,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub claimable_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StorageQuotaRecord {
    pub quota_id: String,
    pub namespace_id: String,
    pub status: QuotaStatus,
    pub quota_commitment: String,
    pub max_slots: u64,
    pub max_storage_bytes: u64,
    pub max_rotations_per_epoch: u64,
    pub used_slots: u64,
    pub used_storage_bytes: u64,
    pub used_rotations_this_epoch: u64,
    pub reserve_micro_credits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub quarantine_ids: BTreeSet<String>,
}

impl StorageQuotaRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportRecord {
    pub abuse_report_id: String,
    pub kind: AbuseKind,
    pub namespace_id: Option<String>,
    pub slot_id: Option<String>,
    pub session_id: Option<String>,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub quarantine_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub status: QuarantineStatus,
    pub abuse_report_id: String,
    pub namespace_id: Option<String>,
    pub slot_id: Option<String>,
    pub session_id: Option<String>,
    pub reason: AbuseKind,
    pub evidence_root: String,
    pub reserve_micro_credits: u128,
    pub opened_at_height: u64,
    pub review_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub redaction_budget_id: String,
    pub namespace_id: String,
    pub session_id: Option<String>,
    pub class: RedactionClass,
    pub status: RedactionBudgetStatus,
    pub policy_root: String,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub reserve_micro_credits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub record_id: String,
    pub domain: String,
    pub subject_id: String,
    pub record_root: String,
    pub published_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterFheNamespaceRequest {
    pub kind: FheNamespaceKind,
    pub owner_commitment: String,
    pub contract_commitment: String,
    pub namespace_commitment_root: String,
    pub policy_root: String,
    pub slot_index_root: String,
    pub allowed_callers_root: String,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub tags: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenStorageQuotaRequest {
    pub namespace_id: String,
    pub quota_commitment: String,
    pub max_slots: u64,
    pub max_storage_bytes: u64,
    pub max_rotations_per_epoch: u64,
    pub reserve_micro_credits: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveCiphertextSlotRequest {
    pub namespace_id: String,
    pub scheme: FheCiphertextScheme,
    pub slot_index: u64,
    pub ciphertext_commitment: String,
    pub ciphertext_root: String,
    pub key_epoch_root: String,
    pub access_pattern_commitment: String,
    pub redacted_payload_root: String,
    pub byte_size: u64,
    pub radix_limbs: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenMeterSessionRequest {
    pub namespace_id: String,
    pub kind: MeterSessionKind,
    pub caller_commitment: String,
    pub sealed_meter_envelope_root: String,
    pub session_nullifier: String,
    pub meter_key_commitment: String,
    pub privacy_set_root: String,
    pub redaction_policy_root: String,
    pub max_slots: u64,
    pub max_storage_bytes: u64,
    pub max_rotations: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPqContractAttestationRequest {
    pub kind: PqAttestationKind,
    pub namespace_id: Option<String>,
    pub slot_id: Option<String>,
    pub session_id: Option<String>,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub contract_code_root: String,
    pub fhe_circuit_root: String,
    pub measured_slot_count: u64,
    pub measured_bytes: u64,
    pub measured_rotations: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllocateRedactionBudgetRequest {
    pub namespace_id: String,
    pub session_id: Option<String>,
    pub class: RedactionClass,
    pub policy_root: String,
    pub reserved_units: u64,
    pub reserve_micro_credits: u128,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueUsageReceiptRequest {
    pub session_id: String,
    pub slot_ids: BTreeSet<String>,
    pub receipt_root: String,
    pub meter_transcript_root: String,
    pub slot_count: u64,
    pub storage_bytes: u64,
    pub rotations: u64,
    pub redaction_units_spent: u64,
    pub rebate_owner_commitment: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportAbuseRequest {
    pub kind: AbuseKind,
    pub namespace_id: Option<String>,
    pub slot_id: Option<String>,
    pub session_id: Option<String>,
    pub reporter_commitment: String,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub namespaces: BTreeMap<String, FheStorageNamespaceRecord>,
    pub ciphertext_slots: BTreeMap<String, CiphertextSlotRecord>,
    pub pq_attestations: BTreeMap<String, PqContractAttestationRecord>,
    pub meter_sessions: BTreeMap<String, MeterSessionRecord>,
    pub usage_receipts: BTreeMap<String, UsageReceiptRecord>,
    pub low_fee_rebates: BTreeMap<String, LowFeeStorageRebateRecord>,
    pub quotas: BTreeMap<String, StorageQuotaRecord>,
    pub abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
    pub spent_session_nullifiers: BTreeSet<String>,
    pub quarantined_namespaces: BTreeSet<String>,
    pub quarantined_slots: BTreeSet<String>,
}

impl State {
    pub fn new(config: Config, height: u64, epoch: u64) -> Self {
        let mut state = Self {
            config,
            height,
            epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            namespaces: BTreeMap::new(),
            ciphertext_slots: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            meter_sessions: BTreeMap::new(),
            usage_receipts: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            quotas: BTreeMap::new(),
            abuse_reports: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
            spent_session_nullifiers: BTreeSet::new(),
            quarantined_namespaces: BTreeSet::new(),
            quarantined_slots: BTreeSet::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_fhe_namespace(
        &mut self,
        request: RegisterFheNamespaceRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.namespaces.len() < self.config.max_namespaces,
            "namespace capacity exhausted"
        );
        required("owner_commitment", &request.owner_commitment)?;
        required("contract_commitment", &request.contract_commitment)?;
        required(
            "namespace_commitment_root",
            &request.namespace_commitment_root,
        )?;
        required("policy_root", &request.policy_root)?;
        required("slot_index_root", &request.slot_index_root)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits too low"
        );
        let sequence = self.counters.namespaces_registered + 1;
        let namespace_id = fhe_namespace_id(&request, sequence);
        let record = FheStorageNamespaceRecord {
            namespace_id: namespace_id.clone(),
            kind: request.kind,
            status: NamespaceStatus::Active,
            owner_commitment: request.owner_commitment,
            contract_commitment: request.contract_commitment,
            namespace_commitment_root: request.namespace_commitment_root,
            policy_root: request.policy_root,
            slot_index_root: request.slot_index_root,
            quota_id: None,
            allowed_callers_root: request.allowed_callers_root,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            registered_at_height: self.height,
            expires_at_height: self.height + self.config.namespace_ttl_blocks,
            slot_count: 0,
            live_bytes: 0,
            metered_slot_blocks: 0,
            redaction_budget_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            quarantine_ids: BTreeSet::new(),
            tags: request.tags,
        };
        self.namespaces.insert(namespace_id.clone(), record);
        self.counters.namespaces_registered = sequence;
        self.publish_public_record("namespace", &namespace_id)?;
        self.refresh_roots();
        Ok(namespace_id)
    }

    pub fn open_storage_quota(
        &mut self,
        request: OpenStorageQuotaRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.quotas.len() < self.config.max_quotas,
            "quota capacity exhausted"
        );
        required("quota_commitment", &request.quota_commitment)?;
        ensure!(request.max_slots > 0, "max_slots must be positive");
        ensure!(
            request.max_storage_bytes > 0,
            "max_storage_bytes must be positive"
        );
        let namespace = self
            .namespaces
            .get_mut(&request.namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        ensure!(
            namespace.status.accepts_sessions(),
            "namespace does not accept quota openings"
        );
        let sequence = self.counters.quotas_opened + 1;
        let quota_id = storage_quota_id(&request, sequence);
        let record = StorageQuotaRecord {
            quota_id: quota_id.clone(),
            namespace_id: request.namespace_id.clone(),
            status: QuotaStatus::Open,
            quota_commitment: request.quota_commitment,
            max_slots: request.max_slots,
            max_storage_bytes: request.max_storage_bytes,
            max_rotations_per_epoch: request.max_rotations_per_epoch,
            used_slots: 0,
            used_storage_bytes: 0,
            used_rotations_this_epoch: 0,
            reserve_micro_credits: request.reserve_micro_credits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.namespace_ttl_blocks,
            quarantine_ids: BTreeSet::new(),
        };
        namespace.quota_id = Some(quota_id.clone());
        self.quotas.insert(quota_id.clone(), record);
        self.counters.quotas_opened = sequence;
        self.publish_public_record("quota", &quota_id)?;
        self.refresh_roots();
        Ok(quota_id)
    }

    pub fn reserve_ciphertext_slot(
        &mut self,
        request: ReserveCiphertextSlotRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.ciphertext_slots.len() < self.config.max_ciphertext_slots,
            "ciphertext slot capacity exhausted"
        );
        required("ciphertext_commitment", &request.ciphertext_commitment)?;
        required("ciphertext_root", &request.ciphertext_root)?;
        required("key_epoch_root", &request.key_epoch_root)?;
        required(
            "access_pattern_commitment",
            &request.access_pattern_commitment,
        )?;
        ensure!(request.byte_size > 0, "byte_size must be positive");
        let namespace = self
            .namespaces
            .get_mut(&request.namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        ensure!(
            namespace.status.accepts_sessions(),
            "namespace does not accept slot reservations"
        );
        if let Some(quota_id) = &namespace.quota_id {
            let quota = self
                .quotas
                .get_mut(quota_id)
                .ok_or_else(|| "namespace quota missing".to_string())?;
            ensure!(
                quota.status.accepts_writes(),
                "quota does not accept writes"
            );
            ensure!(quota.used_slots < quota.max_slots, "slot quota exhausted");
            ensure!(
                quota.used_storage_bytes.saturating_add(request.byte_size)
                    <= quota.max_storage_bytes,
                "storage byte quota exhausted"
            );
            quota.used_slots = quota.used_slots.saturating_add(1);
            quota.used_storage_bytes = quota.used_storage_bytes.saturating_add(request.byte_size);
        }
        let sequence = self.counters.ciphertext_slots_reserved + 1;
        let slot_id = ciphertext_slot_id(&request, sequence);
        let record = CiphertextSlotRecord {
            slot_id: slot_id.clone(),
            namespace_id: request.namespace_id.clone(),
            scheme: request.scheme,
            status: CiphertextSlotStatus::Reserved,
            slot_index: request.slot_index,
            ciphertext_commitment: request.ciphertext_commitment,
            ciphertext_root: request.ciphertext_root,
            key_epoch_root: request.key_epoch_root,
            access_pattern_commitment: request.access_pattern_commitment,
            redacted_payload_root: request.redacted_payload_root,
            byte_size: request.byte_size,
            radix_limbs: request.radix_limbs,
            rotation_count: 0,
            reserved_at_height: self.height,
            last_metered_height: self.height,
            expires_at_height: self.height + self.config.slot_ttl_blocks,
            meter_session_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
        };
        namespace.slot_count = namespace.slot_count.saturating_add(1);
        namespace.live_bytes = namespace.live_bytes.saturating_add(request.byte_size);
        self.ciphertext_slots.insert(slot_id.clone(), record);
        self.counters.ciphertext_slots_reserved = sequence;
        self.publish_public_record("ciphertext_slot", &slot_id)?;
        self.refresh_roots();
        Ok(slot_id)
    }

    pub fn open_meter_session(
        &mut self,
        request: OpenMeterSessionRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.meter_sessions.len() < self.config.max_sessions,
            "meter session capacity exhausted"
        );
        required("caller_commitment", &request.caller_commitment)?;
        required(
            "sealed_meter_envelope_root",
            &request.sealed_meter_envelope_root,
        )?;
        required("session_nullifier", &request.session_nullifier)?;
        ensure!(
            !self
                .spent_session_nullifiers
                .contains(&request.session_nullifier),
            "session nullifier already spent"
        );
        ensure!(
            request.max_slots <= self.config.max_ciphertext_slots_per_session,
            "session slot limit exceeds config"
        );
        ensure!(
            request.max_storage_bytes <= self.config.max_storage_bytes_per_session,
            "session byte limit exceeds config"
        );
        let namespace = self
            .namespaces
            .get(&request.namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        ensure!(
            namespace.status.accepts_sessions(),
            "namespace does not accept meter sessions"
        );
        let sequence = self.counters.meter_sessions_opened + 1;
        let session_id = meter_session_id(&request, sequence);
        let record = MeterSessionRecord {
            session_id: session_id.clone(),
            namespace_id: request.namespace_id,
            kind: request.kind,
            status: MeterSessionStatus::Sealed,
            caller_commitment: request.caller_commitment,
            sealed_meter_envelope_root: request.sealed_meter_envelope_root,
            session_nullifier: request.session_nullifier.clone(),
            meter_key_commitment: request.meter_key_commitment,
            privacy_set_root: request.privacy_set_root,
            redaction_policy_root: request.redaction_policy_root,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.session_ttl_blocks,
            max_slots: request.max_slots,
            max_storage_bytes: request.max_storage_bytes,
            max_rotations: request.max_rotations,
            metered_slots: 0,
            metered_bytes: 0,
            metered_rotations: 0,
            slot_ids: BTreeSet::new(),
            attestation_ids: BTreeSet::new(),
            receipt_ids: BTreeSet::new(),
            redaction_budget_ids: BTreeSet::new(),
        };
        self.spent_session_nullifiers
            .insert(request.session_nullifier);
        self.meter_sessions.insert(session_id.clone(), record);
        self.counters.meter_sessions_opened = sequence;
        self.publish_public_record("meter_session", &session_id)?;
        self.refresh_roots();
        Ok(session_id)
    }

    pub fn submit_pq_contract_attestation(
        &mut self,
        request: SubmitPqContractAttestationRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.pq_attestations.len() < self.config.max_attestations,
            "attestation capacity exhausted"
        );
        required("signer_set_root", &request.signer_set_root)?;
        required("attestation_root", &request.attestation_root)?;
        required("transcript_root", &request.transcript_root)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "privacy set too small"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "pq security bits too low"
        );
        if let Some(namespace_id) = &request.namespace_id {
            ensure!(
                self.namespaces.contains_key(namespace_id),
                "attested namespace not found"
            );
        }
        if let Some(slot_id) = &request.slot_id {
            ensure!(
                self.ciphertext_slots.contains_key(slot_id),
                "attested slot not found"
            );
        }
        if let Some(session_id) = &request.session_id {
            ensure!(
                self.meter_sessions.contains_key(session_id),
                "attested session not found"
            );
        }
        let sequence = self.counters.pq_attestations_submitted + 1;
        let attestation_id = pq_contract_attestation_id(&request, sequence);
        let record = PqContractAttestationRecord {
            attestation_id: attestation_id.clone(),
            kind: request.kind,
            status: AttestationStatus::Accepted,
            namespace_id: request.namespace_id.clone(),
            slot_id: request.slot_id.clone(),
            session_id: request.session_id.clone(),
            signer_set_root: request.signer_set_root,
            attestation_root: request.attestation_root,
            transcript_root: request.transcript_root,
            contract_code_root: request.contract_code_root,
            fhe_circuit_root: request.fhe_circuit_root,
            measured_slot_count: request.measured_slot_count,
            measured_bytes: request.measured_bytes,
            measured_rotations: request.measured_rotations,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.attestation_ttl_blocks,
        };
        if let Some(namespace_id) = &request.namespace_id {
            if let Some(namespace) = self.namespaces.get_mut(namespace_id) {
                namespace.attestation_ids.insert(attestation_id.clone());
            }
        }
        if let Some(slot_id) = &request.slot_id {
            if let Some(slot) = self.ciphertext_slots.get_mut(slot_id) {
                slot.attestation_ids.insert(attestation_id.clone());
                if slot.status == CiphertextSlotStatus::Reserved {
                    slot.status = CiphertextSlotStatus::Written;
                }
            }
        }
        if let Some(session_id) = &request.session_id {
            if let Some(session) = self.meter_sessions.get_mut(session_id) {
                session.attestation_ids.insert(attestation_id.clone());
                if session.status == MeterSessionStatus::Sealed {
                    session.status = MeterSessionStatus::Attested;
                }
            }
        }
        self.pq_attestations.insert(attestation_id.clone(), record);
        self.counters.pq_attestations_submitted = sequence;
        self.publish_public_record("pq_contract_attestation", &attestation_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: AllocateRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exhausted"
        );
        required("policy_root", &request.policy_root)?;
        ensure!(
            request.reserved_units > 0,
            "reserved_units must be positive"
        );
        let namespace = self
            .namespaces
            .get_mut(&request.namespace_id)
            .ok_or_else(|| "namespace not found".to_string())?;
        if let Some(session_id) = &request.session_id {
            ensure!(
                self.meter_sessions.contains_key(session_id),
                "session not found"
            );
        }
        let sequence = self.counters.redaction_budgets_opened + 1;
        let redaction_budget_id = redaction_budget_id(&request, sequence);
        let record = PrivacyRedactionBudgetRecord {
            redaction_budget_id: redaction_budget_id.clone(),
            namespace_id: request.namespace_id.clone(),
            session_id: request.session_id.clone(),
            class: request.class,
            status: RedactionBudgetStatus::Open,
            policy_root: request.policy_root,
            reserved_units: request.reserved_units,
            spent_units: 0,
            reserve_micro_credits: request.reserve_micro_credits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.redaction_ttl_blocks,
        };
        namespace
            .redaction_budget_ids
            .insert(redaction_budget_id.clone());
        if let Some(session_id) = &request.session_id {
            if let Some(session) = self.meter_sessions.get_mut(session_id) {
                session
                    .redaction_budget_ids
                    .insert(redaction_budget_id.clone());
            }
        }
        self.redaction_budgets
            .insert(redaction_budget_id.clone(), record);
        self.counters.redaction_budgets_opened = sequence;
        self.publish_public_record("redaction_budget", &redaction_budget_id)?;
        self.refresh_roots();
        Ok(redaction_budget_id)
    }

    pub fn issue_usage_receipt(
        &mut self,
        request: IssueUsageReceiptRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.usage_receipts.len() < self.config.max_receipts,
            "usage receipt capacity exhausted"
        );
        required("receipt_root", &request.receipt_root)?;
        required("meter_transcript_root", &request.meter_transcript_root)?;
        required("rebate_owner_commitment", &request.rebate_owner_commitment)?;
        let session = self
            .meter_sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| "session not found".to_string())?;
        ensure!(session.status.meterable(), "session is not meterable");
        ensure!(
            request.slot_count <= session.max_slots,
            "session slot cap exceeded"
        );
        ensure!(
            request.storage_bytes <= session.max_storage_bytes,
            "session storage byte cap exceeded"
        );
        ensure!(
            request.rotations <= session.max_rotations,
            "session rotation cap exceeded"
        );
        let namespace_id = session.namespace_id.clone();
        for slot_id in &request.slot_ids {
            let slot = self
                .ciphertext_slots
                .get_mut(slot_id)
                .ok_or_else(|| format!("slot not found: {slot_id}"))?;
            ensure!(
                slot.namespace_id == namespace_id,
                "slot belongs to another namespace"
            );
            slot.meter_session_ids.insert(request.session_id.clone());
            slot.status = CiphertextSlotStatus::Warm;
            slot.last_metered_height = self.height;
            slot.rotation_count = slot.rotation_count.saturating_add(request.rotations);
        }
        let gross_micro_credits = storage_meter_cost(
            request.slot_count,
            request.storage_bytes,
            request.rotations,
            self.config.base_slot_price_micro_credits,
            self.config.base_byte_price_micro_credits,
            self.config.base_rotation_price_micro_credits,
        );
        let sequence = self.counters.usage_receipts_issued + 1;
        let receipt_id = usage_receipt_id(&request, sequence);
        let slot_records: Vec<Value> = request
            .slot_ids
            .iter()
            .filter_map(|slot_id| self.ciphertext_slots.get(slot_id))
            .map(CiphertextSlotRecord::public_record)
            .collect();
        let slot_root = public_record_root("USAGE-RECEIPT-SLOTS", &slot_records);
        let record = UsageReceiptRecord {
            receipt_id: receipt_id.clone(),
            session_id: request.session_id.clone(),
            namespace_id: namespace_id.clone(),
            status: UsageReceiptStatus::RebateQueued,
            receipt_root: request.receipt_root,
            slot_root,
            meter_transcript_root: request.meter_transcript_root,
            slot_count: request.slot_count,
            storage_bytes: request.storage_bytes,
            rotations: request.rotations,
            slot_price_micro_credits: self.config.base_slot_price_micro_credits,
            byte_price_micro_credits: self.config.base_byte_price_micro_credits,
            rotation_price_micro_credits: self.config.base_rotation_price_micro_credits,
            gross_micro_credits,
            redaction_units_spent: request.redaction_units_spent,
            issued_at_height: self.height,
            expires_at_height: self.height + self.config.receipt_ttl_blocks,
            rebate_id: None,
        };
        session.status = MeterSessionStatus::Completed;
        session.metered_slots = session.metered_slots.saturating_add(request.slot_count);
        session.metered_bytes = session.metered_bytes.saturating_add(request.storage_bytes);
        session.metered_rotations = session.metered_rotations.saturating_add(request.rotations);
        session.slot_ids.extend(request.slot_ids.iter().cloned());
        session.receipt_ids.insert(receipt_id.clone());
        if let Some(namespace) = self.namespaces.get_mut(&namespace_id) {
            namespace.metered_slot_blocks = namespace
                .metered_slot_blocks
                .saturating_add(request.slot_count as u128);
        }
        for budget in self.redaction_budgets.values_mut() {
            if budget.namespace_id == namespace_id
                && budget.status == RedactionBudgetStatus::Open
                && budget.spent_units < budget.reserved_units
            {
                let remaining = budget.reserved_units - budget.spent_units;
                let spent = remaining.min(request.redaction_units_spent);
                budget.spent_units = budget.spent_units.saturating_add(spent);
                if budget.spent_units == budget.reserved_units {
                    budget.status = RedactionBudgetStatus::Exhausted;
                } else if spent > 0 {
                    budget.status = RedactionBudgetStatus::PartiallySpent;
                }
                break;
            }
        }
        self.usage_receipts.insert(receipt_id.clone(), record);
        self.counters.usage_receipts_issued = sequence;
        self.counters.storage_bytes_metered = self
            .counters
            .storage_bytes_metered
            .saturating_add(request.storage_bytes as u128);
        self.counters.ciphertext_slot_blocks_metered = self
            .counters
            .ciphertext_slot_blocks_metered
            .saturating_add(request.slot_count as u128);
        self.counters.rotation_count_metered = self
            .counters
            .rotation_count_metered
            .saturating_add(request.rotations as u128);
        self.counters.gross_micro_credits_charged = self
            .counters
            .gross_micro_credits_charged
            .saturating_add(gross_micro_credits);
        let rebate_id = self.issue_low_fee_storage_rebate(
            &receipt_id,
            &namespace_id,
            &request.rebate_owner_commitment,
            gross_micro_credits,
        )?;
        if let Some(receipt) = self.usage_receipts.get_mut(&receipt_id) {
            receipt.rebate_id = Some(rebate_id);
        }
        self.publish_public_record("usage_receipt", &receipt_id)?;
        self.refresh_roots();
        Ok(receipt_id)
    }

    pub fn report_abuse(
        &mut self,
        request: ReportAbuseRequest,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.abuse_reports.len() < self.config.max_abuse_reports,
            "abuse report capacity exhausted"
        );
        required("reporter_commitment", &request.reporter_commitment)?;
        required("evidence_root", &request.evidence_root)?;
        if let Some(namespace_id) = &request.namespace_id {
            ensure!(
                self.namespaces.contains_key(namespace_id),
                "reported namespace not found"
            );
        }
        if let Some(slot_id) = &request.slot_id {
            ensure!(
                self.ciphertext_slots.contains_key(slot_id),
                "reported slot not found"
            );
        }
        if let Some(session_id) = &request.session_id {
            ensure!(
                self.meter_sessions.contains_key(session_id),
                "reported session not found"
            );
        }
        let sequence = self.counters.abuse_reports + 1;
        let abuse_report_id = abuse_report_id(&request, sequence);
        let report = AbuseReportRecord {
            abuse_report_id: abuse_report_id.clone(),
            kind: request.kind,
            namespace_id: request.namespace_id.clone(),
            slot_id: request.slot_id.clone(),
            session_id: request.session_id.clone(),
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root.clone(),
            opened_at_height: self.height,
            quarantine_id: None,
        };
        self.abuse_reports.insert(abuse_report_id.clone(), report);
        self.counters.abuse_reports = sequence;
        let quarantine_id = self.open_quarantine(
            &abuse_report_id,
            request.kind,
            request.namespace_id,
            request.slot_id,
            request.session_id,
            request.evidence_root,
        )?;
        if let Some(report) = self.abuse_reports.get_mut(&abuse_report_id) {
            report.quarantine_id = Some(quarantine_id);
        }
        self.publish_public_record("abuse_report", &abuse_report_id)?;
        self.refresh_roots();
        Ok(abuse_report_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.namespace_root =
            public_record_root("NAMESPACE", &values_record(&self.namespaces));
        self.roots.ciphertext_slot_root =
            public_record_root("CIPHERTEXT-SLOT", &values_record(&self.ciphertext_slots));
        self.roots.pq_attestation_root =
            public_record_root("PQ-ATTESTATION", &values_record(&self.pq_attestations));
        self.roots.meter_session_root =
            public_record_root("METER-SESSION", &values_record(&self.meter_sessions));
        self.roots.usage_receipt_root =
            public_record_root("USAGE-RECEIPT", &values_record(&self.usage_receipts));
        self.roots.low_fee_rebate_root =
            public_record_root("LOW-FEE-REBATE", &values_record(&self.low_fee_rebates));
        self.roots.quota_root = public_record_root("QUOTA", &values_record(&self.quotas));
        self.roots.abuse_report_root =
            public_record_root("ABUSE-REPORT", &values_record(&self.abuse_reports));
        self.roots.quarantine_root =
            public_record_root("QUARANTINE", &values_record(&self.quarantines));
        self.roots.redaction_budget_root =
            public_record_root("REDACTION-BUDGET", &values_record(&self.redaction_budgets));
        self.roots.deterministic_public_record_root = public_record_root(
            "DETERMINISTIC-PUBLIC-RECORD",
            &values_record(&self.deterministic_public_records),
        );
        self.roots.state_root = self.state_root_without_cached_root();
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "height": self.height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "namespace_root": self.roots.namespace_root,
                "ciphertext_slot_root": self.roots.ciphertext_slot_root,
                "pq_attestation_root": self.roots.pq_attestation_root,
                "meter_session_root": self.roots.meter_session_root,
                "usage_receipt_root": self.roots.usage_receipt_root,
                "low_fee_rebate_root": self.roots.low_fee_rebate_root,
                "quota_root": self.roots.quota_root,
                "abuse_report_root": self.roots.abuse_report_root,
                "quarantine_root": self.roots.quarantine_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "deterministic_public_record_root": self.roots.deterministic_public_record_root,
            },
            "spent_session_nullifiers": sorted_strings(&self.spent_session_nullifiers),
            "quarantined_namespaces": sorted_strings(&self.quarantined_namespaces),
            "quarantined_slots": sorted_strings(&self.quarantined_slots),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn state_root_without_cached_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn issue_low_fee_storage_rebate(
        &mut self,
        receipt_id: &str,
        namespace_id: &str,
        owner_commitment: &str,
        gross_micro_credits: u128,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.low_fee_rebates.len() < self.config.max_rebates,
            "rebate capacity exhausted"
        );
        let sequence = self.counters.low_fee_rebates_issued + 1;
        let record_seed = json!({
            "receipt_id": receipt_id,
            "namespace_id": namespace_id,
            "owner_commitment": owner_commitment,
            "gross_micro_credits": gross_micro_credits,
            "rebate_bps": self.config.low_fee_rebate_bps,
        });
        let rebate_id = deterministic_id("LOW-FEE-STORAGE-REBATE-ID", sequence, &record_seed);
        let amount_micro_credits = bps_amount(gross_micro_credits, self.config.low_fee_rebate_bps);
        let rebate_commitment = deterministic_record_root(
            "PRIVATE-L2-PQ-FHE-STORAGE-METER:REBATE-COMMITMENT",
            &record_seed,
        );
        let eligibility_root = deterministic_record_root(
            "PRIVATE-L2-PQ-FHE-STORAGE-METER:REBATE-ELIGIBILITY",
            &record_seed,
        );
        let record = LowFeeStorageRebateRecord {
            rebate_id: rebate_id.clone(),
            receipt_id: receipt_id.to_string(),
            namespace_id: namespace_id.to_string(),
            status: RebateStatus::Claimable,
            owner_commitment: owner_commitment.to_string(),
            rebate_commitment,
            eligibility_root,
            amount_micro_credits,
            rebate_bps: self.config.low_fee_rebate_bps,
            issued_at_height: self.height,
            claimable_at_height: self.height,
            expires_at_height: self.height + self.config.rebate_ttl_blocks,
        };
        self.low_fee_rebates.insert(rebate_id.clone(), record);
        self.counters.low_fee_rebates_issued = sequence;
        self.counters.rebate_micro_credits_issued = self
            .counters
            .rebate_micro_credits_issued
            .saturating_add(amount_micro_credits);
        self.publish_public_record("low_fee_storage_rebate", &rebate_id)?;
        Ok(rebate_id)
    }

    fn open_quarantine(
        &mut self,
        abuse_report_id: &str,
        reason: AbuseKind,
        namespace_id: Option<String>,
        slot_id: Option<String>,
        session_id: Option<String>,
        evidence_root: String,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<String> {
        ensure!(
            self.quarantines.len() < self.config.max_quarantines,
            "quarantine capacity exhausted"
        );
        let sequence = self.counters.quarantines_opened + 1;
        let record_seed = json!({
            "abuse_report_id": abuse_report_id,
            "reason": reason,
            "namespace_id": namespace_id,
            "slot_id": slot_id,
            "session_id": session_id,
            "evidence_root": evidence_root,
        });
        let quarantine_id = deterministic_id("QUARANTINE-ID", sequence, &record_seed);
        let reserve_micro_credits = bps_amount(
            self.counters.gross_micro_credits_charged,
            self.config.quarantine_reserve_bps,
        );
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            status: QuarantineStatus::Active,
            abuse_report_id: abuse_report_id.to_string(),
            namespace_id: namespace_id.clone(),
            slot_id: slot_id.clone(),
            session_id: session_id.clone(),
            reason,
            evidence_root,
            reserve_micro_credits,
            opened_at_height: self.height,
            review_at_height: self.height + self.config.session_ttl_blocks,
            expires_at_height: self.height + self.config.quarantine_ttl_blocks,
        };
        if let Some(namespace_id) = &namespace_id {
            self.quarantined_namespaces.insert(namespace_id.clone());
            if let Some(namespace) = self.namespaces.get_mut(namespace_id) {
                namespace.status = NamespaceStatus::Quarantined;
                namespace.quarantine_ids.insert(quarantine_id.clone());
                if let Some(quota_id) = &namespace.quota_id {
                    if let Some(quota) = self.quotas.get_mut(quota_id) {
                        quota.status = QuotaStatus::Quarantined;
                        quota.quarantine_ids.insert(quarantine_id.clone());
                    }
                }
            }
        }
        if let Some(slot_id) = &slot_id {
            self.quarantined_slots.insert(slot_id.clone());
            if let Some(slot) = self.ciphertext_slots.get_mut(slot_id) {
                slot.status = CiphertextSlotStatus::Quarantined;
            }
        }
        if let Some(session_id) = &session_id {
            if let Some(session) = self.meter_sessions.get_mut(session_id) {
                session.status = MeterSessionStatus::Quarantined;
            }
        }
        self.quarantines.insert(quarantine_id.clone(), record);
        self.counters.quarantines_opened = sequence;
        self.counters.slashed_micro_credits = self
            .counters
            .slashed_micro_credits
            .saturating_add(reserve_micro_credits);
        self.publish_public_record("quarantine", &quarantine_id)?;
        Ok(quarantine_id)
    }

    fn publish_public_record(
        &mut self,
        domain: &str,
        subject_id: &str,
    ) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<()> {
        ensure!(
            self.deterministic_public_records.len() < self.config.max_public_records,
            "public record capacity exhausted"
        );
        let sequence = self.deterministic_public_records.len() as u64 + 1;
        let record_seed = json!({
            "domain": domain,
            "subject_id": subject_id,
            "height": self.height,
        });
        let record_id = deterministic_id("PUBLIC-RECORD-ID", sequence, &record_seed);
        let record_root = deterministic_record_root(
            "PRIVATE-L2-PQ-FHE-STORAGE-METER:PUBLIC-RECORD",
            &record_seed,
        );
        self.deterministic_public_records.insert(
            record_id.clone(),
            DeterministicPublicRecord {
                record_id,
                domain: domain.to_string(),
                subject_id: subject_id.to_string(),
                record_root,
                published_at_height: self.height,
            },
        );
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH);
    let mut tags = BTreeSet::new();
    tags.insert("devnet".to_string());
    tags.insert("fhe-storage-meter".to_string());
    tags.insert("monero-private-l2".to_string());
    let namespace_id = state
        .register_fhe_namespace(RegisterFheNamespaceRequest {
            kind: FheNamespaceKind::ContractState,
            owner_commitment: "owner:commitment:devnet-fhe-vault".to_string(),
            contract_commitment: "contract:commitment:private-l2-vault-v1".to_string(),
            namespace_commitment_root: "namespace:root:fhe-vault-state".to_string(),
            policy_root: "policy:root:fhe-storage-meter-devnet".to_string(),
            slot_index_root: "slot:index:root:empty-devnet".to_string(),
            allowed_callers_root: "callers:root:wallets-and-contracts-devnet".to_string(),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            tags,
        })
        .expect("devnet namespace registration must succeed");
    state
        .open_storage_quota(OpenStorageQuotaRequest {
            namespace_id: namespace_id.clone(),
            quota_commitment: "quota:commitment:fhe-vault-64k-slots".to_string(),
            max_slots: 65_536,
            max_storage_bytes: 16_777_216,
            max_rotations_per_epoch: 4_096,
            reserve_micro_credits: 25_000_000,
        })
        .expect("devnet quota must succeed");
    let slot_id = state
        .reserve_ciphertext_slot(ReserveCiphertextSlotRequest {
            namespace_id: namespace_id.clone(),
            scheme: FheCiphertextScheme::EncryptedBalance,
            slot_index: 42,
            ciphertext_commitment: "ciphertext:commitment:slot-42-balance".to_string(),
            ciphertext_root: "ciphertext:root:slot-42-balance".to_string(),
            key_epoch_root: "fhe:key-epoch:root:devnet-0001".to_string(),
            access_pattern_commitment: "access:pattern:commitment:redacted-slot-42".to_string(),
            redacted_payload_root: "payload:redacted:root:slot-42".to_string(),
            byte_size: 2_048,
            radix_limbs: 16,
        })
        .expect("devnet slot reservation must succeed");
    let session_id = state
        .open_meter_session(OpenMeterSessionRequest {
            namespace_id: namespace_id.clone(),
            kind: MeterSessionKind::WriteBatch,
            caller_commitment: "caller:commitment:demo-wallet".to_string(),
            sealed_meter_envelope_root: "sealed:meter:envelope:root:demo-session".to_string(),
            session_nullifier: "session:nullifier:fhe-storage-demo-001".to_string(),
            meter_key_commitment: "meter:key:commitment:fhe-storage-demo".to_string(),
            privacy_set_root: "privacy:set:root:demo-524288".to_string(),
            redaction_policy_root: "redaction:policy:root:fhe-slot-access".to_string(),
            max_slots: 128,
            max_storage_bytes: 262_144,
            max_rotations: 16,
        })
        .expect("devnet meter session must succeed");
    let attestation_id = state
        .submit_pq_contract_attestation(SubmitPqContractAttestationRequest {
            kind: PqAttestationKind::MeterReading,
            namespace_id: Some(namespace_id.clone()),
            slot_id: Some(slot_id.clone()),
            session_id: Some(session_id.clone()),
            signer_set_root: "pq:signer:set:root:devnet-fhe-meter-committee".to_string(),
            attestation_root: "pq:attestation:root:fhe-meter-demo".to_string(),
            transcript_root: "meter:transcript:root:fhe-storage-demo".to_string(),
            contract_code_root: "contract:code:root:private-l2-vault-v1".to_string(),
            fhe_circuit_root: "fhe:circuit:root:encrypted-balance-write-v1".to_string(),
            measured_slot_count: 1,
            measured_bytes: 2_048,
            measured_rotations: 1,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet attestation must succeed");
    state
        .allocate_redaction_budget(AllocateRedactionBudgetRequest {
            namespace_id: namespace_id.clone(),
            session_id: Some(session_id.clone()),
            class: RedactionClass::SlotAccessPattern,
            policy_root: "redaction:policy:root:fhe-slot-access".to_string(),
            reserved_units: 64,
            reserve_micro_credits: 32_000,
        })
        .expect("devnet redaction budget must succeed");
    let mut slot_ids = BTreeSet::new();
    slot_ids.insert(slot_id);
    state
        .issue_usage_receipt(IssueUsageReceiptRequest {
            session_id,
            slot_ids,
            receipt_root: "usage:receipt:root:fhe-storage-demo".to_string(),
            meter_transcript_root: format!("meter:transcript:root:attested:{attestation_id}"),
            slot_count: 1,
            storage_bytes: 2_048,
            rotations: 1,
            redaction_units_spent: 8,
            rebate_owner_commitment: "rebate:owner:commitment:demo-wallet".to_string(),
        })
        .expect("devnet usage receipt must succeed");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let namespace_id = state
        .namespaces
        .keys()
        .next()
        .cloned()
        .expect("demo has a namespace");
    let slot_id = state
        .ciphertext_slots
        .keys()
        .next()
        .cloned()
        .expect("demo has a slot");
    state
        .report_abuse(ReportAbuseRequest {
            kind: AbuseKind::CiphertextFlood,
            namespace_id: Some(namespace_id),
            slot_id: Some(slot_id),
            session_id: None,
            reporter_commitment: "reporter:commitment:watchtower-demo".to_string(),
            evidence_root: "abuse:evidence:root:ciphertext-flood-demo".to_string(),
        })
        .expect("demo abuse report must succeed");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn fhe_namespace_id(request: &RegisterFheNamespaceRequest, sequence: u64) -> String {
    deterministic_id("FHE-NAMESPACE-ID", sequence, &json!(request))
}

pub fn storage_quota_id(request: &OpenStorageQuotaRequest, sequence: u64) -> String {
    deterministic_id("STORAGE-QUOTA-ID", sequence, &json!(request))
}

pub fn ciphertext_slot_id(request: &ReserveCiphertextSlotRequest, sequence: u64) -> String {
    deterministic_id("CIPHERTEXT-SLOT-ID", sequence, &json!(request))
}

pub fn meter_session_id(request: &OpenMeterSessionRequest, sequence: u64) -> String {
    deterministic_id("METER-SESSION-ID", sequence, &json!(request))
}

pub fn pq_contract_attestation_id(
    request: &SubmitPqContractAttestationRequest,
    sequence: u64,
) -> String {
    deterministic_id("PQ-CONTRACT-ATTESTATION-ID", sequence, &json!(request))
}

pub fn redaction_budget_id(request: &AllocateRedactionBudgetRequest, sequence: u64) -> String {
    deterministic_id("REDACTION-BUDGET-ID", sequence, &json!(request))
}

pub fn usage_receipt_id(request: &IssueUsageReceiptRequest, sequence: u64) -> String {
    deterministic_id("USAGE-RECEIPT-ID", sequence, &json!(request))
}

pub fn abuse_report_id(request: &ReportAbuseRequest, sequence: u64) -> String {
    deterministic_id("ABUSE-REPORT-ID", sequence, &json!(request))
}

pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-FHE-STORAGE-METER:{kind}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-FHE-STORAGE-METER:{domain}-ROOT"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-FHE-STORAGE-METER:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

fn values_record<T>(records: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    records
        .values()
        .map(PublicRecord::public_record_value)
        .collect()
}

trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for FheStorageNamespaceRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for CiphertextSlotRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqContractAttestationRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for MeterSessionRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for UsageReceiptRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for LowFeeStorageRebateRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for StorageQuotaRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for AbuseReportRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for QuarantineRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for PrivacyRedactionBudgetRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

impl PublicRecord for DeterministicPublicRecord {
    fn public_record_value(&self) -> Value {
        json!(self)
    }
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn required(
    name: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractFheStorageMeterRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn storage_meter_cost(
    slots: u64,
    bytes: u64,
    rotations: u64,
    slot_price_micro_credits: u128,
    byte_price_micro_credits: u128,
    rotation_price_micro_credits: u128,
) -> u128 {
    slot_price_micro_credits
        .saturating_mul(slots as u128)
        .saturating_add(byte_price_micro_credits.saturating_mul(bytes as u128))
        .saturating_add(rotation_price_micro_credits.saturating_mul(rotations as u128))
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-FHE-STORAGE-METER:{domain}-EMPTY"),
        &[],
    )
}
