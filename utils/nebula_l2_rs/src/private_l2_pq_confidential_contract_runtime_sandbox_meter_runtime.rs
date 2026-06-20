use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_RUNTIME_SANDBOX_METER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-contract-runtime-sandbox-meter-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_RUNTIME_SANDBOX_METER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_METER_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-runtime-sandbox-meter-attestation-v1";
pub const SEALED_SANDBOX_SUITE: &str =
    "ML-KEM-1024+XChaCha20Poly1305+sealed-runtime-sandbox-session-v1";
pub const NAMESPACE_COMMITMENT_SUITE: &str =
    "monero-l2-confidential-contract-namespace-commitment-root-v1";
pub const BUDGET_COMMITMENT_SUITE: &str =
    "confidential-contract-runtime-gas-io-budget-commitment-v1";
pub const LOW_FEE_REBATE_SCHEME: &str = "private-l2-low-fee-runtime-sandbox-rebate-credit-v1";
pub const ABUSE_QUARANTINE_SCHEME: &str =
    "pq-confidential-contract-runtime-sandbox-abuse-quarantine-v1";
pub const PRIVACY_REDACTION_SCHEME: &str =
    "private-l2-confidential-runtime-privacy-redaction-budget-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "deterministic-runtime-sandbox-public-record-and-roots-v1";
pub const DEVNET_HEIGHT: u64 = 1_944_000;
pub const DEVNET_EPOCH: u64 = 2_700;
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_REDACTION_TTL_BLOCKS: u64 = 4_320;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 524_288;
pub const DEFAULT_MAX_GAS_UNITS: u64 = 48_000_000;
pub const DEFAULT_MAX_IO_BYTES: u64 = 16_777_216;
pub const DEFAULT_MAX_LOG_BYTES: u64 = 1_048_576;
pub const DEFAULT_BASE_GAS_PRICE_MICRO_CREDITS: u128 = 1_000;
pub const DEFAULT_BASE_IO_PRICE_MICRO_CREDITS: u128 = 64;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_200;
pub const DEFAULT_ABUSE_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_QUARANTINE_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_REDACTION_RESERVE_BPS: u64 = 500;
pub const DEFAULT_MAX_NAMESPACES: usize = 1_048_576;
pub const DEFAULT_MAX_SESSIONS: usize = 16_777_216;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_BUDGETS: usize = 33_554_432;
pub const DEFAULT_MAX_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_ABUSE_REPORTS: usize = 8_388_608;
pub const DEFAULT_MAX_QUARANTINES: usize = 8_388_608;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 16_777_216;
pub const DEFAULT_MAX_PUBLIC_RECORDS: usize = 67_108_864;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    ContractVm,
    DefiRouter,
    LiquidityPool,
    LendingPool,
    Perpetuals,
    Options,
    BridgeAdapter,
    OracleAdapter,
    AccountAbstraction,
    Governance,
    Precompile,
    CustomContract,
}

impl NamespaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractVm => "contract_vm",
            Self::DefiRouter => "defi_router",
            Self::LiquidityPool => "liquidity_pool",
            Self::LendingPool => "lending_pool",
            Self::Perpetuals => "perpetuals",
            Self::Options => "options",
            Self::BridgeAdapter => "bridge_adapter",
            Self::OracleAdapter => "oracle_adapter",
            Self::AccountAbstraction => "account_abstraction",
            Self::Governance => "governance",
            Self::Precompile => "precompile",
            Self::CustomContract => "custom_contract",
        }
    }
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
pub enum SandboxProfile {
    ReadOnly,
    Stateful,
    CrossContract,
    BatchSettlement,
    Liquidation,
    OracleUpdate,
    BridgeSettlement,
    Governance,
    Emergency,
}

impl SandboxProfile {
    pub fn high_risk(self) -> bool {
        matches!(
            self,
            Self::Liquidation | Self::BridgeSettlement | Self::Governance | Self::Emergency
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Sealed,
    Attested,
    Budgeted,
    Running,
    Suspended,
    Completed,
    Rebated,
    Expired,
    Quarantined,
    Slashed,
    Cancelled,
}

impl SessionStatus {
    pub fn meterable(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Budgeted | Self::Running | Self::Suspended
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignerSet,
    SandboxOpening,
    NamespaceBinding,
    MeterReading,
    BudgetOpening,
    PrivacyRedaction,
    RebateEligibility,
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
pub enum BudgetStatus {
    Opened,
    Reserved,
    PartiallySpent,
    Exhausted,
    RebateQueued,
    Settled,
    Expired,
    Quarantined,
    Slashed,
}

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(self, Self::Opened | Self::Reserved | Self::PartiallySpent)
    }
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
pub enum AbuseKind {
    NamespaceSpray,
    SessionReplay,
    MeterForgery,
    GasEvasion,
    IoEvasion,
    AttestationForgery,
    RedactionBypass,
    PrivacySetCollapse,
    ContractSpam,
    QuarantineBypass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseStatus {
    Reported,
    EvidenceCommitted,
    UnderReview,
    Accepted,
    Rejected,
    Quarantined,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineScope {
    Namespace,
    Session,
    MeterKey,
    Operator,
    RedactionPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Proposed,
    Active,
    CoolingDown,
    Released,
    Escalated,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionClass {
    CallData,
    ReturnData,
    EventLog,
    StorageKey,
    WitnessBlob,
    MeterTrace,
    ErrorTrace,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Allocated,
    Reserved,
    Spent,
    Exhausted,
    Expired,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_meter_attestation_suite: String,
    pub sealed_sandbox_suite: String,
    pub namespace_commitment_suite: String,
    pub budget_commitment_suite: String,
    pub low_fee_rebate_scheme: String,
    pub abuse_quarantine_scheme: String,
    pub privacy_redaction_scheme: String,
    pub public_record_scheme: String,
    pub monero_network: String,
    pub l2_network: String,
    pub epoch_blocks: u64,
    pub session_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub redaction_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_log_bytes: u64,
    pub base_gas_price_micro_credits: u128,
    pub base_io_price_micro_credits: u128,
    pub low_fee_rebate_bps: u64,
    pub abuse_slash_bps: u64,
    pub quarantine_reserve_bps: u64,
    pub redaction_reserve_bps: u64,
    pub max_namespaces: usize,
    pub max_sessions: usize,
    pub max_attestations: usize,
    pub max_budgets: usize,
    pub max_rebates: usize,
    pub max_abuse_reports: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub max_public_records: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_meter_attestation_suite: PQ_METER_ATTESTATION_SUITE.to_string(),
            sealed_sandbox_suite: SEALED_SANDBOX_SUITE.to_string(),
            namespace_commitment_suite: NAMESPACE_COMMITMENT_SUITE.to_string(),
            budget_commitment_suite: BUDGET_COMMITMENT_SUITE.to_string(),
            low_fee_rebate_scheme: LOW_FEE_REBATE_SCHEME.to_string(),
            abuse_quarantine_scheme: ABUSE_QUARANTINE_SCHEME.to_string(),
            privacy_redaction_scheme: PRIVACY_REDACTION_SCHEME.to_string(),
            public_record_scheme: PUBLIC_RECORD_SCHEME.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            session_ttl_blocks: DEFAULT_SESSION_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            redaction_ttl_blocks: DEFAULT_REDACTION_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            max_gas_units: DEFAULT_MAX_GAS_UNITS,
            max_io_bytes: DEFAULT_MAX_IO_BYTES,
            max_log_bytes: DEFAULT_MAX_LOG_BYTES,
            base_gas_price_micro_credits: DEFAULT_BASE_GAS_PRICE_MICRO_CREDITS,
            base_io_price_micro_credits: DEFAULT_BASE_IO_PRICE_MICRO_CREDITS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            abuse_slash_bps: DEFAULT_ABUSE_SLASH_BPS,
            quarantine_reserve_bps: DEFAULT_QUARANTINE_RESERVE_BPS,
            redaction_reserve_bps: DEFAULT_REDACTION_RESERVE_BPS,
            max_namespaces: DEFAULT_MAX_NAMESPACES,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_budgets: DEFAULT_MAX_BUDGETS,
            max_rebates: DEFAULT_MAX_REBATES,
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
    pub sessions_sealed: u64,
    pub sessions_attested: u64,
    pub sessions_completed: u64,
    pub meter_attestations_submitted: u64,
    pub budgets_opened: u64,
    pub gas_units_reserved: u128,
    pub gas_units_spent: u128,
    pub io_bytes_reserved: u128,
    pub io_bytes_spent: u128,
    pub log_bytes_spent: u128,
    pub rebate_credits_issued: u128,
    pub rebate_credits_claimed: u128,
    pub abuse_reports: u64,
    pub active_quarantines: u64,
    pub redaction_units_allocated: u128,
    pub redaction_units_spent: u128,
    pub deterministic_public_records: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub namespace_root: String,
    pub sealed_session_root: String,
    pub meter_attestation_root: String,
    pub budget_root: String,
    pub rebate_root: String,
    pub abuse_report_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            namespace_root: empty_root("NAMESPACE"),
            sealed_session_root: empty_root("SEALED-SESSION"),
            meter_attestation_root: empty_root("METER-ATTESTATION"),
            budget_root: empty_root("BUDGET"),
            rebate_root: empty_root("REBATE"),
            abuse_report_root: empty_root("ABUSE-REPORT"),
            quarantine_root: empty_root("QUARANTINE"),
            redaction_budget_root: empty_root("REDACTION-BUDGET"),
            public_record_root: empty_root("PUBLIC-RECORD"),
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
pub struct NamespaceCommitmentRecord {
    pub namespace_id: String,
    pub kind: NamespaceKind,
    pub status: NamespaceStatus,
    pub owner_commitment: String,
    pub namespace_commitment: String,
    pub code_root: String,
    pub policy_root: String,
    pub redaction_policy_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub sealed_session_ids: BTreeSet<String>,
}

impl NamespaceCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "kind": self.kind,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "namespace_commitment": self.namespace_commitment,
            "code_root": self.code_root,
            "policy_root": self.policy_root,
            "redaction_policy_root": self.redaction_policy_root,
            "min_privacy_set_size": self.min_privacy_set_size,
            "pq_security_bits": self.pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "sealed_session_ids": sorted_strings(&self.sealed_session_ids),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedSandboxSessionRecord {
    pub session_id: String,
    pub namespace_id: String,
    pub profile: SandboxProfile,
    pub status: SessionStatus,
    pub caller_commitment: String,
    pub sealed_envelope_root: String,
    pub session_nullifier: String,
    pub namespace_commitment: String,
    pub meter_key_commitment: String,
    pub privacy_set_root: String,
    pub redaction_policy_root: String,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_log_bytes: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub latest_attestation_id: Option<String>,
    pub budget_id: Option<String>,
}

impl SealedSandboxSessionRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqMeterAttestationRecord {
    pub attestation_id: String,
    pub session_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub measured_gas_units: u64,
    pub measured_io_bytes: u64,
    pub measured_log_bytes: u64,
    pub redacted_field_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqMeterAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GasIoBudgetRecord {
    pub budget_id: String,
    pub session_id: String,
    pub namespace_id: String,
    pub status: BudgetStatus,
    pub budget_commitment: String,
    pub gas_limit: u64,
    pub gas_spent: u64,
    pub io_limit_bytes: u64,
    pub io_spent_bytes: u64,
    pub log_limit_bytes: u64,
    pub log_spent_bytes: u64,
    pub gas_price_micro_credits: u128,
    pub io_price_micro_credits: u128,
    pub locked_micro_credits: u128,
    pub spent_micro_credits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl GasIoBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebateCreditRecord {
    pub rebate_id: String,
    pub session_id: String,
    pub budget_id: String,
    pub namespace_id: String,
    pub status: RebateStatus,
    pub rebate_owner_commitment: String,
    pub eligibility_root: String,
    pub credit_units: u128,
    pub rebate_bps: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebateCreditRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AbuseReportRecord {
    pub abuse_report_id: String,
    pub kind: AbuseKind,
    pub status: AbuseStatus,
    pub session_id: Option<String>,
    pub namespace_id: Option<String>,
    pub reporter_commitment: String,
    pub evidence_root: String,
    pub slash_bps: u64,
    pub reported_at_height: u64,
    pub expires_at_height: u64,
}

impl AbuseReportRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub scope: QuarantineScope,
    pub status: QuarantineStatus,
    pub target_id: String,
    pub abuse_report_id: String,
    pub quarantine_root: String,
    pub reserve_micro_credits: u128,
    pub opened_at_height: u64,
    pub releases_at_height: u64,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyRedactionBudgetRecord {
    pub redaction_budget_id: String,
    pub session_id: String,
    pub namespace_id: String,
    pub class: RedactionClass,
    pub status: RedactionStatus,
    pub policy_root: String,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub reserve_micro_credits: u128,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyRedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeterministicPublicRecord {
    pub public_record_id: String,
    pub record_kind: String,
    pub subject_id: String,
    pub record_root: String,
    pub state_root_after: String,
    pub emitted_at_height: u64,
}

impl DeterministicPublicRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterNamespaceRequest {
    pub kind: NamespaceKind,
    pub owner_commitment: String,
    pub namespace_commitment: String,
    pub code_root: String,
    pub policy_root: String,
    pub redaction_policy_root: String,
    pub min_privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl RegisterNamespaceRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealSandboxSessionRequest {
    pub namespace_id: String,
    pub profile: SandboxProfile,
    pub caller_commitment: String,
    pub sealed_envelope_root: String,
    pub session_nullifier: String,
    pub meter_key_commitment: String,
    pub privacy_set_root: String,
    pub redaction_policy_root: String,
    pub max_gas_units: u64,
    pub max_io_bytes: u64,
    pub max_log_bytes: u64,
}

impl SealSandboxSessionRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitMeterAttestationRequest {
    pub session_id: String,
    pub kind: AttestationKind,
    pub signer_set_root: String,
    pub attestation_root: String,
    pub transcript_root: String,
    pub measured_gas_units: u64,
    pub measured_io_bytes: u64,
    pub measured_log_bytes: u64,
    pub redacted_field_count: u64,
    pub privacy_set_size: u64,
    pub pq_security_bits: u16,
}

impl SubmitMeterAttestationRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenGasIoBudgetRequest {
    pub session_id: String,
    pub budget_commitment: String,
    pub gas_limit: u64,
    pub io_limit_bytes: u64,
    pub log_limit_bytes: u64,
    pub gas_price_micro_credits: u128,
    pub io_price_micro_credits: u128,
    pub locked_micro_credits: u128,
}

impl OpenGasIoBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleSandboxSessionRequest {
    pub session_id: String,
    pub budget_id: String,
    pub final_meter_attestation_id: String,
    pub final_receipt_root: String,
    pub gas_spent: u64,
    pub io_spent_bytes: u64,
    pub log_spent_bytes: u64,
    pub rebate_owner_commitment: String,
}

impl SettleSandboxSessionRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReportAbuseRequest {
    pub kind: AbuseKind,
    pub session_id: Option<String>,
    pub namespace_id: Option<String>,
    pub reporter_commitment: String,
    pub evidence_root: String,
}

impl ReportAbuseRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AllocateRedactionBudgetRequest {
    pub session_id: String,
    pub class: RedactionClass,
    pub policy_root: String,
    pub reserved_units: u64,
    pub reserve_micro_credits: u128,
}

impl AllocateRedactionBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub namespaces: BTreeMap<String, NamespaceCommitmentRecord>,
    pub sealed_sessions: BTreeMap<String, SealedSandboxSessionRecord>,
    pub meter_attestations: BTreeMap<String, PqMeterAttestationRecord>,
    pub budgets: BTreeMap<String, GasIoBudgetRecord>,
    pub rebates: BTreeMap<String, LowFeeRebateCreditRecord>,
    pub abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub redaction_budgets: BTreeMap<String, PrivacyRedactionBudgetRecord>,
    pub deterministic_public_records: BTreeMap<String, DeterministicPublicRecord>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            epoch: DEVNET_EPOCH,
            counters: Counters::default(),
            roots: Roots::default(),
            namespaces: BTreeMap::new(),
            sealed_sessions: BTreeMap::new(),
            meter_attestations: BTreeMap::new(),
            budgets: BTreeMap::new(),
            rebates: BTreeMap::new(),
            abuse_reports: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }
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
            sealed_sessions: BTreeMap::new(),
            meter_attestations: BTreeMap::new(),
            budgets: BTreeMap::new(),
            rebates: BTreeMap::new(),
            abuse_reports: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            deterministic_public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        devnet()
    }

    pub fn register_namespace(
        &mut self,
        request: RegisterNamespaceRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.namespaces.len() < self.config.max_namespaces,
            "namespace capacity exceeded"
        );
        required("owner_commitment", &request.owner_commitment)?;
        required("namespace_commitment", &request.namespace_commitment)?;
        required("code_root", &request.code_root)?;
        required("policy_root", &request.policy_root)?;
        required("redaction_policy_root", &request.redaction_policy_root)?;
        ensure!(
            request.min_privacy_set_size >= self.config.min_privacy_set_size,
            "namespace privacy set below minimum"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "namespace pq security bits below minimum"
        );
        let sequence = self.counters.namespaces_registered + 1;
        let namespace_id = namespace_id(&request, sequence);
        ensure!(
            !self.namespaces.contains_key(&namespace_id),
            "namespace already registered"
        );
        let record = NamespaceCommitmentRecord {
            namespace_id: namespace_id.clone(),
            kind: request.kind,
            status: NamespaceStatus::Active,
            owner_commitment: request.owner_commitment,
            namespace_commitment: request.namespace_commitment,
            code_root: request.code_root,
            policy_root: request.policy_root,
            redaction_policy_root: request.redaction_policy_root,
            min_privacy_set_size: request.min_privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.epoch_blocks * 64,
            sealed_session_ids: BTreeSet::new(),
        };
        self.namespaces.insert(namespace_id.clone(), record);
        self.counters.namespaces_registered = sequence;
        self.emit_public_record("namespace", &namespace_id)?;
        self.refresh_roots();
        Ok(namespace_id)
    }

    pub fn seal_sandbox_session(
        &mut self,
        request: SealSandboxSessionRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.sealed_sessions.len() < self.config.max_sessions,
            "sealed session capacity exceeded"
        );
        required("caller_commitment", &request.caller_commitment)?;
        required("sealed_envelope_root", &request.sealed_envelope_root)?;
        required("session_nullifier", &request.session_nullifier)?;
        required("meter_key_commitment", &request.meter_key_commitment)?;
        required("privacy_set_root", &request.privacy_set_root)?;
        required("redaction_policy_root", &request.redaction_policy_root)?;
        ensure!(
            request.max_gas_units <= self.config.max_gas_units,
            "gas limit exceeds configured maximum"
        );
        ensure!(
            request.max_io_bytes <= self.config.max_io_bytes,
            "io limit exceeds configured maximum"
        );
        ensure!(
            request.max_log_bytes <= self.config.max_log_bytes,
            "log limit exceeds configured maximum"
        );
        let namespace = self
            .namespaces
            .get_mut(&request.namespace_id)
            .ok_or_else(|| format!("unknown namespace {}", request.namespace_id))?;
        ensure!(
            namespace.status.accepts_sessions(),
            "namespace does not accept sessions"
        );
        ensure!(
            namespace.redaction_policy_root == request.redaction_policy_root,
            "redaction policy root mismatch"
        );
        let sequence = self.counters.sessions_sealed + 1;
        let session_id = sealed_session_id(&request, sequence);
        ensure!(
            !self.sealed_sessions.contains_key(&session_id),
            "session already sealed"
        );
        let record = SealedSandboxSessionRecord {
            session_id: session_id.clone(),
            namespace_id: request.namespace_id.clone(),
            profile: request.profile,
            status: SessionStatus::Sealed,
            caller_commitment: request.caller_commitment,
            sealed_envelope_root: request.sealed_envelope_root,
            session_nullifier: request.session_nullifier,
            namespace_commitment: namespace.namespace_commitment.clone(),
            meter_key_commitment: request.meter_key_commitment,
            privacy_set_root: request.privacy_set_root,
            redaction_policy_root: request.redaction_policy_root,
            max_gas_units: request.max_gas_units,
            max_io_bytes: request.max_io_bytes,
            max_log_bytes: request.max_log_bytes,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.session_ttl_blocks,
            latest_attestation_id: None,
            budget_id: None,
        };
        namespace.sealed_session_ids.insert(session_id.clone());
        self.sealed_sessions.insert(session_id.clone(), record);
        self.counters.sessions_sealed = sequence;
        self.emit_public_record("sealed_session", &session_id)?;
        self.refresh_roots();
        Ok(session_id)
    }

    pub fn submit_meter_attestation(
        &mut self,
        request: SubmitMeterAttestationRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.meter_attestations.len() < self.config.max_attestations,
            "meter attestation capacity exceeded"
        );
        required("signer_set_root", &request.signer_set_root)?;
        required("attestation_root", &request.attestation_root)?;
        required("transcript_root", &request.transcript_root)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set_size,
            "attestation privacy set below minimum"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security bits below minimum"
        );
        let session = self
            .sealed_sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| format!("unknown session {}", request.session_id))?;
        ensure!(
            session.status.meterable() || session.status == SessionStatus::Sealed,
            "session is not meterable"
        );
        ensure!(
            request.measured_gas_units <= session.max_gas_units,
            "attested gas exceeds session limit"
        );
        ensure!(
            request.measured_io_bytes <= session.max_io_bytes,
            "attested io exceeds session limit"
        );
        ensure!(
            request.measured_log_bytes <= session.max_log_bytes,
            "attested logs exceed session limit"
        );
        let sequence = self.counters.meter_attestations_submitted + 1;
        let attestation_id = meter_attestation_id(&request, sequence);
        let record = PqMeterAttestationRecord {
            attestation_id: attestation_id.clone(),
            session_id: request.session_id.clone(),
            kind: request.kind,
            status: AttestationStatus::Accepted,
            signer_set_root: request.signer_set_root,
            attestation_root: request.attestation_root,
            transcript_root: request.transcript_root,
            measured_gas_units: request.measured_gas_units,
            measured_io_bytes: request.measured_io_bytes,
            measured_log_bytes: request.measured_log_bytes,
            redacted_field_count: request.redacted_field_count,
            privacy_set_size: request.privacy_set_size,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: self.height,
            expires_at_height: self.height + self.config.attestation_ttl_blocks,
        };
        session.status = SessionStatus::Attested;
        session.latest_attestation_id = Some(attestation_id.clone());
        self.meter_attestations
            .insert(attestation_id.clone(), record);
        self.counters.sessions_attested += 1;
        self.counters.meter_attestations_submitted = sequence;
        self.emit_public_record("meter_attestation", &attestation_id)?;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn open_gas_io_budget(
        &mut self,
        request: OpenGasIoBudgetRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.budgets.len() < self.config.max_budgets,
            "budget capacity exceeded"
        );
        required("budget_commitment", &request.budget_commitment)?;
        let session = self
            .sealed_sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| format!("unknown session {}", request.session_id))?;
        ensure!(
            session.status.meterable(),
            "session is not ready for budget"
        );
        ensure!(session.budget_id.is_none(), "session already has a budget");
        ensure!(
            request.gas_limit <= session.max_gas_units,
            "gas budget exceeds session limit"
        );
        ensure!(
            request.io_limit_bytes <= session.max_io_bytes,
            "io budget exceeds session limit"
        );
        ensure!(
            request.log_limit_bytes <= session.max_log_bytes,
            "log budget exceeds session limit"
        );
        let sequence = self.counters.budgets_opened + 1;
        let budget_id = gas_io_budget_id(&request, sequence);
        let record = GasIoBudgetRecord {
            budget_id: budget_id.clone(),
            session_id: request.session_id.clone(),
            namespace_id: session.namespace_id.clone(),
            status: BudgetStatus::Opened,
            budget_commitment: request.budget_commitment,
            gas_limit: request.gas_limit,
            gas_spent: 0,
            io_limit_bytes: request.io_limit_bytes,
            io_spent_bytes: 0,
            log_limit_bytes: request.log_limit_bytes,
            log_spent_bytes: 0,
            gas_price_micro_credits: request.gas_price_micro_credits,
            io_price_micro_credits: request.io_price_micro_credits,
            locked_micro_credits: request.locked_micro_credits,
            spent_micro_credits: 0,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.session_ttl_blocks,
        };
        session.status = SessionStatus::Budgeted;
        session.budget_id = Some(budget_id.clone());
        self.counters.budgets_opened = sequence;
        self.counters.gas_units_reserved += request.gas_limit as u128;
        self.counters.io_bytes_reserved += request.io_limit_bytes as u128;
        self.budgets.insert(budget_id.clone(), record);
        self.emit_public_record("budget", &budget_id)?;
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: AllocateRedactionBudgetRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.redaction_budgets.len() < self.config.max_redaction_budgets,
            "redaction budget capacity exceeded"
        );
        required("policy_root", &request.policy_root)?;
        ensure!(request.reserved_units > 0, "redaction units are required");
        let session = self
            .sealed_sessions
            .get(&request.session_id)
            .ok_or_else(|| format!("unknown session {}", request.session_id))?;
        ensure!(
            session.redaction_policy_root == request.policy_root,
            "redaction policy root mismatch"
        );
        let sequence = self.redaction_budgets.len() as u64 + 1;
        let redaction_budget_id = redaction_budget_id(&request, sequence);
        let record = PrivacyRedactionBudgetRecord {
            redaction_budget_id: redaction_budget_id.clone(),
            session_id: request.session_id,
            namespace_id: session.namespace_id.clone(),
            class: request.class,
            status: RedactionStatus::Allocated,
            policy_root: request.policy_root,
            reserved_units: request.reserved_units,
            spent_units: 0,
            reserve_micro_credits: request.reserve_micro_credits,
            opened_at_height: self.height,
            expires_at_height: self.height + self.config.redaction_ttl_blocks,
        };
        self.counters.redaction_units_allocated += record.reserved_units as u128;
        self.redaction_budgets
            .insert(redaction_budget_id.clone(), record);
        self.emit_public_record("redaction_budget", &redaction_budget_id)?;
        self.refresh_roots();
        Ok(redaction_budget_id)
    }

    pub fn settle_sandbox_session(
        &mut self,
        request: SettleSandboxSessionRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        required(
            "final_meter_attestation_id",
            &request.final_meter_attestation_id,
        )?;
        required("final_receipt_root", &request.final_receipt_root)?;
        required("rebate_owner_commitment", &request.rebate_owner_commitment)?;
        let session = self
            .sealed_sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| format!("unknown session {}", request.session_id))?;
        ensure!(session.status.meterable(), "session is not settleable");
        ensure!(
            session.budget_id.as_deref() == Some(request.budget_id.as_str()),
            "session budget mismatch"
        );
        let budget = self
            .budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| format!("unknown budget {}", request.budget_id))?;
        ensure!(budget.status.spendable(), "budget is not spendable");
        ensure!(
            request.gas_spent <= budget.gas_limit,
            "gas spent exceeds budget"
        );
        ensure!(
            request.io_spent_bytes <= budget.io_limit_bytes,
            "io spent exceeds budget"
        );
        ensure!(
            request.log_spent_bytes <= budget.log_limit_bytes,
            "log spent exceeds budget"
        );
        let attestation = self
            .meter_attestations
            .get(&request.final_meter_attestation_id)
            .ok_or_else(|| {
                format!(
                    "unknown meter attestation {}",
                    request.final_meter_attestation_id
                )
            })?;
        ensure!(
            attestation.session_id == request.session_id,
            "attestation session mismatch"
        );
        let spent_micro_credits = gas_io_cost(
            request.gas_spent,
            request.io_spent_bytes,
            budget.gas_price_micro_credits,
            budget.io_price_micro_credits,
        );
        budget.gas_spent = request.gas_spent;
        budget.io_spent_bytes = request.io_spent_bytes;
        budget.log_spent_bytes = request.log_spent_bytes;
        budget.spent_micro_credits = spent_micro_credits;
        budget.status = if request.gas_spent == budget.gas_limit
            || request.io_spent_bytes == budget.io_limit_bytes
        {
            BudgetStatus::Exhausted
        } else {
            BudgetStatus::Settled
        };
        session.status = SessionStatus::Completed;
        self.counters.sessions_completed += 1;
        self.counters.gas_units_spent += request.gas_spent as u128;
        self.counters.io_bytes_spent += request.io_spent_bytes as u128;
        self.counters.log_bytes_spent += request.log_spent_bytes as u128;
        let rebate_id = self.issue_low_fee_rebate(
            &request.session_id,
            &request.budget_id,
            &budget.namespace_id.clone(),
            &request.rebate_owner_commitment,
            &request.final_receipt_root,
            spent_micro_credits,
        )?;
        self.emit_public_record("settled_session", &request.session_id)?;
        self.refresh_roots();
        Ok(rebate_id)
    }

    pub fn report_abuse(
        &mut self,
        request: ReportAbuseRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.abuse_reports.len() < self.config.max_abuse_reports,
            "abuse report capacity exceeded"
        );
        required("reporter_commitment", &request.reporter_commitment)?;
        required("evidence_root", &request.evidence_root)?;
        ensure!(
            request.session_id.is_some() || request.namespace_id.is_some(),
            "abuse report target is required"
        );
        let sequence = self.counters.abuse_reports + 1;
        let abuse_report_id = abuse_report_id(&request, sequence);
        let record = AbuseReportRecord {
            abuse_report_id: abuse_report_id.clone(),
            kind: request.kind,
            status: AbuseStatus::Accepted,
            session_id: request.session_id.clone(),
            namespace_id: request.namespace_id.clone(),
            reporter_commitment: request.reporter_commitment,
            evidence_root: request.evidence_root,
            slash_bps: self.config.abuse_slash_bps,
            reported_at_height: self.height,
            expires_at_height: self.height + self.config.quarantine_ttl_blocks,
        };
        self.abuse_reports.insert(abuse_report_id.clone(), record);
        self.counters.abuse_reports = sequence;
        let quarantine_id = self.open_quarantine(&abuse_report_id, &request)?;
        self.emit_public_record("abuse_report", &abuse_report_id)?;
        self.emit_public_record("quarantine", &quarantine_id)?;
        self.refresh_roots();
        Ok(abuse_report_id)
    }

    pub fn refresh_roots(&mut self) {
        self.roots.namespace_root =
            public_record_root("NAMESPACE", &values_record(&self.namespaces));
        self.roots.sealed_session_root =
            public_record_root("SEALED-SESSION", &values_record(&self.sealed_sessions));
        self.roots.meter_attestation_root = public_record_root(
            "METER-ATTESTATION",
            &values_record(&self.meter_attestations),
        );
        self.roots.budget_root = public_record_root("BUDGET", &values_record(&self.budgets));
        self.roots.rebate_root = public_record_root("REBATE", &values_record(&self.rebates));
        self.roots.abuse_report_root =
            public_record_root("ABUSE-REPORT", &values_record(&self.abuse_reports));
        self.roots.quarantine_root =
            public_record_root("QUARANTINE", &values_record(&self.quarantines));
        self.roots.redaction_budget_root =
            public_record_root("REDACTION-BUDGET", &values_record(&self.redaction_budgets));
        self.roots.public_record_root = public_record_root(
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
                "sealed_session_root": self.roots.sealed_session_root,
                "meter_attestation_root": self.roots.meter_attestation_root,
                "budget_root": self.roots.budget_root,
                "rebate_root": self.roots.rebate_root,
                "abuse_report_root": self.roots.abuse_report_root,
                "quarantine_root": self.roots.quarantine_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "public_record_root": self.roots.public_record_root,
            },
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

    fn issue_low_fee_rebate(
        &mut self,
        session_id: &str,
        budget_id: &str,
        namespace_id: &str,
        rebate_owner_commitment: &str,
        eligibility_root: &str,
        spent_micro_credits: u128,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.rebates.len() < self.config.max_rebates,
            "rebate capacity exceeded"
        );
        let credit_units = bps_amount(spent_micro_credits, self.config.low_fee_rebate_bps);
        let sequence = self.rebates.len() as u64 + 1;
        let rebate_id = deterministic_id(
            "REBATE-ID",
            sequence,
            &json!({
                "session_id": session_id,
                "budget_id": budget_id,
                "namespace_id": namespace_id,
                "eligibility_root": eligibility_root,
                "credit_units": credit_units,
            }),
        );
        let record = LowFeeRebateCreditRecord {
            rebate_id: rebate_id.clone(),
            session_id: session_id.to_string(),
            budget_id: budget_id.to_string(),
            namespace_id: namespace_id.to_string(),
            status: RebateStatus::Claimable,
            rebate_owner_commitment: rebate_owner_commitment.to_string(),
            eligibility_root: eligibility_root.to_string(),
            credit_units,
            rebate_bps: self.config.low_fee_rebate_bps,
            issued_at_height: self.height,
            expires_at_height: self.height + self.config.rebate_ttl_blocks,
        };
        self.counters.rebate_credits_issued += credit_units;
        self.rebates.insert(rebate_id.clone(), record);
        self.emit_public_record("rebate", &rebate_id)?;
        Ok(rebate_id)
    }

    fn open_quarantine(
        &mut self,
        abuse_report_id: &str,
        request: &ReportAbuseRequest,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.quarantines.len() < self.config.max_quarantines,
            "quarantine capacity exceeded"
        );
        let (scope, target_id) = if let Some(session_id) = request.session_id.as_ref() {
            if let Some(session) = self.sealed_sessions.get_mut(session_id) {
                session.status = SessionStatus::Quarantined;
            }
            (QuarantineScope::Session, session_id.clone())
        } else {
            let namespace_id = request
                .namespace_id
                .as_ref()
                .ok_or_else(|| "namespace target required".to_string())?;
            if let Some(namespace) = self.namespaces.get_mut(namespace_id) {
                namespace.status = NamespaceStatus::Quarantined;
            }
            (QuarantineScope::Namespace, namespace_id.clone())
        };
        let sequence = self.quarantines.len() as u64 + 1;
        let quarantine_id = deterministic_id(
            "QUARANTINE-ID",
            sequence,
            &json!({
                "abuse_report_id": abuse_report_id,
                "scope": scope,
                "target_id": target_id,
            }),
        );
        let reserve_micro_credits = bps_amount(
            self.config
                .base_gas_price_micro_credits
                .saturating_mul(self.config.max_gas_units as u128),
            self.config.quarantine_reserve_bps,
        );
        let quarantine_root = deterministic_record_root(
            "PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:QUARANTINE-COMMITMENT",
            &json!({
                "abuse_report_id": abuse_report_id,
                "target_id": target_id,
                "reserve_micro_credits": reserve_micro_credits,
            }),
        );
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            scope,
            status: QuarantineStatus::Active,
            target_id,
            abuse_report_id: abuse_report_id.to_string(),
            quarantine_root,
            reserve_micro_credits,
            opened_at_height: self.height,
            releases_at_height: self.height + self.config.quarantine_ttl_blocks,
        };
        self.quarantines.insert(quarantine_id.clone(), record);
        self.counters.active_quarantines += 1;
        Ok(quarantine_id)
    }

    fn emit_public_record(
        &mut self,
        record_kind: &str,
        subject_id: &str,
    ) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<String> {
        ensure!(
            self.deterministic_public_records.len() < self.config.max_public_records,
            "public record capacity exceeded"
        );
        let sequence = self.counters.deterministic_public_records + 1;
        let record_root = deterministic_record_root(
            "PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:PUBLIC-RECORD-SUBJECT",
            &json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "height": self.height,
                "sequence": sequence,
            }),
        );
        let public_record_id = deterministic_id(
            "PUBLIC-RECORD-ID",
            sequence,
            &json!({
                "record_kind": record_kind,
                "subject_id": subject_id,
                "record_root": record_root,
            }),
        );
        let record = DeterministicPublicRecord {
            public_record_id: public_record_id.clone(),
            record_kind: record_kind.to_string(),
            subject_id: subject_id.to_string(),
            record_root,
            state_root_after: self.state_root(),
            emitted_at_height: self.height,
        };
        self.deterministic_public_records
            .insert(public_record_id.clone(), record);
        self.counters.deterministic_public_records = sequence;
        Ok(public_record_id)
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let namespace_id = state
        .register_namespace(RegisterNamespaceRequest {
            kind: NamespaceKind::ContractVm,
            owner_commitment: "owner:commitment:runtime-sandbox-devnet".to_string(),
            namespace_commitment: "namespace:commitment:confidential-contract-vm".to_string(),
            code_root: "code:root:runtime-sandbox-meter-demo".to_string(),
            policy_root: "policy:root:gas-io-low-fee-runtime".to_string(),
            redaction_policy_root: "redaction:policy:root:logs-and-traces".to_string(),
            min_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet namespace registration must succeed");
    let session_id = state
        .seal_sandbox_session(SealSandboxSessionRequest {
            namespace_id,
            profile: SandboxProfile::CrossContract,
            caller_commitment: "caller:commitment:demo-wallet".to_string(),
            sealed_envelope_root: "sealed:envelope:root:demo-session".to_string(),
            session_nullifier: "session:nullifier:demo-001".to_string(),
            meter_key_commitment: "meter:key:commitment:demo".to_string(),
            privacy_set_root: "privacy:set:root:demo-524288".to_string(),
            redaction_policy_root: "redaction:policy:root:logs-and-traces".to_string(),
            max_gas_units: 8_000_000,
            max_io_bytes: 1_048_576,
            max_log_bytes: 65_536,
        })
        .expect("devnet sealed session must succeed");
    let attestation_id = state
        .submit_meter_attestation(SubmitMeterAttestationRequest {
            session_id: session_id.clone(),
            kind: AttestationKind::MeterReading,
            signer_set_root: "pq:signer:set:root:devnet-meter-committee".to_string(),
            attestation_root: "pq:meter:attestation:root:demo".to_string(),
            transcript_root: "meter:transcript:root:demo".to_string(),
            measured_gas_units: 3_250_000,
            measured_io_bytes: 131_072,
            measured_log_bytes: 8_192,
            redacted_field_count: 24,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        })
        .expect("devnet meter attestation must succeed");
    let budget_id = state
        .open_gas_io_budget(OpenGasIoBudgetRequest {
            session_id: session_id.clone(),
            budget_commitment: "budget:commitment:gas-io-demo".to_string(),
            gas_limit: 4_000_000,
            io_limit_bytes: 262_144,
            log_limit_bytes: 16_384,
            gas_price_micro_credits: DEFAULT_BASE_GAS_PRICE_MICRO_CREDITS,
            io_price_micro_credits: DEFAULT_BASE_IO_PRICE_MICRO_CREDITS,
            locked_micro_credits: 4_250_000_000,
        })
        .expect("devnet budget must succeed");
    state
        .allocate_redaction_budget(AllocateRedactionBudgetRequest {
            session_id: session_id.clone(),
            class: RedactionClass::MeterTrace,
            policy_root: "redaction:policy:root:logs-and-traces".to_string(),
            reserved_units: 64,
            reserve_micro_credits: 32_000,
        })
        .expect("devnet redaction budget must succeed");
    state
        .settle_sandbox_session(SettleSandboxSessionRequest {
            session_id,
            budget_id,
            final_meter_attestation_id: attestation_id,
            final_receipt_root: "runtime:receipt:root:demo-settlement".to_string(),
            gas_spent: 3_250_000,
            io_spent_bytes: 131_072,
            log_spent_bytes: 8_192,
            rebate_owner_commitment: "rebate:owner:commitment:demo-wallet".to_string(),
        })
        .expect("devnet settlement must succeed");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let session_id = state
        .sealed_sessions
        .keys()
        .next()
        .cloned()
        .expect("demo has a session");
    state
        .report_abuse(ReportAbuseRequest {
            kind: AbuseKind::MeterForgery,
            session_id: Some(session_id),
            namespace_id: None,
            reporter_commitment: "reporter:commitment:watchtower-demo".to_string(),
            evidence_root: "abuse:evidence:root:meter-forgery-demo".to_string(),
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

pub fn namespace_id(request: &RegisterNamespaceRequest, sequence: u64) -> String {
    deterministic_id("NAMESPACE-ID", sequence, &request.public_record())
}

pub fn sealed_session_id(request: &SealSandboxSessionRequest, sequence: u64) -> String {
    deterministic_id("SEALED-SESSION-ID", sequence, &request.public_record())
}

pub fn meter_attestation_id(request: &SubmitMeterAttestationRequest, sequence: u64) -> String {
    deterministic_id("METER-ATTESTATION-ID", sequence, &request.public_record())
}

pub fn gas_io_budget_id(request: &OpenGasIoBudgetRequest, sequence: u64) -> String {
    deterministic_id("GAS-IO-BUDGET-ID", sequence, &request.public_record())
}

pub fn redaction_budget_id(request: &AllocateRedactionBudgetRequest, sequence: u64) -> String {
    deterministic_id("REDACTION-BUDGET-ID", sequence, &request.public_record())
}

pub fn abuse_report_id(request: &ReportAbuseRequest, sequence: u64) -> String {
    deterministic_id("ABUSE-REPORT-ID", sequence, &request.public_record())
}

pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:{kind}"),
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
        &format!("PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:{domain}-ROOT"),
        records,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:STATE-ROOT",
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

impl PublicRecord for NamespaceCommitmentRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SealedSandboxSessionRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqMeterAttestationRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for GasIoBudgetRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for LowFeeRebateCreditRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for AbuseReportRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for QuarantineRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyRedactionBudgetRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for DeterministicPublicRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn required(
    name: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractRuntimeSandboxMeterRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn gas_io_cost(
    gas_units: u64,
    io_bytes: u64,
    gas_price_micro_credits: u128,
    io_price_micro_credits: u128,
) -> u128 {
    gas_price_micro_credits
        .saturating_mul(gas_units as u128)
        .saturating_add(io_price_micro_credits.saturating_mul(io_bytes as u128))
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-RUNTIME-SANDBOX-METER:{domain}-EMPTY"),
        &[],
    )
}
