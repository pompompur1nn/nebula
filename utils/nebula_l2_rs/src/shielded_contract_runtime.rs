use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ShieldedContractRuntimeResult<T> = Result<T, String>;

pub const SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-l2-shielded-contract-runtime-v1";
pub const SHIELDED_CONTRACT_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const SHIELDED_CONTRACT_RUNTIME_HOST: &str = "deterministic-pq-private-parallel-contract-host";
pub const SHIELDED_CONTRACT_RUNTIME_ENCRYPTION_SCHEME: &str = "ML-KEM-768+SHAKE256-state-cell-seal";
pub const SHIELDED_CONTRACT_RUNTIME_COMMITMENT_SCHEME: &str =
    "SHAKE256-canonical-json-merkle-runtime";
pub const SHIELDED_CONTRACT_RUNTIME_PQ_ACCOUNT_SCHEME: &str = "ML-DSA-65";
pub const SHIELDED_CONTRACT_RUNTIME_PQ_RECOVERY_SCHEME: &str = "SLH-DSA-SHAKE-128s";
pub const SHIELDED_CONTRACT_RUNTIME_SESSION_SCHEME: &str = "ML-KEM-768+ML-DSA-65-devnet-session";
pub const SHIELDED_CONTRACT_RUNTIME_PROOF_SYSTEM: &str = "nebula-devnet-shielded-contract-proof-v1";
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_RENT_ASSET_ID: &str = "dnr-devnet-rent";
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_VIEW_KEY_TTL_BLOCKS: u64 = 720;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS: u64 = 24;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 128;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_RENT_EPOCH_BLOCKS: u64 = 10_080;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_CALL_GAS: u64 = 4_000_000;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_BLOCK_GAS: u64 = 24_000_000;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_PARALLEL_SHARDS: u16 = 16;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_STATE_CELL_BYTES: u64 = 32 * 1024;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_MIN_RENT_DEPOSIT_UNITS: u64 = 10;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS: u16 = 6_000;
pub const SHIELDED_CONTRACT_RUNTIME_DEFAULT_PROOF_BYTE_PRICE_UNITS: u64 = 2;
pub const SHIELDED_CONTRACT_RUNTIME_MAX_BPS: u16 = 10_000;
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE: &str = "active";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_PENDING: &str = "pending";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_PAUSED: &str = "paused";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_RETIRED: &str = "retired";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_REVOKED: &str = "revoked";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_EXPIRED: &str = "expired";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_ACCEPTED: &str = "accepted";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_EXECUTED: &str = "executed";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_REVERTED: &str = "reverted";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_DISPUTED: &str = "disputed";
pub const SHIELDED_CONTRACT_RUNTIME_STATUS_SLASHED: &str = "slashed";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedContractClassKind {
    Account,
    Token,
    SwapPool,
    LendingMarket,
    Paymaster,
    AccessController,
    OracleAdapter,
    RollbackGuard,
    Custom(String),
}

impl ShieldedContractClassKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Account => "account".to_string(),
            Self::Token => "token".to_string(),
            Self::SwapPool => "swap_pool".to_string(),
            Self::LendingMarket => "lending_market".to_string(),
            Self::Paymaster => "paymaster".to_string(),
            Self::AccessController => "access_controller".to_string(),
            Self::OracleAdapter => "oracle_adapter".to_string(),
            Self::RollbackGuard => "rollback_guard".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedContractPermission {
    ClassAdmin,
    Instantiate,
    Call,
    DelegateCall,
    ReadState,
    WriteState,
    EmitEvent,
    ScheduleProof,
    SpendGasCredit,
    UpdateDisclosurePolicy,
    RotateViewKey,
    OpenPqSession,
    CrossContractCall,
    RollbackPropose,
    FraudChallenge,
    Custom(String),
}

impl ShieldedContractPermission {
    pub fn as_str(&self) -> String {
        match self {
            Self::ClassAdmin => "class_admin".to_string(),
            Self::Instantiate => "instantiate".to_string(),
            Self::Call => "call".to_string(),
            Self::DelegateCall => "delegate_call".to_string(),
            Self::ReadState => "read_state".to_string(),
            Self::WriteState => "write_state".to_string(),
            Self::EmitEvent => "emit_event".to_string(),
            Self::ScheduleProof => "schedule_proof".to_string(),
            Self::SpendGasCredit => "spend_gas_credit".to_string(),
            Self::UpdateDisclosurePolicy => "update_disclosure_policy".to_string(),
            Self::RotateViewKey => "rotate_view_key".to_string(),
            Self::OpenPqSession => "open_pq_session".to_string(),
            Self::CrossContractCall => "cross_contract_call".to_string(),
            Self::RollbackPropose => "rollback_propose".to_string(),
            Self::FraudChallenge => "fraud_challenge".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedAccessMode {
    Read,
    Write,
    ReadWrite,
    ProveOnly,
    ViewOnly,
    Revoke,
}

impl ShieldedAccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::ReadWrite => "read_write",
            Self::ProveOnly => "prove_only",
            Self::ViewOnly => "view_only",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateCellVisibility {
    CommitmentOnly,
    SequencerSealed,
    OwnerDecryptable,
    AuditorDecryptable,
    SelectivelyDisclosed,
    PublicSummary,
}

impl StateCellVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::SequencerSealed => "sequencer_sealed",
            Self::OwnerDecryptable => "owner_decryptable",
            Self::AuditorDecryptable => "auditor_decryptable",
            Self::SelectivelyDisclosed => "selectively_disclosed",
            Self::PublicSummary => "public_summary",
        }
    }

    pub fn publishes_ciphertext(self) -> bool {
        !matches!(self, Self::CommitmentOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAudience {
    Owner,
    Counterparty,
    Auditor,
    Regulator,
    SequencerCommittee,
    Public,
}

impl DisclosureAudience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Counterparty => "counterparty",
            Self::Auditor => "auditor",
            Self::Regulator => "regulator",
            Self::SequencerCommittee => "sequencer_committee",
            Self::Public => "public",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKeyScope {
    Contract,
    Method,
    StatePrefix,
    Cell,
    Receipt,
    AuditWindow,
}

impl ViewKeyScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::Method => "method",
            Self::StatePrefix => "state_prefix",
            Self::Cell => "cell",
            Self::Receipt => "receipt",
            Self::AuditWindow => "audit_window",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationScheme {
    MlDsa65,
    SlhDsaShake128s,
    HybridMlDsaSlhDsa,
    SessionKemBound,
}

impl PqAuthorizationScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa65 => SHIELDED_CONTRACT_RUNTIME_PQ_ACCOUNT_SCHEME,
            Self::SlhDsaShake128s => SHIELDED_CONTRACT_RUNTIME_PQ_RECOVERY_SCHEME,
            Self::HybridMlDsaSlhDsa => "ML-DSA-65+SLH-DSA-SHAKE-128s",
            Self::SessionKemBound => SHIELDED_CONTRACT_RUNTIME_SESSION_SCHEME,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSessionStatus {
    Pending,
    Active,
    Expired,
    Revoked,
    Compromised,
}

impl PqSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => SHIELDED_CONTRACT_RUNTIME_STATUS_PENDING,
            Self::Active => SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
            Self::Expired => SHIELDED_CONTRACT_RUNTIME_STATUS_EXPIRED,
            Self::Revoked => SHIELDED_CONTRACT_RUNTIME_STATUS_REVOKED,
            Self::Compromised => "compromised",
        }
    }

    pub fn allows_calls(self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkProofObligationKind {
    CallIntegrity,
    StateTransition,
    AccessListMembership,
    ViewKeyDisclosure,
    TokenConservation,
    FeeSponsorship,
    CrossContractConsistency,
    RollbackSafety,
    FraudChallenge,
    Custom(String),
}

impl ZkProofObligationKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::CallIntegrity => "call_integrity".to_string(),
            Self::StateTransition => "state_transition".to_string(),
            Self::AccessListMembership => "access_list_membership".to_string(),
            Self::ViewKeyDisclosure => "view_key_disclosure".to_string(),
            Self::TokenConservation => "token_conservation".to_string(),
            Self::FeeSponsorship => "fee_sponsorship".to_string(),
            Self::CrossContractConsistency => "cross_contract_consistency".to_string(),
            Self::RollbackSafety => "rollback_safety".to_string(),
            Self::FraudChallenge => "fraud_challenge".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZkProofStatus {
    Required,
    Scheduled,
    Submitted,
    Verified,
    Failed,
    Waived,
}

impl ZkProofStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Scheduled => "scheduled",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Failed => "failed",
            Self::Waived => "waived",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasFeeLaneKind {
    Interactive,
    BulkProof,
    LowFeePrivateCall,
    Sponsored,
    RentSettlement,
    FraudChallenge,
}

impl GasFeeLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Interactive => "interactive",
            Self::BulkProof => "bulk_proof",
            Self::LowFeePrivateCall => "low_fee_private_call",
            Self::Sponsored => "sponsored",
            Self::RentSettlement => "rent_settlement",
            Self::FraudChallenge => "fraud_challenge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GasPriority {
    Background,
    Normal,
    Fast,
    Urgent,
}

impl GasPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Normal => "normal",
            Self::Fast => "fast",
            Self::Urgent => "urgent",
        }
    }

    pub fn multiplier_bps(self) -> u16 {
        match self {
            Self::Background => 7_500,
            Self::Normal => 10_000,
            Self::Fast => 12_500,
            Self::Urgent => 17_500,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionShardKind {
    ReadMostly,
    WriteHeavy,
    ProofOnly,
    CrossContract,
    RentMaintenance,
}

impl ExecutionShardKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadMostly => "read_mostly",
            Self::WriteHeavy => "write_heavy",
            Self::ProofOnly => "proof_only",
            Self::CrossContract => "cross_contract",
            Self::RentMaintenance => "rent_maintenance",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionShardStatus {
    Open,
    Sealed,
    Draining,
    Paused,
}

impl ExecutionShardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Draining => "draining",
            Self::Paused => SHIELDED_CONTRACT_RUNTIME_STATUS_PAUSED,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallReceiptStatus {
    Accepted,
    Executed,
    Reverted,
    Proved,
    Disputed,
}

impl CallReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => SHIELDED_CONTRACT_RUNTIME_STATUS_ACCEPTED,
            Self::Executed => SHIELDED_CONTRACT_RUNTIME_STATUS_EXECUTED,
            Self::Reverted => SHIELDED_CONTRACT_RUNTIME_STATUS_REVERTED,
            Self::Proved => "proved",
            Self::Disputed => SHIELDED_CONTRACT_RUNTIME_STATUS_DISPUTED,
        }
    }

    pub fn is_success(self) -> bool {
        matches!(self, Self::Executed | Self::Proved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptVisibility {
    CommitmentOnly,
    EncryptedTrace,
    SelectiveDisclosure,
    PublicSummary,
}

impl ReceiptVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::EncryptedTrace => "encrypted_trace",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodec {
    None,
    CanonicalJsonDictionary,
    PoseidonFriendlyBits,
    SparseMerkleDelta,
    ZstdDictionaryHint,
}

impl CompressionCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CanonicalJsonDictionary => "canonical_json_dictionary",
            Self::PoseidonFriendlyBits => "poseidon_friendly_bits",
            Self::SparseMerkleDelta => "sparse_merkle_delta",
            Self::ZstdDictionaryHint => "zstd_dictionary_hint",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudEvidenceKind {
    InvalidStateTransition,
    MissingProof,
    UnauthorizedView,
    FeeOvercharge,
    ShardConflict,
    RentEvasion,
    RollbackMismatch,
    Custom(String),
}

impl FraudEvidenceKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::InvalidStateTransition => "invalid_state_transition".to_string(),
            Self::MissingProof => "missing_proof".to_string(),
            Self::UnauthorizedView => "unauthorized_view".to_string(),
            Self::FeeOvercharge => "fee_overcharge".to_string(),
            Self::ShardConflict => "shard_conflict".to_string(),
            Self::RentEvasion => "rent_evasion".to_string(),
            Self::RollbackMismatch => "rollback_mismatch".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudEvidenceStatus {
    Open,
    Accepted,
    Rejected,
    Slashed,
}

impl FraudEvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => SHIELDED_CONTRACT_RUNTIME_STATUS_ACCEPTED,
            Self::Rejected => "rejected",
            Self::Slashed => SHIELDED_CONTRACT_RUNTIME_STATUS_SLASHED,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractRuntimeConfig {
    pub operator_label: String,
    pub fee_asset_id: String,
    pub rent_asset_id: String,
    pub max_call_gas: u64,
    pub max_block_gas: u64,
    pub max_parallel_shards: u16,
    pub max_state_cell_bytes: u64,
    pub default_view_key_ttl_blocks: u64,
    pub default_session_ttl_blocks: u64,
    pub default_proof_ttl_blocks: u64,
    pub default_receipt_ttl_blocks: u64,
    pub rent_epoch_blocks: u64,
    pub min_rent_deposit_units: u64,
    pub low_fee_rebate_bps: u16,
    pub proof_byte_price_units: u64,
    pub require_pq_authorization: bool,
    pub require_zk_obligations: bool,
    pub allow_parallel_execution: bool,
    pub enable_storage_rent: bool,
    pub enable_compression_hints: bool,
}

impl Default for ShieldedContractRuntimeConfig {
    fn default() -> Self {
        Self {
            operator_label: "devnet-shielded-runtime-operator".to_string(),
            fee_asset_id: SHIELDED_CONTRACT_RUNTIME_DEFAULT_FEE_ASSET_ID.to_string(),
            rent_asset_id: SHIELDED_CONTRACT_RUNTIME_DEFAULT_RENT_ASSET_ID.to_string(),
            max_call_gas: SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_CALL_GAS,
            max_block_gas: SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_BLOCK_GAS,
            max_parallel_shards: SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_PARALLEL_SHARDS,
            max_state_cell_bytes: SHIELDED_CONTRACT_RUNTIME_DEFAULT_MAX_STATE_CELL_BYTES,
            default_view_key_ttl_blocks: SHIELDED_CONTRACT_RUNTIME_DEFAULT_VIEW_KEY_TTL_BLOCKS,
            default_session_ttl_blocks: SHIELDED_CONTRACT_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS,
            default_proof_ttl_blocks: SHIELDED_CONTRACT_RUNTIME_DEFAULT_PROOF_TTL_BLOCKS,
            default_receipt_ttl_blocks: SHIELDED_CONTRACT_RUNTIME_DEFAULT_RECEIPT_TTL_BLOCKS,
            rent_epoch_blocks: SHIELDED_CONTRACT_RUNTIME_DEFAULT_RENT_EPOCH_BLOCKS,
            min_rent_deposit_units: SHIELDED_CONTRACT_RUNTIME_DEFAULT_MIN_RENT_DEPOSIT_UNITS,
            low_fee_rebate_bps: SHIELDED_CONTRACT_RUNTIME_DEFAULT_LOW_FEE_REBATE_BPS,
            proof_byte_price_units: SHIELDED_CONTRACT_RUNTIME_DEFAULT_PROOF_BYTE_PRICE_UNITS,
            require_pq_authorization: true,
            require_zk_obligations: true,
            allow_parallel_execution: true,
            enable_storage_rent: true,
            enable_compression_hints: true,
        }
    }
}

impl ShieldedContractRuntimeConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_contract_runtime_config",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "operator_label": self.operator_label,
            "fee_asset_id": self.fee_asset_id,
            "rent_asset_id": self.rent_asset_id,
            "max_call_gas": self.max_call_gas,
            "max_block_gas": self.max_block_gas,
            "max_parallel_shards": self.max_parallel_shards,
            "max_state_cell_bytes": self.max_state_cell_bytes,
            "default_view_key_ttl_blocks": self.default_view_key_ttl_blocks,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_proof_ttl_blocks": self.default_proof_ttl_blocks,
            "default_receipt_ttl_blocks": self.default_receipt_ttl_blocks,
            "rent_epoch_blocks": self.rent_epoch_blocks,
            "min_rent_deposit_units": self.min_rent_deposit_units,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "proof_byte_price_units": self.proof_byte_price_units,
            "require_pq_authorization": self.require_pq_authorization,
            "require_zk_obligations": self.require_zk_obligations,
            "allow_parallel_execution": self.allow_parallel_execution,
            "enable_storage_rent": self.enable_storage_rent,
            "enable_compression_hints": self.enable_compression_hints,
        })
    }

    pub fn config_root(&self) -> String {
        runtime_payload_root("SHIELDED-RUNTIME-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.operator_label, "runtime operator label")?;
        ensure_non_empty(&self.fee_asset_id, "runtime fee asset id")?;
        ensure_non_empty(&self.rent_asset_id, "runtime rent asset id")?;
        ensure_positive(self.max_call_gas, "runtime max call gas")?;
        ensure_positive(self.max_block_gas, "runtime max block gas")?;
        ensure_positive(
            self.max_parallel_shards as u64,
            "runtime max parallel shards",
        )?;
        ensure_positive(self.max_state_cell_bytes, "runtime max state cell bytes")?;
        ensure_positive(
            self.default_session_ttl_blocks,
            "runtime default session ttl blocks",
        )?;
        ensure_positive(
            self.default_view_key_ttl_blocks,
            "runtime default view key ttl blocks",
        )?;
        ensure_positive(
            self.default_proof_ttl_blocks,
            "runtime default proof ttl blocks",
        )?;
        ensure_positive(self.rent_epoch_blocks, "runtime rent epoch blocks")?;
        if self.max_call_gas > self.max_block_gas {
            return Err("runtime max call gas cannot exceed max block gas".to_string());
        }
        if self.low_fee_rebate_bps > SHIELDED_CONTRACT_RUNTIME_MAX_BPS {
            return Err("runtime low fee rebate bps exceeds 100%".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInterfaceMethod {
    pub method_id: String,
    pub class_id: String,
    pub selector: String,
    pub entrypoint: String,
    pub arg_schema_root: String,
    pub return_schema_root: String,
    pub required_permission_root: String,
    pub default_proof_kind: ZkProofObligationKind,
    pub max_gas: u64,
    pub private_args: bool,
    pub emits_encrypted_events: bool,
}

impl ContractInterfaceMethod {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        selector: impl Into<String>,
        entrypoint: impl Into<String>,
        arg_schema_root: impl Into<String>,
        return_schema_root: impl Into<String>,
        required_permissions: Vec<ShieldedContractPermission>,
        default_proof_kind: ZkProofObligationKind,
        max_gas: u64,
        private_args: bool,
        emits_encrypted_events: bool,
    ) -> ShieldedContractRuntimeResult<Self> {
        let class_id = class_id.into();
        let selector = selector.into();
        let entrypoint = entrypoint.into();
        let arg_schema_root = arg_schema_root.into();
        let return_schema_root = return_schema_root.into();
        ensure_non_empty(&class_id, "contract method class id")?;
        ensure_non_empty(&selector, "contract method selector")?;
        ensure_non_empty(&entrypoint, "contract method entrypoint")?;
        ensure_non_empty(&arg_schema_root, "contract method arg schema root")?;
        ensure_non_empty(&return_schema_root, "contract method return schema root")?;
        ensure_positive(max_gas, "contract method max gas")?;
        let required_permission_root = permission_set_root(&required_permissions);
        let method_id = contract_interface_method_id(
            &class_id,
            &selector,
            &entrypoint,
            &arg_schema_root,
            &return_schema_root,
            &required_permission_root,
            &default_proof_kind,
            max_gas,
        );
        Ok(Self {
            method_id,
            class_id,
            selector,
            entrypoint,
            arg_schema_root,
            return_schema_root,
            required_permission_root,
            default_proof_kind,
            max_gas,
            private_args,
            emits_encrypted_events,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_interface_method",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "method_id": self.method_id,
            "class_id": self.class_id,
            "selector": self.selector,
            "entrypoint": self.entrypoint,
            "arg_schema_root": self.arg_schema_root,
            "return_schema_root": self.return_schema_root,
            "required_permission_root": self.required_permission_root,
            "default_proof_kind": self.default_proof_kind.as_str(),
            "max_gas": self.max_gas,
            "private_args": self.private_args,
            "emits_encrypted_events": self.emits_encrypted_events,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.method_id, "contract method id")?;
        ensure_non_empty(&self.class_id, "contract method class id")?;
        ensure_non_empty(&self.selector, "contract method selector")?;
        ensure_non_empty(&self.entrypoint, "contract method entrypoint")?;
        ensure_non_empty(&self.arg_schema_root, "contract method arg schema root")?;
        ensure_non_empty(
            &self.return_schema_root,
            "contract method return schema root",
        )?;
        ensure_non_empty(
            &self.required_permission_root,
            "contract method required permission root",
        )?;
        ensure_positive(self.max_gas, "contract method max gas")?;
        let expected = contract_interface_method_id(
            &self.class_id,
            &self.selector,
            &self.entrypoint,
            &self.arg_schema_root,
            &self.return_schema_root,
            &self.required_permission_root,
            &self.default_proof_kind,
            self.max_gas,
        );
        ensure_matches(&self.method_id, &expected, "contract method id")?;
        Ok(contract_interface_method_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractClassManifest {
    pub class_id: String,
    pub name: String,
    pub version: String,
    pub kind: ShieldedContractClassKind,
    pub code_commitment: String,
    pub code_size_bytes: u64,
    pub abi_root: String,
    pub method_root: String,
    pub constructor_root: String,
    pub state_schema_root: String,
    pub event_schema_root: String,
    pub proof_policy_root: String,
    pub disclosure_policy_root: String,
    pub compression_policy_root: String,
    pub max_state_cells: u64,
    pub max_call_gas: u64,
    pub publisher_commitment: String,
    pub published_at_height: u64,
    pub lifecycle_status: String,
}

impl ShieldedContractClassManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        kind: ShieldedContractClassKind,
        code_commitment: impl Into<String>,
        code_size_bytes: u64,
        methods: Vec<ContractInterfaceMethod>,
        constructor_root: impl Into<String>,
        state_schema_root: impl Into<String>,
        event_schema_root: impl Into<String>,
        proof_policy_root: impl Into<String>,
        disclosure_policy_root: impl Into<String>,
        compression_policy_root: impl Into<String>,
        max_state_cells: u64,
        max_call_gas: u64,
        publisher_commitment: impl Into<String>,
        published_at_height: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let name = name.into();
        let version = version.into();
        let code_commitment = code_commitment.into();
        let constructor_root = constructor_root.into();
        let state_schema_root = state_schema_root.into();
        let event_schema_root = event_schema_root.into();
        let proof_policy_root = proof_policy_root.into();
        let disclosure_policy_root = disclosure_policy_root.into();
        let compression_policy_root = compression_policy_root.into();
        let publisher_commitment = publisher_commitment.into();
        ensure_non_empty(&name, "contract class name")?;
        ensure_non_empty(&version, "contract class version")?;
        ensure_non_empty(&code_commitment, "contract class code commitment")?;
        ensure_positive(code_size_bytes, "contract class code size bytes")?;
        ensure_positive(max_state_cells, "contract class max state cells")?;
        ensure_positive(max_call_gas, "contract class max call gas")?;
        let abi_root = contract_interface_method_root_from_slice(&methods);
        let method_root = abi_root.clone();
        let class_id = contract_class_manifest_id(
            &name,
            &version,
            &kind,
            &code_commitment,
            code_size_bytes,
            &abi_root,
            &state_schema_root,
            &event_schema_root,
            &publisher_commitment,
            published_at_height,
        );
        Ok(Self {
            class_id,
            name,
            version,
            kind,
            code_commitment,
            code_size_bytes,
            abi_root,
            method_root,
            constructor_root,
            state_schema_root,
            event_schema_root,
            proof_policy_root,
            disclosure_policy_root,
            compression_policy_root,
            max_state_cells,
            max_call_gas,
            publisher_commitment,
            published_at_height,
            lifecycle_status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_contract_class_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "class_id": self.class_id,
            "name": self.name,
            "version": self.version,
            "class_kind": self.kind.as_str(),
            "code_commitment": self.code_commitment,
            "code_size_bytes": self.code_size_bytes,
            "abi_root": self.abi_root,
            "method_root": self.method_root,
            "constructor_root": self.constructor_root,
            "state_schema_root": self.state_schema_root,
            "event_schema_root": self.event_schema_root,
            "proof_policy_root": self.proof_policy_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "compression_policy_root": self.compression_policy_root,
            "max_state_cells": self.max_state_cells,
            "max_call_gas": self.max_call_gas,
            "publisher_commitment": self.publisher_commitment,
            "published_at_height": self.published_at_height,
            "lifecycle_status": self.lifecycle_status,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.class_id, "contract class id")?;
        ensure_non_empty(&self.name, "contract class name")?;
        ensure_non_empty(&self.version, "contract class version")?;
        ensure_non_empty(&self.code_commitment, "contract class code commitment")?;
        ensure_non_empty(&self.abi_root, "contract class abi root")?;
        ensure_non_empty(&self.method_root, "contract class method root")?;
        ensure_non_empty(&self.constructor_root, "contract class constructor root")?;
        ensure_non_empty(&self.state_schema_root, "contract class state schema root")?;
        ensure_non_empty(&self.event_schema_root, "contract class event schema root")?;
        ensure_non_empty(&self.proof_policy_root, "contract class proof policy root")?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "contract class disclosure policy root",
        )?;
        ensure_non_empty(
            &self.compression_policy_root,
            "contract class compression policy root",
        )?;
        ensure_non_empty(
            &self.publisher_commitment,
            "contract class publisher commitment",
        )?;
        ensure_positive(self.code_size_bytes, "contract class code size bytes")?;
        ensure_positive(self.max_state_cells, "contract class max state cells")?;
        ensure_positive(self.max_call_gas, "contract class max call gas")?;
        ensure_status(
            &self.lifecycle_status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
                SHIELDED_CONTRACT_RUNTIME_STATUS_PENDING,
                SHIELDED_CONTRACT_RUNTIME_STATUS_PAUSED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_RETIRED,
            ],
            "contract class lifecycle status",
        )?;
        let expected = contract_class_manifest_id(
            &self.name,
            &self.version,
            &self.kind,
            &self.code_commitment,
            self.code_size_bytes,
            &self.abi_root,
            &self.state_schema_root,
            &self.event_schema_root,
            &self.publisher_commitment,
            self.published_at_height,
        );
        ensure_matches(&self.class_id, &expected, "contract class id")?;
        Ok(contract_class_manifest_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStateCell {
    pub cell_id: String,
    pub contract_id: String,
    pub cell_key_commitment: String,
    pub owner_commitment: String,
    pub visibility: StateCellVisibility,
    pub ciphertext_root: String,
    pub ciphertext_bytes: u64,
    pub nonce_root: String,
    pub aad_root: String,
    pub version: u64,
    pub compression_hint_id: String,
    pub rent_deposit_units: u64,
    pub last_touched_height: u64,
    pub status: String,
}

impl EncryptedStateCell {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        cell_key: impl Into<String>,
        owner_commitment: impl Into<String>,
        plaintext_commitment: &Value,
        visibility: StateCellVisibility,
        compression_hint_id: impl Into<String>,
        rent_deposit_units: u64,
        height: u64,
        nonce: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let cell_key_commitment = runtime_string_root("STATE-CELL-KEY", &cell_key.into());
        let owner_commitment = owner_commitment.into();
        let compression_hint_id = compression_hint_id.into();
        ensure_non_empty(&contract_id, "state cell contract id")?;
        ensure_non_empty(&owner_commitment, "state cell owner commitment")?;
        let plaintext_root = runtime_payload_root("STATE-CELL-PLAINTEXT", plaintext_commitment);
        let aad_root = runtime_payload_root(
            "STATE-CELL-AAD",
            &json!({
                "contract_id": contract_id,
                "cell_key_commitment": cell_key_commitment,
                "owner_commitment": owner_commitment,
                "visibility": visibility.as_str(),
                "height": height,
                "nonce": nonce,
            }),
        );
        let nonce_root = domain_hash(
            "SHIELDED-RUNTIME-STATE-CELL-NONCE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&contract_id),
                HashPart::Str(&cell_key_commitment),
                HashPart::Int(height as i128),
                HashPart::Int(nonce as i128),
            ],
            32,
        );
        let ciphertext_root = domain_hash(
            "SHIELDED-RUNTIME-STATE-CELL-CIPHERTEXT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(SHIELDED_CONTRACT_RUNTIME_ENCRYPTION_SCHEME),
                HashPart::Str(&plaintext_root),
                HashPart::Str(&aad_root),
                HashPart::Str(&nonce_root),
            ],
            32,
        );
        let ciphertext_bytes = estimated_ciphertext_bytes(plaintext_commitment);
        let cell_id = encrypted_state_cell_id(
            &contract_id,
            &cell_key_commitment,
            &owner_commitment,
            &ciphertext_root,
            height,
            nonce,
        );
        Ok(Self {
            cell_id,
            contract_id,
            cell_key_commitment,
            owner_commitment,
            visibility,
            ciphertext_root,
            ciphertext_bytes,
            nonce_root,
            aad_root,
            version: 1,
            compression_hint_id,
            rent_deposit_units,
            last_touched_height: height,
            status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_state_cell",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "cell_id": self.cell_id,
            "contract_id": self.contract_id,
            "cell_key_commitment": self.cell_key_commitment,
            "owner_commitment": self.owner_commitment,
            "visibility": self.visibility.as_str(),
            "ciphertext_root": self.ciphertext_root,
            "ciphertext_bytes": self.ciphertext_bytes,
            "nonce_root": self.nonce_root,
            "aad_root": self.aad_root,
            "version": self.version,
            "compression_hint_id": self.compression_hint_id,
            "rent_deposit_units": self.rent_deposit_units,
            "last_touched_height": self.last_touched_height,
            "status": self.status,
            "publishes_ciphertext": self.visibility.publishes_ciphertext(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.cell_id, "state cell id")?;
        ensure_non_empty(&self.contract_id, "state cell contract id")?;
        ensure_non_empty(&self.cell_key_commitment, "state cell key commitment")?;
        ensure_non_empty(&self.owner_commitment, "state cell owner commitment")?;
        ensure_non_empty(&self.ciphertext_root, "state cell ciphertext root")?;
        ensure_non_empty(&self.nonce_root, "state cell nonce root")?;
        ensure_non_empty(&self.aad_root, "state cell aad root")?;
        ensure_positive(self.ciphertext_bytes, "state cell ciphertext bytes")?;
        ensure_positive(self.version, "state cell version")?;
        ensure_status(
            &self.status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
                SHIELDED_CONTRACT_RUNTIME_STATUS_REVOKED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_EXPIRED,
            ],
            "state cell status",
        )?;
        Ok(encrypted_state_cell_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessListEntry {
    pub entry_id: String,
    pub contract_id: String,
    pub principal_commitment: String,
    pub permission: ShieldedContractPermission,
    pub mode: ShieldedAccessMode,
    pub scope_root: String,
    pub session_id: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub spending_limit_units: u64,
    pub nonce: u64,
    pub revoked: bool,
}

impl AccessListEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        principal_commitment: impl Into<String>,
        permission: ShieldedContractPermission,
        mode: ShieldedAccessMode,
        scope: &Value,
        session_id: impl Into<String>,
        starts_at_height: u64,
        ttl_blocks: u64,
        spending_limit_units: u64,
        nonce: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let principal_commitment = principal_commitment.into();
        let session_id = session_id.into();
        ensure_non_empty(&contract_id, "access list contract id")?;
        ensure_non_empty(&principal_commitment, "access list principal commitment")?;
        let scope_root = runtime_payload_root("ACCESS-LIST-SCOPE", scope);
        let expires_at_height = starts_at_height.saturating_add(ttl_blocks);
        ensure_positive(ttl_blocks, "access list ttl blocks")?;
        let entry_id = access_list_entry_id(
            &contract_id,
            &principal_commitment,
            &permission,
            mode,
            &scope_root,
            &session_id,
            starts_at_height,
            expires_at_height,
            nonce,
        );
        Ok(Self {
            entry_id,
            contract_id,
            principal_commitment,
            permission,
            mode,
            scope_root,
            session_id,
            starts_at_height,
            expires_at_height,
            spending_limit_units,
            nonce,
            revoked: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "access_list_entry",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "entry_id": self.entry_id,
            "contract_id": self.contract_id,
            "principal_commitment": self.principal_commitment,
            "permission": self.permission.as_str(),
            "mode": self.mode.as_str(),
            "scope_root": self.scope_root,
            "session_id": self.session_id,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "spending_limit_units": self.spending_limit_units,
            "nonce": self.nonce,
            "revoked": self.revoked,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.entry_id, "access list entry id")?;
        ensure_non_empty(&self.contract_id, "access list contract id")?;
        ensure_non_empty(
            &self.principal_commitment,
            "access list principal commitment",
        )?;
        ensure_non_empty(&self.scope_root, "access list scope root")?;
        ensure_height_range(
            self.starts_at_height,
            self.expires_at_height,
            "access list height range",
        )?;
        let expected = access_list_entry_id(
            &self.contract_id,
            &self.principal_commitment,
            &self.permission,
            self.mode,
            &self.scope_root,
            &self.session_id,
            self.starts_at_height,
            self.expires_at_height,
            self.nonce,
        );
        ensure_matches(&self.entry_id, &expected, "access list entry id")?;
        Ok(access_list_entry_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    pub policy_id: String,
    pub contract_id: String,
    pub default_audience: DisclosureAudience,
    pub allowed_audience_root: String,
    pub disclosed_field_root: String,
    pub redaction_salt_root: String,
    pub threshold: u16,
    pub audit_delay_blocks: u64,
    pub emergency_reveal: bool,
    pub regulator_key_root: String,
    pub status: String,
}

impl DisclosurePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        default_audience: DisclosureAudience,
        allowed_audiences: Vec<DisclosureAudience>,
        disclosed_fields: Vec<String>,
        threshold: u16,
        audit_delay_blocks: u64,
        emergency_reveal: bool,
        regulator_key_root: impl Into<String>,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let regulator_key_root = regulator_key_root.into();
        ensure_non_empty(&contract_id, "disclosure policy contract id")?;
        ensure_non_empty(&regulator_key_root, "disclosure policy regulator key root")?;
        ensure_positive(threshold as u64, "disclosure policy threshold")?;
        let allowed_audience_root = disclosure_audience_root(&allowed_audiences);
        let disclosed_field_root = runtime_string_set_root("DISCLOSURE-FIELD", &disclosed_fields);
        let redaction_salt_root = domain_hash(
            "SHIELDED-RUNTIME-DISCLOSURE-REDACTION-SALT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&contract_id),
                HashPart::Str(default_audience.as_str()),
                HashPart::Str(&allowed_audience_root),
                HashPart::Str(&disclosed_field_root),
            ],
            32,
        );
        let policy_id = disclosure_policy_id(
            &contract_id,
            default_audience,
            &allowed_audience_root,
            &disclosed_field_root,
            threshold,
            audit_delay_blocks,
            emergency_reveal,
        );
        Ok(Self {
            policy_id,
            contract_id,
            default_audience,
            allowed_audience_root,
            disclosed_field_root,
            redaction_salt_root,
            threshold,
            audit_delay_blocks,
            emergency_reveal,
            regulator_key_root,
            status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "disclosure_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "contract_id": self.contract_id,
            "default_audience": self.default_audience.as_str(),
            "allowed_audience_root": self.allowed_audience_root,
            "disclosed_field_root": self.disclosed_field_root,
            "redaction_salt_root": self.redaction_salt_root,
            "threshold": self.threshold,
            "audit_delay_blocks": self.audit_delay_blocks,
            "emergency_reveal": self.emergency_reveal,
            "regulator_key_root": self.regulator_key_root,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.policy_id, "disclosure policy id")?;
        ensure_non_empty(&self.contract_id, "disclosure policy contract id")?;
        ensure_non_empty(
            &self.allowed_audience_root,
            "disclosure policy audience root",
        )?;
        ensure_non_empty(&self.disclosed_field_root, "disclosure policy field root")?;
        ensure_non_empty(
            &self.redaction_salt_root,
            "disclosure policy redaction salt root",
        )?;
        ensure_non_empty(
            &self.regulator_key_root,
            "disclosure policy regulator key root",
        )?;
        ensure_positive(self.threshold as u64, "disclosure policy threshold")?;
        ensure_status(
            &self.status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
                SHIELDED_CONTRACT_RUNTIME_STATUS_PAUSED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_REVOKED,
            ],
            "disclosure policy status",
        )?;
        let expected = disclosure_policy_id(
            &self.contract_id,
            self.default_audience,
            &self.allowed_audience_root,
            &self.disclosed_field_root,
            self.threshold,
            self.audit_delay_blocks,
            self.emergency_reveal,
        );
        ensure_matches(&self.policy_id, &expected, "disclosure policy id")?;
        Ok(disclosure_policy_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKeyGrant {
    pub grant_id: String,
    pub contract_id: String,
    pub grantee_commitment: String,
    pub key_commitment: String,
    pub scope: ViewKeyScope,
    pub audience: DisclosureAudience,
    pub policy_id: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub max_reads: u64,
    pub usage_count: u64,
    pub disclosure_root: String,
    pub revoked: bool,
}

impl ViewKeyGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        grantee_commitment: impl Into<String>,
        key_label: impl Into<String>,
        scope: ViewKeyScope,
        audience: DisclosureAudience,
        policy_id: impl Into<String>,
        disclosure: &Value,
        starts_at_height: u64,
        ttl_blocks: u64,
        max_reads: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let grantee_commitment = grantee_commitment.into();
        let key_commitment = runtime_string_root("VIEW-KEY", &key_label.into());
        let policy_id = policy_id.into();
        ensure_non_empty(&contract_id, "view key contract id")?;
        ensure_non_empty(&grantee_commitment, "view key grantee commitment")?;
        ensure_non_empty(&policy_id, "view key policy id")?;
        ensure_positive(ttl_blocks, "view key ttl blocks")?;
        ensure_positive(max_reads, "view key max reads")?;
        let disclosure_root = runtime_payload_root("VIEW-KEY-DISCLOSURE", disclosure);
        let expires_at_height = starts_at_height.saturating_add(ttl_blocks);
        let grant_id = view_key_grant_id(
            &contract_id,
            &grantee_commitment,
            &key_commitment,
            scope,
            audience,
            &policy_id,
            starts_at_height,
            expires_at_height,
            &disclosure_root,
        );
        Ok(Self {
            grant_id,
            contract_id,
            grantee_commitment,
            key_commitment,
            scope,
            audience,
            policy_id,
            starts_at_height,
            expires_at_height,
            max_reads,
            usage_count: 0,
            disclosure_root,
            revoked: false,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_key_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "contract_id": self.contract_id,
            "grantee_commitment": self.grantee_commitment,
            "key_commitment": self.key_commitment,
            "scope": self.scope.as_str(),
            "audience": self.audience.as_str(),
            "policy_id": self.policy_id,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "max_reads": self.max_reads,
            "usage_count": self.usage_count,
            "disclosure_root": self.disclosure_root,
            "revoked": self.revoked,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.grant_id, "view key grant id")?;
        ensure_non_empty(&self.contract_id, "view key contract id")?;
        ensure_non_empty(&self.grantee_commitment, "view key grantee commitment")?;
        ensure_non_empty(&self.key_commitment, "view key commitment")?;
        ensure_non_empty(&self.policy_id, "view key policy id")?;
        ensure_non_empty(&self.disclosure_root, "view key disclosure root")?;
        ensure_positive(self.max_reads, "view key max reads")?;
        ensure_height_range(
            self.starts_at_height,
            self.expires_at_height,
            "view key grant height range",
        )?;
        if self.usage_count > self.max_reads {
            return Err("view key usage count exceeds max reads".to_string());
        }
        let expected = view_key_grant_id(
            &self.contract_id,
            &self.grantee_commitment,
            &self.key_commitment,
            self.scope,
            self.audience,
            &self.policy_id,
            self.starts_at_height,
            self.expires_at_height,
            &self.disclosure_root,
        );
        ensure_matches(&self.grant_id, &expected, "view key grant id")?;
        Ok(view_key_grant_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAccountKey {
    pub key_id: String,
    pub account_commitment: String,
    pub scheme: PqAuthorizationScheme,
    pub role: String,
    pub public_key_root: String,
    pub weight: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub rotation_nonce: u64,
    pub status: String,
}

impl PqAccountKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: impl Into<String>,
        scheme: PqAuthorizationScheme,
        role: impl Into<String>,
        public_key_material: impl Into<String>,
        weight: u16,
        valid_from_height: u64,
        ttl_blocks: u64,
        rotation_nonce: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let account_commitment = runtime_account_commitment(&account_label.into());
        let role = role.into();
        let public_key_root =
            runtime_string_root("PQ-ACCOUNT-PUBLIC-KEY", &public_key_material.into());
        ensure_non_empty(&role, "pq account key role")?;
        ensure_positive(weight as u64, "pq account key weight")?;
        ensure_positive(ttl_blocks, "pq account key ttl blocks")?;
        let expires_at_height = valid_from_height.saturating_add(ttl_blocks);
        let key_id = pq_account_key_id(
            &account_commitment,
            scheme,
            &role,
            &public_key_root,
            weight,
            valid_from_height,
            expires_at_height,
            rotation_nonce,
        );
        Ok(Self {
            key_id,
            account_commitment,
            scheme,
            role,
            public_key_root,
            weight,
            valid_from_height,
            expires_at_height,
            rotation_nonce,
            status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_account_key",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "key_id": self.key_id,
            "account_commitment": self.account_commitment,
            "scheme": self.scheme.as_str(),
            "role": self.role,
            "public_key_root": self.public_key_root,
            "weight": self.weight,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "rotation_nonce": self.rotation_nonce,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.key_id, "pq account key id")?;
        ensure_non_empty(&self.account_commitment, "pq account commitment")?;
        ensure_non_empty(&self.role, "pq account key role")?;
        ensure_non_empty(&self.public_key_root, "pq account key public key root")?;
        ensure_positive(self.weight as u64, "pq account key weight")?;
        ensure_height_range(
            self.valid_from_height,
            self.expires_at_height,
            "pq account key height range",
        )?;
        ensure_status(
            &self.status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
                SHIELDED_CONTRACT_RUNTIME_STATUS_REVOKED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_EXPIRED,
            ],
            "pq account key status",
        )?;
        let expected = pq_account_key_id(
            &self.account_commitment,
            self.scheme,
            &self.role,
            &self.public_key_root,
            self.weight,
            self.valid_from_height,
            self.expires_at_height,
            self.rotation_nonce,
        );
        ensure_matches(&self.key_id, &expected, "pq account key id")?;
        Ok(pq_account_key_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionAuthorization {
    pub authorization_id: String,
    pub account_commitment: String,
    pub session_id: String,
    pub signer_key_id: String,
    pub scheme: PqAuthorizationScheme,
    pub transcript_hash: String,
    pub signature_commitment: String,
    pub scope_root: String,
    pub call_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: PqSessionStatus,
}

impl PqSessionAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        account_commitment: impl Into<String>,
        signer_key_id: impl Into<String>,
        scheme: PqAuthorizationScheme,
        scope: &Value,
        call_root: impl Into<String>,
        opened_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let account_commitment = account_commitment.into();
        let signer_key_id = signer_key_id.into();
        let call_root = call_root.into();
        ensure_non_empty(&account_commitment, "pq session account commitment")?;
        ensure_non_empty(&signer_key_id, "pq session signer key id")?;
        ensure_non_empty(&call_root, "pq session call root")?;
        ensure_positive(ttl_blocks, "pq session ttl blocks")?;
        let scope_root = runtime_payload_root("PQ-SESSION-SCOPE", scope);
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let transcript_hash = pq_session_transcript_hash(
            &account_commitment,
            &signer_key_id,
            scheme,
            &scope_root,
            &call_root,
            opened_at_height,
            expires_at_height,
            nonce,
        );
        let signature_commitment = pq_signature_commitment(
            &account_commitment,
            &signer_key_id,
            scheme,
            &transcript_hash,
            nonce,
        );
        let session_id = pq_session_id(
            &account_commitment,
            &signer_key_id,
            &scope_root,
            opened_at_height,
            expires_at_height,
            nonce,
        );
        let authorization_id = pq_session_authorization_id(
            &account_commitment,
            &session_id,
            &signer_key_id,
            scheme,
            &transcript_hash,
            &signature_commitment,
        );
        Ok(Self {
            authorization_id,
            account_commitment,
            session_id,
            signer_key_id,
            scheme,
            transcript_hash,
            signature_commitment,
            scope_root,
            call_root,
            opened_at_height,
            expires_at_height,
            nonce,
            status: PqSessionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "account_commitment": self.account_commitment,
            "session_id": self.session_id,
            "signer_key_id": self.signer_key_id,
            "scheme": self.scheme.as_str(),
            "transcript_hash": self.transcript_hash,
            "signature_commitment": self.signature_commitment,
            "scope_root": self.scope_root,
            "call_root": self.call_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
            "allows_calls": self.status.allows_calls(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.authorization_id, "pq session authorization id")?;
        ensure_non_empty(&self.account_commitment, "pq session account commitment")?;
        ensure_non_empty(&self.session_id, "pq session id")?;
        ensure_non_empty(&self.signer_key_id, "pq session signer key id")?;
        ensure_non_empty(&self.transcript_hash, "pq session transcript hash")?;
        ensure_non_empty(
            &self.signature_commitment,
            "pq session signature commitment",
        )?;
        ensure_non_empty(&self.scope_root, "pq session scope root")?;
        ensure_non_empty(&self.call_root, "pq session call root")?;
        ensure_height_range(
            self.opened_at_height,
            self.expires_at_height,
            "pq session height range",
        )?;
        let expected_transcript = pq_session_transcript_hash(
            &self.account_commitment,
            &self.signer_key_id,
            self.scheme,
            &self.scope_root,
            &self.call_root,
            self.opened_at_height,
            self.expires_at_height,
            self.nonce,
        );
        ensure_matches(
            &self.transcript_hash,
            &expected_transcript,
            "pq session transcript hash",
        )?;
        let expected_signature = pq_signature_commitment(
            &self.account_commitment,
            &self.signer_key_id,
            self.scheme,
            &self.transcript_hash,
            self.nonce,
        );
        ensure_matches(
            &self.signature_commitment,
            &expected_signature,
            "pq session signature commitment",
        )?;
        let expected_session = pq_session_id(
            &self.account_commitment,
            &self.signer_key_id,
            &self.scope_root,
            self.opened_at_height,
            self.expires_at_height,
            self.nonce,
        );
        ensure_matches(&self.session_id, &expected_session, "pq session id")?;
        let expected_authorization = pq_session_authorization_id(
            &self.account_commitment,
            &self.session_id,
            &self.signer_key_id,
            self.scheme,
            &self.transcript_hash,
            &self.signature_commitment,
        );
        ensure_matches(
            &self.authorization_id,
            &expected_authorization,
            "pq session authorization id",
        )?;
        Ok(pq_session_authorization_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofObligation {
    pub obligation_id: String,
    pub contract_id: String,
    pub call_id: String,
    pub kind: ZkProofObligationKind,
    pub proof_system: String,
    pub public_input_root: String,
    pub private_witness_commitment: String,
    pub statement_root: String,
    pub due_height: u64,
    pub fee_lane_id: String,
    pub estimated_proof_bytes: u64,
    pub status: ZkProofStatus,
}

impl ZkProofObligation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        call_id: impl Into<String>,
        kind: ZkProofObligationKind,
        public_input: &Value,
        private_witness_commitment: impl Into<String>,
        statement: &Value,
        due_height: u64,
        fee_lane_id: impl Into<String>,
        estimated_proof_bytes: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let call_id = call_id.into();
        let private_witness_commitment = private_witness_commitment.into();
        let fee_lane_id = fee_lane_id.into();
        ensure_non_empty(&contract_id, "proof obligation contract id")?;
        ensure_non_empty(&call_id, "proof obligation call id")?;
        ensure_non_empty(
            &private_witness_commitment,
            "proof obligation witness commitment",
        )?;
        ensure_non_empty(&fee_lane_id, "proof obligation fee lane id")?;
        ensure_positive(
            estimated_proof_bytes,
            "proof obligation estimated proof bytes",
        )?;
        let public_input_root = runtime_payload_root("ZK-PUBLIC-INPUT", public_input);
        let statement_root = runtime_payload_root("ZK-STATEMENT", statement);
        let proof_system = SHIELDED_CONTRACT_RUNTIME_PROOF_SYSTEM.to_string();
        let obligation_id = zk_proof_obligation_id(
            &contract_id,
            &call_id,
            &kind,
            &proof_system,
            &public_input_root,
            &statement_root,
            due_height,
        );
        Ok(Self {
            obligation_id,
            contract_id,
            call_id,
            kind,
            proof_system,
            public_input_root,
            private_witness_commitment,
            statement_root,
            due_height,
            fee_lane_id,
            estimated_proof_bytes,
            status: ZkProofStatus::Required,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "zk_proof_obligation",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "obligation_id": self.obligation_id,
            "contract_id": self.contract_id,
            "call_id": self.call_id,
            "proof_kind": self.kind.as_str(),
            "proof_system": self.proof_system,
            "public_input_root": self.public_input_root,
            "private_witness_commitment": self.private_witness_commitment,
            "statement_root": self.statement_root,
            "due_height": self.due_height,
            "fee_lane_id": self.fee_lane_id,
            "estimated_proof_bytes": self.estimated_proof_bytes,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.obligation_id, "proof obligation id")?;
        ensure_non_empty(&self.contract_id, "proof obligation contract id")?;
        ensure_non_empty(&self.call_id, "proof obligation call id")?;
        ensure_non_empty(&self.proof_system, "proof obligation proof system")?;
        ensure_non_empty(
            &self.public_input_root,
            "proof obligation public input root",
        )?;
        ensure_non_empty(
            &self.private_witness_commitment,
            "proof obligation witness commitment",
        )?;
        ensure_non_empty(&self.statement_root, "proof obligation statement root")?;
        ensure_non_empty(&self.fee_lane_id, "proof obligation fee lane id")?;
        ensure_positive(
            self.estimated_proof_bytes,
            "proof obligation estimated proof bytes",
        )?;
        let expected = zk_proof_obligation_id(
            &self.contract_id,
            &self.call_id,
            &self.kind,
            &self.proof_system,
            &self.public_input_root,
            &self.statement_root,
            self.due_height,
        );
        ensure_matches(&self.obligation_id, &expected, "proof obligation id")?;
        Ok(zk_proof_obligation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasFeeLane {
    pub lane_id: String,
    pub kind: GasFeeLaneKind,
    pub priority: GasPriority,
    pub fee_asset_id: String,
    pub base_fee_units: u64,
    pub max_gas_per_block: u64,
    pub reserved_gas: u64,
    pub used_gas: u64,
    pub rebate_bps: u16,
    pub proof_byte_price_units: u64,
    pub congestion_multiplier_bps: u16,
    pub active: bool,
}

impl GasFeeLane {
    pub fn new(
        kind: GasFeeLaneKind,
        priority: GasPriority,
        fee_asset_id: impl Into<String>,
        base_fee_units: u64,
        max_gas_per_block: u64,
        rebate_bps: u16,
        proof_byte_price_units: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&fee_asset_id, "gas lane fee asset id")?;
        ensure_positive(base_fee_units, "gas lane base fee units")?;
        ensure_positive(max_gas_per_block, "gas lane max gas per block")?;
        if rebate_bps > SHIELDED_CONTRACT_RUNTIME_MAX_BPS {
            return Err("gas lane rebate bps exceeds 100%".to_string());
        }
        let congestion_multiplier_bps = priority.multiplier_bps();
        let lane_id = gas_fee_lane_id(
            kind,
            priority,
            &fee_asset_id,
            base_fee_units,
            max_gas_per_block,
            rebate_bps,
        );
        Ok(Self {
            lane_id,
            kind,
            priority,
            fee_asset_id,
            base_fee_units,
            max_gas_per_block,
            reserved_gas: 0,
            used_gas: 0,
            rebate_bps,
            proof_byte_price_units,
            congestion_multiplier_bps,
            active: true,
        })
    }

    pub fn available_gas(&self) -> u64 {
        self.max_gas_per_block
            .saturating_sub(self.reserved_gas)
            .saturating_sub(self.used_gas)
    }

    pub fn effective_fee_units(&self, gas: u64, proof_bytes: u64) -> u64 {
        let gas_fee = gas
            .saturating_mul(self.base_fee_units)
            .saturating_mul(self.congestion_multiplier_bps as u64)
            / SHIELDED_CONTRACT_RUNTIME_MAX_BPS as u64;
        let proof_fee = proof_bytes.saturating_mul(self.proof_byte_price_units);
        let gross = gas_fee.saturating_add(proof_fee);
        gross.saturating_sub(gross.saturating_mul(self.rebate_bps as u64) / 10_000)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_fee_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_kind": self.kind.as_str(),
            "priority": self.priority.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "base_fee_units": self.base_fee_units,
            "max_gas_per_block": self.max_gas_per_block,
            "reserved_gas": self.reserved_gas,
            "used_gas": self.used_gas,
            "available_gas": self.available_gas(),
            "rebate_bps": self.rebate_bps,
            "proof_byte_price_units": self.proof_byte_price_units,
            "congestion_multiplier_bps": self.congestion_multiplier_bps,
            "active": self.active,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.lane_id, "gas lane id")?;
        ensure_non_empty(&self.fee_asset_id, "gas lane fee asset id")?;
        ensure_positive(self.base_fee_units, "gas lane base fee units")?;
        ensure_positive(self.max_gas_per_block, "gas lane max gas per block")?;
        if self.rebate_bps > SHIELDED_CONTRACT_RUNTIME_MAX_BPS {
            return Err("gas lane rebate bps exceeds 100%".to_string());
        }
        if self.reserved_gas.saturating_add(self.used_gas) > self.max_gas_per_block {
            return Err("gas lane reserved plus used gas exceeds max gas per block".to_string());
        }
        let expected = gas_fee_lane_id(
            self.kind,
            self.priority,
            &self.fee_asset_id,
            self.base_fee_units,
            self.max_gas_per_block,
            self.rebate_bps,
        );
        ensure_matches(&self.lane_id, &expected, "gas lane id")?;
        Ok(gas_fee_lane_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelExecutionShard {
    pub shard_id: String,
    pub shard_index: u16,
    pub kind: ExecutionShardKind,
    pub state_domain_root: String,
    pub access_root: String,
    pub write_root: String,
    pub worker_committee_root: String,
    pub max_parallel_calls: u16,
    pub inflight_calls: u16,
    pub deterministic_seed: String,
    pub status: ExecutionShardStatus,
}

impl ParallelExecutionShard {
    pub fn new(
        shard_index: u16,
        kind: ExecutionShardKind,
        state_domain_root: impl Into<String>,
        access_root: impl Into<String>,
        write_root: impl Into<String>,
        worker_labels: Vec<String>,
        max_parallel_calls: u16,
        height: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let state_domain_root = state_domain_root.into();
        let access_root = access_root.into();
        let write_root = write_root.into();
        ensure_non_empty(&state_domain_root, "execution shard state domain root")?;
        ensure_non_empty(&access_root, "execution shard access root")?;
        ensure_non_empty(&write_root, "execution shard write root")?;
        ensure_positive(
            max_parallel_calls as u64,
            "execution shard max parallel calls",
        )?;
        let worker_committee_root =
            runtime_string_set_root("SHARD-WORKER-COMMITTEE", &worker_labels);
        let deterministic_seed = domain_hash(
            "SHIELDED-RUNTIME-SHARD-SEED",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Int(shard_index as i128),
                HashPart::Str(kind.as_str()),
                HashPart::Str(&state_domain_root),
                HashPart::Str(&worker_committee_root),
                HashPart::Int(height as i128),
            ],
            32,
        );
        let shard_id = parallel_execution_shard_id(
            shard_index,
            kind,
            &state_domain_root,
            &access_root,
            &write_root,
            &worker_committee_root,
            &deterministic_seed,
        );
        Ok(Self {
            shard_id,
            shard_index,
            kind,
            state_domain_root,
            access_root,
            write_root,
            worker_committee_root,
            max_parallel_calls,
            inflight_calls: 0,
            deterministic_seed,
            status: ExecutionShardStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "parallel_execution_shard",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "shard_id": self.shard_id,
            "shard_index": self.shard_index,
            "shard_kind": self.kind.as_str(),
            "state_domain_root": self.state_domain_root,
            "access_root": self.access_root,
            "write_root": self.write_root,
            "worker_committee_root": self.worker_committee_root,
            "max_parallel_calls": self.max_parallel_calls,
            "inflight_calls": self.inflight_calls,
            "deterministic_seed": self.deterministic_seed,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.shard_id, "execution shard id")?;
        ensure_non_empty(&self.state_domain_root, "execution shard state domain root")?;
        ensure_non_empty(&self.access_root, "execution shard access root")?;
        ensure_non_empty(&self.write_root, "execution shard write root")?;
        ensure_non_empty(
            &self.worker_committee_root,
            "execution shard worker committee root",
        )?;
        ensure_non_empty(
            &self.deterministic_seed,
            "execution shard deterministic seed",
        )?;
        ensure_positive(
            self.max_parallel_calls as u64,
            "execution shard max parallel calls",
        )?;
        if self.inflight_calls > self.max_parallel_calls {
            return Err("execution shard inflight calls exceed max parallel calls".to_string());
        }
        let expected = parallel_execution_shard_id(
            self.shard_index,
            self.kind,
            &self.state_domain_root,
            &self.access_root,
            &self.write_root,
            &self.worker_committee_root,
            &self.deterministic_seed,
        );
        ensure_matches(&self.shard_id, &expected, "execution shard id")?;
        Ok(parallel_execution_shard_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossContractCallReceipt {
    pub receipt_id: String,
    pub parent_call_id: String,
    pub child_call_id: String,
    pub source_contract_id: String,
    pub target_contract_id: String,
    pub selector: String,
    pub input_commitment: String,
    pub output_commitment: String,
    pub gas_used: u64,
    pub fee_units: u64,
    pub shard_id: String,
    pub proof_obligation_root: String,
    pub status: CallReceiptStatus,
    pub emitted_at_height: u64,
    pub expires_at_height: u64,
    pub visibility: ReceiptVisibility,
}

impl CrossContractCallReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_call_id: impl Into<String>,
        source_contract_id: impl Into<String>,
        target_contract_id: impl Into<String>,
        selector: impl Into<String>,
        input_commitment: impl Into<String>,
        output_commitment: impl Into<String>,
        gas_used: u64,
        fee_units: u64,
        shard_id: impl Into<String>,
        proof_obligation_root: impl Into<String>,
        emitted_at_height: u64,
        ttl_blocks: u64,
        visibility: ReceiptVisibility,
        nonce: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let parent_call_id = parent_call_id.into();
        let source_contract_id = source_contract_id.into();
        let target_contract_id = target_contract_id.into();
        let selector = selector.into();
        let input_commitment = input_commitment.into();
        let output_commitment = output_commitment.into();
        let shard_id = shard_id.into();
        let proof_obligation_root = proof_obligation_root.into();
        ensure_non_empty(&parent_call_id, "cross-contract parent call id")?;
        ensure_non_empty(&source_contract_id, "cross-contract source contract id")?;
        ensure_non_empty(&target_contract_id, "cross-contract target contract id")?;
        ensure_non_empty(&selector, "cross-contract selector")?;
        ensure_positive(gas_used, "cross-contract gas used")?;
        ensure_positive(ttl_blocks, "cross-contract ttl blocks")?;
        let child_call_id = runtime_call_id(
            &target_contract_id,
            &selector,
            &input_commitment,
            emitted_at_height,
            nonce,
        );
        let expires_at_height = emitted_at_height.saturating_add(ttl_blocks);
        let receipt_id = cross_contract_call_receipt_id(
            &parent_call_id,
            &child_call_id,
            &source_contract_id,
            &target_contract_id,
            &selector,
            &input_commitment,
            &output_commitment,
            gas_used,
            fee_units,
            &shard_id,
            emitted_at_height,
        );
        Ok(Self {
            receipt_id,
            parent_call_id,
            child_call_id,
            source_contract_id,
            target_contract_id,
            selector,
            input_commitment,
            output_commitment,
            gas_used,
            fee_units,
            shard_id,
            proof_obligation_root,
            status: CallReceiptStatus::Executed,
            emitted_at_height,
            expires_at_height,
            visibility,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "cross_contract_call_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "parent_call_id": self.parent_call_id,
            "child_call_id": self.child_call_id,
            "source_contract_id": self.source_contract_id,
            "target_contract_id": self.target_contract_id,
            "selector": self.selector,
            "input_commitment": self.input_commitment,
            "output_commitment": self.output_commitment,
            "gas_used": self.gas_used,
            "fee_units": self.fee_units,
            "shard_id": self.shard_id,
            "proof_obligation_root": self.proof_obligation_root,
            "status": self.status.as_str(),
            "success": self.status.is_success(),
            "emitted_at_height": self.emitted_at_height,
            "expires_at_height": self.expires_at_height,
            "visibility": self.visibility.as_str(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.receipt_id, "cross-contract receipt id")?;
        ensure_non_empty(&self.parent_call_id, "cross-contract parent call id")?;
        ensure_non_empty(&self.child_call_id, "cross-contract child call id")?;
        ensure_non_empty(
            &self.source_contract_id,
            "cross-contract source contract id",
        )?;
        ensure_non_empty(
            &self.target_contract_id,
            "cross-contract target contract id",
        )?;
        ensure_non_empty(&self.selector, "cross-contract selector")?;
        ensure_non_empty(&self.input_commitment, "cross-contract input commitment")?;
        ensure_non_empty(&self.output_commitment, "cross-contract output commitment")?;
        ensure_non_empty(&self.shard_id, "cross-contract shard id")?;
        ensure_non_empty(
            &self.proof_obligation_root,
            "cross-contract proof obligation root",
        )?;
        ensure_positive(self.gas_used, "cross-contract gas used")?;
        ensure_height_range(
            self.emitted_at_height,
            self.expires_at_height,
            "cross-contract receipt height range",
        )?;
        let expected = cross_contract_call_receipt_id(
            &self.parent_call_id,
            &self.child_call_id,
            &self.source_contract_id,
            &self.target_contract_id,
            &self.selector,
            &self.input_commitment,
            &self.output_commitment,
            self.gas_used,
            self.fee_units,
            &self.shard_id,
            self.emitted_at_height,
        );
        ensure_matches(&self.receipt_id, &expected, "cross-contract receipt id")?;
        Ok(cross_contract_call_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRentAccount {
    pub rent_account_id: String,
    pub contract_id: String,
    pub owner_commitment: String,
    pub rent_asset_id: String,
    pub prepaid_units: u64,
    pub accrued_units: u64,
    pub cells_covered: u64,
    pub bytes_covered: u64,
    pub last_settlement_height: u64,
    pub next_due_height: u64,
    pub status: String,
}

impl StorageRentAccount {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        owner_commitment: impl Into<String>,
        rent_asset_id: impl Into<String>,
        prepaid_units: u64,
        cells_covered: u64,
        bytes_covered: u64,
        last_settlement_height: u64,
        rent_epoch_blocks: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let owner_commitment = owner_commitment.into();
        let rent_asset_id = rent_asset_id.into();
        ensure_non_empty(&contract_id, "storage rent contract id")?;
        ensure_non_empty(&owner_commitment, "storage rent owner commitment")?;
        ensure_non_empty(&rent_asset_id, "storage rent asset id")?;
        ensure_positive(prepaid_units, "storage rent prepaid units")?;
        ensure_positive(rent_epoch_blocks, "storage rent epoch blocks")?;
        let next_due_height = last_settlement_height.saturating_add(rent_epoch_blocks);
        let rent_account_id = storage_rent_account_id(
            &contract_id,
            &owner_commitment,
            &rent_asset_id,
            last_settlement_height,
        );
        Ok(Self {
            rent_account_id,
            contract_id,
            owner_commitment,
            rent_asset_id,
            prepaid_units,
            accrued_units: 0,
            cells_covered,
            bytes_covered,
            last_settlement_height,
            next_due_height,
            status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn available_units(&self) -> u64 {
        self.prepaid_units.saturating_sub(self.accrued_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "storage_rent_account",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "rent_account_id": self.rent_account_id,
            "contract_id": self.contract_id,
            "owner_commitment": self.owner_commitment,
            "rent_asset_id": self.rent_asset_id,
            "prepaid_units": self.prepaid_units,
            "accrued_units": self.accrued_units,
            "available_units": self.available_units(),
            "cells_covered": self.cells_covered,
            "bytes_covered": self.bytes_covered,
            "last_settlement_height": self.last_settlement_height,
            "next_due_height": self.next_due_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.rent_account_id, "storage rent account id")?;
        ensure_non_empty(&self.contract_id, "storage rent contract id")?;
        ensure_non_empty(&self.owner_commitment, "storage rent owner commitment")?;
        ensure_non_empty(&self.rent_asset_id, "storage rent asset id")?;
        ensure_positive(self.prepaid_units, "storage rent prepaid units")?;
        ensure_height_range(
            self.last_settlement_height,
            self.next_due_height,
            "storage rent height range",
        )?;
        if self.accrued_units > self.prepaid_units {
            return Err("storage rent accrued units exceed prepaid units".to_string());
        }
        ensure_status(
            &self.status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACTIVE,
                SHIELDED_CONTRACT_RUNTIME_STATUS_PAUSED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_EXPIRED,
            ],
            "storage rent status",
        )?;
        let expected = storage_rent_account_id(
            &self.contract_id,
            &self.owner_commitment,
            &self.rent_asset_id,
            self.last_settlement_height,
        );
        ensure_matches(&self.rent_account_id, &expected, "storage rent account id")?;
        Ok(storage_rent_account_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionHint {
    pub compression_hint_id: String,
    pub contract_id: String,
    pub codec: CompressionCodec,
    pub dictionary_root: String,
    pub min_savings_bps: u16,
    pub original_bytes: u64,
    pub compressed_bytes: u64,
    pub witness_root: String,
    pub deterministic: bool,
}

impl CompressionHint {
    pub fn new(
        contract_id: impl Into<String>,
        codec: CompressionCodec,
        dictionary_root: impl Into<String>,
        min_savings_bps: u16,
        original_bytes: u64,
        compressed_bytes: u64,
        witness_root: impl Into<String>,
    ) -> ShieldedContractRuntimeResult<Self> {
        let contract_id = contract_id.into();
        let dictionary_root = dictionary_root.into();
        let witness_root = witness_root.into();
        ensure_non_empty(&contract_id, "compression hint contract id")?;
        ensure_non_empty(&dictionary_root, "compression hint dictionary root")?;
        ensure_non_empty(&witness_root, "compression hint witness root")?;
        ensure_positive(original_bytes, "compression hint original bytes")?;
        if min_savings_bps > SHIELDED_CONTRACT_RUNTIME_MAX_BPS {
            return Err("compression hint min savings bps exceeds 100%".to_string());
        }
        if compressed_bytes > original_bytes {
            return Err("compression hint compressed bytes exceed original bytes".to_string());
        }
        let compression_hint_id = compression_hint_id(
            &contract_id,
            codec,
            &dictionary_root,
            min_savings_bps,
            original_bytes,
            compressed_bytes,
            &witness_root,
        );
        Ok(Self {
            compression_hint_id,
            contract_id,
            codec,
            dictionary_root,
            min_savings_bps,
            original_bytes,
            compressed_bytes,
            witness_root,
            deterministic: true,
        })
    }

    pub fn savings_bps(&self) -> u16 {
        if self.original_bytes == 0 {
            return 0;
        }
        let saved = self.original_bytes.saturating_sub(self.compressed_bytes);
        ((saved.saturating_mul(10_000) / self.original_bytes) as u16)
            .min(SHIELDED_CONTRACT_RUNTIME_MAX_BPS)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compression_hint",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "compression_hint_id": self.compression_hint_id,
            "contract_id": self.contract_id,
            "codec": self.codec.as_str(),
            "dictionary_root": self.dictionary_root,
            "min_savings_bps": self.min_savings_bps,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "savings_bps": self.savings_bps(),
            "witness_root": self.witness_root,
            "deterministic": self.deterministic,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.compression_hint_id, "compression hint id")?;
        ensure_non_empty(&self.contract_id, "compression hint contract id")?;
        ensure_non_empty(&self.dictionary_root, "compression hint dictionary root")?;
        ensure_non_empty(&self.witness_root, "compression hint witness root")?;
        ensure_positive(self.original_bytes, "compression hint original bytes")?;
        if self.compressed_bytes > self.original_bytes {
            return Err("compression hint compressed bytes exceed original bytes".to_string());
        }
        if self.min_savings_bps > SHIELDED_CONTRACT_RUNTIME_MAX_BPS {
            return Err("compression hint min savings bps exceeds 100%".to_string());
        }
        let expected = compression_hint_id(
            &self.contract_id,
            self.codec,
            &self.dictionary_root,
            self.min_savings_bps,
            self.original_bytes,
            self.compressed_bytes,
            &self.witness_root,
        );
        ensure_matches(&self.compression_hint_id, &expected, "compression hint id")?;
        Ok(compression_hint_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackCheckpoint {
    pub checkpoint_id: String,
    pub height: u64,
    pub state_root: String,
    pub runtime_root: String,
    pub accepted_receipt_root: String,
    pub state_delta_root: String,
    pub operator_commitment: String,
    pub created_at_height: u64,
    pub status: String,
}

impl RollbackCheckpoint {
    pub fn new(
        height: u64,
        state_root: impl Into<String>,
        runtime_root: impl Into<String>,
        accepted_receipt_root: impl Into<String>,
        state_delta_root: impl Into<String>,
        operator_commitment: impl Into<String>,
        created_at_height: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let state_root = state_root.into();
        let runtime_root = runtime_root.into();
        let accepted_receipt_root = accepted_receipt_root.into();
        let state_delta_root = state_delta_root.into();
        let operator_commitment = operator_commitment.into();
        ensure_non_empty(&state_root, "rollback state root")?;
        ensure_non_empty(&runtime_root, "rollback runtime root")?;
        ensure_non_empty(&accepted_receipt_root, "rollback accepted receipt root")?;
        ensure_non_empty(&state_delta_root, "rollback state delta root")?;
        ensure_non_empty(&operator_commitment, "rollback operator commitment")?;
        let checkpoint_id = rollback_checkpoint_id(
            height,
            &state_root,
            &runtime_root,
            &accepted_receipt_root,
            &state_delta_root,
            &operator_commitment,
            created_at_height,
        );
        Ok(Self {
            checkpoint_id,
            height,
            state_root,
            runtime_root,
            accepted_receipt_root,
            state_delta_root,
            operator_commitment,
            created_at_height,
            status: SHIELDED_CONTRACT_RUNTIME_STATUS_ACCEPTED.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rollback_checkpoint",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "checkpoint_id": self.checkpoint_id,
            "height": self.height,
            "state_root": self.state_root,
            "runtime_root": self.runtime_root,
            "accepted_receipt_root": self.accepted_receipt_root,
            "state_delta_root": self.state_delta_root,
            "operator_commitment": self.operator_commitment,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.checkpoint_id, "rollback checkpoint id")?;
        ensure_non_empty(&self.state_root, "rollback state root")?;
        ensure_non_empty(&self.runtime_root, "rollback runtime root")?;
        ensure_non_empty(
            &self.accepted_receipt_root,
            "rollback accepted receipt root",
        )?;
        ensure_non_empty(&self.state_delta_root, "rollback state delta root")?;
        ensure_non_empty(&self.operator_commitment, "rollback operator commitment")?;
        ensure_status(
            &self.status,
            &[
                SHIELDED_CONTRACT_RUNTIME_STATUS_PENDING,
                SHIELDED_CONTRACT_RUNTIME_STATUS_ACCEPTED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_REVERTED,
                SHIELDED_CONTRACT_RUNTIME_STATUS_DISPUTED,
            ],
            "rollback checkpoint status",
        )?;
        let expected = rollback_checkpoint_id(
            self.height,
            &self.state_root,
            &self.runtime_root,
            &self.accepted_receipt_root,
            &self.state_delta_root,
            &self.operator_commitment,
            self.created_at_height,
        );
        ensure_matches(&self.checkpoint_id, &expected, "rollback checkpoint id")?;
        Ok(rollback_checkpoint_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FraudEvidenceRecord {
    pub evidence_id: String,
    pub kind: FraudEvidenceKind,
    pub challenger_commitment: String,
    pub target_receipt_id: String,
    pub target_checkpoint_id: String,
    pub evidence_root: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub disputed_state_root: String,
    pub slash_amount_units: u64,
    pub submitted_at_height: u64,
    pub challenge_expires_at_height: u64,
    pub status: FraudEvidenceStatus,
}

impl FraudEvidenceRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: FraudEvidenceKind,
        challenger_commitment: impl Into<String>,
        target_receipt_id: impl Into<String>,
        target_checkpoint_id: impl Into<String>,
        evidence: &Value,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        disputed_state_root: impl Into<String>,
        slash_amount_units: u64,
        submitted_at_height: u64,
        challenge_ttl_blocks: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let challenger_commitment = challenger_commitment.into();
        let target_receipt_id = target_receipt_id.into();
        let target_checkpoint_id = target_checkpoint_id.into();
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let disputed_state_root = disputed_state_root.into();
        ensure_non_empty(
            &challenger_commitment,
            "fraud evidence challenger commitment",
        )?;
        ensure_non_empty(&target_receipt_id, "fraud evidence target receipt id")?;
        ensure_non_empty(&target_checkpoint_id, "fraud evidence target checkpoint id")?;
        ensure_non_empty(&pre_state_root, "fraud evidence pre state root")?;
        ensure_non_empty(&post_state_root, "fraud evidence post state root")?;
        ensure_non_empty(&disputed_state_root, "fraud evidence disputed state root")?;
        ensure_positive(challenge_ttl_blocks, "fraud evidence challenge ttl blocks")?;
        let evidence_root = runtime_payload_root("FRAUD-EVIDENCE", evidence);
        let challenge_expires_at_height = submitted_at_height.saturating_add(challenge_ttl_blocks);
        let evidence_id = fraud_evidence_id(
            &kind,
            &challenger_commitment,
            &target_receipt_id,
            &target_checkpoint_id,
            &evidence_root,
            submitted_at_height,
        );
        Ok(Self {
            evidence_id,
            kind,
            challenger_commitment,
            target_receipt_id,
            target_checkpoint_id,
            evidence_root,
            pre_state_root,
            post_state_root,
            disputed_state_root,
            slash_amount_units,
            submitted_at_height,
            challenge_expires_at_height,
            status: FraudEvidenceStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fraud_evidence_record",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "evidence_id": self.evidence_id,
            "evidence_kind": self.kind.as_str(),
            "challenger_commitment": self.challenger_commitment,
            "target_receipt_id": self.target_receipt_id,
            "target_checkpoint_id": self.target_checkpoint_id,
            "evidence_root": self.evidence_root,
            "pre_state_root": self.pre_state_root,
            "post_state_root": self.post_state_root,
            "disputed_state_root": self.disputed_state_root,
            "slash_amount_units": self.slash_amount_units,
            "submitted_at_height": self.submitted_at_height,
            "challenge_expires_at_height": self.challenge_expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.evidence_id, "fraud evidence id")?;
        ensure_non_empty(
            &self.challenger_commitment,
            "fraud evidence challenger commitment",
        )?;
        ensure_non_empty(&self.target_receipt_id, "fraud evidence target receipt id")?;
        ensure_non_empty(
            &self.target_checkpoint_id,
            "fraud evidence target checkpoint id",
        )?;
        ensure_non_empty(&self.evidence_root, "fraud evidence root")?;
        ensure_non_empty(&self.pre_state_root, "fraud evidence pre state root")?;
        ensure_non_empty(&self.post_state_root, "fraud evidence post state root")?;
        ensure_non_empty(
            &self.disputed_state_root,
            "fraud evidence disputed state root",
        )?;
        ensure_height_range(
            self.submitted_at_height,
            self.challenge_expires_at_height,
            "fraud evidence challenge height range",
        )?;
        let expected = fraud_evidence_id(
            &self.kind,
            &self.challenger_commitment,
            &self.target_receipt_id,
            &self.target_checkpoint_id,
            &self.evidence_root,
            self.submitted_at_height,
        );
        ensure_matches(&self.evidence_id, &expected, "fraud evidence id")?;
        Ok(fraud_evidence_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeDevnetRecord {
    pub record_id: String,
    pub label: String,
    pub category: String,
    pub payload_root: String,
    pub created_at_height: u64,
}

impl RuntimeDevnetRecord {
    pub fn new(
        label: impl Into<String>,
        category: impl Into<String>,
        payload_root: impl Into<String>,
        created_at_height: u64,
    ) -> ShieldedContractRuntimeResult<Self> {
        let label = label.into();
        let category = category.into();
        let payload_root = payload_root.into();
        ensure_non_empty(&label, "devnet record label")?;
        ensure_non_empty(&category, "devnet record category")?;
        ensure_non_empty(&payload_root, "devnet record payload root")?;
        let record_id =
            runtime_devnet_record_id(&label, &category, &payload_root, created_at_height);
        Ok(Self {
            record_id,
            label,
            category,
            payload_root,
            created_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_runtime_devnet_record",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "label": self.label,
            "category": self.category,
            "payload_root": self.payload_root,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        ensure_non_empty(&self.record_id, "devnet record id")?;
        ensure_non_empty(&self.label, "devnet record label")?;
        ensure_non_empty(&self.category, "devnet record category")?;
        ensure_non_empty(&self.payload_root, "devnet record payload root")?;
        let expected = runtime_devnet_record_id(
            &self.label,
            &self.category,
            &self.payload_root,
            self.created_at_height,
        );
        ensure_matches(&self.record_id, &expected, "devnet record id")?;
        Ok(runtime_devnet_record_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractRuntimeRoots {
    pub config_root: String,
    pub class_manifest_root: String,
    pub state_cell_root: String,
    pub access_list_root: String,
    pub disclosure_policy_root: String,
    pub view_key_grant_root: String,
    pub pq_account_key_root: String,
    pub pq_session_authorization_root: String,
    pub proof_obligation_root: String,
    pub gas_lane_root: String,
    pub execution_shard_root: String,
    pub call_receipt_root: String,
    pub storage_rent_root: String,
    pub compression_hint_root: String,
    pub rollback_checkpoint_root: String,
    pub fraud_evidence_root: String,
    pub devnet_record_root: String,
}

impl ShieldedContractRuntimeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "class_manifest_root": self.class_manifest_root,
            "state_cell_root": self.state_cell_root,
            "access_list_root": self.access_list_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "view_key_grant_root": self.view_key_grant_root,
            "pq_account_key_root": self.pq_account_key_root,
            "pq_session_authorization_root": self.pq_session_authorization_root,
            "proof_obligation_root": self.proof_obligation_root,
            "gas_lane_root": self.gas_lane_root,
            "execution_shard_root": self.execution_shard_root,
            "call_receipt_root": self.call_receipt_root,
            "storage_rent_root": self.storage_rent_root,
            "compression_hint_root": self.compression_hint_root,
            "rollback_checkpoint_root": self.rollback_checkpoint_root,
            "fraud_evidence_root": self.fraud_evidence_root,
            "devnet_record_root": self.devnet_record_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        runtime_payload_root("SHIELDED-RUNTIME-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractRuntimeCounters {
    pub class_manifest_count: u64,
    pub state_cell_count: u64,
    pub access_list_count: u64,
    pub disclosure_policy_count: u64,
    pub view_key_grant_count: u64,
    pub pq_account_key_count: u64,
    pub pq_session_authorization_count: u64,
    pub proof_obligation_count: u64,
    pub gas_lane_count: u64,
    pub execution_shard_count: u64,
    pub call_receipt_count: u64,
    pub storage_rent_account_count: u64,
    pub compression_hint_count: u64,
    pub rollback_checkpoint_count: u64,
    pub fraud_evidence_count: u64,
    pub devnet_record_count: u64,
    pub encrypted_state_bytes: u64,
    pub prepaid_rent_units: u64,
    pub accrued_rent_units: u64,
    pub reserved_gas: u64,
    pub used_gas: u64,
    pub receipt_fee_units: u64,
    pub estimated_proof_bytes: u64,
}

impl ShieldedContractRuntimeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "class_manifest_count": self.class_manifest_count,
            "state_cell_count": self.state_cell_count,
            "access_list_count": self.access_list_count,
            "disclosure_policy_count": self.disclosure_policy_count,
            "view_key_grant_count": self.view_key_grant_count,
            "pq_account_key_count": self.pq_account_key_count,
            "pq_session_authorization_count": self.pq_session_authorization_count,
            "proof_obligation_count": self.proof_obligation_count,
            "gas_lane_count": self.gas_lane_count,
            "execution_shard_count": self.execution_shard_count,
            "call_receipt_count": self.call_receipt_count,
            "storage_rent_account_count": self.storage_rent_account_count,
            "compression_hint_count": self.compression_hint_count,
            "rollback_checkpoint_count": self.rollback_checkpoint_count,
            "fraud_evidence_count": self.fraud_evidence_count,
            "devnet_record_count": self.devnet_record_count,
            "encrypted_state_bytes": self.encrypted_state_bytes,
            "prepaid_rent_units": self.prepaid_rent_units,
            "accrued_rent_units": self.accrued_rent_units,
            "reserved_gas": self.reserved_gas,
            "used_gas": self.used_gas,
            "receipt_fee_units": self.receipt_fee_units,
            "estimated_proof_bytes": self.estimated_proof_bytes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractRuntimeState {
    pub height: u64,
    pub config: ShieldedContractRuntimeConfig,
    pub class_manifests: BTreeMap<String, ShieldedContractClassManifest>,
    pub state_cells: BTreeMap<String, EncryptedStateCell>,
    pub access_list: BTreeMap<String, AccessListEntry>,
    pub disclosure_policies: BTreeMap<String, DisclosurePolicy>,
    pub view_key_grants: BTreeMap<String, ViewKeyGrant>,
    pub pq_account_keys: BTreeMap<String, PqAccountKey>,
    pub pq_session_authorizations: BTreeMap<String, PqSessionAuthorization>,
    pub proof_obligations: BTreeMap<String, ZkProofObligation>,
    pub gas_lanes: BTreeMap<String, GasFeeLane>,
    pub execution_shards: BTreeMap<String, ParallelExecutionShard>,
    pub call_receipts: BTreeMap<String, CrossContractCallReceipt>,
    pub storage_rent_accounts: BTreeMap<String, StorageRentAccount>,
    pub compression_hints: BTreeMap<String, CompressionHint>,
    pub rollback_checkpoints: BTreeMap<String, RollbackCheckpoint>,
    pub fraud_evidence: BTreeMap<String, FraudEvidenceRecord>,
    pub devnet_records: BTreeMap<String, RuntimeDevnetRecord>,
}

impl Default for ShieldedContractRuntimeState {
    fn default() -> Self {
        Self::new(ShieldedContractRuntimeConfig::default())
    }
}

impl ShieldedContractRuntimeState {
    pub fn new(config: ShieldedContractRuntimeConfig) -> Self {
        Self {
            height: 0,
            config,
            class_manifests: BTreeMap::new(),
            state_cells: BTreeMap::new(),
            access_list: BTreeMap::new(),
            disclosure_policies: BTreeMap::new(),
            view_key_grants: BTreeMap::new(),
            pq_account_keys: BTreeMap::new(),
            pq_session_authorizations: BTreeMap::new(),
            proof_obligations: BTreeMap::new(),
            gas_lanes: BTreeMap::new(),
            execution_shards: BTreeMap::new(),
            call_receipts: BTreeMap::new(),
            storage_rent_accounts: BTreeMap::new(),
            compression_hints: BTreeMap::new(),
            rollback_checkpoints: BTreeMap::new(),
            fraud_evidence: BTreeMap::new(),
            devnet_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ShieldedContractRuntimeResult<Self> {
        let mut state = Self::new(ShieldedContractRuntimeConfig::default());
        state.set_height(64);

        let interactive_lane = GasFeeLane::new(
            GasFeeLaneKind::Interactive,
            GasPriority::Fast,
            state.config.fee_asset_id.clone(),
            3,
            8_000_000,
            0,
            state.config.proof_byte_price_units,
        )?;
        let low_fee_lane = GasFeeLane::new(
            GasFeeLaneKind::LowFeePrivateCall,
            GasPriority::Background,
            state.config.fee_asset_id.clone(),
            1,
            4_000_000,
            state.config.low_fee_rebate_bps,
            1,
        )?;
        let proof_lane = GasFeeLane::new(
            GasFeeLaneKind::BulkProof,
            GasPriority::Normal,
            state.config.fee_asset_id.clone(),
            2,
            12_000_000,
            1_500,
            state.config.proof_byte_price_units,
        )?;
        state.insert_gas_lane(interactive_lane.clone())?;
        state.insert_gas_lane(low_fee_lane.clone())?;
        state.insert_gas_lane(proof_lane.clone())?;

        let shielded_counter_methods = vec![
            ContractInterfaceMethod::new(
                "devnet-counter-class-seed",
                "increment(bytes32,uint64)",
                "counter_increment",
                runtime_string_root("ABI", "increment-args"),
                runtime_string_root("ABI", "increment-return"),
                vec![
                    ShieldedContractPermission::Call,
                    ShieldedContractPermission::WriteState,
                    ShieldedContractPermission::ScheduleProof,
                ],
                ZkProofObligationKind::StateTransition,
                450_000,
                true,
                true,
            )?,
            ContractInterfaceMethod::new(
                "devnet-counter-class-seed",
                "read_view(bytes32)",
                "counter_read_view",
                runtime_string_root("ABI", "read-view-args"),
                runtime_string_root("ABI", "read-view-return"),
                vec![
                    ShieldedContractPermission::ReadState,
                    ShieldedContractPermission::RotateViewKey,
                ],
                ZkProofObligationKind::ViewKeyDisclosure,
                120_000,
                true,
                false,
            )?,
        ];
        let counter_method_root =
            contract_interface_method_root_from_slice(&shielded_counter_methods);
        let counter_manifest = ShieldedContractClassManifest::new(
            "devnet shielded counter",
            "1.0.0",
            ShieldedContractClassKind::Custom("shielded_counter".to_string()),
            runtime_string_root("WASM-CODE", "devnet-shielded-counter-code"),
            18_432,
            shielded_counter_methods,
            runtime_string_root("CONSTRUCTOR", "counter-owner-initial-value"),
            runtime_string_root("STATE-SCHEMA", "counter-state-v1"),
            runtime_string_root("EVENT-SCHEMA", "counter-event-v1"),
            runtime_payload_root(
                "PROOF-POLICY",
                &json!({"required": ["state_transition", "access_list_membership"]}),
            ),
            runtime_string_root("DISCLOSURE-POLICY", "counter-selective-view"),
            runtime_string_root("COMPRESSION-POLICY", "counter-sparse-delta"),
            64,
            600_000,
            runtime_account_commitment("devnet-publisher"),
            state.height,
        )?;

        let paymaster_methods = vec![ContractInterfaceMethod::new(
            "devnet-paymaster-class-seed",
            "sponsor(bytes32,uint64)",
            "paymaster_sponsor",
            runtime_string_root("ABI", "sponsor-args"),
            runtime_string_root("ABI", "sponsor-return"),
            vec![
                ShieldedContractPermission::Call,
                ShieldedContractPermission::SpendGasCredit,
            ],
            ZkProofObligationKind::FeeSponsorship,
            250_000,
            true,
            true,
        )?];
        let _paymaster_method_root = contract_interface_method_root_from_slice(&paymaster_methods);
        let paymaster_manifest = ShieldedContractClassManifest::new(
            "devnet private paymaster",
            "1.0.0",
            ShieldedContractClassKind::Paymaster,
            runtime_string_root("WASM-CODE", "devnet-private-paymaster-code"),
            23_040,
            paymaster_methods,
            runtime_string_root("CONSTRUCTOR", "paymaster-budget-root"),
            runtime_string_root("STATE-SCHEMA", "paymaster-state-v1"),
            runtime_string_root("EVENT-SCHEMA", "paymaster-event-v1"),
            runtime_payload_root(
                "PROOF-POLICY",
                &json!({"required": ["fee_sponsorship", "token_conservation"]}),
            ),
            runtime_string_root("DISCLOSURE-POLICY", "paymaster-auditor-window"),
            runtime_string_root("COMPRESSION-POLICY", "paymaster-json-dictionary"),
            128,
            400_000,
            runtime_account_commitment("devnet-publisher"),
            state.height,
        )?;
        state.insert_class_manifest(counter_manifest.clone())?;
        state.insert_class_manifest(paymaster_manifest.clone())?;

        let counter_disclosure = DisclosurePolicy::new(
            counter_manifest.class_id.clone(),
            DisclosureAudience::Owner,
            vec![
                DisclosureAudience::Owner,
                DisclosureAudience::Auditor,
                DisclosureAudience::SequencerCommittee,
            ],
            vec![
                "counter_owner".to_string(),
                "counter_value_commitment".to_string(),
                "last_update_height".to_string(),
            ],
            1,
            12,
            true,
            runtime_string_root("REGULATOR-KEY", "devnet-auditor"),
        )?;
        let paymaster_disclosure = DisclosurePolicy::new(
            paymaster_manifest.class_id.clone(),
            DisclosureAudience::Auditor,
            vec![DisclosureAudience::Auditor, DisclosureAudience::Regulator],
            vec![
                "sponsor_budget_commitment".to_string(),
                "fee_lane_id".to_string(),
            ],
            2,
            24,
            true,
            runtime_string_root("REGULATOR-KEY", "devnet-fee-auditor"),
        )?;
        state.insert_disclosure_policy(counter_disclosure.clone())?;
        state.insert_disclosure_policy(paymaster_disclosure.clone())?;

        let counter_hint = CompressionHint::new(
            counter_manifest.class_id.clone(),
            CompressionCodec::SparseMerkleDelta,
            runtime_string_root("COMPRESSION-DICT", "counter-delta-dictionary"),
            2_500,
            2_048,
            512,
            runtime_string_root("COMPRESSION-WITNESS", "counter-hint-witness"),
        )?;
        let paymaster_hint = CompressionHint::new(
            paymaster_manifest.class_id.clone(),
            CompressionCodec::CanonicalJsonDictionary,
            runtime_string_root("COMPRESSION-DICT", "paymaster-json-dictionary"),
            2_000,
            4_096,
            1_536,
            runtime_string_root("COMPRESSION-WITNESS", "paymaster-hint-witness"),
        )?;
        state.insert_compression_hint(counter_hint.clone())?;
        state.insert_compression_hint(paymaster_hint.clone())?;

        let alice_account = runtime_account_commitment("alice");
        let operator_account = runtime_account_commitment("devnet-operator");
        let alice_key = PqAccountKey::new(
            "alice",
            PqAuthorizationScheme::HybridMlDsaSlhDsa,
            "owner",
            "alice-devnet-pq-public-key",
            1,
            state.height,
            2_000,
            1,
        )?;
        let operator_key = PqAccountKey::new(
            "devnet-operator",
            PqAuthorizationScheme::MlDsa65,
            "sequencer",
            "operator-devnet-pq-public-key",
            2,
            state.height,
            4_000,
            1,
        )?;
        state.insert_pq_account_key(alice_key.clone())?;
        state.insert_pq_account_key(operator_key.clone())?;

        let parent_call_id = runtime_call_id(
            &counter_manifest.class_id,
            "increment(bytes32,uint64)",
            &alice_account,
            state.height,
            1,
        );
        let session_scope = json!({
            "contracts": [counter_manifest.class_id, paymaster_manifest.class_id],
            "selectors": ["increment(bytes32,uint64)", "sponsor(bytes32,uint64)"],
            "max_fee_units": 2500,
        });
        let session_auth = PqSessionAuthorization::open(
            alice_account.clone(),
            alice_key.key_id.clone(),
            PqAuthorizationScheme::SessionKemBound,
            &session_scope,
            parent_call_id.clone(),
            state.height,
            state.config.default_session_ttl_blocks,
            7,
        )?;
        state.insert_pq_session_authorization(session_auth.clone())?;

        let access = AccessListEntry::new(
            counter_manifest.class_id.clone(),
            alice_account.clone(),
            ShieldedContractPermission::WriteState,
            ShieldedAccessMode::ReadWrite,
            &json!({"prefix": "counter", "method": "increment"}),
            session_auth.session_id.clone(),
            state.height,
            state.config.default_session_ttl_blocks,
            20_000,
            3,
        )?;
        let sponsor_access = AccessListEntry::new(
            paymaster_manifest.class_id.clone(),
            alice_account.clone(),
            ShieldedContractPermission::SpendGasCredit,
            ShieldedAccessMode::ProveOnly,
            &json!({"lane": low_fee_lane.lane_id, "budget": "alice-devnet"}),
            session_auth.session_id.clone(),
            state.height,
            state.config.default_session_ttl_blocks,
            10_000,
            4,
        )?;
        state.insert_access_list_entry(access.clone())?;
        state.insert_access_list_entry(sponsor_access.clone())?;

        let view_grant = ViewKeyGrant::new(
            counter_manifest.class_id.clone(),
            runtime_account_commitment("devnet-auditor"),
            "alice-counter-view-key",
            ViewKeyScope::StatePrefix,
            DisclosureAudience::Auditor,
            counter_disclosure.policy_id.clone(),
            &json!({"prefix": "counter", "redacted_fields": ["owner_secret"]}),
            state.height,
            state.config.default_view_key_ttl_blocks,
            32,
        )?;
        state.insert_view_key_grant(view_grant.clone())?;

        let counter_cell = EncryptedStateCell::new(
            counter_manifest.class_id.clone(),
            "counter/alice/value",
            alice_account.clone(),
            &json!({"counter": 41, "owner": "alice", "blinding": "devnet"}),
            StateCellVisibility::OwnerDecryptable,
            counter_hint.compression_hint_id.clone(),
            100,
            state.height,
            11,
        )?;
        let paymaster_cell = EncryptedStateCell::new(
            paymaster_manifest.class_id.clone(),
            "budget/alice/low_fee",
            operator_account.clone(),
            &json!({"remaining_fee_units": 10000, "lane": "low_fee_private_call"}),
            StateCellVisibility::AuditorDecryptable,
            paymaster_hint.compression_hint_id.clone(),
            150,
            state.height,
            12,
        )?;
        state.insert_state_cell(counter_cell.clone())?;
        state.insert_state_cell(paymaster_cell.clone())?;

        let counter_rent = StorageRentAccount::new(
            counter_manifest.class_id.clone(),
            alice_account.clone(),
            state.config.rent_asset_id.clone(),
            1_000,
            1,
            counter_cell.ciphertext_bytes,
            state.height,
            state.config.rent_epoch_blocks,
        )?;
        let paymaster_rent = StorageRentAccount::new(
            paymaster_manifest.class_id.clone(),
            operator_account.clone(),
            state.config.rent_asset_id.clone(),
            2_000,
            1,
            paymaster_cell.ciphertext_bytes,
            state.height,
            state.config.rent_epoch_blocks,
        )?;
        state.insert_storage_rent_account(counter_rent)?;
        state.insert_storage_rent_account(paymaster_rent)?;

        let counter_shard = ParallelExecutionShard::new(
            0,
            ExecutionShardKind::WriteHeavy,
            runtime_string_root("SHARD-DOMAIN", "counter-state"),
            access_list_entry_root(&access),
            encrypted_state_cell_root(&counter_cell),
            vec!["worker-a".to_string(), "worker-b".to_string()],
            8,
            state.height,
        )?;
        let paymaster_shard = ParallelExecutionShard::new(
            1,
            ExecutionShardKind::CrossContract,
            runtime_string_root("SHARD-DOMAIN", "paymaster-state"),
            access_list_entry_root(&sponsor_access),
            encrypted_state_cell_root(&paymaster_cell),
            vec!["worker-c".to_string(), "worker-d".to_string()],
            6,
            state.height,
        )?;
        state.insert_execution_shard(counter_shard.clone())?;
        state.insert_execution_shard(paymaster_shard.clone())?;

        let counter_obligation = ZkProofObligation::new(
            counter_manifest.class_id.clone(),
            parent_call_id.clone(),
            ZkProofObligationKind::StateTransition,
            &json!({
                "old_cell": counter_cell.cell_id,
                "new_value_commitment": runtime_string_root("COUNTER-VALUE", "42"),
                "method_root": counter_method_root,
            }),
            runtime_string_root("PRIVATE-WITNESS", "counter-increment-witness"),
            &json!({"statement": "counter increments by one and access list is valid"}),
            state.height + state.config.default_proof_ttl_blocks,
            proof_lane.lane_id.clone(),
            2_048,
        )?;
        state.insert_proof_obligation(counter_obligation.clone())?;

        let sponsor_call_input = runtime_payload_root(
            "CALL-INPUT",
            &json!({"parent": parent_call_id, "gross_fee_units": 1500}),
        );
        let sponsor_obligation = ZkProofObligation::new(
            paymaster_manifest.class_id.clone(),
            runtime_call_id(
                &paymaster_manifest.class_id,
                "sponsor(bytes32,uint64)",
                &sponsor_call_input,
                state.height,
                2,
            ),
            ZkProofObligationKind::FeeSponsorship,
            &json!({"lane": low_fee_lane.lane_id, "gross_fee_units": 1500}),
            runtime_string_root("PRIVATE-WITNESS", "paymaster-sponsor-witness"),
            &json!({"statement": "paymaster budget covers low-fee rebate"}),
            state.height + state.config.default_proof_ttl_blocks,
            proof_lane.lane_id.clone(),
            1_536,
        )?;
        state.insert_proof_obligation(sponsor_obligation.clone())?;

        let receipt = CrossContractCallReceipt::new(
            parent_call_id.clone(),
            counter_manifest.class_id.clone(),
            paymaster_manifest.class_id.clone(),
            "sponsor(bytes32,uint64)",
            sponsor_call_input,
            runtime_payload_root(
                "CALL-OUTPUT",
                &json!({"sponsored_units": 900, "settled_fee_units": 600}),
            ),
            180_000,
            600,
            paymaster_shard.shard_id.clone(),
            zk_proof_obligation_root(&sponsor_obligation),
            state.height,
            state.config.default_receipt_ttl_blocks,
            ReceiptVisibility::EncryptedTrace,
            2,
        )?;
        state.insert_call_receipt(receipt.clone())?;

        let pre_checkpoint_root = state.state_root();
        let roots = state.roots();
        let checkpoint = RollbackCheckpoint::new(
            state.height,
            pre_checkpoint_root.clone(),
            roots.aggregate_root(),
            roots.call_receipt_root,
            runtime_payload_root(
                "DEVNET-STATE-DELTA",
                &json!({"counter": "41->42", "fee": "sponsored"}),
            ),
            runtime_account_commitment(&state.config.operator_label),
            state.height,
        )?;
        state.insert_rollback_checkpoint(checkpoint.clone())?;

        let evidence = FraudEvidenceRecord::new(
            FraudEvidenceKind::MissingProof,
            runtime_account_commitment("watchtower-one"),
            receipt.receipt_id.clone(),
            checkpoint.checkpoint_id.clone(),
            &json!({
                "note": "devnet fixture keeps an open challenge for proof timeout testing",
                "missing_obligation": counter_obligation.obligation_id,
            }),
            pre_checkpoint_root,
            state.state_root(),
            runtime_string_root("DISPUTED-ROOT", "counter-proof-timeout"),
            50,
            state.height + 1,
            24,
        )?;
        state.insert_fraud_evidence(evidence)?;

        let manifest_record = RuntimeDevnetRecord::new(
            "shielded-counter",
            "class_manifest",
            contract_class_manifest_root(&counter_manifest),
            state.height,
        )?;
        let receipt_record = RuntimeDevnetRecord::new(
            "counter-paymaster-call",
            "cross_contract_receipt",
            cross_contract_call_receipt_root(&receipt),
            state.height,
        )?;
        state.insert_devnet_record(manifest_record)?;
        state.insert_devnet_record(receipt_record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn roots(&self) -> ShieldedContractRuntimeRoots {
        ShieldedContractRuntimeRoots {
            config_root: self.config.config_root(),
            class_manifest_root: class_manifest_root_from_map(&self.class_manifests),
            state_cell_root: encrypted_state_cell_root_from_map(&self.state_cells),
            access_list_root: access_list_root_from_map(&self.access_list),
            disclosure_policy_root: disclosure_policy_root_from_map(&self.disclosure_policies),
            view_key_grant_root: view_key_grant_root_from_map(&self.view_key_grants),
            pq_account_key_root: pq_account_key_root_from_map(&self.pq_account_keys),
            pq_session_authorization_root: pq_session_authorization_root_from_map(
                &self.pq_session_authorizations,
            ),
            proof_obligation_root: zk_proof_obligation_root_from_map(&self.proof_obligations),
            gas_lane_root: gas_fee_lane_root_from_map(&self.gas_lanes),
            execution_shard_root: parallel_execution_shard_root_from_map(&self.execution_shards),
            call_receipt_root: cross_contract_call_receipt_root_from_map(&self.call_receipts),
            storage_rent_root: storage_rent_account_root_from_map(&self.storage_rent_accounts),
            compression_hint_root: compression_hint_root_from_map(&self.compression_hints),
            rollback_checkpoint_root: rollback_checkpoint_root_from_map(&self.rollback_checkpoints),
            fraud_evidence_root: fraud_evidence_root_from_map(&self.fraud_evidence),
            devnet_record_root: runtime_devnet_record_root_from_map(&self.devnet_records),
        }
    }

    pub fn counters(&self) -> ShieldedContractRuntimeCounters {
        ShieldedContractRuntimeCounters {
            class_manifest_count: self.class_manifests.len() as u64,
            state_cell_count: self.state_cells.len() as u64,
            access_list_count: self.access_list.len() as u64,
            disclosure_policy_count: self.disclosure_policies.len() as u64,
            view_key_grant_count: self.view_key_grants.len() as u64,
            pq_account_key_count: self.pq_account_keys.len() as u64,
            pq_session_authorization_count: self.pq_session_authorizations.len() as u64,
            proof_obligation_count: self.proof_obligations.len() as u64,
            gas_lane_count: self.gas_lanes.len() as u64,
            execution_shard_count: self.execution_shards.len() as u64,
            call_receipt_count: self.call_receipts.len() as u64,
            storage_rent_account_count: self.storage_rent_accounts.len() as u64,
            compression_hint_count: self.compression_hints.len() as u64,
            rollback_checkpoint_count: self.rollback_checkpoints.len() as u64,
            fraud_evidence_count: self.fraud_evidence.len() as u64,
            devnet_record_count: self.devnet_records.len() as u64,
            encrypted_state_bytes: self
                .state_cells
                .values()
                .map(|cell| cell.ciphertext_bytes)
                .sum(),
            prepaid_rent_units: self
                .storage_rent_accounts
                .values()
                .map(|rent| rent.prepaid_units)
                .sum(),
            accrued_rent_units: self
                .storage_rent_accounts
                .values()
                .map(|rent| rent.accrued_units)
                .sum(),
            reserved_gas: self.gas_lanes.values().map(|lane| lane.reserved_gas).sum(),
            used_gas: self.gas_lanes.values().map(|lane| lane.used_gas).sum(),
            receipt_fee_units: self
                .call_receipts
                .values()
                .map(|receipt| receipt.fee_units)
                .sum(),
            estimated_proof_bytes: self
                .proof_obligations
                .values()
                .map(|proof| proof.estimated_proof_bytes)
                .sum(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        let mut record = self.public_record_without_state_root(&roots, &counters);
        record
            .as_object_mut()
            .expect("shielded runtime public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_state_root(
        &self,
        roots: &ShieldedContractRuntimeRoots,
        counters: &ShieldedContractRuntimeCounters,
    ) -> Value {
        json!({
            "kind": "shielded_contract_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION,
            "schema_version": SHIELDED_CONTRACT_RUNTIME_SCHEMA_VERSION,
            "height": self.height,
            "host": SHIELDED_CONTRACT_RUNTIME_HOST,
            "encryption_scheme": SHIELDED_CONTRACT_RUNTIME_ENCRYPTION_SCHEME,
            "commitment_scheme": SHIELDED_CONTRACT_RUNTIME_COMMITMENT_SCHEME,
            "pq_account_scheme": SHIELDED_CONTRACT_RUNTIME_PQ_ACCOUNT_SCHEME,
            "pq_recovery_scheme": SHIELDED_CONTRACT_RUNTIME_PQ_RECOVERY_SCHEME,
            "session_scheme": SHIELDED_CONTRACT_RUNTIME_SESSION_SCHEME,
            "proof_system": SHIELDED_CONTRACT_RUNTIME_PROOF_SYSTEM,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.aggregate_root(),
            "counters": counters.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        let counters = self.counters();
        shielded_contract_runtime_state_root_from_record(
            &self.public_record_without_state_root(&roots, &counters),
        )
    }

    pub fn validate(&self) -> ShieldedContractRuntimeResult<String> {
        self.config.validate()?;
        ensure_map_keys_match(
            &self.class_manifests,
            |value| &value.class_id,
            "class manifest",
        )?;
        ensure_map_keys_match(&self.state_cells, |value| &value.cell_id, "state cell")?;
        ensure_map_keys_match(&self.access_list, |value| &value.entry_id, "access list")?;
        ensure_map_keys_match(
            &self.disclosure_policies,
            |value| &value.policy_id,
            "disclosure policy",
        )?;
        ensure_map_keys_match(
            &self.view_key_grants,
            |value| &value.grant_id,
            "view key grant",
        )?;
        ensure_map_keys_match(
            &self.pq_account_keys,
            |value| &value.key_id,
            "pq account key",
        )?;
        ensure_map_keys_match(
            &self.pq_session_authorizations,
            |value| &value.authorization_id,
            "pq session authorization",
        )?;
        ensure_map_keys_match(
            &self.proof_obligations,
            |value| &value.obligation_id,
            "proof obligation",
        )?;
        ensure_map_keys_match(&self.gas_lanes, |value| &value.lane_id, "gas lane")?;
        ensure_map_keys_match(
            &self.execution_shards,
            |value| &value.shard_id,
            "execution shard",
        )?;
        ensure_map_keys_match(
            &self.call_receipts,
            |value| &value.receipt_id,
            "call receipt",
        )?;
        ensure_map_keys_match(
            &self.storage_rent_accounts,
            |value| &value.rent_account_id,
            "storage rent account",
        )?;
        ensure_map_keys_match(
            &self.compression_hints,
            |value| &value.compression_hint_id,
            "compression hint",
        )?;
        ensure_map_keys_match(
            &self.rollback_checkpoints,
            |value| &value.checkpoint_id,
            "rollback checkpoint",
        )?;
        ensure_map_keys_match(
            &self.fraud_evidence,
            |value| &value.evidence_id,
            "fraud evidence",
        )?;
        ensure_map_keys_match(
            &self.devnet_records,
            |value| &value.record_id,
            "devnet record",
        )?;

        for manifest in self.class_manifests.values() {
            manifest.validate()?;
        }
        for cell in self.state_cells.values() {
            cell.validate()?;
            ensure_contract_exists(&self.class_manifests, &cell.contract_id, "state cell")?;
            if !cell.compression_hint_id.is_empty()
                && !self
                    .compression_hints
                    .contains_key(&cell.compression_hint_id)
            {
                return Err(format!(
                    "state cell compression hint missing: {}",
                    cell.compression_hint_id
                ));
            }
            if cell.ciphertext_bytes > self.config.max_state_cell_bytes {
                return Err(format!("state cell exceeds max bytes: {}", cell.cell_id));
            }
        }
        for entry in self.access_list.values() {
            entry.validate()?;
            ensure_contract_exists(&self.class_manifests, &entry.contract_id, "access list")?;
            if !entry.session_id.is_empty()
                && !self
                    .pq_session_authorizations
                    .values()
                    .any(|session| session.session_id == entry.session_id)
            {
                return Err(format!("access list session missing: {}", entry.session_id));
            }
        }
        for policy in self.disclosure_policies.values() {
            policy.validate()?;
            ensure_contract_exists(
                &self.class_manifests,
                &policy.contract_id,
                "disclosure policy",
            )?;
        }
        for grant in self.view_key_grants.values() {
            grant.validate()?;
            ensure_contract_exists(&self.class_manifests, &grant.contract_id, "view key grant")?;
            if !self.disclosure_policies.contains_key(&grant.policy_id) {
                return Err(format!("view key policy missing: {}", grant.policy_id));
            }
        }
        for key in self.pq_account_keys.values() {
            key.validate()?;
        }
        for session in self.pq_session_authorizations.values() {
            session.validate()?;
            if !self.pq_account_keys.contains_key(&session.signer_key_id) {
                return Err(format!(
                    "pq session signer key missing: {}",
                    session.signer_key_id
                ));
            }
        }
        for obligation in self.proof_obligations.values() {
            obligation.validate()?;
            ensure_contract_exists(
                &self.class_manifests,
                &obligation.contract_id,
                "proof obligation",
            )?;
            if !self.gas_lanes.contains_key(&obligation.fee_lane_id) {
                return Err(format!(
                    "proof obligation fee lane missing: {}",
                    obligation.fee_lane_id
                ));
            }
        }
        for lane in self.gas_lanes.values() {
            lane.validate()?;
        }
        for shard in self.execution_shards.values() {
            shard.validate()?;
        }
        if self.execution_shards.len() > self.config.max_parallel_shards as usize {
            return Err("execution shard count exceeds config max_parallel_shards".to_string());
        }
        for receipt in self.call_receipts.values() {
            receipt.validate()?;
            ensure_contract_exists(
                &self.class_manifests,
                &receipt.source_contract_id,
                "call receipt source",
            )?;
            ensure_contract_exists(
                &self.class_manifests,
                &receipt.target_contract_id,
                "call receipt target",
            )?;
            if !self.execution_shards.contains_key(&receipt.shard_id) {
                return Err(format!("call receipt shard missing: {}", receipt.shard_id));
            }
            if receipt.gas_used > self.config.max_call_gas {
                return Err(format!(
                    "call receipt gas exceeds max call gas: {}",
                    receipt.receipt_id
                ));
            }
        }
        for rent in self.storage_rent_accounts.values() {
            rent.validate()?;
            ensure_contract_exists(&self.class_manifests, &rent.contract_id, "storage rent")?;
        }
        for hint in self.compression_hints.values() {
            hint.validate()?;
            ensure_contract_exists(&self.class_manifests, &hint.contract_id, "compression hint")?;
        }
        for checkpoint in self.rollback_checkpoints.values() {
            checkpoint.validate()?;
        }
        for evidence in self.fraud_evidence.values() {
            evidence.validate()?;
            if !self.call_receipts.contains_key(&evidence.target_receipt_id) {
                return Err(format!(
                    "fraud evidence target receipt missing: {}",
                    evidence.target_receipt_id
                ));
            }
            if !self
                .rollback_checkpoints
                .contains_key(&evidence.target_checkpoint_id)
            {
                return Err(format!(
                    "fraud evidence target checkpoint missing: {}",
                    evidence.target_checkpoint_id
                ));
            }
        }
        for record in self.devnet_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    pub fn insert_class_manifest(
        &mut self,
        manifest: ShieldedContractClassManifest,
    ) -> ShieldedContractRuntimeResult<String> {
        manifest.validate()?;
        insert_unique(
            &mut self.class_manifests,
            manifest.class_id.clone(),
            manifest,
            "class manifest",
        )
    }

    pub fn insert_state_cell(
        &mut self,
        cell: EncryptedStateCell,
    ) -> ShieldedContractRuntimeResult<String> {
        cell.validate()?;
        insert_unique(
            &mut self.state_cells,
            cell.cell_id.clone(),
            cell,
            "state cell",
        )
    }

    pub fn insert_access_list_entry(
        &mut self,
        entry: AccessListEntry,
    ) -> ShieldedContractRuntimeResult<String> {
        entry.validate()?;
        insert_unique(
            &mut self.access_list,
            entry.entry_id.clone(),
            entry,
            "access list entry",
        )
    }

    pub fn insert_disclosure_policy(
        &mut self,
        policy: DisclosurePolicy,
    ) -> ShieldedContractRuntimeResult<String> {
        policy.validate()?;
        insert_unique(
            &mut self.disclosure_policies,
            policy.policy_id.clone(),
            policy,
            "disclosure policy",
        )
    }

    pub fn insert_view_key_grant(
        &mut self,
        grant: ViewKeyGrant,
    ) -> ShieldedContractRuntimeResult<String> {
        grant.validate()?;
        insert_unique(
            &mut self.view_key_grants,
            grant.grant_id.clone(),
            grant,
            "view key grant",
        )
    }

    pub fn insert_pq_account_key(
        &mut self,
        key: PqAccountKey,
    ) -> ShieldedContractRuntimeResult<String> {
        key.validate()?;
        insert_unique(
            &mut self.pq_account_keys,
            key.key_id.clone(),
            key,
            "pq account key",
        )
    }

    pub fn insert_pq_session_authorization(
        &mut self,
        authorization: PqSessionAuthorization,
    ) -> ShieldedContractRuntimeResult<String> {
        authorization.validate()?;
        insert_unique(
            &mut self.pq_session_authorizations,
            authorization.authorization_id.clone(),
            authorization,
            "pq session authorization",
        )
    }

    pub fn insert_proof_obligation(
        &mut self,
        obligation: ZkProofObligation,
    ) -> ShieldedContractRuntimeResult<String> {
        obligation.validate()?;
        insert_unique(
            &mut self.proof_obligations,
            obligation.obligation_id.clone(),
            obligation,
            "proof obligation",
        )
    }

    pub fn insert_gas_lane(&mut self, lane: GasFeeLane) -> ShieldedContractRuntimeResult<String> {
        lane.validate()?;
        insert_unique(&mut self.gas_lanes, lane.lane_id.clone(), lane, "gas lane")
    }

    pub fn insert_execution_shard(
        &mut self,
        shard: ParallelExecutionShard,
    ) -> ShieldedContractRuntimeResult<String> {
        shard.validate()?;
        insert_unique(
            &mut self.execution_shards,
            shard.shard_id.clone(),
            shard,
            "execution shard",
        )
    }

    pub fn insert_call_receipt(
        &mut self,
        receipt: CrossContractCallReceipt,
    ) -> ShieldedContractRuntimeResult<String> {
        receipt.validate()?;
        insert_unique(
            &mut self.call_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "call receipt",
        )
    }

    pub fn insert_storage_rent_account(
        &mut self,
        account: StorageRentAccount,
    ) -> ShieldedContractRuntimeResult<String> {
        account.validate()?;
        insert_unique(
            &mut self.storage_rent_accounts,
            account.rent_account_id.clone(),
            account,
            "storage rent account",
        )
    }

    pub fn insert_compression_hint(
        &mut self,
        hint: CompressionHint,
    ) -> ShieldedContractRuntimeResult<String> {
        hint.validate()?;
        insert_unique(
            &mut self.compression_hints,
            hint.compression_hint_id.clone(),
            hint,
            "compression hint",
        )
    }

    pub fn insert_rollback_checkpoint(
        &mut self,
        checkpoint: RollbackCheckpoint,
    ) -> ShieldedContractRuntimeResult<String> {
        checkpoint.validate()?;
        insert_unique(
            &mut self.rollback_checkpoints,
            checkpoint.checkpoint_id.clone(),
            checkpoint,
            "rollback checkpoint",
        )
    }

    pub fn insert_fraud_evidence(
        &mut self,
        evidence: FraudEvidenceRecord,
    ) -> ShieldedContractRuntimeResult<String> {
        evidence.validate()?;
        insert_unique(
            &mut self.fraud_evidence,
            evidence.evidence_id.clone(),
            evidence,
            "fraud evidence",
        )
    }

    pub fn insert_devnet_record(
        &mut self,
        record: RuntimeDevnetRecord,
    ) -> ShieldedContractRuntimeResult<String> {
        record.validate()?;
        insert_unique(
            &mut self.devnet_records,
            record.record_id.clone(),
            record,
            "devnet record",
        )
    }
}

pub fn shielded_contract_runtime_state_root_from_record(record: &Value) -> String {
    runtime_payload_root("SHIELDED-CONTRACT-RUNTIME-STATE", record)
}

pub fn runtime_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn runtime_empty_root(domain: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn runtime_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn runtime_string_set_root(domain: &str, values: &[String]) -> String {
    let mut normalized = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    let leaves = normalized
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn runtime_account_commitment(label: &str) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-ACCOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(SHIELDED_CONTRACT_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn runtime_call_id(
    contract_id: &str,
    selector: &str,
    caller_commitment: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Str(caller_commitment),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn permission_set_root(values: &[ShieldedContractPermission]) -> String {
    let mut values = values
        .iter()
        .map(ShieldedContractPermission::as_str)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    let leaves = values
        .into_iter()
        .map(|permission| json!({ "permission": permission }))
        .collect::<Vec<_>>();
    merkle_root("SHIELDED-RUNTIME-PERMISSION-SET", &leaves)
}

pub fn disclosure_audience_root(values: &[DisclosureAudience]) -> String {
    let mut values = values
        .iter()
        .map(|audience| audience.as_str().to_string())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    let leaves = values
        .into_iter()
        .map(|audience| json!({ "audience": audience }))
        .collect::<Vec<_>>();
    merkle_root("SHIELDED-RUNTIME-DISCLOSURE-AUDIENCE", &leaves)
}

#[allow(clippy::too_many_arguments)]
pub fn contract_interface_method_id(
    class_id: &str,
    selector: &str,
    entrypoint: &str,
    arg_schema_root: &str,
    return_schema_root: &str,
    required_permission_root: &str,
    default_proof_kind: &ZkProofObligationKind,
    max_gas: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-CONTRACT-METHOD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(selector),
            HashPart::Str(entrypoint),
            HashPart::Str(arg_schema_root),
            HashPart::Str(return_schema_root),
            HashPart::Str(required_permission_root),
            HashPart::Str(&default_proof_kind.as_str()),
            HashPart::Int(max_gas as i128),
        ],
        32,
    )
}

pub fn contract_interface_method_root(method: &ContractInterfaceMethod) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-CONTRACT-METHOD", &method.public_record())
}

pub fn contract_interface_method_root_from_slice(methods: &[ContractInterfaceMethod]) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-CONTRACT-METHOD",
        &methods
            .iter()
            .map(ContractInterfaceMethod::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn contract_class_manifest_id(
    name: &str,
    version: &str,
    kind: &ShieldedContractClassKind,
    code_commitment: &str,
    code_size_bytes: u64,
    abi_root: &str,
    state_schema_root: &str,
    event_schema_root: &str,
    publisher_commitment: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-CONTRACT-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(name),
            HashPart::Str(version),
            HashPart::Str(&kind.as_str()),
            HashPart::Str(code_commitment),
            HashPart::Int(code_size_bytes as i128),
            HashPart::Str(abi_root),
            HashPart::Str(state_schema_root),
            HashPart::Str(event_schema_root),
            HashPart::Str(publisher_commitment),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn contract_class_manifest_root(manifest: &ShieldedContractClassManifest) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-CONTRACT-CLASS-MANIFEST",
        &manifest.public_record(),
    )
}

pub fn class_manifest_root_from_map(
    values: &BTreeMap<String, ShieldedContractClassManifest>,
) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-CONTRACT-CLASS-MANIFEST",
        &values
            .values()
            .map(ShieldedContractClassManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn encrypted_state_cell_id(
    contract_id: &str,
    cell_key_commitment: &str,
    owner_commitment: &str,
    ciphertext_root: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-ENCRYPTED-STATE-CELL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(cell_key_commitment),
            HashPart::Str(owner_commitment),
            HashPart::Str(ciphertext_root),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn encrypted_state_cell_root(cell: &EncryptedStateCell) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-ENCRYPTED-STATE-CELL",
        &cell.public_record(),
    )
}

pub fn encrypted_state_cell_root_from_map(values: &BTreeMap<String, EncryptedStateCell>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-ENCRYPTED-STATE-CELL",
        &values
            .values()
            .map(EncryptedStateCell::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn access_list_entry_id(
    contract_id: &str,
    principal_commitment: &str,
    permission: &ShieldedContractPermission,
    mode: ShieldedAccessMode,
    scope_root: &str,
    session_id: &str,
    starts_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-ACCESS-LIST-ENTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(principal_commitment),
            HashPart::Str(&permission.as_str()),
            HashPart::Str(mode.as_str()),
            HashPart::Str(scope_root),
            HashPart::Str(session_id),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn access_list_entry_root(entry: &AccessListEntry) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-ACCESS-LIST-ENTRY", &entry.public_record())
}

pub fn access_list_root_from_map(values: &BTreeMap<String, AccessListEntry>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-ACCESS-LIST-ENTRY",
        &values
            .values()
            .map(AccessListEntry::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn disclosure_policy_id(
    contract_id: &str,
    default_audience: DisclosureAudience,
    allowed_audience_root: &str,
    disclosed_field_root: &str,
    threshold: u16,
    audit_delay_blocks: u64,
    emergency_reveal: bool,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-DISCLOSURE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(default_audience.as_str()),
            HashPart::Str(allowed_audience_root),
            HashPart::Str(disclosed_field_root),
            HashPart::Int(threshold as i128),
            HashPart::Int(audit_delay_blocks as i128),
            HashPart::Str(if emergency_reveal {
                "emergency"
            } else {
                "normal"
            }),
        ],
        32,
    )
}

pub fn disclosure_policy_root(policy: &DisclosurePolicy) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-DISCLOSURE-POLICY",
        &policy.public_record(),
    )
}

pub fn disclosure_policy_root_from_map(values: &BTreeMap<String, DisclosurePolicy>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-DISCLOSURE-POLICY",
        &values
            .values()
            .map(DisclosurePolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn view_key_grant_id(
    contract_id: &str,
    grantee_commitment: &str,
    key_commitment: &str,
    scope: ViewKeyScope,
    audience: DisclosureAudience,
    policy_id: &str,
    starts_at_height: u64,
    expires_at_height: u64,
    disclosure_root: &str,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-VIEW-KEY-GRANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(grantee_commitment),
            HashPart::Str(key_commitment),
            HashPart::Str(scope.as_str()),
            HashPart::Str(audience.as_str()),
            HashPart::Str(policy_id),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(disclosure_root),
        ],
        32,
    )
}

pub fn view_key_grant_root(grant: &ViewKeyGrant) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-VIEW-KEY-GRANT", &grant.public_record())
}

pub fn view_key_grant_root_from_map(values: &BTreeMap<String, ViewKeyGrant>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-VIEW-KEY-GRANT",
        &values
            .values()
            .map(ViewKeyGrant::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_account_key_id(
    account_commitment: &str,
    scheme: PqAuthorizationScheme,
    role: &str,
    public_key_root: &str,
    weight: u16,
    valid_from_height: u64,
    expires_at_height: u64,
    rotation_nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PQ-ACCOUNT-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(role),
            HashPart::Str(public_key_root),
            HashPart::Int(weight as i128),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(rotation_nonce as i128),
        ],
        32,
    )
}

pub fn pq_account_key_root(key: &PqAccountKey) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-PQ-ACCOUNT-KEY", &key.public_record())
}

pub fn pq_account_key_root_from_map(values: &BTreeMap<String, PqAccountKey>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-PQ-ACCOUNT-KEY",
        &values
            .values()
            .map(PqAccountKey::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_session_transcript_hash(
    account_commitment: &str,
    signer_key_id: &str,
    scheme: PqAuthorizationScheme,
    scope_root: &str,
    call_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PQ-SESSION-TRANSCRIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(signer_key_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(scope_root),
            HashPart::Str(call_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_signature_commitment(
    account_commitment: &str,
    signer_key_id: &str,
    scheme: PqAuthorizationScheme,
    transcript_hash: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PQ-SIGNATURE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(signer_key_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(transcript_hash),
            HashPart::Int(nonce as i128),
        ],
        64,
    )
}

pub fn pq_session_id(
    account_commitment: &str,
    signer_key_id: &str,
    scope_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PQ-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(signer_key_id),
            HashPart::Str(scope_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn pq_session_authorization_id(
    account_commitment: &str,
    session_id: &str,
    signer_key_id: &str,
    scheme: PqAuthorizationScheme,
    transcript_hash: &str,
    signature_commitment: &str,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PQ-SESSION-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(session_id),
            HashPart::Str(signer_key_id),
            HashPart::Str(scheme.as_str()),
            HashPart::Str(transcript_hash),
            HashPart::Str(signature_commitment),
        ],
        32,
    )
}

pub fn pq_session_authorization_root(authorization: &PqSessionAuthorization) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-PQ-SESSION-AUTHORIZATION",
        &authorization.public_record(),
    )
}

pub fn pq_session_authorization_root_from_map(
    values: &BTreeMap<String, PqSessionAuthorization>,
) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-PQ-SESSION-AUTHORIZATION",
        &values
            .values()
            .map(PqSessionAuthorization::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn zk_proof_obligation_id(
    contract_id: &str,
    call_id: &str,
    kind: &ZkProofObligationKind,
    proof_system: &str,
    public_input_root: &str,
    statement_root: &str,
    due_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-ZK-PROOF-OBLIGATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(call_id),
            HashPart::Str(&kind.as_str()),
            HashPart::Str(proof_system),
            HashPart::Str(public_input_root),
            HashPart::Str(statement_root),
            HashPart::Int(due_height as i128),
        ],
        32,
    )
}

pub fn zk_proof_obligation_root(obligation: &ZkProofObligation) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-ZK-PROOF-OBLIGATION",
        &obligation.public_record(),
    )
}

pub fn zk_proof_obligation_root_from_map(values: &BTreeMap<String, ZkProofObligation>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-ZK-PROOF-OBLIGATION",
        &values
            .values()
            .map(ZkProofObligation::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn gas_fee_lane_id(
    kind: GasFeeLaneKind,
    priority: GasPriority,
    fee_asset_id: &str,
    base_fee_units: u64,
    max_gas_per_block: u64,
    rebate_bps: u16,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-GAS-FEE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(priority.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(base_fee_units as i128),
            HashPart::Int(max_gas_per_block as i128),
            HashPart::Int(rebate_bps as i128),
        ],
        32,
    )
}

pub fn gas_fee_lane_root(lane: &GasFeeLane) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-GAS-FEE-LANE", &lane.public_record())
}

pub fn gas_fee_lane_root_from_map(values: &BTreeMap<String, GasFeeLane>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-GAS-FEE-LANE",
        &values
            .values()
            .map(GasFeeLane::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn parallel_execution_shard_id(
    shard_index: u16,
    kind: ExecutionShardKind,
    state_domain_root: &str,
    access_root: &str,
    write_root: &str,
    worker_committee_root: &str,
    deterministic_seed: &str,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-PARALLEL-EXECUTION-SHARD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(shard_index as i128),
            HashPart::Str(kind.as_str()),
            HashPart::Str(state_domain_root),
            HashPart::Str(access_root),
            HashPart::Str(write_root),
            HashPart::Str(worker_committee_root),
            HashPart::Str(deterministic_seed),
        ],
        32,
    )
}

pub fn parallel_execution_shard_root(shard: &ParallelExecutionShard) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-PARALLEL-EXECUTION-SHARD",
        &shard.public_record(),
    )
}

pub fn parallel_execution_shard_root_from_map(
    values: &BTreeMap<String, ParallelExecutionShard>,
) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-PARALLEL-EXECUTION-SHARD",
        &values
            .values()
            .map(ParallelExecutionShard::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn cross_contract_call_receipt_id(
    parent_call_id: &str,
    child_call_id: &str,
    source_contract_id: &str,
    target_contract_id: &str,
    selector: &str,
    input_commitment: &str,
    output_commitment: &str,
    gas_used: u64,
    fee_units: u64,
    shard_id: &str,
    emitted_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-CROSS-CONTRACT-CALL-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(parent_call_id),
            HashPart::Str(child_call_id),
            HashPart::Str(source_contract_id),
            HashPart::Str(target_contract_id),
            HashPart::Str(selector),
            HashPart::Str(input_commitment),
            HashPart::Str(output_commitment),
            HashPart::Int(gas_used as i128),
            HashPart::Int(fee_units as i128),
            HashPart::Str(shard_id),
            HashPart::Int(emitted_at_height as i128),
        ],
        32,
    )
}

pub fn cross_contract_call_receipt_root(receipt: &CrossContractCallReceipt) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-CROSS-CONTRACT-CALL-RECEIPT",
        &receipt.public_record(),
    )
}

pub fn cross_contract_call_receipt_root_from_map(
    values: &BTreeMap<String, CrossContractCallReceipt>,
) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-CROSS-CONTRACT-CALL-RECEIPT",
        &values
            .values()
            .map(CrossContractCallReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn storage_rent_account_id(
    contract_id: &str,
    owner_commitment: &str,
    rent_asset_id: &str,
    last_settlement_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-STORAGE-RENT-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(rent_asset_id),
            HashPart::Int(last_settlement_height as i128),
        ],
        32,
    )
}

pub fn storage_rent_account_root(account: &StorageRentAccount) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-STORAGE-RENT-ACCOUNT",
        &account.public_record(),
    )
}

pub fn storage_rent_account_root_from_map(values: &BTreeMap<String, StorageRentAccount>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-STORAGE-RENT-ACCOUNT",
        &values
            .values()
            .map(StorageRentAccount::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn compression_hint_id(
    contract_id: &str,
    codec: CompressionCodec,
    dictionary_root: &str,
    min_savings_bps: u16,
    original_bytes: u64,
    compressed_bytes: u64,
    witness_root: &str,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-COMPRESSION-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(codec.as_str()),
            HashPart::Str(dictionary_root),
            HashPart::Int(min_savings_bps as i128),
            HashPart::Int(original_bytes as i128),
            HashPart::Int(compressed_bytes as i128),
            HashPart::Str(witness_root),
        ],
        32,
    )
}

pub fn compression_hint_root(hint: &CompressionHint) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-COMPRESSION-HINT", &hint.public_record())
}

pub fn compression_hint_root_from_map(values: &BTreeMap<String, CompressionHint>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-COMPRESSION-HINT",
        &values
            .values()
            .map(CompressionHint::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn rollback_checkpoint_id(
    height: u64,
    state_root: &str,
    runtime_root: &str,
    accepted_receipt_root: &str,
    state_delta_root: &str,
    operator_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-ROLLBACK-CHECKPOINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(state_root),
            HashPart::Str(runtime_root),
            HashPart::Str(accepted_receipt_root),
            HashPart::Str(state_delta_root),
            HashPart::Str(operator_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn rollback_checkpoint_root(checkpoint: &RollbackCheckpoint) -> String {
    runtime_payload_root(
        "SHIELDED-RUNTIME-ROLLBACK-CHECKPOINT",
        &checkpoint.public_record(),
    )
}

pub fn rollback_checkpoint_root_from_map(values: &BTreeMap<String, RollbackCheckpoint>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-ROLLBACK-CHECKPOINT",
        &values
            .values()
            .map(RollbackCheckpoint::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fraud_evidence_id(
    kind: &FraudEvidenceKind,
    challenger_commitment: &str,
    target_receipt_id: &str,
    target_checkpoint_id: &str,
    evidence_root: &str,
    submitted_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-FRAUD-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&kind.as_str()),
            HashPart::Str(challenger_commitment),
            HashPart::Str(target_receipt_id),
            HashPart::Str(target_checkpoint_id),
            HashPart::Str(evidence_root),
            HashPart::Int(submitted_at_height as i128),
        ],
        32,
    )
}

pub fn fraud_evidence_root(evidence: &FraudEvidenceRecord) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-FRAUD-EVIDENCE", &evidence.public_record())
}

pub fn fraud_evidence_root_from_map(values: &BTreeMap<String, FraudEvidenceRecord>) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-FRAUD-EVIDENCE",
        &values
            .values()
            .map(FraudEvidenceRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn runtime_devnet_record_id(
    label: &str,
    category: &str,
    payload_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "SHIELDED-RUNTIME-DEVNET-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(category),
            HashPart::Str(payload_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn runtime_devnet_record_root(record: &RuntimeDevnetRecord) -> String {
    runtime_payload_root("SHIELDED-RUNTIME-DEVNET-RECORD", &record.public_record())
}

pub fn runtime_devnet_record_root_from_map(
    values: &BTreeMap<String, RuntimeDevnetRecord>,
) -> String {
    merkle_root(
        "SHIELDED-RUNTIME-DEVNET-RECORD",
        &values
            .values()
            .map(RuntimeDevnetRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

fn estimated_ciphertext_bytes(payload: &Value) -> u64 {
    serde_json::to_string(payload)
        .map(|encoded| encoded.len() as u64)
        .unwrap_or(0)
        .saturating_add(1_088)
}

fn ensure_non_empty(value: &str, label: &str) -> ShieldedContractRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> ShieldedContractRuntimeResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_height_range(start: u64, end: u64, label: &str) -> ShieldedContractRuntimeResult<()> {
    if end <= start {
        Err(format!("{label} end must be greater than start"))
    } else {
        Ok(())
    }
}

fn ensure_matches(actual: &str, expected: &str, label: &str) -> ShieldedContractRuntimeResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} mismatch"))
    }
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> ShieldedContractRuntimeResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported: {value}"))
    }
}

fn ensure_contract_exists(
    manifests: &BTreeMap<String, ShieldedContractClassManifest>,
    contract_id: &str,
    label: &str,
) -> ShieldedContractRuntimeResult<()> {
    if manifests.contains_key(contract_id) {
        Ok(())
    } else {
        Err(format!(
            "{label} references unknown contract: {contract_id}"
        ))
    }
}

fn ensure_map_keys_match<T, F>(
    values: &BTreeMap<String, T>,
    id: F,
    label: &str,
) -> ShieldedContractRuntimeResult<()>
where
    F: Fn(&T) -> &String,
{
    for (key, value) in values {
        if key != id(value) {
            return Err(format!("{label} map key does not match record id: {key}"));
        }
    }
    Ok(())
}

fn insert_unique<T>(
    values: &mut BTreeMap<String, T>,
    id: String,
    value: T,
    label: &str,
) -> ShieldedContractRuntimeResult<String> {
    if values.contains_key(&id) {
        return Err(format!("{label} already exists: {id}"));
    }
    values.insert(id.clone(), value);
    Ok(id)
}

fn _ensure_unique_strings(values: &[String], label: &str) -> ShieldedContractRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        Err(format!("{label} must be unique"))
    } else {
        Ok(())
    }
}
