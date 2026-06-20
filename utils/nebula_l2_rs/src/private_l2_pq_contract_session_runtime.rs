use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqContractSessionRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-contract-session-runtime-v1";
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PQ_AUTH_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-contract-session-v1";
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEVNET_HEIGHT: u64 = 746_000;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_POLICIES: usize = 524_288;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_SESSIONS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_CALLS: usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize = 4_194_304;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_BATCHES: usize = 1_048_576;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 16_777_216;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MIN_PRIVACY_SET: usize = 128;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET: usize = 1_024;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_CALL_FEE_BPS: u64 = 18;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 11;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 = 72;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSessionPolicyKind {
    AccountScoped,
    ContractScoped,
    MethodScoped,
    SpendingBounded,
    TimeBounded,
    RecoveryBounded,
    EmergencyOnly,
}

impl ContractSessionPolicyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountScoped => "account_scoped",
            Self::ContractScoped => "contract_scoped",
            Self::MethodScoped => "method_scoped",
            Self::SpendingBounded => "spending_bounded",
            Self::TimeBounded => "time_bounded",
            Self::RecoveryBounded => "recovery_bounded",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Proposed,
    Active,
    Rotating,
    Paused,
    Revoked,
    Expired,
}

impl PolicyStatus {
    pub fn allows_session(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Opened,
    Authorized,
    Executing,
    Settled,
    Revoked,
    Expired,
    Slashed,
}

impl SessionStatus {
    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Opened | Self::Authorized | Self::Executing)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCallKind {
    TokenTransfer,
    Swap,
    Lend,
    Borrow,
    Vote,
    Bridge,
    Liquidate,
    Custom,
}

impl ContractCallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenTransfer => "token_transfer",
            Self::Swap => "swap",
            Self::Lend => "lend",
            Self::Borrow => "borrow",
            Self::Vote => "vote",
            Self::Bridge => "bridge",
            Self::Liquidate => "liquidate",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallStatus {
    Submitted,
    Authorized,
    Scheduled,
    Executed,
    Reverted,
    Cancelled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorReservationStatus {
    Reserved,
    Consumed,
    RebateQueued,
    Refunded,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBatchStatus {
    Proposed,
    Scheduling,
    Executed,
    PartiallyExecuted,
    Disputed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    SessionOpened,
    SessionRevoked,
    CallScheduled,
    CallExecuted,
    CallReverted,
    SponsorConsumed,
    RebatePaid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub devnet_height: u64,
    pub hash_suite: String,
    pub pq_auth_suite: String,
    pub max_policies: usize,
    pub max_sessions: usize,
    pub max_calls: usize,
    pub max_sponsor_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub min_privacy_set: usize,
    pub batch_privacy_set: usize,
    pub min_pq_security_bits: u16,
    pub max_call_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub session_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_SCHEMA_VERSION,
            devnet_height: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEVNET_HEIGHT,
            hash_suite: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_HASH_SUITE.to_string(),
            pq_auth_suite: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PQ_AUTH_SUITE.to_string(),
            max_policies: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_POLICIES,
            max_sessions: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_SESSIONS,
            max_calls: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_CALLS,
            max_sponsor_reservations:
                PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_RECEIPTS,
            min_privacy_set: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MIN_PRIVACY_SET,
            batch_privacy_set: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_BATCH_PRIVACY_SET,
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_call_fee_bps: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_MAX_CALL_FEE_BPS,
            target_rebate_bps: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            session_ttl_blocks: PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_SESSION_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
        }
    }

    pub fn validate(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.chain_id.is_empty()
            || self.protocol_version.is_empty()
            || self.hash_suite.is_empty()
            || self.pq_auth_suite.is_empty()
        {
            return Err("contract session config identifiers cannot be empty".to_string());
        }
        if self.schema_version == 0 || self.devnet_height == 0 {
            return Err("contract session version/height must be positive".to_string());
        }
        if self.max_policies == 0
            || self.max_sessions == 0
            || self.max_calls == 0
            || self.max_sponsor_reservations == 0
            || self.max_batches == 0
            || self.max_receipts == 0
        {
            return Err("contract session capacities must be positive".to_string());
        }
        if self.min_privacy_set == 0 || self.batch_privacy_set < self.min_privacy_set {
            return Err("contract session privacy set bounds are invalid".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("contract session pq security target is too low".to_string());
        }
        if self.max_call_fee_bps > PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_MAX_BPS
            || self.target_rebate_bps > PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_MAX_BPS
        {
            return Err("contract session fee bps exceeds max".to_string());
        }
        if self.session_ttl_blocks == 0 || self.reservation_ttl_blocks == 0 {
            return Err("contract session ttl windows must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "devnet_height": self.devnet_height,
            "hash_suite": self.hash_suite,
            "pq_auth_suite": self.pq_auth_suite,
            "max_policies": self.max_policies,
            "max_sessions": self.max_sessions,
            "max_calls": self.max_calls,
            "max_sponsor_reservations": self.max_sponsor_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "min_privacy_set": self.min_privacy_set,
            "batch_privacy_set": self.batch_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_call_fee_bps": self.max_call_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "session_ttl_blocks": self.session_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub policies_registered: u64,
    pub sessions_opened: u64,
    pub calls_submitted: u64,
    pub sponsor_reservations_opened: u64,
    pub execution_batches_built: u64,
    pub receipts_published: u64,
    pub rebates_published: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_counters",
            "policies_registered": self.policies_registered,
            "sessions_opened": self.sessions_opened,
            "calls_submitted": self.calls_submitted,
            "sponsor_reservations_opened": self.sponsor_reservations_opened,
            "execution_batches_built": self.execution_batches_built,
            "receipts_published": self.receipts_published,
            "rebates_published": self.rebates_published,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterContractSessionPolicyRequest {
    pub policy_kind: ContractSessionPolicyKind,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub contract_address_root: String,
    pub method_selector_root: String,
    pub spending_limit_root: String,
    pub policy_metadata_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub min_pq_security_bits: u16,
    pub pq_policy_authorization_root: String,
}

impl RegisterContractSessionPolicyRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "register_contract_session_policy_request",
            "policy_kind": self.policy_kind.as_str(),
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "contract_address_root": self.contract_address_root,
            "method_selector_root": self.method_selector_root,
            "spending_limit_root": self.spending_limit_root,
            "policy_metadata_root": self.policy_metadata_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "pq_policy_authorization_root": self.pq_policy_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenPrivateContractSessionRequest {
    pub policy_id: String,
    pub session_owner_commitment: String,
    pub encrypted_session_key_root: String,
    pub capability_root: String,
    pub replay_fence_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub privacy_set_size: usize,
    pub pq_session_authorization_root: String,
}

impl OpenPrivateContractSessionRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "open_private_contract_session_request",
            "policy_id": self.policy_id,
            "session_owner_commitment": self.session_owner_commitment,
            "encrypted_session_key_root": self.encrypted_session_key_root,
            "capability_root": self.capability_root,
            "replay_fence_root": self.replay_fence_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "privacy_set_size": self.privacy_set_size,
            "pq_session_authorization_root": self.pq_session_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitPrivateContractCallRequest {
    pub session_id: String,
    pub call_kind: ContractCallKind,
    pub contract_address_root: String,
    pub encrypted_calldata_root: String,
    pub witness_commitment_root: String,
    pub value_commitment_root: String,
    pub nonce_nullifier: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: usize,
    pub expires_at_height: u64,
    pub pq_call_authorization_root: String,
}

impl SubmitPrivateContractCallRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "submit_private_contract_call_request",
            "session_id": self.session_id,
            "call_kind": self.call_kind.as_str(),
            "contract_address_root": self.contract_address_root,
            "encrypted_calldata_root": self.encrypted_calldata_root,
            "witness_commitment_root": self.witness_commitment_root,
            "value_commitment_root": self.value_commitment_root,
            "nonce_nullifier": self.nonce_nullifier,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "expires_at_height": self.expires_at_height,
            "pq_call_authorization_root": self.pq_call_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveContractCallSponsorRequest {
    pub session_id: String,
    pub call_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub coverage_bps: u64,
    pub expires_at_height: u64,
    pub pq_sponsor_authorization_root: String,
}

impl ReserveContractCallSponsorRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "reserve_contract_call_sponsor_request",
            "session_id": self.session_id,
            "call_id": self.call_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "coverage_bps": self.coverage_bps,
            "expires_at_height": self.expires_at_height,
            "pq_sponsor_authorization_root": self.pq_sponsor_authorization_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildContractExecutionBatchRequest {
    pub batch_height: u64,
    pub session_ids: Vec<String>,
    pub call_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub scheduler_root: String,
    pub encrypted_witness_root: String,
    pub state_diff_commitment_root: String,
    pub pq_batch_authorization_root: String,
    pub batch_privacy_set_size: usize,
}

impl BuildContractExecutionBatchRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "build_contract_execution_batch_request",
            "batch_height": self.batch_height,
            "session_ids": self.session_ids,
            "call_ids": self.call_ids,
            "reservation_ids": self.reservation_ids,
            "scheduler_root": self.scheduler_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "state_diff_commitment_root": self.state_diff_commitment_root,
            "pq_batch_authorization_root": self.pq_batch_authorization_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishContractSessionReceiptRequest {
    pub batch_id: String,
    pub session_id: Option<String>,
    pub call_id: Option<String>,
    pub receipt_kind: ReceiptKind,
    pub recipient_commitment: String,
    pub execution_receipt_root: String,
    pub fee_charged_bps: u64,
    pub rebate_bps: u64,
    pub pq_receipt_root: String,
}

impl PublishContractSessionReceiptRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_contract_session_receipt_request",
            "batch_id": self.batch_id,
            "session_id": self.session_id,
            "call_id": self.call_id,
            "receipt_kind": format!("{:?}", self.receipt_kind).to_lowercase(),
            "recipient_commitment": self.recipient_commitment,
            "execution_receipt_root": self.execution_receipt_root,
            "fee_charged_bps": self.fee_charged_bps,
            "rebate_bps": self.rebate_bps,
            "pq_receipt_root": self.pq_receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishContractSessionRebateRequest {
    pub reservation_id: String,
    pub receipt_id: String,
    pub sponsor_commitment: String,
    pub rebate_note_root: String,
    pub rebate_bps: u64,
    pub pq_rebate_root: String,
}

impl PublishContractSessionRebateRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "publish_contract_session_rebate_request",
            "reservation_id": self.reservation_id,
            "receipt_id": self.receipt_id,
            "sponsor_commitment": self.sponsor_commitment,
            "rebate_note_root": self.rebate_note_root,
            "rebate_bps": self.rebate_bps,
            "pq_rebate_root": self.pq_rebate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSessionPolicyRecord {
    pub policy_id: String,
    pub request: RegisterContractSessionPolicyRequest,
    pub status: PolicyStatus,
    pub created_sequence: u64,
}

impl ContractSessionPolicyRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_policy",
            "policy_id": self.policy_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateContractSessionRecord {
    pub session_id: String,
    pub request: OpenPrivateContractSessionRequest,
    pub status: SessionStatus,
    pub created_sequence: u64,
    pub call_ids: Vec<String>,
}

impl PrivateContractSessionRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session",
            "session_id": self.session_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "call_ids": self.call_ids,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivateContractCallRecord {
    pub call_id: String,
    pub request: SubmitPrivateContractCallRequest,
    pub status: CallStatus,
    pub created_sequence: u64,
    pub execution_batch_id: Option<String>,
}

impl PrivateContractCallRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_call",
            "call_id": self.call_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "execution_batch_id": self.execution_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractCallSponsorReservationRecord {
    pub reservation_id: String,
    pub request: ReserveContractCallSponsorRequest,
    pub status: SponsorReservationStatus,
    pub created_sequence: u64,
    pub consumed_by_batch_id: Option<String>,
}

impl ContractCallSponsorReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_call_sponsor_reservation",
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
            "consumed_by_batch_id": self.consumed_by_batch_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractExecutionBatchRecord {
    pub batch_id: String,
    pub request: BuildContractExecutionBatchRequest,
    pub status: ExecutionBatchStatus,
    pub created_sequence: u64,
}

impl ContractExecutionBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_execution_batch",
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": format!("{:?}", self.status).to_lowercase(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSessionReceiptRecord {
    pub receipt_id: String,
    pub request: PublishContractSessionReceiptRequest,
    pub created_sequence: u64,
}

impl ContractSessionReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_receipt",
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContractSessionRebateRecord {
    pub rebate_id: String,
    pub request: PublishContractSessionRebateRequest,
    pub created_sequence: u64,
}

impl ContractSessionRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_rebate",
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "created_sequence": self.created_sequence,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub policy_root: String,
    pub session_root: String,
    pub call_root: String,
    pub sponsor_reservation_root: String,
    pub execution_batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
    pub nonce_nullifier_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_roots",
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "policy_root": self.policy_root,
            "session_root": self.session_root,
            "call_root": self.call_root,
            "sponsor_reservation_root": self.sponsor_reservation_root,
            "execution_batch_root": self.execution_batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
            "nonce_nullifier_root": self.nonce_nullifier_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub policies: BTreeMap<String, ContractSessionPolicyRecord>,
    pub sessions: BTreeMap<String, PrivateContractSessionRecord>,
    pub calls: BTreeMap<String, PrivateContractCallRecord>,
    pub sponsor_reservations: BTreeMap<String, ContractCallSponsorReservationRecord>,
    pub execution_batches: BTreeMap<String, ContractExecutionBatchRecord>,
    pub receipts: BTreeMap<String, ContractSessionReceiptRecord>,
    pub rebates: BTreeMap<String, ContractSessionRebateRecord>,
    pub consumed_nonce_nullifiers: BTreeSet<String>,
}

impl State {
    pub fn devnet() -> PrivateL2PqContractSessionRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2PqContractSessionRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            policies: BTreeMap::new(),
            sessions: BTreeMap::new(),
            calls: BTreeMap::new(),
            sponsor_reservations: BTreeMap::new(),
            execution_batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
            consumed_nonce_nullifiers: BTreeSet::new(),
        })
    }

    pub fn register_policy(
        &mut self,
        request: RegisterContractSessionPolicyRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_policy_capacity()?;
        require_nonempty("owner_commitment", &request.owner_commitment)?;
        require_nonempty("account_commitment", &request.account_commitment)?;
        require_nonempty("contract_address_root", &request.contract_address_root)?;
        require_nonempty("method_selector_root", &request.method_selector_root)?;
        require_nonempty("spending_limit_root", &request.spending_limit_root)?;
        require_nonempty("policy_metadata_root", &request.policy_metadata_root)?;
        require_nonempty(
            "pq_policy_authorization_root",
            &request.pq_policy_authorization_root,
        )?;
        if request.valid_from_height >= request.valid_until_height {
            return Err("contract session policy height window is invalid".to_string());
        }
        if request.min_pq_security_bits < self.config.min_pq_security_bits {
            return Err("contract session policy pq security below target".to_string());
        }
        let sequence = self.counters.policies_registered.saturating_add(1);
        let policy_id = contract_session_policy_id(&request, sequence);
        if self.policies.contains_key(&policy_id) {
            return Err("contract session policy id collision".to_string());
        }
        let record = ContractSessionPolicyRecord {
            policy_id: policy_id.clone(),
            request,
            status: PolicyStatus::Active,
            created_sequence: sequence,
        };
        self.policies.insert(policy_id.clone(), record);
        self.counters.policies_registered = sequence;
        Ok(policy_id)
    }

    pub fn open_session(
        &mut self,
        request: OpenPrivateContractSessionRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_session_capacity()?;
        require_nonempty("policy_id", &request.policy_id)?;
        require_nonempty(
            "session_owner_commitment",
            &request.session_owner_commitment,
        )?;
        require_nonempty(
            "encrypted_session_key_root",
            &request.encrypted_session_key_root,
        )?;
        require_nonempty("capability_root", &request.capability_root)?;
        require_nonempty("replay_fence_root", &request.replay_fence_root)?;
        require_nonempty(
            "pq_session_authorization_root",
            &request.pq_session_authorization_root,
        )?;
        if request.valid_from_height >= request.valid_until_height {
            return Err("contract session height window is invalid".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("contract session privacy set is too small".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "contract session policy not found".to_string())?;
        if !policy.status.allows_session() {
            return Err("contract session policy does not allow sessions".to_string());
        }
        if request.valid_from_height < policy.request.valid_from_height
            || request.valid_until_height > policy.request.valid_until_height
        {
            return Err("contract session exceeds policy validity window".to_string());
        }
        let sequence = self.counters.sessions_opened.saturating_add(1);
        let session_id = private_contract_session_id(&request, sequence);
        if self.sessions.contains_key(&session_id) {
            return Err("private contract session id collision".to_string());
        }
        let record = PrivateContractSessionRecord {
            session_id: session_id.clone(),
            request,
            status: SessionStatus::Authorized,
            created_sequence: sequence,
            call_ids: Vec::new(),
        };
        self.sessions.insert(session_id.clone(), record);
        self.counters.sessions_opened = sequence;
        Ok(session_id)
    }

    pub fn submit_call(
        &mut self,
        request: SubmitPrivateContractCallRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_call_capacity()?;
        require_nonempty("session_id", &request.session_id)?;
        require_nonempty("contract_address_root", &request.contract_address_root)?;
        require_nonempty("encrypted_calldata_root", &request.encrypted_calldata_root)?;
        require_nonempty("witness_commitment_root", &request.witness_commitment_root)?;
        require_nonempty("value_commitment_root", &request.value_commitment_root)?;
        require_nonempty("nonce_nullifier", &request.nonce_nullifier)?;
        require_nonempty(
            "pq_call_authorization_root",
            &request.pq_call_authorization_root,
        )?;
        if self
            .consumed_nonce_nullifiers
            .contains(&request.nonce_nullifier)
        {
            return Err("contract session nonce nullifier already consumed".to_string());
        }
        if request.max_fee_bps > self.config.max_call_fee_bps {
            return Err("contract session call fee exceeds configured max".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set {
            return Err("contract session call privacy set is too small".to_string());
        }
        let session = self
            .sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| "private contract session not found".to_string())?;
        if !session.status.accepts_calls() {
            return Err("private contract session does not accept calls".to_string());
        }
        let sequence = self.counters.calls_submitted.saturating_add(1);
        let call_id = private_contract_call_id(&request, sequence);
        if self.calls.contains_key(&call_id) {
            return Err("private contract call id collision".to_string());
        }
        let nullifier = request.nonce_nullifier.clone();
        let record = PrivateContractCallRecord {
            call_id: call_id.clone(),
            request,
            status: CallStatus::Authorized,
            created_sequence: sequence,
            execution_batch_id: None,
        };
        session.status = SessionStatus::Executing;
        session.call_ids.push(call_id.clone());
        self.consumed_nonce_nullifiers.insert(nullifier);
        self.calls.insert(call_id.clone(), record);
        self.counters.calls_submitted = sequence;
        Ok(call_id)
    }

    pub fn reserve_sponsor(
        &mut self,
        request: ReserveContractCallSponsorRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_reservation_capacity()?;
        require_nonempty("session_id", &request.session_id)?;
        require_nonempty("call_id", &request.call_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("fee_asset_id", &request.fee_asset_id)?;
        require_nonempty(
            "pq_sponsor_authorization_root",
            &request.pq_sponsor_authorization_root,
        )?;
        if request.max_fee_bps > self.config.max_call_fee_bps {
            return Err("contract session sponsor fee exceeds configured max".to_string());
        }
        if request.coverage_bps > PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_MAX_BPS {
            return Err("contract session sponsor coverage exceeds max bps".to_string());
        }
        let call = self
            .calls
            .get(&request.call_id)
            .ok_or_else(|| "private contract call not found".to_string())?;
        if call.request.session_id != request.session_id {
            return Err("contract call belongs to another session".to_string());
        }
        if call.status != CallStatus::Authorized {
            return Err("private contract call is not sponsorable".to_string());
        }
        let sequence = self.counters.sponsor_reservations_opened.saturating_add(1);
        let reservation_id = contract_call_sponsor_reservation_id(&request, sequence);
        if self.sponsor_reservations.contains_key(&reservation_id) {
            return Err("contract call sponsor reservation id collision".to_string());
        }
        let record = ContractCallSponsorReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: SponsorReservationStatus::Reserved,
            created_sequence: sequence,
            consumed_by_batch_id: None,
        };
        self.sponsor_reservations
            .insert(reservation_id.clone(), record);
        self.counters.sponsor_reservations_opened = sequence;
        Ok(reservation_id)
    }

    pub fn build_execution_batch(
        &mut self,
        request: BuildContractExecutionBatchRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_batch_capacity()?;
        require_nonempty("scheduler_root", &request.scheduler_root)?;
        require_nonempty("encrypted_witness_root", &request.encrypted_witness_root)?;
        require_nonempty(
            "state_diff_commitment_root",
            &request.state_diff_commitment_root,
        )?;
        require_nonempty(
            "pq_batch_authorization_root",
            &request.pq_batch_authorization_root,
        )?;
        require_unique("contract session batch session ids", &request.session_ids)?;
        require_unique("contract session batch call ids", &request.call_ids)?;
        require_unique(
            "contract session batch reservation ids",
            &request.reservation_ids,
        )?;
        if request.call_ids.is_empty() {
            return Err("contract session execution batch needs calls".to_string());
        }
        if request.batch_privacy_set_size < self.config.batch_privacy_set {
            return Err("contract session batch privacy set is too small".to_string());
        }
        for session_id in &request.session_ids {
            let session = self
                .sessions
                .get(session_id)
                .ok_or_else(|| format!("contract session {session_id} not found"))?;
            if !session.status.accepts_calls() {
                return Err("contract session batch contains inactive session".to_string());
            }
        }
        for call_id in &request.call_ids {
            let call = self
                .calls
                .get(call_id)
                .ok_or_else(|| format!("contract call {call_id} not found"))?;
            if call.status != CallStatus::Authorized {
                return Err("contract session batch contains unauthorized call".to_string());
            }
            if !request.session_ids.contains(&call.request.session_id) {
                return Err("contract session batch missing call session".to_string());
            }
        }
        for reservation_id in &request.reservation_ids {
            let reservation = self
                .sponsor_reservations
                .get(reservation_id)
                .ok_or_else(|| {
                    format!("contract sponsor reservation {reservation_id} not found")
                })?;
            if reservation.status != SponsorReservationStatus::Reserved {
                return Err("contract sponsor reservation is not active".to_string());
            }
            if !request.call_ids.contains(&reservation.request.call_id) {
                return Err("contract sponsor reservation call missing from batch".to_string());
            }
        }
        let sequence = self.counters.execution_batches_built.saturating_add(1);
        let batch_id = contract_execution_batch_id(&request, sequence);
        if self.execution_batches.contains_key(&batch_id) {
            return Err("contract execution batch id collision".to_string());
        }
        for call_id in &request.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = CallStatus::Scheduled;
                call.execution_batch_id = Some(batch_id.clone());
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.sponsor_reservations.get_mut(reservation_id) {
                reservation.status = SponsorReservationStatus::Consumed;
                reservation.consumed_by_batch_id = Some(batch_id.clone());
            }
        }
        let record = ContractExecutionBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: ExecutionBatchStatus::Scheduling,
            created_sequence: sequence,
        };
        self.execution_batches.insert(batch_id.clone(), record);
        self.counters.execution_batches_built = sequence;
        Ok(batch_id)
    }

    pub fn publish_receipt(
        &mut self,
        request: PublishContractSessionReceiptRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("batch_id", &request.batch_id)?;
        require_nonempty("recipient_commitment", &request.recipient_commitment)?;
        require_nonempty("execution_receipt_root", &request.execution_receipt_root)?;
        require_nonempty("pq_receipt_root", &request.pq_receipt_root)?;
        if request.fee_charged_bps > self.config.max_call_fee_bps {
            return Err("contract session receipt fee exceeds configured max".to_string());
        }
        if request.rebate_bps > PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_MAX_BPS {
            return Err("contract session receipt rebate exceeds max bps".to_string());
        }
        let batch = self
            .execution_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "contract execution batch not found".to_string())?;
        batch.status = ExecutionBatchStatus::Executed;
        for call_id in &batch.request.call_ids {
            if let Some(call) = self.calls.get_mut(call_id) {
                call.status = match request.receipt_kind {
                    ReceiptKind::CallReverted => CallStatus::Reverted,
                    _ => CallStatus::Executed,
                };
            }
        }
        for session_id in &batch.request.session_ids {
            if let Some(session) = self.sessions.get_mut(session_id) {
                session.status = SessionStatus::Settled;
            }
        }
        let sequence = self.counters.receipts_published.saturating_add(1);
        let receipt_id = contract_session_receipt_id(&request, sequence);
        if self.receipts.contains_key(&receipt_id) {
            return Err("contract session receipt id collision".to_string());
        }
        let record = ContractSessionReceiptRecord {
            receipt_id: receipt_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.receipts.insert(receipt_id.clone(), record);
        self.counters.receipts_published = sequence;
        Ok(receipt_id)
    }

    pub fn publish_rebate(
        &mut self,
        request: PublishContractSessionRebateRequest,
    ) -> PrivateL2PqContractSessionRuntimeResult<String> {
        self.require_receipt_capacity()?;
        require_nonempty("reservation_id", &request.reservation_id)?;
        require_nonempty("receipt_id", &request.receipt_id)?;
        require_nonempty("sponsor_commitment", &request.sponsor_commitment)?;
        require_nonempty("rebate_note_root", &request.rebate_note_root)?;
        require_nonempty("pq_rebate_root", &request.pq_rebate_root)?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("contract session rebate exceeds runtime target".to_string());
        }
        if !self.receipts.contains_key(&request.receipt_id) {
            return Err("contract session rebate receipt not found".to_string());
        }
        let reservation = self
            .sponsor_reservations
            .get_mut(&request.reservation_id)
            .ok_or_else(|| "contract session sponsor reservation not found".to_string())?;
        reservation.status = SponsorReservationStatus::RebateQueued;
        let sequence = self.counters.rebates_published.saturating_add(1);
        let rebate_id = contract_session_rebate_id(&request, sequence);
        if self.rebates.contains_key(&rebate_id) {
            return Err("contract session rebate id collision".to_string());
        }
        let record = ContractSessionRebateRecord {
            rebate_id: rebate_id.clone(),
            request,
            created_sequence: sequence,
        };
        self.rebates.insert(rebate_id.clone(), record);
        self.counters.rebates_published = sequence;
        Ok(rebate_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: root_from_record(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-CONFIG",
                &self.config.public_record(),
            ),
            counters_root: root_from_record(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-COUNTERS",
                &self.counters.public_record(),
            ),
            policy_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-POLICIES",
                &self
                    .policies
                    .values()
                    .map(ContractSessionPolicyRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            session_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSIONS",
                &self
                    .sessions
                    .values()
                    .map(PrivateContractSessionRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            call_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-CALLS",
                &self
                    .calls
                    .values()
                    .map(PrivateContractCallRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            sponsor_reservation_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-SPONSOR-RESERVATIONS",
                &self
                    .sponsor_reservations
                    .values()
                    .map(ContractCallSponsorReservationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            execution_batch_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-BATCHES",
                &self
                    .execution_batches
                    .values()
                    .map(ContractExecutionBatchRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-RECEIPTS",
                &self
                    .receipts
                    .values()
                    .map(ContractSessionReceiptRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-REBATES",
                &self
                    .rebates
                    .values()
                    .map(ContractSessionRebateRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            nonce_nullifier_root: id_list_root(
                "PRIVATE-L2-PQ-CONTRACT-SESSION-NONCE-NULLIFIERS",
                self.consumed_nonce_nullifiers.iter(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "private_l2_pq_contract_session_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    fn require_policy_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.policies.len() >= self.config.max_policies {
            return Err("contract session policy capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_session_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.sessions.len() >= self.config.max_sessions {
            return Err("contract session capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_call_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.calls.len() >= self.config.max_calls {
            return Err("contract session call capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_reservation_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.sponsor_reservations.len() >= self.config.max_sponsor_reservations {
            return Err("contract session sponsor reservation capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_batch_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.execution_batches.len() >= self.config.max_batches {
            return Err("contract session execution batch capacity exhausted".to_string());
        }
        Ok(())
    }

    fn require_receipt_capacity(&self) -> PrivateL2PqContractSessionRuntimeResult<()> {
        if self.receipts.len() >= self.config.max_receipts {
            return Err("contract session receipt capacity exhausted".to_string());
        }
        Ok(())
    }
}

pub type Runtime = State;

pub fn contract_session_policy_id(
    request: &RegisterContractSessionPolicyRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-POLICY-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn private_contract_session_id(
    request: &OpenPrivateContractSessionRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn private_contract_call_id(
    request: &SubmitPrivateContractCallRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-CALL-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn contract_call_sponsor_reservation_id(
    request: &ReserveContractCallSponsorRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-SPONSOR-RESERVATION-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn contract_execution_batch_id(
    request: &BuildContractExecutionBatchRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-BATCH-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn contract_session_receipt_id(
    request: &PublishContractSessionReceiptRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-RECEIPT-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn contract_session_rebate_id(
    request: &PublishContractSessionRebateRequest,
    sequence: u64,
) -> String {
    payload_id(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-REBATE-ID",
        &json!({ "sequence": sequence, "request": request.public_record() }),
    )
}

pub fn replay_fence_root(session_id: &str, replay_fence_root: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-REPLAY-FENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(replay_fence_root),
        ],
        32,
    )
}

pub fn nullifier_root(kind: &str, nullifier: &str) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CONTRACT-SESSION-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(nullifier),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(record)], 32)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            Value::String(root_from_record(
                domain,
                &json!({
                    "index": index,
                    "record": record,
                }),
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    root_from_record("PRIVATE-L2-PQ-CONTRACT-SESSION-STATE-ROOT", record)
}

fn payload_id(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_L2_PQ_CONTRACT_SESSION_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

fn id_list_root<'a, I>(domain: &str, ids: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let leaves = ids
        .enumerate()
        .map(|(index, id)| {
            Value::String(domain_hash(
                domain,
                &[HashPart::U64(index as u64), HashPart::Str(id)],
                32,
            ))
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn require_nonempty(field: &str, value: &str) -> PrivateL2PqContractSessionRuntimeResult<()> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    Ok(())
}

fn require_unique(field: &str, values: &[String]) -> PrivateL2PqContractSessionRuntimeResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(format!("{field} cannot contain empty ids"));
        }
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate id {value}"));
        }
    }
    Ok(())
}
