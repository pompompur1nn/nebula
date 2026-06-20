use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2AccountAbstractionFeeRouterRuntimeResult<T> = Result<T, String>;

pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-account-abstraction-fee-router-runtime-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PQ_CREDENTIAL_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256s-private-aa-paymaster-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PAYMASTER_SCHEME: &str =
    "private-aa-paymaster-vault-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_USER_OPERATION_SCHEME: &str =
    "shielded-private-user-operation-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RESERVATION_SCHEME: &str =
    "low-fee-aa-route-reservation-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_BATCH_SCHEME: &str =
    "batched-private-aa-fee-route-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RECEIPT_SCHEME: &str =
    "private-aa-low-fee-settlement-receipt-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_REBATE_SCHEME: &str =
    "private-aa-fee-rebate-root-v1";
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEVNET_HEIGHT: u64 = 640_000;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_PAYMASTERS: usize = 262_144;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_OPERATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS: usize =
    4_194_304;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES: usize = 524_288;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS: usize = 1_048_576;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_OPERATIONS: usize =
    16_384;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_OPERATION_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS: u64 =
    24;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    1_024;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS: u64 = 14;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_PAYMASTER_FEE_BPS: u64 = 10;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS: u64 = 6;
pub const PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountActionKind {
    ContractCall,
    TokenTransfer,
    TokenMint,
    TokenBurn,
    DefiSwap,
    LendingAction,
    GovernanceVote,
    MoneroBridgeAction,
    SessionRenewal,
}

impl AccountActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCall => "contract_call",
            Self::TokenTransfer => "token_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::DefiSwap => "defi_swap",
            Self::LendingAction => "lending_action",
            Self::GovernanceVote => "governance_vote",
            Self::MoneroBridgeAction => "monero_bridge_action",
            Self::SessionRenewal => "session_renewal",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterPolicy {
    UniversalLowFee,
    TokenLaunch,
    DefiOnly,
    BridgeOnly,
    GovernanceOnly,
    RecoveryOnly,
}

impl PaymasterPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniversalLowFee => "universal_low_fee",
            Self::TokenLaunch => "token_launch",
            Self::DefiOnly => "defi_only",
            Self::BridgeOnly => "bridge_only",
            Self::GovernanceOnly => "governance_only",
            Self::RecoveryOnly => "recovery_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterStatus {
    Registered,
    Active,
    Exhausted,
    Slashed,
    Retired,
}

impl PaymasterStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Slashed => "slashed",
            Self::Retired => "retired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserOperationStatus {
    Submitted,
    CredentialVerified,
    Reserved,
    Batched,
    Settled,
    Expired,
    Rejected,
}

impl UserOperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::CredentialVerified => "credential_verified",
            Self::Reserved => "reserved",
            Self::Batched => "batched",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorCredentialStatus {
    Pending,
    Verified,
    Consumed,
    Revoked,
}

impl SponsorCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Verified => "verified",
            Self::Consumed => "consumed",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    Reserved,
    Matched,
    Consumed,
    Rebated,
    Expired,
    Cancelled,
}

impl ReservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Matched => "matched",
            Self::Consumed => "consumed",
            Self::Rebated => "rebated",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingBatchStatus {
    Built,
    ProofQueued,
    Settled,
    Rebated,
    Rejected,
}

impl RoutingBatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Built => "built",
            Self::ProofQueued => "proof_queued",
            Self::Settled => "settled",
            Self::Rebated => "rebated",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Pending,
    Accepted,
    Finalized,
    Rebated,
    Disputed,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Finalized => "finalized",
            Self::Rebated => "rebated",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub router_id: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub pq_credential_suite: String,
    pub hash_suite: String,
    pub max_paymasters: usize,
    pub max_operations: usize,
    pub max_reservations: usize,
    pub max_batches: usize,
    pub max_receipts: usize,
    pub max_batch_operations: usize,
    pub operation_ttl_blocks: u64,
    pub reservation_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_user_fee_bps: u64,
    pub max_paymaster_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub current_height: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION
                .to_string(),
            chain_id: CHAIN_ID.to_string(),
            router_id: "devnet-private-aa-fee-router".to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            pq_credential_suite:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PQ_CREDENTIAL_SUITE.to_string(),
            hash_suite: PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_HASH_SUITE.to_string(),
            max_paymasters:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_PAYMASTERS,
            max_operations:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_OPERATIONS,
            max_reservations:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_RESERVATIONS,
            max_batches: PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_BATCHES,
            max_receipts: PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_RECEIPTS,
            max_batch_operations:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_BATCH_OPERATIONS,
            operation_ttl_blocks:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_OPERATION_TTL_BLOCKS,
            reservation_ttl_blocks:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_RESERVATION_TTL_BLOCKS,
            batch_ttl_blocks:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_BATCH_TTL_BLOCKS,
            min_privacy_set_size:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_user_fee_bps:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_USER_FEE_BPS,
            max_paymaster_fee_bps:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MAX_PAYMASTER_FEE_BPS,
            target_rebate_bps:
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_TARGET_REBATE_BPS,
            current_height: PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEVNET_HEIGHT,
        }
    }

    pub fn validate(&self) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require(
            self.protocol_version
                == PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION,
            "unsupported private account abstraction fee router protocol version",
        )?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("router_id", &self.router_id)?;
        require_non_empty("l2_network", &self.l2_network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("pq_credential_suite", &self.pq_credential_suite)?;
        require(self.max_paymasters > 0, "max_paymasters must be positive")?;
        require(self.max_operations > 0, "max_operations must be positive")?;
        require(
            self.max_reservations > 0,
            "max_reservations must be positive",
        )?;
        require(self.max_batches > 0, "max_batches must be positive")?;
        require(self.max_receipts > 0, "max_receipts must be positive")?;
        require(
            self.max_batch_operations > 0,
            "max_batch_operations must be positive",
        )?;
        require(
            self.min_privacy_set_size > 0,
            "min_privacy_set_size must be positive",
        )?;
        require(
            self.batch_privacy_set_size >= self.min_privacy_set_size,
            "batch privacy set must cover per-operation privacy floor",
        )?;
        require(
            self.min_pq_security_bits
                >= PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            "PQ credential security floor is too low",
        )?;
        require_bps("max_user_fee_bps", self.max_user_fee_bps)?;
        require_bps("max_paymaster_fee_bps", self.max_paymaster_fee_bps)?;
        require_bps("target_rebate_bps", self.target_rebate_bps)?;
        require(
            self.target_rebate_bps <= self.max_user_fee_bps,
            "target rebate cannot exceed user fee cap",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "router_id": self.router_id,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "pq_credential_suite": self.pq_credential_suite,
            "hash_suite": self.hash_suite,
            "max_paymasters": self.max_paymasters,
            "max_operations": self.max_operations,
            "max_reservations": self.max_reservations,
            "max_batches": self.max_batches,
            "max_receipts": self.max_receipts,
            "max_batch_operations": self.max_batch_operations,
            "operation_ttl_blocks": self.operation_ttl_blocks,
            "reservation_ttl_blocks": self.reservation_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_user_fee_bps": self.max_user_fee_bps,
            "max_paymaster_fee_bps": self.max_paymaster_fee_bps,
            "target_rebate_bps": self.target_rebate_bps,
            "current_height": self.current_height,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub next_paymaster: u64,
    pub next_operation: u64,
    pub next_reservation: u64,
    pub next_batch: u64,
    pub next_receipt: u64,
    pub next_rebate: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_paymaster": self.next_paymaster,
            "next_operation": self.next_operation,
            "next_reservation": self.next_reservation,
            "next_batch": self.next_batch,
            "next_receipt": self.next_receipt,
            "next_rebate": self.next_rebate,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterPaymasterRequest {
    pub paymaster_commitment: String,
    pub policy: PaymasterPolicy,
    pub funding_asset_id: String,
    pub funding_commitment_root: String,
    pub sponsor_key_root: String,
    pub allowed_action_root: String,
    pub max_fee_bps: u64,
    pub rebate_bps: u64,
    pub pq_security_bits: u16,
    pub metadata_root: String,
}

impl RegisterPaymasterRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require_non_empty("paymaster_commitment", &self.paymaster_commitment)?;
        require_non_empty("funding_asset_id", &self.funding_asset_id)?;
        require_root("funding_commitment_root", &self.funding_commitment_root)?;
        require_root("sponsor_key_root", &self.sponsor_key_root)?;
        require_root("allowed_action_root", &self.allowed_action_root)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_paymaster_fee_bps,
            "paymaster fee exceeds low-fee cap",
        )?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= self.max_fee_bps,
            "rebate cannot exceed paymaster fee",
        )?;
        require(
            self.pq_security_bits >= config.min_pq_security_bits,
            "paymaster PQ credential security is too low",
        )?;
        require_root("metadata_root", &self.metadata_root)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_commitment": self.paymaster_commitment,
            "policy": self.policy.as_str(),
            "funding_asset_id": self.funding_asset_id,
            "funding_commitment_root": self.funding_commitment_root,
            "sponsor_key_root": self.sponsor_key_root,
            "allowed_action_root": self.allowed_action_root,
            "max_fee_bps": self.max_fee_bps,
            "rebate_bps": self.rebate_bps,
            "pq_security_bits": self.pq_security_bits,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitPrivateUserOperationRequest {
    pub action_kind: AccountActionKind,
    pub account_commitment: String,
    pub session_key_root: String,
    pub target_contract_commitment: String,
    pub encrypted_call_root: String,
    pub private_witness_root: String,
    pub nonce_nullifier: String,
    pub fee_asset_id: String,
    pub max_fee_bps: u64,
    pub privacy_set_size: u64,
    pub pq_session_credential_root: String,
    pub expires_at_height: u64,
}

impl SubmitPrivateUserOperationRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_root("session_key_root", &self.session_key_root)?;
        require_non_empty(
            "target_contract_commitment",
            &self.target_contract_commitment,
        )?;
        require_root("encrypted_call_root", &self.encrypted_call_root)?;
        require_root("private_witness_root", &self.private_witness_root)?;
        require_root("nonce_nullifier", &self.nonce_nullifier)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "user operation fee exceeds cap",
        )?;
        require(
            self.privacy_set_size >= config.min_privacy_set_size,
            "user operation privacy set is too small",
        )?;
        require_root(
            "pq_session_credential_root",
            &self.pq_session_credential_root,
        )?;
        require(
            self.expires_at_height > config.current_height,
            "user operation must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "action_kind": self.action_kind.as_str(),
            "account_commitment": self.account_commitment,
            "session_key_root": self.session_key_root,
            "target_contract_commitment": self.target_contract_commitment,
            "encrypted_call_root": self.encrypted_call_root,
            "private_witness_root": self.private_witness_root,
            "nonce_nullifier": self.nonce_nullifier,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_bps": self.max_fee_bps,
            "privacy_set_size": self.privacy_set_size,
            "pq_session_credential_root": self.pq_session_credential_root,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReserveFeeRouteRequest {
    pub operation_id: String,
    pub paymaster_id: String,
    pub credential_root: String,
    pub route_nullifier: String,
    pub reserved_fee_bps: u64,
    pub rebate_bps: u64,
    pub reserved_at_height: u64,
    pub expires_at_height: u64,
}

impl ReserveFeeRouteRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require_non_empty("operation_id", &self.operation_id)?;
        require_non_empty("paymaster_id", &self.paymaster_id)?;
        require_root("credential_root", &self.credential_root)?;
        require_root("route_nullifier", &self.route_nullifier)?;
        require_bps("reserved_fee_bps", self.reserved_fee_bps)?;
        require(
            self.reserved_fee_bps <= config.max_user_fee_bps,
            "reserved fee exceeds cap",
        )?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= self.reserved_fee_bps,
            "rebate cannot exceed reserved fee",
        )?;
        require(
            self.reserved_at_height >= config.current_height,
            "reservation height cannot be behind current height",
        )?;
        require(
            self.expires_at_height > self.reserved_at_height,
            "reservation must expire after creation",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "paymaster_id": self.paymaster_id,
            "credential_root": self.credential_root,
            "route_nullifier": self.route_nullifier,
            "reserved_fee_bps": self.reserved_fee_bps,
            "rebate_bps": self.rebate_bps,
            "reserved_at_height": self.reserved_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildFeeRouteBatchRequest {
    pub operation_ids: Vec<String>,
    pub reservation_ids: Vec<String>,
    pub paymaster_ids: Vec<String>,
    pub operation_root: String,
    pub reservation_root: String,
    pub sponsor_settlement_root: String,
    pub recursive_proof_hint_root: String,
    pub batch_privacy_set_size: u64,
    pub max_fee_bps: u64,
    pub expires_at_height: u64,
}

impl BuildFeeRouteBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require(!self.operation_ids.is_empty(), "batch needs operations")?;
        require(
            self.operation_ids.len() <= config.max_batch_operations,
            "batch contains too many operations",
        )?;
        require_unique("operation_ids", &self.operation_ids)?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_unique("paymaster_ids", &self.paymaster_ids)?;
        require_root("operation_root", &self.operation_root)?;
        require_root("reservation_root", &self.reservation_root)?;
        require_root("sponsor_settlement_root", &self.sponsor_settlement_root)?;
        require_root("recursive_proof_hint_root", &self.recursive_proof_hint_root)?;
        require(
            self.batch_privacy_set_size >= config.batch_privacy_set_size,
            "batch privacy set is too small",
        )?;
        require_bps("max_fee_bps", self.max_fee_bps)?;
        require(
            self.max_fee_bps <= config.max_user_fee_bps,
            "batch fee exceeds cap",
        )?;
        require(
            self.expires_at_height > config.current_height,
            "batch must expire in the future",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "operation_ids": self.operation_ids,
            "reservation_ids": self.reservation_ids,
            "paymaster_ids": self.paymaster_ids,
            "operation_root": self.operation_root,
            "reservation_root": self.reservation_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "recursive_proof_hint_root": self.recursive_proof_hint_root,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "max_fee_bps": self.max_fee_bps,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettleFeeRouteBatchRequest {
    pub batch_id: String,
    pub settled_operation_root: String,
    pub paymaster_debit_root: String,
    pub fee_rebate_root: String,
    pub recursive_proof_root: String,
    pub pq_settlement_signature_root: String,
    pub settled_fee_bps: u64,
    pub settled_at_height: u64,
}

impl SettleFeeRouteBatchRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_root("settled_operation_root", &self.settled_operation_root)?;
        require_root("paymaster_debit_root", &self.paymaster_debit_root)?;
        require_root("fee_rebate_root", &self.fee_rebate_root)?;
        require_root("recursive_proof_root", &self.recursive_proof_root)?;
        require_root(
            "pq_settlement_signature_root",
            &self.pq_settlement_signature_root,
        )?;
        require_bps("settled_fee_bps", self.settled_fee_bps)?;
        require(
            self.settled_fee_bps <= config.max_user_fee_bps,
            "settled fee exceeds cap",
        )?;
        require(
            self.settled_at_height >= config.current_height,
            "settlement height cannot be behind current height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "settled_operation_root": self.settled_operation_root,
            "paymaster_debit_root": self.paymaster_debit_root,
            "fee_rebate_root": self.fee_rebate_root,
            "recursive_proof_root": self.recursive_proof_root,
            "pq_settlement_signature_root": self.pq_settlement_signature_root,
            "settled_fee_bps": self.settled_fee_bps,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishFeeRebateRequest {
    pub receipt_id: String,
    pub reservation_ids: Vec<String>,
    pub rebate_pool_root: String,
    pub rebate_nullifier_root: String,
    pub rebate_bps: u64,
    pub published_at_height: u64,
}

impl PublishFeeRebateRequest {
    pub fn validate(
        &self,
        config: &Config,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require(
            !self.reservation_ids.is_empty(),
            "rebate needs reservations",
        )?;
        require_unique("reservation_ids", &self.reservation_ids)?;
        require_root("rebate_pool_root", &self.rebate_pool_root)?;
        require_root("rebate_nullifier_root", &self.rebate_nullifier_root)?;
        require_bps("rebate_bps", self.rebate_bps)?;
        require(
            self.rebate_bps <= config.max_user_fee_bps,
            "rebate exceeds fee cap",
        )?;
        require(
            self.published_at_height >= config.current_height,
            "rebate publication height cannot be behind current height",
        )?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "reservation_ids": self.reservation_ids,
            "rebate_pool_root": self.rebate_pool_root,
            "rebate_nullifier_root": self.rebate_nullifier_root,
            "rebate_bps": self.rebate_bps,
            "published_at_height": self.published_at_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymasterVaultRecord {
    pub paymaster_id: String,
    pub request: RegisterPaymasterRequest,
    pub status: PaymasterStatus,
    pub credential_status: SponsorCredentialStatus,
    pub registered_at_height: u64,
    pub paymaster_root: String,
}

impl PaymasterVaultRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_id": self.paymaster_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "credential_status": self.credential_status.as_str(),
            "registered_at_height": self.registered_at_height,
            "paymaster_root": self.paymaster_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateUserOperationRecord {
    pub operation_id: String,
    pub request: SubmitPrivateUserOperationRequest,
    pub status: UserOperationStatus,
    pub submitted_at_height: u64,
    pub operation_root: String,
}

impl PrivateUserOperationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "operation_id": self.operation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "submitted_at_height": self.submitted_at_height,
            "operation_root": self.operation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRouteReservationRecord {
    pub reservation_id: String,
    pub request: ReserveFeeRouteRequest,
    pub status: ReservationStatus,
    pub reservation_root: String,
}

impl FeeRouteReservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "reservation_id": self.reservation_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "reservation_root": self.reservation_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRouteBatchRecord {
    pub batch_id: String,
    pub request: BuildFeeRouteBatchRequest,
    pub status: RoutingBatchStatus,
    pub built_at_height: u64,
    pub batch_root: String,
}

impl FeeRouteBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "built_at_height": self.built_at_height,
            "batch_root": self.batch_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRouteSettlementReceipt {
    pub receipt_id: String,
    pub request: SettleFeeRouteBatchRequest,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

impl FeeRouteSettlementReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRouteRebateReceipt {
    pub rebate_id: String,
    pub request: PublishFeeRebateRequest,
    pub status: ReceiptStatus,
    pub rebate_root: String,
}

impl FeeRouteRebateReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "request": self.request.public_record(),
            "status": self.status.as_str(),
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub paymaster_root: String,
    pub operation_root: String,
    pub reservation_root: String,
    pub batch_root: String,
    pub receipt_root: String,
    pub rebate_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "paymaster_root": self.paymaster_root,
            "operation_root": self.operation_root,
            "reservation_root": self.reservation_root,
            "batch_root": self.batch_root,
            "receipt_root": self.receipt_root,
            "rebate_root": self.rebate_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub paymasters: BTreeMap<String, PaymasterVaultRecord>,
    pub operations: BTreeMap<String, PrivateUserOperationRecord>,
    pub reservations: BTreeMap<String, FeeRouteReservationRecord>,
    pub batches: BTreeMap<String, FeeRouteBatchRecord>,
    pub receipts: BTreeMap<String, FeeRouteSettlementReceipt>,
    pub rebates: BTreeMap<String, FeeRouteRebateReceipt>,
}

impl State {
    pub fn devnet() -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<Self> {
        Self::new(Config::devnet())
    }

    pub fn new(config: Config) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            paymasters: BTreeMap::new(),
            operations: BTreeMap::new(),
            reservations: BTreeMap::new(),
            batches: BTreeMap::new(),
            receipts: BTreeMap::new(),
            rebates: BTreeMap::new(),
        })
    }

    pub fn register_paymaster(
        &mut self,
        request: RegisterPaymasterRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<PaymasterVaultRecord> {
        request.validate(&self.config)?;
        require(
            self.paymasters.len() < self.config.max_paymasters,
            "paymaster capacity exhausted",
        )?;
        let sequence = self.counters.next_paymaster;
        self.counters.next_paymaster = self.counters.next_paymaster.saturating_add(1);
        let paymaster_id = paymaster_id(&request, sequence);
        let paymaster_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PAYMASTER_SCHEME,
            &json!({"paymaster_id": paymaster_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = PaymasterVaultRecord {
            paymaster_id: paymaster_id.clone(),
            request,
            status: PaymasterStatus::Active,
            credential_status: SponsorCredentialStatus::Verified,
            registered_at_height: self.config.current_height,
            paymaster_root,
        };
        self.paymasters.insert(paymaster_id, record.clone());
        Ok(record)
    }

    pub fn submit_private_user_operation(
        &mut self,
        request: SubmitPrivateUserOperationRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<PrivateUserOperationRecord> {
        request.validate(&self.config)?;
        require(
            self.operations.len() < self.config.max_operations,
            "user operation capacity exhausted",
        )?;
        let sequence = self.counters.next_operation;
        self.counters.next_operation = self.counters.next_operation.saturating_add(1);
        let operation_id = private_user_operation_id(&request, sequence);
        let operation_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_USER_OPERATION_SCHEME,
            &json!({"operation_id": operation_id, "sequence": sequence, "request": request.public_record()}),
        );
        let record = PrivateUserOperationRecord {
            operation_id: operation_id.clone(),
            request,
            status: UserOperationStatus::CredentialVerified,
            submitted_at_height: self.config.current_height,
            operation_root,
        };
        self.operations.insert(operation_id, record.clone());
        Ok(record)
    }

    pub fn reserve_fee_route(
        &mut self,
        request: ReserveFeeRouteRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<FeeRouteReservationRecord> {
        request.validate(&self.config)?;
        require(
            self.reservations.len() < self.config.max_reservations,
            "fee route reservation capacity exhausted",
        )?;
        require(
            self.operations.contains_key(&request.operation_id),
            "reservation references unknown operation",
        )?;
        require(
            self.paymasters.contains_key(&request.paymaster_id),
            "reservation references unknown paymaster",
        )?;
        let sequence = self.counters.next_reservation;
        self.counters.next_reservation = self.counters.next_reservation.saturating_add(1);
        let reservation_id = fee_route_reservation_id(&request, sequence);
        let reservation_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RESERVATION_SCHEME,
            &json!({"reservation_id": reservation_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(operation) = self.operations.get_mut(&request.operation_id) {
            operation.status = UserOperationStatus::Reserved;
        }
        let record = FeeRouteReservationRecord {
            reservation_id: reservation_id.clone(),
            request,
            status: ReservationStatus::Reserved,
            reservation_root,
        };
        self.reservations.insert(reservation_id, record.clone());
        Ok(record)
    }

    pub fn build_fee_route_batch(
        &mut self,
        request: BuildFeeRouteBatchRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<FeeRouteBatchRecord> {
        request.validate(&self.config)?;
        require(
            self.batches.len() < self.config.max_batches,
            "fee route batch capacity exhausted",
        )?;
        for operation_id in &request.operation_ids {
            require(
                self.operations.contains_key(operation_id),
                "batch references unknown operation",
            )?;
        }
        for reservation_id in &request.reservation_ids {
            require(
                self.reservations.contains_key(reservation_id),
                "batch references unknown reservation",
            )?;
        }
        for paymaster_id in &request.paymaster_ids {
            require(
                self.paymasters.contains_key(paymaster_id),
                "batch references unknown paymaster",
            )?;
        }
        let sequence = self.counters.next_batch;
        self.counters.next_batch = self.counters.next_batch.saturating_add(1);
        let batch_id = fee_route_batch_id(&request, sequence);
        let batch_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_BATCH_SCHEME,
            &json!({"batch_id": batch_id, "sequence": sequence, "request": request.public_record()}),
        );
        for operation_id in &request.operation_ids {
            if let Some(operation) = self.operations.get_mut(operation_id) {
                operation.status = UserOperationStatus::Batched;
            }
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Matched;
            }
        }
        let record = FeeRouteBatchRecord {
            batch_id: batch_id.clone(),
            request,
            status: RoutingBatchStatus::Built,
            built_at_height: self.config.current_height,
            batch_root,
        };
        self.batches.insert(batch_id, record.clone());
        Ok(record)
    }

    pub fn settle_fee_route_batch(
        &mut self,
        request: SettleFeeRouteBatchRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<FeeRouteSettlementReceipt> {
        request.validate(&self.config)?;
        require(
            self.receipts.len() < self.config.max_receipts,
            "fee route receipt capacity exhausted",
        )?;
        let batch = self
            .batches
            .get(&request.batch_id)
            .ok_or_else(|| "settlement references unknown batch".to_string())?;
        let operation_ids = batch.request.operation_ids.clone();
        let reservation_ids = batch.request.reservation_ids.clone();
        let sequence = self.counters.next_receipt;
        self.counters.next_receipt = self.counters.next_receipt.saturating_add(1);
        let receipt_id = fee_route_settlement_receipt_id(&request, sequence);
        let receipt_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RECEIPT_SCHEME,
            &json!({"receipt_id": receipt_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(batch) = self.batches.get_mut(&request.batch_id) {
            batch.status = RoutingBatchStatus::Settled;
        }
        for operation_id in operation_ids {
            if let Some(operation) = self.operations.get_mut(&operation_id) {
                operation.status = UserOperationStatus::Settled;
            }
        }
        for reservation_id in reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(&reservation_id) {
                reservation.status = ReservationStatus::Consumed;
            }
        }
        let record = FeeRouteSettlementReceipt {
            receipt_id: receipt_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            receipt_root,
        };
        self.receipts.insert(receipt_id, record.clone());
        Ok(record)
    }

    pub fn publish_fee_rebate(
        &mut self,
        request: PublishFeeRebateRequest,
    ) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<FeeRouteRebateReceipt> {
        request.validate(&self.config)?;
        require(
            self.rebates.len() < self.config.max_receipts,
            "fee rebate capacity exhausted",
        )?;
        require(
            self.receipts.contains_key(&request.receipt_id),
            "rebate references unknown receipt",
        )?;
        let sequence = self.counters.next_rebate;
        self.counters.next_rebate = self.counters.next_rebate.saturating_add(1);
        let rebate_id = fee_route_rebate_id(&request, sequence);
        let rebate_root = payload_root(
            PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_REBATE_SCHEME,
            &json!({"rebate_id": rebate_id, "sequence": sequence, "request": request.public_record()}),
        );
        if let Some(receipt) = self.receipts.get_mut(&request.receipt_id) {
            receipt.status = ReceiptStatus::Rebated;
        }
        for reservation_id in &request.reservation_ids {
            if let Some(reservation) = self.reservations.get_mut(reservation_id) {
                reservation.status = ReservationStatus::Rebated;
            }
        }
        let record = FeeRouteRebateReceipt {
            rebate_id: rebate_id.clone(),
            request,
            status: ReceiptStatus::Accepted,
            rebate_root,
        };
        self.rebates.insert(rebate_id, record.clone());
        Ok(record)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            paymaster_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PAYMASTER_SCHEME,
                &self
                    .paymasters
                    .values()
                    .map(PaymasterVaultRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            operation_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_USER_OPERATION_SCHEME,
                &self
                    .operations
                    .values()
                    .map(PrivateUserOperationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            reservation_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RESERVATION_SCHEME,
                &self
                    .reservations
                    .values()
                    .map(FeeRouteReservationRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            batch_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_BATCH_SCHEME,
                &self
                    .batches
                    .values()
                    .map(FeeRouteBatchRecord::public_record)
                    .collect::<Vec<_>>(),
            ),
            receipt_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_RECEIPT_SCHEME,
                &self
                    .receipts
                    .values()
                    .map(FeeRouteSettlementReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
            rebate_root: public_record_root(
                PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_REBATE_SCHEME,
                &self
                    .rebates
                    .values()
                    .map(FeeRouteRebateReceipt::public_record)
                    .collect::<Vec<_>>(),
            ),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots().public_record(),
            "paymaster_count": self.paymasters.len(),
            "operation_count": self.operations.len(),
            "reservation_count": self.reservations.len(),
            "batch_count": self.batches.len(),
            "receipt_count": self.receipts.len(),
            "rebate_count": self.rebates.len(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }
}

pub fn paymaster_id(request: &RegisterPaymasterRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-PAYMASTER-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.paymaster_commitment),
            HashPart::Str(request.policy.as_str()),
            HashPart::Str(&request.funding_commitment_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn private_user_operation_id(
    request: &SubmitPrivateUserOperationRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-USER-OPERATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(request.action_kind.as_str()),
            HashPart::Str(&request.account_commitment),
            HashPart::Str(&request.target_contract_commitment),
            HashPart::Str(&request.nonce_nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_route_reservation_id(request: &ReserveFeeRouteRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-RESERVATION-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.operation_id),
            HashPart::Str(&request.paymaster_id),
            HashPart::Str(&request.route_nullifier),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_route_batch_id(request: &BuildFeeRouteBatchRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-BATCH-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(&json!(request.operation_ids)),
            HashPart::Str(&request.operation_root),
            HashPart::Str(&request.reservation_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_route_settlement_receipt_id(
    request: &SettleFeeRouteBatchRequest,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.batch_id),
            HashPart::Str(&request.settled_operation_root),
            HashPart::Str(&request.recursive_proof_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn fee_route_rebate_id(request: &PublishFeeRebateRequest, sequence: u64) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-REBATE-ID",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(&request.receipt_id),
            HashPart::Json(&json!(request.reservation_ids)),
            HashPart::Str(&request.rebate_pool_root),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn root_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-RECORD-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    root_from_record(domain, payload)
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    let leaves = records
        .iter()
        .map(|record| Value::String(root_from_record(domain, record)))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-AA-FEE-ROUTER-STATE-ROOT",
        &[
            HashPart::Str(PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn require(
    condition: bool,
    message: &str,
) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(
    label: &str,
    value: &str,
) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
    require(
        !value.trim().is_empty(),
        &format!("{label} must not be empty"),
    )
}

fn require_root(label: &str, value: &str) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
    require_non_empty(label, value)?;
    require(
        value.len() >= 16,
        &format!("{label} must look like a root/commitment"),
    )
}

fn require_bps(label: &str, value: u64) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
    require(
        value <= PRIVATE_L2_ACCOUNT_ABSTRACTION_FEE_ROUTER_RUNTIME_MAX_BPS,
        &format!("{label} exceeds basis point maximum"),
    )
}

fn require_unique(
    label: &str,
    values: &[String],
) -> PrivateL2AccountAbstractionFeeRouterRuntimeResult<()> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    require(
        unique.len() == values.len(),
        &format!("{label} must be unique"),
    )
}
