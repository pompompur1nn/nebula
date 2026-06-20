use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    crypto_policy::{sign_authorization, verify_authorization, Authorization},
    defi::{build_privacy_proof, PrivacyProof},
    fees::FeeMarketResource,
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID, DEVNET_AUTH_BYTES, DEVNET_PRIVACY_PROOF_BYTES,
};

pub type PrivateContractResult<T> = Result<T, String>;

pub const PRIVATE_CONTRACTS_PROTOCOL_VERSION: &str = "nebula-l2-private-contracts-v1";
pub const PRIVATE_CONTRACTS_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_CONTRACTS_RUNTIME: &str = "deterministic-devnet-private-contract-runtime";
pub const PRIVATE_CONTRACTS_ENCRYPTION_SCHEME: &str = "ML-KEM-768+SHAKE256-slot-seal-devnet";
pub const PRIVATE_CONTRACTS_STATE_COMMITMENT_SCHEME: &str = "SHAKE256-canonical-json-merkle-slots";
pub const PRIVATE_CONTRACTS_EVENT_SCHEME: &str = "encrypted-event-log-v1";
pub const PRIVATE_CONTRACTS_PQ_AUTH_SCHEME: &str = "ML-DSA-65+SLH-DSA-SHAKE-128s-session";
pub const PRIVATE_CONTRACTS_PRECOMPILE_PROOF_SYSTEM: &str =
    "nebula-devnet-private-contract-precompile-v1";
pub const PRIVATE_CONTRACTS_CALL_PROOF_SYSTEM: &str =
    "nebula-devnet-private-contract-call-proof-v1";
pub const PRIVATE_CONTRACTS_TOKEN_TEMPLATE: &str = "private_token_v1";
pub const PRIVATE_CONTRACTS_SWAP_TEMPLATE: &str = "private_swap_pool_v1";
pub const PRIVATE_CONTRACTS_LENDING_TEMPLATE: &str = "private_lending_market_v1";
pub const PRIVATE_CONTRACTS_DEFAULT_FEE_ASSET_ID: &str = "dnr-devnet-fee";
pub const PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_CONTRACTS_DEVNET_USD_ASSET_ID: &str = "usd-private-devnet";
pub const PRIVATE_CONTRACTS_DEFAULT_VIEW_TAG_BITS: u16 = 32;
pub const PRIVATE_CONTRACTS_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_CONTRACTS_DEFAULT_CALL_TTL_BLOCKS: u64 = 16;
pub const PRIVATE_CONTRACTS_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_CONTRACTS_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 75_000;
pub const PRIVATE_CONTRACTS_DEFAULT_MAX_CALL_GAS: u64 = 2_000_000;
pub const PRIVATE_CONTRACTS_DEFAULT_MAX_SLOT_BYTES: u64 = 16 * 1024;
pub const PRIVATE_CONTRACTS_DEFAULT_MAX_EVENT_BYTES: u64 = 32 * 1024;
pub const PRIVATE_CONTRACTS_LOW_FEE_CALL_GAS_CREDIT: u64 = 40_000;
pub const PRIVATE_CONTRACTS_MAX_BPS: u64 = 10_000;
pub const PRIVATE_CONTRACTS_DEFAULT_SWAP_FEE_BPS: u64 = 30;
pub const PRIVATE_CONTRACTS_DEFAULT_LENDING_RESERVE_BPS: u64 = 1_000;
pub const PRIVATE_CONTRACTS_DEFAULT_LIQUIDATION_BONUS_BPS: u64 = 600;
pub const PRIVATE_CONTRACTS_DEFAULT_COLLATERAL_FACTOR_BPS: u64 = 6_500;
pub const PRIVATE_CONTRACTS_STATUS_ACTIVE: &str = "active";
pub const PRIVATE_CONTRACTS_STATUS_PENDING: &str = "pending";
pub const PRIVATE_CONTRACTS_STATUS_EXECUTED: &str = "executed";
pub const PRIVATE_CONTRACTS_STATUS_FAILED: &str = "failed";
pub const PRIVATE_CONTRACTS_STATUS_REVOKED: &str = "revoked";
pub const PRIVATE_CONTRACTS_STATUS_EXPIRED: &str = "expired";
pub const PRIVATE_CONTRACTS_STATUS_PAUSED: &str = "paused";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateContractKind {
    Token,
    SwapPool,
    LendingMarket,
    Paymaster,
    AccessController,
    OracleAdapter,
    Custom(String),
}

impl PrivateContractKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Token => "token".to_string(),
            Self::SwapPool => "swap_pool".to_string(),
            Self::LendingMarket => "lending_market".to_string(),
            Self::Paymaster => "paymaster".to_string(),
            Self::AccessController => "access_controller".to_string(),
            Self::OracleAdapter => "oracle_adapter".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateSlotVisibility {
    PublicCommitment,
    ShieldedCiphertext,
    AuditorDecryptable,
    SequencerSealed,
    EphemeralWitness,
}

impl StateSlotVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PublicCommitment => "public_commitment",
            Self::ShieldedCiphertext => "shielded_ciphertext",
            Self::AuditorDecryptable => "auditor_decryptable",
            Self::SequencerSealed => "sequencer_sealed",
            Self::EphemeralWitness => "ephemeral_witness",
        }
    }

    pub fn publishes_ciphertext(&self) -> bool {
        matches!(
            self,
            Self::ShieldedCiphertext | Self::AuditorDecryptable | Self::SequencerSealed
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEventVisibility {
    CommitmentOnly,
    EncryptedPayload,
    SelectiveDisclosure,
    PublicSummary,
}

impl PrivateEventVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::EncryptedPayload => "encrypted_payload",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::PublicSummary => "public_summary",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateCallStatus {
    Pending,
    Admitted,
    Executed,
    Reverted,
    Proved,
    Sponsored,
    Rejected,
}

impl PrivateCallStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Executed => "executed",
            Self::Reverted => "reverted",
            Self::Proved => "proved",
            Self::Sponsored => "sponsored",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self, Self::Executed | Self::Proved | Self::Sponsored)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateProofKind {
    ShieldedCall,
    SlotTransition,
    EventIntegrity,
    TokenConservation,
    SwapInvariant,
    LendingSolvency,
    AccessControl,
    GasSponsorship,
    Precompile(String),
}

impl PrivateProofKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ShieldedCall => "shielded_call".to_string(),
            Self::SlotTransition => "slot_transition".to_string(),
            Self::EventIntegrity => "event_integrity".to_string(),
            Self::TokenConservation => "token_conservation".to_string(),
            Self::SwapInvariant => "swap_invariant".to_string(),
            Self::LendingSolvency => "lending_solvency".to_string(),
            Self::AccessControl => "access_control".to_string(),
            Self::GasSponsorship => "gas_sponsorship".to_string(),
            Self::Precompile(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ContractAdmin,
    ContractCall,
    SlotRead,
    SlotWrite,
    EmitPrivateEvent,
    ProveExecution,
    SponsorGas,
    TokenMint,
    TokenBurn,
    TokenTransfer,
    SwapExactIn,
    LendingDeposit,
    LendingBorrow,
    LendingRepay,
    LiquidatePosition,
    EmergencyPause,
    Custom(String),
}

impl CapabilityKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::ContractAdmin => "contract_admin".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::SlotRead => "slot_read".to_string(),
            Self::SlotWrite => "slot_write".to_string(),
            Self::EmitPrivateEvent => "emit_private_event".to_string(),
            Self::ProveExecution => "prove_execution".to_string(),
            Self::SponsorGas => "sponsor_gas".to_string(),
            Self::TokenMint => "token_mint".to_string(),
            Self::TokenBurn => "token_burn".to_string(),
            Self::TokenTransfer => "token_transfer".to_string(),
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::LendingDeposit => "lending_deposit".to_string(),
            Self::LendingBorrow => "lending_borrow".to_string(),
            Self::LendingRepay => "lending_repay".to_string(),
            Self::LiquidatePosition => "liquidate_position".to_string(),
            Self::EmergencyPause => "emergency_pause".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorScope {
    AnyPrivateCall,
    Contract,
    Method,
    Asset,
    UserCommitment,
    DevnetLane,
}

impl SponsorScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AnyPrivateCall => "any_private_call",
            Self::Contract => "contract",
            Self::Method => "method",
            Self::Asset => "asset",
            Self::UserCommitment => "user_commitment",
            Self::DevnetLane => "devnet_lane",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwapCurveKind {
    ConstantProduct,
    Stable,
    ConcentratedBand,
    OraclePegged,
}

impl SwapCurveKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConstantProduct => "constant_product",
            Self::Stable => "stable",
            Self::ConcentratedBand => "concentrated_band",
            Self::OraclePegged => "oracle_pegged",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingRateModel {
    Fixed,
    KinkedUtilization,
    OracleDriven,
}

impl LendingRateModel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::KinkedUtilization => "kinked_utilization",
            Self::OracleDriven => "oracle_driven",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LendingPositionKind {
    Supply,
    Borrow,
    Collateral,
    Liquidation,
}

impl LendingPositionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supply => "supply",
            Self::Borrow => "borrow",
            Self::Collateral => "collateral",
            Self::Liquidation => "liquidation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecisionKind {
    Granted,
    DeniedExpired,
    DeniedRevoked,
    DeniedMissingCapability,
    DeniedSelector,
    DeniedSpendLimit,
    DeniedSession,
}

impl AccessDecisionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::DeniedExpired => "denied_expired",
            Self::DeniedRevoked => "denied_revoked",
            Self::DeniedMissingCapability => "denied_missing_capability",
            Self::DeniedSelector => "denied_selector",
            Self::DeniedSpendLimit => "denied_spend_limit",
            Self::DeniedSession => "denied_session",
        }
    }

    pub fn permits(&self) -> bool {
        matches!(self, Self::Granted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractsConfig {
    pub protocol_version: String,
    pub schema_version: u64,
    pub runtime: String,
    pub encryption_scheme: String,
    pub state_commitment_scheme: String,
    pub event_scheme: String,
    pub pq_auth_scheme: String,
    pub default_fee_asset_id: String,
    pub default_view_tag_bits: u16,
    pub default_session_ttl_blocks: u64,
    pub default_call_ttl_blocks: u64,
    pub max_call_gas: u64,
    pub max_slot_bytes: u64,
    pub max_event_bytes: u64,
    pub low_fee_call_gas_credit: u64,
    pub sponsor_epoch_blocks: u64,
    pub sponsor_epoch_budget_units: u64,
}

impl Default for PrivateContractsConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_CONTRACTS_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_CONTRACTS_SCHEMA_VERSION,
            runtime: PRIVATE_CONTRACTS_RUNTIME.to_string(),
            encryption_scheme: PRIVATE_CONTRACTS_ENCRYPTION_SCHEME.to_string(),
            state_commitment_scheme: PRIVATE_CONTRACTS_STATE_COMMITMENT_SCHEME.to_string(),
            event_scheme: PRIVATE_CONTRACTS_EVENT_SCHEME.to_string(),
            pq_auth_scheme: PRIVATE_CONTRACTS_PQ_AUTH_SCHEME.to_string(),
            default_fee_asset_id: PRIVATE_CONTRACTS_DEFAULT_FEE_ASSET_ID.to_string(),
            default_view_tag_bits: PRIVATE_CONTRACTS_DEFAULT_VIEW_TAG_BITS,
            default_session_ttl_blocks: PRIVATE_CONTRACTS_DEFAULT_SESSION_TTL_BLOCKS,
            default_call_ttl_blocks: PRIVATE_CONTRACTS_DEFAULT_CALL_TTL_BLOCKS,
            max_call_gas: PRIVATE_CONTRACTS_DEFAULT_MAX_CALL_GAS,
            max_slot_bytes: PRIVATE_CONTRACTS_DEFAULT_MAX_SLOT_BYTES,
            max_event_bytes: PRIVATE_CONTRACTS_DEFAULT_MAX_EVENT_BYTES,
            low_fee_call_gas_credit: PRIVATE_CONTRACTS_LOW_FEE_CALL_GAS_CREDIT,
            sponsor_epoch_blocks: PRIVATE_CONTRACTS_DEFAULT_SPONSOR_EPOCH_BLOCKS,
            sponsor_epoch_budget_units: PRIVATE_CONTRACTS_DEFAULT_SPONSOR_BUDGET_UNITS,
        }
    }
}

impl PrivateContractsConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contracts_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "runtime": self.runtime,
            "encryption_scheme": self.encryption_scheme,
            "state_commitment_scheme": self.state_commitment_scheme,
            "event_scheme": self.event_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_view_tag_bits": self.default_view_tag_bits,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_call_ttl_blocks": self.default_call_ttl_blocks,
            "max_call_gas": self.max_call_gas,
            "max_slot_bytes": self.max_slot_bytes,
            "max_event_bytes": self.max_event_bytes,
            "low_fee_call_gas_credit": self.low_fee_call_gas_credit,
            "sponsor_epoch_blocks": self.sponsor_epoch_blocks,
            "sponsor_epoch_budget_units": self.sponsor_epoch_budget_units,
        })
    }

    pub fn config_root(&self) -> String {
        private_contract_payload_root("PRIVATE-CONTRACTS-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.protocol_version, "private contracts protocol version")?;
        ensure_non_empty(&self.runtime, "private contracts runtime")?;
        ensure_non_empty(
            &self.encryption_scheme,
            "private contracts encryption scheme",
        )?;
        ensure_non_empty(
            &self.state_commitment_scheme,
            "private contracts state commitment scheme",
        )?;
        ensure_non_empty(&self.event_scheme, "private contracts event scheme")?;
        ensure_non_empty(&self.pq_auth_scheme, "private contracts pq auth scheme")?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "private contracts default fee asset",
        )?;
        ensure_positive(self.schema_version, "private contracts schema version")?;
        ensure_positive(
            self.default_session_ttl_blocks,
            "private contracts session ttl",
        )?;
        ensure_positive(self.default_call_ttl_blocks, "private contracts call ttl")?;
        ensure_positive(self.max_call_gas, "private contracts max call gas")?;
        ensure_positive(self.max_slot_bytes, "private contracts max slot bytes")?;
        ensure_positive(self.max_event_bytes, "private contracts max event bytes")?;
        ensure_positive(self.sponsor_epoch_blocks, "private contracts sponsor epoch")?;
        ensure_positive(
            self.sponsor_epoch_budget_units,
            "private contracts sponsor budget",
        )?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractRoots {
    pub config_root: String,
    pub deployment_root: String,
    pub slot_root: String,
    pub event_root: String,
    pub pq_session_root: String,
    pub session_grant_root: String,
    pub capability_root: String,
    pub access_decision_root: String,
    pub proof_receipt_root: String,
    pub precompile_root: String,
    pub gas_sponsorship_root: String,
    pub call_receipt_root: String,
    pub token_ledger_root: String,
    pub swap_pool_root: String,
    pub lending_market_root: String,
    pub devnet_record_root: String,
}

impl PrivateContractRoots {
    pub fn aggregate_root(&self) -> String {
        private_contract_payload_root("PRIVATE-CONTRACTS-ROOTS-AGGREGATE", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "deployment_root": self.deployment_root,
            "slot_root": self.slot_root,
            "event_root": self.event_root,
            "pq_session_root": self.pq_session_root,
            "session_grant_root": self.session_grant_root,
            "capability_root": self.capability_root,
            "access_decision_root": self.access_decision_root,
            "proof_receipt_root": self.proof_receipt_root,
            "precompile_root": self.precompile_root,
            "gas_sponsorship_root": self.gas_sponsorship_root,
            "call_receipt_root": self.call_receipt_root,
            "token_ledger_root": self.token_ledger_root,
            "swap_pool_root": self.swap_pool_root,
            "lending_market_root": self.lending_market_root,
            "devnet_record_root": self.devnet_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedStateSlot {
    pub slot_id: String,
    pub contract_id: String,
    pub namespace: String,
    pub key_commitment: String,
    pub value_commitment: String,
    pub ciphertext_hash: String,
    pub ciphertext_size_bytes: u64,
    pub recipient_root: String,
    pub disclosure_policy_root: String,
    pub visibility: StateSlotVisibility,
    pub version: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub nonce: u64,
    pub encrypted_payload: Value,
    pub status: String,
}

impl EncryptedStateSlot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        namespace: impl Into<String>,
        logical_key: &str,
        value: &Value,
        recipient_root: impl Into<String>,
        disclosure_policy_root: impl Into<String>,
        visibility: StateSlotVisibility,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let contract_id = contract_id.into();
        let namespace = normalize_label(namespace.into());
        let recipient_root = recipient_root.into();
        let disclosure_policy_root = disclosure_policy_root.into();
        ensure_non_empty(&contract_id, "encrypted slot contract id")?;
        ensure_non_empty(&namespace, "encrypted slot namespace")?;
        ensure_non_empty(logical_key, "encrypted slot logical key")?;
        ensure_non_empty(&recipient_root, "encrypted slot recipient root")?;
        ensure_non_empty(
            &disclosure_policy_root,
            "encrypted slot disclosure policy root",
        )?;
        let key_commitment = private_contract_slot_key_commitment(
            &contract_id,
            &namespace,
            logical_key,
            &recipient_root,
        );
        let encrypted_payload = sealed_payload(
            "state_slot",
            &contract_id,
            &recipient_root,
            value,
            height,
            nonce,
        );
        let value_commitment = private_contract_slot_value_commitment(
            &contract_id,
            &key_commitment,
            value,
            height,
            nonce,
        );
        let ciphertext_hash = private_contract_ciphertext_hash(&encrypted_payload);
        let ciphertext_size_bytes = json_size(&encrypted_payload) as u64;
        let identity = encrypted_state_slot_identity_record(
            &contract_id,
            &namespace,
            &key_commitment,
            &value_commitment,
            &ciphertext_hash,
            &recipient_root,
            &disclosure_policy_root,
            visibility.as_str(),
            1,
            height,
            nonce,
        );
        let slot_id = encrypted_state_slot_id(&identity);
        let slot = Self {
            slot_id,
            contract_id,
            namespace,
            key_commitment,
            value_commitment,
            ciphertext_hash,
            ciphertext_size_bytes,
            recipient_root,
            disclosure_policy_root,
            visibility,
            version: 1,
            created_at_height: height,
            updated_at_height: height,
            nonce,
            encrypted_payload,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        slot.validate()?;
        Ok(slot)
    }

    pub fn update_value(
        &self,
        value: &Value,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        if self.status != PRIVATE_CONTRACTS_STATUS_ACTIVE {
            return Err("cannot update inactive encrypted slot".to_string());
        }
        let encrypted_payload = sealed_payload(
            "state_slot_update",
            &self.contract_id,
            &self.recipient_root,
            value,
            height,
            nonce,
        );
        let value_commitment = private_contract_slot_value_commitment(
            &self.contract_id,
            &self.key_commitment,
            value,
            height,
            nonce,
        );
        let ciphertext_hash = private_contract_ciphertext_hash(&encrypted_payload);
        let identity = encrypted_state_slot_identity_record(
            &self.contract_id,
            &self.namespace,
            &self.key_commitment,
            &value_commitment,
            &ciphertext_hash,
            &self.recipient_root,
            &self.disclosure_policy_root,
            self.visibility.as_str(),
            self.version.saturating_add(1),
            self.created_at_height,
            nonce,
        );
        let mut updated = self.clone();
        updated.value_commitment = value_commitment;
        updated.ciphertext_hash = ciphertext_hash;
        updated.ciphertext_size_bytes = json_size(&encrypted_payload) as u64;
        updated.encrypted_payload = encrypted_payload;
        updated.version = updated.version.saturating_add(1);
        updated.updated_at_height = height;
        updated.nonce = nonce;
        updated.slot_id = encrypted_state_slot_id(&identity);
        updated.validate()?;
        Ok(updated)
    }

    pub fn identity_record(&self) -> Value {
        encrypted_state_slot_identity_record(
            &self.contract_id,
            &self.namespace,
            &self.key_commitment,
            &self.value_commitment,
            &self.ciphertext_hash,
            &self.recipient_root,
            &self.disclosure_policy_root,
            self.visibility.as_str(),
            self.version,
            self.created_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("encrypted slot public record object");
        object.insert("slot_id".to_string(), Value::String(self.slot_id.clone()));
        object.insert(
            "updated_at_height".to_string(),
            Value::from(self.updated_at_height),
        );
        object.insert(
            "ciphertext_size_bytes".to_string(),
            Value::from(self.ciphertext_size_bytes),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        if self.visibility.publishes_ciphertext() {
            object.insert(
                "encrypted_payload".to_string(),
                self.encrypted_payload_public_record(),
            );
        }
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("encrypted slot state record object")
            .insert(
                "encrypted_payload_state".to_string(),
                self.encrypted_payload.clone(),
            );
        record
    }

    pub fn encrypted_payload_public_record(&self) -> Value {
        json!({
            "payload_hash": self.ciphertext_hash,
            "payload_size_bytes": self.ciphertext_size_bytes,
            "recipient_root": self.recipient_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "encryption_scheme": PRIVATE_CONTRACTS_ENCRYPTION_SCHEME,
        })
    }

    pub fn slot_root(&self) -> String {
        encrypted_state_slot_root(self)
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.slot_id, "encrypted slot id")?;
        ensure_non_empty(&self.contract_id, "encrypted slot contract id")?;
        ensure_non_empty(&self.namespace, "encrypted slot namespace")?;
        ensure_non_empty(&self.key_commitment, "encrypted slot key commitment")?;
        ensure_non_empty(&self.value_commitment, "encrypted slot value commitment")?;
        ensure_non_empty(&self.ciphertext_hash, "encrypted slot ciphertext hash")?;
        ensure_non_empty(&self.recipient_root, "encrypted slot recipient root")?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "encrypted slot disclosure policy root",
        )?;
        ensure_positive(self.version, "encrypted slot version")?;
        if self.updated_at_height < self.created_at_height {
            return Err("encrypted slot updated before creation".to_string());
        }
        if self.ciphertext_hash != private_contract_ciphertext_hash(&self.encrypted_payload) {
            return Err("encrypted slot ciphertext hash mismatch".to_string());
        }
        if self.ciphertext_size_bytes != json_size(&self.encrypted_payload) as u64 {
            return Err("encrypted slot ciphertext size mismatch".to_string());
        }
        if self.slot_id != encrypted_state_slot_id(&self.identity_record()) {
            return Err("encrypted slot id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
            ],
            "encrypted slot status",
        )?;
        Ok(self.slot_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateEventLog {
    pub event_id: String,
    pub contract_id: String,
    pub call_id: String,
    pub event_name: String,
    pub event_index: u64,
    pub visibility: PrivateEventVisibility,
    pub payload_commitment: String,
    pub encrypted_payload_hash: String,
    pub public_summary: Value,
    pub disclosure_root: String,
    pub previous_event_root: String,
    pub event_chain_root: String,
    pub emitted_at_height: u64,
    pub nonce: u64,
    pub encrypted_payload: Value,
}

impl PrivateEventLog {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        call_id: impl Into<String>,
        event_name: impl Into<String>,
        event_index: u64,
        visibility: PrivateEventVisibility,
        private_payload: &Value,
        public_summary: Value,
        disclosure_root: impl Into<String>,
        previous_event_root: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let contract_id = contract_id.into();
        let call_id = call_id.into();
        let event_name = normalize_label(event_name.into());
        let disclosure_root = disclosure_root.into();
        let previous_event_root = previous_event_root.into();
        ensure_non_empty(&contract_id, "private event contract id")?;
        ensure_non_empty(&call_id, "private event call id")?;
        ensure_non_empty(&event_name, "private event name")?;
        ensure_non_empty(&disclosure_root, "private event disclosure root")?;
        ensure_non_empty(&previous_event_root, "private event previous root")?;
        let encrypted_payload = sealed_payload(
            "private_event",
            &contract_id,
            &disclosure_root,
            private_payload,
            height,
            nonce,
        );
        let payload_commitment =
            private_contract_payload_root("PRIVATE-EVENT-PAYLOAD", private_payload);
        let encrypted_payload_hash = private_contract_ciphertext_hash(&encrypted_payload);
        let identity = private_event_identity_record(
            &contract_id,
            &call_id,
            &event_name,
            event_index,
            visibility.as_str(),
            &payload_commitment,
            &encrypted_payload_hash,
            &public_summary,
            &disclosure_root,
            &previous_event_root,
            height,
            nonce,
        );
        let event_id = private_event_id(&identity);
        let event_chain_root = private_event_chain_root(&event_id, &previous_event_root, &identity);
        let event = Self {
            event_id,
            contract_id,
            call_id,
            event_name,
            event_index,
            visibility,
            payload_commitment,
            encrypted_payload_hash,
            public_summary,
            disclosure_root,
            previous_event_root,
            event_chain_root,
            emitted_at_height: height,
            nonce,
            encrypted_payload,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn identity_record(&self) -> Value {
        private_event_identity_record(
            &self.contract_id,
            &self.call_id,
            &self.event_name,
            self.event_index,
            self.visibility.as_str(),
            &self.payload_commitment,
            &self.encrypted_payload_hash,
            &self.public_summary,
            &self.disclosure_root,
            &self.previous_event_root,
            self.emitted_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("private event public record object");
        object.insert("event_id".to_string(), Value::String(self.event_id.clone()));
        object.insert(
            "event_chain_root".to_string(),
            Value::String(self.event_chain_root.clone()),
        );
        if matches!(
            self.visibility,
            PrivateEventVisibility::EncryptedPayload | PrivateEventVisibility::SelectiveDisclosure
        ) {
            object.insert(
                "encrypted_payload".to_string(),
                json!({
                    "payload_hash": self.encrypted_payload_hash,
                    "payload_size_bytes": json_size(&self.encrypted_payload) as u64,
                    "event_scheme": PRIVATE_CONTRACTS_EVENT_SCHEME,
                }),
            );
        }
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("private event state record object")
            .insert(
                "encrypted_payload_state".to_string(),
                self.encrypted_payload.clone(),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.event_id, "private event id")?;
        ensure_non_empty(&self.contract_id, "private event contract id")?;
        ensure_non_empty(&self.call_id, "private event call id")?;
        ensure_non_empty(&self.event_name, "private event name")?;
        ensure_non_empty(&self.payload_commitment, "private event payload commitment")?;
        ensure_non_empty(
            &self.encrypted_payload_hash,
            "private event encrypted payload hash",
        )?;
        ensure_non_empty(&self.disclosure_root, "private event disclosure root")?;
        ensure_non_empty(&self.previous_event_root, "private event previous root")?;
        ensure_non_empty(&self.event_chain_root, "private event chain root")?;
        if self.encrypted_payload_hash != private_contract_ciphertext_hash(&self.encrypted_payload)
        {
            return Err("private event ciphertext hash mismatch".to_string());
        }
        if self.event_id != private_event_id(&self.identity_record()) {
            return Err("private event id mismatch".to_string());
        }
        let expected_chain = private_event_chain_root(
            &self.event_id,
            &self.previous_event_root,
            &self.identity_record(),
        );
        if self.event_chain_root != expected_chain {
            return Err("private event chain root mismatch".to_string());
        }
        Ok(private_event_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthorizationSession {
    pub session_id: String,
    pub owner_commitment: String,
    pub delegate_commitment: String,
    pub session_public_key_root: String,
    pub recovery_key_root: String,
    pub context_root: String,
    pub allowed_contract_root: String,
    pub capability_root: String,
    pub replay_domain_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
    pub authorization: Authorization,
}

impl PqAuthorizationSession {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        owner_label: &str,
        delegate_label: &str,
        allowed_contracts: Vec<String>,
        capabilities: Vec<CapabilityKind>,
        context: &Value,
        opened_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        ensure_non_empty(owner_label, "pq session owner label")?;
        ensure_non_empty(delegate_label, "pq session delegate label")?;
        ensure_positive(ttl_blocks, "pq session ttl")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let delegate_commitment = private_contract_account_commitment(delegate_label);
        let session_public_key_root =
            private_contract_session_key_root(delegate_label, opened_at_height, nonce);
        let recovery_key_root = private_contract_recovery_key_root(owner_label, nonce);
        let context_root = private_contract_payload_root("PRIVATE-PQ-SESSION-CONTEXT", context);
        let allowed_contract_root =
            private_contract_string_set_root("PRIVATE-PQ-SESSION-CONTRACT", &allowed_contracts);
        let capability_root = private_contract_capability_kind_root(&capabilities);
        let replay_domain_root = private_contract_replay_domain_root(
            &owner_commitment,
            &delegate_commitment,
            &context_root,
            nonce,
        );
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let identity = pq_authorization_session_identity_record(
            &owner_commitment,
            &delegate_commitment,
            &session_public_key_root,
            &recovery_key_root,
            &context_root,
            &allowed_contract_root,
            &capability_root,
            &replay_domain_root,
            opened_at_height,
            expires_at_height,
            nonce,
        );
        let session_id = pq_authorization_session_id(&identity);
        let unsigned = pq_authorization_session_unsigned_record(&session_id, &identity);
        let authorization =
            sign_authorization(owner_label, "private_contract_pq_session_open", &unsigned);
        let session = Self {
            session_id,
            owner_commitment,
            delegate_commitment,
            session_public_key_root,
            recovery_key_root,
            context_root,
            allowed_contract_root,
            capability_root,
            replay_domain_root,
            opened_at_height,
            expires_at_height,
            nonce,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
            authorization,
        };
        session.validate(owner_label)?;
        Ok(session)
    }

    pub fn identity_record(&self) -> Value {
        pq_authorization_session_identity_record(
            &self.owner_commitment,
            &self.delegate_commitment,
            &self.session_public_key_root,
            &self.recovery_key_root,
            &self.context_root,
            &self.allowed_contract_root,
            &self.capability_root,
            &self.replay_domain_root,
            self.opened_at_height,
            self.expires_at_height,
            self.nonce,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        pq_authorization_session_unsigned_record(&self.session_id, &self.identity_record())
    }

    pub fn public_record(&self) -> Value {
        with_authorization(self.unsigned_record(), &self.authorization, false)
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("pq session state record object")
            .insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_CONTRACTS_STATUS_ACTIVE
            && self.opened_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self, owner_label: &str) -> PrivateContractResult<String> {
        ensure_non_empty(&self.session_id, "pq session id")?;
        ensure_non_empty(&self.owner_commitment, "pq session owner commitment")?;
        ensure_non_empty(&self.delegate_commitment, "pq session delegate commitment")?;
        ensure_non_empty(&self.session_public_key_root, "pq session key root")?;
        ensure_non_empty(&self.recovery_key_root, "pq session recovery key root")?;
        ensure_non_empty(&self.context_root, "pq session context root")?;
        ensure_non_empty(
            &self.allowed_contract_root,
            "pq session allowed contract root",
        )?;
        ensure_non_empty(&self.capability_root, "pq session capability root")?;
        ensure_non_empty(&self.replay_domain_root, "pq session replay domain root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("pq session expires before opening".to_string());
        }
        if self.session_id != pq_authorization_session_id(&self.identity_record()) {
            return Err("pq session id mismatch".to_string());
        }
        if !verify_authorization(
            owner_label,
            "private_contract_pq_session_open",
            &self.unsigned_record(),
            &self.authorization,
        ) {
            return Err("invalid pq session authorization".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
            ],
            "pq session status",
        )?;
        Ok(pq_authorization_session_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCapabilityGrant {
    pub grant_id: String,
    pub session_id: String,
    pub grantee_commitment: String,
    pub contract_id: String,
    pub capability: CapabilityKind,
    pub selector_root: String,
    pub spend_limit_units: u64,
    pub spent_units: u64,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl SessionCapabilityGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: impl Into<String>,
        grantee_label: &str,
        contract_id: impl Into<String>,
        capability: CapabilityKind,
        selectors: Vec<String>,
        spend_limit_units: u64,
        issued_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let session_id = session_id.into();
        let contract_id = contract_id.into();
        ensure_non_empty(&session_id, "session grant session id")?;
        ensure_non_empty(grantee_label, "session grant grantee")?;
        ensure_non_empty(&contract_id, "session grant contract id")?;
        ensure_positive(ttl_blocks, "session grant ttl")?;
        let grantee_commitment = private_contract_account_commitment(grantee_label);
        let selector_root = private_contract_string_set_root("PRIVATE-GRANT-SELECTOR", &selectors);
        let expires_at_height = issued_at_height.saturating_add(ttl_blocks);
        let identity = session_capability_grant_identity_record(
            &session_id,
            &grantee_commitment,
            &contract_id,
            &capability.as_str(),
            &selector_root,
            spend_limit_units,
            issued_at_height,
            expires_at_height,
            nonce,
        );
        let grant_id = session_capability_grant_id(&identity);
        let grant = Self {
            grant_id,
            session_id,
            grantee_commitment,
            contract_id,
            capability,
            selector_root,
            spend_limit_units,
            spent_units: 0,
            issued_at_height,
            expires_at_height,
            nonce,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn identity_record(&self) -> Value {
        session_capability_grant_identity_record(
            &self.session_id,
            &self.grantee_commitment,
            &self.contract_id,
            &self.capability.as_str(),
            &self.selector_root,
            self.spend_limit_units,
            self.issued_at_height,
            self.expires_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "session_capability_grant",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "grant_id": self.grant_id,
            "session_id": self.session_id,
            "grantee_commitment": self.grantee_commitment,
            "contract_id": self.contract_id,
            "capability": self.capability.as_str(),
            "selector_root": self.selector_root,
            "spend_limit_units": self.spend_limit_units,
            "spent_units": self.spent_units,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_CONTRACTS_STATUS_ACTIVE
            && self.issued_at_height <= height
            && height < self.expires_at_height
    }

    pub fn remaining_units(&self) -> u64 {
        self.spend_limit_units.saturating_sub(self.spent_units)
    }

    pub fn charge(&mut self, units: u64) -> PrivateContractResult<()> {
        if self.spend_limit_units > 0 && units > self.remaining_units() {
            return Err("session grant spend limit exceeded".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.grant_id, "session grant id")?;
        ensure_non_empty(&self.session_id, "session grant session id")?;
        ensure_non_empty(&self.grantee_commitment, "session grant grantee")?;
        ensure_non_empty(&self.contract_id, "session grant contract id")?;
        ensure_non_empty(&self.selector_root, "session grant selector root")?;
        if self.expires_at_height <= self.issued_at_height {
            return Err("session grant expires before issue".to_string());
        }
        if self.spent_units > self.spend_limit_units && self.spend_limit_units > 0 {
            return Err("session grant spent units exceed limit".to_string());
        }
        if self.grant_id != session_capability_grant_id(&self.identity_record()) {
            return Err("session grant id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
            ],
            "session grant status",
        )?;
        Ok(session_capability_grant_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessControlCapability {
    pub capability_id: String,
    pub subject_commitment: String,
    pub contract_id: String,
    pub capability: CapabilityKind,
    pub selector_root: String,
    pub allowed_selectors: Vec<String>,
    pub spending_limit_units: u64,
    pub used_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub revocation_root: String,
    pub status: String,
}

impl AccessControlCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_label: &str,
        contract_id: impl Into<String>,
        capability: CapabilityKind,
        allowed_selectors: Vec<String>,
        spending_limit_units: u64,
        created_at_height: u64,
        expires_at_height: u64,
        revocation_scope: &Value,
    ) -> PrivateContractResult<Self> {
        let subject_commitment = private_contract_account_commitment(subject_label);
        let contract_id = contract_id.into();
        ensure_non_empty(subject_label, "capability subject label")?;
        ensure_non_empty(&contract_id, "capability contract id")?;
        if expires_at_height != 0 && expires_at_height <= created_at_height {
            return Err("capability expiry must be after creation".to_string());
        }
        let allowed_selectors = normalize_unique_strings(allowed_selectors);
        let selector_root =
            private_contract_string_set_root("PRIVATE-CAPABILITY-SELECTOR", &allowed_selectors);
        let revocation_root =
            private_contract_payload_root("PRIVATE-CAPABILITY-REVOCATION-SCOPE", revocation_scope);
        let identity = access_control_capability_identity_record(
            &subject_commitment,
            &contract_id,
            &capability.as_str(),
            &selector_root,
            spending_limit_units,
            created_at_height,
            expires_at_height,
            &revocation_root,
        );
        let capability_id = access_control_capability_id(&identity);
        let capability_record = Self {
            capability_id,
            subject_commitment,
            contract_id,
            capability,
            selector_root,
            allowed_selectors,
            spending_limit_units,
            used_units: 0,
            created_at_height,
            expires_at_height,
            revocation_root,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        capability_record.validate()?;
        Ok(capability_record)
    }

    pub fn identity_record(&self) -> Value {
        access_control_capability_identity_record(
            &self.subject_commitment,
            &self.contract_id,
            &self.capability.as_str(),
            &self.selector_root,
            self.spending_limit_units,
            self.created_at_height,
            self.expires_at_height,
            &self.revocation_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "access_control_capability",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "capability_id": self.capability_id,
            "subject_commitment": self.subject_commitment,
            "contract_id": self.contract_id,
            "capability": self.capability.as_str(),
            "selector_root": self.selector_root,
            "allowed_selectors": self.allowed_selectors,
            "spending_limit_units": self.spending_limit_units,
            "used_units": self.used_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "revocation_root": self.revocation_root,
            "status": self.status,
        })
    }

    pub fn permits_selector(&self, selector: &str) -> bool {
        self.allowed_selectors.is_empty()
            || self
                .allowed_selectors
                .iter()
                .any(|allowed| allowed == selector || allowed == "*")
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_CONTRACTS_STATUS_ACTIVE
            && self.created_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn remaining_units(&self) -> u64 {
        if self.spending_limit_units == 0 {
            u64::MAX
        } else {
            self.spending_limit_units.saturating_sub(self.used_units)
        }
    }

    pub fn charge(&mut self, units: u64) -> PrivateContractResult<()> {
        if self.spending_limit_units > 0 && units > self.remaining_units() {
            return Err("capability spending limit exceeded".to_string());
        }
        self.used_units = self.used_units.saturating_add(units);
        Ok(())
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.capability_id, "capability id")?;
        ensure_non_empty(&self.subject_commitment, "capability subject")?;
        ensure_non_empty(&self.contract_id, "capability contract")?;
        ensure_non_empty(&self.selector_root, "capability selector root")?;
        ensure_non_empty(&self.revocation_root, "capability revocation root")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.created_at_height {
            return Err("capability expiry must be after creation".to_string());
        }
        if self.spending_limit_units > 0 && self.used_units > self.spending_limit_units {
            return Err("capability used units exceed spending limit".to_string());
        }
        let expected_selector_root = private_contract_string_set_root(
            "PRIVATE-CAPABILITY-SELECTOR",
            &self.allowed_selectors,
        );
        if self.selector_root != expected_selector_root {
            return Err("capability selector root mismatch".to_string());
        }
        if self.capability_id != access_control_capability_id(&self.identity_record()) {
            return Err("capability id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
            ],
            "capability status",
        )?;
        Ok(access_control_capability_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessDecisionReceipt {
    pub decision_id: String,
    pub capability_id: String,
    pub session_id: String,
    pub subject_commitment: String,
    pub contract_id: String,
    pub selector: String,
    pub requested_units: u64,
    pub decision: AccessDecisionKind,
    pub reason_root: String,
    pub decided_at_height: u64,
}

impl AccessDecisionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: impl Into<String>,
        session_id: impl Into<String>,
        subject_commitment: impl Into<String>,
        contract_id: impl Into<String>,
        selector: impl Into<String>,
        requested_units: u64,
        decision: AccessDecisionKind,
        reason: &Value,
        decided_at_height: u64,
    ) -> PrivateContractResult<Self> {
        let capability_id = capability_id.into();
        let session_id = session_id.into();
        let subject_commitment = subject_commitment.into();
        let contract_id = contract_id.into();
        let selector = selector.into();
        ensure_non_empty(&capability_id, "access decision capability id")?;
        ensure_non_empty(&session_id, "access decision session id")?;
        ensure_non_empty(&subject_commitment, "access decision subject")?;
        ensure_non_empty(&contract_id, "access decision contract")?;
        ensure_non_empty(&selector, "access decision selector")?;
        let reason_root = private_contract_payload_root("PRIVATE-ACCESS-DECISION-REASON", reason);
        let identity = access_decision_identity_record(
            &capability_id,
            &session_id,
            &subject_commitment,
            &contract_id,
            &selector,
            requested_units,
            decision.as_str(),
            &reason_root,
            decided_at_height,
        );
        let decision_id = access_decision_id(&identity);
        let receipt = Self {
            decision_id,
            capability_id,
            session_id,
            subject_commitment,
            contract_id,
            selector,
            requested_units,
            decision,
            reason_root,
            decided_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        access_decision_identity_record(
            &self.capability_id,
            &self.session_id,
            &self.subject_commitment,
            &self.contract_id,
            &self.selector,
            self.requested_units,
            self.decision.as_str(),
            &self.reason_root,
            self.decided_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("access decision public record object")
            .insert(
                "decision_id".to_string(),
                Value::String(self.decision_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.decision_id, "access decision id")?;
        ensure_non_empty(&self.capability_id, "access decision capability id")?;
        ensure_non_empty(&self.session_id, "access decision session id")?;
        ensure_non_empty(&self.subject_commitment, "access decision subject")?;
        ensure_non_empty(&self.contract_id, "access decision contract")?;
        ensure_non_empty(&self.selector, "access decision selector")?;
        ensure_non_empty(&self.reason_root, "access decision reason root")?;
        if self.decision_id != access_decision_id(&self.identity_record()) {
            return Err("access decision id mismatch".to_string());
        }
        Ok(access_decision_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPrecompileProofReceipt {
    pub proof_id: String,
    pub proof_kind: PrivateProofKind,
    pub proof_system: String,
    pub verifier_key_root: String,
    pub public_input_root: String,
    pub private_witness_root: String,
    pub proof_root: String,
    pub precompile_address: String,
    pub gas_used: u64,
    pub produced_at_height: u64,
    pub expires_at_height: u64,
    pub status: String,
}

impl ZkPrecompileProofReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proof_kind: PrivateProofKind,
        proof_system: impl Into<String>,
        verifier_key_root: impl Into<String>,
        public_inputs: &Value,
        private_witness: &Value,
        precompile_address: impl Into<String>,
        gas_used: u64,
        produced_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateContractResult<Self> {
        let proof_system = proof_system.into();
        let verifier_key_root = verifier_key_root.into();
        let precompile_address = normalize_label(precompile_address.into());
        ensure_non_empty(&proof_system, "zk precompile proof system")?;
        ensure_non_empty(&verifier_key_root, "zk precompile verifier key root")?;
        ensure_non_empty(&precompile_address, "zk precompile address")?;
        ensure_positive(gas_used, "zk precompile gas used")?;
        if expires_at_height != 0 && expires_at_height <= produced_at_height {
            return Err("zk precompile receipt expiry must be after production".to_string());
        }
        let public_input_root =
            private_contract_payload_root("PRIVATE-ZK-PUBLIC-INPUTS", public_inputs);
        let private_witness_root =
            private_contract_payload_root("PRIVATE-ZK-PRIVATE-WITNESS", private_witness);
        let proof_root = private_contract_zk_proof_root(
            proof_kind.as_str().as_str(),
            &proof_system,
            &verifier_key_root,
            &public_input_root,
            &private_witness_root,
        );
        let identity = zk_precompile_proof_identity_record(
            proof_kind.as_str().as_str(),
            &proof_system,
            &verifier_key_root,
            &public_input_root,
            &private_witness_root,
            &proof_root,
            &precompile_address,
            gas_used,
            produced_at_height,
            expires_at_height,
        );
        let proof_id = zk_precompile_proof_id(&identity);
        let receipt = Self {
            proof_id,
            proof_kind,
            proof_system,
            verifier_key_root,
            public_input_root,
            private_witness_root,
            proof_root,
            precompile_address,
            gas_used,
            produced_at_height,
            expires_at_height,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        zk_precompile_proof_identity_record(
            self.proof_kind.as_str().as_str(),
            &self.proof_system,
            &self.verifier_key_root,
            &self.public_input_root,
            &self.private_witness_root,
            &self.proof_root,
            &self.precompile_address,
            self.gas_used,
            self.produced_at_height,
            self.expires_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("zk proof receipt public record object");
        object.insert("proof_id".to_string(), Value::String(self.proof_id.clone()));
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn state_record(&self) -> Value {
        self.public_record()
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_CONTRACTS_STATUS_ACTIVE
            && self.produced_at_height <= height
            && (self.expires_at_height == 0 || height < self.expires_at_height)
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.proof_id, "zk precompile proof id")?;
        ensure_non_empty(&self.proof_system, "zk precompile proof system")?;
        ensure_non_empty(&self.verifier_key_root, "zk precompile verifier key")?;
        ensure_non_empty(&self.public_input_root, "zk precompile public inputs")?;
        ensure_non_empty(&self.private_witness_root, "zk precompile private witness")?;
        ensure_non_empty(&self.proof_root, "zk precompile proof root")?;
        ensure_non_empty(&self.precompile_address, "zk precompile address")?;
        ensure_positive(self.gas_used, "zk precompile gas used")?;
        if self.expires_at_height != 0 && self.expires_at_height <= self.produced_at_height {
            return Err("zk precompile receipt expiry must be after production".to_string());
        }
        let expected_root = private_contract_zk_proof_root(
            self.proof_kind.as_str().as_str(),
            &self.proof_system,
            &self.verifier_key_root,
            &self.public_input_root,
            &self.private_witness_root,
        );
        if self.proof_root != expected_root {
            return Err("zk precompile proof root mismatch".to_string());
        }
        if self.proof_id != zk_precompile_proof_id(&self.identity_record()) {
            return Err("zk precompile proof id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_EXECUTED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "zk precompile receipt status",
        )?;
        Ok(zk_precompile_proof_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecompileInvocation {
    pub invocation_id: String,
    pub call_id: String,
    pub precompile_address: String,
    pub proof_receipt_id: String,
    pub input_root: String,
    pub output_root: String,
    pub gas_charged: u64,
    pub invoked_at_height: u64,
    pub status: String,
}

impl PrecompileInvocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: impl Into<String>,
        precompile_address: impl Into<String>,
        proof_receipt_id: impl Into<String>,
        input: &Value,
        output: &Value,
        gas_charged: u64,
        invoked_at_height: u64,
        status: impl Into<String>,
    ) -> PrivateContractResult<Self> {
        let call_id = call_id.into();
        let precompile_address = normalize_label(precompile_address.into());
        let proof_receipt_id = proof_receipt_id.into();
        let status = status.into();
        ensure_non_empty(&call_id, "precompile invocation call id")?;
        ensure_non_empty(&precompile_address, "precompile address")?;
        ensure_non_empty(&proof_receipt_id, "precompile proof receipt")?;
        ensure_non_empty(&status, "precompile status")?;
        ensure_positive(gas_charged, "precompile gas charged")?;
        let input_root = private_contract_payload_root("PRIVATE-PRECOMPILE-INPUT", input);
        let output_root = private_contract_payload_root("PRIVATE-PRECOMPILE-OUTPUT", output);
        let identity = precompile_invocation_identity_record(
            &call_id,
            &precompile_address,
            &proof_receipt_id,
            &input_root,
            &output_root,
            gas_charged,
            invoked_at_height,
            &status,
        );
        let invocation_id = precompile_invocation_id(&identity);
        let invocation = Self {
            invocation_id,
            call_id,
            precompile_address,
            proof_receipt_id,
            input_root,
            output_root,
            gas_charged,
            invoked_at_height,
            status,
        };
        invocation.validate()?;
        Ok(invocation)
    }

    pub fn identity_record(&self) -> Value {
        precompile_invocation_identity_record(
            &self.call_id,
            &self.precompile_address,
            &self.proof_receipt_id,
            &self.input_root,
            &self.output_root,
            self.gas_charged,
            self.invoked_at_height,
            &self.status,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("precompile invocation object")
            .insert(
                "invocation_id".to_string(),
                Value::String(self.invocation_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.invocation_id, "precompile invocation id")?;
        ensure_non_empty(&self.call_id, "precompile invocation call id")?;
        ensure_non_empty(&self.precompile_address, "precompile address")?;
        ensure_non_empty(&self.proof_receipt_id, "precompile proof receipt")?;
        ensure_non_empty(&self.input_root, "precompile input root")?;
        ensure_non_empty(&self.output_root, "precompile output root")?;
        ensure_non_empty(&self.status, "precompile status")?;
        ensure_positive(self.gas_charged, "precompile gas charged")?;
        if self.invocation_id != precompile_invocation_id(&self.identity_record()) {
            return Err("precompile invocation id mismatch".to_string());
        }
        Ok(precompile_invocation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSponsorshipPolicy {
    pub sponsorship_id: String,
    pub sponsor_commitment: String,
    pub scope: SponsorScope,
    pub scope_value: String,
    pub fee_asset_id: String,
    pub epoch_start_height: u64,
    pub epoch_end_height: u64,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_units_per_call: u64,
    pub rebate_bps: u64,
    pub low_fee_lane_root: String,
    pub status: String,
}

impl GasSponsorshipPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_label: &str,
        scope: SponsorScope,
        scope_value: impl Into<String>,
        fee_asset_id: impl Into<String>,
        epoch_start_height: u64,
        epoch_end_height: u64,
        budget_units: u64,
        max_units_per_call: u64,
        rebate_bps: u64,
        low_fee_lanes: Vec<String>,
    ) -> PrivateContractResult<Self> {
        ensure_non_empty(sponsor_label, "gas sponsor label")?;
        let scope_value = scope_value.into();
        let fee_asset_id = fee_asset_id.into();
        ensure_non_empty(&scope_value, "gas sponsorship scope value")?;
        ensure_non_empty(&fee_asset_id, "gas sponsorship fee asset")?;
        ensure_positive(budget_units, "gas sponsorship budget")?;
        ensure_positive(max_units_per_call, "gas sponsorship max units per call")?;
        if epoch_end_height <= epoch_start_height {
            return Err("gas sponsorship epoch end must be after start".to_string());
        }
        if rebate_bps > PRIVATE_CONTRACTS_MAX_BPS {
            return Err("gas sponsorship rebate exceeds max bps".to_string());
        }
        let sponsor_commitment = private_contract_account_commitment(sponsor_label);
        let low_fee_lane_root =
            private_contract_string_set_root("PRIVATE-GAS-LOW-FEE-LANE", &low_fee_lanes);
        let identity = gas_sponsorship_identity_record(
            &sponsor_commitment,
            scope.as_str(),
            &scope_value,
            &fee_asset_id,
            epoch_start_height,
            epoch_end_height,
            budget_units,
            max_units_per_call,
            rebate_bps,
            &low_fee_lane_root,
        );
        let sponsorship_id = gas_sponsorship_id(&identity);
        let policy = Self {
            sponsorship_id,
            sponsor_commitment,
            scope,
            scope_value,
            fee_asset_id,
            epoch_start_height,
            epoch_end_height,
            budget_units,
            spent_units: 0,
            max_units_per_call,
            rebate_bps,
            low_fee_lane_root,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn identity_record(&self) -> Value {
        gas_sponsorship_identity_record(
            &self.sponsor_commitment,
            self.scope.as_str(),
            &self.scope_value,
            &self.fee_asset_id,
            self.epoch_start_height,
            self.epoch_end_height,
            self.budget_units,
            self.max_units_per_call,
            self.rebate_bps,
            &self.low_fee_lane_root,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_sponsorship_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "sponsor_commitment": self.sponsor_commitment,
            "scope": self.scope.as_str(),
            "scope_value": self.scope_value,
            "fee_asset_id": self.fee_asset_id,
            "epoch_start_height": self.epoch_start_height,
            "epoch_end_height": self.epoch_end_height,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "max_units_per_call": self.max_units_per_call,
            "rebate_bps": self.rebate_bps,
            "low_fee_lane_root": self.low_fee_lane_root,
            "status": self.status,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == PRIVATE_CONTRACTS_STATUS_ACTIVE
            && self.epoch_start_height <= height
            && height < self.epoch_end_height
    }

    pub fn remaining_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn matches_call(&self, call: &ShieldedContractCall) -> bool {
        match self.scope {
            SponsorScope::AnyPrivateCall => true,
            SponsorScope::Contract => self.scope_value == call.contract_id,
            SponsorScope::Method => self.scope_value == call.selector,
            SponsorScope::Asset => self.scope_value == call.fee_asset_id,
            SponsorScope::UserCommitment => self.scope_value == call.caller_commitment,
            SponsorScope::DevnetLane => {
                self.scope_value == "private_contracts" || self.scope_value == call.low_fee_lane
            }
        }
    }

    pub fn quote(&self, call: &ShieldedContractCall) -> PrivateContractResult<GasSponsorshipQuote> {
        if !self.matches_call(call) {
            return Err("gas sponsorship does not match call".to_string());
        }
        let eligible_units = call.gas_used.min(self.max_units_per_call);
        let sponsored_units = mul_bps(eligible_units, self.rebate_bps).min(self.remaining_units());
        let quote = GasSponsorshipQuote {
            quote_id: gas_sponsorship_quote_id(
                &self.sponsorship_id,
                &call.call_id,
                sponsored_units,
                self.rebate_bps,
            ),
            sponsorship_id: self.sponsorship_id.clone(),
            call_id: call.call_id.clone(),
            fee_asset_id: self.fee_asset_id.clone(),
            eligible_units,
            sponsored_units,
            user_fee_units: call.fee_units.saturating_sub(sponsored_units),
            sponsor_fee_units: sponsored_units,
            rebate_bps: self.rebate_bps,
        };
        Ok(quote)
    }

    pub fn apply_quote(&mut self, quote: &GasSponsorshipQuote) -> PrivateContractResult<()> {
        if quote.sponsorship_id != self.sponsorship_id {
            return Err("gas quote sponsorship mismatch".to_string());
        }
        if quote.sponsor_fee_units > self.remaining_units() {
            return Err("gas sponsorship budget exhausted".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(quote.sponsor_fee_units);
        Ok(())
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.sponsorship_id, "gas sponsorship id")?;
        ensure_non_empty(&self.sponsor_commitment, "gas sponsor commitment")?;
        ensure_non_empty(&self.scope_value, "gas sponsorship scope value")?;
        ensure_non_empty(&self.fee_asset_id, "gas sponsorship fee asset")?;
        ensure_non_empty(&self.low_fee_lane_root, "gas sponsorship lane root")?;
        ensure_positive(self.budget_units, "gas sponsorship budget")?;
        ensure_positive(
            self.max_units_per_call,
            "gas sponsorship max units per call",
        )?;
        if self.epoch_end_height <= self.epoch_start_height {
            return Err("gas sponsorship epoch end must be after start".to_string());
        }
        if self.spent_units > self.budget_units {
            return Err("gas sponsorship spent units exceed budget".to_string());
        }
        if self.rebate_bps > PRIVATE_CONTRACTS_MAX_BPS {
            return Err("gas sponsorship rebate exceeds max bps".to_string());
        }
        if self.sponsorship_id != gas_sponsorship_id(&self.identity_record()) {
            return Err("gas sponsorship id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_EXPIRED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "gas sponsorship status",
        )?;
        Ok(gas_sponsorship_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasSponsorshipQuote {
    pub quote_id: String,
    pub sponsorship_id: String,
    pub call_id: String,
    pub fee_asset_id: String,
    pub eligible_units: u64,
    pub sponsored_units: u64,
    pub user_fee_units: u64,
    pub sponsor_fee_units: u64,
    pub rebate_bps: u64,
}

impl GasSponsorshipQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "gas_sponsorship_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "sponsorship_id": self.sponsorship_id,
            "call_id": self.call_id,
            "fee_asset_id": self.fee_asset_id,
            "eligible_units": self.eligible_units,
            "sponsored_units": self.sponsored_units,
            "user_fee_units": self.user_fee_units,
            "sponsor_fee_units": self.sponsor_fee_units,
            "rebate_bps": self.rebate_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractTemplate {
    pub template_id: String,
    pub kind: PrivateContractKind,
    pub template_name: String,
    pub version: u64,
    pub code_hash: String,
    pub abi_root: String,
    pub selector_root: String,
    pub required_capability_root: String,
    pub precompile_root: String,
    pub max_gas: u64,
    pub private_state: bool,
    pub status: String,
}

impl PrivateContractTemplate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: PrivateContractKind,
        template_name: impl Into<String>,
        version: u64,
        selectors: Vec<String>,
        required_capabilities: Vec<CapabilityKind>,
        precompiles: Vec<String>,
        max_gas: u64,
        private_state: bool,
    ) -> PrivateContractResult<Self> {
        let template_name = normalize_label(template_name.into());
        ensure_non_empty(&template_name, "private contract template name")?;
        ensure_positive(version, "private contract template version")?;
        ensure_positive(max_gas, "private contract template max gas")?;
        let selectors = normalize_unique_strings(selectors);
        let precompiles = normalize_unique_strings(precompiles);
        let selector_root =
            private_contract_string_set_root("PRIVATE-TEMPLATE-SELECTOR", &selectors);
        let required_capability_root =
            private_contract_capability_kind_root(&required_capabilities);
        let precompile_root =
            private_contract_string_set_root("PRIVATE-TEMPLATE-PRECOMPILE", &precompiles);
        let abi_root = private_contract_payload_root(
            "PRIVATE-TEMPLATE-ABI",
            &json!({
                "template_name": template_name,
                "selectors": selectors,
                "required_capability_root": required_capability_root,
                "precompile_root": precompile_root,
            }),
        );
        let code_hash =
            private_contract_code_hash(kind.as_str().as_str(), &template_name, version, &abi_root);
        let identity = private_contract_template_identity_record(
            kind.as_str().as_str(),
            &template_name,
            version,
            &code_hash,
            &abi_root,
            &selector_root,
            &required_capability_root,
            &precompile_root,
            max_gas,
            private_state,
        );
        let template_id = private_contract_template_id(&identity);
        let template = Self {
            template_id,
            kind,
            template_name,
            version,
            code_hash,
            abi_root,
            selector_root,
            required_capability_root,
            precompile_root,
            max_gas,
            private_state,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        template.validate()?;
        Ok(template)
    }

    pub fn private_token() -> PrivateContractResult<Self> {
        Self::new(
            PrivateContractKind::Token,
            PRIVATE_CONTRACTS_TOKEN_TEMPLATE,
            1,
            vec![
                "mint".to_string(),
                "burn".to_string(),
                "transfer".to_string(),
                "approve".to_string(),
                "freeze".to_string(),
            ],
            vec![
                CapabilityKind::TokenMint,
                CapabilityKind::TokenBurn,
                CapabilityKind::TokenTransfer,
                CapabilityKind::EmitPrivateEvent,
            ],
            vec![
                "verify_token_conservation".to_string(),
                "verify_balance_note".to_string(),
            ],
            1_250_000,
            true,
        )
    }

    pub fn private_swap_pool() -> PrivateContractResult<Self> {
        Self::new(
            PrivateContractKind::SwapPool,
            PRIVATE_CONTRACTS_SWAP_TEMPLATE,
            1,
            vec![
                "quote_exact_in".to_string(),
                "swap_exact_in".to_string(),
                "add_liquidity".to_string(),
                "remove_liquidity".to_string(),
            ],
            vec![
                CapabilityKind::SwapExactIn,
                CapabilityKind::TokenTransfer,
                CapabilityKind::EmitPrivateEvent,
            ],
            vec![
                "verify_swap_invariant".to_string(),
                "verify_lp_share".to_string(),
            ],
            1_600_000,
            true,
        )
    }

    pub fn private_lending_market() -> PrivateContractResult<Self> {
        Self::new(
            PrivateContractKind::LendingMarket,
            PRIVATE_CONTRACTS_LENDING_TEMPLATE,
            1,
            vec![
                "deposit".to_string(),
                "withdraw".to_string(),
                "borrow".to_string(),
                "repay".to_string(),
                "liquidate".to_string(),
            ],
            vec![
                CapabilityKind::LendingDeposit,
                CapabilityKind::LendingBorrow,
                CapabilityKind::LendingRepay,
                CapabilityKind::LiquidatePosition,
                CapabilityKind::EmitPrivateEvent,
            ],
            vec![
                "verify_lending_solvency".to_string(),
                "verify_collateral_factor".to_string(),
            ],
            1_850_000,
            true,
        )
    }

    pub fn identity_record(&self) -> Value {
        private_contract_template_identity_record(
            self.kind.as_str().as_str(),
            &self.template_name,
            self.version,
            &self.code_hash,
            &self.abi_root,
            &self.selector_root,
            &self.required_capability_root,
            &self.precompile_root,
            self.max_gas,
            self.private_state,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("private contract template public record object");
        object.insert(
            "template_id".to_string(),
            Value::String(self.template_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.template_id, "private contract template id")?;
        ensure_non_empty(&self.template_name, "private contract template name")?;
        ensure_non_empty(&self.code_hash, "private contract template code hash")?;
        ensure_non_empty(&self.abi_root, "private contract template abi root")?;
        ensure_non_empty(&self.selector_root, "private contract selector root")?;
        ensure_non_empty(
            &self.required_capability_root,
            "private contract capability root",
        )?;
        ensure_non_empty(&self.precompile_root, "private contract precompile root")?;
        ensure_positive(self.version, "private contract template version")?;
        ensure_positive(self.max_gas, "private contract template max gas")?;
        if self.template_id != private_contract_template_id(&self.identity_record()) {
            return Err("private contract template id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "private contract template status",
        )?;
        Ok(private_contract_template_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractDeployment {
    pub contract_id: String,
    pub template: PrivateContractTemplate,
    pub owner_commitment: String,
    pub admin_capability_root: String,
    pub slot_root: String,
    pub event_root: String,
    pub metadata_root: String,
    pub deployed_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl PrivateContractDeployment {
    pub fn deploy(
        template: PrivateContractTemplate,
        owner_label: &str,
        admin_capabilities: Vec<AccessControlCapability>,
        metadata: &Value,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        template.validate()?;
        ensure_non_empty(owner_label, "private contract owner label")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let admin_capability_root = access_control_capability_root_from_slice(&admin_capabilities);
        let slot_root = encrypted_state_slot_root_from_slice(&[]);
        let event_root = private_event_root_from_slice(&[]);
        let metadata_root = private_contract_payload_root("PRIVATE-CONTRACT-METADATA", metadata);
        let identity = private_contract_deployment_identity_record(
            &template.template_id,
            &template.code_hash,
            &owner_commitment,
            &admin_capability_root,
            &slot_root,
            &event_root,
            &metadata_root,
            height,
            nonce,
        );
        let contract_id = private_contract_deployment_id(&identity);
        let deployment = Self {
            contract_id,
            template,
            owner_commitment,
            admin_capability_root,
            slot_root,
            event_root,
            metadata_root,
            deployed_at_height: height,
            nonce,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        deployment.validate()?;
        Ok(deployment)
    }

    pub fn identity_record(&self) -> Value {
        private_contract_deployment_identity_record(
            &self.template.template_id,
            &self.template.code_hash,
            &self.owner_commitment,
            &self.admin_capability_root,
            &self.slot_root,
            &self.event_root,
            &self.metadata_root,
            self.deployed_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("private deployment public record object");
        object.insert(
            "contract_id".to_string(),
            Value::String(self.contract_id.clone()),
        );
        object.insert("template".to_string(), self.template.public_record());
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn with_roots(mut self, slot_root: String, event_root: String) -> Self {
        self.slot_root = slot_root;
        self.event_root = event_root;
        self.contract_id = private_contract_deployment_id(&self.identity_record());
        self
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        self.template.validate()?;
        ensure_non_empty(&self.contract_id, "private deployment contract id")?;
        ensure_non_empty(
            &self.owner_commitment,
            "private deployment owner commitment",
        )?;
        ensure_non_empty(
            &self.admin_capability_root,
            "private deployment admin capability root",
        )?;
        ensure_non_empty(&self.slot_root, "private deployment slot root")?;
        ensure_non_empty(&self.event_root, "private deployment event root")?;
        ensure_non_empty(&self.metadata_root, "private deployment metadata root")?;
        if self.contract_id != private_contract_deployment_id(&self.identity_record()) {
            return Err("private deployment id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "private deployment status",
        )?;
        Ok(private_contract_deployment_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractCallRequest {
    pub contract_id: String,
    pub selector: String,
    pub args: Value,
    pub caller_label: String,
    pub session_id: String,
    pub capability_id: String,
    pub fee_asset_id: String,
    pub gas_limit: u64,
    pub private_args: bool,
    pub sponsor_hint: Option<String>,
    pub nonce: u64,
}

impl ShieldedContractCallRequest {
    pub fn new(
        contract_id: impl Into<String>,
        selector: impl Into<String>,
        args: Value,
        caller_label: impl Into<String>,
        session_id: impl Into<String>,
        capability_id: impl Into<String>,
        gas_limit: u64,
    ) -> Self {
        Self {
            contract_id: contract_id.into(),
            selector: normalize_label(selector.into()),
            args,
            caller_label: caller_label.into(),
            session_id: session_id.into(),
            capability_id: capability_id.into(),
            fee_asset_id: PRIVATE_CONTRACTS_DEFAULT_FEE_ASSET_ID.to_string(),
            gas_limit,
            private_args: true,
            sponsor_hint: None,
            nonce: 0,
        }
    }

    pub fn fee_asset(mut self, fee_asset_id: impl Into<String>) -> Self {
        self.fee_asset_id = fee_asset_id.into();
        self
    }

    pub fn public_args(mut self) -> Self {
        self.private_args = false;
        self
    }

    pub fn sponsor_hint(mut self, sponsorship_id: impl Into<String>) -> Self {
        self.sponsor_hint = Some(sponsorship_id.into());
        self
    }

    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractCall {
    pub call_id: String,
    pub contract_id: String,
    pub selector: String,
    pub args_commitment: String,
    pub encrypted_args_hash: String,
    pub caller_commitment: String,
    pub session_id: String,
    pub capability_id: String,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub fee_asset_id: String,
    pub fee_units: u64,
    pub low_fee_lane: String,
    pub sponsor_quote_id: String,
    pub private_args: bool,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub encrypted_args: Value,
    pub authorization: Authorization,
    pub privacy_proof: PrivacyProof,
    pub status: PrivateCallStatus,
}

impl ShieldedContractCall {
    pub fn from_request(
        request: ShieldedContractCallRequest,
        height: u64,
        ttl_blocks: u64,
    ) -> PrivateContractResult<Self> {
        ensure_non_empty(&request.contract_id, "shielded call contract id")?;
        ensure_non_empty(&request.selector, "shielded call selector")?;
        ensure_non_empty(&request.caller_label, "shielded call caller label")?;
        ensure_non_empty(&request.session_id, "shielded call session id")?;
        ensure_non_empty(&request.capability_id, "shielded call capability id")?;
        ensure_non_empty(&request.fee_asset_id, "shielded call fee asset")?;
        ensure_positive(request.gas_limit, "shielded call gas limit")?;
        ensure_positive(ttl_blocks, "shielded call ttl")?;
        let caller_commitment = private_contract_account_commitment(&request.caller_label);
        let args_commitment = private_contract_args_commitment(
            &request.contract_id,
            &request.selector,
            &request.args,
            request.private_args,
        );
        let encrypted_args = sealed_payload(
            "shielded_call_args",
            &request.contract_id,
            &caller_commitment,
            &request.args,
            height,
            request.nonce,
        );
        let encrypted_args_hash = private_contract_ciphertext_hash(&encrypted_args);
        let low_fee_lane = private_contract_low_fee_lane(&request.contract_id, &request.selector);
        let gas_used = estimate_private_call_gas(
            &request.selector,
            &request.args,
            request.private_args,
            request.gas_limit,
        )?;
        let fee_units = private_contract_fee_units(gas_used, request.private_args);
        let expires_at_height = height.saturating_add(ttl_blocks);
        let identity = shielded_contract_call_identity_record(
            &request.contract_id,
            &request.selector,
            &args_commitment,
            &encrypted_args_hash,
            &caller_commitment,
            &request.session_id,
            &request.capability_id,
            request.gas_limit,
            gas_used,
            &request.fee_asset_id,
            fee_units,
            &low_fee_lane,
            request.private_args,
            height,
            expires_at_height,
            request.nonce,
        );
        let call_id = shielded_contract_call_id(&identity);
        let (public_inputs, private_witnesses) = shielded_call_proof_context(
            &call_id,
            &request.contract_id,
            &request.selector,
            &args_commitment,
            &encrypted_args_hash,
            &caller_commitment,
            gas_used,
            fee_units,
            &request.args,
            request.private_args,
        );
        let privacy_proof = build_privacy_proof(
            PRIVATE_CONTRACTS_CALL_PROOF_SYSTEM,
            &public_inputs,
            &private_witnesses,
        );
        let unsigned = shielded_contract_call_unsigned_record(&call_id, &identity, &privacy_proof);
        let authorization =
            sign_authorization(&request.caller_label, "private_contract_call", &unsigned);
        let call = Self {
            call_id,
            contract_id: request.contract_id,
            selector: request.selector,
            args_commitment,
            encrypted_args_hash,
            caller_commitment,
            session_id: request.session_id,
            capability_id: request.capability_id,
            gas_limit: request.gas_limit,
            gas_used,
            fee_asset_id: request.fee_asset_id,
            fee_units,
            low_fee_lane,
            sponsor_quote_id: String::new(),
            private_args: request.private_args,
            submitted_at_height: height,
            expires_at_height,
            nonce: request.nonce,
            encrypted_args,
            authorization,
            privacy_proof,
            status: PrivateCallStatus::Pending,
        };
        call.validate()?;
        Ok(call)
    }

    pub fn identity_record(&self) -> Value {
        shielded_contract_call_identity_record(
            &self.contract_id,
            &self.selector,
            &self.args_commitment,
            &self.encrypted_args_hash,
            &self.caller_commitment,
            &self.session_id,
            &self.capability_id,
            self.gas_limit,
            self.gas_used,
            &self.fee_asset_id,
            self.fee_units,
            &self.low_fee_lane,
            self.private_args,
            self.submitted_at_height,
            self.expires_at_height,
            self.nonce,
        )
    }

    pub fn unsigned_record(&self) -> Value {
        shielded_contract_call_unsigned_record(
            &self.call_id,
            &self.identity_record(),
            &self.privacy_proof,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = with_authorization(self.unsigned_record(), &self.authorization, false);
        let object = record
            .as_object_mut()
            .expect("shielded call public record object");
        object.insert(
            "status".to_string(),
            Value::String(self.status.as_str().to_string()),
        );
        object.insert(
            "sponsor_quote_id".to_string(),
            Value::String(self.sponsor_quote_id.clone()),
        );
        if self.private_args {
            object.insert(
                "encrypted_args".to_string(),
                json!({
                    "payload_hash": self.encrypted_args_hash,
                    "payload_size_bytes": json_size(&self.encrypted_args) as u64,
                    "encryption_scheme": PRIVATE_CONTRACTS_ENCRYPTION_SCHEME,
                }),
            );
        }
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("shielded call state object")
            .insert(
                "encrypted_args_state".to_string(),
                self.encrypted_args.clone(),
            );
        record
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.submitted_at_height <= height && height < self.expires_at_height
    }

    pub fn mark_sponsored(&mut self, quote_id: String) {
        self.sponsor_quote_id = quote_id;
        self.status = PrivateCallStatus::Sponsored;
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.call_id, "shielded call id")?;
        ensure_non_empty(&self.contract_id, "shielded call contract id")?;
        ensure_non_empty(&self.selector, "shielded call selector")?;
        ensure_non_empty(&self.args_commitment, "shielded call args commitment")?;
        ensure_non_empty(
            &self.encrypted_args_hash,
            "shielded call encrypted args hash",
        )?;
        ensure_non_empty(&self.caller_commitment, "shielded call caller commitment")?;
        ensure_non_empty(&self.session_id, "shielded call session id")?;
        ensure_non_empty(&self.capability_id, "shielded call capability id")?;
        ensure_non_empty(&self.fee_asset_id, "shielded call fee asset")?;
        ensure_non_empty(&self.low_fee_lane, "shielded call low fee lane")?;
        ensure_positive(self.gas_limit, "shielded call gas limit")?;
        ensure_positive(self.gas_used, "shielded call gas used")?;
        if self.gas_used > self.gas_limit {
            return Err("shielded call gas used exceeds limit".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("shielded call expiry must be after submission".to_string());
        }
        if self.encrypted_args_hash != private_contract_ciphertext_hash(&self.encrypted_args) {
            return Err("shielded call encrypted args hash mismatch".to_string());
        }
        if self.call_id != shielded_contract_call_id(&self.identity_record()) {
            return Err("shielded call id mismatch".to_string());
        }
        if self.privacy_proof.proof_system != PRIVATE_CONTRACTS_CALL_PROOF_SYSTEM {
            return Err("shielded call privacy proof system mismatch".to_string());
        }
        Ok(shielded_contract_call_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedContractExecutionReceipt {
    pub receipt_id: String,
    pub call_id: String,
    pub contract_id: String,
    pub selector: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub slot_write_root: String,
    pub event_root: String,
    pub proof_receipt_root: String,
    pub access_decision_id: String,
    pub gas_used: u64,
    pub fee_units: u64,
    pub sponsored_units: u64,
    pub status: PrivateCallStatus,
    pub executed_at_height: u64,
}

impl ShieldedContractExecutionReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call: &ShieldedContractCall,
        pre_state_root: impl Into<String>,
        post_state_root: impl Into<String>,
        slot_writes: &[EncryptedStateSlot],
        events: &[PrivateEventLog],
        proofs: &[ZkPrecompileProofReceipt],
        access_decision_id: impl Into<String>,
        sponsored_units: u64,
        status: PrivateCallStatus,
        executed_at_height: u64,
    ) -> PrivateContractResult<Self> {
        call.validate()?;
        let pre_state_root = pre_state_root.into();
        let post_state_root = post_state_root.into();
        let access_decision_id = access_decision_id.into();
        ensure_non_empty(&pre_state_root, "execution receipt pre state root")?;
        ensure_non_empty(&post_state_root, "execution receipt post state root")?;
        ensure_non_empty(&access_decision_id, "execution receipt access decision")?;
        let slot_write_root = encrypted_state_slot_root_from_slice(slot_writes);
        let event_root = private_event_root_from_slice(events);
        let proof_receipt_root = zk_precompile_proof_root_from_slice(proofs);
        let identity = shielded_execution_receipt_identity_record(
            &call.call_id,
            &call.contract_id,
            &call.selector,
            &pre_state_root,
            &post_state_root,
            &slot_write_root,
            &event_root,
            &proof_receipt_root,
            &access_decision_id,
            call.gas_used,
            call.fee_units,
            sponsored_units,
            status.as_str(),
            executed_at_height,
        );
        let receipt_id = shielded_execution_receipt_id(&identity);
        let receipt = Self {
            receipt_id,
            call_id: call.call_id.clone(),
            contract_id: call.contract_id.clone(),
            selector: call.selector.clone(),
            pre_state_root,
            post_state_root,
            slot_write_root,
            event_root,
            proof_receipt_root,
            access_decision_id,
            gas_used: call.gas_used,
            fee_units: call.fee_units,
            sponsored_units,
            status,
            executed_at_height,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        shielded_execution_receipt_identity_record(
            &self.call_id,
            &self.contract_id,
            &self.selector,
            &self.pre_state_root,
            &self.post_state_root,
            &self.slot_write_root,
            &self.event_root,
            &self.proof_receipt_root,
            &self.access_decision_id,
            self.gas_used,
            self.fee_units,
            self.sponsored_units,
            self.status.as_str(),
            self.executed_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("execution receipt object")
            .insert(
                "receipt_id".to_string(),
                Value::String(self.receipt_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.receipt_id, "execution receipt id")?;
        ensure_non_empty(&self.call_id, "execution receipt call id")?;
        ensure_non_empty(&self.contract_id, "execution receipt contract id")?;
        ensure_non_empty(&self.selector, "execution receipt selector")?;
        ensure_non_empty(&self.pre_state_root, "execution receipt pre state root")?;
        ensure_non_empty(&self.post_state_root, "execution receipt post state root")?;
        ensure_non_empty(&self.slot_write_root, "execution receipt slot root")?;
        ensure_non_empty(&self.event_root, "execution receipt event root")?;
        ensure_non_empty(&self.proof_receipt_root, "execution receipt proof root")?;
        ensure_non_empty(
            &self.access_decision_id,
            "execution receipt access decision",
        )?;
        ensure_positive(self.gas_used, "execution receipt gas used")?;
        if self.sponsored_units > self.fee_units {
            return Err("execution receipt sponsored units exceed fee".to_string());
        }
        if self.receipt_id != shielded_execution_receipt_id(&self.identity_record()) {
            return Err("execution receipt id mismatch".to_string());
        }
        Ok(shielded_execution_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialBalanceCommitment {
    pub balance_id: String,
    pub owner_commitment: String,
    pub asset_id: String,
    pub amount_commitment: String,
    pub blinding_root: String,
    pub note_root: String,
    pub slot_id: String,
    pub updated_at_height: u64,
    pub nonce: u64,
    pub amount: u64,
}

impl ConfidentialBalanceCommitment {
    pub fn new(
        owner_label: &str,
        asset_id: impl Into<String>,
        amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let asset_id = asset_id.into();
        let slot_id = slot_id.into();
        ensure_non_empty(owner_label, "balance owner label")?;
        ensure_non_empty(&asset_id, "balance asset id")?;
        ensure_non_empty(&slot_id, "balance slot id")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let blinding_root =
            private_contract_amount_blinding(&owner_commitment, &asset_id, amount, nonce);
        let amount_commitment = private_contract_amount_commitment(amount, &blinding_root);
        let note_root = private_contract_balance_note_root(
            &owner_commitment,
            &asset_id,
            &amount_commitment,
            &slot_id,
            height,
            nonce,
        );
        let identity = confidential_balance_identity_record(
            &owner_commitment,
            &asset_id,
            &amount_commitment,
            &blinding_root,
            &note_root,
            &slot_id,
            height,
            nonce,
        );
        let balance_id = confidential_balance_id(&identity);
        let balance = Self {
            balance_id,
            owner_commitment,
            asset_id,
            amount_commitment,
            blinding_root,
            note_root,
            slot_id,
            updated_at_height: height,
            nonce,
            amount,
        };
        balance.validate()?;
        Ok(balance)
    }

    pub fn reblind(
        &self,
        amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let slot_id = slot_id.into();
        ensure_non_empty(&slot_id, "balance slot id")?;
        let blinding_root =
            private_contract_amount_blinding(&self.owner_commitment, &self.asset_id, amount, nonce);
        let amount_commitment = private_contract_amount_commitment(amount, &blinding_root);
        let note_root = private_contract_balance_note_root(
            &self.owner_commitment,
            &self.asset_id,
            &amount_commitment,
            &slot_id,
            height,
            nonce,
        );
        let identity = confidential_balance_identity_record(
            &self.owner_commitment,
            &self.asset_id,
            &amount_commitment,
            &blinding_root,
            &note_root,
            &slot_id,
            height,
            nonce,
        );
        let balance_id = confidential_balance_id(&identity);
        let balance = Self {
            balance_id,
            owner_commitment: self.owner_commitment.clone(),
            asset_id: self.asset_id.clone(),
            amount_commitment,
            blinding_root,
            note_root,
            slot_id,
            updated_at_height: height,
            nonce,
            amount,
        };
        balance.validate()?;
        Ok(balance)
    }

    pub fn identity_record(&self) -> Value {
        confidential_balance_identity_record(
            &self.owner_commitment,
            &self.asset_id,
            &self.amount_commitment,
            &self.blinding_root,
            &self.note_root,
            &self.slot_id,
            self.updated_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("balance record object")
            .insert(
                "balance_id".to_string(),
                Value::String(self.balance_id.clone()),
            );
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        record
            .as_object_mut()
            .expect("balance state object")
            .insert("amount".to_string(), Value::from(self.amount));
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.balance_id, "balance id")?;
        ensure_non_empty(&self.owner_commitment, "balance owner commitment")?;
        ensure_non_empty(&self.asset_id, "balance asset id")?;
        ensure_non_empty(&self.amount_commitment, "balance amount commitment")?;
        ensure_non_empty(&self.blinding_root, "balance blinding root")?;
        ensure_non_empty(&self.note_root, "balance note root")?;
        ensure_non_empty(&self.slot_id, "balance slot id")?;
        let expected_amount = private_contract_amount_commitment(self.amount, &self.blinding_root);
        if self.amount_commitment != expected_amount {
            return Err("balance amount commitment mismatch".to_string());
        }
        if self.balance_id != confidential_balance_id(&self.identity_record()) {
            return Err("balance id mismatch".to_string());
        }
        Ok(confidential_balance_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenLedger {
    pub token_id: String,
    pub contract_id: String,
    pub asset_id: String,
    pub symbol: String,
    pub decimals: u8,
    pub issuer_commitment: String,
    pub supply_commitment: String,
    pub supply_blinding_root: String,
    pub total_supply: u64,
    pub balance_root: String,
    pub allowance_root: String,
    pub transfer_policy_root: String,
    pub status: String,
    pub balances: BTreeMap<String, ConfidentialBalanceCommitment>,
}

impl PrivateTokenLedger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        asset_id: impl Into<String>,
        symbol: impl Into<String>,
        decimals: u8,
        issuer_label: &str,
        transfer_policy: &Value,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let contract_id = contract_id.into();
        let asset_id = asset_id.into();
        let symbol = normalize_symbol(symbol.into());
        ensure_non_empty(&contract_id, "private token contract id")?;
        ensure_non_empty(&asset_id, "private token asset id")?;
        ensure_non_empty(&symbol, "private token symbol")?;
        ensure_non_empty(issuer_label, "private token issuer")?;
        let issuer_commitment = private_contract_account_commitment(issuer_label);
        let supply_blinding_root =
            private_contract_amount_blinding(&issuer_commitment, &asset_id, 0, nonce);
        let supply_commitment = private_contract_amount_commitment(0, &supply_blinding_root);
        let transfer_policy_root =
            private_contract_payload_root("PRIVATE-TOKEN-TRANSFER-POLICY", transfer_policy);
        let balance_root = confidential_balance_root_from_slice(&[]);
        let allowance_root = private_contract_empty_root("PRIVATE-TOKEN-ALLOWANCE");
        let identity = private_token_ledger_identity_record(
            &contract_id,
            &asset_id,
            &symbol,
            decimals,
            &issuer_commitment,
            &supply_commitment,
            &supply_blinding_root,
            &balance_root,
            &allowance_root,
            &transfer_policy_root,
            height,
        );
        let token_id = private_token_ledger_id(&identity);
        let ledger = Self {
            token_id,
            contract_id,
            asset_id,
            symbol,
            decimals,
            issuer_commitment,
            supply_commitment,
            supply_blinding_root,
            total_supply: 0,
            balance_root,
            allowance_root,
            transfer_policy_root,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
            balances: BTreeMap::new(),
        };
        ledger.validate()?;
        Ok(ledger)
    }

    pub fn identity_record(&self) -> Value {
        private_token_ledger_identity_record(
            &self.contract_id,
            &self.asset_id,
            &self.symbol,
            self.decimals,
            &self.issuer_commitment,
            &self.supply_commitment,
            &self.supply_blinding_root,
            &self.balance_root,
            &self.allowance_root,
            &self.transfer_policy_root,
            0,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_ledger",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "token_id": self.token_id,
            "contract_id": self.contract_id,
            "asset_id": self.asset_id,
            "symbol": self.symbol,
            "decimals": self.decimals,
            "issuer_commitment": self.issuer_commitment,
            "supply_commitment": self.supply_commitment,
            "supply_blinding_root": self.supply_blinding_root,
            "balance_root": self.balance_root,
            "allowance_root": self.allowance_root,
            "transfer_policy_root": self.transfer_policy_root,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record.as_object_mut().expect("token state object");
        object.insert("total_supply".to_string(), Value::from(self.total_supply));
        object.insert(
            "balances".to_string(),
            Value::Array(
                self.balances
                    .values()
                    .map(ConfidentialBalanceCommitment::state_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn balance_for_owner(&self, owner_commitment: &str) -> u64 {
        self.balances
            .get(owner_commitment)
            .map(|balance| balance.amount)
            .unwrap_or(0)
    }

    pub fn refresh_roots(&mut self, nonce: u64) {
        let balances = self.balances.values().cloned().collect::<Vec<_>>();
        self.balance_root = confidential_balance_root_from_slice(&balances);
        self.supply_blinding_root = private_contract_amount_blinding(
            &self.issuer_commitment,
            &self.asset_id,
            self.total_supply,
            nonce,
        );
        self.supply_commitment =
            private_contract_amount_commitment(self.total_supply, &self.supply_blinding_root);
    }

    pub fn mint(
        &mut self,
        recipient_label: &str,
        amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateTokenOperationReceipt> {
        ensure_positive(amount, "private token mint amount")?;
        let owner_commitment = private_contract_account_commitment(recipient_label);
        let current = self.balance_for_owner(&owner_commitment);
        let slot_id = slot_id.into();
        let balance = if let Some(balance) = self.balances.get(&owner_commitment) {
            balance.reblind(current.saturating_add(amount), slot_id, height, nonce)?
        } else {
            ConfidentialBalanceCommitment::new(
                recipient_label,
                self.asset_id.clone(),
                amount,
                slot_id,
                height,
                nonce,
            )?
        };
        self.balances.insert(owner_commitment.clone(), balance);
        self.total_supply = self.total_supply.saturating_add(amount);
        self.refresh_roots(nonce);
        let receipt = PrivateTokenOperationReceipt::new(
            &self.contract_id,
            &self.asset_id,
            "mint",
            &owner_commitment,
            amount,
            self.total_supply,
            &self.balance_root,
            height,
            nonce,
        )?;
        Ok(receipt)
    }

    pub fn burn(
        &mut self,
        owner_label: &str,
        amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateTokenOperationReceipt> {
        ensure_positive(amount, "private token burn amount")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let current = self.balance_for_owner(&owner_commitment);
        if current < amount {
            return Err("private token burn exceeds balance".to_string());
        }
        let slot_id = slot_id.into();
        let balance = self
            .balances
            .get(&owner_commitment)
            .ok_or_else(|| "private token burn missing balance".to_string())?
            .reblind(current - amount, slot_id, height, nonce)?;
        self.balances.insert(owner_commitment.clone(), balance);
        self.total_supply = self.total_supply.saturating_sub(amount);
        self.refresh_roots(nonce);
        PrivateTokenOperationReceipt::new(
            &self.contract_id,
            &self.asset_id,
            "burn",
            &owner_commitment,
            amount,
            self.total_supply,
            &self.balance_root,
            height,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn transfer(
        &mut self,
        sender_label: &str,
        recipient_label: &str,
        amount: u64,
        sender_slot_id: impl Into<String>,
        recipient_slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateTokenOperationReceipt> {
        ensure_positive(amount, "private token transfer amount")?;
        let sender_commitment = private_contract_account_commitment(sender_label);
        let recipient_commitment = private_contract_account_commitment(recipient_label);
        if sender_commitment == recipient_commitment {
            return Err("private token transfer requires distinct parties".to_string());
        }
        let sender_current = self.balance_for_owner(&sender_commitment);
        if sender_current < amount {
            return Err("private token transfer exceeds balance".to_string());
        }
        let recipient_current = self.balance_for_owner(&recipient_commitment);
        let sender_slot_id = sender_slot_id.into();
        let recipient_slot_id = recipient_slot_id.into();
        let sender_balance = self
            .balances
            .get(&sender_commitment)
            .ok_or_else(|| "private token sender balance missing".to_string())?
            .reblind(sender_current - amount, sender_slot_id, height, nonce)?;
        let recipient_balance = if let Some(balance) = self.balances.get(&recipient_commitment) {
            balance.reblind(
                recipient_current.saturating_add(amount),
                recipient_slot_id,
                height,
                nonce.saturating_add(1),
            )?
        } else {
            ConfidentialBalanceCommitment::new(
                recipient_label,
                self.asset_id.clone(),
                amount,
                recipient_slot_id,
                height,
                nonce.saturating_add(1),
            )?
        };
        self.balances
            .insert(sender_commitment.clone(), sender_balance);
        self.balances
            .insert(recipient_commitment.clone(), recipient_balance);
        self.refresh_roots(nonce);
        PrivateTokenOperationReceipt::new(
            &self.contract_id,
            &self.asset_id,
            "transfer",
            &recipient_commitment,
            amount,
            self.total_supply,
            &self.balance_root,
            height,
            nonce,
        )
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.token_id, "private token id")?;
        ensure_non_empty(&self.contract_id, "private token contract id")?;
        ensure_non_empty(&self.asset_id, "private token asset id")?;
        ensure_non_empty(&self.symbol, "private token symbol")?;
        ensure_non_empty(&self.issuer_commitment, "private token issuer")?;
        ensure_non_empty(&self.supply_commitment, "private token supply commitment")?;
        ensure_non_empty(&self.supply_blinding_root, "private token supply blinding")?;
        ensure_non_empty(&self.balance_root, "private token balance root")?;
        ensure_non_empty(&self.allowance_root, "private token allowance root")?;
        ensure_non_empty(&self.transfer_policy_root, "private token transfer policy")?;
        let balance_sum = self
            .balances
            .values()
            .map(|balance| balance.amount)
            .fold(0_u64, u64::saturating_add);
        if balance_sum != self.total_supply {
            return Err("private token balance sum does not equal supply".to_string());
        }
        let expected_balance_root = confidential_balance_root_from_slice(
            &self.balances.values().cloned().collect::<Vec<_>>(),
        );
        if self.balance_root != expected_balance_root {
            return Err("private token balance root mismatch".to_string());
        }
        for balance in self.balances.values() {
            balance.validate()?;
            if balance.asset_id != self.asset_id {
                return Err("private token balance asset mismatch".to_string());
            }
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "private token status",
        )?;
        Ok(private_token_ledger_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenOperationReceipt {
    pub operation_id: String,
    pub contract_id: String,
    pub asset_id: String,
    pub operation: String,
    pub party_commitment: String,
    pub amount_commitment: String,
    pub supply_commitment: String,
    pub balance_root: String,
    pub operated_at_height: u64,
    pub nonce: u64,
}

impl PrivateTokenOperationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: &str,
        asset_id: &str,
        operation: &str,
        party_commitment: &str,
        amount: u64,
        total_supply: u64,
        balance_root: &str,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        ensure_non_empty(contract_id, "token receipt contract id")?;
        ensure_non_empty(asset_id, "token receipt asset id")?;
        ensure_non_empty(operation, "token receipt operation")?;
        ensure_non_empty(party_commitment, "token receipt party")?;
        ensure_non_empty(balance_root, "token receipt balance root")?;
        let amount_blinding =
            private_contract_amount_blinding(party_commitment, asset_id, amount, nonce);
        let amount_commitment = private_contract_amount_commitment(amount, &amount_blinding);
        let supply_blinding =
            private_contract_amount_blinding(contract_id, asset_id, total_supply, nonce);
        let supply_commitment = private_contract_amount_commitment(total_supply, &supply_blinding);
        let identity = private_token_operation_identity_record(
            contract_id,
            asset_id,
            operation,
            party_commitment,
            &amount_commitment,
            &supply_commitment,
            balance_root,
            height,
            nonce,
        );
        let operation_id = private_token_operation_id(&identity);
        let receipt = Self {
            operation_id,
            contract_id: contract_id.to_string(),
            asset_id: asset_id.to_string(),
            operation: operation.to_string(),
            party_commitment: party_commitment.to_string(),
            amount_commitment,
            supply_commitment,
            balance_root: balance_root.to_string(),
            operated_at_height: height,
            nonce,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        private_token_operation_identity_record(
            &self.contract_id,
            &self.asset_id,
            &self.operation,
            &self.party_commitment,
            &self.amount_commitment,
            &self.supply_commitment,
            &self.balance_root,
            self.operated_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("token op receipt object")
            .insert(
                "operation_id".to_string(),
                Value::String(self.operation_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.operation_id, "token operation id")?;
        ensure_non_empty(&self.contract_id, "token operation contract")?;
        ensure_non_empty(&self.asset_id, "token operation asset")?;
        ensure_non_empty(&self.operation, "token operation")?;
        ensure_non_empty(&self.party_commitment, "token operation party")?;
        ensure_non_empty(&self.amount_commitment, "token operation amount")?;
        ensure_non_empty(&self.supply_commitment, "token operation supply")?;
        ensure_non_empty(&self.balance_root, "token operation balance root")?;
        if self.operation_id != private_token_operation_id(&self.identity_record()) {
            return Err("token operation id mismatch".to_string());
        }
        Ok(private_token_operation_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSwapPool {
    pub pool_id: String,
    pub contract_id: String,
    pub asset_a: String,
    pub asset_b: String,
    pub lp_asset_id: String,
    pub curve: SwapCurveKind,
    pub fee_bps: u64,
    pub reserve_a: u64,
    pub reserve_b: u64,
    pub reserve_a_commitment: String,
    pub reserve_b_commitment: String,
    pub invariant_commitment: String,
    pub lp_supply_commitment: String,
    pub lp_supply: u64,
    pub oracle_root: String,
    pub status: String,
}

impl PrivateSwapPool {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        asset_a: impl Into<String>,
        asset_b: impl Into<String>,
        lp_asset_id: impl Into<String>,
        curve: SwapCurveKind,
        fee_bps: u64,
        reserve_a: u64,
        reserve_b: u64,
        oracle: &Value,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let contract_id = contract_id.into();
        let asset_a = asset_a.into();
        let asset_b = asset_b.into();
        let lp_asset_id = lp_asset_id.into();
        ensure_non_empty(&contract_id, "swap contract id")?;
        ensure_non_empty(&asset_a, "swap asset a")?;
        ensure_non_empty(&asset_b, "swap asset b")?;
        ensure_non_empty(&lp_asset_id, "swap lp asset")?;
        if asset_a == asset_b {
            return Err("swap pool requires distinct assets".to_string());
        }
        if fee_bps > PRIVATE_CONTRACTS_MAX_BPS {
            return Err("swap fee exceeds max bps".to_string());
        }
        ensure_positive(reserve_a, "swap reserve a")?;
        ensure_positive(reserve_b, "swap reserve b")?;
        let oracle_root = private_contract_payload_root("PRIVATE-SWAP-ORACLE", oracle);
        let reserve_a_commitment = private_contract_amount_commitment(
            reserve_a,
            &private_contract_amount_blinding(&contract_id, &asset_a, reserve_a, nonce),
        );
        let reserve_b_commitment = private_contract_amount_commitment(
            reserve_b,
            &private_contract_amount_blinding(&contract_id, &asset_b, reserve_b, nonce),
        );
        let invariant = swap_invariant(reserve_a, reserve_b, &curve);
        let invariant_commitment = private_contract_amount_commitment(
            invariant,
            &private_contract_amount_blinding(&contract_id, "swap_invariant", invariant, nonce),
        );
        let lp_supply = integer_sqrt(reserve_a.saturating_mul(reserve_b));
        let lp_supply_commitment = private_contract_amount_commitment(
            lp_supply,
            &private_contract_amount_blinding(&contract_id, &lp_asset_id, lp_supply, nonce),
        );
        let identity = private_swap_pool_identity_record(
            &contract_id,
            &asset_a,
            &asset_b,
            &lp_asset_id,
            curve.as_str(),
            fee_bps,
            &reserve_a_commitment,
            &reserve_b_commitment,
            &invariant_commitment,
            &lp_supply_commitment,
            &oracle_root,
        );
        let pool_id = private_swap_pool_id(&identity);
        let pool = Self {
            pool_id,
            contract_id,
            asset_a,
            asset_b,
            lp_asset_id,
            curve,
            fee_bps,
            reserve_a,
            reserve_b,
            reserve_a_commitment,
            reserve_b_commitment,
            invariant_commitment,
            lp_supply_commitment,
            lp_supply,
            oracle_root,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        pool.validate()?;
        Ok(pool)
    }

    pub fn quote_exact_in(
        &self,
        input_asset: &str,
        amount_in: u64,
    ) -> PrivateContractResult<PrivateSwapQuote> {
        ensure_positive(amount_in, "swap amount in")?;
        if input_asset != self.asset_a && input_asset != self.asset_b {
            return Err("swap quote input asset is not in pool".to_string());
        }
        let input_is_a = input_asset == self.asset_a;
        let (reserve_in, reserve_out, output_asset) = if input_is_a {
            (self.reserve_a, self.reserve_b, self.asset_b.clone())
        } else {
            (self.reserve_b, self.reserve_a, self.asset_a.clone())
        };
        let fee_units = mul_bps(amount_in, self.fee_bps);
        let amount_after_fee = amount_in.saturating_sub(fee_units);
        let amount_out = match self.curve {
            SwapCurveKind::ConstantProduct | SwapCurveKind::ConcentratedBand => {
                constant_product_amount_out(reserve_in, reserve_out, amount_after_fee)
            }
            SwapCurveKind::Stable | SwapCurveKind::OraclePegged => {
                stable_amount_out(reserve_in, reserve_out, amount_after_fee, self.fee_bps)
            }
        };
        if amount_out == 0 || amount_out >= reserve_out {
            return Err("swap quote has insufficient output liquidity".to_string());
        }
        let price_impact_bps = ratio_bps(amount_out, reserve_out).min(PRIVATE_CONTRACTS_MAX_BPS);
        let quote_id = private_swap_quote_id(
            &self.pool_id,
            input_asset,
            &output_asset,
            amount_in,
            amount_out,
            fee_units,
        );
        Ok(PrivateSwapQuote {
            quote_id,
            pool_id: self.pool_id.clone(),
            input_asset: input_asset.to_string(),
            output_asset,
            amount_in,
            amount_out,
            fee_units,
            price_impact_bps,
            invariant_before: swap_invariant(self.reserve_a, self.reserve_b, &self.curve),
            invariant_after: 0,
        })
    }

    pub fn apply_exact_in(
        &mut self,
        input_asset: &str,
        amount_in: u64,
        min_amount_out: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateSwapExecution> {
        let mut quote = self.quote_exact_in(input_asset, amount_in)?;
        if quote.amount_out < min_amount_out {
            return Err("swap output below minimum".to_string());
        }
        if input_asset == self.asset_a {
            self.reserve_a = self.reserve_a.saturating_add(quote.amount_in);
            self.reserve_b = self.reserve_b.saturating_sub(quote.amount_out);
        } else {
            self.reserve_b = self.reserve_b.saturating_add(quote.amount_in);
            self.reserve_a = self.reserve_a.saturating_sub(quote.amount_out);
        }
        self.refresh_commitments(nonce);
        quote.invariant_after = swap_invariant(self.reserve_a, self.reserve_b, &self.curve);
        let execution = PrivateSwapExecution::new(self, quote, nonce)?;
        Ok(execution)
    }

    pub fn refresh_commitments(&mut self, nonce: u64) {
        self.reserve_a_commitment = private_contract_amount_commitment(
            self.reserve_a,
            &private_contract_amount_blinding(
                &self.contract_id,
                &self.asset_a,
                self.reserve_a,
                nonce,
            ),
        );
        self.reserve_b_commitment = private_contract_amount_commitment(
            self.reserve_b,
            &private_contract_amount_blinding(
                &self.contract_id,
                &self.asset_b,
                self.reserve_b,
                nonce,
            ),
        );
        let invariant = swap_invariant(self.reserve_a, self.reserve_b, &self.curve);
        self.invariant_commitment = private_contract_amount_commitment(
            invariant,
            &private_contract_amount_blinding(
                &self.contract_id,
                "swap_invariant",
                invariant,
                nonce,
            ),
        );
        self.lp_supply_commitment = private_contract_amount_commitment(
            self.lp_supply,
            &private_contract_amount_blinding(
                &self.contract_id,
                &self.lp_asset_id,
                self.lp_supply,
                nonce,
            ),
        );
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_swap_pool",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "pool_id": self.pool_id,
            "contract_id": self.contract_id,
            "asset_a": self.asset_a,
            "asset_b": self.asset_b,
            "lp_asset_id": self.lp_asset_id,
            "curve": self.curve.as_str(),
            "fee_bps": self.fee_bps,
            "reserve_a_commitment": self.reserve_a_commitment,
            "reserve_b_commitment": self.reserve_b_commitment,
            "invariant_commitment": self.invariant_commitment,
            "lp_supply_commitment": self.lp_supply_commitment,
            "oracle_root": self.oracle_root,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record.as_object_mut().expect("swap state object");
        object.insert("reserve_a".to_string(), Value::from(self.reserve_a));
        object.insert("reserve_b".to_string(), Value::from(self.reserve_b));
        object.insert("lp_supply".to_string(), Value::from(self.lp_supply));
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.pool_id, "swap pool id")?;
        ensure_non_empty(&self.contract_id, "swap contract id")?;
        ensure_non_empty(&self.asset_a, "swap asset a")?;
        ensure_non_empty(&self.asset_b, "swap asset b")?;
        ensure_non_empty(&self.lp_asset_id, "swap lp asset")?;
        ensure_non_empty(&self.reserve_a_commitment, "swap reserve a commitment")?;
        ensure_non_empty(&self.reserve_b_commitment, "swap reserve b commitment")?;
        ensure_non_empty(&self.invariant_commitment, "swap invariant commitment")?;
        ensure_non_empty(&self.lp_supply_commitment, "swap lp supply commitment")?;
        ensure_non_empty(&self.oracle_root, "swap oracle root")?;
        if self.asset_a == self.asset_b {
            return Err("swap pool requires distinct assets".to_string());
        }
        ensure_positive(self.reserve_a, "swap reserve a")?;
        ensure_positive(self.reserve_b, "swap reserve b")?;
        if self.fee_bps > PRIVATE_CONTRACTS_MAX_BPS {
            return Err("swap fee exceeds max bps".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "swap status",
        )?;
        Ok(private_swap_pool_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSwapQuote {
    pub quote_id: String,
    pub pool_id: String,
    pub input_asset: String,
    pub output_asset: String,
    pub amount_in: u64,
    pub amount_out: u64,
    pub fee_units: u64,
    pub price_impact_bps: u64,
    pub invariant_before: u64,
    pub invariant_after: u64,
}

impl PrivateSwapQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_swap_quote",
            "chain_id": CHAIN_ID,
            "quote_id": self.quote_id,
            "pool_id": self.pool_id,
            "input_asset": self.input_asset,
            "output_asset": self.output_asset,
            "amount_in_commitment": private_contract_amount_commitment(self.amount_in, &self.quote_id),
            "amount_out_commitment": private_contract_amount_commitment(self.amount_out, &self.quote_id),
            "fee_units_commitment": private_contract_amount_commitment(self.fee_units, &self.quote_id),
            "price_impact_bps": self.price_impact_bps,
            "invariant_before": self.invariant_before,
            "invariant_after": self.invariant_after,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSwapExecution {
    pub execution_id: String,
    pub pool_id: String,
    pub quote_root: String,
    pub reserve_a_commitment: String,
    pub reserve_b_commitment: String,
    pub invariant_commitment: String,
    pub proof_root: String,
    pub nonce: u64,
}

impl PrivateSwapExecution {
    pub fn new(
        pool: &PrivateSwapPool,
        quote: PrivateSwapQuote,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        pool.validate()?;
        let quote_root =
            private_contract_payload_root("PRIVATE-SWAP-QUOTE", &quote.public_record());
        let public_inputs = json!({
            "pool_id": pool.pool_id,
            "quote_root": quote_root,
            "reserve_a_commitment": pool.reserve_a_commitment,
            "reserve_b_commitment": pool.reserve_b_commitment,
            "invariant_commitment": pool.invariant_commitment,
            "invariant_before": quote.invariant_before,
            "invariant_after": quote.invariant_after,
        });
        let proof_root = private_contract_zk_proof_root(
            PrivateProofKind::SwapInvariant.as_str().as_str(),
            PRIVATE_CONTRACTS_PRECOMPILE_PROOF_SYSTEM,
            &pool.oracle_root,
            &private_contract_payload_root("PRIVATE-SWAP-PUBLIC", &public_inputs),
            &private_contract_empty_root("PRIVATE-SWAP-WITNESS"),
        );
        let identity = private_swap_execution_identity_record(
            &pool.pool_id,
            &quote_root,
            &pool.reserve_a_commitment,
            &pool.reserve_b_commitment,
            &pool.invariant_commitment,
            &proof_root,
            nonce,
        );
        let execution_id = private_swap_execution_id(&identity);
        let execution = Self {
            execution_id,
            pool_id: pool.pool_id.clone(),
            quote_root,
            reserve_a_commitment: pool.reserve_a_commitment.clone(),
            reserve_b_commitment: pool.reserve_b_commitment.clone(),
            invariant_commitment: pool.invariant_commitment.clone(),
            proof_root,
            nonce,
        };
        execution.validate()?;
        Ok(execution)
    }

    pub fn identity_record(&self) -> Value {
        private_swap_execution_identity_record(
            &self.pool_id,
            &self.quote_root,
            &self.reserve_a_commitment,
            &self.reserve_b_commitment,
            &self.invariant_commitment,
            &self.proof_root,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("swap execution object")
            .insert(
                "execution_id".to_string(),
                Value::String(self.execution_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.execution_id, "swap execution id")?;
        ensure_non_empty(&self.pool_id, "swap execution pool id")?;
        ensure_non_empty(&self.quote_root, "swap execution quote root")?;
        ensure_non_empty(&self.reserve_a_commitment, "swap reserve a")?;
        ensure_non_empty(&self.reserve_b_commitment, "swap reserve b")?;
        ensure_non_empty(&self.invariant_commitment, "swap invariant")?;
        ensure_non_empty(&self.proof_root, "swap proof root")?;
        if self.execution_id != private_swap_execution_id(&self.identity_record()) {
            return Err("swap execution id mismatch".to_string());
        }
        Ok(private_swap_execution_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialLendingPosition {
    pub position_id: String,
    pub owner_commitment: String,
    pub market_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub collateral_commitment: String,
    pub debt_commitment: String,
    pub health_factor_bps: u64,
    pub position_kind: LendingPositionKind,
    pub slot_id: String,
    pub updated_at_height: u64,
    pub nonce: u64,
    pub collateral_amount: u64,
    pub debt_amount: u64,
    pub status: String,
}

impl ConfidentialLendingPosition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_label: &str,
        market_id: impl Into<String>,
        collateral_asset_id: impl Into<String>,
        debt_asset_id: impl Into<String>,
        collateral_amount: u64,
        debt_amount: u64,
        position_kind: LendingPositionKind,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
        collateral_factor_bps: u64,
    ) -> PrivateContractResult<Self> {
        let market_id = market_id.into();
        let collateral_asset_id = collateral_asset_id.into();
        let debt_asset_id = debt_asset_id.into();
        let slot_id = slot_id.into();
        ensure_non_empty(owner_label, "lending position owner")?;
        ensure_non_empty(&market_id, "lending position market")?;
        ensure_non_empty(&collateral_asset_id, "lending collateral asset")?;
        ensure_non_empty(&debt_asset_id, "lending debt asset")?;
        ensure_non_empty(&slot_id, "lending position slot")?;
        if collateral_factor_bps > PRIVATE_CONTRACTS_MAX_BPS {
            return Err("lending collateral factor exceeds max bps".to_string());
        }
        let owner_commitment = private_contract_account_commitment(owner_label);
        let collateral_commitment = private_contract_amount_commitment(
            collateral_amount,
            &private_contract_amount_blinding(
                &owner_commitment,
                &collateral_asset_id,
                collateral_amount,
                nonce,
            ),
        );
        let debt_commitment = private_contract_amount_commitment(
            debt_amount,
            &private_contract_amount_blinding(
                &owner_commitment,
                &debt_asset_id,
                debt_amount,
                nonce,
            ),
        );
        let health_factor_bps =
            lending_health_factor_bps(collateral_amount, debt_amount, collateral_factor_bps);
        let identity = lending_position_identity_record(
            &owner_commitment,
            &market_id,
            &collateral_asset_id,
            &debt_asset_id,
            &collateral_commitment,
            &debt_commitment,
            health_factor_bps,
            position_kind.as_str(),
            &slot_id,
            height,
            nonce,
        );
        let position_id = lending_position_id(&identity);
        let position = Self {
            position_id,
            owner_commitment,
            market_id,
            collateral_asset_id,
            debt_asset_id,
            collateral_commitment,
            debt_commitment,
            health_factor_bps,
            position_kind,
            slot_id,
            updated_at_height: height,
            nonce,
            collateral_amount,
            debt_amount,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        position.validate()?;
        Ok(position)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_amounts(
        &self,
        collateral_amount: u64,
        debt_amount: u64,
        position_kind: LendingPositionKind,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
        collateral_factor_bps: u64,
    ) -> PrivateContractResult<Self> {
        let slot_id = slot_id.into();
        ensure_non_empty(&slot_id, "lending position slot")?;
        let collateral_commitment = private_contract_amount_commitment(
            collateral_amount,
            &private_contract_amount_blinding(
                &self.owner_commitment,
                &self.collateral_asset_id,
                collateral_amount,
                nonce,
            ),
        );
        let debt_commitment = private_contract_amount_commitment(
            debt_amount,
            &private_contract_amount_blinding(
                &self.owner_commitment,
                &self.debt_asset_id,
                debt_amount,
                nonce,
            ),
        );
        let health_factor_bps =
            lending_health_factor_bps(collateral_amount, debt_amount, collateral_factor_bps);
        let identity = lending_position_identity_record(
            &self.owner_commitment,
            &self.market_id,
            &self.collateral_asset_id,
            &self.debt_asset_id,
            &collateral_commitment,
            &debt_commitment,
            health_factor_bps,
            position_kind.as_str(),
            &slot_id,
            height,
            nonce,
        );
        let position_id = lending_position_id(&identity);
        let position = Self {
            position_id,
            owner_commitment: self.owner_commitment.clone(),
            market_id: self.market_id.clone(),
            collateral_asset_id: self.collateral_asset_id.clone(),
            debt_asset_id: self.debt_asset_id.clone(),
            collateral_commitment,
            debt_commitment,
            health_factor_bps,
            position_kind,
            slot_id,
            updated_at_height: height,
            nonce,
            collateral_amount,
            debt_amount,
            status: self.status.clone(),
        };
        position.validate()?;
        Ok(position)
    }

    pub fn identity_record(&self) -> Value {
        lending_position_identity_record(
            &self.owner_commitment,
            &self.market_id,
            &self.collateral_asset_id,
            &self.debt_asset_id,
            &self.collateral_commitment,
            &self.debt_commitment,
            self.health_factor_bps,
            self.position_kind.as_str(),
            &self.slot_id,
            self.updated_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        let object = record
            .as_object_mut()
            .expect("lending position public object");
        object.insert(
            "position_id".to_string(),
            Value::String(self.position_id.clone()),
        );
        object.insert("status".to_string(), Value::String(self.status.clone()));
        record
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record.as_object_mut().expect("lending state object");
        object.insert(
            "collateral_amount".to_string(),
            Value::from(self.collateral_amount),
        );
        object.insert("debt_amount".to_string(), Value::from(self.debt_amount));
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.position_id, "lending position id")?;
        ensure_non_empty(&self.owner_commitment, "lending position owner")?;
        ensure_non_empty(&self.market_id, "lending position market")?;
        ensure_non_empty(&self.collateral_asset_id, "lending collateral asset")?;
        ensure_non_empty(&self.debt_asset_id, "lending debt asset")?;
        ensure_non_empty(&self.collateral_commitment, "lending collateral commitment")?;
        ensure_non_empty(&self.debt_commitment, "lending debt commitment")?;
        ensure_non_empty(&self.slot_id, "lending position slot")?;
        if self.position_id != lending_position_id(&self.identity_record()) {
            return Err("lending position id mismatch".to_string());
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "lending position status",
        )?;
        Ok(lending_position_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLendingMarket {
    pub market_id: String,
    pub contract_id: String,
    pub collateral_asset_id: String,
    pub debt_asset_id: String,
    pub rate_model: LendingRateModel,
    pub collateral_factor_bps: u64,
    pub reserve_factor_bps: u64,
    pub liquidation_bonus_bps: u64,
    pub supplied_commitment: String,
    pub borrowed_commitment: String,
    pub reserve_commitment: String,
    pub position_root: String,
    pub oracle_root: String,
    pub total_supplied: u64,
    pub total_borrowed: u64,
    pub reserve_units: u64,
    pub positions: BTreeMap<String, ConfidentialLendingPosition>,
    pub status: String,
}

impl PrivateLendingMarket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contract_id: impl Into<String>,
        collateral_asset_id: impl Into<String>,
        debt_asset_id: impl Into<String>,
        rate_model: LendingRateModel,
        collateral_factor_bps: u64,
        reserve_factor_bps: u64,
        liquidation_bonus_bps: u64,
        oracle: &Value,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        let contract_id = contract_id.into();
        let collateral_asset_id = collateral_asset_id.into();
        let debt_asset_id = debt_asset_id.into();
        ensure_non_empty(&contract_id, "lending market contract id")?;
        ensure_non_empty(&collateral_asset_id, "lending collateral asset")?;
        ensure_non_empty(&debt_asset_id, "lending debt asset")?;
        if collateral_factor_bps > PRIVATE_CONTRACTS_MAX_BPS
            || reserve_factor_bps > PRIVATE_CONTRACTS_MAX_BPS
            || liquidation_bonus_bps > PRIVATE_CONTRACTS_MAX_BPS
        {
            return Err("lending bps setting exceeds max".to_string());
        }
        let oracle_root = private_contract_payload_root("PRIVATE-LENDING-ORACLE", oracle);
        let supplied_commitment = private_contract_amount_commitment(
            0,
            &private_contract_amount_blinding(&contract_id, &collateral_asset_id, 0, nonce),
        );
        let borrowed_commitment = private_contract_amount_commitment(
            0,
            &private_contract_amount_blinding(&contract_id, &debt_asset_id, 0, nonce),
        );
        let reserve_commitment = private_contract_amount_commitment(
            0,
            &private_contract_amount_blinding(&contract_id, "lending_reserve", 0, nonce),
        );
        let position_root = lending_position_root_from_slice(&[]);
        let identity = private_lending_market_identity_record(
            &contract_id,
            &collateral_asset_id,
            &debt_asset_id,
            rate_model.as_str(),
            collateral_factor_bps,
            reserve_factor_bps,
            liquidation_bonus_bps,
            &supplied_commitment,
            &borrowed_commitment,
            &reserve_commitment,
            &position_root,
            &oracle_root,
        );
        let market_id = private_lending_market_id(&identity);
        let market = Self {
            market_id,
            contract_id,
            collateral_asset_id,
            debt_asset_id,
            rate_model,
            collateral_factor_bps,
            reserve_factor_bps,
            liquidation_bonus_bps,
            supplied_commitment,
            borrowed_commitment,
            reserve_commitment,
            position_root,
            oracle_root,
            total_supplied: 0,
            total_borrowed: 0,
            reserve_units: 0,
            positions: BTreeMap::new(),
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        };
        market.validate()?;
        Ok(market)
    }

    pub fn position_for_owner(
        &self,
        owner_commitment: &str,
    ) -> Option<&ConfidentialLendingPosition> {
        self.positions.get(owner_commitment)
    }

    pub fn refresh_commitments(&mut self, nonce: u64) {
        self.supplied_commitment = private_contract_amount_commitment(
            self.total_supplied,
            &private_contract_amount_blinding(
                &self.contract_id,
                &self.collateral_asset_id,
                self.total_supplied,
                nonce,
            ),
        );
        self.borrowed_commitment = private_contract_amount_commitment(
            self.total_borrowed,
            &private_contract_amount_blinding(
                &self.contract_id,
                &self.debt_asset_id,
                self.total_borrowed,
                nonce,
            ),
        );
        self.reserve_commitment = private_contract_amount_commitment(
            self.reserve_units,
            &private_contract_amount_blinding(
                &self.contract_id,
                "lending_reserve",
                self.reserve_units,
                nonce,
            ),
        );
        self.position_root =
            lending_position_root_from_slice(&self.positions.values().cloned().collect::<Vec<_>>());
    }

    pub fn deposit(
        &mut self,
        owner_label: &str,
        collateral_amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateLendingReceipt> {
        ensure_positive(collateral_amount, "lending deposit amount")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let existing = self.positions.get(&owner_commitment).cloned();
        let slot_id = slot_id.into();
        let position = if let Some(position) = existing {
            position.update_amounts(
                position.collateral_amount.saturating_add(collateral_amount),
                position.debt_amount,
                LendingPositionKind::Collateral,
                slot_id,
                height,
                nonce,
                self.collateral_factor_bps,
            )?
        } else {
            ConfidentialLendingPosition::new(
                owner_label,
                self.market_id.clone(),
                self.collateral_asset_id.clone(),
                self.debt_asset_id.clone(),
                collateral_amount,
                0,
                LendingPositionKind::Collateral,
                slot_id,
                height,
                nonce,
                self.collateral_factor_bps,
            )?
        };
        self.positions.insert(owner_commitment.clone(), position);
        self.total_supplied = self.total_supplied.saturating_add(collateral_amount);
        self.refresh_commitments(nonce);
        PrivateLendingReceipt::new(
            &self.market_id,
            "deposit",
            &owner_commitment,
            collateral_amount,
            0,
            &self.position_root,
            &self.supplied_commitment,
            &self.borrowed_commitment,
            height,
            nonce,
        )
    }

    pub fn borrow(
        &mut self,
        owner_label: &str,
        debt_amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateLendingReceipt> {
        ensure_positive(debt_amount, "lending borrow amount")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let current = self
            .positions
            .get(&owner_commitment)
            .cloned()
            .ok_or_else(|| "lending borrow requires collateral".to_string())?;
        let new_debt = current.debt_amount.saturating_add(debt_amount);
        let health = lending_health_factor_bps(
            current.collateral_amount,
            new_debt,
            self.collateral_factor_bps,
        );
        if health < PRIVATE_CONTRACTS_MAX_BPS {
            return Err("lending borrow would make position unhealthy".to_string());
        }
        let position = current.update_amounts(
            current.collateral_amount,
            new_debt,
            LendingPositionKind::Borrow,
            slot_id,
            height,
            nonce,
            self.collateral_factor_bps,
        )?;
        self.positions.insert(owner_commitment.clone(), position);
        self.total_borrowed = self.total_borrowed.saturating_add(debt_amount);
        self.reserve_units = self
            .reserve_units
            .saturating_add(mul_bps(debt_amount, self.reserve_factor_bps));
        self.refresh_commitments(nonce);
        PrivateLendingReceipt::new(
            &self.market_id,
            "borrow",
            &owner_commitment,
            0,
            debt_amount,
            &self.position_root,
            &self.supplied_commitment,
            &self.borrowed_commitment,
            height,
            nonce,
        )
    }

    pub fn repay(
        &mut self,
        owner_label: &str,
        repay_amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateLendingReceipt> {
        ensure_positive(repay_amount, "lending repay amount")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let current = self
            .positions
            .get(&owner_commitment)
            .cloned()
            .ok_or_else(|| "lending repay requires position".to_string())?;
        let applied = repay_amount.min(current.debt_amount);
        let position = current.update_amounts(
            current.collateral_amount,
            current.debt_amount.saturating_sub(applied),
            LendingPositionKind::Borrow,
            slot_id,
            height,
            nonce,
            self.collateral_factor_bps,
        )?;
        self.positions.insert(owner_commitment.clone(), position);
        self.total_borrowed = self.total_borrowed.saturating_sub(applied);
        self.refresh_commitments(nonce);
        PrivateLendingReceipt::new(
            &self.market_id,
            "repay",
            &owner_commitment,
            0,
            applied,
            &self.position_root,
            &self.supplied_commitment,
            &self.borrowed_commitment,
            height,
            nonce,
        )
    }

    pub fn liquidate(
        &mut self,
        owner_label: &str,
        liquidator_label: &str,
        repay_amount: u64,
        slot_id: impl Into<String>,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<PrivateLendingReceipt> {
        ensure_positive(repay_amount, "lending liquidation repay amount")?;
        let owner_commitment = private_contract_account_commitment(owner_label);
        let _liquidator_commitment = private_contract_account_commitment(liquidator_label);
        let current = self
            .positions
            .get(&owner_commitment)
            .cloned()
            .ok_or_else(|| "lending liquidation requires position".to_string())?;
        if current.health_factor_bps >= PRIVATE_CONTRACTS_MAX_BPS {
            return Err("lending position is not liquidatable".to_string());
        }
        let applied = repay_amount.min(current.debt_amount);
        let seized = mul_bps(
            applied,
            PRIVATE_CONTRACTS_MAX_BPS + self.liquidation_bonus_bps,
        )
        .min(current.collateral_amount);
        let position = current.update_amounts(
            current.collateral_amount.saturating_sub(seized),
            current.debt_amount.saturating_sub(applied),
            LendingPositionKind::Liquidation,
            slot_id,
            height,
            nonce,
            self.collateral_factor_bps,
        )?;
        self.positions.insert(owner_commitment.clone(), position);
        self.total_supplied = self.total_supplied.saturating_sub(seized);
        self.total_borrowed = self.total_borrowed.saturating_sub(applied);
        self.refresh_commitments(nonce);
        PrivateLendingReceipt::new(
            &self.market_id,
            "liquidate",
            &owner_commitment,
            seized,
            applied,
            &self.position_root,
            &self.supplied_commitment,
            &self.borrowed_commitment,
            height,
            nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_lending_market",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "market_id": self.market_id,
            "contract_id": self.contract_id,
            "collateral_asset_id": self.collateral_asset_id,
            "debt_asset_id": self.debt_asset_id,
            "rate_model": self.rate_model.as_str(),
            "collateral_factor_bps": self.collateral_factor_bps,
            "reserve_factor_bps": self.reserve_factor_bps,
            "liquidation_bonus_bps": self.liquidation_bonus_bps,
            "supplied_commitment": self.supplied_commitment,
            "borrowed_commitment": self.borrowed_commitment,
            "reserve_commitment": self.reserve_commitment,
            "position_root": self.position_root,
            "oracle_root": self.oracle_root,
            "status": self.status,
        })
    }

    pub fn state_record(&self) -> Value {
        let mut record = self.public_record();
        let object = record
            .as_object_mut()
            .expect("private lending market state object");
        object.insert(
            "total_supplied".to_string(),
            Value::from(self.total_supplied),
        );
        object.insert(
            "total_borrowed".to_string(),
            Value::from(self.total_borrowed),
        );
        object.insert("reserve_units".to_string(), Value::from(self.reserve_units));
        object.insert(
            "positions".to_string(),
            Value::Array(
                self.positions
                    .values()
                    .map(ConfidentialLendingPosition::state_record)
                    .collect(),
            ),
        );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.market_id, "lending market id")?;
        ensure_non_empty(&self.contract_id, "lending market contract")?;
        ensure_non_empty(&self.collateral_asset_id, "lending collateral asset")?;
        ensure_non_empty(&self.debt_asset_id, "lending debt asset")?;
        ensure_non_empty(&self.supplied_commitment, "lending supplied commitment")?;
        ensure_non_empty(&self.borrowed_commitment, "lending borrowed commitment")?;
        ensure_non_empty(&self.reserve_commitment, "lending reserve commitment")?;
        ensure_non_empty(&self.position_root, "lending position root")?;
        ensure_non_empty(&self.oracle_root, "lending oracle root")?;
        if self.collateral_factor_bps > PRIVATE_CONTRACTS_MAX_BPS
            || self.reserve_factor_bps > PRIVATE_CONTRACTS_MAX_BPS
            || self.liquidation_bonus_bps > PRIVATE_CONTRACTS_MAX_BPS
        {
            return Err("lending bps setting exceeds max".to_string());
        }
        let borrowed_sum = self
            .positions
            .values()
            .map(|position| position.debt_amount)
            .fold(0_u64, u64::saturating_add);
        if borrowed_sum != self.total_borrowed {
            return Err("lending borrowed sum mismatch".to_string());
        }
        for position in self.positions.values() {
            position.validate()?;
        }
        ensure_status(
            &self.status,
            &[
                PRIVATE_CONTRACTS_STATUS_ACTIVE,
                PRIVATE_CONTRACTS_STATUS_PAUSED,
                PRIVATE_CONTRACTS_STATUS_REVOKED,
            ],
            "lending market status",
        )?;
        Ok(private_lending_market_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateLendingReceipt {
    pub receipt_id: String,
    pub market_id: String,
    pub action: String,
    pub owner_commitment: String,
    pub collateral_delta_commitment: String,
    pub debt_delta_commitment: String,
    pub position_root: String,
    pub supplied_commitment: String,
    pub borrowed_commitment: String,
    pub operated_at_height: u64,
    pub nonce: u64,
}

impl PrivateLendingReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        market_id: &str,
        action: &str,
        owner_commitment: &str,
        collateral_delta: u64,
        debt_delta: u64,
        position_root: &str,
        supplied_commitment: &str,
        borrowed_commitment: &str,
        height: u64,
        nonce: u64,
    ) -> PrivateContractResult<Self> {
        ensure_non_empty(market_id, "lending receipt market")?;
        ensure_non_empty(action, "lending receipt action")?;
        ensure_non_empty(owner_commitment, "lending receipt owner")?;
        ensure_non_empty(position_root, "lending receipt position root")?;
        ensure_non_empty(supplied_commitment, "lending receipt supplied")?;
        ensure_non_empty(borrowed_commitment, "lending receipt borrowed")?;
        let collateral_delta_commitment = private_contract_amount_commitment(
            collateral_delta,
            &private_contract_amount_blinding(
                owner_commitment,
                "lending_collateral_delta",
                collateral_delta,
                nonce,
            ),
        );
        let debt_delta_commitment = private_contract_amount_commitment(
            debt_delta,
            &private_contract_amount_blinding(
                owner_commitment,
                "lending_debt_delta",
                debt_delta,
                nonce,
            ),
        );
        let identity = private_lending_receipt_identity_record(
            market_id,
            action,
            owner_commitment,
            &collateral_delta_commitment,
            &debt_delta_commitment,
            position_root,
            supplied_commitment,
            borrowed_commitment,
            height,
            nonce,
        );
        let receipt_id = private_lending_receipt_id(&identity);
        let receipt = Self {
            receipt_id,
            market_id: market_id.to_string(),
            action: action.to_string(),
            owner_commitment: owner_commitment.to_string(),
            collateral_delta_commitment,
            debt_delta_commitment,
            position_root: position_root.to_string(),
            supplied_commitment: supplied_commitment.to_string(),
            borrowed_commitment: borrowed_commitment.to_string(),
            operated_at_height: height,
            nonce,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn identity_record(&self) -> Value {
        private_lending_receipt_identity_record(
            &self.market_id,
            &self.action,
            &self.owner_commitment,
            &self.collateral_delta_commitment,
            &self.debt_delta_commitment,
            &self.position_root,
            &self.supplied_commitment,
            &self.borrowed_commitment,
            self.operated_at_height,
            self.nonce,
        )
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.identity_record();
        record
            .as_object_mut()
            .expect("lending receipt object")
            .insert(
                "receipt_id".to_string(),
                Value::String(self.receipt_id.clone()),
            );
        record
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.receipt_id, "lending receipt id")?;
        ensure_non_empty(&self.market_id, "lending receipt market")?;
        ensure_non_empty(&self.action, "lending receipt action")?;
        ensure_non_empty(&self.owner_commitment, "lending receipt owner")?;
        ensure_non_empty(
            &self.collateral_delta_commitment,
            "lending collateral delta commitment",
        )?;
        ensure_non_empty(&self.debt_delta_commitment, "lending debt delta commitment")?;
        ensure_non_empty(&self.position_root, "lending receipt position root")?;
        ensure_non_empty(&self.supplied_commitment, "lending receipt supplied")?;
        ensure_non_empty(&self.borrowed_commitment, "lending receipt borrowed")?;
        if self.receipt_id != private_lending_receipt_id(&self.identity_record()) {
            return Err("lending receipt id mismatch".to_string());
        }
        Ok(private_lending_receipt_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDevnetRecord {
    pub record_id: String,
    pub label: String,
    pub category: String,
    pub payload_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl PrivateDevnetRecord {
    pub fn new(
        label: impl Into<String>,
        category: impl Into<String>,
        payload: &Value,
        height: u64,
    ) -> PrivateContractResult<Self> {
        let label = normalize_label(label.into());
        let category = normalize_label(category.into());
        ensure_non_empty(&label, "devnet record label")?;
        ensure_non_empty(&category, "devnet record category")?;
        let payload_root = private_contract_payload_root("PRIVATE-DEVNET-RECORD-PAYLOAD", payload);
        let record_id = private_devnet_record_id(&label, &category, &payload_root, height);
        Ok(Self {
            record_id,
            label,
            category,
            payload_root,
            created_at_height: height,
            status: PRIVATE_CONTRACTS_STATUS_ACTIVE.to_string(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_devnet_record",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "label": self.label,
            "category": self.category,
            "payload_root": self.payload_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        ensure_non_empty(&self.record_id, "devnet record id")?;
        ensure_non_empty(&self.label, "devnet record label")?;
        ensure_non_empty(&self.category, "devnet record category")?;
        ensure_non_empty(&self.payload_root, "devnet record payload root")?;
        if self.record_id
            != private_devnet_record_id(
                &self.label,
                &self.category,
                &self.payload_root,
                self.created_at_height,
            )
        {
            return Err("devnet record id mismatch".to_string());
        }
        Ok(private_devnet_record_root(self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractsState {
    pub height: u64,
    pub config: PrivateContractsConfig,
    pub deployments: BTreeMap<String, PrivateContractDeployment>,
    pub encrypted_slots: BTreeMap<String, EncryptedStateSlot>,
    pub event_logs: BTreeMap<String, PrivateEventLog>,
    pub pq_sessions: BTreeMap<String, PqAuthorizationSession>,
    pub session_grants: BTreeMap<String, SessionCapabilityGrant>,
    pub capabilities: BTreeMap<String, AccessControlCapability>,
    pub access_decisions: BTreeMap<String, AccessDecisionReceipt>,
    pub proof_receipts: BTreeMap<String, ZkPrecompileProofReceipt>,
    pub precompile_invocations: BTreeMap<String, PrecompileInvocation>,
    pub gas_sponsorships: BTreeMap<String, GasSponsorshipPolicy>,
    pub call_receipts: BTreeMap<String, ShieldedContractExecutionReceipt>,
    pub token_ledgers: BTreeMap<String, PrivateTokenLedger>,
    pub swap_pools: BTreeMap<String, PrivateSwapPool>,
    pub lending_markets: BTreeMap<String, PrivateLendingMarket>,
    pub devnet_records: BTreeMap<String, PrivateDevnetRecord>,
}

impl Default for PrivateContractsState {
    fn default() -> Self {
        Self::new(PrivateContractsConfig::default())
    }
}

impl PrivateContractsState {
    pub fn new(config: PrivateContractsConfig) -> Self {
        Self {
            height: 0,
            config,
            deployments: BTreeMap::new(),
            encrypted_slots: BTreeMap::new(),
            event_logs: BTreeMap::new(),
            pq_sessions: BTreeMap::new(),
            session_grants: BTreeMap::new(),
            capabilities: BTreeMap::new(),
            access_decisions: BTreeMap::new(),
            proof_receipts: BTreeMap::new(),
            precompile_invocations: BTreeMap::new(),
            gas_sponsorships: BTreeMap::new(),
            call_receipts: BTreeMap::new(),
            token_ledgers: BTreeMap::new(),
            swap_pools: BTreeMap::new(),
            lending_markets: BTreeMap::new(),
            devnet_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateContractResult<Self> {
        let mut state = Self::new(PrivateContractsConfig::default());
        state.set_height(42);

        let token_template = PrivateContractTemplate::private_token()?;
        let swap_template = PrivateContractTemplate::private_swap_pool()?;
        let lending_template = PrivateContractTemplate::private_lending_market()?;

        let admin_capability = AccessControlCapability::new(
            "devnet-admin",
            "template-admin",
            CapabilityKind::ContractAdmin,
            vec!["*".to_string()],
            0,
            state.height,
            0,
            &json!({"scope": "devnet-admin"}),
        )?;
        let token_deployment = PrivateContractDeployment::deploy(
            token_template,
            "devnet-issuer",
            vec![admin_capability.clone()],
            &json!({"name": "Private Wrapped XMR", "symbol": "pXMR"}),
            state.height,
            1,
        )?;
        let swap_deployment = PrivateContractDeployment::deploy(
            swap_template,
            "devnet-amm",
            vec![admin_capability.clone()],
            &json!({"name": "pXMR/USD private pool"}),
            state.height,
            2,
        )?;
        let lending_deployment = PrivateContractDeployment::deploy(
            lending_template,
            "devnet-credit",
            vec![admin_capability.clone()],
            &json!({"name": "pXMR private credit market"}),
            state.height,
            3,
        )?;

        state.insert_capability(admin_capability)?;
        state.insert_deployment(token_deployment.clone())?;
        state.insert_deployment(swap_deployment.clone())?;
        state.insert_deployment(lending_deployment.clone())?;

        let alice_session = PqAuthorizationSession::open(
            "alice-view-key",
            "alice-session-key",
            vec![
                token_deployment.contract_id.clone(),
                swap_deployment.contract_id.clone(),
                lending_deployment.contract_id.clone(),
            ],
            vec![
                CapabilityKind::TokenTransfer,
                CapabilityKind::SwapExactIn,
                CapabilityKind::LendingDeposit,
                CapabilityKind::LendingBorrow,
                CapabilityKind::LendingRepay,
            ],
            &json!({"device": "alice-devnet-wallet", "purpose": "private-defi"}),
            state.height,
            state.config.default_session_ttl_blocks,
            11,
        )?;
        let bob_session = PqAuthorizationSession::open(
            "bob-view-key",
            "bob-session-key",
            vec![
                token_deployment.contract_id.clone(),
                swap_deployment.contract_id.clone(),
            ],
            vec![CapabilityKind::TokenTransfer, CapabilityKind::SwapExactIn],
            &json!({"device": "bob-devnet-wallet", "purpose": "private-payments"}),
            state.height,
            state.config.default_session_ttl_blocks,
            12,
        )?;
        state.insert_pq_session(alice_session.clone())?;
        state.insert_pq_session(bob_session.clone())?;

        let alice_token_cap = AccessControlCapability::new(
            "alice-view-key",
            token_deployment.contract_id.clone(),
            CapabilityKind::TokenTransfer,
            vec!["transfer".to_string(), "burn".to_string()],
            500_000,
            state.height,
            state.height + 1_000,
            &json!({"wallet_policy": "alice-default"}),
        )?;
        let alice_swap_cap = AccessControlCapability::new(
            "alice-view-key",
            swap_deployment.contract_id.clone(),
            CapabilityKind::SwapExactIn,
            vec!["swap_exact_in".to_string()],
            350_000,
            state.height,
            state.height + 1_000,
            &json!({"wallet_policy": "alice-swap"}),
        )?;
        let alice_lending_cap = AccessControlCapability::new(
            "alice-view-key",
            lending_deployment.contract_id.clone(),
            CapabilityKind::LendingBorrow,
            vec![
                "deposit".to_string(),
                "borrow".to_string(),
                "repay".to_string(),
            ],
            650_000,
            state.height,
            state.height + 1_000,
            &json!({"wallet_policy": "alice-credit"}),
        )?;
        state.insert_capability(alice_token_cap.clone())?;
        state.insert_capability(alice_swap_cap.clone())?;
        state.insert_capability(alice_lending_cap.clone())?;

        let grant = SessionCapabilityGrant::new(
            alice_session.session_id.clone(),
            "alice-view-key",
            token_deployment.contract_id.clone(),
            CapabilityKind::TokenTransfer,
            vec!["transfer".to_string()],
            200_000,
            state.height,
            state.config.default_session_ttl_blocks,
            13,
        )?;
        state.insert_session_grant(grant)?;

        let alice_slot = EncryptedStateSlot::new(
            token_deployment.contract_id.clone(),
            "balances",
            "alice-pxmr",
            &json!({"owner": "alice", "asset": PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID, "amount": 250_000}),
            private_contract_account_commitment("alice-view-key"),
            private_contract_string_root("DISCLOSURE", "alice-auditor"),
            StateSlotVisibility::ShieldedCiphertext,
            state.height,
            21,
        )?;
        let bob_slot = EncryptedStateSlot::new(
            token_deployment.contract_id.clone(),
            "balances",
            "bob-pxmr",
            &json!({"owner": "bob", "asset": PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID, "amount": 75_000}),
            private_contract_account_commitment("bob-view-key"),
            private_contract_string_root("DISCLOSURE", "bob-auditor"),
            StateSlotVisibility::ShieldedCiphertext,
            state.height,
            22,
        )?;
        state.insert_encrypted_slot(alice_slot.clone())?;
        state.insert_encrypted_slot(bob_slot.clone())?;

        let mut ledger = PrivateTokenLedger::new(
            token_deployment.contract_id.clone(),
            PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID,
            "pXMR",
            12,
            "devnet-issuer",
            &json!({"transfer_mode": "shielded", "memo": "encrypted"}),
            state.height,
            30,
        )?;
        ledger.mint(
            "alice-view-key",
            250_000,
            alice_slot.slot_id.clone(),
            state.height,
            31,
        )?;
        ledger.mint(
            "bob-view-key",
            75_000,
            bob_slot.slot_id.clone(),
            state.height,
            32,
        )?;
        state.insert_token_ledger(ledger.clone())?;

        let mut swap_pool = PrivateSwapPool::new(
            swap_deployment.contract_id.clone(),
            PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID,
            PRIVATE_CONTRACTS_DEVNET_USD_ASSET_ID,
            "pxmr-usd-lp",
            SwapCurveKind::ConstantProduct,
            PRIVATE_CONTRACTS_DEFAULT_SWAP_FEE_BPS,
            1_000_000,
            175_000_000,
            &json!({"oracle": "devnet-median", "pxmr_usd": "175.00"}),
            40,
        )?;
        let _swap_execution = swap_pool.apply_exact_in(
            PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID,
            10_000,
            1_700_000,
            41,
        )?;
        state.insert_swap_pool(swap_pool.clone())?;

        let mut lending_market = PrivateLendingMarket::new(
            lending_deployment.contract_id.clone(),
            PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID,
            PRIVATE_CONTRACTS_DEVNET_USD_ASSET_ID,
            LendingRateModel::KinkedUtilization,
            PRIVATE_CONTRACTS_DEFAULT_COLLATERAL_FACTOR_BPS,
            PRIVATE_CONTRACTS_DEFAULT_LENDING_RESERVE_BPS,
            PRIVATE_CONTRACTS_DEFAULT_LIQUIDATION_BONUS_BPS,
            &json!({"oracle": "devnet-credit-oracle", "haircut_bps": 1500}),
            50,
        )?;
        lending_market.deposit(
            "alice-view-key",
            100_000,
            "alice-credit-slot",
            state.height,
            51,
        )?;
        lending_market.borrow(
            "alice-view-key",
            50_000,
            "alice-credit-slot-2",
            state.height,
            52,
        )?;
        state.insert_lending_market(lending_market)?;

        let sponsorship = GasSponsorshipPolicy::new(
            "devnet-paymaster",
            SponsorScope::DevnetLane,
            "private_contracts",
            PRIVATE_CONTRACTS_DEFAULT_FEE_ASSET_ID,
            state.height,
            state.height + state.config.sponsor_epoch_blocks,
            state.config.sponsor_epoch_budget_units,
            state.config.low_fee_call_gas_credit,
            9_000,
            vec![
                "shielded_call".to_string(),
                "private_defi".to_string(),
                "devnet_bootstrap".to_string(),
            ],
        )?;
        state.insert_gas_sponsorship(sponsorship)?;

        let proof = ZkPrecompileProofReceipt::new(
            PrivateProofKind::TokenConservation,
            PRIVATE_CONTRACTS_PRECOMPILE_PROOF_SYSTEM,
            private_contract_string_root("VK", "devnet-token-conservation"),
            &json!({"token_id": ledger.token_id, "balance_root": ledger.balance_root}),
            &json!({"supply": ledger.total_supply}),
            "verify_token_conservation",
            18_000,
            state.height,
            state.height + 64,
        )?;
        state.insert_proof_receipt(proof)?;

        let event = PrivateEventLog::new(
            token_deployment.contract_id.clone(),
            "devnet-genesis-call",
            "token.seeded",
            0,
            PrivateEventVisibility::SelectiveDisclosure,
            &json!({"minted_to": ["alice", "bob"], "asset": PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID}),
            json!({
                "asset_id": PRIVATE_CONTRACTS_NATIVE_XMR_ASSET_ID,
                "recipient_count": 2,
                "amount_commitment": private_contract_amount_commitment(325_000, "devnet-seed"),
            }),
            private_contract_string_root("DISCLOSURE", "devnet-auditor"),
            private_contract_empty_root("PRIVATE-EVENT-CHAIN"),
            state.height,
            60,
        )?;
        state.insert_event(event)?;

        let record = PrivateDevnetRecord::new(
            "private-contracts-devnet",
            "bootstrap",
            &state.public_record_without_state_root(&state.roots()),
            state.height,
        )?;
        state.insert_devnet_record(record)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_deployment(
        &mut self,
        deployment: PrivateContractDeployment,
    ) -> PrivateContractResult<String> {
        deployment.validate()?;
        insert_unique_record(
            &mut self.deployments,
            deployment.contract_id.clone(),
            deployment,
            "private contract deployment",
        )
    }

    pub fn insert_encrypted_slot(
        &mut self,
        slot: EncryptedStateSlot,
    ) -> PrivateContractResult<String> {
        slot.validate()?;
        insert_or_replace_record(&mut self.encrypted_slots, slot.slot_id.clone(), slot)
    }

    pub fn insert_event(&mut self, event: PrivateEventLog) -> PrivateContractResult<String> {
        event.validate()?;
        insert_unique_record(
            &mut self.event_logs,
            event.event_id.clone(),
            event,
            "private event",
        )
    }

    pub fn insert_pq_session(
        &mut self,
        session: PqAuthorizationSession,
    ) -> PrivateContractResult<String> {
        let session_id = session.session_id.clone();
        self.pq_sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    pub fn insert_session_grant(
        &mut self,
        grant: SessionCapabilityGrant,
    ) -> PrivateContractResult<String> {
        grant.validate()?;
        insert_unique_record(
            &mut self.session_grants,
            grant.grant_id.clone(),
            grant,
            "session capability grant",
        )
    }

    pub fn insert_capability(
        &mut self,
        capability: AccessControlCapability,
    ) -> PrivateContractResult<String> {
        capability.validate()?;
        insert_or_replace_record(
            &mut self.capabilities,
            capability.capability_id.clone(),
            capability,
        )
    }

    pub fn insert_access_decision(
        &mut self,
        decision: AccessDecisionReceipt,
    ) -> PrivateContractResult<String> {
        decision.validate()?;
        insert_unique_record(
            &mut self.access_decisions,
            decision.decision_id.clone(),
            decision,
            "access decision",
        )
    }

    pub fn insert_proof_receipt(
        &mut self,
        proof: ZkPrecompileProofReceipt,
    ) -> PrivateContractResult<String> {
        proof.validate()?;
        insert_unique_record(
            &mut self.proof_receipts,
            proof.proof_id.clone(),
            proof,
            "zk proof receipt",
        )
    }

    pub fn insert_precompile_invocation(
        &mut self,
        invocation: PrecompileInvocation,
    ) -> PrivateContractResult<String> {
        invocation.validate()?;
        insert_unique_record(
            &mut self.precompile_invocations,
            invocation.invocation_id.clone(),
            invocation,
            "precompile invocation",
        )
    }

    pub fn insert_gas_sponsorship(
        &mut self,
        sponsorship: GasSponsorshipPolicy,
    ) -> PrivateContractResult<String> {
        sponsorship.validate()?;
        insert_or_replace_record(
            &mut self.gas_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
        )
    }

    pub fn insert_call_receipt(
        &mut self,
        receipt: ShieldedContractExecutionReceipt,
    ) -> PrivateContractResult<String> {
        receipt.validate()?;
        insert_unique_record(
            &mut self.call_receipts,
            receipt.receipt_id.clone(),
            receipt,
            "shielded call receipt",
        )
    }

    pub fn insert_token_ledger(
        &mut self,
        ledger: PrivateTokenLedger,
    ) -> PrivateContractResult<String> {
        ledger.validate()?;
        insert_or_replace_record(&mut self.token_ledgers, ledger.token_id.clone(), ledger)
    }

    pub fn insert_swap_pool(&mut self, pool: PrivateSwapPool) -> PrivateContractResult<String> {
        pool.validate()?;
        insert_or_replace_record(&mut self.swap_pools, pool.pool_id.clone(), pool)
    }

    pub fn insert_lending_market(
        &mut self,
        market: PrivateLendingMarket,
    ) -> PrivateContractResult<String> {
        market.validate()?;
        insert_or_replace_record(&mut self.lending_markets, market.market_id.clone(), market)
    }

    pub fn insert_devnet_record(
        &mut self,
        record: PrivateDevnetRecord,
    ) -> PrivateContractResult<String> {
        record.validate()?;
        insert_or_replace_record(&mut self.devnet_records, record.record_id.clone(), record)
    }

    pub fn decide_access(
        &self,
        call: &ShieldedContractCall,
    ) -> PrivateContractResult<AccessDecisionReceipt> {
        let capability = self
            .capabilities
            .get(&call.capability_id)
            .ok_or_else(|| "missing access capability".to_string())?;
        let session = self
            .pq_sessions
            .get(&call.session_id)
            .ok_or_else(|| "missing pq session".to_string())?;
        let mut decision = AccessDecisionKind::Granted;
        let mut reason = json!({"reason": "granted"});
        if !session.is_active_at(self.height) {
            decision = AccessDecisionKind::DeniedSession;
            reason = json!({"reason": "pq session inactive"});
        } else if !capability.is_active_at(self.height) {
            decision = AccessDecisionKind::DeniedExpired;
            reason = json!({"reason": "capability inactive"});
        } else if capability.contract_id != call.contract_id {
            decision = AccessDecisionKind::DeniedMissingCapability;
            reason = json!({"reason": "capability contract mismatch"});
        } else if !capability.permits_selector(&call.selector) {
            decision = AccessDecisionKind::DeniedSelector;
            reason = json!({"reason": "selector not allowed"});
        } else if call.fee_units > capability.remaining_units() {
            decision = AccessDecisionKind::DeniedSpendLimit;
            reason = json!({"reason": "capability spend limit exceeded"});
        }
        AccessDecisionReceipt::new(
            call.capability_id.clone(),
            call.session_id.clone(),
            call.caller_commitment.clone(),
            call.contract_id.clone(),
            call.selector.clone(),
            call.fee_units,
            decision,
            &reason,
            self.height,
        )
    }

    pub fn submit_shielded_call(
        &mut self,
        request: ShieldedContractCallRequest,
    ) -> PrivateContractResult<ShieldedContractExecutionReceipt> {
        let pre_state_root = self.state_root();
        if request.gas_limit > self.config.max_call_gas {
            return Err("shielded call gas limit exceeds config".to_string());
        }
        let mut call = ShieldedContractCall::from_request(
            request,
            self.height,
            self.config.default_call_ttl_blocks,
        )?;
        if !self.deployments.contains_key(&call.contract_id) {
            return Err("shielded call references unknown contract".to_string());
        }
        let decision = self.decide_access(&call)?;
        if !decision.decision.permits() {
            self.insert_access_decision(decision.clone())?;
            return Err(format!(
                "shielded call denied: {}",
                decision.decision.as_str()
            ));
        }
        self.insert_access_decision(decision.clone())?;

        let quote = self
            .gas_sponsorships
            .values_mut()
            .filter(|policy| policy.is_active_at(self.height) && policy.matches_call(&call))
            .find_map(|policy| {
                let quote = policy.quote(&call).ok()?;
                policy.apply_quote(&quote).ok()?;
                Some(quote)
            });
        let sponsored_units = quote
            .as_ref()
            .map(|quote| quote.sponsor_fee_units)
            .unwrap_or(0);
        if let Some(quote) = quote {
            call.mark_sponsored(quote.quote_id);
        } else {
            call.status = PrivateCallStatus::Executed;
        }

        if let Some(capability) = self.capabilities.get_mut(&call.capability_id) {
            capability.charge(call.fee_units.saturating_sub(sponsored_units))?;
        }

        let slot = EncryptedStateSlot::new(
            call.contract_id.clone(),
            "call_receipts",
            &call.call_id,
            &json!({
                "call_id": call.call_id,
                "selector": call.selector,
                "status": call.status.as_str(),
                "gas_used": call.gas_used,
                "fee_units": call.fee_units,
            }),
            call.caller_commitment.clone(),
            private_contract_string_root("DISCLOSURE", "call-auditor"),
            StateSlotVisibility::SequencerSealed,
            self.height,
            call.nonce.saturating_add(100),
        )?;
        let event = PrivateEventLog::new(
            call.contract_id.clone(),
            call.call_id.clone(),
            format!("{}.executed", call.selector),
            self.event_logs.len() as u64,
            PrivateEventVisibility::EncryptedPayload,
            &call.state_record(),
            json!({
                "call_id": call.call_id,
                "selector": call.selector,
                "status": call.status.as_str(),
                "gas_used": call.gas_used,
                "sponsored_units": sponsored_units,
            }),
            private_contract_string_root("DISCLOSURE", "sequencer-audit"),
            self.event_chain_tip(),
            self.height,
            call.nonce.saturating_add(101),
        )?;
        let proof = ZkPrecompileProofReceipt::new(
            PrivateProofKind::ShieldedCall,
            PRIVATE_CONTRACTS_CALL_PROOF_SYSTEM,
            private_contract_string_root("VK", "shielded-call"),
            &call.public_record(),
            &call.state_record(),
            "verify_shielded_call",
            22_500,
            self.height,
            self.height + 64,
        )?;
        let post_state_preview = private_contract_payload_root(
            "PRIVATE-CONTRACTS-POST-STATE-PREVIEW",
            &json!({
                "pre_state_root": pre_state_root,
                "call": call.public_record(),
                "slot": slot.public_record(),
                "event": event.public_record(),
                "proof": proof.public_record(),
            }),
        );
        let receipt = ShieldedContractExecutionReceipt::new(
            &call,
            pre_state_root,
            post_state_preview,
            std::slice::from_ref(&slot),
            std::slice::from_ref(&event),
            std::slice::from_ref(&proof),
            decision.decision_id,
            sponsored_units,
            call.status.clone(),
            self.height,
        )?;
        self.insert_encrypted_slot(slot)?;
        self.insert_event(event)?;
        self.insert_proof_receipt(proof)?;
        self.insert_call_receipt(receipt.clone())?;
        Ok(receipt)
    }

    pub fn event_chain_tip(&self) -> String {
        self.event_logs
            .values()
            .max_by_key(|event| (event.event_index, event.emitted_at_height))
            .map(|event| event.event_chain_root.clone())
            .unwrap_or_else(|| private_contract_empty_root("PRIVATE-EVENT-CHAIN"))
    }

    pub fn roots(&self) -> PrivateContractRoots {
        PrivateContractRoots {
            config_root: self.config.config_root(),
            deployment_root: private_contract_deployment_root_from_map(&self.deployments),
            slot_root: encrypted_state_slot_root_from_map(&self.encrypted_slots),
            event_root: private_event_root_from_map(&self.event_logs),
            pq_session_root: pq_authorization_session_root_from_map(&self.pq_sessions),
            session_grant_root: session_capability_grant_root_from_map(&self.session_grants),
            capability_root: access_control_capability_root_from_map(&self.capabilities),
            access_decision_root: access_decision_root_from_map(&self.access_decisions),
            proof_receipt_root: zk_precompile_proof_root_from_map(&self.proof_receipts),
            precompile_root: precompile_invocation_root_from_map(&self.precompile_invocations),
            gas_sponsorship_root: gas_sponsorship_root_from_map(&self.gas_sponsorships),
            call_receipt_root: shielded_execution_receipt_root_from_map(&self.call_receipts),
            token_ledger_root: private_token_ledger_root_from_map(&self.token_ledgers),
            swap_pool_root: private_swap_pool_root_from_map(&self.swap_pools),
            lending_market_root: private_lending_market_root_from_map(&self.lending_markets),
            devnet_record_root: private_devnet_record_root_from_map(&self.devnet_records),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let mut record = self.public_record_without_state_root(&roots);
        record
            .as_object_mut()
            .expect("private contracts state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_state_root(&self, roots: &PrivateContractRoots) -> Value {
        json!({
            "kind": "private_contracts_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
            "schema_version": PRIVATE_CONTRACTS_SCHEMA_VERSION,
            "height": self.height,
            "runtime": PRIVATE_CONTRACTS_RUNTIME,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.aggregate_root(),
            "deployment_count": self.deployments.len() as u64,
            "slot_count": self.encrypted_slots.len() as u64,
            "event_count": self.event_logs.len() as u64,
            "pq_session_count": self.pq_sessions.len() as u64,
            "session_grant_count": self.session_grants.len() as u64,
            "capability_count": self.capabilities.len() as u64,
            "proof_receipt_count": self.proof_receipts.len() as u64,
            "gas_sponsorship_count": self.gas_sponsorships.len() as u64,
            "call_receipt_count": self.call_receipts.len() as u64,
            "token_ledger_count": self.token_ledgers.len() as u64,
            "swap_pool_count": self.swap_pools.len() as u64,
            "lending_market_count": self.lending_markets.len() as u64,
        })
    }

    pub fn state_root(&self) -> String {
        private_contracts_state_root_from_record(
            &self.public_record_without_state_root(&self.roots()),
        )
    }

    pub fn validate(&self) -> PrivateContractResult<String> {
        self.config.validate()?;
        for deployment in self.deployments.values() {
            deployment.validate()?;
        }
        for slot in self.encrypted_slots.values() {
            slot.validate()?;
        }
        for event in self.event_logs.values() {
            event.validate()?;
        }
        for grant in self.session_grants.values() {
            grant.validate()?;
        }
        for capability in self.capabilities.values() {
            capability.validate()?;
        }
        for decision in self.access_decisions.values() {
            decision.validate()?;
        }
        for proof in self.proof_receipts.values() {
            proof.validate()?;
        }
        for invocation in self.precompile_invocations.values() {
            invocation.validate()?;
        }
        for sponsorship in self.gas_sponsorships.values() {
            sponsorship.validate()?;
        }
        for receipt in self.call_receipts.values() {
            receipt.validate()?;
        }
        for ledger in self.token_ledgers.values() {
            ledger.validate()?;
        }
        for pool in self.swap_pools.values() {
            pool.validate()?;
        }
        for market in self.lending_markets.values() {
            market.validate()?;
        }
        for record in self.devnet_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }
}

pub fn private_contracts_state_root_from_record(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-CONTRACTS-STATE", record)
}

pub fn private_contracts_state_root(state: &PrivateContractsState) -> String {
    state.state_root()
}

pub fn private_contract_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn private_contract_empty_root(domain: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID)], 32)
}

pub fn private_contract_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn private_contract_string_set_root(domain: &str, values: &[String]) -> String {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    let leaves = values
        .into_iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn private_contract_account_commitment(label: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-ACCOUNT-COMMITMENT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

pub fn private_contract_session_key_root(label: &str, height: u64, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-SESSION-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_recovery_key_root(label: &str, nonce: u64) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-RECOVERY-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_replay_domain_root(
    owner_commitment: &str,
    delegate_commitment: &str,
    context_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-REPLAY-DOMAIN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(delegate_commitment),
            HashPart::Str(context_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_slot_key_commitment(
    contract_id: &str,
    namespace: &str,
    logical_key: &str,
    recipient_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-SLOT-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(namespace),
            HashPart::Str(logical_key),
            HashPart::Str(recipient_root),
        ],
        32,
    )
}

pub fn private_contract_slot_value_commitment(
    contract_id: &str,
    key_commitment: &str,
    value: &Value,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-SLOT-VALUE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(key_commitment),
            HashPart::Json(value),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_ciphertext_hash(payload: &Value) -> String {
    private_contract_payload_root("PRIVATE-CONTRACT-CIPHERTEXT", payload)
}

pub fn encrypted_state_slot_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-STATE-SLOT-ID", record)
}

pub fn encrypted_state_slot_root(slot: &EncryptedStateSlot) -> String {
    private_contract_payload_root("PRIVATE-STATE-SLOT", &slot.public_record())
}

pub fn encrypted_state_slot_root_from_slice(values: &[EncryptedStateSlot]) -> String {
    merkle_root(
        "PRIVATE-STATE-SLOT",
        &values
            .iter()
            .map(EncryptedStateSlot::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn encrypted_state_slot_root_from_map(values: &BTreeMap<String, EncryptedStateSlot>) -> String {
    encrypted_state_slot_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn encrypted_state_slot_identity_record(
    contract_id: &str,
    namespace: &str,
    key_commitment: &str,
    value_commitment: &str,
    ciphertext_hash: &str,
    recipient_root: &str,
    disclosure_policy_root: &str,
    visibility: &str,
    version: u64,
    created_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "encrypted_state_slot",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "namespace": namespace,
        "key_commitment": key_commitment,
        "value_commitment": value_commitment,
        "ciphertext_hash": ciphertext_hash,
        "recipient_root": recipient_root,
        "disclosure_policy_root": disclosure_policy_root,
        "visibility": visibility,
        "version": version,
        "created_at_height": created_at_height,
        "nonce": nonce,
    })
}

#[allow(clippy::too_many_arguments)]
fn private_event_identity_record(
    contract_id: &str,
    call_id: &str,
    event_name: &str,
    event_index: u64,
    visibility: &str,
    payload_commitment: &str,
    encrypted_payload_hash: &str,
    public_summary: &Value,
    disclosure_root: &str,
    previous_event_root: &str,
    emitted_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "private_event",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "call_id": call_id,
        "event_name": event_name,
        "event_index": event_index,
        "visibility": visibility,
        "payload_commitment": payload_commitment,
        "encrypted_payload_hash": encrypted_payload_hash,
        "public_summary": public_summary,
        "disclosure_root": disclosure_root,
        "previous_event_root": previous_event_root,
        "emitted_at_height": emitted_at_height,
        "nonce": nonce,
    })
}

pub fn private_event_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-EVENT-ID", record)
}

pub fn private_event_chain_root(
    event_id: &str,
    previous_event_root: &str,
    record: &Value,
) -> String {
    domain_hash(
        "PRIVATE-EVENT-CHAIN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_id),
            HashPart::Str(previous_event_root),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn private_event_root(event: &PrivateEventLog) -> String {
    private_contract_payload_root("PRIVATE-EVENT", &event.public_record())
}

pub fn private_event_root_from_slice(values: &[PrivateEventLog]) -> String {
    merkle_root(
        "PRIVATE-EVENT",
        &values
            .iter()
            .map(PrivateEventLog::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_event_root_from_map(values: &BTreeMap<String, PrivateEventLog>) -> String {
    private_event_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn pq_authorization_session_identity_record(
    owner_commitment: &str,
    delegate_commitment: &str,
    session_public_key_root: &str,
    recovery_key_root: &str,
    context_root: &str,
    allowed_contract_root: &str,
    capability_root: &str,
    replay_domain_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "pq_authorization_session",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "auth_scheme": PRIVATE_CONTRACTS_PQ_AUTH_SCHEME,
        "owner_commitment": owner_commitment,
        "delegate_commitment": delegate_commitment,
        "session_public_key_root": session_public_key_root,
        "recovery_key_root": recovery_key_root,
        "context_root": context_root,
        "allowed_contract_root": allowed_contract_root,
        "capability_root": capability_root,
        "replay_domain_root": replay_domain_root,
        "opened_at_height": opened_at_height,
        "expires_at_height": expires_at_height,
        "nonce": nonce,
    })
}

fn pq_authorization_session_unsigned_record(session_id: &str, identity: &Value) -> Value {
    json!({
        "kind": "pq_authorization_session_unsigned",
        "chain_id": CHAIN_ID,
        "session_id": session_id,
        "identity": identity,
    })
}

pub fn pq_authorization_session_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-PQ-SESSION-ID", record)
}

pub fn pq_authorization_session_root(session: &PqAuthorizationSession) -> String {
    private_contract_payload_root("PRIVATE-PQ-SESSION", &session.public_record())
}

pub fn pq_authorization_session_root_from_map(
    values: &BTreeMap<String, PqAuthorizationSession>,
) -> String {
    merkle_root(
        "PRIVATE-PQ-SESSION",
        &values
            .values()
            .map(PqAuthorizationSession::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn session_capability_grant_identity_record(
    session_id: &str,
    grantee_commitment: &str,
    contract_id: &str,
    capability: &str,
    selector_root: &str,
    spend_limit_units: u64,
    issued_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "session_capability_grant",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "session_id": session_id,
        "grantee_commitment": grantee_commitment,
        "contract_id": contract_id,
        "capability": capability,
        "selector_root": selector_root,
        "spend_limit_units": spend_limit_units,
        "issued_at_height": issued_at_height,
        "expires_at_height": expires_at_height,
        "nonce": nonce,
    })
}

pub fn session_capability_grant_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-SESSION-GRANT-ID", record)
}

pub fn session_capability_grant_root(grant: &SessionCapabilityGrant) -> String {
    private_contract_payload_root("PRIVATE-SESSION-GRANT", &grant.public_record())
}

pub fn session_capability_grant_root_from_map(
    values: &BTreeMap<String, SessionCapabilityGrant>,
) -> String {
    merkle_root(
        "PRIVATE-SESSION-GRANT",
        &values
            .values()
            .map(SessionCapabilityGrant::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_contract_capability_kind_root(values: &[CapabilityKind]) -> String {
    let mut names = values
        .iter()
        .map(CapabilityKind::as_str)
        .collect::<Vec<_>>();
    names.sort();
    names.dedup();
    private_contract_string_set_root("PRIVATE-CAPABILITY-KIND", &names)
}

#[allow(clippy::too_many_arguments)]
fn access_control_capability_identity_record(
    subject_commitment: &str,
    contract_id: &str,
    capability: &str,
    selector_root: &str,
    spending_limit_units: u64,
    created_at_height: u64,
    expires_at_height: u64,
    revocation_root: &str,
) -> Value {
    json!({
        "kind": "access_control_capability",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "subject_commitment": subject_commitment,
        "contract_id": contract_id,
        "capability": capability,
        "selector_root": selector_root,
        "spending_limit_units": spending_limit_units,
        "created_at_height": created_at_height,
        "expires_at_height": expires_at_height,
        "revocation_root": revocation_root,
    })
}

pub fn access_control_capability_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-CAPABILITY-ID", record)
}

pub fn access_control_capability_root(capability: &AccessControlCapability) -> String {
    private_contract_payload_root("PRIVATE-CAPABILITY", &capability.public_record())
}

pub fn access_control_capability_root_from_slice(values: &[AccessControlCapability]) -> String {
    merkle_root(
        "PRIVATE-CAPABILITY",
        &values
            .iter()
            .map(AccessControlCapability::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn access_control_capability_root_from_map(
    values: &BTreeMap<String, AccessControlCapability>,
) -> String {
    access_control_capability_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn access_decision_identity_record(
    capability_id: &str,
    session_id: &str,
    subject_commitment: &str,
    contract_id: &str,
    selector: &str,
    requested_units: u64,
    decision: &str,
    reason_root: &str,
    decided_at_height: u64,
) -> Value {
    json!({
        "kind": "access_decision",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "capability_id": capability_id,
        "session_id": session_id,
        "subject_commitment": subject_commitment,
        "contract_id": contract_id,
        "selector": selector,
        "requested_units": requested_units,
        "decision": decision,
        "reason_root": reason_root,
        "decided_at_height": decided_at_height,
    })
}

pub fn access_decision_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-ACCESS-DECISION-ID", record)
}

pub fn access_decision_root(decision: &AccessDecisionReceipt) -> String {
    private_contract_payload_root("PRIVATE-ACCESS-DECISION", &decision.public_record())
}

pub fn access_decision_root_from_map(values: &BTreeMap<String, AccessDecisionReceipt>) -> String {
    merkle_root(
        "PRIVATE-ACCESS-DECISION",
        &values
            .values()
            .map(AccessDecisionReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn zk_precompile_proof_identity_record(
    proof_kind: &str,
    proof_system: &str,
    verifier_key_root: &str,
    public_input_root: &str,
    private_witness_root: &str,
    proof_root: &str,
    precompile_address: &str,
    gas_used: u64,
    produced_at_height: u64,
    expires_at_height: u64,
) -> Value {
    json!({
        "kind": "zk_precompile_proof_receipt",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "proof_kind": proof_kind,
        "proof_system": proof_system,
        "verifier_key_root": verifier_key_root,
        "public_input_root": public_input_root,
        "private_witness_root": private_witness_root,
        "proof_root": proof_root,
        "precompile_address": precompile_address,
        "gas_used": gas_used,
        "produced_at_height": produced_at_height,
        "expires_at_height": expires_at_height,
    })
}

pub fn private_contract_zk_proof_root(
    proof_kind: &str,
    proof_system: &str,
    verifier_key_root: &str,
    public_input_root: &str,
    private_witness_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-ZK-PROOF-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(proof_kind),
            HashPart::Str(proof_system),
            HashPart::Str(verifier_key_root),
            HashPart::Str(public_input_root),
            HashPart::Str(private_witness_root),
        ],
        32,
    )
}

pub fn zk_precompile_proof_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-ZK-PROOF-ID", record)
}

pub fn zk_precompile_proof_root(proof: &ZkPrecompileProofReceipt) -> String {
    private_contract_payload_root("PRIVATE-ZK-PROOF", &proof.public_record())
}

pub fn zk_precompile_proof_root_from_slice(values: &[ZkPrecompileProofReceipt]) -> String {
    merkle_root(
        "PRIVATE-ZK-PROOF",
        &values
            .iter()
            .map(ZkPrecompileProofReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn zk_precompile_proof_root_from_map(
    values: &BTreeMap<String, ZkPrecompileProofReceipt>,
) -> String {
    zk_precompile_proof_root_from_slice(&values.values().cloned().collect::<Vec<_>>())
}

#[allow(clippy::too_many_arguments)]
fn precompile_invocation_identity_record(
    call_id: &str,
    precompile_address: &str,
    proof_receipt_id: &str,
    input_root: &str,
    output_root: &str,
    gas_charged: u64,
    invoked_at_height: u64,
    status: &str,
) -> Value {
    json!({
        "kind": "precompile_invocation",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "call_id": call_id,
        "precompile_address": precompile_address,
        "proof_receipt_id": proof_receipt_id,
        "input_root": input_root,
        "output_root": output_root,
        "gas_charged": gas_charged,
        "invoked_at_height": invoked_at_height,
        "status": status,
    })
}

pub fn precompile_invocation_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-PRECOMPILE-ID", record)
}

pub fn precompile_invocation_root(invocation: &PrecompileInvocation) -> String {
    private_contract_payload_root("PRIVATE-PRECOMPILE", &invocation.public_record())
}

pub fn precompile_invocation_root_from_map(
    values: &BTreeMap<String, PrecompileInvocation>,
) -> String {
    merkle_root(
        "PRIVATE-PRECOMPILE",
        &values
            .values()
            .map(PrecompileInvocation::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn gas_sponsorship_identity_record(
    sponsor_commitment: &str,
    scope: &str,
    scope_value: &str,
    fee_asset_id: &str,
    epoch_start_height: u64,
    epoch_end_height: u64,
    budget_units: u64,
    max_units_per_call: u64,
    rebate_bps: u64,
    low_fee_lane_root: &str,
) -> Value {
    json!({
        "kind": "gas_sponsorship_policy",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "sponsor_commitment": sponsor_commitment,
        "scope": scope,
        "scope_value": scope_value,
        "fee_asset_id": fee_asset_id,
        "epoch_start_height": epoch_start_height,
        "epoch_end_height": epoch_end_height,
        "budget_units": budget_units,
        "max_units_per_call": max_units_per_call,
        "rebate_bps": rebate_bps,
        "low_fee_lane_root": low_fee_lane_root,
    })
}

pub fn gas_sponsorship_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-GAS-SPONSORSHIP-ID", record)
}

pub fn gas_sponsorship_root(policy: &GasSponsorshipPolicy) -> String {
    private_contract_payload_root("PRIVATE-GAS-SPONSORSHIP", &policy.public_record())
}

pub fn gas_sponsorship_root_from_map(values: &BTreeMap<String, GasSponsorshipPolicy>) -> String {
    merkle_root(
        "PRIVATE-GAS-SPONSORSHIP",
        &values
            .values()
            .map(GasSponsorshipPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn gas_sponsorship_quote_id(
    sponsorship_id: &str,
    call_id: &str,
    sponsored_units: u64,
    rebate_bps: u64,
) -> String {
    domain_hash(
        "PRIVATE-GAS-SPONSORSHIP-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsorship_id),
            HashPart::Str(call_id),
            HashPart::Int(sponsored_units as i128),
            HashPart::Int(rebate_bps as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_contract_template_identity_record(
    kind: &str,
    template_name: &str,
    version: u64,
    code_hash: &str,
    abi_root: &str,
    selector_root: &str,
    required_capability_root: &str,
    precompile_root: &str,
    max_gas: u64,
    private_state: bool,
) -> Value {
    json!({
        "kind": "private_contract_template",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_kind": kind,
        "template_name": template_name,
        "version": version,
        "code_hash": code_hash,
        "abi_root": abi_root,
        "selector_root": selector_root,
        "required_capability_root": required_capability_root,
        "precompile_root": precompile_root,
        "max_gas": max_gas,
        "private_state": private_state,
    })
}

pub fn private_contract_code_hash(
    kind: &str,
    template_name: &str,
    version: u64,
    abi_root: &str,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-CODE-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(template_name),
            HashPart::Int(version as i128),
            HashPart::Str(abi_root),
        ],
        32,
    )
}

pub fn private_contract_template_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-CONTRACT-TEMPLATE-ID", record)
}

pub fn private_contract_template_root(template: &PrivateContractTemplate) -> String {
    private_contract_payload_root("PRIVATE-CONTRACT-TEMPLATE", &template.public_record())
}

#[allow(clippy::too_many_arguments)]
fn private_contract_deployment_identity_record(
    template_id: &str,
    code_hash: &str,
    owner_commitment: &str,
    admin_capability_root: &str,
    slot_root: &str,
    event_root: &str,
    metadata_root: &str,
    deployed_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "private_contract_deployment",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "template_id": template_id,
        "code_hash": code_hash,
        "owner_commitment": owner_commitment,
        "admin_capability_root": admin_capability_root,
        "slot_root": slot_root,
        "event_root": event_root,
        "metadata_root": metadata_root,
        "deployed_at_height": deployed_at_height,
        "nonce": nonce,
    })
}

pub fn private_contract_deployment_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-CONTRACT-DEPLOYMENT-ID", record)
}

pub fn private_contract_deployment_root(deployment: &PrivateContractDeployment) -> String {
    private_contract_payload_root("PRIVATE-CONTRACT-DEPLOYMENT", &deployment.public_record())
}

pub fn private_contract_deployment_root_from_map(
    values: &BTreeMap<String, PrivateContractDeployment>,
) -> String {
    merkle_root(
        "PRIVATE-CONTRACT-DEPLOYMENT",
        &values
            .values()
            .map(PrivateContractDeployment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_contract_args_commitment(
    contract_id: &str,
    selector: &str,
    args: &Value,
    private_args: bool,
) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-ARGS-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
            HashPart::Json(args),
            HashPart::Int(private_args as i128),
        ],
        32,
    )
}

pub fn private_contract_low_fee_lane(contract_id: &str, selector: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-LOW-FEE-LANE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(contract_id),
            HashPart::Str(selector),
        ],
        16,
    )
}

pub fn private_contract_fee_units(gas_used: u64, private_args: bool) -> u64 {
    let privacy_surcharge = if private_args { 2 } else { 1 };
    gas_used
        .saturating_mul(privacy_surcharge)
        .saturating_add(999)
        / 1_000
        + 1
}

pub fn estimate_private_call_gas(
    selector: &str,
    args: &Value,
    private_args: bool,
    gas_limit: u64,
) -> PrivateContractResult<u64> {
    let selector_cost = 2_500 + selector.len() as u64 * 10;
    let arg_cost = json_size(args) as u64 * if private_args { 20 } else { 8 };
    let proof_cost = if private_args { 18_000 } else { 7_500 };
    let estimated = selector_cost
        .saturating_add(arg_cost)
        .saturating_add(proof_cost);
    if estimated == 0 || estimated > gas_limit {
        return Err("private call estimated gas exceeds limit".to_string());
    }
    Ok(estimated)
}

#[allow(clippy::too_many_arguments)]
fn shielded_contract_call_identity_record(
    contract_id: &str,
    selector: &str,
    args_commitment: &str,
    encrypted_args_hash: &str,
    caller_commitment: &str,
    session_id: &str,
    capability_id: &str,
    gas_limit: u64,
    gas_used: u64,
    fee_asset_id: &str,
    fee_units: u64,
    low_fee_lane: &str,
    private_args: bool,
    submitted_at_height: u64,
    expires_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "shielded_contract_call",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "selector": selector,
        "args_commitment": args_commitment,
        "encrypted_args_hash": encrypted_args_hash,
        "caller_commitment": caller_commitment,
        "session_id": session_id,
        "capability_id": capability_id,
        "gas_limit": gas_limit,
        "gas_used": gas_used,
        "fee_asset_id": fee_asset_id,
        "fee_units": fee_units,
        "low_fee_lane": low_fee_lane,
        "private_args": private_args,
        "submitted_at_height": submitted_at_height,
        "expires_at_height": expires_at_height,
        "nonce": nonce,
    })
}

fn shielded_contract_call_unsigned_record(
    call_id: &str,
    identity: &Value,
    proof: &PrivacyProof,
) -> Value {
    json!({
        "kind": "shielded_contract_call_unsigned",
        "chain_id": CHAIN_ID,
        "call_id": call_id,
        "identity": identity,
        "proof": proof.public_record(),
    })
}

pub fn shielded_contract_call_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-CALL-ID", record)
}

pub fn shielded_contract_call_root(call: &ShieldedContractCall) -> String {
    private_contract_payload_root("PRIVATE-CALL", &call.public_record())
}

#[allow(clippy::too_many_arguments)]
fn shielded_call_proof_context(
    call_id: &str,
    contract_id: &str,
    selector: &str,
    args_commitment: &str,
    encrypted_args_hash: &str,
    caller_commitment: &str,
    gas_used: u64,
    fee_units: u64,
    args: &Value,
    private_args: bool,
) -> (Value, Value) {
    let public_inputs = json!({
        "kind": "shielded_call_public_inputs",
        "chain_id": CHAIN_ID,
        "call_id": call_id,
        "contract_id": contract_id,
        "selector": selector,
        "args_commitment": args_commitment,
        "encrypted_args_hash": encrypted_args_hash,
        "caller_commitment": caller_commitment,
        "gas_used": gas_used,
        "fee_units": fee_units,
        "private_args": private_args,
    });
    let private_witnesses = json!({
        "args": if private_args { args.clone() } else { Value::Null },
        "devnet_auth_bytes": DEVNET_AUTH_BYTES,
        "privacy_proof_bytes": DEVNET_PRIVACY_PROOF_BYTES,
    });
    (public_inputs, private_witnesses)
}

#[allow(clippy::too_many_arguments)]
fn shielded_execution_receipt_identity_record(
    call_id: &str,
    contract_id: &str,
    selector: &str,
    pre_state_root: &str,
    post_state_root: &str,
    slot_write_root: &str,
    event_root: &str,
    proof_receipt_root: &str,
    access_decision_id: &str,
    gas_used: u64,
    fee_units: u64,
    sponsored_units: u64,
    status: &str,
    executed_at_height: u64,
) -> Value {
    json!({
        "kind": "shielded_contract_execution_receipt",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "call_id": call_id,
        "contract_id": contract_id,
        "selector": selector,
        "pre_state_root": pre_state_root,
        "post_state_root": post_state_root,
        "slot_write_root": slot_write_root,
        "event_root": event_root,
        "proof_receipt_root": proof_receipt_root,
        "access_decision_id": access_decision_id,
        "gas_used": gas_used,
        "fee_units": fee_units,
        "sponsored_units": sponsored_units,
        "status": status,
        "executed_at_height": executed_at_height,
    })
}

pub fn shielded_execution_receipt_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-EXECUTION-RECEIPT-ID", record)
}

pub fn shielded_execution_receipt_root(receipt: &ShieldedContractExecutionReceipt) -> String {
    private_contract_payload_root("PRIVATE-EXECUTION-RECEIPT", &receipt.public_record())
}

pub fn shielded_execution_receipt_root_from_map(
    values: &BTreeMap<String, ShieldedContractExecutionReceipt>,
) -> String {
    merkle_root(
        "PRIVATE-EXECUTION-RECEIPT",
        &values
            .values()
            .map(ShieldedContractExecutionReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn confidential_balance_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-BALANCE-ID", record)
}

pub fn confidential_balance_root(balance: &ConfidentialBalanceCommitment) -> String {
    private_contract_payload_root("PRIVATE-BALANCE", &balance.public_record())
}

pub fn confidential_balance_root_from_slice(values: &[ConfidentialBalanceCommitment]) -> String {
    merkle_root(
        "PRIVATE-BALANCE",
        &values
            .iter()
            .map(ConfidentialBalanceCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn confidential_balance_identity_record(
    owner_commitment: &str,
    asset_id: &str,
    amount_commitment: &str,
    blinding_root: &str,
    note_root: &str,
    slot_id: &str,
    updated_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "confidential_balance",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "owner_commitment": owner_commitment,
        "asset_id": asset_id,
        "amount_commitment": amount_commitment,
        "blinding_root": blinding_root,
        "note_root": note_root,
        "slot_id": slot_id,
        "updated_at_height": updated_at_height,
        "nonce": nonce,
    })
}

pub fn private_contract_amount_blinding(
    owner_commitment: &str,
    asset_id: &str,
    amount: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-AMOUNT-BLINDING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Int(amount as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_amount_commitment(amount: u64, blinding_root: &str) -> String {
    domain_hash(
        "PRIVATE-AMOUNT-COMMITMENT",
        &[HashPart::Int(amount as i128), HashPart::Str(blinding_root)],
        32,
    )
}

pub fn private_contract_balance_note_root(
    owner_commitment: &str,
    asset_id: &str,
    amount_commitment: &str,
    slot_id: &str,
    height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "PRIVATE-BALANCE-NOTE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(amount_commitment),
            HashPart::Str(slot_id),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_token_ledger_identity_record(
    contract_id: &str,
    asset_id: &str,
    symbol: &str,
    decimals: u8,
    issuer_commitment: &str,
    supply_commitment: &str,
    supply_blinding_root: &str,
    balance_root: &str,
    allowance_root: &str,
    transfer_policy_root: &str,
    created_at_height: u64,
) -> Value {
    json!({
        "kind": "private_token_ledger",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "asset_id": asset_id,
        "symbol": symbol,
        "decimals": decimals,
        "issuer_commitment": issuer_commitment,
        "supply_commitment": supply_commitment,
        "supply_blinding_root": supply_blinding_root,
        "balance_root": balance_root,
        "allowance_root": allowance_root,
        "transfer_policy_root": transfer_policy_root,
        "created_at_height": created_at_height,
    })
}

pub fn private_token_ledger_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-TOKEN-LEDGER-ID", record)
}

pub fn private_token_ledger_root(ledger: &PrivateTokenLedger) -> String {
    private_contract_payload_root("PRIVATE-TOKEN-LEDGER", &ledger.public_record())
}

pub fn private_token_ledger_root_from_map(values: &BTreeMap<String, PrivateTokenLedger>) -> String {
    merkle_root(
        "PRIVATE-TOKEN-LEDGER",
        &values
            .values()
            .map(PrivateTokenLedger::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn private_token_operation_identity_record(
    contract_id: &str,
    asset_id: &str,
    operation: &str,
    party_commitment: &str,
    amount_commitment: &str,
    supply_commitment: &str,
    balance_root: &str,
    operated_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "private_token_operation",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "asset_id": asset_id,
        "operation": operation,
        "party_commitment": party_commitment,
        "amount_commitment": amount_commitment,
        "supply_commitment": supply_commitment,
        "balance_root": balance_root,
        "operated_at_height": operated_at_height,
        "nonce": nonce,
    })
}

pub fn private_token_operation_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-TOKEN-OP-ID", record)
}

pub fn private_token_operation_root(receipt: &PrivateTokenOperationReceipt) -> String {
    private_contract_payload_root("PRIVATE-TOKEN-OP", &receipt.public_record())
}

#[allow(clippy::too_many_arguments)]
fn private_swap_pool_identity_record(
    contract_id: &str,
    asset_a: &str,
    asset_b: &str,
    lp_asset_id: &str,
    curve: &str,
    fee_bps: u64,
    reserve_a_commitment: &str,
    reserve_b_commitment: &str,
    invariant_commitment: &str,
    lp_supply_commitment: &str,
    oracle_root: &str,
) -> Value {
    json!({
        "kind": "private_swap_pool",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "asset_a": asset_a,
        "asset_b": asset_b,
        "lp_asset_id": lp_asset_id,
        "curve": curve,
        "fee_bps": fee_bps,
        "reserve_a_commitment": reserve_a_commitment,
        "reserve_b_commitment": reserve_b_commitment,
        "invariant_commitment": invariant_commitment,
        "lp_supply_commitment": lp_supply_commitment,
        "oracle_root": oracle_root,
    })
}

pub fn private_swap_pool_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-SWAP-POOL-ID", record)
}

pub fn private_swap_pool_root(pool: &PrivateSwapPool) -> String {
    private_contract_payload_root("PRIVATE-SWAP-POOL", &pool.public_record())
}

pub fn private_swap_pool_root_from_map(values: &BTreeMap<String, PrivateSwapPool>) -> String {
    merkle_root(
        "PRIVATE-SWAP-POOL",
        &values
            .values()
            .map(PrivateSwapPool::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_swap_quote_id(
    pool_id: &str,
    input_asset: &str,
    output_asset: &str,
    amount_in: u64,
    amount_out: u64,
    fee_units: u64,
) -> String {
    domain_hash(
        "PRIVATE-SWAP-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(pool_id),
            HashPart::Str(input_asset),
            HashPart::Str(output_asset),
            HashPart::Int(amount_in as i128),
            HashPart::Int(amount_out as i128),
            HashPart::Int(fee_units as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
fn private_swap_execution_identity_record(
    pool_id: &str,
    quote_root: &str,
    reserve_a_commitment: &str,
    reserve_b_commitment: &str,
    invariant_commitment: &str,
    proof_root: &str,
    nonce: u64,
) -> Value {
    json!({
        "kind": "private_swap_execution",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "pool_id": pool_id,
        "quote_root": quote_root,
        "reserve_a_commitment": reserve_a_commitment,
        "reserve_b_commitment": reserve_b_commitment,
        "invariant_commitment": invariant_commitment,
        "proof_root": proof_root,
        "nonce": nonce,
    })
}

pub fn private_swap_execution_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-SWAP-EXECUTION-ID", record)
}

pub fn private_swap_execution_root(execution: &PrivateSwapExecution) -> String {
    private_contract_payload_root("PRIVATE-SWAP-EXECUTION", &execution.public_record())
}

#[allow(clippy::too_many_arguments)]
fn lending_position_identity_record(
    owner_commitment: &str,
    market_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    collateral_commitment: &str,
    debt_commitment: &str,
    health_factor_bps: u64,
    position_kind: &str,
    slot_id: &str,
    updated_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "confidential_lending_position",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "owner_commitment": owner_commitment,
        "market_id": market_id,
        "collateral_asset_id": collateral_asset_id,
        "debt_asset_id": debt_asset_id,
        "collateral_commitment": collateral_commitment,
        "debt_commitment": debt_commitment,
        "health_factor_bps": health_factor_bps,
        "position_kind": position_kind,
        "slot_id": slot_id,
        "updated_at_height": updated_at_height,
        "nonce": nonce,
    })
}

pub fn lending_position_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-LENDING-POSITION-ID", record)
}

pub fn lending_position_root(position: &ConfidentialLendingPosition) -> String {
    private_contract_payload_root("PRIVATE-LENDING-POSITION", &position.public_record())
}

pub fn lending_position_root_from_slice(values: &[ConfidentialLendingPosition]) -> String {
    merkle_root(
        "PRIVATE-LENDING-POSITION",
        &values
            .iter()
            .map(ConfidentialLendingPosition::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn private_lending_market_identity_record(
    contract_id: &str,
    collateral_asset_id: &str,
    debt_asset_id: &str,
    rate_model: &str,
    collateral_factor_bps: u64,
    reserve_factor_bps: u64,
    liquidation_bonus_bps: u64,
    supplied_commitment: &str,
    borrowed_commitment: &str,
    reserve_commitment: &str,
    position_root: &str,
    oracle_root: &str,
) -> Value {
    json!({
        "kind": "private_lending_market",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "contract_id": contract_id,
        "collateral_asset_id": collateral_asset_id,
        "debt_asset_id": debt_asset_id,
        "rate_model": rate_model,
        "collateral_factor_bps": collateral_factor_bps,
        "reserve_factor_bps": reserve_factor_bps,
        "liquidation_bonus_bps": liquidation_bonus_bps,
        "supplied_commitment": supplied_commitment,
        "borrowed_commitment": borrowed_commitment,
        "reserve_commitment": reserve_commitment,
        "position_root": position_root,
        "oracle_root": oracle_root,
    })
}

pub fn private_lending_market_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-LENDING-MARKET-ID", record)
}

pub fn private_lending_market_root(market: &PrivateLendingMarket) -> String {
    private_contract_payload_root("PRIVATE-LENDING-MARKET", &market.public_record())
}

pub fn private_lending_market_root_from_map(
    values: &BTreeMap<String, PrivateLendingMarket>,
) -> String {
    merkle_root(
        "PRIVATE-LENDING-MARKET",
        &values
            .values()
            .map(PrivateLendingMarket::public_record)
            .collect::<Vec<_>>(),
    )
}

#[allow(clippy::too_many_arguments)]
fn private_lending_receipt_identity_record(
    market_id: &str,
    action: &str,
    owner_commitment: &str,
    collateral_delta_commitment: &str,
    debt_delta_commitment: &str,
    position_root: &str,
    supplied_commitment: &str,
    borrowed_commitment: &str,
    operated_at_height: u64,
    nonce: u64,
) -> Value {
    json!({
        "kind": "private_lending_receipt",
        "chain_id": CHAIN_ID,
        "protocol_version": PRIVATE_CONTRACTS_PROTOCOL_VERSION,
        "market_id": market_id,
        "action": action,
        "owner_commitment": owner_commitment,
        "collateral_delta_commitment": collateral_delta_commitment,
        "debt_delta_commitment": debt_delta_commitment,
        "position_root": position_root,
        "supplied_commitment": supplied_commitment,
        "borrowed_commitment": borrowed_commitment,
        "operated_at_height": operated_at_height,
        "nonce": nonce,
    })
}

pub fn private_lending_receipt_id(record: &Value) -> String {
    private_contract_payload_root("PRIVATE-LENDING-RECEIPT-ID", record)
}

pub fn private_lending_receipt_root(receipt: &PrivateLendingReceipt) -> String {
    private_contract_payload_root("PRIVATE-LENDING-RECEIPT", &receipt.public_record())
}

pub fn private_devnet_record_id(
    label: &str,
    category: &str,
    payload_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "PRIVATE-DEVNET-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(category),
            HashPart::Str(payload_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn private_devnet_record_root(record: &PrivateDevnetRecord) -> String {
    private_contract_payload_root("PRIVATE-DEVNET-RECORD", &record.public_record())
}

pub fn private_devnet_record_root_from_map(
    values: &BTreeMap<String, PrivateDevnetRecord>,
) -> String {
    merkle_root(
        "PRIVATE-DEVNET-RECORD",
        &values
            .values()
            .map(PrivateDevnetRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_market_resource_for_shielded_contract_call(
    call: &ShieldedContractCall,
) -> FeeMarketResource {
    let mut fee_asset_ids = Vec::new();
    if !call.fee_asset_id.is_empty() {
        fee_asset_ids.push(call.fee_asset_id.clone());
    }
    FeeMarketResource {
        public_record: call.public_record(),
        execution_fuel: call.gas_used,
        privacy_proof_count: 1,
        contract_call_count: 1,
        observed_fee_units: call.fee_units,
        estimated_proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids,
        fee_lanes: vec![
            (
                "operation".to_string(),
                "shielded_contract_call".to_string(),
            ),
            ("contract".to_string(), call.contract_id.clone()),
            ("selector".to_string(), call.selector.clone()),
            ("low_fee_lane".to_string(), call.low_fee_lane.clone()),
        ],
    }
}

pub fn fee_market_resource_for_private_execution_receipt(
    receipt: &ShieldedContractExecutionReceipt,
    fee_asset_id: &str,
) -> FeeMarketResource {
    let mut fee_asset_ids = Vec::new();
    if !fee_asset_id.is_empty() {
        fee_asset_ids.push(fee_asset_id.to_string());
    }
    FeeMarketResource {
        public_record: receipt.public_record(),
        execution_fuel: receipt.gas_used,
        privacy_proof_count: 1,
        contract_call_count: 1,
        observed_fee_units: receipt.fee_units.saturating_sub(receipt.sponsored_units),
        estimated_proof_bytes: DEVNET_PRIVACY_PROOF_BYTES,
        authorization_count: 1,
        fee_asset_ids,
        fee_lanes: vec![
            (
                "operation".to_string(),
                "private_contract_execution".to_string(),
            ),
            ("contract".to_string(), receipt.contract_id.clone()),
            ("selector".to_string(), receipt.selector.clone()),
        ],
    }
}

pub fn sealed_payload(
    payload_kind: &str,
    domain: &str,
    recipient_root: &str,
    payload: &Value,
    height: u64,
    nonce: u64,
) -> Value {
    let payload_root = private_contract_payload_root("PRIVATE-SEALED-PAYLOAD-PLAINTEXT", payload);
    let aad_root = private_contract_payload_root(
        "PRIVATE-SEALED-PAYLOAD-AAD",
        &json!({
            "payload_kind": payload_kind,
            "domain": domain,
            "recipient_root": recipient_root,
            "height": height,
            "nonce": nonce,
        }),
    );
    let ciphertext_root = domain_hash(
        "PRIVATE-SEALED-PAYLOAD-CIPHERTEXT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_CONTRACTS_ENCRYPTION_SCHEME),
            HashPart::Str(payload_kind),
            HashPart::Str(domain),
            HashPart::Str(recipient_root),
            HashPart::Str(&payload_root),
            HashPart::Str(&aad_root),
            HashPart::Int(height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    );
    json!({
        "kind": "sealed_private_contract_payload",
        "chain_id": CHAIN_ID,
        "encryption_scheme": PRIVATE_CONTRACTS_ENCRYPTION_SCHEME,
        "payload_kind": payload_kind,
        "domain": domain,
        "recipient_root": recipient_root,
        "payload_root": payload_root,
        "aad_root": aad_root,
        "ciphertext_root": ciphertext_root,
        "height": height,
        "nonce": nonce,
    })
}

pub fn swap_invariant(reserve_a: u64, reserve_b: u64, curve: &SwapCurveKind) -> u64 {
    match curve {
        SwapCurveKind::ConstantProduct | SwapCurveKind::ConcentratedBand => {
            reserve_a.saturating_mul(reserve_b)
        }
        SwapCurveKind::Stable | SwapCurveKind::OraclePegged => reserve_a.saturating_add(reserve_b),
    }
}

pub fn constant_product_amount_out(reserve_in: u64, reserve_out: u64, amount_in: u64) -> u64 {
    if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
        return 0;
    }
    let numerator = amount_in.saturating_mul(reserve_out);
    let denominator = reserve_in.saturating_add(amount_in);
    if denominator == 0 {
        0
    } else {
        numerator / denominator
    }
}

pub fn stable_amount_out(reserve_in: u64, reserve_out: u64, amount_in: u64, fee_bps: u64) -> u64 {
    if reserve_in == 0 || reserve_out == 0 || amount_in == 0 {
        return 0;
    }
    let amount_after_fee = amount_in.saturating_sub(mul_bps(amount_in, fee_bps));
    amount_after_fee.min(reserve_out.saturating_sub(1))
}

pub fn lending_health_factor_bps(
    collateral_amount: u64,
    debt_amount: u64,
    collateral_factor_bps: u64,
) -> u64 {
    if debt_amount == 0 {
        return u64::MAX;
    }
    let adjusted_collateral = mul_bps(collateral_amount, collateral_factor_bps);
    ratio_bps(adjusted_collateral, debt_amount)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    numerator.saturating_mul(PRIVATE_CONTRACTS_MAX_BPS) / denominator
}

pub fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / PRIVATE_CONTRACTS_MAX_BPS
}

pub fn integer_sqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut left = 1_u64;
    let mut right = value.min(1 << 32);
    let mut answer = 1_u64;
    while left <= right {
        let mid = left + (right - left) / 2;
        if mid <= value / mid {
            answer = mid;
            left = mid.saturating_add(1);
        } else {
            right = mid.saturating_sub(1);
        }
    }
    answer
}

fn with_authorization(
    mut record: Value,
    authorization: &Authorization,
    include_signer_label: bool,
) -> Value {
    let object = record
        .as_object_mut()
        .expect("authorization record must be an object");
    if include_signer_label {
        object.insert(
            "signer_label".to_string(),
            Value::String(authorization.signer_label.clone()),
        );
    }
    object.insert(
        "auth_scheme".to_string(),
        Value::String(authorization.auth_scheme.clone()),
    );
    object.insert(
        "auth_public_key".to_string(),
        Value::String(authorization.auth_public_key.clone()),
    );
    object.insert(
        "auth_transcript_hash".to_string(),
        Value::String(authorization.auth_transcript_hash.clone()),
    );
    object.insert(
        "auth_signature".to_string(),
        Value::String(authorization.auth_signature.clone()),
    );
    record
}

fn json_size(value: &Value) -> usize {
    serde_json::to_string(value)
        .map(|encoded| encoded.len())
        .unwrap_or(0)
}

fn normalize_label(value: String) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

fn normalize_symbol(value: String) -> String {
    value.trim().to_ascii_uppercase()
}

fn normalize_unique_strings(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(normalize_label)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn ensure_non_empty(value: &str, label: &str) -> PrivateContractResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> PrivateContractResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_status(value: &str, allowed: &[&str], label: &str) -> PrivateContractResult<()> {
    if allowed.iter().any(|candidate| candidate == &value) {
        Ok(())
    } else {
        Err(format!("{label} is not supported: {value}"))
    }
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
    label: &str,
) -> PrivateContractResult<String> {
    if records.contains_key(&id) {
        return Err(format!("{label} already exists"));
    }
    records.insert(id.clone(), record);
    Ok(id)
}

fn insert_or_replace_record<T>(
    records: &mut BTreeMap<String, T>,
    id: String,
    record: T,
) -> PrivateContractResult<String> {
    records.insert(id.clone(), record);
    Ok(id)
}
