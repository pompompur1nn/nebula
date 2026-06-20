use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateAccountAbstractionRouterResult<T> = Result<T, String>;

pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION: &str =
    "nebula-private-account-abstraction-router-v1";
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEVNET_HEIGHT: u64 = 2_560;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_HASH_SUITE: &str = "SHAKE256-domain-separated";
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PQ_SESSION_SUITE: &str =
    "ML-DSA-65+SLH-DSA-SHAKE-128s-session-authorization";
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_ACCOUNT_PROOF_SUITE: &str =
    "private-account-nullifier-commitment-v1";
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PAYMASTER_SUITE: &str = "low-fee-paymaster-ticket-v1";
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_CALL_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 1_440;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_CALLS_PER_SESSION: u64 = 64;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MIN_PRIVACY_SET: u64 = 512;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_FEE_UNITS: u64 = 35_000;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_SPONSOR_BUDGET_UNITS: u64 = 2_500_000;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_CALL_GAS_UNITS: u64 = 500_000;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_ACTIVE_SESSIONS: usize = 512;
pub const PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_PENDING_CALLS: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRouterSessionKind {
    WalletRecovery,
    PrivateDefi,
    TokenTransfer,
    ContractDeployment,
    Governance,
    MoneroBridgeExit,
    EmergencyFeeRescue,
}

impl AccountRouterSessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRecovery => "wallet_recovery",
            Self::PrivateDefi => "private_defi",
            Self::TokenTransfer => "token_transfer",
            Self::ContractDeployment => "contract_deployment",
            Self::Governance => "governance",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::EmergencyFeeRescue => "emergency_fee_rescue",
        }
    }

    pub fn default_priority(self) -> u64 {
        match self {
            Self::EmergencyFeeRescue => 100,
            Self::MoneroBridgeExit => 92,
            Self::WalletRecovery => 88,
            Self::PrivateDefi => 82,
            Self::ContractDeployment => 76,
            Self::Governance => 70,
            Self::TokenTransfer => 64,
        }
    }

    pub fn requires_contract_allowlist(self) -> bool {
        matches!(
            self,
            Self::PrivateDefi | Self::ContractDeployment | Self::Governance
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Draft,
    Active,
    RateLimited,
    Suspended,
    Exhausted,
    Expired,
    Revoked,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_calls(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutedCallStatus {
    Pending,
    Sponsored,
    Admitted,
    Executed,
    Rejected,
    Expired,
    Challenged,
}

impl RoutedCallStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Sponsored => "sponsored",
            Self::Admitted => "admitted",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterTicketStatus {
    Reserved,
    PartiallySpent,
    Spent,
    Expired,
    Slashed,
}

impl PaymasterTicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PartiallySpent => "partially_spent",
            Self::Spent => "spent",
            Self::Expired => "expired",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterChallengeKind {
    InvalidSessionProof,
    ReplayNullifierReuse,
    PaymasterOverspend,
    ContractPolicyBypass,
    PqSignatureMismatch,
    PrivacySetTooSmall,
}

impl RouterChallengeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSessionProof => "invalid_session_proof",
            Self::ReplayNullifierReuse => "replay_nullifier_reuse",
            Self::PaymasterOverspend => "paymaster_overspend",
            Self::ContractPolicyBypass => "contract_policy_bypass",
            Self::PqSignatureMismatch => "pq_signature_mismatch",
            Self::PrivacySetTooSmall => "privacy_set_too_small",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAccountAbstractionRouterConfig {
    pub session_ttl_blocks: u64,
    pub call_ttl_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_calls_per_session: u64,
    pub min_privacy_set_size: u64,
    pub max_fee_units_per_call: u64,
    pub default_sponsor_budget_units: u64,
    pub default_call_gas_units: u64,
    pub max_active_sessions: usize,
    pub max_pending_calls: usize,
    pub allow_emergency_fee_rescue: bool,
    pub require_pq_dual_signature: bool,
}

impl PrivateAccountAbstractionRouterConfig {
    pub fn devnet() -> Self {
        Self {
            session_ttl_blocks: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_SESSION_TTL_BLOCKS,
            call_ttl_blocks: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_CALL_TTL_BLOCKS,
            replay_window_blocks: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_calls_per_session: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_CALLS_PER_SESSION,
            min_privacy_set_size: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MIN_PRIVACY_SET,
            max_fee_units_per_call: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_FEE_UNITS,
            default_sponsor_budget_units:
                PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_SPONSOR_BUDGET_UNITS,
            default_call_gas_units: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_CALL_GAS_UNITS,
            max_active_sessions: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_ACTIVE_SESSIONS,
            max_pending_calls: PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEFAULT_MAX_PENDING_CALLS,
            allow_emergency_fee_rescue: true,
            require_pq_dual_signature: true,
        }
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        if self.session_ttl_blocks == 0
            || self.call_ttl_blocks == 0
            || self.replay_window_blocks == 0
        {
            return Err("router ttl windows must be positive".to_string());
        }
        if self.max_calls_per_session == 0 {
            return Err("router max calls per session must be positive".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("router minimum privacy set must be positive".to_string());
        }
        if self.max_fee_units_per_call == 0 || self.default_sponsor_budget_units == 0 {
            return Err("router fee and sponsor budgets must be positive".to_string());
        }
        if self.max_active_sessions == 0 || self.max_pending_calls == 0 {
            return Err("router capacity limits must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_account_abstraction_router_config",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "session_ttl_blocks": self.session_ttl_blocks,
            "call_ttl_blocks": self.call_ttl_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_calls_per_session": self.max_calls_per_session,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_fee_units_per_call": self.max_fee_units_per_call,
            "default_sponsor_budget_units": self.default_sponsor_budget_units,
            "default_call_gas_units": self.default_call_gas_units,
            "max_active_sessions": self.max_active_sessions,
            "max_pending_calls": self.max_pending_calls,
            "allow_emergency_fee_rescue": self.allow_emergency_fee_rescue,
            "require_pq_dual_signature": self.require_pq_dual_signature,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAccountSession {
    pub session_id: String,
    pub session_kind: AccountRouterSessionKind,
    pub account_commitment: String,
    pub session_public_key_root: String,
    pub pq_signature_root: String,
    pub policy_root: String,
    pub contract_allowlist_root: String,
    pub replay_domain_root: String,
    pub privacy_set_size: u64,
    pub calls_used: u64,
    pub max_calls: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub priority: u64,
    pub status: SessionStatus,
}

impl ShieldedAccountSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_kind: AccountRouterSessionKind,
        account_commitment: &str,
        session_public_key_root: &str,
        pq_signature_root: &str,
        policy_root: &str,
        contract_allowlist_root: &str,
        replay_domain_root: &str,
        privacy_set_size: u64,
        created_at_height: u64,
        config: &PrivateAccountAbstractionRouterConfig,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if account_commitment.is_empty()
            || session_public_key_root.is_empty()
            || pq_signature_root.is_empty()
            || policy_root.is_empty()
            || replay_domain_root.is_empty()
        {
            return Err("router session commitments cannot be empty".to_string());
        }
        if session_kind.requires_contract_allowlist() && contract_allowlist_root.is_empty() {
            return Err("contract session requires allowlist root".to_string());
        }
        let expires_at_height = created_at_height.saturating_add(config.session_ttl_blocks);
        let session_id = router_id(
            "SESSION-ID",
            &[
                account_commitment,
                session_kind.as_str(),
                session_public_key_root,
                replay_domain_root,
            ],
            created_at_height,
        );
        let session = Self {
            session_id,
            session_kind,
            account_commitment: account_commitment.to_string(),
            session_public_key_root: session_public_key_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            policy_root: policy_root.to_string(),
            contract_allowlist_root: contract_allowlist_root.to_string(),
            replay_domain_root: replay_domain_root.to_string(),
            privacy_set_size,
            calls_used: 0,
            max_calls: config.max_calls_per_session,
            created_at_height,
            expires_at_height,
            priority: session_kind.default_priority(),
            status: SessionStatus::Active,
        };
        session.validate(config)?;
        Ok(session)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn can_route_call(&self, height: u64) -> bool {
        self.status.accepts_calls() && !self.expired_at(height) && self.calls_used < self.max_calls
    }

    pub fn validate(
        &self,
        config: &PrivateAccountAbstractionRouterConfig,
    ) -> PrivateAccountAbstractionRouterResult<()> {
        if self.session_id.is_empty()
            || self.account_commitment.is_empty()
            || self.session_public_key_root.is_empty()
            || self.pq_signature_root.is_empty()
            || self.policy_root.is_empty()
            || self.replay_domain_root.is_empty()
        {
            return Err("router session identifiers cannot be empty".to_string());
        }
        if self.session_kind.requires_contract_allowlist()
            && self.contract_allowlist_root.is_empty()
        {
            return Err("router session missing contract allowlist".to_string());
        }
        if self.privacy_set_size < config.min_privacy_set_size {
            return Err("router session privacy set below floor".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("router session expiration must be after creation".to_string());
        }
        if self.max_calls == 0 || self.calls_used > self.max_calls {
            return Err("router session call counter invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_account_session",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "session_kind": self.session_kind.as_str(),
            "account_commitment": self.account_commitment,
            "session_public_key_root": self.session_public_key_root,
            "pq_signature_root": self.pq_signature_root,
            "policy_root": self.policy_root,
            "contract_allowlist_root": self.contract_allowlist_root,
            "replay_domain_root": self.replay_domain_root,
            "privacy_set_size": self.privacy_set_size,
            "calls_used": self.calls_used,
            "max_calls": self.max_calls,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "priority": self.priority,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("SESSION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionAuthorization {
    pub authorization_id: String,
    pub session_id: String,
    pub signer_commitment: String,
    pub mldsa_signature_root: String,
    pub slhdsa_signature_root: String,
    pub scope_root: String,
    pub nonce_commitment: String,
    pub issued_at_height: u64,
    pub expires_at_height: u64,
}

impl PqSessionAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: &str,
        signer_commitment: &str,
        mldsa_signature_root: &str,
        slhdsa_signature_root: &str,
        scope_root: &str,
        nonce_commitment: &str,
        issued_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if session_id.is_empty()
            || signer_commitment.is_empty()
            || mldsa_signature_root.is_empty()
            || slhdsa_signature_root.is_empty()
            || scope_root.is_empty()
            || nonce_commitment.is_empty()
        {
            return Err("router authorization commitments cannot be empty".to_string());
        }
        if issued_at_height >= expires_at_height {
            return Err("router authorization expiration must be after issue height".to_string());
        }
        let authorization_id = router_id(
            "AUTHORIZATION-ID",
            &[session_id, signer_commitment, scope_root, nonce_commitment],
            issued_at_height,
        );
        Ok(Self {
            authorization_id,
            session_id: session_id.to_string(),
            signer_commitment: signer_commitment.to_string(),
            mldsa_signature_root: mldsa_signature_root.to_string(),
            slhdsa_signature_root: slhdsa_signature_root.to_string(),
            scope_root: scope_root.to_string(),
            nonce_commitment: nonce_commitment.to_string(),
            issued_at_height,
            expires_at_height,
        })
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        if self.authorization_id.is_empty()
            || self.session_id.is_empty()
            || self.signer_commitment.is_empty()
            || self.mldsa_signature_root.is_empty()
            || self.slhdsa_signature_root.is_empty()
            || self.scope_root.is_empty()
            || self.nonce_commitment.is_empty()
        {
            return Err("router authorization identifiers cannot be empty".to_string());
        }
        if self.issued_at_height >= self.expires_at_height {
            return Err("router authorization has invalid ttl".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "session_id": self.session_id,
            "signer_commitment": self.signer_commitment,
            "mldsa_signature_root": self.mldsa_signature_root,
            "slhdsa_signature_root": self.slhdsa_signature_root,
            "scope_root": self.scope_root,
            "nonce_commitment": self.nonce_commitment,
            "issued_at_height": self.issued_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("AUTHORIZATION", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeePaymasterTicket {
    pub ticket_id: String,
    pub sponsor_commitment: String,
    pub session_id: String,
    pub asset_id: String,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
    pub max_fee_units_per_call: u64,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PaymasterTicketStatus,
}

impl LowFeePaymasterTicket {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sponsor_commitment: &str,
        session_id: &str,
        asset_id: &str,
        reserved_fee_units: u64,
        max_fee_units_per_call: u64,
        policy_root: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if sponsor_commitment.is_empty()
            || session_id.is_empty()
            || asset_id.is_empty()
            || policy_root.is_empty()
        {
            return Err("paymaster ticket commitments cannot be empty".to_string());
        }
        if reserved_fee_units == 0 || max_fee_units_per_call == 0 {
            return Err("paymaster ticket fee limits must be positive".to_string());
        }
        if created_at_height >= expires_at_height {
            return Err("paymaster ticket expiration must be after creation".to_string());
        }
        let ticket_id = router_id(
            "PAYMASTER-TICKET-ID",
            &[sponsor_commitment, session_id, asset_id, policy_root],
            created_at_height,
        );
        Ok(Self {
            ticket_id,
            sponsor_commitment: sponsor_commitment.to_string(),
            session_id: session_id.to_string(),
            asset_id: asset_id.to_string(),
            reserved_fee_units,
            spent_fee_units: 0,
            max_fee_units_per_call,
            policy_root: policy_root.to_string(),
            created_at_height,
            expires_at_height,
            status: PaymasterTicketStatus::Reserved,
        })
    }

    pub fn available_fee_units(&self) -> u64 {
        self.reserved_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn can_spend(&self, fee_units: u64, height: u64) -> bool {
        matches!(
            self.status,
            PaymasterTicketStatus::Reserved | PaymasterTicketStatus::PartiallySpent
        ) && !self.expired_at(height)
            && fee_units <= self.max_fee_units_per_call
            && fee_units <= self.available_fee_units()
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        if self.ticket_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.session_id.is_empty()
            || self.asset_id.is_empty()
            || self.policy_root.is_empty()
        {
            return Err("paymaster ticket identifiers cannot be empty".to_string());
        }
        if self.reserved_fee_units == 0 || self.max_fee_units_per_call == 0 {
            return Err("paymaster ticket fee limits invalid".to_string());
        }
        if self.spent_fee_units > self.reserved_fee_units {
            return Err("paymaster ticket overspent".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("paymaster ticket ttl invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_paymaster_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "sponsor_commitment": self.sponsor_commitment,
            "session_id": self.session_id,
            "asset_id": self.asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "available_fee_units": self.available_fee_units(),
            "max_fee_units_per_call": self.max_fee_units_per_call,
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("PAYMASTER-TICKET", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutedPrivateCall {
    pub call_id: String,
    pub session_id: String,
    pub authorization_id: String,
    pub paymaster_ticket_id: String,
    pub contract_commitment: String,
    pub call_data_root: String,
    pub witness_root: String,
    pub replay_nullifier: String,
    pub fee_units: u64,
    pub gas_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: RoutedCallStatus,
}

impl RoutedPrivateCall {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: &str,
        authorization_id: &str,
        paymaster_ticket_id: &str,
        contract_commitment: &str,
        call_data_root: &str,
        witness_root: &str,
        replay_nullifier: &str,
        fee_units: u64,
        gas_units: u64,
        created_at_height: u64,
        config: &PrivateAccountAbstractionRouterConfig,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if session_id.is_empty()
            || authorization_id.is_empty()
            || paymaster_ticket_id.is_empty()
            || contract_commitment.is_empty()
            || call_data_root.is_empty()
            || witness_root.is_empty()
            || replay_nullifier.is_empty()
        {
            return Err("routed call commitments cannot be empty".to_string());
        }
        if fee_units == 0 || fee_units > config.max_fee_units_per_call || gas_units == 0 {
            return Err("routed call fee or gas limits invalid".to_string());
        }
        let expires_at_height = created_at_height.saturating_add(config.call_ttl_blocks);
        let call_id = router_id(
            "ROUTED-CALL-ID",
            &[
                session_id,
                authorization_id,
                paymaster_ticket_id,
                contract_commitment,
                replay_nullifier,
            ],
            created_at_height,
        );
        Ok(Self {
            call_id,
            session_id: session_id.to_string(),
            authorization_id: authorization_id.to_string(),
            paymaster_ticket_id: paymaster_ticket_id.to_string(),
            contract_commitment: contract_commitment.to_string(),
            call_data_root: call_data_root.to_string(),
            witness_root: witness_root.to_string(),
            replay_nullifier: replay_nullifier.to_string(),
            fee_units,
            gas_units,
            created_at_height,
            expires_at_height,
            status: RoutedCallStatus::Pending,
        })
    }

    pub fn expired_at(&self, height: u64) -> bool {
        height >= self.expires_at_height
    }

    pub fn validate(
        &self,
        config: &PrivateAccountAbstractionRouterConfig,
    ) -> PrivateAccountAbstractionRouterResult<()> {
        if self.call_id.is_empty()
            || self.session_id.is_empty()
            || self.authorization_id.is_empty()
            || self.paymaster_ticket_id.is_empty()
            || self.contract_commitment.is_empty()
            || self.call_data_root.is_empty()
            || self.witness_root.is_empty()
            || self.replay_nullifier.is_empty()
        {
            return Err("routed call identifiers cannot be empty".to_string());
        }
        if self.fee_units == 0 || self.fee_units > config.max_fee_units_per_call {
            return Err("routed call fee invalid".to_string());
        }
        if self.gas_units == 0 {
            return Err("routed call gas invalid".to_string());
        }
        if self.created_at_height >= self.expires_at_height {
            return Err("routed call ttl invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "routed_private_call",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "call_id": self.call_id,
            "session_id": self.session_id,
            "authorization_id": self.authorization_id,
            "paymaster_ticket_id": self.paymaster_ticket_id,
            "contract_commitment": self.contract_commitment,
            "call_data_root": self.call_data_root,
            "witness_root": self.witness_root,
            "replay_nullifier": self.replay_nullifier,
            "fee_units": self.fee_units,
            "gas_units": self.gas_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("ROUTED-CALL", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPolicyLane {
    pub lane_id: String,
    pub lane_label: String,
    pub session_kind: AccountRouterSessionKind,
    pub policy_root: String,
    pub contract_set_root: String,
    pub max_gas_units: u64,
    pub max_fee_units: u64,
    pub privacy_floor: u64,
    pub enabled: bool,
}

impl ContractPolicyLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane_label: &str,
        session_kind: AccountRouterSessionKind,
        policy_root: &str,
        contract_set_root: &str,
        max_gas_units: u64,
        max_fee_units: u64,
        privacy_floor: u64,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if lane_label.is_empty() || policy_root.is_empty() || contract_set_root.is_empty() {
            return Err("contract policy lane identifiers cannot be empty".to_string());
        }
        if max_gas_units == 0 || max_fee_units == 0 || privacy_floor == 0 {
            return Err("contract policy lane limits must be positive".to_string());
        }
        let lane_id = router_id(
            "CONTRACT-LANE-ID",
            &[
                lane_label,
                session_kind.as_str(),
                policy_root,
                contract_set_root,
            ],
            privacy_floor,
        );
        Ok(Self {
            lane_id,
            lane_label: lane_label.to_string(),
            session_kind,
            policy_root: policy_root.to_string(),
            contract_set_root: contract_set_root.to_string(),
            max_gas_units,
            max_fee_units,
            privacy_floor,
            enabled: true,
        })
    }

    pub fn accepts(&self, session: &ShieldedAccountSession, call: &RoutedPrivateCall) -> bool {
        self.enabled
            && self.session_kind == session.session_kind
            && session.privacy_set_size >= self.privacy_floor
            && call.fee_units <= self.max_fee_units
            && call.gas_units <= self.max_gas_units
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        if self.lane_id.is_empty()
            || self.lane_label.is_empty()
            || self.policy_root.is_empty()
            || self.contract_set_root.is_empty()
        {
            return Err("contract policy lane identifiers cannot be empty".to_string());
        }
        if self.max_gas_units == 0 || self.max_fee_units == 0 || self.privacy_floor == 0 {
            return Err("contract policy lane limits invalid".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_policy_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "lane_label": self.lane_label,
            "session_kind": self.session_kind.as_str(),
            "policy_root": self.policy_root,
            "contract_set_root": self.contract_set_root,
            "max_gas_units": self.max_gas_units,
            "max_fee_units": self.max_fee_units,
            "privacy_floor": self.privacy_floor,
            "enabled": self.enabled,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("CONTRACT-POLICY-LANE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterChallenge {
    pub challenge_id: String,
    pub challenge_kind: RouterChallengeKind,
    pub subject_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub bond_units: u64,
    pub opened_at_height: u64,
    pub resolved_at_height: Option<u64>,
    pub slashing_ready: bool,
}

impl RouterChallenge {
    pub fn new(
        challenge_kind: RouterChallengeKind,
        subject_id: &str,
        challenger_commitment: &str,
        evidence_root: &str,
        bond_units: u64,
        opened_at_height: u64,
    ) -> PrivateAccountAbstractionRouterResult<Self> {
        if subject_id.is_empty() || challenger_commitment.is_empty() || evidence_root.is_empty() {
            return Err("router challenge identifiers cannot be empty".to_string());
        }
        if bond_units == 0 {
            return Err("router challenge bond must be positive".to_string());
        }
        let challenge_id = router_id(
            "CHALLENGE-ID",
            &[
                challenge_kind.as_str(),
                subject_id,
                challenger_commitment,
                evidence_root,
            ],
            opened_at_height,
        );
        Ok(Self {
            challenge_id,
            challenge_kind,
            subject_id: subject_id.to_string(),
            challenger_commitment: challenger_commitment.to_string(),
            evidence_root: evidence_root.to_string(),
            bond_units,
            opened_at_height,
            resolved_at_height: None,
            slashing_ready: false,
        })
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        if self.challenge_id.is_empty()
            || self.subject_id.is_empty()
            || self.challenger_commitment.is_empty()
            || self.evidence_root.is_empty()
        {
            return Err("router challenge identifiers cannot be empty".to_string());
        }
        if self.bond_units == 0 {
            return Err("router challenge bond invalid".to_string());
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("router challenge resolved before open".to_string());
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "router_challenge",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_kind": self.challenge_kind.as_str(),
            "subject_id": self.subject_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "bond_units": self.bond_units,
            "opened_at_height": self.opened_at_height,
            "resolved_at_height": self.resolved_at_height,
            "slashing_ready": self.slashing_ready,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("CHALLENGE", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAccountAbstractionRouterRoots {
    pub config_root: String,
    pub session_root: String,
    pub authorization_root: String,
    pub paymaster_ticket_root: String,
    pub routed_call_root: String,
    pub contract_lane_root: String,
    pub challenge_root: String,
    pub spent_nullifier_root: String,
}

impl PrivateAccountAbstractionRouterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_account_abstraction_router_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "session_root": self.session_root,
            "authorization_root": self.authorization_root,
            "paymaster_ticket_root": self.paymaster_ticket_root,
            "routed_call_root": self.routed_call_root,
            "contract_lane_root": self.contract_lane_root,
            "challenge_root": self.challenge_root,
            "spent_nullifier_root": self.spent_nullifier_root,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAccountAbstractionRouterCounters {
    pub session_count: u64,
    pub active_session_count: u64,
    pub authorization_count: u64,
    pub paymaster_ticket_count: u64,
    pub pending_call_count: u64,
    pub executed_call_count: u64,
    pub contract_lane_count: u64,
    pub challenge_count: u64,
    pub spent_nullifier_count: u64,
    pub reserved_fee_units: u64,
    pub spent_fee_units: u64,
}

impl PrivateAccountAbstractionRouterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_account_abstraction_router_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "session_count": self.session_count,
            "active_session_count": self.active_session_count,
            "authorization_count": self.authorization_count,
            "paymaster_ticket_count": self.paymaster_ticket_count,
            "pending_call_count": self.pending_call_count,
            "executed_call_count": self.executed_call_count,
            "contract_lane_count": self.contract_lane_count,
            "challenge_count": self.challenge_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "reserved_fee_units": self.reserved_fee_units,
            "spent_fee_units": self.spent_fee_units,
        })
    }

    pub fn state_root(&self) -> String {
        router_json_root("COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAccountAbstractionRouterState {
    pub height: u64,
    pub config: PrivateAccountAbstractionRouterConfig,
    pub sessions: BTreeMap<String, ShieldedAccountSession>,
    pub authorizations: BTreeMap<String, PqSessionAuthorization>,
    pub paymaster_tickets: BTreeMap<String, LowFeePaymasterTicket>,
    pub routed_calls: BTreeMap<String, RoutedPrivateCall>,
    pub contract_lanes: BTreeMap<String, ContractPolicyLane>,
    pub challenges: BTreeMap<String, RouterChallenge>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl PrivateAccountAbstractionRouterState {
    pub fn new(height: u64, config: PrivateAccountAbstractionRouterConfig) -> Self {
        Self {
            height,
            config,
            sessions: BTreeMap::new(),
            authorizations: BTreeMap::new(),
            paymaster_tickets: BTreeMap::new(),
            routed_calls: BTreeMap::new(),
            contract_lanes: BTreeMap::new(),
            challenges: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PrivateAccountAbstractionRouterResult<Self> {
        let config = PrivateAccountAbstractionRouterConfig::devnet();
        let mut state = Self::new(PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_DEVNET_HEIGHT, config);
        state.insert_contract_lane(ContractPolicyLane::new(
            "private-defi-fast-lane",
            AccountRouterSessionKind::PrivateDefi,
            "policy:private-defi:root",
            "contracts:private-defi:allowlist-root",
            state.config.default_call_gas_units,
            state.config.max_fee_units_per_call,
            state.config.min_privacy_set_size,
        )?)?;
        state.insert_contract_lane(ContractPolicyLane::new(
            "monero-exit-fee-rescue",
            AccountRouterSessionKind::MoneroBridgeExit,
            "policy:monero-exit:root",
            "contracts:monero-exit:allowlist-root",
            state.config.default_call_gas_units.saturating_mul(2),
            state.config.max_fee_units_per_call,
            state.config.min_privacy_set_size,
        )?)?;
        let session = ShieldedAccountSession::new(
            AccountRouterSessionKind::PrivateDefi,
            "account:shielded:alice:commitment",
            "session-key:alice:pq-root",
            "pq-signature:alice:session-root",
            "policy:alice:defi-session",
            "contracts:private-defi:allowlist-root",
            "replay-domain:alice:defi",
            state.config.min_privacy_set_size.saturating_mul(2),
            state.height,
            &state.config,
        )?;
        let session_id = session.session_id.clone();
        state.insert_session(session)?;
        let authorization = PqSessionAuthorization::new(
            &session_id,
            "signer:alice:commitment",
            "ml-dsa:alice:authorization-root",
            "slh-dsa:alice:authorization-root",
            "scope:private-defi:swap-and-lend",
            "nonce:alice:session:0",
            state.height,
            state.height.saturating_add(state.config.session_ttl_blocks),
        )?;
        let authorization_id = authorization.authorization_id.clone();
        state.insert_authorization(authorization)?;
        let ticket = LowFeePaymasterTicket::new(
            "sponsor:router:devnet",
            &session_id,
            "wxmr-devnet",
            state.config.default_sponsor_budget_units,
            state.config.max_fee_units_per_call,
            "paymaster-policy:private-defi",
            state.height,
            state.height.saturating_add(state.config.session_ttl_blocks),
        )?;
        let ticket_id = ticket.ticket_id.clone();
        state.insert_paymaster_ticket(ticket)?;
        let call = RoutedPrivateCall::new(
            &session_id,
            &authorization_id,
            &ticket_id,
            "contract:private-amm:commitment",
            "calldata:swap:xmr-usd:root",
            "witness:private-amm:root",
            "nullifier:alice:call:0",
            12_000,
            320_000,
            state.height,
            &state.config,
        )?;
        let call_id = call.call_id.clone();
        state.insert_routed_call(call)?;
        state.admit_call(&call_id)?;
        let challenge = RouterChallenge::new(
            RouterChallengeKind::PrivacySetTooSmall,
            &session_id,
            "watcher:privacy-floor:commitment",
            "evidence:privacy-floor:root",
            50_000,
            state.height.saturating_add(1),
        )?;
        state.insert_challenge(challenge)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, next_height: u64) -> PrivateAccountAbstractionRouterResult<()> {
        if next_height < self.height {
            return Err("private account abstraction router height cannot decrease".to_string());
        }
        self.height = next_height;
        self.expire_records();
        Ok(())
    }

    pub fn insert_session(
        &mut self,
        session: ShieldedAccountSession,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        if self.sessions.len() >= self.config.max_active_sessions
            && !self.sessions.contains_key(&session.session_id)
        {
            return Err("router active session limit exceeded".to_string());
        }
        session.validate(&self.config)?;
        if self.sessions.contains_key(&session.session_id) {
            return Err("duplicate router session".to_string());
        }
        let id = session.session_id.clone();
        self.sessions.insert(id.clone(), session);
        Ok(id)
    }

    pub fn insert_authorization(
        &mut self,
        authorization: PqSessionAuthorization,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        authorization.validate()?;
        if !self.sessions.contains_key(&authorization.session_id) {
            return Err("authorization references unknown session".to_string());
        }
        if self
            .authorizations
            .contains_key(&authorization.authorization_id)
        {
            return Err("duplicate router authorization".to_string());
        }
        let id = authorization.authorization_id.clone();
        self.authorizations.insert(id.clone(), authorization);
        Ok(id)
    }

    pub fn insert_paymaster_ticket(
        &mut self,
        ticket: LowFeePaymasterTicket,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        ticket.validate()?;
        if !self.sessions.contains_key(&ticket.session_id) {
            return Err("paymaster ticket references unknown session".to_string());
        }
        if self.paymaster_tickets.contains_key(&ticket.ticket_id) {
            return Err("duplicate paymaster ticket".to_string());
        }
        let id = ticket.ticket_id.clone();
        self.paymaster_tickets.insert(id.clone(), ticket);
        Ok(id)
    }

    pub fn insert_contract_lane(
        &mut self,
        lane: ContractPolicyLane,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        lane.validate()?;
        if self.contract_lanes.contains_key(&lane.lane_id) {
            return Err("duplicate contract policy lane".to_string());
        }
        let id = lane.lane_id.clone();
        self.contract_lanes.insert(id.clone(), lane);
        Ok(id)
    }

    pub fn insert_routed_call(
        &mut self,
        call: RoutedPrivateCall,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        if self.routed_calls.len() >= self.config.max_pending_calls
            && !self.routed_calls.contains_key(&call.call_id)
        {
            return Err("router pending call limit exceeded".to_string());
        }
        call.validate(&self.config)?;
        if self.spent_nullifiers.contains(&call.replay_nullifier) {
            return Err("routed call replay nullifier already spent".to_string());
        }
        if !self.sessions.contains_key(&call.session_id) {
            return Err("routed call references unknown session".to_string());
        }
        if !self.authorizations.contains_key(&call.authorization_id) {
            return Err("routed call references unknown authorization".to_string());
        }
        if !self
            .paymaster_tickets
            .contains_key(&call.paymaster_ticket_id)
        {
            return Err("routed call references unknown paymaster ticket".to_string());
        }
        if self.routed_calls.contains_key(&call.call_id) {
            return Err("duplicate routed call".to_string());
        }
        let id = call.call_id.clone();
        self.routed_calls.insert(id.clone(), call);
        Ok(id)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: RouterChallenge,
    ) -> PrivateAccountAbstractionRouterResult<String> {
        challenge.validate()?;
        if self.challenges.contains_key(&challenge.challenge_id) {
            return Err("duplicate router challenge".to_string());
        }
        let id = challenge.challenge_id.clone();
        self.challenges.insert(id.clone(), challenge);
        Ok(id)
    }

    pub fn admit_call(&mut self, call_id: &str) -> PrivateAccountAbstractionRouterResult<()> {
        let call = self
            .routed_calls
            .get(call_id)
            .cloned()
            .ok_or_else(|| "unknown routed call".to_string())?;
        let session = self
            .sessions
            .get(&call.session_id)
            .cloned()
            .ok_or_else(|| "routed call missing session".to_string())?;
        if !session.can_route_call(self.height) {
            return Err("session cannot route call".to_string());
        }
        let authorization = self
            .authorizations
            .get(&call.authorization_id)
            .ok_or_else(|| "routed call missing authorization".to_string())?;
        if authorization.expired_at(self.height) {
            return Err("authorization expired".to_string());
        }
        let accepted_by_lane = self
            .contract_lanes
            .values()
            .any(|lane| lane.accepts(&session, &call));
        if !accepted_by_lane {
            return Err("routed call rejected by contract policy lanes".to_string());
        }
        let ticket = self
            .paymaster_tickets
            .get_mut(&call.paymaster_ticket_id)
            .ok_or_else(|| "routed call missing paymaster ticket".to_string())?;
        if !ticket.can_spend(call.fee_units, self.height) {
            return Err("paymaster ticket cannot sponsor call".to_string());
        }
        ticket.spent_fee_units = ticket.spent_fee_units.saturating_add(call.fee_units);
        ticket.status = if ticket.available_fee_units() == 0 {
            PaymasterTicketStatus::Spent
        } else {
            PaymasterTicketStatus::PartiallySpent
        };
        if let Some(session) = self.sessions.get_mut(&call.session_id) {
            session.calls_used = session.calls_used.saturating_add(1);
            if session.calls_used >= session.max_calls {
                session.status = SessionStatus::Exhausted;
            }
        }
        if let Some(call) = self.routed_calls.get_mut(call_id) {
            call.status = RoutedCallStatus::Admitted;
            self.spent_nullifiers.insert(call.replay_nullifier.clone());
        }
        Ok(())
    }

    pub fn roots(&self) -> PrivateAccountAbstractionRouterRoots {
        PrivateAccountAbstractionRouterRoots {
            config_root: self.config.state_root(),
            session_root: map_root(
                "PRIVATE-AA-ROUTER-SESSIONS",
                self.sessions
                    .values()
                    .map(ShieldedAccountSession::public_record),
            ),
            authorization_root: map_root(
                "PRIVATE-AA-ROUTER-AUTHORIZATIONS",
                self.authorizations
                    .values()
                    .map(PqSessionAuthorization::public_record),
            ),
            paymaster_ticket_root: map_root(
                "PRIVATE-AA-ROUTER-PAYMASTER-TICKETS",
                self.paymaster_tickets
                    .values()
                    .map(LowFeePaymasterTicket::public_record),
            ),
            routed_call_root: map_root(
                "PRIVATE-AA-ROUTER-CALLS",
                self.routed_calls
                    .values()
                    .map(RoutedPrivateCall::public_record),
            ),
            contract_lane_root: map_root(
                "PRIVATE-AA-ROUTER-LANES",
                self.contract_lanes
                    .values()
                    .map(ContractPolicyLane::public_record),
            ),
            challenge_root: map_root(
                "PRIVATE-AA-ROUTER-CHALLENGES",
                self.challenges.values().map(RouterChallenge::public_record),
            ),
            spent_nullifier_root: string_set_root(
                "PRIVATE-AA-ROUTER-SPENT-NULLIFIERS",
                &self.spent_nullifiers,
            ),
        }
    }

    pub fn counters(&self) -> PrivateAccountAbstractionRouterCounters {
        PrivateAccountAbstractionRouterCounters {
            session_count: self.sessions.len() as u64,
            active_session_count: self
                .sessions
                .values()
                .filter(|session| session.status.accepts_calls())
                .count() as u64,
            authorization_count: self.authorizations.len() as u64,
            paymaster_ticket_count: self.paymaster_tickets.len() as u64,
            pending_call_count: self
                .routed_calls
                .values()
                .filter(|call| matches!(call.status, RoutedCallStatus::Pending))
                .count() as u64,
            executed_call_count: self
                .routed_calls
                .values()
                .filter(|call| matches!(call.status, RoutedCallStatus::Executed))
                .count() as u64,
            contract_lane_count: self.contract_lanes.len() as u64,
            challenge_count: self.challenges.len() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
            reserved_fee_units: self
                .paymaster_tickets
                .values()
                .map(|ticket| ticket.reserved_fee_units)
                .sum(),
            spent_fee_units: self
                .paymaster_tickets
                .values()
                .map(|ticket| ticket.spent_fee_units)
                .sum(),
        }
    }

    pub fn active_session_ids(&self) -> Vec<String> {
        self.sessions
            .values()
            .filter(|session| session.status.accepts_calls())
            .map(|session| session.session_id.clone())
            .collect()
    }

    pub fn live_ticket_ids(&self) -> Vec<String> {
        self.paymaster_tickets
            .values()
            .filter(|ticket| {
                !ticket.expired_at(self.height)
                    && matches!(
                        ticket.status,
                        PaymasterTicketStatus::Reserved | PaymasterTicketStatus::PartiallySpent
                    )
            })
            .map(|ticket| ticket.ticket_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        private_account_abstraction_router_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_account_abstraction_router_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PROTOCOL_VERSION,
            "schema_version": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_SCHEMA_VERSION,
            "height": self.height,
            "hash_suite": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_HASH_SUITE,
            "pq_session_suite": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PQ_SESSION_SUITE,
            "account_proof_suite": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_ACCOUNT_PROOF_SUITE,
            "paymaster_suite": PRIVATE_ACCOUNT_ABSTRACTION_ROUTER_PAYMASTER_SUITE,
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "active_session_ids": self.active_session_ids(),
            "live_ticket_ids": self.live_ticket_ids(),
        })
    }

    pub fn validate(&self) -> PrivateAccountAbstractionRouterResult<()> {
        self.config.validate()?;
        if self.sessions.len() > self.config.max_active_sessions {
            return Err("router session capacity exceeded".to_string());
        }
        if self.routed_calls.len() > self.config.max_pending_calls {
            return Err("router call capacity exceeded".to_string());
        }
        for session in self.sessions.values() {
            session.validate(&self.config)?;
        }
        for authorization in self.authorizations.values() {
            authorization.validate()?;
            if !self.sessions.contains_key(&authorization.session_id) {
                return Err("authorization references missing session".to_string());
            }
        }
        for ticket in self.paymaster_tickets.values() {
            ticket.validate()?;
            if !self.sessions.contains_key(&ticket.session_id) {
                return Err("paymaster ticket references missing session".to_string());
            }
        }
        for call in self.routed_calls.values() {
            call.validate(&self.config)?;
            if !self.sessions.contains_key(&call.session_id)
                || !self.authorizations.contains_key(&call.authorization_id)
                || !self
                    .paymaster_tickets
                    .contains_key(&call.paymaster_ticket_id)
            {
                return Err("routed call references missing dependency".to_string());
            }
        }
        for lane in self.contract_lanes.values() {
            lane.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(())
    }

    fn expire_records(&mut self) {
        for session in self.sessions.values_mut() {
            if session.expired_at(self.height) && session.status.accepts_calls() {
                session.status = SessionStatus::Expired;
            }
        }
        for ticket in self.paymaster_tickets.values_mut() {
            if ticket.expired_at(self.height)
                && !matches!(
                    ticket.status,
                    PaymasterTicketStatus::Spent | PaymasterTicketStatus::Slashed
                )
            {
                ticket.status = PaymasterTicketStatus::Expired;
            }
        }
        for call in self.routed_calls.values_mut() {
            if call.expired_at(self.height) && matches!(call.status, RoutedCallStatus::Pending) {
                call.status = RoutedCallStatus::Expired;
            }
        }
    }
}

pub fn devnet() -> PrivateAccountAbstractionRouterResult<PrivateAccountAbstractionRouterState> {
    PrivateAccountAbstractionRouterState::devnet()
}

pub fn private_account_abstraction_router_state_root_from_record(record: &Value) -> String {
    router_json_root("STATE", record)
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}

fn string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    let leaves = values
        .iter()
        .map(|value| json!({ "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn router_id(domain: &str, parts: &[&str], height: u64) -> String {
    let mut hash_parts = parts
        .iter()
        .map(|part| HashPart::Str(*part))
        .collect::<Vec<_>>();
    hash_parts.push(HashPart::Int(height as i128));
    domain_hash(domain, &hash_parts, 32)
}

fn router_json_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-AA-ROUTER-{domain}"),
        &[HashPart::Json(value)],
        32,
    )
}
