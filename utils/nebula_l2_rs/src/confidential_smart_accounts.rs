use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash as stable_hash_hex, HashPart},
    CHAIN_ID,
};

pub type ConfidentialSmartAccountResult<T> = Result<T, String>;

pub const CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION: &str =
    "nebula-confidential-smart-accounts-v1";
pub const CONFIDENTIAL_SMART_ACCOUNTS_SECURITY_MODEL: &str =
    "deterministic-devnet-account-abstraction-not-real-crypto";
pub const CONFIDENTIAL_SMART_ACCOUNTS_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const CONFIDENTIAL_SMART_ACCOUNTS_PROOF_SYSTEM: &str =
    "zk-confidential-account-policy-shake256-v1";
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_HEIGHT: u64 = 192;
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_INTENT_TTL_BLOCKS: u64 = 24;
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_SPEND_WINDOW_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_PRIVACY_SET_SIZE: u64 = 128;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_ACCOUNTS: usize = 128;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_SESSION_KEYS: usize = 256;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_SPEND_LIMITS: usize = 256;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_PAYMASTER_POLICIES: usize = 128;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_INTENT_PERMISSIONS: usize = 256;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_RECOVERY_GUARDIANS: usize = 256;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_DEFI_ALLOWLISTS: usize = 128;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_NONCE_LANES: usize = 512;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_EXECUTION_ENVELOPES: usize = 256;
pub const CONFIDENTIAL_SMART_ACCOUNTS_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAccountStatus {
    Draft,
    Active,
    Frozen,
    Recovery,
    Suspended,
    Closed,
}

impl ConfidentialAccountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Recovery => "recovery",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    pub fn can_execute(self) -> bool {
        matches!(self, Self::Active | Self::Recovery)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialPolicyMode {
    Conservative,
    Balanced,
    DefiEnabled,
    HighThroughput,
    RecoveryOnly,
}

impl ConfidentialPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::DefiEnabled => "defi_enabled",
            Self::HighThroughput => "high_throughput",
            Self::RecoveryOnly => "recovery_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSessionKeyKind {
    Wallet,
    Hardware,
    Automation,
    ContractDelegate,
    Recovery,
}

impl PqSessionKeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Hardware => "hardware",
            Self::Automation => "automation",
            Self::ContractDelegate => "contract_delegate",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialOperationKind {
    PrivateTransfer,
    TokenMint,
    TokenBurn,
    DefiSwap,
    Lending,
    Staking,
    ContractCall,
    Recovery,
    Bridge,
}

impl ConfidentialOperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::TokenMint => "token_mint",
            Self::TokenBurn => "token_burn",
            Self::DefiSwap => "defi_swap",
            Self::Lending => "lending",
            Self::Staking => "staking",
            Self::ContractCall => "contract_call",
            Self::Recovery => "recovery",
            Self::Bridge => "bridge",
        }
    }

    pub fn is_defi(self) -> bool {
        matches!(self, Self::DefiSwap | Self::Lending | Self::Staking)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicyMode {
    Disabled,
    SelfPay,
    PreferPrivateSponsor,
    RequirePrivateSponsor,
    HybridLowFee,
}

impl SponsorPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SelfPay => "self_pay",
            Self::PreferPrivateSponsor => "prefer_private_sponsor",
            Self::RequirePrivateSponsor => "require_private_sponsor",
            Self::HybridLowFee => "hybrid_low_fee",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentPermissionScope {
    Transfer,
    Token,
    Defi,
    Contract,
    Sponsor,
    Recovery,
}

impl IntentPermissionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Token => "token",
            Self::Defi => "defi",
            Self::Contract => "contract",
            Self::Sponsor => "sponsor",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryGuardianKind {
    Person,
    HardwareKey,
    Institution,
    SocialQuorum,
    TimeLock,
}

impl RecoveryGuardianKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::HardwareKey => "hardware_key",
            Self::Institution => "institution",
            Self::SocialQuorum => "social_quorum",
            Self::TimeLock => "time_lock",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiContractKind {
    Dex,
    LendingMarket,
    StablePool,
    TokenFactory,
    PrivacyPool,
    Oracle,
    BridgeAdapter,
}

impl DefiContractKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dex => "dex",
            Self::LendingMarket => "lending_market",
            Self::StablePool => "stable_pool",
            Self::TokenFactory => "token_factory",
            Self::PrivacyPool => "privacy_pool",
            Self::Oracle => "oracle",
            Self::BridgeAdapter => "bridge_adapter",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvelopeStatus {
    Draft,
    Authorized,
    Sponsored,
    Sequenced,
    Executed,
    Expired,
    Rejected,
}

impl ExecutionEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Authorized => "authorized",
            Self::Sponsored => "sponsored",
            Self::Sequenced => "sequenced",
            Self::Executed => "executed",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Executed | Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSmartAccountConfig {
    pub protocol_version: String,
    pub default_session_ttl_blocks: u64,
    pub default_intent_ttl_blocks: u64,
    pub default_recovery_delay_blocks: u64,
    pub default_spend_window_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_accounts: usize,
    pub max_session_keys: usize,
    pub max_spend_limits: usize,
    pub max_paymaster_policies: usize,
    pub max_intent_permissions: usize,
    pub max_recovery_guardians: usize,
    pub max_defi_allowlists: usize,
    pub max_nonce_lanes: usize,
    pub max_execution_envelopes: usize,
    pub allow_public_fallback: bool,
    pub require_pq_sessions: bool,
    pub require_shielded_paymasters: bool,
}

impl Default for ConfidentialSmartAccountConfig {
    fn default() -> Self {
        Self {
            protocol_version: CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION.to_string(),
            default_session_ttl_blocks: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_SESSION_TTL_BLOCKS,
            default_intent_ttl_blocks: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_INTENT_TTL_BLOCKS,
            default_recovery_delay_blocks:
                CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_RECOVERY_DELAY_BLOCKS,
            default_spend_window_blocks: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_SPEND_WINDOW_BLOCKS,
            min_privacy_set_size: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_PRIVACY_SET_SIZE,
            min_pq_security_bits: CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS,
            max_accounts: CONFIDENTIAL_SMART_ACCOUNTS_MAX_ACCOUNTS,
            max_session_keys: CONFIDENTIAL_SMART_ACCOUNTS_MAX_SESSION_KEYS,
            max_spend_limits: CONFIDENTIAL_SMART_ACCOUNTS_MAX_SPEND_LIMITS,
            max_paymaster_policies: CONFIDENTIAL_SMART_ACCOUNTS_MAX_PAYMASTER_POLICIES,
            max_intent_permissions: CONFIDENTIAL_SMART_ACCOUNTS_MAX_INTENT_PERMISSIONS,
            max_recovery_guardians: CONFIDENTIAL_SMART_ACCOUNTS_MAX_RECOVERY_GUARDIANS,
            max_defi_allowlists: CONFIDENTIAL_SMART_ACCOUNTS_MAX_DEFI_ALLOWLISTS,
            max_nonce_lanes: CONFIDENTIAL_SMART_ACCOUNTS_MAX_NONCE_LANES,
            max_execution_envelopes: CONFIDENTIAL_SMART_ACCOUNTS_MAX_EXECUTION_ENVELOPES,
            allow_public_fallback: false,
            require_pq_sessions: true,
            require_shielded_paymasters: true,
        }
    }
}

impl ConfidentialSmartAccountConfig {
    pub fn devnet() -> Self {
        Self {
            default_session_ttl_blocks: 72,
            default_intent_ttl_blocks: 18,
            default_recovery_delay_blocks: 360,
            default_spend_window_blocks: 480,
            min_privacy_set_size: 96,
            max_accounts: 16,
            max_session_keys: 64,
            max_spend_limits: 64,
            max_paymaster_policies: 32,
            max_intent_permissions: 64,
            max_recovery_guardians: 64,
            max_defi_allowlists: 32,
            max_nonce_lanes: 128,
            max_execution_envelopes: 64,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_smart_account_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "security_model": CONFIDENTIAL_SMART_ACCOUNTS_SECURITY_MODEL,
            "pq_suite": CONFIDENTIAL_SMART_ACCOUNTS_PQ_SUITE,
            "proof_system": CONFIDENTIAL_SMART_ACCOUNTS_PROOF_SYSTEM,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_recovery_delay_blocks": self.default_recovery_delay_blocks,
            "default_spend_window_blocks": self.default_spend_window_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_accounts": self.max_accounts,
            "max_session_keys": self.max_session_keys,
            "max_spend_limits": self.max_spend_limits,
            "max_paymaster_policies": self.max_paymaster_policies,
            "max_intent_permissions": self.max_intent_permissions,
            "max_recovery_guardians": self.max_recovery_guardians,
            "max_defi_allowlists": self.max_defi_allowlists,
            "max_nonce_lanes": self.max_nonce_lanes,
            "max_execution_envelopes": self.max_execution_envelopes,
            "allow_public_fallback": self.allow_public_fallback,
            "require_pq_sessions": self.require_pq_sessions,
            "require_shielded_paymasters": self.require_shielded_paymasters,
        })
    }

    pub fn config_root(&self) -> String {
        csa_hash("CONFIG", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.protocol_version != CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION {
            return Err("unsupported confidential smart account protocol version".to_string());
        }
        if self.min_pq_security_bits < CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS {
            return Err("minimum PQ security bits below protocol floor".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("minimum privacy set size must be non-zero".to_string());
        }
        if self.default_session_ttl_blocks == 0 || self.default_intent_ttl_blocks == 0 {
            return Err("default TTL values must be non-zero".to_string());
        }
        if self.default_recovery_delay_blocks < self.default_intent_ttl_blocks {
            return Err("recovery delay must be at least intent TTL".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAccountPolicy {
    pub account_id: String,
    pub owner_commitment: String,
    pub policy_mode: ConfidentialPolicyMode,
    pub status: ConfidentialAccountStatus,
    pub required_signature_threshold: u16,
    pub recovery_threshold: u16,
    pub min_pq_security_bits: u16,
    pub privacy_set_floor: u64,
    pub allow_defi: bool,
    pub allow_tokens: bool,
    pub allow_contract_delegation: bool,
    pub allow_sponsored_execution: bool,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialAccountPolicy {
    pub fn new(
        owner_commitment: &str,
        policy_mode: ConfidentialPolicyMode,
        created_at_height: u64,
    ) -> Self {
        let metadata = json!({
            "owner_commitment": owner_commitment,
            "policy_mode": policy_mode.as_str(),
            "created_at_height": created_at_height,
        });
        let account_id = csa_hash(
            "ACCOUNT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(owner_commitment),
                HashPart::Str(policy_mode.as_str()),
                HashPart::Int(created_at_height as i128),
            ],
            24,
        );
        Self {
            account_id,
            owner_commitment: owner_commitment.to_string(),
            policy_mode,
            status: ConfidentialAccountStatus::Active,
            required_signature_threshold: 1,
            recovery_threshold: 2,
            min_pq_security_bits: CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS,
            privacy_set_floor: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_PRIVACY_SET_SIZE,
            allow_defi: matches!(
                policy_mode,
                ConfidentialPolicyMode::DefiEnabled | ConfidentialPolicyMode::HighThroughput
            ),
            allow_tokens: !matches!(policy_mode, ConfidentialPolicyMode::RecoveryOnly),
            allow_contract_delegation: matches!(
                policy_mode,
                ConfidentialPolicyMode::DefiEnabled | ConfidentialPolicyMode::HighThroughput
            ),
            allow_sponsored_execution: !matches!(policy_mode, ConfidentialPolicyMode::RecoveryOnly),
            metadata_root: csa_hash("ACCOUNT-METADATA", &[HashPart::Json(&metadata)], 32),
            created_at_height,
            updated_at_height: created_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_account_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "account_id": self.account_id,
            "owner_commitment": self.owner_commitment,
            "policy_mode": self.policy_mode.as_str(),
            "status": self.status.as_str(),
            "required_signature_threshold": self.required_signature_threshold,
            "recovery_threshold": self.recovery_threshold,
            "min_pq_security_bits": self.min_pq_security_bits,
            "privacy_set_floor": self.privacy_set_floor,
            "allow_defi": self.allow_defi,
            "allow_tokens": self.allow_tokens,
            "allow_contract_delegation": self.allow_contract_delegation,
            "allow_sponsored_execution": self.allow_sponsored_execution,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        csa_hash(
            "ACCOUNT-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.account_id.is_empty() {
            return Err("account id must be set".to_string());
        }
        if self.owner_commitment.is_empty() {
            return Err("owner commitment must be set".to_string());
        }
        if self.required_signature_threshold == 0 {
            return Err("signature threshold must be non-zero".to_string());
        }
        if self.recovery_threshold == 0 {
            return Err("recovery threshold must be non-zero".to_string());
        }
        if self.min_pq_security_bits < CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS {
            return Err("account PQ security below protocol floor".to_string());
        }
        if self.privacy_set_floor == 0 {
            return Err("account privacy set floor must be non-zero".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("account updated height before created height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionKey {
    pub session_key_id: String,
    pub account_id: String,
    pub key_kind: PqSessionKeyKind,
    pub public_key_commitment: String,
    pub kem_ciphertext_hash: String,
    pub allowed_scope_root: String,
    pub min_pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub revoked_at_height: Option<u64>,
}

impl PqSessionKey {
    pub fn new(
        account_id: &str,
        key_kind: PqSessionKeyKind,
        public_key_commitment: &str,
        kem_ciphertext_hash: &str,
        allowed_scope_root: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let session_key_id = csa_hash(
            "PQ-SESSION-KEY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(account_id),
                HashPart::Str(key_kind.as_str()),
                HashPart::Str(public_key_commitment),
                HashPart::Str(kem_ciphertext_hash),
                HashPart::Int(opened_at_height as i128),
                HashPart::Int(expires_at_height as i128),
            ],
            24,
        );
        Self {
            session_key_id,
            account_id: account_id.to_string(),
            key_kind,
            public_key_commitment: public_key_commitment.to_string(),
            kem_ciphertext_hash: kem_ciphertext_hash.to_string(),
            allowed_scope_root: allowed_scope_root.to_string(),
            min_pq_security_bits: CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS,
            opened_at_height,
            expires_at_height,
            revoked_at_height: None,
        }
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        let not_revoked = match self.revoked_at_height {
            Some(revoked_at_height) => height < revoked_at_height,
            None => true,
        };
        self.opened_at_height <= height && height <= self.expires_at_height && not_revoked
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_key",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "session_key_id": self.session_key_id,
            "account_id": self.account_id,
            "key_kind": self.key_kind.as_str(),
            "public_key_commitment": self.public_key_commitment,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "allowed_scope_root": self.allowed_scope_root,
            "min_pq_security_bits": self.min_pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "revoked_at_height": self.revoked_at_height,
        })
    }

    pub fn session_root(&self) -> String {
        csa_hash(
            "PQ-SESSION-KEY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.session_key_id.is_empty() || self.account_id.is_empty() {
            return Err("session key id and account id must be set".to_string());
        }
        if self.public_key_commitment.is_empty() || self.kem_ciphertext_hash.is_empty() {
            return Err("session key commitments must be set".to_string());
        }
        if self.allowed_scope_root.is_empty() {
            return Err("session allowed scope root must be set".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("session key expiry must be after opening height".to_string());
        }
        if self.min_pq_security_bits < CONFIDENTIAL_SMART_ACCOUNTS_MIN_PQ_SECURITY_BITS {
            return Err("session key PQ security below protocol floor".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedSpendLimit {
    pub limit_id: String,
    pub account_id: String,
    pub asset_id: String,
    pub operation_kind: ConfidentialOperationKind,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_amount_units: u128,
    pub spent_amount_units: u128,
    pub nullifier_domain: String,
    pub policy_root: String,
    pub enabled: bool,
}

impl ShieldedSpendLimit {
    pub fn new(
        account_id: &str,
        asset_id: &str,
        operation_kind: ConfidentialOperationKind,
        window_start_height: u64,
        window_blocks: u64,
        max_amount_units: u128,
    ) -> Self {
        let window_end_height = window_start_height.saturating_add(window_blocks);
        let policy = json!({
            "account_id": account_id,
            "asset_id": asset_id,
            "operation_kind": operation_kind.as_str(),
            "window_start_height": window_start_height,
            "window_end_height": window_end_height,
            "max_amount_units": max_amount_units.to_string(),
        });
        let limit_id = csa_hash(
            "SPEND-LIMIT-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(asset_id),
                HashPart::Str(operation_kind.as_str()),
                HashPart::Int(window_start_height as i128),
            ],
            24,
        );
        Self {
            limit_id,
            account_id: account_id.to_string(),
            asset_id: asset_id.to_string(),
            operation_kind,
            window_start_height,
            window_end_height,
            max_amount_units,
            spent_amount_units: 0,
            nullifier_domain: csa_hash(
                "SPEND-LIMIT-NULLIFIER-DOMAIN",
                &[HashPart::Json(&policy)],
                16,
            ),
            policy_root: csa_hash("SPEND-LIMIT-POLICY", &[HashPart::Json(&policy)], 32),
            enabled: true,
        }
    }

    pub fn remaining_amount_units(&self) -> u128 {
        self.max_amount_units
            .saturating_sub(self.spent_amount_units)
    }

    pub fn admits(&self, amount_units: u128, height: u64) -> bool {
        self.enabled
            && self.window_start_height <= height
            && height <= self.window_end_height
            && self.remaining_amount_units() >= amount_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_spend_limit",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "limit_id": self.limit_id,
            "account_id": self.account_id,
            "asset_id": self.asset_id,
            "operation_kind": self.operation_kind.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_amount_units": self.max_amount_units.to_string(),
            "spent_amount_units": self.spent_amount_units.to_string(),
            "remaining_amount_units": self.remaining_amount_units().to_string(),
            "nullifier_domain": self.nullifier_domain,
            "policy_root": self.policy_root,
            "enabled": self.enabled,
        })
    }

    pub fn limit_root(&self) -> String {
        csa_hash("SPEND-LIMIT", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.limit_id.is_empty() || self.account_id.is_empty() || self.asset_id.is_empty() {
            return Err("spend limit identifiers must be set".to_string());
        }
        if self.window_end_height <= self.window_start_height {
            return Err("spend limit window must end after it starts".to_string());
        }
        if self.max_amount_units == 0 {
            return Err("spend limit maximum must be non-zero".to_string());
        }
        if self.spent_amount_units > self.max_amount_units {
            return Err("spend limit spent amount exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SponsorPaymasterPolicy {
    pub policy_id: String,
    pub account_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub mode: SponsorPolicyMode,
    pub max_fee_units: u64,
    pub max_rebate_bps: u64,
    pub min_privacy_set_size: u64,
    pub allowed_operation_root: String,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub paused: bool,
}

impl SponsorPaymasterPolicy {
    pub fn new(
        account_id: &str,
        sponsor_commitment: &str,
        fee_asset_id: &str,
        mode: SponsorPolicyMode,
        max_fee_units: u64,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> Self {
        let operations = json!({
            "account_id": account_id,
            "mode": mode.as_str(),
            "fee_asset_id": fee_asset_id,
        });
        let policy_id = csa_hash(
            "SPONSOR-PAYMASTER-POLICY-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(sponsor_commitment),
                HashPart::Str(fee_asset_id),
                HashPart::Str(mode.as_str()),
                HashPart::Int(valid_from_height as i128),
            ],
            24,
        );
        Self {
            policy_id,
            account_id: account_id.to_string(),
            sponsor_commitment: sponsor_commitment.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            mode,
            max_fee_units,
            max_rebate_bps: 2_500,
            min_privacy_set_size: CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_PRIVACY_SET_SIZE,
            allowed_operation_root: csa_hash(
                "SPONSOR-ALLOWED-OPERATIONS",
                &[HashPart::Json(&operations)],
                32,
            ),
            valid_from_height,
            valid_until_height,
            paused: false,
        }
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        !self.paused && self.valid_from_height <= height && height <= self.valid_until_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sponsor_paymaster_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "account_id": self.account_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "max_fee_units": self.max_fee_units,
            "max_rebate_bps": self.max_rebate_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "allowed_operation_root": self.allowed_operation_root,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "paused": self.paused,
        })
    }

    pub fn policy_root(&self) -> String {
        csa_hash(
            "SPONSOR-PAYMASTER-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.policy_id.is_empty()
            || self.account_id.is_empty()
            || self.sponsor_commitment.is_empty()
            || self.fee_asset_id.is_empty()
        {
            return Err("sponsor policy identifiers must be set".to_string());
        }
        if self.max_fee_units == 0 {
            return Err("sponsor policy max fee must be non-zero".to_string());
        }
        if self.max_rebate_bps > CONFIDENTIAL_SMART_ACCOUNTS_MAX_BPS {
            return Err("sponsor policy rebate bps above maximum".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("sponsor policy validity window is invalid".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentPermission {
    pub permission_id: String,
    pub account_id: String,
    pub session_key_id: String,
    pub scope: IntentPermissionScope,
    pub operation_kind: ConfidentialOperationKind,
    pub target_root: String,
    pub asset_root: String,
    pub max_amount_units: u128,
    pub max_uses: u64,
    pub used_count: u64,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
}

impl IntentPermission {
    pub fn new(
        account_id: &str,
        session_key_id: &str,
        scope: IntentPermissionScope,
        operation_kind: ConfidentialOperationKind,
        target_root: &str,
        asset_root: &str,
        max_amount_units: u128,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> Self {
        let permission_id = csa_hash(
            "INTENT-PERMISSION-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(session_key_id),
                HashPart::Str(scope.as_str()),
                HashPart::Str(operation_kind.as_str()),
                HashPart::Str(target_root),
                HashPart::Int(valid_from_height as i128),
            ],
            24,
        );
        Self {
            permission_id,
            account_id: account_id.to_string(),
            session_key_id: session_key_id.to_string(),
            scope,
            operation_kind,
            target_root: target_root.to_string(),
            asset_root: asset_root.to_string(),
            max_amount_units,
            max_uses: 1,
            used_count: 0,
            valid_from_height,
            valid_until_height,
        }
    }

    pub fn admits(
        &self,
        operation_kind: ConfidentialOperationKind,
        amount_units: u128,
        height: u64,
    ) -> bool {
        self.operation_kind == operation_kind
            && self.valid_from_height <= height
            && height <= self.valid_until_height
            && self.used_count < self.max_uses
            && amount_units <= self.max_amount_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_permission",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "permission_id": self.permission_id,
            "account_id": self.account_id,
            "session_key_id": self.session_key_id,
            "scope": self.scope.as_str(),
            "operation_kind": self.operation_kind.as_str(),
            "target_root": self.target_root,
            "asset_root": self.asset_root,
            "max_amount_units": self.max_amount_units.to_string(),
            "max_uses": self.max_uses,
            "used_count": self.used_count,
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
        })
    }

    pub fn permission_root(&self) -> String {
        csa_hash(
            "INTENT-PERMISSION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.permission_id.is_empty()
            || self.account_id.is_empty()
            || self.session_key_id.is_empty()
            || self.target_root.is_empty()
            || self.asset_root.is_empty()
        {
            return Err("intent permission identifiers must be set".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("intent permission validity window is invalid".to_string());
        }
        if self.max_uses == 0 {
            return Err("intent permission max uses must be non-zero".to_string());
        }
        if self.used_count > self.max_uses {
            return Err("intent permission used count exceeds max uses".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryGuardian {
    pub guardian_id: String,
    pub account_id: String,
    pub guardian_kind: RecoveryGuardianKind,
    pub guardian_commitment: String,
    pub pq_public_key_commitment: String,
    pub weight: u16,
    pub delay_blocks: u64,
    pub added_at_height: u64,
    pub revoked_at_height: Option<u64>,
}

impl RecoveryGuardian {
    pub fn new(
        account_id: &str,
        guardian_kind: RecoveryGuardianKind,
        guardian_commitment: &str,
        pq_public_key_commitment: &str,
        weight: u16,
        delay_blocks: u64,
        added_at_height: u64,
    ) -> Self {
        let guardian_id = csa_hash(
            "RECOVERY-GUARDIAN-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(guardian_kind.as_str()),
                HashPart::Str(guardian_commitment),
                HashPart::Str(pq_public_key_commitment),
                HashPart::Int(added_at_height as i128),
            ],
            24,
        );
        Self {
            guardian_id,
            account_id: account_id.to_string(),
            guardian_kind,
            guardian_commitment: guardian_commitment.to_string(),
            pq_public_key_commitment: pq_public_key_commitment.to_string(),
            weight,
            delay_blocks,
            added_at_height,
            revoked_at_height: None,
        }
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        let not_revoked = match self.revoked_at_height {
            Some(revoked_at_height) => height < revoked_at_height,
            None => true,
        };
        self.added_at_height <= height && not_revoked
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recovery_guardian",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "guardian_id": self.guardian_id,
            "account_id": self.account_id,
            "guardian_kind": self.guardian_kind.as_str(),
            "guardian_commitment": self.guardian_commitment,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "weight": self.weight,
            "delay_blocks": self.delay_blocks,
            "added_at_height": self.added_at_height,
            "revoked_at_height": self.revoked_at_height,
        })
    }

    pub fn guardian_root(&self) -> String {
        csa_hash(
            "RECOVERY-GUARDIAN",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.guardian_id.is_empty()
            || self.account_id.is_empty()
            || self.guardian_commitment.is_empty()
            || self.pq_public_key_commitment.is_empty()
        {
            return Err("recovery guardian identifiers must be set".to_string());
        }
        if self.weight == 0 {
            return Err("recovery guardian weight must be non-zero".to_string());
        }
        if self.delay_blocks == 0 {
            return Err("recovery guardian delay must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiContractAllowlist {
    pub allowlist_id: String,
    pub account_id: String,
    pub contract_id: String,
    pub contract_kind: DefiContractKind,
    pub selector_root: String,
    pub asset_root: String,
    pub risk_tier: u8,
    pub max_slippage_bps: u64,
    pub max_notional_units: u128,
    pub valid_from_height: u64,
    pub valid_until_height: u64,
    pub enabled: bool,
}

impl DefiContractAllowlist {
    pub fn new(
        account_id: &str,
        contract_id: &str,
        contract_kind: DefiContractKind,
        selector_root: &str,
        asset_root: &str,
        valid_from_height: u64,
        valid_until_height: u64,
    ) -> Self {
        let allowlist_id = csa_hash(
            "DEFI-ALLOWLIST-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(contract_id),
                HashPart::Str(contract_kind.as_str()),
                HashPart::Str(selector_root),
                HashPart::Int(valid_from_height as i128),
            ],
            24,
        );
        Self {
            allowlist_id,
            account_id: account_id.to_string(),
            contract_id: contract_id.to_string(),
            contract_kind,
            selector_root: selector_root.to_string(),
            asset_root: asset_root.to_string(),
            risk_tier: 1,
            max_slippage_bps: 50,
            max_notional_units: 1_000_000,
            valid_from_height,
            valid_until_height,
            enabled: true,
        }
    }

    pub fn admits(&self, contract_id: &str, notional_units: u128, height: u64) -> bool {
        self.enabled
            && self.contract_id == contract_id
            && self.valid_from_height <= height
            && height <= self.valid_until_height
            && notional_units <= self.max_notional_units
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_contract_allowlist",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "allowlist_id": self.allowlist_id,
            "account_id": self.account_id,
            "contract_id": self.contract_id,
            "contract_kind": self.contract_kind.as_str(),
            "selector_root": self.selector_root,
            "asset_root": self.asset_root,
            "risk_tier": self.risk_tier,
            "max_slippage_bps": self.max_slippage_bps,
            "max_notional_units": self.max_notional_units.to_string(),
            "valid_from_height": self.valid_from_height,
            "valid_until_height": self.valid_until_height,
            "enabled": self.enabled,
        })
    }

    pub fn allowlist_root(&self) -> String {
        csa_hash(
            "DEFI-ALLOWLIST",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.allowlist_id.is_empty()
            || self.account_id.is_empty()
            || self.contract_id.is_empty()
            || self.selector_root.is_empty()
            || self.asset_root.is_empty()
        {
            return Err("DeFi allowlist identifiers must be set".to_string());
        }
        if self.valid_until_height <= self.valid_from_height {
            return Err("DeFi allowlist validity window is invalid".to_string());
        }
        if self.max_slippage_bps > CONFIDENTIAL_SMART_ACCOUNTS_MAX_BPS {
            return Err("DeFi allowlist slippage bps above maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceLane {
    pub lane_id: String,
    pub account_id: String,
    pub lane_label: String,
    pub operation_kind: ConfidentialOperationKind,
    pub current_nonce: u64,
    pub min_height: u64,
    pub max_pending: u32,
    pub pending_count: u32,
    pub parallel_execution: bool,
}

impl NonceLane {
    pub fn new(
        account_id: &str,
        lane_label: &str,
        operation_kind: ConfidentialOperationKind,
        min_height: u64,
    ) -> Self {
        let lane_id = csa_hash(
            "NONCE-LANE-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(lane_label),
                HashPart::Str(operation_kind.as_str()),
            ],
            20,
        );
        Self {
            lane_id,
            account_id: account_id.to_string(),
            lane_label: lane_label.to_string(),
            operation_kind,
            current_nonce: 0,
            min_height,
            max_pending: 8,
            pending_count: 0,
            parallel_execution: operation_kind.is_defi(),
        }
    }

    pub fn next_nonce_commitment(&self) -> String {
        csa_hash(
            "NONCE-LANE-NEXT",
            &[
                HashPart::Str(&self.lane_id),
                HashPart::Int(self.current_nonce.saturating_add(1) as i128),
                HashPart::Int(self.pending_count as i128),
            ],
            32,
        )
    }

    pub fn admits(&self, nonce: u64, height: u64) -> bool {
        height >= self.min_height
            && nonce > self.current_nonce
            && self.pending_count < self.max_pending
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "nonce_lane",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "lane_id": self.lane_id,
            "account_id": self.account_id,
            "lane_label": self.lane_label,
            "operation_kind": self.operation_kind.as_str(),
            "current_nonce": self.current_nonce,
            "min_height": self.min_height,
            "max_pending": self.max_pending,
            "pending_count": self.pending_count,
            "parallel_execution": self.parallel_execution,
            "next_nonce_commitment": self.next_nonce_commitment(),
        })
    }

    pub fn lane_root(&self) -> String {
        csa_hash("NONCE-LANE", &[HashPart::Json(&self.public_record())], 32)
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.lane_id.is_empty() || self.account_id.is_empty() || self.lane_label.is_empty() {
            return Err("nonce lane identifiers must be set".to_string());
        }
        if self.max_pending == 0 {
            return Err("nonce lane max pending must be non-zero".to_string());
        }
        if self.pending_count > self.max_pending {
            return Err("nonce lane pending count exceeds maximum".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEnvelope {
    pub envelope_id: String,
    pub account_id: String,
    pub session_key_id: String,
    pub nonce_lane_id: String,
    pub nonce: u64,
    pub operation_kind: ConfidentialOperationKind,
    pub target_contract_id: Option<String>,
    pub calldata_root: String,
    pub private_witness_root: String,
    pub spend_limit_id: Option<String>,
    pub sponsor_policy_id: Option<String>,
    pub max_fee_units: u64,
    pub amount_units: u128,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: ExecutionEnvelopeStatus,
    pub authorization_root: String,
    pub execution_result_root: Option<String>,
}

impl ExecutionEnvelope {
    pub fn new(
        account_id: &str,
        session_key_id: &str,
        nonce_lane_id: &str,
        nonce: u64,
        operation_kind: ConfidentialOperationKind,
        calldata_root: &str,
        private_witness_root: &str,
        created_at_height: u64,
        ttl_blocks: u64,
    ) -> Self {
        let expires_at_height = created_at_height.saturating_add(ttl_blocks);
        let authorization = json!({
            "account_id": account_id,
            "session_key_id": session_key_id,
            "nonce_lane_id": nonce_lane_id,
            "nonce": nonce,
            "operation_kind": operation_kind.as_str(),
            "calldata_root": calldata_root,
            "private_witness_root": private_witness_root,
            "created_at_height": created_at_height,
            "expires_at_height": expires_at_height,
        });
        let authorization_root = csa_hash(
            "EXECUTION-AUTHORIZATION",
            &[HashPart::Json(&authorization)],
            32,
        );
        let envelope_id = csa_hash(
            "EXECUTION-ENVELOPE-ID",
            &[
                HashPart::Str(account_id),
                HashPart::Str(session_key_id),
                HashPart::Str(nonce_lane_id),
                HashPart::Int(nonce as i128),
                HashPart::Str(&authorization_root),
            ],
            24,
        );
        Self {
            envelope_id,
            account_id: account_id.to_string(),
            session_key_id: session_key_id.to_string(),
            nonce_lane_id: nonce_lane_id.to_string(),
            nonce,
            operation_kind,
            target_contract_id: None,
            calldata_root: calldata_root.to_string(),
            private_witness_root: private_witness_root.to_string(),
            spend_limit_id: None,
            sponsor_policy_id: None,
            max_fee_units: 8,
            amount_units: 0,
            created_at_height,
            expires_at_height,
            status: ExecutionEnvelopeStatus::Draft,
            authorization_root,
            execution_result_root: None,
        }
    }

    pub fn with_contract(mut self, target_contract_id: &str) -> Self {
        self.target_contract_id = Some(target_contract_id.to_string());
        self
    }

    pub fn with_spend_limit(mut self, spend_limit_id: &str, amount_units: u128) -> Self {
        self.spend_limit_id = Some(spend_limit_id.to_string());
        self.amount_units = amount_units;
        self
    }

    pub fn with_sponsor(mut self, sponsor_policy_id: &str, max_fee_units: u64) -> Self {
        self.sponsor_policy_id = Some(sponsor_policy_id.to_string());
        self.max_fee_units = max_fee_units;
        self
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        !self.status.is_terminal()
            && self.created_at_height <= height
            && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "execution_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "envelope_id": self.envelope_id,
            "account_id": self.account_id,
            "session_key_id": self.session_key_id,
            "nonce_lane_id": self.nonce_lane_id,
            "nonce": self.nonce,
            "operation_kind": self.operation_kind.as_str(),
            "target_contract_id": self.target_contract_id,
            "calldata_root": self.calldata_root,
            "private_witness_root": self.private_witness_root,
            "spend_limit_id": self.spend_limit_id,
            "sponsor_policy_id": self.sponsor_policy_id,
            "max_fee_units": self.max_fee_units,
            "amount_units": self.amount_units.to_string(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "authorization_root": self.authorization_root,
            "execution_result_root": self.execution_result_root,
        })
    }

    pub fn envelope_root(&self) -> String {
        csa_hash(
            "EXECUTION-ENVELOPE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        if self.envelope_id.is_empty()
            || self.account_id.is_empty()
            || self.session_key_id.is_empty()
            || self.nonce_lane_id.is_empty()
            || self.calldata_root.is_empty()
            || self.private_witness_root.is_empty()
            || self.authorization_root.is_empty()
        {
            return Err("execution envelope identifiers and roots must be set".to_string());
        }
        if self.nonce == 0 {
            return Err("execution envelope nonce must be non-zero".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("execution envelope expiry must be after creation height".to_string());
        }
        if self.max_fee_units == 0 {
            return Err("execution envelope max fee must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSmartAccountRoots {
    pub config_root: String,
    pub account_policy_root: String,
    pub session_key_root: String,
    pub spend_limit_root: String,
    pub sponsor_policy_root: String,
    pub intent_permission_root: String,
    pub recovery_guardian_root: String,
    pub defi_allowlist_root: String,
    pub nonce_lane_root: String,
    pub execution_envelope_root: String,
    pub state_root: String,
}

impl ConfidentialSmartAccountRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_smart_account_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "account_policy_root": self.account_policy_root,
            "session_key_root": self.session_key_root,
            "spend_limit_root": self.spend_limit_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "intent_permission_root": self.intent_permission_root,
            "recovery_guardian_root": self.recovery_guardian_root,
            "defi_allowlist_root": self.defi_allowlist_root,
            "nonce_lane_root": self.nonce_lane_root,
            "execution_envelope_root": self.execution_envelope_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSmartAccountCounters {
    pub accounts: usize,
    pub active_accounts: usize,
    pub session_keys: usize,
    pub live_session_keys: usize,
    pub spend_limits: usize,
    pub paymaster_policies: usize,
    pub intent_permissions: usize,
    pub recovery_guardians: usize,
    pub defi_allowlists: usize,
    pub nonce_lanes: usize,
    pub execution_envelopes: usize,
    pub live_execution_envelopes: usize,
}

impl ConfidentialSmartAccountCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_smart_account_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "accounts": self.accounts,
            "active_accounts": self.active_accounts,
            "session_keys": self.session_keys,
            "live_session_keys": self.live_session_keys,
            "spend_limits": self.spend_limits,
            "paymaster_policies": self.paymaster_policies,
            "intent_permissions": self.intent_permissions,
            "recovery_guardians": self.recovery_guardians,
            "defi_allowlists": self.defi_allowlists,
            "nonce_lanes": self.nonce_lanes,
            "execution_envelopes": self.execution_envelopes,
            "live_execution_envelopes": self.live_execution_envelopes,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialSmartAccountState {
    pub config: ConfidentialSmartAccountConfig,
    pub height: u64,
    pub accounts: BTreeMap<String, ConfidentialAccountPolicy>,
    pub session_keys: BTreeMap<String, PqSessionKey>,
    pub spend_limits: BTreeMap<String, ShieldedSpendLimit>,
    pub paymaster_policies: BTreeMap<String, SponsorPaymasterPolicy>,
    pub intent_permissions: BTreeMap<String, IntentPermission>,
    pub recovery_guardians: BTreeMap<String, RecoveryGuardian>,
    pub defi_allowlists: BTreeMap<String, DefiContractAllowlist>,
    pub nonce_lanes: BTreeMap<String, NonceLane>,
    pub execution_envelopes: BTreeMap<String, ExecutionEnvelope>,
}

impl ConfidentialSmartAccountState {
    pub fn new(config: ConfidentialSmartAccountConfig, height: u64) -> Self {
        Self {
            config,
            height,
            accounts: BTreeMap::new(),
            session_keys: BTreeMap::new(),
            spend_limits: BTreeMap::new(),
            paymaster_policies: BTreeMap::new(),
            intent_permissions: BTreeMap::new(),
            recovery_guardians: BTreeMap::new(),
            defi_allowlists: BTreeMap::new(),
            nonce_lanes: BTreeMap::new(),
            execution_envelopes: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ConfidentialSmartAccountResult<Self> {
        let config = ConfidentialSmartAccountConfig::devnet();
        let height = CONFIDENTIAL_SMART_ACCOUNTS_DEFAULT_HEIGHT;
        let mut state = Self::new(config.clone(), height);

        let mut treasury = ConfidentialAccountPolicy::new(
            "owner-commitment-devnet-treasury",
            ConfidentialPolicyMode::DefiEnabled,
            height,
        );
        treasury.required_signature_threshold = 2;
        treasury.recovery_threshold = 2;
        treasury.privacy_set_floor = config.min_privacy_set_size;

        let wallet = ConfidentialAccountPolicy::new(
            "owner-commitment-devnet-wallet",
            ConfidentialPolicyMode::Balanced,
            height,
        );
        let treasury_id = treasury.account_id.clone();
        let wallet_id = wallet.account_id.clone();
        state.accounts.insert(treasury.account_id.clone(), treasury);
        state.accounts.insert(wallet.account_id.clone(), wallet);

        let defi_scope_root = csa_hash(
            "DEVNET-SCOPE",
            &[HashPart::Json(&json!({
                "operations": ["private_transfer", "defi_swap", "contract_call"],
                "privacy_set_floor": config.min_privacy_set_size,
            }))],
            32,
        );
        let wallet_scope_root = csa_hash(
            "DEVNET-SCOPE",
            &[HashPart::Json(&json!({
                "operations": ["private_transfer", "token_mint", "token_burn"],
                "privacy_set_floor": config.min_privacy_set_size,
            }))],
            32,
        );

        let treasury_session = PqSessionKey::new(
            &treasury_id,
            PqSessionKeyKind::Hardware,
            "pq-public-key-commitment-devnet-treasury",
            "kem-ciphertext-hash-devnet-treasury",
            &defi_scope_root,
            height,
            config.default_session_ttl_blocks,
        );
        let wallet_session = PqSessionKey::new(
            &wallet_id,
            PqSessionKeyKind::Wallet,
            "pq-public-key-commitment-devnet-wallet",
            "kem-ciphertext-hash-devnet-wallet",
            &wallet_scope_root,
            height,
            config.default_session_ttl_blocks,
        );
        let treasury_session_id = treasury_session.session_key_id.clone();
        let wallet_session_id = wallet_session.session_key_id.clone();
        state
            .session_keys
            .insert(treasury_session.session_key_id.clone(), treasury_session);
        state
            .session_keys
            .insert(wallet_session.session_key_id.clone(), wallet_session);

        let treasury_limit = ShieldedSpendLimit::new(
            &treasury_id,
            "wxmr-devnet",
            ConfidentialOperationKind::DefiSwap,
            height,
            config.default_spend_window_blocks,
            2_500_000,
        );
        let wallet_limit = ShieldedSpendLimit::new(
            &wallet_id,
            "wxmr-devnet",
            ConfidentialOperationKind::PrivateTransfer,
            height,
            config.default_spend_window_blocks,
            250_000,
        );
        let treasury_limit_id = treasury_limit.limit_id.clone();
        let wallet_limit_id = wallet_limit.limit_id.clone();
        state
            .spend_limits
            .insert(treasury_limit.limit_id.clone(), treasury_limit);
        state
            .spend_limits
            .insert(wallet_limit.limit_id.clone(), wallet_limit);

        let sponsor_policy = SponsorPaymasterPolicy::new(
            &wallet_id,
            "sponsor-commitment-devnet-private-pool",
            "wxmr-devnet",
            SponsorPolicyMode::HybridLowFee,
            12,
            height,
            height.saturating_add(720),
        );
        let sponsor_policy_id = sponsor_policy.policy_id.clone();
        state
            .paymaster_policies
            .insert(sponsor_policy.policy_id.clone(), sponsor_policy);

        let permission = IntentPermission::new(
            &wallet_id,
            &wallet_session_id,
            IntentPermissionScope::Transfer,
            ConfidentialOperationKind::PrivateTransfer,
            "target-root-private-transfer-devnet",
            "asset-root-wxmr-devnet",
            50_000,
            height,
            height.saturating_add(config.default_intent_ttl_blocks),
        );
        state
            .intent_permissions
            .insert(permission.permission_id.clone(), permission);

        for (kind, commitment, key, weight) in [
            (
                RecoveryGuardianKind::Person,
                "guardian-commitment-devnet-alice",
                "guardian-pq-key-devnet-alice",
                1,
            ),
            (
                RecoveryGuardianKind::HardwareKey,
                "guardian-commitment-devnet-hardware",
                "guardian-pq-key-devnet-hardware",
                1,
            ),
            (
                RecoveryGuardianKind::Institution,
                "guardian-commitment-devnet-institution",
                "guardian-pq-key-devnet-institution",
                1,
            ),
        ] {
            let guardian = RecoveryGuardian::new(
                &wallet_id,
                kind,
                commitment,
                key,
                weight,
                config.default_recovery_delay_blocks,
                height,
            );
            state
                .recovery_guardians
                .insert(guardian.guardian_id.clone(), guardian);
        }

        let dex_allowlist = DefiContractAllowlist::new(
            &treasury_id,
            "contract-devnet-private-dex",
            DefiContractKind::Dex,
            "selector-root-private-swap-exact-in",
            "asset-root-wxmr-usdd",
            height,
            height.saturating_add(720),
        );
        state
            .defi_allowlists
            .insert(dex_allowlist.allowlist_id.clone(), dex_allowlist);

        let transfer_lane = NonceLane::new(
            &wallet_id,
            "private-transfer",
            ConfidentialOperationKind::PrivateTransfer,
            height,
        );
        let defi_lane = NonceLane::new(
            &treasury_id,
            "private-defi",
            ConfidentialOperationKind::DefiSwap,
            height,
        );
        let transfer_lane_id = transfer_lane.lane_id.clone();
        let defi_lane_id = defi_lane.lane_id.clone();
        state
            .nonce_lanes
            .insert(transfer_lane.lane_id.clone(), transfer_lane);
        state
            .nonce_lanes
            .insert(defi_lane.lane_id.clone(), defi_lane);

        let transfer_envelope = ExecutionEnvelope::new(
            &wallet_id,
            &wallet_session_id,
            &transfer_lane_id,
            1,
            ConfidentialOperationKind::PrivateTransfer,
            "calldata-root-devnet-private-transfer",
            "witness-root-devnet-private-transfer",
            height,
            config.default_intent_ttl_blocks,
        )
        .with_spend_limit(&wallet_limit_id, 25_000)
        .with_sponsor(&sponsor_policy_id, 8);

        let defi_envelope = ExecutionEnvelope::new(
            &treasury_id,
            &treasury_session_id,
            &defi_lane_id,
            1,
            ConfidentialOperationKind::DefiSwap,
            "calldata-root-devnet-private-swap",
            "witness-root-devnet-private-swap",
            height,
            config.default_intent_ttl_blocks,
        )
        .with_contract("contract-devnet-private-dex")
        .with_spend_limit(&treasury_limit_id, 100_000);

        state
            .execution_envelopes
            .insert(transfer_envelope.envelope_id.clone(), transfer_envelope);
        state
            .execution_envelopes
            .insert(defi_envelope.envelope_id.clone(), defi_envelope);

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn counters(&self) -> ConfidentialSmartAccountCounters {
        ConfidentialSmartAccountCounters {
            accounts: self.accounts.len(),
            active_accounts: self
                .accounts
                .values()
                .filter(|account| account.status.can_execute())
                .count(),
            session_keys: self.session_keys.len(),
            live_session_keys: self
                .session_keys
                .values()
                .filter(|session| session.is_live_at(self.height))
                .count(),
            spend_limits: self.spend_limits.len(),
            paymaster_policies: self.paymaster_policies.len(),
            intent_permissions: self.intent_permissions.len(),
            recovery_guardians: self.recovery_guardians.len(),
            defi_allowlists: self.defi_allowlists.len(),
            nonce_lanes: self.nonce_lanes.len(),
            execution_envelopes: self.execution_envelopes.len(),
            live_execution_envelopes: self
                .execution_envelopes
                .values()
                .filter(|envelope| envelope.is_live_at(self.height))
                .count(),
        }
    }

    pub fn roots(&self) -> ConfidentialSmartAccountRoots {
        let config_root = self.config.config_root();
        let account_policy_root = record_root(
            "ACCOUNT-POLICIES",
            self.accounts
                .values()
                .map(ConfidentialAccountPolicy::public_record)
                .collect::<Vec<_>>(),
        );
        let session_key_root = record_root(
            "SESSION-KEYS",
            self.session_keys
                .values()
                .map(PqSessionKey::public_record)
                .collect::<Vec<_>>(),
        );
        let spend_limit_root = record_root(
            "SPEND-LIMITS",
            self.spend_limits
                .values()
                .map(ShieldedSpendLimit::public_record)
                .collect::<Vec<_>>(),
        );
        let sponsor_policy_root = record_root(
            "SPONSOR-POLICIES",
            self.paymaster_policies
                .values()
                .map(SponsorPaymasterPolicy::public_record)
                .collect::<Vec<_>>(),
        );
        let intent_permission_root = record_root(
            "INTENT-PERMISSIONS",
            self.intent_permissions
                .values()
                .map(IntentPermission::public_record)
                .collect::<Vec<_>>(),
        );
        let recovery_guardian_root = record_root(
            "RECOVERY-GUARDIANS",
            self.recovery_guardians
                .values()
                .map(RecoveryGuardian::public_record)
                .collect::<Vec<_>>(),
        );
        let defi_allowlist_root = record_root(
            "DEFI-ALLOWLISTS",
            self.defi_allowlists
                .values()
                .map(DefiContractAllowlist::public_record)
                .collect::<Vec<_>>(),
        );
        let nonce_lane_root = record_root(
            "NONCE-LANES",
            self.nonce_lanes
                .values()
                .map(NonceLane::public_record)
                .collect::<Vec<_>>(),
        );
        let execution_envelope_root = record_root(
            "EXECUTION-ENVELOPES",
            self.execution_envelopes
                .values()
                .map(ExecutionEnvelope::public_record)
                .collect::<Vec<_>>(),
        );
        let state_root = csa_hash(
            "STATE-ROOT",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&account_policy_root),
                HashPart::Str(&session_key_root),
                HashPart::Str(&spend_limit_root),
                HashPart::Str(&sponsor_policy_root),
                HashPart::Str(&intent_permission_root),
                HashPart::Str(&recovery_guardian_root),
                HashPart::Str(&defi_allowlist_root),
                HashPart::Str(&nonce_lane_root),
                HashPart::Str(&execution_envelope_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        ConfidentialSmartAccountRoots {
            config_root,
            account_policy_root,
            session_key_root,
            spend_limit_root,
            sponsor_policy_root,
            intent_permission_root,
            recovery_guardian_root,
            defi_allowlist_root,
            nonce_lane_root,
            execution_envelope_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_smart_account_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "accounts": self.accounts.values().map(ConfidentialAccountPolicy::public_record).collect::<Vec<_>>(),
            "session_keys": self.session_keys.values().map(PqSessionKey::public_record).collect::<Vec<_>>(),
            "spend_limits": self.spend_limits.values().map(ShieldedSpendLimit::public_record).collect::<Vec<_>>(),
            "paymaster_policies": self.paymaster_policies.values().map(SponsorPaymasterPolicy::public_record).collect::<Vec<_>>(),
            "intent_permissions": self.intent_permissions.values().map(IntentPermission::public_record).collect::<Vec<_>>(),
            "recovery_guardians": self.recovery_guardians.values().map(RecoveryGuardian::public_record).collect::<Vec<_>>(),
            "defi_allowlists": self.defi_allowlists.values().map(DefiContractAllowlist::public_record).collect::<Vec<_>>(),
            "nonce_lanes": self.nonce_lanes.values().map(NonceLane::public_record).collect::<Vec<_>>(),
            "execution_envelopes": self.execution_envelopes.values().map(ExecutionEnvelope::public_record).collect::<Vec<_>>(),
            "state_root": self.state_root(),
        })
    }

    pub fn validate(&self) -> ConfidentialSmartAccountResult<()> {
        self.config.validate()?;
        self.validate_counts()?;
        self.validate_accounts()?;
        self.validate_sessions()?;
        self.validate_spend_limits()?;
        self.validate_sponsor_policies()?;
        self.validate_intent_permissions()?;
        self.validate_recovery_guardians()?;
        self.validate_defi_allowlists()?;
        self.validate_nonce_lanes()?;
        self.validate_execution_envelopes()?;
        Ok(())
    }

    fn validate_counts(&self) -> ConfidentialSmartAccountResult<()> {
        if self.accounts.len() > self.config.max_accounts {
            return Err("too many confidential smart accounts".to_string());
        }
        if self.session_keys.len() > self.config.max_session_keys {
            return Err("too many PQ session keys".to_string());
        }
        if self.spend_limits.len() > self.config.max_spend_limits {
            return Err("too many shielded spend limits".to_string());
        }
        if self.paymaster_policies.len() > self.config.max_paymaster_policies {
            return Err("too many sponsor paymaster policies".to_string());
        }
        if self.intent_permissions.len() > self.config.max_intent_permissions {
            return Err("too many intent permissions".to_string());
        }
        if self.recovery_guardians.len() > self.config.max_recovery_guardians {
            return Err("too many recovery guardians".to_string());
        }
        if self.defi_allowlists.len() > self.config.max_defi_allowlists {
            return Err("too many DeFi allowlists".to_string());
        }
        if self.nonce_lanes.len() > self.config.max_nonce_lanes {
            return Err("too many nonce lanes".to_string());
        }
        if self.execution_envelopes.len() > self.config.max_execution_envelopes {
            return Err("too many execution envelopes".to_string());
        }
        Ok(())
    }

    fn validate_accounts(&self) -> ConfidentialSmartAccountResult<()> {
        for (account_id, account) in &self.accounts {
            account.validate()?;
            if account_id != &account.account_id {
                return Err("account map key does not match account id".to_string());
            }
            if account.privacy_set_floor < self.config.min_privacy_set_size {
                return Err("account privacy floor below config minimum".to_string());
            }
        }
        Ok(())
    }

    fn validate_sessions(&self) -> ConfidentialSmartAccountResult<()> {
        for (session_id, session) in &self.session_keys {
            session.validate()?;
            if session_id != &session.session_key_id {
                return Err("session key map key does not match session key id".to_string());
            }
            if !self.accounts.contains_key(&session.account_id) {
                return Err("session key references missing account".to_string());
            }
        }
        Ok(())
    }

    fn validate_spend_limits(&self) -> ConfidentialSmartAccountResult<()> {
        for (limit_id, limit) in &self.spend_limits {
            limit.validate()?;
            if limit_id != &limit.limit_id {
                return Err("spend limit map key does not match limit id".to_string());
            }
            if !self.accounts.contains_key(&limit.account_id) {
                return Err("spend limit references missing account".to_string());
            }
        }
        Ok(())
    }

    fn validate_sponsor_policies(&self) -> ConfidentialSmartAccountResult<()> {
        for (policy_id, policy) in &self.paymaster_policies {
            policy.validate()?;
            if policy_id != &policy.policy_id {
                return Err("sponsor policy map key does not match policy id".to_string());
            }
            if !self.accounts.contains_key(&policy.account_id) {
                return Err("sponsor policy references missing account".to_string());
            }
            if policy.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("sponsor policy privacy set below config minimum".to_string());
            }
        }
        Ok(())
    }

    fn validate_intent_permissions(&self) -> ConfidentialSmartAccountResult<()> {
        for (permission_id, permission) in &self.intent_permissions {
            permission.validate()?;
            if permission_id != &permission.permission_id {
                return Err("intent permission map key does not match permission id".to_string());
            }
            if !self.accounts.contains_key(&permission.account_id) {
                return Err("intent permission references missing account".to_string());
            }
            if !self.session_keys.contains_key(&permission.session_key_id) {
                return Err("intent permission references missing session key".to_string());
            }
        }
        Ok(())
    }

    fn validate_recovery_guardians(&self) -> ConfidentialSmartAccountResult<()> {
        let mut weights_by_account = BTreeMap::<String, u64>::new();
        for (guardian_id, guardian) in &self.recovery_guardians {
            guardian.validate()?;
            if guardian_id != &guardian.guardian_id {
                return Err("recovery guardian map key does not match guardian id".to_string());
            }
            if !self.accounts.contains_key(&guardian.account_id) {
                return Err("recovery guardian references missing account".to_string());
            }
            if guardian.is_live_at(self.height) {
                let entry = weights_by_account
                    .entry(guardian.account_id.clone())
                    .or_insert(0);
                *entry = entry.saturating_add(guardian.weight as u64);
            }
        }
        for (account_id, account) in &self.accounts {
            if account.recovery_threshold > 0 {
                let weight = match weights_by_account.get(account_id) {
                    Some(weight) => *weight,
                    None => 0,
                };
                if weight < account.recovery_threshold as u64 {
                    return Err("live recovery guardian weight below account threshold".to_string());
                }
            }
        }
        Ok(())
    }

    fn validate_defi_allowlists(&self) -> ConfidentialSmartAccountResult<()> {
        for (allowlist_id, allowlist) in &self.defi_allowlists {
            allowlist.validate()?;
            if allowlist_id != &allowlist.allowlist_id {
                return Err("DeFi allowlist map key does not match allowlist id".to_string());
            }
            match self.accounts.get(&allowlist.account_id) {
                Some(account) if account.allow_defi => {}
                Some(_) => {
                    return Err("DeFi allowlist references account without DeFi enabled".to_string())
                }
                None => return Err("DeFi allowlist references missing account".to_string()),
            }
        }
        Ok(())
    }

    fn validate_nonce_lanes(&self) -> ConfidentialSmartAccountResult<()> {
        let mut labels = BTreeSet::<(String, String)>::new();
        for (lane_id, lane) in &self.nonce_lanes {
            lane.validate()?;
            if lane_id != &lane.lane_id {
                return Err("nonce lane map key does not match lane id".to_string());
            }
            if !self.accounts.contains_key(&lane.account_id) {
                return Err("nonce lane references missing account".to_string());
            }
            let key = (lane.account_id.clone(), lane.lane_label.clone());
            if labels.contains(&key) {
                return Err("duplicate nonce lane label for account".to_string());
            }
            labels.insert(key);
        }
        Ok(())
    }

    fn validate_execution_envelopes(&self) -> ConfidentialSmartAccountResult<()> {
        for (envelope_id, envelope) in &self.execution_envelopes {
            envelope.validate()?;
            if envelope_id != &envelope.envelope_id {
                return Err("execution envelope map key does not match envelope id".to_string());
            }
            let account = match self.accounts.get(&envelope.account_id) {
                Some(account) => account,
                None => return Err("execution envelope references missing account".to_string()),
            };
            if !account.status.can_execute() {
                return Err("execution envelope references account that cannot execute".to_string());
            }
            match self.session_keys.get(&envelope.session_key_id) {
                Some(session) if session.account_id == envelope.account_id => {}
                Some(_) => {
                    return Err(
                        "execution envelope session belongs to a different account".to_string()
                    )
                }
                None => return Err("execution envelope references missing session key".to_string()),
            }
            match self.nonce_lanes.get(&envelope.nonce_lane_id) {
                Some(lane)
                    if lane.account_id == envelope.account_id
                        && lane.operation_kind == envelope.operation_kind => {}
                Some(_) => return Err("execution envelope nonce lane is incompatible".to_string()),
                None => return Err("execution envelope references missing nonce lane".to_string()),
            }
            if let Some(limit_id) = &envelope.spend_limit_id {
                match self.spend_limits.get(limit_id) {
                    Some(limit)
                        if limit.account_id == envelope.account_id
                            && limit.operation_kind == envelope.operation_kind => {}
                    Some(_) => {
                        return Err("execution envelope spend limit is incompatible".to_string())
                    }
                    None => {
                        return Err("execution envelope references missing spend limit".to_string())
                    }
                }
            }
            if let Some(policy_id) = &envelope.sponsor_policy_id {
                match self.paymaster_policies.get(policy_id) {
                    Some(policy) if policy.account_id == envelope.account_id => {}
                    Some(_) => {
                        return Err("execution envelope sponsor policy is incompatible".to_string())
                    }
                    None => {
                        return Err(
                            "execution envelope references missing sponsor policy".to_string()
                        )
                    }
                }
            }
            if envelope.operation_kind.is_defi() {
                let target = match &envelope.target_contract_id {
                    Some(target) => target,
                    None => {
                        return Err(
                            "DeFi execution envelope must include a target contract".to_string()
                        )
                    }
                };
                let admitted = self.defi_allowlists.values().any(|allowlist| {
                    allowlist.account_id == envelope.account_id
                        && allowlist.admits(
                            target,
                            envelope.amount_units,
                            envelope.created_at_height,
                        )
                });
                if !admitted {
                    return Err("DeFi execution envelope target is not allowlisted".to_string());
                }
            }
        }
        Ok(())
    }
}

pub fn confidential_account_id(owner_commitment: &str, created_at_height: u64) -> String {
    csa_hash(
        "ACCOUNT-ID-HELPER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        24,
    )
}

pub fn confidential_scope_root(scopes: &[IntentPermissionScope]) -> String {
    let leaves = scopes
        .iter()
        .map(|scope| json!({ "scope": scope.as_str() }))
        .collect::<Vec<_>>();
    record_root("SCOPE-ROOT", leaves)
}

pub fn confidential_asset_root(asset_ids: &[String]) -> String {
    let leaves = asset_ids
        .iter()
        .map(|asset_id| json!({ "asset_id": asset_id }))
        .collect::<Vec<_>>();
    record_root("ASSET-ROOT", leaves)
}

pub fn confidential_selector_root(selectors: &[String]) -> String {
    let leaves = selectors
        .iter()
        .map(|selector| json!({ "selector": selector }))
        .collect::<Vec<_>>();
    record_root("SELECTOR-ROOT", leaves)
}

fn record_root(domain: &str, records: Vec<Value>) -> String {
    if records.is_empty() {
        return csa_hash(domain, &[HashPart::Str("empty")], 32);
    }
    let leaf_roots = records
        .iter()
        .map(|record| csa_hash(&format!("{domain}-LEAF"), &[HashPart::Json(record)], 32))
        .collect::<Vec<_>>();
    csa_hash(
        domain,
        &[HashPart::Json(&json!({
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_SMART_ACCOUNTS_PROTOCOL_VERSION,
            "leaf_roots": leaf_roots,
        }))],
        32,
    )
}

fn csa_hash(domain: &str, parts: &[HashPart<'_>], out_len: usize) -> String {
    stable_hash_hex(
        &format!("CONFIDENTIAL-SMART-ACCOUNTS-{domain}"),
        parts,
        out_len,
    )
}
