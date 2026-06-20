use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialAccountSessionLayerResult<T> = Result<T, String>;

pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PROTOCOL_VERSION: &str =
    "nebula-confidential-account-session-layer-v1";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SCHEMA_VERSION: u64 = 1;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SESSION_KEY_SCHEME: &str =
    "ml-kem-1024-shielded-session-key-v1";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PQ_AUTH_SCHEME: &str =
    "ml-dsa-87-session-authority-v1";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_TRANSCRIPT_SCHEME: &str =
    "encrypted-session-transcript-shake256-v1";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_REPLAY_DOMAIN: &str =
    "nebula-private-account-session-replay-v1";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_FEE_ASSET_ID: &str = "dxmr";
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_SESSION_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_REVOCATION_TTL_BLOCKS: u64 = 96;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_SPONSOR_TTL_BLOCKS: u64 = 7_200;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MAX_SCOPE_COUNT: usize = 32;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MAX_SPEND_CAP_BPS: u64 = 2_500;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 128;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_REPLAY_WINDOW_BLOCKS: u64 = 128;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEVNET_HEIGHT: u64 = 840;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_SESSION_KEYS: usize = 262_144;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PERMISSION_SCOPES: usize = 524_288;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_SPEND_CAPS: usize = 262_144;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PAYMASTER_GRANTS: usize = 131_072;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_RECOVERY_DELEGATES: usize = 131_072;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_TRANSCRIPTS: usize = 262_144;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_REVOCATIONS: usize = 131_072;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_REPLAY_NONCES: usize = 524_288;
pub const CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PUBLIC_RECORDS: usize = 262_144;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionAuthorityRole {
    Owner,
    Guardian,
    RecoveryDelegate,
    Paymaster,
    Dapp,
    HardwareSigner,
    Custom(String),
}

impl SessionAuthorityRole {
    pub fn as_str(&self) -> String {
        match self {
            Self::Owner => "owner".to_string(),
            Self::Guardian => "guardian".to_string(),
            Self::RecoveryDelegate => "recovery_delegate".to_string(),
            Self::Paymaster => "paymaster".to_string(),
            Self::Dapp => "dapp".to_string(),
            Self::HardwareSigner => "hardware_signer".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKeyStatus {
    Pending,
    Active,
    CoolingDown,
    Revoked,
    Expired,
    Quarantined,
}

impl SessionKeyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn live(&self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::CoolingDown)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScopeKind {
    TokenTransfer,
    PrivateSwap,
    Lending,
    Derivatives,
    BridgeExit,
    ContractCall,
    GovernanceVote,
    RecoveryAction,
    Custom(String),
}

impl PermissionScopeKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::TokenTransfer => "token_transfer".to_string(),
            Self::PrivateSwap => "private_swap".to_string(),
            Self::Lending => "lending".to_string(),
            Self::Derivatives => "derivatives".to_string(),
            Self::BridgeExit => "bridge_exit".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::GovernanceVote => "governance_vote".to_string(),
            Self::RecoveryAction => "recovery_action".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScopeStatus {
    Active,
    Spent,
    Suspended,
    Revoked,
    Expired,
}

impl PermissionScopeStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Spent => "spent",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendCapStatus {
    Active,
    Exhausted,
    Suspended,
    Revoked,
    Expired,
}

impl SpendCapStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterGrantStatus {
    Active,
    Reserved,
    Spent,
    Revoked,
    Expired,
}

impl PaymasterGrantStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::Spent => "spent",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn available(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDelegateStatus {
    Pending,
    Active,
    CoolingDown,
    Revoked,
    Expired,
}

impl RecoveryDelegateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::CoolingDown => "cooling_down",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStatus {
    Submitted,
    Accepted,
    Challenged,
    Redacted,
    Expired,
}

impl TranscriptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Accepted => "accepted",
            Self::Challenged => "challenged",
            Self::Redacted => "redacted",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationStatus {
    Pending,
    Effective,
    Disputed,
    Expired,
}

impl RevocationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Effective => "effective",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }

    pub fn live(&self) -> bool {
        matches!(self, Self::Pending | Self::Disputed)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayNonceStatus {
    Fresh,
    Consumed,
    Expired,
    Quarantined,
}

impl ReplayNonceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAccountSessionLayerConfig {
    pub chain_id: String,
    pub fee_asset_id: String,
    pub session_key_scheme: String,
    pub pq_auth_scheme: String,
    pub transcript_scheme: String,
    pub replay_domain: String,
    pub session_ttl_blocks: u64,
    pub revocation_ttl_blocks: u64,
    pub sponsor_ttl_blocks: u64,
    pub replay_window_blocks: u64,
    pub max_scope_count: usize,
    pub max_spend_cap_bps: u64,
    pub min_privacy_set_size: u64,
    pub max_session_keys: usize,
    pub max_permission_scopes: usize,
    pub max_spend_caps: usize,
    pub max_paymaster_grants: usize,
    pub max_recovery_delegates: usize,
    pub max_transcripts: usize,
    pub max_revocations: usize,
    pub max_replay_nonces: usize,
    pub max_public_records: usize,
}

impl Default for ConfidentialAccountSessionLayerConfig {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            fee_asset_id: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_FEE_ASSET_ID.to_string(),
            session_key_scheme: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SESSION_KEY_SCHEME.to_string(),
            pq_auth_scheme: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PQ_AUTH_SCHEME.to_string(),
            transcript_scheme: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_TRANSCRIPT_SCHEME.to_string(),
            replay_domain: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_REPLAY_DOMAIN.to_string(),
            session_ttl_blocks: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_SESSION_TTL_BLOCKS,
            revocation_ttl_blocks: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_REVOCATION_TTL_BLOCKS,
            sponsor_ttl_blocks: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_SPONSOR_TTL_BLOCKS,
            replay_window_blocks: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_REPLAY_WINDOW_BLOCKS,
            max_scope_count: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MAX_SCOPE_COUNT,
            max_spend_cap_bps: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MAX_SPEND_CAP_BPS,
            min_privacy_set_size: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEFAULT_MIN_PRIVACY_SET_SIZE,
            max_session_keys: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_SESSION_KEYS,
            max_permission_scopes: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PERMISSION_SCOPES,
            max_spend_caps: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_SPEND_CAPS,
            max_paymaster_grants: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PAYMASTER_GRANTS,
            max_recovery_delegates: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_RECOVERY_DELEGATES,
            max_transcripts: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_TRANSCRIPTS,
            max_revocations: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_REVOCATIONS,
            max_replay_nonces: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_REPLAY_NONCES,
            max_public_records: CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_PUBLIC_RECORDS,
        }
    }
}

impl ConfidentialAccountSessionLayerConfig {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<()> {
        ensure_non_empty("config.chain_id", &self.chain_id)?;
        ensure_non_empty("config.fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("config.session_key_scheme", &self.session_key_scheme)?;
        ensure_non_empty("config.pq_auth_scheme", &self.pq_auth_scheme)?;
        ensure_non_empty("config.transcript_scheme", &self.transcript_scheme)?;
        ensure_non_empty("config.replay_domain", &self.replay_domain)?;
        ensure_positive("config.session_ttl_blocks", self.session_ttl_blocks)?;
        ensure_positive("config.revocation_ttl_blocks", self.revocation_ttl_blocks)?;
        ensure_positive("config.sponsor_ttl_blocks", self.sponsor_ttl_blocks)?;
        ensure_positive("config.replay_window_blocks", self.replay_window_blocks)?;
        ensure_capacity("config.max_scope_count", self.max_scope_count)?;
        ensure_bps("config.max_spend_cap_bps", self.max_spend_cap_bps)?;
        ensure_positive("config.min_privacy_set_size", self.min_privacy_set_size)?;
        ensure_capacity("config.max_session_keys", self.max_session_keys)?;
        ensure_capacity("config.max_permission_scopes", self.max_permission_scopes)?;
        ensure_capacity("config.max_spend_caps", self.max_spend_caps)?;
        ensure_capacity("config.max_paymaster_grants", self.max_paymaster_grants)?;
        ensure_capacity("config.max_recovery_delegates", self.max_recovery_delegates)?;
        ensure_capacity("config.max_transcripts", self.max_transcripts)?;
        ensure_capacity("config.max_revocations", self.max_revocations)?;
        ensure_capacity("config.max_replay_nonces", self.max_replay_nonces)?;
        ensure_capacity("config.max_public_records", self.max_public_records)?;
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_account_session_layer_config",
            "protocol_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PROTOCOL_VERSION,
            "schema_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "fee_asset_id": self.fee_asset_id,
            "session_key_scheme": self.session_key_scheme,
            "pq_auth_scheme": self.pq_auth_scheme,
            "transcript_scheme": self.transcript_scheme,
            "replay_domain": self.replay_domain,
            "session_ttl_blocks": self.session_ttl_blocks,
            "revocation_ttl_blocks": self.revocation_ttl_blocks,
            "sponsor_ttl_blocks": self.sponsor_ttl_blocks,
            "replay_window_blocks": self.replay_window_blocks,
            "max_scope_count": self.max_scope_count,
            "max_spend_cap_bps": self.max_spend_cap_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "max_session_keys": self.max_session_keys,
            "max_permission_scopes": self.max_permission_scopes,
            "max_spend_caps": self.max_spend_caps,
            "max_paymaster_grants": self.max_paymaster_grants,
            "max_recovery_delegates": self.max_recovery_delegates,
            "max_transcripts": self.max_transcripts,
            "max_revocations": self.max_revocations,
            "max_replay_nonces": self.max_replay_nonces,
            "max_public_records": self.max_public_records,
        })
    }

    pub fn config_root(&self) -> String {
        confidential_account_session_layer_payload_root(
            "CONFIDENTIAL-ACCOUNT-SESSION-LAYER-CONFIG",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedSessionKey {
    pub session_id: String,
    pub account_commitment_root: String,
    pub session_key_commitment: String,
    pub pq_authority_commitment: String,
    pub authority_role: SessionAuthorityRole,
    pub privacy_set_size: u64,
    pub scope_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce_domain_root: String,
    pub status: SessionKeyStatus,
}

impl ShieldedSessionKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment_root: &str,
        session_key_commitment: &str,
        pq_authority_commitment: &str,
        authority_role: SessionAuthorityRole,
        privacy_set_size: u64,
        scopes: &[String],
        created_at_height: u64,
        expires_at_height: u64,
        nonce_domain_root: &str,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_hex_root("session.account_commitment_root", account_commitment_root)?;
        ensure_hex_root("session.session_key_commitment", session_key_commitment)?;
        ensure_non_empty("session.pq_authority_commitment", pq_authority_commitment)?;
        ensure_positive("session.privacy_set_size", privacy_set_size)?;
        ensure_non_empty_list("session.scopes", scopes)?;
        ensure_height_order("session.created", created_at_height, expires_at_height)?;
        ensure_hex_root("session.nonce_domain_root", nonce_domain_root)?;
        let scope_root = merkle_string_root("CONFIDENTIAL-SESSION-SCOPE", scopes);
        let session_id = shielded_session_key_id(
            account_commitment_root,
            session_key_commitment,
            &scope_root,
            created_at_height,
        );
        let item = Self {
            session_id,
            account_commitment_root: account_commitment_root.to_string(),
            session_key_commitment: session_key_commitment.to_string(),
            pq_authority_commitment: pq_authority_commitment.to_string(),
            authority_role,
            privacy_set_size,
            scope_root,
            created_at_height,
            expires_at_height,
            nonce_domain_root: nonce_domain_root.to_string(),
            status: SessionKeyStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "account_commitment_root": self.account_commitment_root,
            "session_key_commitment": self.session_key_commitment,
            "pq_authority_commitment": self.pq_authority_commitment,
            "authority_role": self.authority_role.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "scope_root": self.scope_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce_domain_root": self.nonce_domain_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("session.session_id", &self.session_id)?;
        ensure_hex_root(
            "session.account_commitment_root",
            &self.account_commitment_root,
        )?;
        ensure_hex_root(
            "session.session_key_commitment",
            &self.session_key_commitment,
        )?;
        ensure_non_empty(
            "session.pq_authority_commitment",
            &self.pq_authority_commitment,
        )?;
        ensure_positive("session.privacy_set_size", self.privacy_set_size)?;
        ensure_hex_root("session.scope_root", &self.scope_root)?;
        ensure_height_order(
            "session.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        ensure_hex_root("session.nonce_domain_root", &self.nonce_domain_root)?;
        let expected = shielded_session_key_id(
            &self.account_commitment_root,
            &self.session_key_commitment,
            &self.scope_root,
            self.created_at_height,
        );
        if self.session_id != expected {
            return Err("shielded session key id mismatch".to_string());
        }
        Ok(self.session_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPermissionScope {
    pub permission_id: String,
    pub session_id: String,
    pub scope_kind: PermissionScopeKind,
    pub target_commitment_root: String,
    pub method_root: String,
    pub asset_id: Option<String>,
    pub privacy_budget_units: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PermissionScopeStatus,
}

impl SessionPermissionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: &str,
        scope_kind: PermissionScopeKind,
        target_commitment_root: &str,
        method_root: &str,
        asset_id: Option<String>,
        privacy_budget_units: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("permission.session_id", session_id)?;
        ensure_hex_root("permission.target_commitment_root", target_commitment_root)?;
        ensure_hex_root("permission.method_root", method_root)?;
        ensure_positive("permission.privacy_budget_units", privacy_budget_units)?;
        ensure_height_order("permission.created", created_at_height, expires_at_height)?;
        let permission_id =
            session_permission_scope_id(session_id, &scope_kind.as_str(), method_root);
        let item = Self {
            permission_id,
            session_id: session_id.to_string(),
            scope_kind,
            target_commitment_root: target_commitment_root.to_string(),
            method_root: method_root.to_string(),
            asset_id,
            privacy_budget_units,
            created_at_height,
            expires_at_height,
            status: PermissionScopeStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "permission_id": self.permission_id,
            "session_id": self.session_id,
            "scope_kind": self.scope_kind.as_str(),
            "target_commitment_root": self.target_commitment_root,
            "method_root": self.method_root,
            "asset_id": self.asset_id,
            "privacy_budget_units": self.privacy_budget_units,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("permission.permission_id", &self.permission_id)?;
        ensure_non_empty("permission.session_id", &self.session_id)?;
        ensure_hex_root(
            "permission.target_commitment_root",
            &self.target_commitment_root,
        )?;
        ensure_hex_root("permission.method_root", &self.method_root)?;
        ensure_positive("permission.privacy_budget_units", self.privacy_budget_units)?;
        ensure_height_order(
            "permission.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected = session_permission_scope_id(
            &self.session_id,
            &self.scope_kind.as_str(),
            &self.method_root,
        );
        if self.permission_id != expected {
            return Err("session permission scope id mismatch".to_string());
        }
        Ok(self.permission_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSpendCap {
    pub cap_id: String,
    pub session_id: String,
    pub asset_id: String,
    pub cap_commitment_root: String,
    pub spent_commitment_root: String,
    pub max_cap_bps: u64,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: SpendCapStatus,
}

impl SessionSpendCap {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: &str,
        asset_id: &str,
        cap_commitment_root: &str,
        spent_commitment_root: &str,
        max_cap_bps: u64,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("cap.session_id", session_id)?;
        ensure_non_empty("cap.asset_id", asset_id)?;
        ensure_hex_root("cap.cap_commitment_root", cap_commitment_root)?;
        ensure_hex_root("cap.spent_commitment_root", spent_commitment_root)?;
        ensure_bps("cap.max_cap_bps", max_cap_bps)?;
        ensure_height_order("cap.created", created_at_height, expires_at_height)?;
        let cap_id = session_spend_cap_id(session_id, asset_id, cap_commitment_root);
        let item = Self {
            cap_id,
            session_id: session_id.to_string(),
            asset_id: asset_id.to_string(),
            cap_commitment_root: cap_commitment_root.to_string(),
            spent_commitment_root: spent_commitment_root.to_string(),
            max_cap_bps,
            created_at_height,
            expires_at_height,
            status: SpendCapStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cap_id": self.cap_id,
            "session_id": self.session_id,
            "asset_id": self.asset_id,
            "cap_commitment_root": self.cap_commitment_root,
            "spent_commitment_root": self.spent_commitment_root,
            "max_cap_bps": self.max_cap_bps,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("cap.cap_id", &self.cap_id)?;
        ensure_non_empty("cap.session_id", &self.session_id)?;
        ensure_non_empty("cap.asset_id", &self.asset_id)?;
        ensure_hex_root("cap.cap_commitment_root", &self.cap_commitment_root)?;
        ensure_hex_root("cap.spent_commitment_root", &self.spent_commitment_root)?;
        ensure_bps("cap.max_cap_bps", self.max_cap_bps)?;
        ensure_height_order(
            "cap.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected =
            session_spend_cap_id(&self.session_id, &self.asset_id, &self.cap_commitment_root);
        if self.cap_id != expected {
            return Err("session spend cap id mismatch".to_string());
        }
        Ok(self.cap_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivatePaymasterGrant {
    pub grant_id: String,
    pub session_id: String,
    pub paymaster_id: String,
    pub lane_id: String,
    pub asset_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub policy_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: PaymasterGrantStatus,
}

impl PrivatePaymasterGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: &str,
        paymaster_id: &str,
        lane_id: &str,
        asset_id: &str,
        budget_units: u64,
        policy: &Value,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("grant.session_id", session_id)?;
        ensure_non_empty("grant.paymaster_id", paymaster_id)?;
        ensure_non_empty("grant.lane_id", lane_id)?;
        ensure_non_empty("grant.asset_id", asset_id)?;
        ensure_positive("grant.budget_units", budget_units)?;
        ensure_height_order("grant.created", created_at_height, expires_at_height)?;
        let policy_root = confidential_account_session_layer_payload_root(
            "SESSION-PAYMASTER-GRANT-POLICY",
            policy,
        );
        let grant_id = private_paymaster_grant_id(session_id, paymaster_id, &policy_root);
        let item = Self {
            grant_id,
            session_id: session_id.to_string(),
            paymaster_id: paymaster_id.to_string(),
            lane_id: lane_id.to_string(),
            asset_id: asset_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            policy_root,
            created_at_height,
            expires_at_height,
            status: PaymasterGrantStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "grant_id": self.grant_id,
            "session_id": self.session_id,
            "paymaster_id": self.paymaster_id,
            "lane_id": self.lane_id,
            "asset_id": self.asset_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "policy_root": self.policy_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("grant.grant_id", &self.grant_id)?;
        ensure_non_empty("grant.session_id", &self.session_id)?;
        ensure_non_empty("grant.paymaster_id", &self.paymaster_id)?;
        ensure_non_empty("grant.lane_id", &self.lane_id)?;
        ensure_non_empty("grant.asset_id", &self.asset_id)?;
        ensure_positive("grant.budget_units", self.budget_units)?;
        if self.reserved_units.saturating_add(self.spent_units) > self.budget_units {
            return Err("paymaster grant reserved plus spent exceeds budget".to_string());
        }
        ensure_hex_root("grant.policy_root", &self.policy_root)?;
        ensure_height_order(
            "grant.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected =
            private_paymaster_grant_id(&self.session_id, &self.paymaster_id, &self.policy_root);
        if self.grant_id != expected {
            return Err("private paymaster grant id mismatch".to_string());
        }
        Ok(self.grant_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqRecoveryDelegate {
    pub delegate_id: String,
    pub account_commitment_root: String,
    pub delegate_commitment: String,
    pub role: SessionAuthorityRole,
    pub threshold_weight: u64,
    pub pq_signature_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: RecoveryDelegateStatus,
}

impl PqRecoveryDelegate {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_commitment_root: &str,
        delegate_commitment: &str,
        role: SessionAuthorityRole,
        threshold_weight: u64,
        pq_signature_commitment: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_hex_root("delegate.account_commitment_root", account_commitment_root)?;
        ensure_non_empty("delegate.delegate_commitment", delegate_commitment)?;
        ensure_positive("delegate.threshold_weight", threshold_weight)?;
        ensure_hex_root("delegate.pq_signature_commitment", pq_signature_commitment)?;
        ensure_height_order("delegate.created", created_at_height, expires_at_height)?;
        let delegate_id = pq_recovery_delegate_id(
            account_commitment_root,
            delegate_commitment,
            created_at_height,
        );
        let item = Self {
            delegate_id,
            account_commitment_root: account_commitment_root.to_string(),
            delegate_commitment: delegate_commitment.to_string(),
            role,
            threshold_weight,
            pq_signature_commitment: pq_signature_commitment.to_string(),
            created_at_height,
            expires_at_height,
            status: RecoveryDelegateStatus::Active,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "delegate_id": self.delegate_id,
            "account_commitment_root": self.account_commitment_root,
            "delegate_commitment": self.delegate_commitment,
            "role": self.role.as_str(),
            "threshold_weight": self.threshold_weight,
            "pq_signature_commitment": self.pq_signature_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("delegate.delegate_id", &self.delegate_id)?;
        ensure_hex_root(
            "delegate.account_commitment_root",
            &self.account_commitment_root,
        )?;
        ensure_non_empty("delegate.delegate_commitment", &self.delegate_commitment)?;
        ensure_positive("delegate.threshold_weight", self.threshold_weight)?;
        ensure_hex_root(
            "delegate.pq_signature_commitment",
            &self.pq_signature_commitment,
        )?;
        ensure_height_order(
            "delegate.created",
            self.created_at_height,
            self.expires_at_height,
        )?;
        let expected = pq_recovery_delegate_id(
            &self.account_commitment_root,
            &self.delegate_commitment,
            self.created_at_height,
        );
        if self.delegate_id != expected {
            return Err("pq recovery delegate id mismatch".to_string());
        }
        Ok(self.delegate_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSessionTranscript {
    pub transcript_id: String,
    pub session_id: String,
    pub transcript_root: String,
    pub action_count: u64,
    pub disclosure_policy_root: String,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub status: TranscriptStatus,
}

impl EncryptedSessionTranscript {
    pub fn new(
        session_id: &str,
        transcript_root: &str,
        action_count: u64,
        disclosure_policy: &Value,
        submitted_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("transcript.session_id", session_id)?;
        ensure_hex_root("transcript.transcript_root", transcript_root)?;
        ensure_positive("transcript.action_count", action_count)?;
        ensure_height_order(
            "transcript.submitted",
            submitted_at_height,
            expires_at_height,
        )?;
        let disclosure_policy_root = confidential_account_session_layer_payload_root(
            "SESSION-TRANSCRIPT-DISCLOSURE-POLICY",
            disclosure_policy,
        );
        let transcript_id = encrypted_session_transcript_id(session_id, transcript_root);
        let item = Self {
            transcript_id,
            session_id: session_id.to_string(),
            transcript_root: transcript_root.to_string(),
            action_count,
            disclosure_policy_root,
            submitted_at_height,
            expires_at_height,
            status: TranscriptStatus::Submitted,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "transcript_id": self.transcript_id,
            "session_id": self.session_id,
            "transcript_root": self.transcript_root,
            "action_count": self.action_count,
            "disclosure_policy_root": self.disclosure_policy_root,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("transcript.transcript_id", &self.transcript_id)?;
        ensure_non_empty("transcript.session_id", &self.session_id)?;
        ensure_hex_root("transcript.transcript_root", &self.transcript_root)?;
        ensure_positive("transcript.action_count", self.action_count)?;
        ensure_hex_root(
            "transcript.disclosure_policy_root",
            &self.disclosure_policy_root,
        )?;
        ensure_height_order(
            "transcript.submitted",
            self.submitted_at_height,
            self.expires_at_height,
        )?;
        let expected = encrypted_session_transcript_id(&self.session_id, &self.transcript_root);
        if self.transcript_id != expected {
            return Err("encrypted session transcript id mismatch".to_string());
        }
        Ok(self.transcript_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastRevocationReceipt {
    pub revocation_id: String,
    pub session_id: String,
    pub revoker_commitment_root: String,
    pub reason_root: String,
    pub effective_at_height: u64,
    pub expires_at_height: u64,
    pub status: RevocationStatus,
}

impl FastRevocationReceipt {
    pub fn new(
        session_id: &str,
        revoker_commitment_root: &str,
        reason: &Value,
        effective_at_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("revocation.session_id", session_id)?;
        ensure_hex_root(
            "revocation.revoker_commitment_root",
            revoker_commitment_root,
        )?;
        ensure_height_order(
            "revocation.effective",
            effective_at_height,
            expires_at_height,
        )?;
        let reason_root =
            confidential_account_session_layer_payload_root("SESSION-REVOCATION-REASON", reason);
        let revocation_id =
            fast_revocation_receipt_id(session_id, revoker_commitment_root, effective_at_height);
        let item = Self {
            revocation_id,
            session_id: session_id.to_string(),
            revoker_commitment_root: revoker_commitment_root.to_string(),
            reason_root,
            effective_at_height,
            expires_at_height,
            status: RevocationStatus::Pending,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "revocation_id": self.revocation_id,
            "session_id": self.session_id,
            "revoker_commitment_root": self.revoker_commitment_root,
            "reason_root": self.reason_root,
            "effective_at_height": self.effective_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("revocation.revocation_id", &self.revocation_id)?;
        ensure_non_empty("revocation.session_id", &self.session_id)?;
        ensure_hex_root(
            "revocation.revoker_commitment_root",
            &self.revoker_commitment_root,
        )?;
        ensure_hex_root("revocation.reason_root", &self.reason_root)?;
        ensure_height_order(
            "revocation.effective",
            self.effective_at_height,
            self.expires_at_height,
        )?;
        let expected = fast_revocation_receipt_id(
            &self.session_id,
            &self.revoker_commitment_root,
            self.effective_at_height,
        );
        if self.revocation_id != expected {
            return Err("fast revocation receipt id mismatch".to_string());
        }
        Ok(self.revocation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNonceRecord {
    pub nonce_id: String,
    pub session_id: String,
    pub nonce_commitment_root: String,
    pub action_domain_root: String,
    pub first_seen_height: u64,
    pub expires_at_height: u64,
    pub status: ReplayNonceStatus,
}

impl ReplayNonceRecord {
    pub fn new(
        session_id: &str,
        nonce_commitment_root: &str,
        action_domain_root: &str,
        first_seen_height: u64,
        expires_at_height: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("nonce.session_id", session_id)?;
        ensure_hex_root("nonce.nonce_commitment_root", nonce_commitment_root)?;
        ensure_hex_root("nonce.action_domain_root", action_domain_root)?;
        ensure_height_order("nonce.first_seen", first_seen_height, expires_at_height)?;
        let nonce_id = replay_nonce_record_id(session_id, nonce_commitment_root);
        let item = Self {
            nonce_id,
            session_id: session_id.to_string(),
            nonce_commitment_root: nonce_commitment_root.to_string(),
            action_domain_root: action_domain_root.to_string(),
            first_seen_height,
            expires_at_height,
            status: ReplayNonceStatus::Fresh,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "nonce_id": self.nonce_id,
            "session_id": self.session_id,
            "nonce_commitment_root": self.nonce_commitment_root,
            "action_domain_root": self.action_domain_root,
            "first_seen_height": self.first_seen_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("nonce.nonce_id", &self.nonce_id)?;
        ensure_non_empty("nonce.session_id", &self.session_id)?;
        ensure_hex_root("nonce.nonce_commitment_root", &self.nonce_commitment_root)?;
        ensure_hex_root("nonce.action_domain_root", &self.action_domain_root)?;
        ensure_height_order(
            "nonce.first_seen",
            self.first_seen_height,
            self.expires_at_height,
        )?;
        let expected = replay_nonce_record_id(&self.session_id, &self.nonce_commitment_root);
        if self.nonce_id != expected {
            return Err("replay nonce record id mismatch".to_string());
        }
        Ok(self.nonce_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPublicRecord {
    pub record_id: String,
    pub record_kind: String,
    pub payload_root: String,
    pub emitted_at_height: u64,
    pub sequence: u64,
}

impl SessionPublicRecord {
    pub fn new(
        record_kind: &str,
        payload: &Value,
        emitted_at_height: u64,
        sequence: u64,
    ) -> ConfidentialAccountSessionLayerResult<Self> {
        ensure_non_empty("record.record_kind", record_kind)?;
        let payload_root = confidential_account_session_layer_payload_root(
            "SESSION-PUBLIC-RECORD-PAYLOAD",
            payload,
        );
        let record_id =
            session_public_record_id(record_kind, &payload_root, emitted_at_height, sequence);
        let item = Self {
            record_id,
            record_kind: record_kind.to_string(),
            payload_root,
            emitted_at_height,
            sequence,
        };
        item.validate()?;
        Ok(item)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "record_id": self.record_id,
            "record_kind": self.record_kind,
            "payload_root": self.payload_root,
            "emitted_at_height": self.emitted_at_height,
            "sequence": self.sequence,
        })
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_non_empty("record.record_id", &self.record_id)?;
        ensure_non_empty("record.record_kind", &self.record_kind)?;
        ensure_hex_root("record.payload_root", &self.payload_root)?;
        let expected = session_public_record_id(
            &self.record_kind,
            &self.payload_root,
            self.emitted_at_height,
            self.sequence,
        );
        if self.record_id != expected {
            return Err("session public record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAccountSessionLayerRoots {
    pub config_root: String,
    pub session_key_root: String,
    pub permission_scope_root: String,
    pub spend_cap_root: String,
    pub paymaster_grant_root: String,
    pub recovery_delegate_root: String,
    pub transcript_root: String,
    pub revocation_root: String,
    pub replay_nonce_root: String,
    pub public_record_root: String,
}

impl ConfidentialAccountSessionLayerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_account_session_layer_roots",
            "protocol_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "session_key_root": self.session_key_root,
            "permission_scope_root": self.permission_scope_root,
            "spend_cap_root": self.spend_cap_root,
            "paymaster_grant_root": self.paymaster_grant_root,
            "recovery_delegate_root": self.recovery_delegate_root,
            "transcript_root": self.transcript_root,
            "revocation_root": self.revocation_root,
            "replay_nonce_root": self.replay_nonce_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        confidential_account_session_layer_payload_root(
            "CONFIDENTIAL-ACCOUNT-SESSION-LAYER-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAccountSessionLayerCounters {
    pub session_key_count: u64,
    pub active_session_key_count: u64,
    pub permission_scope_count: u64,
    pub active_permission_scope_count: u64,
    pub spend_cap_count: u64,
    pub active_spend_cap_count: u64,
    pub paymaster_grant_count: u64,
    pub active_paymaster_grant_count: u64,
    pub recovery_delegate_count: u64,
    pub active_recovery_delegate_count: u64,
    pub transcript_count: u64,
    pub accepted_transcript_count: u64,
    pub revocation_count: u64,
    pub live_revocation_count: u64,
    pub replay_nonce_count: u64,
    pub fresh_replay_nonce_count: u64,
    pub public_record_count: u64,
    pub total_available_paymaster_units: u64,
}

impl ConfidentialAccountSessionLayerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_account_session_layer_counters",
            "protocol_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PROTOCOL_VERSION,
            "session_key_count": self.session_key_count,
            "active_session_key_count": self.active_session_key_count,
            "permission_scope_count": self.permission_scope_count,
            "active_permission_scope_count": self.active_permission_scope_count,
            "spend_cap_count": self.spend_cap_count,
            "active_spend_cap_count": self.active_spend_cap_count,
            "paymaster_grant_count": self.paymaster_grant_count,
            "active_paymaster_grant_count": self.active_paymaster_grant_count,
            "recovery_delegate_count": self.recovery_delegate_count,
            "active_recovery_delegate_count": self.active_recovery_delegate_count,
            "transcript_count": self.transcript_count,
            "accepted_transcript_count": self.accepted_transcript_count,
            "revocation_count": self.revocation_count,
            "live_revocation_count": self.live_revocation_count,
            "replay_nonce_count": self.replay_nonce_count,
            "fresh_replay_nonce_count": self.fresh_replay_nonce_count,
            "public_record_count": self.public_record_count,
            "total_available_paymaster_units": self.total_available_paymaster_units,
        })
    }

    pub fn counters_root(&self) -> String {
        confidential_account_session_layer_payload_root(
            "CONFIDENTIAL-ACCOUNT-SESSION-LAYER-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAccountSessionLayerState {
    pub height: u64,
    pub config: ConfidentialAccountSessionLayerConfig,
    pub session_keys: BTreeMap<String, ShieldedSessionKey>,
    pub permission_scopes: BTreeMap<String, SessionPermissionScope>,
    pub spend_caps: BTreeMap<String, SessionSpendCap>,
    pub paymaster_grants: BTreeMap<String, PrivatePaymasterGrant>,
    pub recovery_delegates: BTreeMap<String, PqRecoveryDelegate>,
    pub transcripts: BTreeMap<String, EncryptedSessionTranscript>,
    pub revocations: BTreeMap<String, FastRevocationReceipt>,
    pub replay_nonces: BTreeMap<String, ReplayNonceRecord>,
    pub public_records: BTreeMap<String, SessionPublicRecord>,
}

impl ConfidentialAccountSessionLayerState {
    pub fn new(config: ConfidentialAccountSessionLayerConfig, height: u64) -> Self {
        Self {
            height,
            config,
            session_keys: BTreeMap::new(),
            permission_scopes: BTreeMap::new(),
            spend_caps: BTreeMap::new(),
            paymaster_grants: BTreeMap::new(),
            recovery_delegates: BTreeMap::new(),
            transcripts: BTreeMap::new(),
            revocations: BTreeMap::new(),
            replay_nonces: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> ConfidentialAccountSessionLayerResult<Self> {
        let config = ConfidentialAccountSessionLayerConfig::devnet();
        let mut state = Self::new(
            config.clone(),
            CONFIDENTIAL_ACCOUNT_SESSION_LAYER_DEVNET_HEIGHT,
        );
        let scopes = vec![
            "token:transfer:dxmr".to_string(),
            "private_swap:dxmr-dusd".to_string(),
            "contract:call:private-vault".to_string(),
        ];
        let account_root =
            confidential_account_session_layer_string_root("devnet-account", "alice");
        let session = ShieldedSessionKey::new(
            &account_root,
            &confidential_account_session_layer_string_root("devnet-session-key", "alice-fast"),
            "devnet-alice-ml-dsa-87-authority",
            SessionAuthorityRole::Owner,
            config.min_privacy_set_size.saturating_mul(2),
            &scopes,
            state.height,
            state.height.saturating_add(config.session_ttl_blocks),
            &confidential_account_session_layer_string_root("devnet-nonce-domain", "alice-fast"),
        )?;
        let session_id = state.insert_session_key(session)?;
        for (index, scope) in [
            PermissionScopeKind::TokenTransfer,
            PermissionScopeKind::PrivateSwap,
            PermissionScopeKind::ContractCall,
        ]
        .into_iter()
        .enumerate()
        {
            let permission = SessionPermissionScope::new(
                &session_id,
                scope,
                &confidential_account_session_layer_string_root(
                    "devnet-target",
                    &format!("target-{index}"),
                ),
                &confidential_account_session_layer_string_root(
                    "devnet-method",
                    &format!("method-{index}"),
                ),
                Some(config.fee_asset_id.clone()),
                10_000_u64.saturating_add(index as u64),
                state.height,
                state.height.saturating_add(config.session_ttl_blocks),
            )?;
            state.insert_permission_scope(permission)?;
        }
        let cap = SessionSpendCap::new(
            &session_id,
            &config.fee_asset_id,
            &confidential_account_session_layer_string_root("devnet-cap", "dxmr"),
            &confidential_account_session_layer_string_root("devnet-spent", "dxmr"),
            config.max_spend_cap_bps,
            state.height,
            state.height.saturating_add(config.session_ttl_blocks),
        )?;
        state.insert_spend_cap(cap)?;
        let grant = PrivatePaymasterGrant::new(
            &session_id,
            "devnet-private-paymaster-a",
            "low-fee-session-lane",
            &config.fee_asset_id,
            250_000,
            &json!({"max_fee_units": 125, "session": session_id}),
            state.height,
            state.height.saturating_add(config.sponsor_ttl_blocks),
        )?;
        state.insert_paymaster_grant(grant)?;
        let delegate = PqRecoveryDelegate::new(
            &account_root,
            "devnet-guardian-a-ml-dsa-87",
            SessionAuthorityRole::RecoveryDelegate,
            1,
            &confidential_account_session_layer_string_root("devnet-delegate-sig", "guardian-a"),
            state.height,
            state.height.saturating_add(config.session_ttl_blocks),
        )?;
        state.insert_recovery_delegate(delegate)?;
        let transcript = EncryptedSessionTranscript::new(
            &session_id,
            &confidential_account_session_layer_string_root("devnet-transcript", "session-a"),
            3,
            &json!({"audience": "owner_and_recovery_delegate", "max_disclosure_bps": 250}),
            state.height,
            state.height.saturating_add(config.session_ttl_blocks),
        )?;
        state.insert_transcript(transcript)?;
        let nonce = ReplayNonceRecord::new(
            &session_id,
            &confidential_account_session_layer_string_root("devnet-replay-nonce", "1"),
            &confidential_account_session_layer_string_root("devnet-action-domain", "swap"),
            state.height,
            state.height.saturating_add(config.replay_window_blocks),
        )?;
        state.insert_replay_nonce(nonce)?;
        let revocation = FastRevocationReceipt::new(
            &session_id,
            &confidential_account_session_layer_string_root("devnet-revoker", "alice"),
            &json!({"reason": "devnet-fast-revocation-drill"}),
            state.height.saturating_add(12),
            state
                .height
                .saturating_add(12)
                .saturating_add(config.revocation_ttl_blocks),
        )?;
        state.insert_revocation(revocation)?;
        state.insert_public_record(SessionPublicRecord::new(
            "devnet_confidential_session_summary",
            &json!({
                "session_id": session_id,
                "account_root": account_root,
                "low_fee_lane": "low-fee-session-lane",
                "scheme": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SESSION_KEY_SCHEME,
            }),
            state.height,
            1,
        )?)?;
        state.validate()?;
        Ok(state)
    }

    pub fn insert_session_key(
        &mut self,
        session: ShieldedSessionKey,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "session_keys",
            self.session_keys.len(),
            self.config.max_session_keys,
        )?;
        if session.privacy_set_size < self.config.min_privacy_set_size {
            return Err("session privacy set below configured minimum".to_string());
        }
        let id = session.validate()?;
        self.session_keys.insert(id.clone(), session);
        Ok(id)
    }

    pub fn insert_permission_scope(
        &mut self,
        permission: SessionPermissionScope,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "permission_scopes",
            self.permission_scopes.len(),
            self.config.max_permission_scopes,
        )?;
        if !self.session_keys.contains_key(&permission.session_id) {
            return Err("permission references unknown session".to_string());
        }
        let id = permission.validate()?;
        self.permission_scopes.insert(id.clone(), permission);
        Ok(id)
    }

    pub fn insert_spend_cap(
        &mut self,
        cap: SessionSpendCap,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "spend_caps",
            self.spend_caps.len(),
            self.config.max_spend_caps,
        )?;
        if !self.session_keys.contains_key(&cap.session_id) {
            return Err("spend cap references unknown session".to_string());
        }
        if cap.max_cap_bps > self.config.max_spend_cap_bps {
            return Err("spend cap exceeds configured maximum".to_string());
        }
        let id = cap.validate()?;
        self.spend_caps.insert(id.clone(), cap);
        Ok(id)
    }

    pub fn insert_paymaster_grant(
        &mut self,
        grant: PrivatePaymasterGrant,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "paymaster_grants",
            self.paymaster_grants.len(),
            self.config.max_paymaster_grants,
        )?;
        if !self.session_keys.contains_key(&grant.session_id) {
            return Err("paymaster grant references unknown session".to_string());
        }
        let id = grant.validate()?;
        self.paymaster_grants.insert(id.clone(), grant);
        Ok(id)
    }

    pub fn insert_recovery_delegate(
        &mut self,
        delegate: PqRecoveryDelegate,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "recovery_delegates",
            self.recovery_delegates.len(),
            self.config.max_recovery_delegates,
        )?;
        let id = delegate.validate()?;
        self.recovery_delegates.insert(id.clone(), delegate);
        Ok(id)
    }

    pub fn insert_transcript(
        &mut self,
        transcript: EncryptedSessionTranscript,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "transcripts",
            self.transcripts.len(),
            self.config.max_transcripts,
        )?;
        if !self.session_keys.contains_key(&transcript.session_id) {
            return Err("transcript references unknown session".to_string());
        }
        let id = transcript.validate()?;
        self.transcripts.insert(id.clone(), transcript);
        Ok(id)
    }

    pub fn insert_revocation(
        &mut self,
        revocation: FastRevocationReceipt,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "revocations",
            self.revocations.len(),
            self.config.max_revocations,
        )?;
        if !self.session_keys.contains_key(&revocation.session_id) {
            return Err("revocation references unknown session".to_string());
        }
        let id = revocation.validate()?;
        self.revocations.insert(id.clone(), revocation);
        Ok(id)
    }

    pub fn insert_replay_nonce(
        &mut self,
        nonce: ReplayNonceRecord,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "replay_nonces",
            self.replay_nonces.len(),
            self.config.max_replay_nonces,
        )?;
        if !self.session_keys.contains_key(&nonce.session_id) {
            return Err("replay nonce references unknown session".to_string());
        }
        let id = nonce.validate()?;
        self.replay_nonces.insert(id.clone(), nonce);
        Ok(id)
    }

    pub fn insert_public_record(
        &mut self,
        record: SessionPublicRecord,
    ) -> ConfidentialAccountSessionLayerResult<String> {
        ensure_insert_capacity(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        let id = record.validate()?;
        self.public_records.insert(id.clone(), record);
        Ok(id)
    }

    pub fn set_height(&mut self, height: u64) -> ConfidentialAccountSessionLayerResult<()> {
        if height < self.height {
            return Err(
                "confidential account session layer height cannot move backwards".to_string(),
            );
        }
        self.height = height;
        for session in self.session_keys.values_mut() {
            if session.status.live() && session.expires_at_height <= height {
                session.status = SessionKeyStatus::Expired;
            } else if session.status == SessionKeyStatus::Pending {
                session.status = SessionKeyStatus::Active;
            }
        }
        for permission in self.permission_scopes.values_mut() {
            if permission.status.usable() && permission.expires_at_height <= height {
                permission.status = PermissionScopeStatus::Expired;
            }
        }
        for cap in self.spend_caps.values_mut() {
            if cap.status.usable() && cap.expires_at_height <= height {
                cap.status = SpendCapStatus::Expired;
            }
        }
        for grant in self.paymaster_grants.values_mut() {
            if grant.status.available() && grant.expires_at_height <= height {
                grant.status = PaymasterGrantStatus::Expired;
            }
        }
        for delegate in self.recovery_delegates.values_mut() {
            if delegate.status.usable() && delegate.expires_at_height <= height {
                delegate.status = RecoveryDelegateStatus::Expired;
            }
        }
        for transcript in self.transcripts.values_mut() {
            if transcript.status == TranscriptStatus::Submitted {
                transcript.status = TranscriptStatus::Accepted;
            }
            if transcript.expires_at_height <= height
                && matches!(
                    transcript.status,
                    TranscriptStatus::Submitted | TranscriptStatus::Accepted
                )
            {
                transcript.status = TranscriptStatus::Expired;
            }
        }
        let mut revoked_sessions = BTreeSet::new();
        for revocation in self.revocations.values_mut() {
            if revocation.status.live() && revocation.effective_at_height <= height {
                revocation.status = RevocationStatus::Effective;
                revoked_sessions.insert(revocation.session_id.clone());
            }
            if revocation.status.live() && revocation.expires_at_height <= height {
                revocation.status = RevocationStatus::Expired;
            }
        }
        for session_id in revoked_sessions {
            if let Some(session) = self.session_keys.get_mut(&session_id) {
                session.status = SessionKeyStatus::Revoked;
            }
        }
        for nonce in self.replay_nonces.values_mut() {
            if nonce.status == ReplayNonceStatus::Fresh && nonce.expires_at_height <= height {
                nonce.status = ReplayNonceStatus::Expired;
            }
        }
        self.validate()?;
        Ok(())
    }

    pub fn active_session_ids(&self) -> Vec<String> {
        self.session_keys
            .iter()
            .filter(|(_, session)| session.status.usable())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn active_recovery_delegate_ids(&self) -> Vec<String> {
        self.recovery_delegates
            .iter()
            .filter(|(_, delegate)| delegate.status.usable())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn total_available_paymaster_units(&self) -> u64 {
        self.paymaster_grants
            .values()
            .filter(|grant| grant.status.available())
            .map(PrivatePaymasterGrant::available_units)
            .fold(0_u64, u64::saturating_add)
    }

    pub fn roots(&self) -> ConfidentialAccountSessionLayerRoots {
        ConfidentialAccountSessionLayerRoots {
            config_root: self.config.config_root(),
            session_key_root: session_key_root(&self.session_keys),
            permission_scope_root: permission_scope_root(&self.permission_scopes),
            spend_cap_root: spend_cap_root(&self.spend_caps),
            paymaster_grant_root: paymaster_grant_root(&self.paymaster_grants),
            recovery_delegate_root: recovery_delegate_root(&self.recovery_delegates),
            transcript_root: transcript_root(&self.transcripts),
            revocation_root: revocation_root(&self.revocations),
            replay_nonce_root: replay_nonce_root(&self.replay_nonces),
            public_record_root: session_public_record_root(&self.public_records),
        }
    }

    pub fn counters(&self) -> ConfidentialAccountSessionLayerCounters {
        ConfidentialAccountSessionLayerCounters {
            session_key_count: self.session_keys.len() as u64,
            active_session_key_count: self
                .session_keys
                .values()
                .filter(|session| session.status.usable())
                .count() as u64,
            permission_scope_count: self.permission_scopes.len() as u64,
            active_permission_scope_count: self
                .permission_scopes
                .values()
                .filter(|permission| permission.status.usable())
                .count() as u64,
            spend_cap_count: self.spend_caps.len() as u64,
            active_spend_cap_count: self
                .spend_caps
                .values()
                .filter(|cap| cap.status.usable())
                .count() as u64,
            paymaster_grant_count: self.paymaster_grants.len() as u64,
            active_paymaster_grant_count: self
                .paymaster_grants
                .values()
                .filter(|grant| grant.status.available())
                .count() as u64,
            recovery_delegate_count: self.recovery_delegates.len() as u64,
            active_recovery_delegate_count: self
                .recovery_delegates
                .values()
                .filter(|delegate| delegate.status.usable())
                .count() as u64,
            transcript_count: self.transcripts.len() as u64,
            accepted_transcript_count: self
                .transcripts
                .values()
                .filter(|transcript| transcript.status == TranscriptStatus::Accepted)
                .count() as u64,
            revocation_count: self.revocations.len() as u64,
            live_revocation_count: self
                .revocations
                .values()
                .filter(|revocation| revocation.status.live())
                .count() as u64,
            replay_nonce_count: self.replay_nonces.len() as u64,
            fresh_replay_nonce_count: self
                .replay_nonces
                .values()
                .filter(|nonce| nonce.status == ReplayNonceStatus::Fresh)
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_available_paymaster_units: self.total_available_paymaster_units(),
        }
    }

    pub fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_account_session_layer_state",
            "protocol_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_PROTOCOL_VERSION,
            "schema_version": CONFIDENTIAL_ACCOUNT_SESSION_LAYER_SCHEMA_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
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
        confidential_account_session_layer_state_root_from_record(
            &self.public_record_without_state_root(),
        )
    }

    pub fn validate(&self) -> ConfidentialAccountSessionLayerResult<String> {
        self.config.validate()?;
        ensure_count_at_most(
            "session_keys",
            self.session_keys.len(),
            self.config.max_session_keys,
        )?;
        ensure_count_at_most(
            "permission_scopes",
            self.permission_scopes.len(),
            self.config.max_permission_scopes,
        )?;
        ensure_count_at_most(
            "spend_caps",
            self.spend_caps.len(),
            self.config.max_spend_caps,
        )?;
        ensure_count_at_most(
            "paymaster_grants",
            self.paymaster_grants.len(),
            self.config.max_paymaster_grants,
        )?;
        ensure_count_at_most(
            "recovery_delegates",
            self.recovery_delegates.len(),
            self.config.max_recovery_delegates,
        )?;
        ensure_count_at_most(
            "transcripts",
            self.transcripts.len(),
            self.config.max_transcripts,
        )?;
        ensure_count_at_most(
            "revocations",
            self.revocations.len(),
            self.config.max_revocations,
        )?;
        ensure_count_at_most(
            "replay_nonces",
            self.replay_nonces.len(),
            self.config.max_replay_nonces,
        )?;
        ensure_count_at_most(
            "public_records",
            self.public_records.len(),
            self.config.max_public_records,
        )?;
        for (id, session) in &self.session_keys {
            if id != &session.validate()? {
                return Err("session key map key mismatch".to_string());
            }
            if session.privacy_set_size < self.config.min_privacy_set_size {
                return Err("session privacy set below configured minimum".to_string());
            }
        }
        for (id, permission) in &self.permission_scopes {
            if id != &permission.validate()? {
                return Err("permission scope map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&permission.session_id) {
                return Err("permission references unknown session".to_string());
            }
        }
        for (id, cap) in &self.spend_caps {
            if id != &cap.validate()? {
                return Err("spend cap map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&cap.session_id) {
                return Err("spend cap references unknown session".to_string());
            }
        }
        for (id, grant) in &self.paymaster_grants {
            if id != &grant.validate()? {
                return Err("paymaster grant map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&grant.session_id) {
                return Err("paymaster grant references unknown session".to_string());
            }
        }
        for (id, delegate) in &self.recovery_delegates {
            if id != &delegate.validate()? {
                return Err("recovery delegate map key mismatch".to_string());
            }
        }
        for (id, transcript) in &self.transcripts {
            if id != &transcript.validate()? {
                return Err("transcript map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&transcript.session_id) {
                return Err("transcript references unknown session".to_string());
            }
        }
        for (id, revocation) in &self.revocations {
            if id != &revocation.validate()? {
                return Err("revocation map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&revocation.session_id) {
                return Err("revocation references unknown session".to_string());
            }
        }
        for (id, nonce) in &self.replay_nonces {
            if id != &nonce.validate()? {
                return Err("replay nonce map key mismatch".to_string());
            }
            if !self.session_keys.contains_key(&nonce.session_id) {
                return Err("replay nonce references unknown session".to_string());
            }
        }
        for (id, record) in &self.public_records {
            if id != &record.validate()? {
                return Err("public record map key mismatch".to_string());
            }
        }
        Ok(self.state_root())
    }
}

pub fn confidential_account_session_layer_state_root_from_record(record: &Value) -> String {
    confidential_account_session_layer_payload_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-LAYER-STATE",
        record,
    )
}

pub fn confidential_account_session_layer_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn confidential_account_session_layer_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-LAYER-STRING",
        &[HashPart::Str(domain), HashPart::Str(value)],
        32,
    )
}

pub fn shielded_session_key_id(
    account_commitment_root: &str,
    session_key_commitment: &str,
    scope_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-KEY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment_root),
            HashPart::Str(session_key_commitment),
            HashPart::Str(scope_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn session_permission_scope_id(
    session_id: &str,
    scope_kind: &str,
    method_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-PERMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(scope_kind),
            HashPart::Str(method_root),
        ],
        32,
    )
}

pub fn session_spend_cap_id(session_id: &str, asset_id: &str, cap_commitment_root: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-SPEND-CAP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(asset_id),
            HashPart::Str(cap_commitment_root),
        ],
        32,
    )
}

pub fn private_paymaster_grant_id(
    session_id: &str,
    paymaster_id: &str,
    policy_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-PAYMASTER-GRANT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(paymaster_id),
            HashPart::Str(policy_root),
        ],
        32,
    )
}

pub fn pq_recovery_delegate_id(
    account_commitment_root: &str,
    delegate_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-RECOVERY-DELEGATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment_root),
            HashPart::Str(delegate_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn encrypted_session_transcript_id(session_id: &str, transcript_root: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-TRANSCRIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(transcript_root),
        ],
        32,
    )
}

pub fn fast_revocation_receipt_id(
    session_id: &str,
    revoker_commitment_root: &str,
    effective_at_height: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-REVOCATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(revoker_commitment_root),
            HashPart::Int(effective_at_height as i128),
        ],
        32,
    )
}

pub fn replay_nonce_record_id(session_id: &str, nonce_commitment_root: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-REPLAY-NONCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(session_id),
            HashPart::Str(nonce_commitment_root),
        ],
        32,
    )
}

pub fn session_public_record_id(
    record_kind: &str,
    payload_root: &str,
    emitted_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ACCOUNT-SESSION-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(record_kind),
            HashPart::Str(payload_root),
            HashPart::Int(emitted_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn session_key_root(records: &BTreeMap<String, ShieldedSessionKey>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-KEY-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn permission_scope_root(records: &BTreeMap<String, SessionPermissionScope>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-PERMISSION-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn spend_cap_root(records: &BTreeMap<String, SessionSpendCap>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-SPEND-CAP-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn paymaster_grant_root(records: &BTreeMap<String, PrivatePaymasterGrant>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-PAYMASTER-GRANT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn recovery_delegate_root(records: &BTreeMap<String, PqRecoveryDelegate>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-RECOVERY-DELEGATE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn transcript_root(records: &BTreeMap<String, EncryptedSessionTranscript>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-TRANSCRIPT-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn revocation_root(records: &BTreeMap<String, FastRevocationReceipt>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-REVOCATION-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn replay_nonce_root(records: &BTreeMap<String, ReplayNonceRecord>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-REPLAY-NONCE-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

pub fn session_public_record_root(records: &BTreeMap<String, SessionPublicRecord>) -> String {
    keyed_record_root(
        "CONFIDENTIAL-ACCOUNT-SESSION-PUBLIC-RECORD-ROOT",
        records
            .iter()
            .map(|(id, record)| (id, record.public_record())),
    )
}

fn keyed_record_root<'a, I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = (&'a String, Value)>,
{
    let leaves = records
        .into_iter()
        .map(|(id, record)| json!({ "id": id, "record": record }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn merkle_string_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn ensure_non_empty(field: &str, value: &str) -> ConfidentialAccountSessionLayerResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(())
}

fn ensure_non_empty_list(
    field: &str,
    values: &[String],
) -> ConfidentialAccountSessionLayerResult<()> {
    if values.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(field, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}

fn ensure_positive(field: &str, value: u64) -> ConfidentialAccountSessionLayerResult<()> {
    if value == 0 {
        return Err(format!("{field} must be positive"));
    }
    Ok(())
}

fn ensure_capacity(field: &str, value: usize) -> ConfidentialAccountSessionLayerResult<()> {
    if value == 0 {
        return Err(format!("{field} capacity must be positive"));
    }
    Ok(())
}

fn ensure_insert_capacity(
    field: &str,
    current: usize,
    limit: usize,
) -> ConfidentialAccountSessionLayerResult<()> {
    if current >= limit {
        return Err(format!("{field} capacity exceeded"));
    }
    Ok(())
}

fn ensure_count_at_most(
    field: &str,
    current: usize,
    limit: usize,
) -> ConfidentialAccountSessionLayerResult<()> {
    if current > limit {
        return Err(format!("{field} capacity exceeded"));
    }
    Ok(())
}

fn ensure_bps(field: &str, value: u64) -> ConfidentialAccountSessionLayerResult<()> {
    if value > CONFIDENTIAL_ACCOUNT_SESSION_LAYER_MAX_BPS {
        return Err(format!("{field} exceeds 100%"));
    }
    Ok(())
}

fn ensure_height_order(
    field: &str,
    start_height: u64,
    end_height: u64,
) -> ConfidentialAccountSessionLayerResult<()> {
    if end_height <= start_height {
        return Err(format!("{field} end height must be after start height"));
    }
    Ok(())
}

fn ensure_hex_root(field: &str, value: &str) -> ConfidentialAccountSessionLayerResult<()> {
    ensure_non_empty(field, value)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 32-byte hex commitment"));
    }
    Ok(())
}
