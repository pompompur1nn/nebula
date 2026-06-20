use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PqAccountSessionFeeSponsorResult<T> = Result<T, String>;

pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_PROTOCOL_VERSION: &str =
    "nebula-pq-account-session-fee-sponsor-v1";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_SCHEMA_VERSION: &str =
    "pq-account-session-fee-sponsor-state-v1";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_SECURITY_MODEL: &str =
    "deterministic-devnet-pq-private-fee-sponsor-not-real-crypto";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_PROOF_SYSTEM: &str =
    "zk-private-account-session-fee-sponsor-shake256-v1";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-canonical-json";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_NULLIFIER_SCHEME: &str =
    "one-time-session-fee-nullifier-v1";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEVNET_LABEL: &str =
    "devnet-pq-account-session-fee-sponsor";
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_HEIGHT: u64 = 360;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_EPOCH_BLOCKS: u64 = 240;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_GRANT_TTL_BLOCKS: u64 = 72;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_RATE_WINDOW_BLOCKS: u64 = 32;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 720;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAccountSessionStatus {
    Active,
    Frozen,
    Recovery,
    Suspended,
    Closed,
}

impl PqAccountSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Frozen => "frozen",
            Self::Recovery => "recovery",
            Self::Suspended => "suspended",
            Self::Closed => "closed",
        }
    }

    pub fn can_open_session(self) -> bool {
        matches!(self, Self::Active | Self::Recovery)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSessionGrantStatus {
    Offered,
    Active,
    Exhausted,
    Expired,
    Revoked,
    Challenged,
}

impl PqSessionGrantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Challenged => "challenged",
        }
    }

    pub fn can_spend(self) -> bool {
        matches!(self, Self::Offered | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCredentialKind {
    OnlineMlDsa,
    RecoverySlhDsa,
    DeviceMlKem,
    HardwareWitness,
    ContractDelegate,
    SponsorBlindCredential,
}

impl PqCredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnlineMlDsa => "online_ml_dsa",
            Self::RecoverySlhDsa => "recovery_slh_dsa",
            Self::DeviceMlKem => "device_ml_kem",
            Self::HardwareWitness => "hardware_witness",
            Self::ContractDelegate => "contract_delegate",
            Self::SponsorBlindCredential => "sponsor_blind_credential",
        }
    }

    pub fn scheme(self) -> &'static str {
        match self {
            Self::OnlineMlDsa | Self::HardwareWitness | Self::ContractDelegate => "ML-DSA-65",
            Self::RecoverySlhDsa => "SLH-DSA-SHAKE-128s",
            Self::DeviceMlKem => "ML-KEM-768",
            Self::SponsorBlindCredential => {
                "ML-DSA-65+SLH-DSA-SHAKE-128s-anonymous-sponsor-credential"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqCredentialStatus {
    Pending,
    Active,
    Rotating,
    Revoked,
    Expired,
    Quarantined,
}

impl PqCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Pending | Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPermissionScope {
    PrivateTransfer,
    ContractCall,
    DefiSwap,
    MoneroBridgeExit,
    LiquidityRoute,
    ProofAggregation,
    WalletRecovery,
    Automation,
}

impl PqPermissionScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::DefiSwap => "defi_swap",
            Self::MoneroBridgeExit => "monero_bridge_exit",
            Self::LiquidityRoute => "liquidity_route",
            Self::ProofAggregation => "proof_aggregation",
            Self::WalletRecovery => "wallet_recovery",
            Self::Automation => "automation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorPolicyMode {
    Disabled,
    LowFeeOnly,
    PreferShielded,
    RequireShielded,
    RecoverySponsor,
    ContractAllowance,
}

impl SponsorPolicyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LowFeeOnly => "low_fee_only",
            Self::PreferShielded => "prefer_shielded",
            Self::RequireShielded => "require_shielded",
            Self::RecoverySponsor => "recovery_sponsor",
            Self::ContractAllowance => "contract_allowance",
        }
    }

    pub fn allows_sponsorship(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementReceiptStatus {
    Reserved,
    Included,
    Settled,
    Released,
    Disputed,
    Slashed,
}

impl SettlementReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Included => "included",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Disputed => "disputed",
            Self::Slashed => "slashed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryHookStatus {
    Armed,
    Requested,
    DelayElapsed,
    Executed,
    Cancelled,
    Expired,
}

impl RecoveryHookStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Requested => "requested",
            Self::DelayElapsed => "delay_elapsed",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Open,
    Accepted,
    Rejected,
    Slashed,
    Expired,
}

impl ChallengeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

pub trait PqAccountSessionFeeSponsorRooted {
    fn root(&self) -> String;
    fn public_record(&self) -> Value;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAccountSessionFeeSponsorConfig {
    pub config_id: String,
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub security_model: String,
    pub pq_suite: String,
    pub proof_system: String,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub epoch_blocks: u64,
    pub session_ttl_blocks: u64,
    pub grant_ttl_blocks: u64,
    pub rate_window_blocks: u64,
    pub recovery_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_discount_bps: u64,
    pub require_private_nullifiers: bool,
    pub require_pq_credentials: bool,
    pub allow_contract_delegation: bool,
}

impl PqAccountSessionFeeSponsorConfig {
    pub fn devnet() -> PqAccountSessionFeeSponsorResult<Self> {
        let mut config = Self {
            config_id: String::new(),
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PQ_ACCOUNT_SESSION_FEE_SPONSOR_PROTOCOL_VERSION.to_string(),
            schema_version: PQ_ACCOUNT_SESSION_FEE_SPONSOR_SCHEMA_VERSION.to_string(),
            security_model: PQ_ACCOUNT_SESSION_FEE_SPONSOR_SECURITY_MODEL.to_string(),
            pq_suite: PQ_ACCOUNT_SESSION_FEE_SPONSOR_PQ_SUITE.to_string(),
            proof_system: PQ_ACCOUNT_SESSION_FEE_SPONSOR_PROOF_SYSTEM.to_string(),
            commitment_scheme: PQ_ACCOUNT_SESSION_FEE_SPONSOR_COMMITMENT_SCHEME.to_string(),
            nullifier_scheme: PQ_ACCOUNT_SESSION_FEE_SPONSOR_NULLIFIER_SCHEME.to_string(),
            epoch_blocks: PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_EPOCH_BLOCKS,
            session_ttl_blocks: PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_SESSION_TTL_BLOCKS,
            grant_ttl_blocks: PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_GRANT_TTL_BLOCKS,
            rate_window_blocks: PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_RATE_WINDOW_BLOCKS,
            recovery_delay_blocks: PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_RECOVERY_DELAY_BLOCKS,
            min_privacy_set_size: PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PRIVACY_SET_SIZE,
            min_pq_security_bits: PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PQ_SECURITY_BITS,
            max_discount_bps: 8_500,
            require_private_nullifiers: true,
            require_pq_credentials: true,
            allow_contract_delegation: true,
        };
        config.config_id = pq_asfs_config_id(&config.chain_id, &config.protocol_version);
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.config_id, "config id")?;
        ensure_non_empty(&self.chain_id, "chain id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.schema_version, "schema version")?;
        ensure_non_empty(&self.security_model, "security model")?;
        ensure_non_empty(&self.pq_suite, "pq suite")?;
        ensure_non_empty(&self.proof_system, "proof system")?;
        ensure_non_empty(&self.commitment_scheme, "commitment scheme")?;
        ensure_non_empty(&self.nullifier_scheme, "nullifier scheme")?;
        if self.epoch_blocks == 0
            || self.session_ttl_blocks == 0
            || self.grant_ttl_blocks == 0
            || self.rate_window_blocks == 0
            || self.recovery_delay_blocks == 0
        {
            return Err("time windows must be positive".to_string());
        }
        if self.min_privacy_set_size < PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PRIVACY_SET_SIZE {
            return Err("privacy set size below devnet minimum".to_string());
        }
        if self.min_pq_security_bits < PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PQ_SECURITY_BITS {
            return Err("pq security bits below policy minimum".to_string());
        }
        if self.max_discount_bps > PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS {
            return Err("discount bps exceeds maximum".to_string());
        }
        let expected = pq_asfs_config_id(&self.chain_id, &self.protocol_version);
        if self.config_id != expected {
            return Err("config id does not match chain and protocol".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for PqAccountSessionFeeSponsorConfig {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-CONFIG", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_account_session_fee_sponsor_config",
            "config_id": self.config_id,
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "security_model": self.security_model,
            "pq_suite": self.pq_suite,
            "proof_system": self.proof_system,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "epoch_blocks": self.epoch_blocks,
            "session_ttl_blocks": self.session_ttl_blocks,
            "grant_ttl_blocks": self.grant_ttl_blocks,
            "rate_window_blocks": self.rate_window_blocks,
            "recovery_delay_blocks": self.recovery_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_discount_bps": self.max_discount_bps,
            "require_private_nullifiers": self.require_private_nullifiers,
            "require_pq_credentials": self.require_pq_credentials,
            "allow_contract_delegation": self.allow_contract_delegation,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAccountProfile {
    pub account_id: String,
    pub wallet_commitment: String,
    pub recovery_root: String,
    pub spend_authority_root: String,
    pub status: PqAccountSessionStatus,
    pub privacy_set_size: u64,
    pub created_height: u64,
    pub last_active_height: u64,
    pub session_nonce: u64,
    pub active_grant_count: u64,
}

impl PqAccountProfile {
    pub fn new(
        wallet_label: &str,
        recovery_label: &str,
        spend_authority_label: &str,
        height: u64,
        privacy_set_size: u64,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(wallet_label, "wallet label")?;
        ensure_non_empty(recovery_label, "recovery label")?;
        ensure_non_empty(spend_authority_label, "spend authority label")?;
        if privacy_set_size < PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PRIVACY_SET_SIZE {
            return Err("account privacy set too small".to_string());
        }
        let wallet_commitment = pq_asfs_string_root("PQ-ASFS-WALLET", wallet_label);
        let recovery_root = pq_asfs_string_root("PQ-ASFS-RECOVERY", recovery_label);
        let spend_authority_root =
            pq_asfs_string_root("PQ-ASFS-SPEND-AUTHORITY", spend_authority_label);
        let account_id = pq_account_id(&wallet_commitment, &recovery_root, &spend_authority_root);
        let profile = Self {
            account_id,
            wallet_commitment,
            recovery_root,
            spend_authority_root,
            status: PqAccountSessionStatus::Active,
            privacy_set_size,
            created_height: height,
            last_active_height: height,
            session_nonce: 0,
            active_grant_count: 0,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.account_id, "account id")?;
        ensure_non_empty(&self.wallet_commitment, "wallet commitment")?;
        ensure_non_empty(&self.recovery_root, "recovery root")?;
        ensure_non_empty(&self.spend_authority_root, "spend authority root")?;
        if self.privacy_set_size < PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PRIVACY_SET_SIZE {
            return Err("account privacy set below minimum".to_string());
        }
        if self.last_active_height < self.created_height {
            return Err("account last active height precedes creation".to_string());
        }
        let expected = pq_account_id(
            &self.wallet_commitment,
            &self.recovery_root,
            &self.spend_authority_root,
        );
        if self.account_id != expected {
            return Err("account id does not match commitments".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for PqAccountProfile {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-ACCOUNT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_account_profile",
            "account_id": self.account_id,
            "wallet_commitment": self.wallet_commitment,
            "recovery_root": self.recovery_root,
            "spend_authority_root": self.spend_authority_root,
            "status": self.status.as_str(),
            "privacy_set_size": self.privacy_set_size,
            "created_height": self.created_height,
            "last_active_height": self.last_active_height,
            "session_nonce": self.session_nonce,
            "active_grant_count": self.active_grant_count,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqCredential {
    pub credential_id: String,
    pub account_id: String,
    pub kind: PqCredentialKind,
    pub status: PqCredentialStatus,
    pub verification_key_root: String,
    pub device_commitment: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub security_bits: u16,
    pub transcript_root: String,
}

impl PqCredential {
    pub fn issue(
        account_id: &str,
        kind: PqCredentialKind,
        device_label: &str,
        height: u64,
        ttl_blocks: u64,
        transcript_label: &str,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(account_id, "credential account id")?;
        ensure_non_empty(device_label, "credential device label")?;
        ensure_non_empty(transcript_label, "credential transcript label")?;
        if ttl_blocks == 0 {
            return Err("credential ttl must be positive".to_string());
        }
        let verification_key_root = pq_asfs_string_root(
            "PQ-ASFS-CREDENTIAL-KEY",
            &format!("{account_id}:{device_label}"),
        );
        let device_commitment = pq_asfs_string_root("PQ-ASFS-CREDENTIAL-DEVICE", device_label);
        let transcript_root =
            pq_asfs_string_root("PQ-ASFS-CREDENTIAL-TRANSCRIPT", transcript_label);
        let credential_id = pq_credential_id(account_id, kind, &verification_key_root);
        let credential = Self {
            credential_id,
            account_id: account_id.to_string(),
            kind,
            status: PqCredentialStatus::Active,
            verification_key_root,
            device_commitment,
            issued_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            security_bits: PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PQ_SECURITY_BITS,
            transcript_root,
        };
        credential.validate()?;
        Ok(credential)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.credential_id, "credential id")?;
        ensure_non_empty(&self.account_id, "credential account id")?;
        ensure_non_empty(&self.verification_key_root, "credential key root")?;
        ensure_non_empty(&self.device_commitment, "credential device commitment")?;
        ensure_non_empty(&self.transcript_root, "credential transcript root")?;
        if self.expires_height <= self.issued_height {
            return Err("credential expiration must be after issue height".to_string());
        }
        if self.security_bits < PQ_ACCOUNT_SESSION_FEE_SPONSOR_MIN_PQ_SECURITY_BITS {
            return Err("credential security bits below minimum".to_string());
        }
        let expected = pq_credential_id(&self.account_id, self.kind, &self.verification_key_root);
        if self.credential_id != expected {
            return Err("credential id does not match key material".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for PqCredential {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-CREDENTIAL", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "pq_credential",
            "credential_id": self.credential_id,
            "account_id": self.account_id,
            "credential_kind": self.kind.as_str(),
            "credential_scheme": self.kind.scheme(),
            "status": self.status.as_str(),
            "verification_key_root": self.verification_key_root,
            "device_commitment": self.device_commitment,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "security_bits": self.security_bits,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendingCap {
    pub cap_id: String,
    pub account_id: String,
    pub scope: PqPermissionScope,
    pub asset_id: String,
    pub window_blocks: u64,
    pub max_units: u64,
    pub spent_units: u64,
    pub reset_height: u64,
}

impl SpendingCap {
    pub fn new(
        account_id: &str,
        scope: PqPermissionScope,
        asset_id: &str,
        window_blocks: u64,
        max_units: u64,
        reset_height: u64,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(account_id, "spending cap account id")?;
        ensure_non_empty(asset_id, "spending cap asset")?;
        if window_blocks == 0 || max_units == 0 {
            return Err("spending cap window and units must be positive".to_string());
        }
        let cap_id = spending_cap_id(account_id, scope, asset_id, reset_height);
        let cap = Self {
            cap_id,
            account_id: account_id.to_string(),
            scope,
            asset_id: asset_id.to_string(),
            window_blocks,
            max_units,
            spent_units: 0,
            reset_height,
        };
        cap.validate()?;
        Ok(cap)
    }

    pub fn remaining_units(&self) -> u64 {
        self.max_units.saturating_sub(self.spent_units)
    }

    pub fn allows(&self, amount: u64) -> bool {
        amount > 0 && self.remaining_units() >= amount
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.cap_id, "spending cap id")?;
        ensure_non_empty(&self.account_id, "spending cap account id")?;
        ensure_non_empty(&self.asset_id, "spending cap asset")?;
        if self.window_blocks == 0 || self.max_units == 0 {
            return Err("spending cap values must be positive".to_string());
        }
        if self.spent_units > self.max_units {
            return Err("spending cap spent units exceed maximum".to_string());
        }
        let expected = spending_cap_id(
            &self.account_id,
            self.scope,
            &self.asset_id,
            self.reset_height,
        );
        if self.cap_id != expected {
            return Err("spending cap id does not match cap fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for SpendingCap {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-SPENDING-CAP", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "spending_cap",
            "cap_id": self.cap_id,
            "account_id": self.account_id,
            "scope": self.scope.as_str(),
            "asset_id": self.asset_id,
            "window_blocks": self.window_blocks,
            "max_units": self.max_units,
            "spent_units": self.spent_units,
            "remaining_units": self.remaining_units(),
            "reset_height": self.reset_height,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractPermissionScope {
    pub permission_id: String,
    pub account_id: String,
    pub contract_commitment: String,
    pub scope: PqPermissionScope,
    pub method_root: String,
    pub argument_policy_root: String,
    pub max_call_value_units: u64,
    pub expires_height: u64,
    pub sponsor_allowed: bool,
}

impl ContractPermissionScope {
    pub fn new(
        account_id: &str,
        contract_label: &str,
        scope: PqPermissionScope,
        method_label: &str,
        max_call_value_units: u64,
        expires_height: u64,
        sponsor_allowed: bool,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(account_id, "contract permission account id")?;
        ensure_non_empty(contract_label, "contract label")?;
        ensure_non_empty(method_label, "method label")?;
        if max_call_value_units == 0 {
            return Err("contract permission value must be positive".to_string());
        }
        let contract_commitment = pq_asfs_string_root("PQ-ASFS-CONTRACT", contract_label);
        let method_root = pq_asfs_string_root("PQ-ASFS-CONTRACT-METHOD", method_label);
        let argument_policy_root =
            pq_asfs_string_root("PQ-ASFS-CONTRACT-ARGUMENT-POLICY", method_label);
        let permission_id = contract_permission_id(
            account_id,
            &contract_commitment,
            scope,
            &method_root,
            expires_height,
        );
        let permission = Self {
            permission_id,
            account_id: account_id.to_string(),
            contract_commitment,
            scope,
            method_root,
            argument_policy_root,
            max_call_value_units,
            expires_height,
            sponsor_allowed,
        };
        permission.validate()?;
        Ok(permission)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.permission_id, "contract permission id")?;
        ensure_non_empty(&self.account_id, "contract permission account id")?;
        ensure_non_empty(&self.contract_commitment, "contract commitment")?;
        ensure_non_empty(&self.method_root, "contract method root")?;
        ensure_non_empty(&self.argument_policy_root, "argument policy root")?;
        if self.max_call_value_units == 0 {
            return Err("contract permission max call value must be positive".to_string());
        }
        let expected = contract_permission_id(
            &self.account_id,
            &self.contract_commitment,
            self.scope,
            &self.method_root,
            self.expires_height,
        );
        if self.permission_id != expected {
            return Err("contract permission id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for ContractPermissionScope {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-CONTRACT-PERMISSION", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "contract_permission_scope",
            "permission_id": self.permission_id,
            "account_id": self.account_id,
            "contract_commitment": self.contract_commitment,
            "scope": self.scope.as_str(),
            "method_root": self.method_root,
            "argument_policy_root": self.argument_policy_root,
            "max_call_value_units": self.max_call_value_units,
            "expires_height": self.expires_height,
            "sponsor_allowed": self.sponsor_allowed,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeSponsorPolicy {
    pub policy_id: String,
    pub sponsor_id: String,
    pub mode: SponsorPolicyMode,
    pub supported_scopes: BTreeSet<PqPermissionScope>,
    pub max_fee_units: u64,
    pub min_discount_bps: u64,
    pub max_epoch_budget_units: u64,
    pub reserved_epoch_budget_units: u64,
    pub privacy_pool_root: String,
    pub reputation_score: u64,
    pub active: bool,
}

impl LowFeeSponsorPolicy {
    pub fn new(
        sponsor_label: &str,
        mode: SponsorPolicyMode,
        supported_scopes: BTreeSet<PqPermissionScope>,
        max_fee_units: u64,
        min_discount_bps: u64,
        max_epoch_budget_units: u64,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(sponsor_label, "sponsor label")?;
        if supported_scopes.is_empty() {
            return Err("sponsor policy must include at least one scope".to_string());
        }
        if max_fee_units == 0 || max_epoch_budget_units == 0 {
            return Err("sponsor fee and budget must be positive".to_string());
        }
        if min_discount_bps > PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS {
            return Err("sponsor discount bps exceeds maximum".to_string());
        }
        let sponsor_id = pq_asfs_string_root("PQ-ASFS-SPONSOR", sponsor_label);
        let privacy_pool_root = pq_asfs_string_root("PQ-ASFS-SPONSOR-PRIVACY-POOL", sponsor_label);
        let policy_id = sponsor_policy_id(&sponsor_id, mode, max_fee_units);
        let policy = Self {
            policy_id,
            sponsor_id,
            mode,
            supported_scopes,
            max_fee_units,
            min_discount_bps,
            max_epoch_budget_units,
            reserved_epoch_budget_units: 0,
            privacy_pool_root,
            reputation_score: 100,
            active: true,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn supports(&self, scope: PqPermissionScope, fee_units: u64) -> bool {
        self.active
            && self.mode.allows_sponsorship()
            && self.supported_scopes.contains(&scope)
            && fee_units <= self.max_fee_units
            && self.reserved_epoch_budget_units.saturating_add(fee_units)
                <= self.max_epoch_budget_units
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.policy_id, "sponsor policy id")?;
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.privacy_pool_root, "privacy pool root")?;
        if self.supported_scopes.is_empty() {
            return Err("sponsor policy scopes empty".to_string());
        }
        if self.max_fee_units == 0 || self.max_epoch_budget_units == 0 {
            return Err("sponsor policy values must be positive".to_string());
        }
        if self.reserved_epoch_budget_units > self.max_epoch_budget_units {
            return Err("sponsor reserved budget exceeds epoch budget".to_string());
        }
        if self.min_discount_bps > PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS {
            return Err("sponsor policy discount exceeds maximum".to_string());
        }
        let expected = sponsor_policy_id(&self.sponsor_id, self.mode, self.max_fee_units);
        if self.policy_id != expected {
            return Err("sponsor policy id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for LowFeeSponsorPolicy {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-SPONSOR-POLICY", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_policy",
            "policy_id": self.policy_id,
            "sponsor_id": self.sponsor_id,
            "mode": self.mode.as_str(),
            "supported_scopes": self.supported_scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "max_fee_units": self.max_fee_units,
            "min_discount_bps": self.min_discount_bps,
            "max_epoch_budget_units": self.max_epoch_budget_units,
            "reserved_epoch_budget_units": self.reserved_epoch_budget_units,
            "privacy_pool_root": self.privacy_pool_root,
            "reputation_score": self.reputation_score,
            "active": self.active,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub bucket_id: String,
    pub subject_commitment: String,
    pub scope: PqPermissionScope,
    pub window_start_height: u64,
    pub window_blocks: u64,
    pub max_ops: u64,
    pub consumed_ops: u64,
    pub max_fee_units: u64,
    pub consumed_fee_units: u64,
}

impl RateLimitBucket {
    pub fn new(
        subject_commitment: &str,
        scope: PqPermissionScope,
        window_start_height: u64,
        window_blocks: u64,
        max_ops: u64,
        max_fee_units: u64,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(subject_commitment, "rate limit subject")?;
        if window_blocks == 0 || max_ops == 0 || max_fee_units == 0 {
            return Err("rate limit values must be positive".to_string());
        }
        let bucket_id = rate_limit_bucket_id(subject_commitment, scope, window_start_height);
        let bucket = Self {
            bucket_id,
            subject_commitment: subject_commitment.to_string(),
            scope,
            window_start_height,
            window_blocks,
            max_ops,
            consumed_ops: 0,
            max_fee_units,
            consumed_fee_units: 0,
        };
        bucket.validate()?;
        Ok(bucket)
    }

    pub fn consume(&mut self, fee_units: u64) -> PqAccountSessionFeeSponsorResult<()> {
        if fee_units == 0 {
            return Err("rate limit fee units must be positive".to_string());
        }
        if self.consumed_ops.saturating_add(1) > self.max_ops {
            return Err("rate limit operation count exhausted".to_string());
        }
        if self.consumed_fee_units.saturating_add(fee_units) > self.max_fee_units {
            return Err("rate limit fee budget exhausted".to_string());
        }
        self.consumed_ops = self.consumed_ops.saturating_add(1);
        self.consumed_fee_units = self.consumed_fee_units.saturating_add(fee_units);
        Ok(())
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.bucket_id, "rate limit bucket id")?;
        ensure_non_empty(&self.subject_commitment, "rate limit subject")?;
        if self.window_blocks == 0 || self.max_ops == 0 || self.max_fee_units == 0 {
            return Err("rate limit values must be positive".to_string());
        }
        if self.consumed_ops > self.max_ops {
            return Err("rate limit operations exceed maximum".to_string());
        }
        if self.consumed_fee_units > self.max_fee_units {
            return Err("rate limit fee units exceed maximum".to_string());
        }
        let expected = rate_limit_bucket_id(
            &self.subject_commitment,
            self.scope,
            self.window_start_height,
        );
        if self.bucket_id != expected {
            return Err("rate limit bucket id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for RateLimitBucket {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-RATE-LIMIT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "rate_limit_bucket",
            "bucket_id": self.bucket_id,
            "subject_commitment": self.subject_commitment,
            "scope": self.scope.as_str(),
            "window_start_height": self.window_start_height,
            "window_blocks": self.window_blocks,
            "max_ops": self.max_ops,
            "consumed_ops": self.consumed_ops,
            "max_fee_units": self.max_fee_units,
            "consumed_fee_units": self.consumed_fee_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrant {
    pub grant_id: String,
    pub account_id: String,
    pub credential_id: String,
    pub sponsor_policy_id: String,
    pub status: PqSessionGrantStatus,
    pub scopes: BTreeSet<PqPermissionScope>,
    pub cap_ids: BTreeSet<String>,
    pub contract_permission_ids: BTreeSet<String>,
    pub grant_commitment: String,
    pub blinded_wallet_root: String,
    pub issued_height: u64,
    pub expires_height: u64,
    pub max_fee_units: u64,
    pub spent_fee_units: u64,
    pub max_operations: u64,
    pub used_operations: u64,
    pub nullifier_set_root: String,
}

impl SessionGrant {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        credential_id: &str,
        sponsor_policy_id: &str,
        scopes: BTreeSet<PqPermissionScope>,
        cap_ids: BTreeSet<String>,
        contract_permission_ids: BTreeSet<String>,
        height: u64,
        ttl_blocks: u64,
        max_fee_units: u64,
        max_operations: u64,
        wallet_blind_label: &str,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(account_id, "session grant account id")?;
        ensure_non_empty(credential_id, "session grant credential id")?;
        ensure_non_empty(sponsor_policy_id, "session grant sponsor policy id")?;
        ensure_non_empty(wallet_blind_label, "session grant wallet blind label")?;
        if scopes.is_empty() || cap_ids.is_empty() {
            return Err("session grant must include scopes and caps".to_string());
        }
        if ttl_blocks == 0 || max_fee_units == 0 || max_operations == 0 {
            return Err("session grant ttl, fee, and operations must be positive".to_string());
        }
        let blinded_wallet_root = pq_asfs_string_root("PQ-ASFS-BLINDED-WALLET", wallet_blind_label);
        let grant_commitment = session_grant_commitment(
            account_id,
            credential_id,
            sponsor_policy_id,
            &blinded_wallet_root,
            height,
        );
        let grant_id = session_grant_id(&grant_commitment, height);
        let grant = Self {
            grant_id,
            account_id: account_id.to_string(),
            credential_id: credential_id.to_string(),
            sponsor_policy_id: sponsor_policy_id.to_string(),
            status: PqSessionGrantStatus::Active,
            scopes,
            cap_ids,
            contract_permission_ids,
            grant_commitment,
            blinded_wallet_root,
            issued_height: height,
            expires_height: height.saturating_add(ttl_blocks),
            max_fee_units,
            spent_fee_units: 0,
            max_operations,
            used_operations: 0,
            nullifier_set_root: merkle_root("PQ-ASFS-GRANT-NULLIFIERS-EMPTY", &[]),
        };
        grant.validate()?;
        Ok(grant)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn remaining_operations(&self) -> u64 {
        self.max_operations.saturating_sub(self.used_operations)
    }

    pub fn can_spend(&self, scope: PqPermissionScope, fee_units: u64, height: u64) -> bool {
        self.status.can_spend()
            && self.expires_height >= height
            && self.scopes.contains(&scope)
            && fee_units > 0
            && self.remaining_fee_units() >= fee_units
            && self.remaining_operations() > 0
    }

    pub fn mark_spent(&mut self, fee_units: u64, nullifier_root: String) {
        self.spent_fee_units = self.spent_fee_units.saturating_add(fee_units);
        self.used_operations = self.used_operations.saturating_add(1);
        self.nullifier_set_root = nullifier_root;
        if self.remaining_fee_units() == 0 || self.remaining_operations() == 0 {
            self.status = PqSessionGrantStatus::Exhausted;
        }
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.grant_id, "session grant id")?;
        ensure_non_empty(&self.account_id, "session grant account id")?;
        ensure_non_empty(&self.credential_id, "session grant credential id")?;
        ensure_non_empty(&self.sponsor_policy_id, "session grant sponsor policy id")?;
        ensure_non_empty(&self.grant_commitment, "session grant commitment")?;
        ensure_non_empty(&self.blinded_wallet_root, "session grant blinded wallet")?;
        ensure_non_empty(&self.nullifier_set_root, "session grant nullifier set root")?;
        if self.scopes.is_empty() || self.cap_ids.is_empty() {
            return Err("session grant scopes or caps are empty".to_string());
        }
        if self.expires_height <= self.issued_height {
            return Err("session grant expiration must be after issue height".to_string());
        }
        if self.spent_fee_units > self.max_fee_units {
            return Err("session grant spent fee exceeds max".to_string());
        }
        if self.used_operations > self.max_operations {
            return Err("session grant used operations exceeds max".to_string());
        }
        let expected_commitment = session_grant_commitment(
            &self.account_id,
            &self.credential_id,
            &self.sponsor_policy_id,
            &self.blinded_wallet_root,
            self.issued_height,
        );
        if self.grant_commitment != expected_commitment {
            return Err("session grant commitment does not match fields".to_string());
        }
        let expected_id = session_grant_id(&self.grant_commitment, self.issued_height);
        if self.grant_id != expected_id {
            return Err("session grant id does not match commitment".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for SessionGrant {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-SESSION-GRANT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "session_grant",
            "grant_id": self.grant_id,
            "account_id": self.account_id,
            "credential_id": self.credential_id,
            "sponsor_policy_id": self.sponsor_policy_id,
            "status": self.status.as_str(),
            "scopes": self.scopes.iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
            "cap_ids": self.cap_ids.iter().cloned().collect::<Vec<_>>(),
            "contract_permission_ids": self.contract_permission_ids.iter().cloned().collect::<Vec<_>>(),
            "grant_commitment": self.grant_commitment,
            "blinded_wallet_root": self.blinded_wallet_root,
            "issued_height": self.issued_height,
            "expires_height": self.expires_height,
            "max_fee_units": self.max_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "max_operations": self.max_operations,
            "used_operations": self.used_operations,
            "remaining_operations": self.remaining_operations(),
            "nullifier_set_root": self.nullifier_set_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NullifierRecord {
    pub nullifier: String,
    pub grant_id: String,
    pub scope: PqPermissionScope,
    pub sponsor_policy_id: String,
    pub fee_units: u64,
    pub block_height: u64,
    pub receipt_id: String,
}

impl NullifierRecord {
    pub fn new(
        grant_id: &str,
        scope: PqPermissionScope,
        sponsor_policy_id: &str,
        fee_units: u64,
        block_height: u64,
        witness_label: &str,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(grant_id, "nullifier grant id")?;
        ensure_non_empty(sponsor_policy_id, "nullifier sponsor policy id")?;
        ensure_non_empty(witness_label, "nullifier witness label")?;
        if fee_units == 0 {
            return Err("nullifier fee units must be positive".to_string());
        }
        let nullifier = fee_nullifier(grant_id, scope, sponsor_policy_id, witness_label);
        let receipt_id = settlement_receipt_id(grant_id, &nullifier, block_height);
        let record = Self {
            nullifier,
            grant_id: grant_id.to_string(),
            scope,
            sponsor_policy_id: sponsor_policy_id.to_string(),
            fee_units,
            block_height,
            receipt_id,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.nullifier, "nullifier")?;
        ensure_non_empty(&self.grant_id, "nullifier grant id")?;
        ensure_non_empty(&self.sponsor_policy_id, "nullifier sponsor policy id")?;
        ensure_non_empty(&self.receipt_id, "nullifier receipt id")?;
        if self.fee_units == 0 {
            return Err("nullifier fee units must be positive".to_string());
        }
        let expected_receipt =
            settlement_receipt_id(&self.grant_id, &self.nullifier, self.block_height);
        if self.receipt_id != expected_receipt {
            return Err("nullifier receipt id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for NullifierRecord {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-NULLIFIER", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "nullifier_record",
            "nullifier": self.nullifier,
            "grant_id": self.grant_id,
            "scope": self.scope.as_str(),
            "sponsor_policy_id": self.sponsor_policy_id,
            "fee_units": self.fee_units,
            "block_height": self.block_height,
            "receipt_id": self.receipt_id,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementReceipt {
    pub receipt_id: String,
    pub grant_id: String,
    pub nullifier: String,
    pub sponsor_policy_id: String,
    pub fee_units: u64,
    pub discounted_fee_units: u64,
    pub status: SettlementReceiptStatus,
    pub inclusion_height: u64,
    pub settlement_height: u64,
    pub batch_root: String,
    pub proof_root: String,
}

impl SettlementReceipt {
    pub fn from_nullifier(
        nullifier: &NullifierRecord,
        discounted_fee_units: u64,
        batch_label: &str,
        proof_label: &str,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(batch_label, "settlement batch label")?;
        ensure_non_empty(proof_label, "settlement proof label")?;
        if discounted_fee_units > nullifier.fee_units {
            return Err("discounted fee cannot exceed original fee".to_string());
        }
        let receipt = Self {
            receipt_id: nullifier.receipt_id.clone(),
            grant_id: nullifier.grant_id.clone(),
            nullifier: nullifier.nullifier.clone(),
            sponsor_policy_id: nullifier.sponsor_policy_id.clone(),
            fee_units: nullifier.fee_units,
            discounted_fee_units,
            status: SettlementReceiptStatus::Settled,
            inclusion_height: nullifier.block_height,
            settlement_height: nullifier.block_height.saturating_add(1),
            batch_root: pq_asfs_string_root("PQ-ASFS-SETTLEMENT-BATCH", batch_label),
            proof_root: pq_asfs_string_root("PQ-ASFS-SETTLEMENT-PROOF", proof_label),
        };
        receipt.validate()?;
        Ok(receipt)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.receipt_id, "receipt id")?;
        ensure_non_empty(&self.grant_id, "receipt grant id")?;
        ensure_non_empty(&self.nullifier, "receipt nullifier")?;
        ensure_non_empty(&self.sponsor_policy_id, "receipt sponsor policy id")?;
        ensure_non_empty(&self.batch_root, "receipt batch root")?;
        ensure_non_empty(&self.proof_root, "receipt proof root")?;
        if self.fee_units == 0 {
            return Err("receipt fee units must be positive".to_string());
        }
        if self.discounted_fee_units > self.fee_units {
            return Err("receipt discounted fee exceeds fee".to_string());
        }
        if self.settlement_height < self.inclusion_height {
            return Err("receipt settlement height precedes inclusion".to_string());
        }
        let expected =
            settlement_receipt_id(&self.grant_id, &self.nullifier, self.inclusion_height);
        if self.receipt_id != expected {
            return Err("receipt id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for SettlementReceipt {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-SETTLEMENT-RECEIPT", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "settlement_receipt",
            "receipt_id": self.receipt_id,
            "grant_id": self.grant_id,
            "nullifier": self.nullifier,
            "sponsor_policy_id": self.sponsor_policy_id,
            "fee_units": self.fee_units,
            "discounted_fee_units": self.discounted_fee_units,
            "status": self.status.as_str(),
            "inclusion_height": self.inclusion_height,
            "settlement_height": self.settlement_height,
            "batch_root": self.batch_root,
            "proof_root": self.proof_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRecoveryHook {
    pub hook_id: String,
    pub account_id: String,
    pub recovery_root: String,
    pub new_authority_root: String,
    pub status: RecoveryHookStatus,
    pub requested_height: u64,
    pub execute_after_height: u64,
    pub sponsor_policy_id: String,
    pub witness_count: u64,
    pub transcript_root: String,
}

impl WalletRecoveryHook {
    pub fn request(
        account_id: &str,
        recovery_label: &str,
        new_authority_label: &str,
        sponsor_policy_id: &str,
        height: u64,
        delay_blocks: u64,
        witness_count: u64,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(account_id, "recovery hook account id")?;
        ensure_non_empty(recovery_label, "recovery label")?;
        ensure_non_empty(new_authority_label, "new authority label")?;
        ensure_non_empty(sponsor_policy_id, "recovery sponsor policy id")?;
        if delay_blocks == 0 || witness_count == 0 {
            return Err("recovery delay and witness count must be positive".to_string());
        }
        let recovery_root = pq_asfs_string_root("PQ-ASFS-HOOK-RECOVERY", recovery_label);
        let new_authority_root =
            pq_asfs_string_root("PQ-ASFS-HOOK-NEW-AUTHORITY", new_authority_label);
        let transcript_root =
            recovery_transcript_root(account_id, &recovery_root, &new_authority_root);
        let hook_id = recovery_hook_id(account_id, &transcript_root, height);
        let hook = Self {
            hook_id,
            account_id: account_id.to_string(),
            recovery_root,
            new_authority_root,
            status: RecoveryHookStatus::Requested,
            requested_height: height,
            execute_after_height: height.saturating_add(delay_blocks),
            sponsor_policy_id: sponsor_policy_id.to_string(),
            witness_count,
            transcript_root,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.hook_id, "recovery hook id")?;
        ensure_non_empty(&self.account_id, "recovery account id")?;
        ensure_non_empty(&self.recovery_root, "recovery root")?;
        ensure_non_empty(&self.new_authority_root, "new authority root")?;
        ensure_non_empty(&self.sponsor_policy_id, "recovery sponsor policy id")?;
        ensure_non_empty(&self.transcript_root, "recovery transcript root")?;
        if self.execute_after_height <= self.requested_height {
            return Err("recovery execute height must be after request".to_string());
        }
        if self.witness_count == 0 {
            return Err("recovery witness count must be positive".to_string());
        }
        let expected_transcript = recovery_transcript_root(
            &self.account_id,
            &self.recovery_root,
            &self.new_authority_root,
        );
        if self.transcript_root != expected_transcript {
            return Err("recovery transcript root does not match fields".to_string());
        }
        let expected = recovery_hook_id(
            &self.account_id,
            &self.transcript_root,
            self.requested_height,
        );
        if self.hook_id != expected {
            return Err("recovery hook id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for WalletRecoveryHook {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-RECOVERY-HOOK", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_recovery_hook",
            "hook_id": self.hook_id,
            "account_id": self.account_id,
            "recovery_root": self.recovery_root,
            "new_authority_root": self.new_authority_root,
            "status": self.status.as_str(),
            "requested_height": self.requested_height,
            "execute_after_height": self.execute_after_height,
            "sponsor_policy_id": self.sponsor_policy_id,
            "witness_count": self.witness_count,
            "transcript_root": self.transcript_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeSlashRecord {
    pub challenge_id: String,
    pub target_id: String,
    pub challenger_commitment: String,
    pub evidence_root: String,
    pub status: ChallengeStatus,
    pub opened_height: u64,
    pub resolved_height: Option<u64>,
    pub slash_units: u64,
    pub reason_code: String,
}

impl ChallengeSlashRecord {
    pub fn open(
        target_id: &str,
        challenger_label: &str,
        evidence_label: &str,
        opened_height: u64,
        slash_units: u64,
        reason_code: &str,
    ) -> PqAccountSessionFeeSponsorResult<Self> {
        ensure_non_empty(target_id, "challenge target id")?;
        ensure_non_empty(challenger_label, "challenger label")?;
        ensure_non_empty(evidence_label, "challenge evidence label")?;
        ensure_non_empty(reason_code, "challenge reason code")?;
        if slash_units == 0 {
            return Err("challenge slash units must be positive".to_string());
        }
        let challenger_commitment = pq_asfs_string_root("PQ-ASFS-CHALLENGER", challenger_label);
        let evidence_root = pq_asfs_string_root("PQ-ASFS-CHALLENGE-EVIDENCE", evidence_label);
        let challenge_id = challenge_id(target_id, &challenger_commitment, &evidence_root);
        let challenge = Self {
            challenge_id,
            target_id: target_id.to_string(),
            challenger_commitment,
            evidence_root,
            status: ChallengeStatus::Open,
            opened_height,
            resolved_height: None,
            slash_units,
            reason_code: reason_code.to_string(),
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn resolve(&mut self, status: ChallengeStatus, resolved_height: u64) {
        self.status = status;
        self.resolved_height = Some(resolved_height);
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(&self.challenge_id, "challenge id")?;
        ensure_non_empty(&self.target_id, "challenge target id")?;
        ensure_non_empty(&self.challenger_commitment, "challenger commitment")?;
        ensure_non_empty(&self.evidence_root, "challenge evidence root")?;
        ensure_non_empty(&self.reason_code, "challenge reason code")?;
        if self.slash_units == 0 {
            return Err("challenge slash units must be positive".to_string());
        }
        if let Some(resolved_height) = self.resolved_height {
            if resolved_height < self.opened_height {
                return Err("challenge resolved height precedes opened height".to_string());
            }
        }
        let expected = challenge_id(
            &self.target_id,
            &self.challenger_commitment,
            &self.evidence_root,
        );
        if self.challenge_id != expected {
            return Err("challenge id does not match fields".to_string());
        }
        Ok(self.root())
    }
}

impl PqAccountSessionFeeSponsorRooted for ChallengeSlashRecord {
    fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-CHALLENGE-SLASH", &self.public_record())
    }

    fn public_record(&self) -> Value {
        json!({
            "kind": "challenge_slash_record",
            "challenge_id": self.challenge_id,
            "target_id": self.target_id,
            "challenger_commitment": self.challenger_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status.as_str(),
            "opened_height": self.opened_height,
            "resolved_height": self.resolved_height,
            "slash_units": self.slash_units,
            "reason_code": self.reason_code,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAccountSessionFeeSponsorRoots {
    pub config_root: String,
    pub account_root: String,
    pub credential_root: String,
    pub spending_cap_root: String,
    pub contract_permission_root: String,
    pub sponsor_policy_root: String,
    pub grant_root: String,
    pub nullifier_root: String,
    pub receipt_root: String,
    pub recovery_hook_root: String,
    pub rate_limit_root: String,
    pub challenge_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PqAccountSessionFeeSponsorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "account_root": self.account_root,
            "credential_root": self.credential_root,
            "spending_cap_root": self.spending_cap_root,
            "contract_permission_root": self.contract_permission_root,
            "sponsor_policy_root": self.sponsor_policy_root,
            "grant_root": self.grant_root,
            "nullifier_root": self.nullifier_root,
            "receipt_root": self.receipt_root,
            "recovery_hook_root": self.recovery_hook_root,
            "rate_limit_root": self.rate_limit_root,
            "challenge_root": self.challenge_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }

    pub fn root(&self) -> String {
        pq_asfs_payload_root("PQ-ASFS-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAccountSessionFeeSponsorCounters {
    pub account_count: usize,
    pub credential_count: usize,
    pub spending_cap_count: usize,
    pub contract_permission_count: usize,
    pub sponsor_policy_count: usize,
    pub grant_count: usize,
    pub active_grant_count: usize,
    pub nullifier_count: usize,
    pub receipt_count: usize,
    pub recovery_hook_count: usize,
    pub rate_limit_bucket_count: usize,
    pub challenge_count: usize,
    pub open_challenge_count: usize,
    pub total_sponsored_fee_units: u64,
    pub total_discounted_fee_units: u64,
}

impl PqAccountSessionFeeSponsorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "account_count": self.account_count,
            "credential_count": self.credential_count,
            "spending_cap_count": self.spending_cap_count,
            "contract_permission_count": self.contract_permission_count,
            "sponsor_policy_count": self.sponsor_policy_count,
            "grant_count": self.grant_count,
            "active_grant_count": self.active_grant_count,
            "nullifier_count": self.nullifier_count,
            "receipt_count": self.receipt_count,
            "recovery_hook_count": self.recovery_hook_count,
            "rate_limit_bucket_count": self.rate_limit_bucket_count,
            "challenge_count": self.challenge_count,
            "open_challenge_count": self.open_challenge_count,
            "total_sponsored_fee_units": self.total_sponsored_fee_units,
            "total_discounted_fee_units": self.total_discounted_fee_units,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqAccountSessionFeeSponsorState {
    pub config: PqAccountSessionFeeSponsorConfig,
    pub height: u64,
    pub accounts: BTreeMap<String, PqAccountProfile>,
    pub credentials: BTreeMap<String, PqCredential>,
    pub spending_caps: BTreeMap<String, SpendingCap>,
    pub contract_permissions: BTreeMap<String, ContractPermissionScope>,
    pub sponsor_policies: BTreeMap<String, LowFeeSponsorPolicy>,
    pub session_grants: BTreeMap<String, SessionGrant>,
    pub nullifiers: BTreeMap<String, NullifierRecord>,
    pub settlement_receipts: BTreeMap<String, SettlementReceipt>,
    pub recovery_hooks: BTreeMap<String, WalletRecoveryHook>,
    pub rate_limits: BTreeMap<String, RateLimitBucket>,
    pub challenges: BTreeMap<String, ChallengeSlashRecord>,
    pub revoked_grants: BTreeSet<String>,
    pub quarantined_credentials: BTreeSet<String>,
}

impl PqAccountSessionFeeSponsorState {
    pub fn new(config: PqAccountSessionFeeSponsorConfig, height: u64) -> Self {
        Self {
            config,
            height,
            accounts: BTreeMap::new(),
            credentials: BTreeMap::new(),
            spending_caps: BTreeMap::new(),
            contract_permissions: BTreeMap::new(),
            sponsor_policies: BTreeMap::new(),
            session_grants: BTreeMap::new(),
            nullifiers: BTreeMap::new(),
            settlement_receipts: BTreeMap::new(),
            recovery_hooks: BTreeMap::new(),
            rate_limits: BTreeMap::new(),
            challenges: BTreeMap::new(),
            revoked_grants: BTreeSet::new(),
            quarantined_credentials: BTreeSet::new(),
        }
    }

    pub fn devnet() -> PqAccountSessionFeeSponsorResult<Self> {
        let config = PqAccountSessionFeeSponsorConfig::devnet()?;
        let mut state = Self::new(config, PQ_ACCOUNT_SESSION_FEE_SPONSOR_DEFAULT_HEIGHT);

        let account = PqAccountProfile::new(
            "alice-primary-wallet",
            "alice-slh-recovery",
            "alice-ml-dsa-spend-authority",
            state.height,
            256,
        )?;
        let account_id = account.account_id.clone();
        state.insert_account(account)?;

        let online_credential = PqCredential::issue(
            &account_id,
            PqCredentialKind::OnlineMlDsa,
            "alice-phone-secure-enclave",
            state.height,
            state.config.session_ttl_blocks.saturating_mul(4),
            "alice-online-session-transcript",
        )?;
        let credential_id = online_credential.credential_id.clone();
        state.insert_credential(online_credential)?;

        let recovery_credential = PqCredential::issue(
            &account_id,
            PqCredentialKind::RecoverySlhDsa,
            "alice-recovery-card",
            state.height,
            state.config.recovery_delay_blocks.saturating_mul(2),
            "alice-recovery-transcript",
        )?;
        state.insert_credential(recovery_credential)?;

        let transfer_cap = SpendingCap::new(
            &account_id,
            PqPermissionScope::PrivateTransfer,
            "xmr-devnet",
            state.config.rate_window_blocks,
            10_000,
            state.height,
        )?;
        let transfer_cap_id = transfer_cap.cap_id.clone();
        state.insert_spending_cap(transfer_cap)?;

        let contract_cap = SpendingCap::new(
            &account_id,
            PqPermissionScope::ContractCall,
            "xmr-devnet",
            state.config.rate_window_blocks,
            4_000,
            state.height,
        )?;
        let contract_cap_id = contract_cap.cap_id.clone();
        state.insert_spending_cap(contract_cap)?;

        let contract_permission = ContractPermissionScope::new(
            &account_id,
            "private-limit-order-router",
            PqPermissionScope::ContractCall,
            "swap_exact_private_input",
            2_500,
            state.height.saturating_add(state.config.session_ttl_blocks),
            true,
        )?;
        let contract_permission_id = contract_permission.permission_id.clone();
        state.insert_contract_permission(contract_permission)?;

        let mut scopes = BTreeSet::new();
        scopes.insert(PqPermissionScope::PrivateTransfer);
        scopes.insert(PqPermissionScope::ContractCall);
        scopes.insert(PqPermissionScope::ProofAggregation);

        let sponsor = LowFeeSponsorPolicy::new(
            "devnet-shielded-low-fee-sponsor",
            SponsorPolicyMode::PreferShielded,
            scopes.clone(),
            120,
            6_000,
            250_000,
        )?;
        let sponsor_policy_id = sponsor.policy_id.clone();
        state.insert_sponsor_policy(sponsor)?;

        let mut cap_ids = BTreeSet::new();
        cap_ids.insert(transfer_cap_id);
        cap_ids.insert(contract_cap_id);
        let mut contract_permission_ids = BTreeSet::new();
        contract_permission_ids.insert(contract_permission_id);

        let grant = SessionGrant::new(
            &account_id,
            &credential_id,
            &sponsor_policy_id,
            scopes,
            cap_ids,
            contract_permission_ids,
            state.height,
            state.config.grant_ttl_blocks,
            1_200,
            24,
            "alice-grant-blind-0",
        )?;
        let grant_id = grant.grant_id.clone();
        state.insert_session_grant(grant)?;

        state.record_sponsored_spend(
            &grant_id,
            PqPermissionScope::PrivateTransfer,
            40,
            "alice-nullifier-witness-0",
            "devnet-batch-0",
            "devnet-settlement-proof-0",
        )?;

        let recovery_hook = WalletRecoveryHook::request(
            &account_id,
            "alice-slh-recovery",
            "alice-new-ml-dsa-authority",
            &sponsor_policy_id,
            state.height,
            state.config.recovery_delay_blocks,
            2,
        )?;
        state.insert_recovery_hook(recovery_hook)?;

        let mut bucket = RateLimitBucket::new(
            &account_id,
            PqPermissionScope::PrivateTransfer,
            state.height,
            state.config.rate_window_blocks,
            32,
            2_000,
        )?;
        bucket.consume(40)?;
        state.insert_rate_limit(bucket)?;

        let mut challenge = ChallengeSlashRecord::open(
            &sponsor_policy_id,
            "watchtower-fee-monitor",
            "sponsor-fee-over-reservation-proof",
            state.height.saturating_add(2),
            25,
            "fee_reservation_mismatch",
        )?;
        challenge.resolve(ChallengeStatus::Rejected, state.height.saturating_add(4));
        state.insert_challenge(challenge)?;

        state.validate()?;
        Ok(state)
    }

    pub fn insert_account(
        &mut self,
        account: PqAccountProfile,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        let root = account.validate()?;
        self.accounts.insert(account.account_id.clone(), account);
        Ok(root)
    }

    pub fn insert_credential(
        &mut self,
        credential: PqCredential,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        credential.validate()?;
        if !self.accounts.contains_key(&credential.account_id) {
            return Err("credential account does not exist".to_string());
        }
        let root = credential.root();
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(root)
    }

    pub fn insert_spending_cap(
        &mut self,
        cap: SpendingCap,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        cap.validate()?;
        if !self.accounts.contains_key(&cap.account_id) {
            return Err("spending cap account does not exist".to_string());
        }
        let root = cap.root();
        self.spending_caps.insert(cap.cap_id.clone(), cap);
        Ok(root)
    }

    pub fn insert_contract_permission(
        &mut self,
        permission: ContractPermissionScope,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        permission.validate()?;
        if !self.accounts.contains_key(&permission.account_id) {
            return Err("contract permission account does not exist".to_string());
        }
        let root = permission.root();
        self.contract_permissions
            .insert(permission.permission_id.clone(), permission);
        Ok(root)
    }

    pub fn insert_sponsor_policy(
        &mut self,
        policy: LowFeeSponsorPolicy,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        let root = policy.validate()?;
        self.sponsor_policies
            .insert(policy.policy_id.clone(), policy);
        Ok(root)
    }

    pub fn insert_session_grant(
        &mut self,
        grant: SessionGrant,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        grant.validate()?;
        let account = self
            .accounts
            .get_mut(&grant.account_id)
            .ok_or_else(|| "session grant account does not exist".to_string())?;
        if !account.status.can_open_session() {
            return Err("account cannot open session grant".to_string());
        }
        let credential = self
            .credentials
            .get(&grant.credential_id)
            .ok_or_else(|| "session grant credential does not exist".to_string())?;
        if credential.account_id != grant.account_id {
            return Err("session grant credential belongs to different account".to_string());
        }
        if !credential.status.usable() || credential.expires_height < self.height {
            return Err("session grant credential is not usable".to_string());
        }
        let policy = self
            .sponsor_policies
            .get(&grant.sponsor_policy_id)
            .ok_or_else(|| "session grant sponsor policy does not exist".to_string())?;
        for scope in &grant.scopes {
            if !policy.supported_scopes.contains(scope) {
                return Err("session grant scope unsupported by sponsor".to_string());
            }
        }
        for cap_id in &grant.cap_ids {
            if !self.spending_caps.contains_key(cap_id) {
                return Err("session grant references missing spending cap".to_string());
            }
        }
        for permission_id in &grant.contract_permission_ids {
            if !self.contract_permissions.contains_key(permission_id) {
                return Err("session grant references missing contract permission".to_string());
            }
        }
        let root = grant.root();
        account.active_grant_count = account.active_grant_count.saturating_add(1);
        account.session_nonce = account.session_nonce.saturating_add(1);
        account.last_active_height = self.height;
        self.session_grants.insert(grant.grant_id.clone(), grant);
        Ok(root)
    }

    pub fn insert_recovery_hook(
        &mut self,
        hook: WalletRecoveryHook,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        hook.validate()?;
        if !self.accounts.contains_key(&hook.account_id) {
            return Err("recovery hook account does not exist".to_string());
        }
        if !self.sponsor_policies.contains_key(&hook.sponsor_policy_id) {
            return Err("recovery hook sponsor policy does not exist".to_string());
        }
        let root = hook.root();
        self.recovery_hooks.insert(hook.hook_id.clone(), hook);
        Ok(root)
    }

    pub fn insert_rate_limit(
        &mut self,
        bucket: RateLimitBucket,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        let root = bucket.validate()?;
        self.rate_limits.insert(bucket.bucket_id.clone(), bucket);
        Ok(root)
    }

    pub fn insert_challenge(
        &mut self,
        challenge: ChallengeSlashRecord,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        let root = challenge.validate()?;
        self.challenges
            .insert(challenge.challenge_id.clone(), challenge);
        Ok(root)
    }

    pub fn revoke_grant(&mut self, grant_id: &str) -> PqAccountSessionFeeSponsorResult<()> {
        ensure_non_empty(grant_id, "revoke grant id")?;
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| "grant does not exist".to_string())?;
        grant.status = PqSessionGrantStatus::Revoked;
        self.revoked_grants.insert(grant_id.to_string());
        if let Some(account) = self.accounts.get_mut(&grant.account_id) {
            account.active_grant_count = account.active_grant_count.saturating_sub(1);
        }
        Ok(())
    }

    pub fn quarantine_credential(
        &mut self,
        credential_id: &str,
    ) -> PqAccountSessionFeeSponsorResult<()> {
        ensure_non_empty(credential_id, "quarantine credential id")?;
        let credential = self
            .credentials
            .get_mut(credential_id)
            .ok_or_else(|| "credential does not exist".to_string())?;
        credential.status = PqCredentialStatus::Quarantined;
        self.quarantined_credentials
            .insert(credential_id.to_string());
        Ok(())
    }

    pub fn record_sponsored_spend(
        &mut self,
        grant_id: &str,
        scope: PqPermissionScope,
        fee_units: u64,
        witness_label: &str,
        batch_label: &str,
        proof_label: &str,
    ) -> PqAccountSessionFeeSponsorResult<String> {
        ensure_non_empty(grant_id, "sponsored spend grant id")?;
        let (sponsor_policy_id, account_id, cap_ids, permission_ids) = {
            let grant = self
                .session_grants
                .get(grant_id)
                .ok_or_else(|| "sponsored spend grant does not exist".to_string())?;
            if !grant.can_spend(scope, fee_units, self.height) {
                return Err("session grant cannot sponsor requested spend".to_string());
            }
            (
                grant.sponsor_policy_id.clone(),
                grant.account_id.clone(),
                grant.cap_ids.clone(),
                grant.contract_permission_ids.clone(),
            )
        };

        let policy = self
            .sponsor_policies
            .get_mut(&sponsor_policy_id)
            .ok_or_else(|| "sponsor policy does not exist".to_string())?;
        if !policy.supports(scope, fee_units) {
            return Err("sponsor policy rejects spend".to_string());
        }

        let mut matched_cap = false;
        for cap_id in &cap_ids {
            if let Some(cap) = self.spending_caps.get_mut(cap_id) {
                if cap.scope == scope && cap.account_id == account_id {
                    if !cap.allows(fee_units) {
                        return Err("spending cap rejects spend".to_string());
                    }
                    cap.spent_units = cap.spent_units.saturating_add(fee_units);
                    matched_cap = true;
                    break;
                }
            }
        }
        if !matched_cap {
            return Err("no matching spending cap for sponsored spend".to_string());
        }

        if scope == PqPermissionScope::ContractCall {
            let mut allowed_contract = false;
            for permission_id in &permission_ids {
                if let Some(permission) = self.contract_permissions.get(permission_id) {
                    allowed_contract = permission.sponsor_allowed
                        && permission.account_id == account_id
                        && permission.expires_height >= self.height;
                    if allowed_contract {
                        break;
                    }
                }
            }
            if !allowed_contract {
                return Err("contract permission rejects sponsored spend".to_string());
            }
        }

        let nullifier = NullifierRecord::new(
            grant_id,
            scope,
            &sponsor_policy_id,
            fee_units,
            self.height,
            witness_label,
        )?;
        if self.nullifiers.contains_key(&nullifier.nullifier) {
            return Err("fee nullifier already spent".to_string());
        }
        let discounted_fee = discounted_fee_units(fee_units, policy.min_discount_bps);
        let receipt = SettlementReceipt::from_nullifier(
            &nullifier,
            discounted_fee,
            batch_label,
            proof_label,
        )?;
        policy.reserved_epoch_budget_units = policy
            .reserved_epoch_budget_units
            .saturating_add(discounted_fee);

        self.nullifiers
            .insert(nullifier.nullifier.clone(), nullifier.clone());
        self.settlement_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        let nullifier_root = self.nullifier_root();
        let grant = self
            .session_grants
            .get_mut(grant_id)
            .ok_or_else(|| "sponsored spend grant missing during update".to_string())?;
        grant.mark_spent(fee_units, nullifier_root);
        if let Some(account) = self.accounts.get_mut(&account_id) {
            account.last_active_height = self.height;
        }
        Ok(receipt.receipt_id)
    }

    pub fn advance_height(&mut self, new_height: u64) -> PqAccountSessionFeeSponsorResult<()> {
        if new_height < self.height {
            return Err("cannot move state height backwards".to_string());
        }
        self.height = new_height;
        for credential in self.credentials.values_mut() {
            if credential.expires_height < self.height && credential.status.usable() {
                credential.status = PqCredentialStatus::Expired;
            }
        }
        for grant in self.session_grants.values_mut() {
            if grant.expires_height < self.height && grant.status.can_spend() {
                grant.status = PqSessionGrantStatus::Expired;
            }
        }
        for hook in self.recovery_hooks.values_mut() {
            if hook.status == RecoveryHookStatus::Requested
                && hook.execute_after_height <= self.height
            {
                hook.status = RecoveryHookStatus::DelayElapsed;
            }
        }
        Ok(())
    }

    pub fn roots(&self) -> PqAccountSessionFeeSponsorRoots {
        let config_root = self.config.root();
        let account_root = self.account_root();
        let credential_root = self.credential_root();
        let spending_cap_root = self.spending_cap_root();
        let contract_permission_root = self.contract_permission_root();
        let sponsor_policy_root = self.sponsor_policy_root();
        let grant_root = self.grant_root();
        let nullifier_root = self.nullifier_root();
        let receipt_root = self.receipt_root();
        let recovery_hook_root = self.recovery_hook_root();
        let rate_limit_root = self.rate_limit_root();
        let challenge_root = self.challenge_root();
        let public_record_without_roots = self.public_record_without_roots();
        let public_record_root =
            pq_asfs_payload_root("PQ-ASFS-PUBLIC-RECORD", &public_record_without_roots);
        let state_root = domain_hash(
            "PQ-ASFS-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&account_root),
                HashPart::Str(&credential_root),
                HashPart::Str(&spending_cap_root),
                HashPart::Str(&contract_permission_root),
                HashPart::Str(&sponsor_policy_root),
                HashPart::Str(&grant_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&receipt_root),
                HashPart::Str(&recovery_hook_root),
                HashPart::Str(&rate_limit_root),
                HashPart::Str(&challenge_root),
                HashPart::Int(self.height as i128),
            ],
            32,
        );
        PqAccountSessionFeeSponsorRoots {
            config_root,
            account_root,
            credential_root,
            spending_cap_root,
            contract_permission_root,
            sponsor_policy_root,
            grant_root,
            nullifier_root,
            receipt_root,
            recovery_hook_root,
            rate_limit_root,
            challenge_root,
            public_record_root,
            state_root,
        }
    }

    pub fn counters(&self) -> PqAccountSessionFeeSponsorCounters {
        let total_sponsored_fee_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.fee_units)
            .sum();
        let total_discounted_fee_units = self
            .settlement_receipts
            .values()
            .map(|receipt| receipt.discounted_fee_units)
            .sum();
        PqAccountSessionFeeSponsorCounters {
            account_count: self.accounts.len(),
            credential_count: self.credentials.len(),
            spending_cap_count: self.spending_caps.len(),
            contract_permission_count: self.contract_permissions.len(),
            sponsor_policy_count: self.sponsor_policies.len(),
            grant_count: self.session_grants.len(),
            active_grant_count: self
                .session_grants
                .values()
                .filter(|grant| grant.status == PqSessionGrantStatus::Active)
                .count(),
            nullifier_count: self.nullifiers.len(),
            receipt_count: self.settlement_receipts.len(),
            recovery_hook_count: self.recovery_hooks.len(),
            rate_limit_bucket_count: self.rate_limits.len(),
            challenge_count: self.challenges.len(),
            open_challenge_count: self
                .challenges
                .values()
                .filter(|challenge| challenge.status == ChallengeStatus::Open)
                .count(),
            total_sponsored_fee_units,
            total_discounted_fee_units,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record_root(&self) -> String {
        self.roots().public_record_root
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "pq_account_session_fee_sponsor_state",
            "height": self.height,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "accounts": self.accounts.values().map(PqAccountProfile::public_record).collect::<Vec<_>>(),
            "credentials": self.credentials.values().map(PqCredential::public_record).collect::<Vec<_>>(),
            "spending_caps": self.spending_caps.values().map(SpendingCap::public_record).collect::<Vec<_>>(),
            "contract_permissions": self.contract_permissions.values().map(ContractPermissionScope::public_record).collect::<Vec<_>>(),
            "sponsor_policies": self.sponsor_policies.values().map(LowFeeSponsorPolicy::public_record).collect::<Vec<_>>(),
            "session_grants": self.session_grants.values().map(SessionGrant::public_record).collect::<Vec<_>>(),
            "nullifiers": self.nullifiers.values().map(NullifierRecord::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "recovery_hooks": self.recovery_hooks.values().map(WalletRecoveryHook::public_record).collect::<Vec<_>>(),
            "rate_limits": self.rate_limits.values().map(RateLimitBucket::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(ChallengeSlashRecord::public_record).collect::<Vec<_>>(),
            "revoked_grants": self.revoked_grants.iter().cloned().collect::<Vec<_>>(),
            "quarantined_credentials": self.quarantined_credentials.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> PqAccountSessionFeeSponsorResult<String> {
        self.config.validate()?;
        for account in self.accounts.values() {
            account.validate()?;
        }
        for credential in self.credentials.values() {
            credential.validate()?;
            if !self.accounts.contains_key(&credential.account_id) {
                return Err("state credential references missing account".to_string());
            }
        }
        for cap in self.spending_caps.values() {
            cap.validate()?;
            if !self.accounts.contains_key(&cap.account_id) {
                return Err("state cap references missing account".to_string());
            }
        }
        for permission in self.contract_permissions.values() {
            permission.validate()?;
            if !self.accounts.contains_key(&permission.account_id) {
                return Err("state permission references missing account".to_string());
            }
        }
        for policy in self.sponsor_policies.values() {
            policy.validate()?;
        }
        for grant in self.session_grants.values() {
            grant.validate()?;
            if !self.accounts.contains_key(&grant.account_id) {
                return Err("state grant references missing account".to_string());
            }
            if !self.credentials.contains_key(&grant.credential_id) {
                return Err("state grant references missing credential".to_string());
            }
            if !self.sponsor_policies.contains_key(&grant.sponsor_policy_id) {
                return Err("state grant references missing sponsor policy".to_string());
            }
        }
        for nullifier in self.nullifiers.values() {
            nullifier.validate()?;
            if !self.session_grants.contains_key(&nullifier.grant_id) {
                return Err("state nullifier references missing grant".to_string());
            }
        }
        for receipt in self.settlement_receipts.values() {
            receipt.validate()?;
            if !self.nullifiers.contains_key(&receipt.nullifier) {
                return Err("state receipt references missing nullifier".to_string());
            }
        }
        for hook in self.recovery_hooks.values() {
            hook.validate()?;
            if !self.accounts.contains_key(&hook.account_id) {
                return Err("state recovery hook references missing account".to_string());
            }
        }
        for bucket in self.rate_limits.values() {
            bucket.validate()?;
        }
        for challenge in self.challenges.values() {
            challenge.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_roots(&self) -> Value {
        json!({
            "kind": "pq_account_session_fee_sponsor_state_public_record",
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters().public_record(),
            "accounts": self.accounts.values().map(PqAccountProfile::public_record).collect::<Vec<_>>(),
            "credentials": self.credentials.values().map(PqCredential::public_record).collect::<Vec<_>>(),
            "spending_caps": self.spending_caps.values().map(SpendingCap::public_record).collect::<Vec<_>>(),
            "contract_permissions": self.contract_permissions.values().map(ContractPermissionScope::public_record).collect::<Vec<_>>(),
            "sponsor_policies": self.sponsor_policies.values().map(LowFeeSponsorPolicy::public_record).collect::<Vec<_>>(),
            "session_grants": self.session_grants.values().map(SessionGrant::public_record).collect::<Vec<_>>(),
            "nullifiers": self.nullifiers.values().map(NullifierRecord::public_record).collect::<Vec<_>>(),
            "settlement_receipts": self.settlement_receipts.values().map(SettlementReceipt::public_record).collect::<Vec<_>>(),
            "recovery_hooks": self.recovery_hooks.values().map(WalletRecoveryHook::public_record).collect::<Vec<_>>(),
            "rate_limits": self.rate_limits.values().map(RateLimitBucket::public_record).collect::<Vec<_>>(),
            "challenges": self.challenges.values().map(ChallengeSlashRecord::public_record).collect::<Vec<_>>(),
        })
    }

    fn account_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-ACCOUNTS",
            &self
                .accounts
                .values()
                .map(PqAccountProfile::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn credential_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-CREDENTIALS",
            &self
                .credentials
                .values()
                .map(PqCredential::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn spending_cap_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-SPENDING-CAPS",
            &self
                .spending_caps
                .values()
                .map(SpendingCap::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn contract_permission_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-CONTRACT-PERMISSIONS",
            &self
                .contract_permissions
                .values()
                .map(ContractPermissionScope::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn sponsor_policy_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-SPONSOR-POLICIES",
            &self
                .sponsor_policies
                .values()
                .map(LowFeeSponsorPolicy::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn grant_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-GRANTS",
            &self
                .session_grants
                .values()
                .map(SessionGrant::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn nullifier_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-NULLIFIERS",
            &self
                .nullifiers
                .values()
                .map(NullifierRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn receipt_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-RECEIPTS",
            &self
                .settlement_receipts
                .values()
                .map(SettlementReceipt::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn recovery_hook_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-RECOVERY-HOOKS",
            &self
                .recovery_hooks
                .values()
                .map(WalletRecoveryHook::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn rate_limit_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-RATE-LIMITS",
            &self
                .rate_limits
                .values()
                .map(RateLimitBucket::public_record)
                .collect::<Vec<_>>(),
        )
    }

    fn challenge_root(&self) -> String {
        merkle_root(
            "PQ-ASFS-CHALLENGES",
            &self
                .challenges
                .values()
                .map(ChallengeSlashRecord::public_record)
                .collect::<Vec<_>>(),
        )
    }
}

pub fn pq_asfs_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn pq_asfs_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn pq_asfs_config_id(chain_id: &str, protocol_version: &str) -> String {
    domain_hash(
        "PQ-ASFS-CONFIG-ID",
        &[HashPart::Str(chain_id), HashPart::Str(protocol_version)],
        32,
    )
}

pub fn pq_account_id(
    wallet_commitment: &str,
    recovery_root: &str,
    spend_authority_root: &str,
) -> String {
    domain_hash(
        "PQ-ASFS-ACCOUNT-ID",
        &[
            HashPart::Str(wallet_commitment),
            HashPart::Str(recovery_root),
            HashPart::Str(spend_authority_root),
        ],
        32,
    )
}

pub fn pq_credential_id(
    account_id: &str,
    kind: PqCredentialKind,
    verification_key_root: &str,
) -> String {
    domain_hash(
        "PQ-ASFS-CREDENTIAL-ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(verification_key_root),
        ],
        32,
    )
}

pub fn spending_cap_id(
    account_id: &str,
    scope: PqPermissionScope,
    asset_id: &str,
    reset_height: u64,
) -> String {
    domain_hash(
        "PQ-ASFS-SPENDING-CAP-ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(asset_id),
            HashPart::Int(reset_height as i128),
        ],
        32,
    )
}

pub fn contract_permission_id(
    account_id: &str,
    contract_commitment: &str,
    scope: PqPermissionScope,
    method_root: &str,
    expires_height: u64,
) -> String {
    domain_hash(
        "PQ-ASFS-CONTRACT-PERMISSION-ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(scope.as_str()),
            HashPart::Str(method_root),
            HashPart::Int(expires_height as i128),
        ],
        32,
    )
}

pub fn sponsor_policy_id(sponsor_id: &str, mode: SponsorPolicyMode, max_fee_units: u64) -> String {
    domain_hash(
        "PQ-ASFS-SPONSOR-POLICY-ID",
        &[
            HashPart::Str(sponsor_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(max_fee_units as i128),
        ],
        32,
    )
}

pub fn session_grant_commitment(
    account_id: &str,
    credential_id: &str,
    sponsor_policy_id: &str,
    blinded_wallet_root: &str,
    issued_height: u64,
) -> String {
    domain_hash(
        "PQ-ASFS-SESSION-GRANT-COMMITMENT",
        &[
            HashPart::Str(account_id),
            HashPart::Str(credential_id),
            HashPart::Str(sponsor_policy_id),
            HashPart::Str(blinded_wallet_root),
            HashPart::Int(issued_height as i128),
        ],
        32,
    )
}

pub fn session_grant_id(grant_commitment: &str, issued_height: u64) -> String {
    domain_hash(
        "PQ-ASFS-SESSION-GRANT-ID",
        &[
            HashPart::Str(grant_commitment),
            HashPart::Int(issued_height as i128),
        ],
        32,
    )
}

pub fn fee_nullifier(
    grant_id: &str,
    scope: PqPermissionScope,
    sponsor_policy_id: &str,
    witness_label: &str,
) -> String {
    domain_hash(
        "PQ-ASFS-FEE-NULLIFIER",
        &[
            HashPart::Str(grant_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(sponsor_policy_id),
            HashPart::Str(witness_label),
        ],
        32,
    )
}

pub fn settlement_receipt_id(grant_id: &str, nullifier: &str, inclusion_height: u64) -> String {
    domain_hash(
        "PQ-ASFS-SETTLEMENT-RECEIPT-ID",
        &[
            HashPart::Str(grant_id),
            HashPart::Str(nullifier),
            HashPart::Int(inclusion_height as i128),
        ],
        32,
    )
}

pub fn recovery_transcript_root(
    account_id: &str,
    recovery_root: &str,
    new_authority_root: &str,
) -> String {
    domain_hash(
        "PQ-ASFS-RECOVERY-TRANSCRIPT",
        &[
            HashPart::Str(account_id),
            HashPart::Str(recovery_root),
            HashPart::Str(new_authority_root),
        ],
        32,
    )
}

pub fn recovery_hook_id(account_id: &str, transcript_root: &str, requested_height: u64) -> String {
    domain_hash(
        "PQ-ASFS-RECOVERY-HOOK-ID",
        &[
            HashPart::Str(account_id),
            HashPart::Str(transcript_root),
            HashPart::Int(requested_height as i128),
        ],
        32,
    )
}

pub fn rate_limit_bucket_id(
    subject_commitment: &str,
    scope: PqPermissionScope,
    window_start_height: u64,
) -> String {
    domain_hash(
        "PQ-ASFS-RATE-LIMIT-BUCKET-ID",
        &[
            HashPart::Str(subject_commitment),
            HashPart::Str(scope.as_str()),
            HashPart::Int(window_start_height as i128),
        ],
        32,
    )
}

pub fn challenge_id(target_id: &str, challenger_commitment: &str, evidence_root: &str) -> String {
    domain_hash(
        "PQ-ASFS-CHALLENGE-ID",
        &[
            HashPart::Str(target_id),
            HashPart::Str(challenger_commitment),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

pub fn discounted_fee_units(fee_units: u64, discount_bps: u64) -> u64 {
    let clamped = discount_bps.min(PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS);
    let discounted = fee_units.saturating_mul(clamped) / PQ_ACCOUNT_SESSION_FEE_SPONSOR_MAX_BPS;
    fee_units.saturating_sub(discounted)
}

fn ensure_non_empty(value: &str, field: &str) -> PqAccountSessionFeeSponsorResult<()> {
    if value.trim().is_empty() {
        return Err(format!(
            "pq account session fee sponsor {field} is required"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_state_validates_and_has_private_fee_receipt() -> PqAccountSessionFeeSponsorResult<()>
    {
        let state = PqAccountSessionFeeSponsorState::devnet()?;
        assert_eq!(state.counters().account_count, 1);
        assert_eq!(state.counters().nullifier_count, 1);
        assert_eq!(state.counters().receipt_count, 1);
        assert!(state.validate().is_ok());
        assert_eq!(state.state_root().len(), 64);
        Ok(())
    }

    #[test]
    fn duplicate_nullifier_is_rejected() -> PqAccountSessionFeeSponsorResult<()> {
        let mut state = PqAccountSessionFeeSponsorState::devnet()?;
        let grant_id = state
            .session_grants
            .keys()
            .next()
            .cloned()
            .ok_or_else(|| "devnet state should include a grant".to_string())?;
        let result = state.record_sponsored_spend(
            &grant_id,
            PqPermissionScope::PrivateTransfer,
            40,
            "alice-nullifier-witness-0",
            "devnet-batch-1",
            "devnet-settlement-proof-1",
        );
        assert!(result.is_err());
        Ok(())
    }
}
