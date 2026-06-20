use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateSmartWalletPaymasterResult<T> = Result<T, String>;

pub const PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION: &str =
    "nebula-private-smart-wallet-paymaster-v1";
pub const PRIVATE_SMART_WALLET_PAYMASTER_SECURITY_MODEL: &str =
    "deterministic-devnet-private-aa-not-real-crypto";
pub const PRIVATE_SMART_WALLET_PAYMASTER_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const PRIVATE_SMART_WALLET_PAYMASTER_PROOF_SYSTEM: &str =
    "zk-private-smart-wallet-paymaster-shake256-v1";
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_HEIGHT: u64 = 240;
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_INTENT_TTL_BLOCKS: u64 = 18;
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_BUDGET_WINDOW_BLOCKS: u64 = 120;
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 720;
pub const PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE: u64 = 128;
pub const PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const PRIVATE_SMART_WALLET_PAYMASTER_MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateSmartWalletStatus {
    Active,
    Frozen,
    Recovery,
    Suspended,
    Closed,
}

impl PrivateSmartWalletStatus {
    pub fn as_str(self) -> &'static str {
        match self {
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
pub enum PrivateSmartWalletMode {
    Conservative,
    TokensOnly,
    DefiEnabled,
    ContractAutomation,
    RecoveryOnly,
}

impl PrivateSmartWalletMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::TokensOnly => "tokens_only",
            Self::DefiEnabled => "defi_enabled",
            Self::ContractAutomation => "contract_automation",
            Self::RecoveryOnly => "recovery_only",
        }
    }

    pub fn allows_defi(self) -> bool {
        matches!(self, Self::DefiEnabled | Self::ContractAutomation)
    }

    pub fn allows_contract_calls(self) -> bool {
        !matches!(self, Self::RecoveryOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationKind {
    Owner,
    Hardware,
    Session,
    Automation,
    Recovery,
}

impl PqAuthorizationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Hardware => "hardware",
            Self::Session => "session",
            Self::Automation => "automation",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateWalletOperation {
    PrivateTransfer,
    TokenMint,
    TokenBurn,
    DefiSwap,
    Lending,
    Staking,
    ContractCall,
    Recovery,
}

impl PrivateWalletOperation {
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
        }
    }

    pub fn is_defi(self) -> bool {
        matches!(self, Self::DefiSwap | Self::Lending | Self::Staking)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorRuleMode {
    Disabled,
    LowFeeOnly,
    PreferShieldedPool,
    RequireShieldedPool,
    RecoverySponsor,
}

impl SponsorRuleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::LowFeeOnly => "low_fee_only",
            Self::PreferShieldedPool => "prefer_shielded_pool",
            Self::RequireShieldedPool => "require_shielded_pool",
            Self::RecoverySponsor => "recovery_sponsor",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractBudgetWindow {
    Call,
    Session,
    Block,
    Epoch,
}

impl ContractBudgetWindow {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Session => "session",
            Self::Block => "block",
            Self::Epoch => "epoch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPlanStatus {
    Active,
    Requested,
    DelayElapsed,
    Executed,
    Cancelled,
    Expired,
}

impl RecoveryPlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
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
pub enum FeeReceiptStatus {
    Reserved,
    Settled,
    Released,
    Disputed,
}

impl FeeReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Released => "released",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSmartWalletPaymasterConfig {
    pub protocol_version: String,
    pub default_session_ttl_blocks: u64,
    pub default_intent_ttl_blocks: u64,
    pub default_budget_window_blocks: u64,
    pub default_recovery_delay_blocks: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_wallets: usize,
    pub max_sessions: usize,
    pub max_sponsor_rules: usize,
    pub max_contract_budgets: usize,
    pub max_recovery_plans: usize,
    pub max_fee_receipts: usize,
    pub require_pq_sessions: bool,
    pub require_stealth_accounts: bool,
    pub allow_public_fee_fallback: bool,
}

impl Default for PrivateSmartWalletPaymasterConfig {
    fn default() -> Self {
        Self {
            protocol_version: PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION.to_string(),
            default_session_ttl_blocks: PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_SESSION_TTL_BLOCKS,
            default_intent_ttl_blocks: PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_INTENT_TTL_BLOCKS,
            default_budget_window_blocks:
                PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_BUDGET_WINDOW_BLOCKS,
            default_recovery_delay_blocks:
                PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_RECOVERY_DELAY_BLOCKS,
            min_privacy_set_size: PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS,
            max_wallets: 128,
            max_sessions: 256,
            max_sponsor_rules: 128,
            max_contract_budgets: 256,
            max_recovery_plans: 128,
            max_fee_receipts: 512,
            require_pq_sessions: true,
            require_stealth_accounts: true,
            allow_public_fee_fallback: false,
        }
    }
}

impl PrivateSmartWalletPaymasterConfig {
    pub fn devnet() -> Self {
        Self {
            default_session_ttl_blocks: 72,
            default_intent_ttl_blocks: 12,
            default_budget_window_blocks: 80,
            default_recovery_delay_blocks: 360,
            min_privacy_set_size: 96,
            max_wallets: 16,
            max_sessions: 64,
            max_sponsor_rules: 32,
            max_contract_budgets: 64,
            max_recovery_plans: 32,
            max_fee_receipts: 128,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(
            &self.protocol_version,
            "private smart wallet protocol version",
        )?;
        if self.protocol_version != PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION {
            return Err("unsupported private smart wallet paymaster protocol version".to_string());
        }
        if self.default_session_ttl_blocks == 0
            || self.default_intent_ttl_blocks == 0
            || self.default_budget_window_blocks == 0
        {
            return Err("private smart wallet default block windows must be non-zero".to_string());
        }
        if self.default_recovery_delay_blocks < self.default_intent_ttl_blocks {
            return Err("private smart wallet recovery delay below intent ttl".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("private smart wallet privacy set floor must be non-zero".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS {
            return Err("private smart wallet PQ security below protocol floor".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_smart_wallet_paymaster_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "security_model": PRIVATE_SMART_WALLET_PAYMASTER_SECURITY_MODEL,
            "pq_suite": PRIVATE_SMART_WALLET_PAYMASTER_PQ_SUITE,
            "proof_system": PRIVATE_SMART_WALLET_PAYMASTER_PROOF_SYSTEM,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_budget_window_blocks": self.default_budget_window_blocks,
            "default_recovery_delay_blocks": self.default_recovery_delay_blocks,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_wallets": self.max_wallets,
            "max_sessions": self.max_sessions,
            "max_sponsor_rules": self.max_sponsor_rules,
            "max_contract_budgets": self.max_contract_budgets,
            "max_recovery_plans": self.max_recovery_plans,
            "max_fee_receipts": self.max_fee_receipts,
            "require_pq_sessions": self.require_pq_sessions,
            "require_stealth_accounts": self.require_stealth_accounts,
            "allow_public_fee_fallback": self.allow_public_fee_fallback,
        })
    }

    pub fn config_root(&self) -> String {
        pswp_hash("CONFIG", &[HashPart::Json(&self.public_record())], 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAccountPolicy {
    pub wallet_id: String,
    pub owner_commitment: String,
    pub stealth_address_root: String,
    pub view_tag_root: String,
    pub account_mode: PrivateSmartWalletMode,
    pub status: PrivateSmartWalletStatus,
    pub min_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub allow_tokens: bool,
    pub allow_defi: bool,
    pub allow_contract_calls: bool,
    pub allow_sponsored_fees: bool,
    pub recovery_threshold: u16,
    pub metadata_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl StealthAccountPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner_commitment: &str,
        stealth_address_root: &str,
        view_tag_root: &str,
        account_mode: PrivateSmartWalletMode,
        created_at_height: u64,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(owner_commitment, "stealth account owner commitment")?;
        ensure_non_empty(stealth_address_root, "stealth account address root")?;
        ensure_non_empty(view_tag_root, "stealth account view tag root")?;
        let wallet_id = private_smart_wallet_id(
            owner_commitment,
            stealth_address_root,
            view_tag_root,
            account_mode,
            created_at_height,
        );
        let metadata = json!({
            "owner_commitment": owner_commitment,
            "stealth_address_root": stealth_address_root,
            "view_tag_root": view_tag_root,
            "account_mode": account_mode.as_str(),
            "created_at_height": created_at_height,
        });
        Ok(Self {
            wallet_id,
            owner_commitment: owner_commitment.to_string(),
            stealth_address_root: stealth_address_root.to_string(),
            view_tag_root: view_tag_root.to_string(),
            account_mode,
            status: PrivateSmartWalletStatus::Active,
            min_privacy_set_size: PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE,
            min_pq_security_bits: PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS,
            allow_tokens: !matches!(account_mode, PrivateSmartWalletMode::RecoveryOnly),
            allow_defi: account_mode.allows_defi(),
            allow_contract_calls: account_mode.allows_contract_calls(),
            allow_sponsored_fees: !matches!(account_mode, PrivateSmartWalletMode::RecoveryOnly),
            recovery_threshold: 2,
            metadata_root: pswp_hash("STEALTH-ACCOUNT-METADATA", &[HashPart::Json(&metadata)], 32),
            created_at_height,
            updated_at_height: created_at_height,
        })
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.wallet_id, "stealth wallet id")?;
        ensure_non_empty(&self.owner_commitment, "stealth wallet owner commitment")?;
        ensure_non_empty(&self.stealth_address_root, "stealth wallet address root")?;
        ensure_non_empty(&self.view_tag_root, "stealth wallet view tag root")?;
        if self.wallet_id
            != private_smart_wallet_id(
                &self.owner_commitment,
                &self.stealth_address_root,
                &self.view_tag_root,
                self.account_mode,
                self.created_at_height,
            )
        {
            return Err("stealth wallet id mismatch".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("stealth wallet privacy set floor must be non-zero".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS {
            return Err("stealth wallet PQ security below protocol floor".to_string());
        }
        if self.recovery_threshold == 0 {
            return Err("stealth wallet recovery threshold must be non-zero".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("stealth wallet updated height before created height".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "stealth_account_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "wallet_id": self.wallet_id,
            "owner_commitment": self.owner_commitment,
            "stealth_address_root": self.stealth_address_root,
            "view_tag_root": self.view_tag_root,
            "account_mode": self.account_mode.as_str(),
            "status": self.status.as_str(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "allow_tokens": self.allow_tokens,
            "allow_defi": self.allow_defi,
            "allow_contract_calls": self.allow_contract_calls,
            "allow_sponsored_fees": self.allow_sponsored_fees,
            "recovery_threshold": self.recovery_threshold,
            "metadata_root": self.metadata_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn policy_root(&self) -> String {
        pswp_hash(
            "STEALTH-ACCOUNT-POLICY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqSessionAuthorization {
    pub session_id: String,
    pub wallet_id: String,
    pub authorization_kind: PqAuthorizationKind,
    pub public_key_commitment: String,
    pub kem_ciphertext_hash: String,
    pub scope_root: String,
    pub contract_root: String,
    pub asset_root: String,
    pub max_fee_units: u64,
    pub min_pq_security_bits: u16,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub revoked_at_height: Option<u64>,
}

impl PqSessionAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        authorization_kind: PqAuthorizationKind,
        public_key_commitment: &str,
        kem_ciphertext_hash: &str,
        scope_root: &str,
        contract_root: &str,
        asset_root: &str,
        max_fee_units: u64,
        opened_at_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(wallet_id, "PQ session wallet id")?;
        ensure_non_empty(public_key_commitment, "PQ session public key commitment")?;
        ensure_non_empty(kem_ciphertext_hash, "PQ session KEM ciphertext hash")?;
        ensure_non_empty(scope_root, "PQ session scope root")?;
        ensure_non_empty(contract_root, "PQ session contract root")?;
        ensure_non_empty(asset_root, "PQ session asset root")?;
        ensure_positive(ttl_blocks, "PQ session ttl")?;
        let expires_at_height = opened_at_height.saturating_add(ttl_blocks);
        let session_id = pq_session_authorization_id(
            wallet_id,
            authorization_kind,
            public_key_commitment,
            kem_ciphertext_hash,
            scope_root,
            contract_root,
            asset_root,
            opened_at_height,
            expires_at_height,
        );
        Ok(Self {
            session_id,
            wallet_id: wallet_id.to_string(),
            authorization_kind,
            public_key_commitment: public_key_commitment.to_string(),
            kem_ciphertext_hash: kem_ciphertext_hash.to_string(),
            scope_root: scope_root.to_string(),
            contract_root: contract_root.to_string(),
            asset_root: asset_root.to_string(),
            max_fee_units,
            min_pq_security_bits: PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS,
            opened_at_height,
            expires_at_height,
            revoked_at_height: None,
        })
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.opened_at_height <= height
            && height <= self.expires_at_height
            && self
                .revoked_at_height
                .map_or(true, |revoked| height < revoked)
    }

    pub fn revoke(&mut self, height: u64) {
        self.revoked_at_height = Some(height);
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.session_id, "PQ session id")?;
        ensure_non_empty(&self.wallet_id, "PQ session wallet id")?;
        ensure_non_empty(
            &self.public_key_commitment,
            "PQ session public key commitment",
        )?;
        ensure_non_empty(&self.kem_ciphertext_hash, "PQ session KEM ciphertext hash")?;
        ensure_non_empty(&self.scope_root, "PQ session scope root")?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("PQ session expiry must be after open height".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_SMART_WALLET_PAYMASTER_MIN_PQ_SECURITY_BITS {
            return Err("PQ session security below protocol floor".to_string());
        }
        if self.session_id
            != pq_session_authorization_id(
                &self.wallet_id,
                self.authorization_kind,
                &self.public_key_commitment,
                &self.kem_ciphertext_hash,
                &self.scope_root,
                &self.contract_root,
                &self.asset_root,
                self.opened_at_height,
                self.expires_at_height,
            )
        {
            return Err("PQ session authorization id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_session_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "wallet_id": self.wallet_id,
            "authorization_kind": self.authorization_kind.as_str(),
            "public_key_commitment": self.public_key_commitment,
            "kem_ciphertext_hash": self.kem_ciphertext_hash,
            "scope_root": self.scope_root,
            "contract_root": self.contract_root,
            "asset_root": self.asset_root,
            "max_fee_units": self.max_fee_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "revoked_at_height": self.revoked_at_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorRule {
    pub rule_id: String,
    pub wallet_id: String,
    pub sponsor_pool_id: String,
    pub fee_asset_id: String,
    pub mode: SponsorRuleMode,
    pub max_fee_units_per_call: u64,
    pub max_fee_units_per_epoch: u64,
    pub spent_fee_units_in_epoch: u64,
    pub min_privacy_set_size: u64,
    pub relayer_policy_root: String,
    pub active_from_height: u64,
    pub expires_at_height: u64,
    pub paused: bool,
}

impl LowFeeSponsorRule {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        sponsor_pool_id: &str,
        fee_asset_id: &str,
        mode: SponsorRuleMode,
        max_fee_units_per_call: u64,
        max_fee_units_per_epoch: u64,
        relayer_policy_root: &str,
        active_from_height: u64,
        ttl_blocks: u64,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(wallet_id, "low fee sponsor wallet id")?;
        ensure_non_empty(sponsor_pool_id, "low fee sponsor pool id")?;
        ensure_non_empty(fee_asset_id, "low fee sponsor fee asset")?;
        ensure_non_empty(relayer_policy_root, "low fee sponsor relayer policy root")?;
        ensure_positive(max_fee_units_per_call, "low fee sponsor per-call fee cap")?;
        ensure_positive(max_fee_units_per_epoch, "low fee sponsor epoch fee cap")?;
        ensure_positive(ttl_blocks, "low fee sponsor ttl")?;
        if max_fee_units_per_call > max_fee_units_per_epoch {
            return Err("low fee sponsor per-call cap exceeds epoch cap".to_string());
        }
        let expires_at_height = active_from_height.saturating_add(ttl_blocks);
        let rule_id = low_fee_sponsor_rule_id(
            wallet_id,
            sponsor_pool_id,
            fee_asset_id,
            mode,
            max_fee_units_per_call,
            max_fee_units_per_epoch,
            relayer_policy_root,
            active_from_height,
            expires_at_height,
        );
        Ok(Self {
            rule_id,
            wallet_id: wallet_id.to_string(),
            sponsor_pool_id: sponsor_pool_id.to_string(),
            fee_asset_id: fee_asset_id.to_string(),
            mode,
            max_fee_units_per_call,
            max_fee_units_per_epoch,
            spent_fee_units_in_epoch: 0,
            min_privacy_set_size: PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_PRIVACY_SET_SIZE,
            relayer_policy_root: relayer_policy_root.to_string(),
            active_from_height,
            expires_at_height,
            paused: false,
        })
    }

    pub fn remaining_epoch_fee_units(&self) -> u64 {
        self.max_fee_units_per_epoch
            .saturating_sub(self.spent_fee_units_in_epoch)
    }

    pub fn can_sponsor(&self, fee_units: u64, height: u64) -> bool {
        !self.paused
            && self.mode != SponsorRuleMode::Disabled
            && self.active_from_height <= height
            && height <= self.expires_at_height
            && fee_units > 0
            && fee_units <= self.max_fee_units_per_call
            && fee_units <= self.remaining_epoch_fee_units()
    }

    pub fn reserve_fee(
        &mut self,
        fee_units: u64,
        height: u64,
    ) -> PrivateSmartWalletPaymasterResult<()> {
        if !self.can_sponsor(fee_units, height) {
            return Err("low fee sponsor rule cannot cover requested fee".to_string());
        }
        self.spent_fee_units_in_epoch = self
            .spent_fee_units_in_epoch
            .checked_add(fee_units)
            .ok_or_else(|| "low fee sponsor epoch spend overflow".to_string())?;
        Ok(())
    }

    pub fn reset_epoch(&mut self) {
        self.spent_fee_units_in_epoch = 0;
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.rule_id, "low fee sponsor rule id")?;
        ensure_non_empty(&self.wallet_id, "low fee sponsor wallet id")?;
        ensure_non_empty(&self.sponsor_pool_id, "low fee sponsor pool id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee sponsor fee asset")?;
        if self.max_fee_units_per_call == 0 || self.max_fee_units_per_epoch == 0 {
            return Err("low fee sponsor fee caps must be non-zero".to_string());
        }
        if self.max_fee_units_per_call > self.max_fee_units_per_epoch {
            return Err("low fee sponsor per-call cap exceeds epoch cap".to_string());
        }
        if self.spent_fee_units_in_epoch > self.max_fee_units_per_epoch {
            return Err("low fee sponsor spent units exceed epoch cap".to_string());
        }
        if self.min_privacy_set_size == 0 {
            return Err("low fee sponsor privacy set floor must be non-zero".to_string());
        }
        if self.expires_at_height <= self.active_from_height {
            return Err("low fee sponsor expiry must be after activation".to_string());
        }
        if self.rule_id
            != low_fee_sponsor_rule_id(
                &self.wallet_id,
                &self.sponsor_pool_id,
                &self.fee_asset_id,
                self.mode,
                self.max_fee_units_per_call,
                self.max_fee_units_per_epoch,
                &self.relayer_policy_root,
                self.active_from_height,
                self.expires_at_height,
            )
        {
            return Err("low fee sponsor rule id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsor_rule",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "rule_id": self.rule_id,
            "wallet_id": self.wallet_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "fee_asset_id": self.fee_asset_id,
            "mode": self.mode.as_str(),
            "max_fee_units_per_call": self.max_fee_units_per_call,
            "max_fee_units_per_epoch": self.max_fee_units_per_epoch,
            "spent_fee_units_in_epoch": self.spent_fee_units_in_epoch,
            "remaining_epoch_fee_units": self.remaining_epoch_fee_units(),
            "min_privacy_set_size": self.min_privacy_set_size,
            "relayer_policy_root": self.relayer_policy_root,
            "active_from_height": self.active_from_height,
            "expires_at_height": self.expires_at_height,
            "paused": self.paused,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCallBudget {
    pub budget_id: String,
    pub wallet_id: String,
    pub session_id: String,
    pub contract_commitment: String,
    pub selector_root: String,
    pub operation: PrivateWalletOperation,
    pub window: ContractBudgetWindow,
    pub max_call_units: u64,
    pub spent_call_units: u64,
    pub max_fee_units: u64,
    pub spent_fee_units: u64,
    pub reset_interval_blocks: u64,
    pub window_start_height: u64,
    pub privacy_proof_root: String,
}

impl PrivateContractCallBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        session_id: &str,
        contract_commitment: &str,
        selector_root: &str,
        operation: PrivateWalletOperation,
        window: ContractBudgetWindow,
        max_call_units: u64,
        max_fee_units: u64,
        window_start_height: u64,
        reset_interval_blocks: u64,
        privacy_proof_root: &str,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(wallet_id, "private contract budget wallet id")?;
        ensure_non_empty(session_id, "private contract budget session id")?;
        ensure_non_empty(
            contract_commitment,
            "private contract budget contract commitment",
        )?;
        ensure_non_empty(selector_root, "private contract budget selector root")?;
        ensure_non_empty(
            privacy_proof_root,
            "private contract budget privacy proof root",
        )?;
        ensure_positive(max_call_units, "private contract budget call cap")?;
        let budget_id = private_contract_call_budget_id(
            wallet_id,
            session_id,
            contract_commitment,
            selector_root,
            operation,
            window,
            max_call_units,
            max_fee_units,
            window_start_height,
            reset_interval_blocks,
            privacy_proof_root,
        );
        Ok(Self {
            budget_id,
            wallet_id: wallet_id.to_string(),
            session_id: session_id.to_string(),
            contract_commitment: contract_commitment.to_string(),
            selector_root: selector_root.to_string(),
            operation,
            window,
            max_call_units,
            spent_call_units: 0,
            max_fee_units,
            spent_fee_units: 0,
            reset_interval_blocks,
            window_start_height,
            privacy_proof_root: privacy_proof_root.to_string(),
        })
    }

    pub fn remaining_call_units(&self) -> u64 {
        self.max_call_units.saturating_sub(self.spent_call_units)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.spent_fee_units)
    }

    pub fn maybe_reset(&mut self, height: u64) {
        if self.reset_interval_blocks == 0 {
            return;
        }
        if height
            >= self
                .window_start_height
                .saturating_add(self.reset_interval_blocks)
        {
            self.spent_call_units = 0;
            self.spent_fee_units = 0;
            self.window_start_height = height;
        }
    }

    pub fn consume(
        &mut self,
        call_units: u64,
        fee_units: u64,
    ) -> PrivateSmartWalletPaymasterResult<()> {
        if call_units == 0 {
            return Err("private contract budget call units must be non-zero".to_string());
        }
        if call_units > self.remaining_call_units() {
            return Err("private contract budget call cap exceeded".to_string());
        }
        if fee_units > self.remaining_fee_units() {
            return Err("private contract budget fee cap exceeded".to_string());
        }
        self.spent_call_units = self
            .spent_call_units
            .checked_add(call_units)
            .ok_or_else(|| "private contract budget call spend overflow".to_string())?;
        self.spent_fee_units = self
            .spent_fee_units
            .checked_add(fee_units)
            .ok_or_else(|| "private contract budget fee spend overflow".to_string())?;
        Ok(())
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.budget_id, "private contract budget id")?;
        ensure_non_empty(&self.wallet_id, "private contract budget wallet id")?;
        ensure_non_empty(&self.session_id, "private contract budget session id")?;
        ensure_non_empty(
            &self.contract_commitment,
            "private contract budget contract commitment",
        )?;
        ensure_non_empty(&self.selector_root, "private contract budget selector root")?;
        if self.max_call_units == 0 {
            return Err("private contract budget call cap must be non-zero".to_string());
        }
        if self.spent_call_units > self.max_call_units {
            return Err("private contract budget spent call units exceed cap".to_string());
        }
        if self.spent_fee_units > self.max_fee_units {
            return Err("private contract budget spent fee units exceed cap".to_string());
        }
        if self.budget_id
            != private_contract_call_budget_id(
                &self.wallet_id,
                &self.session_id,
                &self.contract_commitment,
                &self.selector_root,
                self.operation,
                self.window,
                self.max_call_units,
                self.max_fee_units,
                self.window_start_height,
                self.reset_interval_blocks,
                &self.privacy_proof_root,
            )
        {
            return Err("private contract budget id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_call_budget",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "budget_id": self.budget_id,
            "wallet_id": self.wallet_id,
            "session_id": self.session_id,
            "contract_commitment": self.contract_commitment,
            "selector_root": self.selector_root,
            "operation": self.operation.as_str(),
            "window": self.window.as_str(),
            "max_call_units": self.max_call_units,
            "spent_call_units": self.spent_call_units,
            "remaining_call_units": self.remaining_call_units(),
            "max_fee_units": self.max_fee_units,
            "spent_fee_units": self.spent_fee_units,
            "remaining_fee_units": self.remaining_fee_units(),
            "reset_interval_blocks": self.reset_interval_blocks,
            "window_start_height": self.window_start_height,
            "privacy_proof_root": self.privacy_proof_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRecoveryPlan {
    pub recovery_id: String,
    pub wallet_id: String,
    pub guardian_root: String,
    pub replacement_owner_commitment: String,
    pub replacement_stealth_address_root: String,
    pub threshold_weight: u16,
    pub observed_weight: u16,
    pub delay_blocks: u64,
    pub requested_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub recovery_proof_root: String,
    pub status: RecoveryPlanStatus,
}

impl WalletRecoveryPlan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        guardian_root: &str,
        replacement_owner_commitment: &str,
        replacement_stealth_address_root: &str,
        threshold_weight: u16,
        delay_blocks: u64,
        requested_at_height: u64,
        ttl_blocks: u64,
        recovery_proof_root: &str,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(wallet_id, "wallet recovery wallet id")?;
        ensure_non_empty(guardian_root, "wallet recovery guardian root")?;
        ensure_non_empty(
            replacement_owner_commitment,
            "wallet recovery replacement owner commitment",
        )?;
        ensure_non_empty(
            replacement_stealth_address_root,
            "wallet recovery replacement stealth address root",
        )?;
        ensure_non_empty(recovery_proof_root, "wallet recovery proof root")?;
        if threshold_weight == 0 {
            return Err("wallet recovery threshold must be non-zero".to_string());
        }
        ensure_positive(delay_blocks, "wallet recovery delay")?;
        ensure_positive(ttl_blocks, "wallet recovery ttl")?;
        let executable_at_height = requested_at_height.saturating_add(delay_blocks);
        let expires_at_height = requested_at_height.saturating_add(ttl_blocks);
        if expires_at_height <= executable_at_height {
            return Err("wallet recovery expiry must be after executable height".to_string());
        }
        let recovery_id = wallet_recovery_plan_id(
            wallet_id,
            guardian_root,
            replacement_owner_commitment,
            replacement_stealth_address_root,
            threshold_weight,
            delay_blocks,
            requested_at_height,
            expires_at_height,
            recovery_proof_root,
        );
        Ok(Self {
            recovery_id,
            wallet_id: wallet_id.to_string(),
            guardian_root: guardian_root.to_string(),
            replacement_owner_commitment: replacement_owner_commitment.to_string(),
            replacement_stealth_address_root: replacement_stealth_address_root.to_string(),
            threshold_weight,
            observed_weight: 0,
            delay_blocks,
            requested_at_height,
            executable_at_height,
            expires_at_height,
            recovery_proof_root: recovery_proof_root.to_string(),
            status: RecoveryPlanStatus::Active,
        })
    }

    pub fn observe_guardian_weight(&mut self, weight: u16, height: u64) {
        self.observed_weight = self.observed_weight.saturating_add(weight);
        if self.observed_weight >= self.threshold_weight {
            self.status = if height >= self.executable_at_height {
                RecoveryPlanStatus::DelayElapsed
            } else {
                RecoveryPlanStatus::Requested
            };
        }
    }

    pub fn can_execute_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            RecoveryPlanStatus::Requested | RecoveryPlanStatus::DelayElapsed
        ) && self.observed_weight >= self.threshold_weight
            && height >= self.executable_at_height
            && height <= self.expires_at_height
    }

    pub fn refresh_status(&mut self, height: u64) {
        if matches!(
            self.status,
            RecoveryPlanStatus::Executed | RecoveryPlanStatus::Cancelled
        ) {
            return;
        }
        if height > self.expires_at_height {
            self.status = RecoveryPlanStatus::Expired;
        } else if self.can_execute_at(height) {
            self.status = RecoveryPlanStatus::DelayElapsed;
        }
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.recovery_id, "wallet recovery id")?;
        ensure_non_empty(&self.wallet_id, "wallet recovery wallet id")?;
        ensure_non_empty(&self.guardian_root, "wallet recovery guardian root")?;
        ensure_non_empty(
            &self.replacement_owner_commitment,
            "wallet recovery replacement owner commitment",
        )?;
        ensure_non_empty(
            &self.replacement_stealth_address_root,
            "wallet recovery replacement stealth address root",
        )?;
        if self.threshold_weight == 0 {
            return Err("wallet recovery threshold must be non-zero".to_string());
        }
        if self.executable_at_height < self.requested_at_height {
            return Err("wallet recovery executable height before request".to_string());
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err("wallet recovery expiry must be after executable height".to_string());
        }
        if self.recovery_id
            != wallet_recovery_plan_id(
                &self.wallet_id,
                &self.guardian_root,
                &self.replacement_owner_commitment,
                &self.replacement_stealth_address_root,
                self.threshold_weight,
                self.delay_blocks,
                self.requested_at_height,
                self.expires_at_height,
                &self.recovery_proof_root,
            )
        {
            return Err("wallet recovery id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_recovery_plan",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "recovery_id": self.recovery_id,
            "wallet_id": self.wallet_id,
            "guardian_root": self.guardian_root,
            "replacement_owner_commitment": self.replacement_owner_commitment,
            "replacement_stealth_address_root": self.replacement_stealth_address_root,
            "threshold_weight": self.threshold_weight,
            "observed_weight": self.observed_weight,
            "delay_blocks": self.delay_blocks,
            "requested_at_height": self.requested_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "recovery_proof_root": self.recovery_proof_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateFeeReceipt {
    pub receipt_id: String,
    pub wallet_id: String,
    pub session_id: String,
    pub sponsor_rule_id: String,
    pub operation: PrivateWalletOperation,
    pub fee_asset_id: String,
    pub sponsored_fee_units: u64,
    pub relayer_tip_units: u64,
    pub private_call_root: String,
    pub fee_commitment_root: String,
    pub pq_attestation_root: String,
    pub created_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub status: FeeReceiptStatus,
}

impl PrivateFeeReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_id: &str,
        session_id: &str,
        sponsor_rule_id: &str,
        operation: PrivateWalletOperation,
        fee_asset_id: &str,
        sponsored_fee_units: u64,
        relayer_tip_units: u64,
        private_call_root: &str,
        fee_commitment_root: &str,
        pq_attestation_root: &str,
        created_at_height: u64,
    ) -> PrivateSmartWalletPaymasterResult<Self> {
        ensure_non_empty(wallet_id, "private fee receipt wallet id")?;
        ensure_non_empty(session_id, "private fee receipt session id")?;
        ensure_non_empty(sponsor_rule_id, "private fee receipt sponsor rule id")?;
        ensure_non_empty(fee_asset_id, "private fee receipt fee asset")?;
        ensure_non_empty(private_call_root, "private fee receipt call root")?;
        ensure_non_empty(
            fee_commitment_root,
            "private fee receipt fee commitment root",
        )?;
        ensure_non_empty(
            pq_attestation_root,
            "private fee receipt PQ attestation root",
        )?;
        ensure_positive(sponsored_fee_units, "private fee receipt sponsored units")?;
        let receipt_id = private_fee_receipt_id(
            wallet_id,
            session_id,
            sponsor_rule_id,
            operation,
            fee_asset_id,
            sponsored_fee_units,
            relayer_tip_units,
            private_call_root,
            fee_commitment_root,
            pq_attestation_root,
            created_at_height,
        );
        Ok(Self {
            receipt_id,
            wallet_id: wallet_id.to_string(),
            session_id: session_id.to_string(),
            sponsor_rule_id: sponsor_rule_id.to_string(),
            operation,
            fee_asset_id: fee_asset_id.to_string(),
            sponsored_fee_units,
            relayer_tip_units,
            private_call_root: private_call_root.to_string(),
            fee_commitment_root: fee_commitment_root.to_string(),
            pq_attestation_root: pq_attestation_root.to_string(),
            created_at_height,
            settled_at_height: None,
            status: FeeReceiptStatus::Reserved,
        })
    }

    pub fn settle(&mut self, height: u64) -> PrivateSmartWalletPaymasterResult<()> {
        if height < self.created_at_height {
            return Err("private fee receipt settlement before creation".to_string());
        }
        self.settled_at_height = Some(height);
        self.status = FeeReceiptStatus::Settled;
        Ok(())
    }

    pub fn release(&mut self) {
        self.status = FeeReceiptStatus::Released;
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        ensure_non_empty(&self.receipt_id, "private fee receipt id")?;
        ensure_non_empty(&self.wallet_id, "private fee receipt wallet id")?;
        ensure_non_empty(&self.session_id, "private fee receipt session id")?;
        ensure_non_empty(&self.sponsor_rule_id, "private fee receipt sponsor rule id")?;
        ensure_positive(
            self.sponsored_fee_units,
            "private fee receipt sponsored units",
        )?;
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.created_at_height {
                return Err("private fee receipt settlement before creation".to_string());
            }
        }
        if self.receipt_id
            != private_fee_receipt_id(
                &self.wallet_id,
                &self.session_id,
                &self.sponsor_rule_id,
                self.operation,
                &self.fee_asset_id,
                self.sponsored_fee_units,
                self.relayer_tip_units,
                &self.private_call_root,
                &self.fee_commitment_root,
                &self.pq_attestation_root,
                self.created_at_height,
            )
        {
            return Err("private fee receipt id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_fee_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "wallet_id": self.wallet_id,
            "session_id": self.session_id,
            "sponsor_rule_id": self.sponsor_rule_id,
            "operation": self.operation.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "sponsored_fee_units": self.sponsored_fee_units,
            "relayer_tip_units": self.relayer_tip_units,
            "private_call_root": self.private_call_root,
            "fee_commitment_root": self.fee_commitment_root,
            "pq_attestation_root": self.pq_attestation_root,
            "created_at_height": self.created_at_height,
            "settled_at_height": self.settled_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSmartWalletPaymasterRoots {
    pub config_root: String,
    pub stealth_account_root: String,
    pub pq_session_root: String,
    pub sponsor_rule_root: String,
    pub contract_budget_root: String,
    pub recovery_plan_root: String,
    pub fee_receipt_root: String,
    pub spent_nullifier_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl PrivateSmartWalletPaymasterRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_smart_wallet_paymaster_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "stealth_account_root": self.stealth_account_root,
            "pq_session_root": self.pq_session_root,
            "sponsor_rule_root": self.sponsor_rule_root,
            "contract_budget_root": self.contract_budget_root,
            "recovery_plan_root": self.recovery_plan_root,
            "fee_receipt_root": self.fee_receipt_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "public_record_root": self.public_record_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSmartWalletPaymasterCounters {
    pub stealth_accounts: u64,
    pub executable_wallets: u64,
    pub pq_sessions: u64,
    pub live_pq_sessions: u64,
    pub sponsor_rules: u64,
    pub live_sponsor_rules: u64,
    pub contract_budgets: u64,
    pub recovery_plans: u64,
    pub executable_recovery_plans: u64,
    pub fee_receipts: u64,
    pub settled_fee_receipts: u64,
    pub spent_nullifiers: u64,
}

impl PrivateSmartWalletPaymasterCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_smart_wallet_paymaster_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "stealth_accounts": self.stealth_accounts,
            "executable_wallets": self.executable_wallets,
            "pq_sessions": self.pq_sessions,
            "live_pq_sessions": self.live_pq_sessions,
            "sponsor_rules": self.sponsor_rules,
            "live_sponsor_rules": self.live_sponsor_rules,
            "contract_budgets": self.contract_budgets,
            "recovery_plans": self.recovery_plans,
            "executable_recovery_plans": self.executable_recovery_plans,
            "fee_receipts": self.fee_receipts,
            "settled_fee_receipts": self.settled_fee_receipts,
            "spent_nullifiers": self.spent_nullifiers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateSmartWalletPaymasterState {
    pub config: PrivateSmartWalletPaymasterConfig,
    pub height: u64,
    pub stealth_accounts: BTreeMap<String, StealthAccountPolicy>,
    pub pq_sessions: BTreeMap<String, PqSessionAuthorization>,
    pub sponsor_rules: BTreeMap<String, LowFeeSponsorRule>,
    pub contract_budgets: BTreeMap<String, PrivateContractCallBudget>,
    pub recovery_plans: BTreeMap<String, WalletRecoveryPlan>,
    pub fee_receipts: BTreeMap<String, PrivateFeeReceipt>,
    pub spent_nullifiers: BTreeSet<String>,
    pub public_records: BTreeMap<String, Value>,
}

impl PrivateSmartWalletPaymasterState {
    pub fn new(config: PrivateSmartWalletPaymasterConfig) -> Self {
        Self {
            config,
            height: 0,
            stealth_accounts: BTreeMap::new(),
            pq_sessions: BTreeMap::new(),
            sponsor_rules: BTreeMap::new(),
            contract_budgets: BTreeMap::new(),
            recovery_plans: BTreeMap::new(),
            fee_receipts: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateSmartWalletPaymasterResult<Self> {
        let mut state = Self::new(PrivateSmartWalletPaymasterConfig::devnet());
        state.set_height(PRIVATE_SMART_WALLET_PAYMASTER_DEFAULT_HEIGHT);
        let scope_root = private_wallet_string_set_root(
            "PRIVATE-SMART-WALLET-DEVNET-SCOPES",
            &[
                PrivateWalletOperation::PrivateTransfer.as_str().to_string(),
                PrivateWalletOperation::ContractCall.as_str().to_string(),
                PrivateWalletOperation::DefiSwap.as_str().to_string(),
            ],
        );
        let asset_root = private_wallet_string_set_root(
            "PRIVATE-SMART-WALLET-DEVNET-ASSETS",
            &["wxmr-devnet".to_string(), "dusd-devnet".to_string()],
        );
        let contract_root = private_wallet_string_set_root(
            "PRIVATE-SMART-WALLET-DEVNET-CONTRACTS",
            &["swap-router".to_string(), "lending-vault".to_string()],
        );
        for index in 0..4_u64 {
            let account_mode = if index % 2 == 0 {
                PrivateSmartWalletMode::DefiEnabled
            } else {
                PrivateSmartWalletMode::TokensOnly
            };
            let wallet = StealthAccountPolicy::new(
                &format!("devnet-owner-commitment-{index}"),
                &pswp_hash(
                    "DEVNET-STEALTH-ADDRESS",
                    &[HashPart::Int(index as i128)],
                    32,
                ),
                &pswp_hash("DEVNET-VIEW-TAG", &[HashPart::Int(index as i128)], 32),
                account_mode,
                state.height,
            )?;
            let wallet_id = state.insert_stealth_account(wallet)?;
            let session = PqSessionAuthorization::new(
                &wallet_id,
                if index % 2 == 0 {
                    PqAuthorizationKind::Automation
                } else {
                    PqAuthorizationKind::Session
                },
                &format!("devnet-pq-public-key-commitment-{index}"),
                &pswp_hash("DEVNET-KEM-CIPHERTEXT", &[HashPart::Int(index as i128)], 32),
                &scope_root,
                &contract_root,
                &asset_root,
                8,
                state.height,
                state.config.default_session_ttl_blocks,
            )?;
            let session_id = state.insert_pq_session(session)?;
            let sponsor_rule = LowFeeSponsorRule::new(
                &wallet_id,
                &format!("devnet-sponsor-pool-{index}"),
                "wxmr-devnet",
                SponsorRuleMode::PreferShieldedPool,
                4,
                32,
                &pswp_hash("DEVNET-RELAYER-POLICY", &[HashPart::Int(index as i128)], 32),
                state.height,
                state.config.default_budget_window_blocks,
            )?;
            let sponsor_rule_id = state.insert_sponsor_rule(sponsor_rule)?;
            let budget = PrivateContractCallBudget::new(
                &wallet_id,
                &session_id,
                "devnet-swap-router-commitment",
                &private_wallet_string_set_root(
                    "PRIVATE-SMART-WALLET-DEVNET-SELECTORS",
                    &[
                        "swap_exact_private".to_string(),
                        "quote_private".to_string(),
                    ],
                ),
                PrivateWalletOperation::DefiSwap,
                ContractBudgetWindow::Session,
                16,
                8,
                state.height,
                state.config.default_budget_window_blocks,
                &pswp_hash(
                    "DEVNET-BUDGET-PRIVACY-PROOF",
                    &[HashPart::Int(index as i128)],
                    32,
                ),
            )?;
            let budget_id = state.insert_contract_budget(budget)?;
            let call_root = pswp_hash(
                "DEVNET-PRIVATE-CALL",
                &[HashPart::Str(&wallet_id), HashPart::Str(&budget_id)],
                32,
            );
            let receipt_id = state.reserve_fee_receipt(
                &wallet_id,
                &session_id,
                &sponsor_rule_id,
                PrivateWalletOperation::DefiSwap,
                "wxmr-devnet",
                2,
                index % 2,
                &call_root,
                &pswp_hash("DEVNET-FEE-COMMITMENT", &[HashPart::Str(&call_root)], 32),
                &pswp_hash("DEVNET-PQ-ATTESTATION", &[HashPart::Str(&session_id)], 32),
            )?;
            if index % 2 == 0 {
                state.settle_fee_receipt(&receipt_id, state.height.saturating_add(index))?;
            }
            let recovery = WalletRecoveryPlan::new(
                &wallet_id,
                &pswp_hash("DEVNET-GUARDIAN-ROOT", &[HashPart::Str(&wallet_id)], 32),
                &format!("devnet-replacement-owner-{index}"),
                &pswp_hash(
                    "DEVNET-RECOVERY-STEALTH-ADDRESS",
                    &[HashPart::Str(&wallet_id)],
                    32,
                ),
                2,
                state.config.default_recovery_delay_blocks,
                state.height,
                state.config.default_recovery_delay_blocks.saturating_mul(2),
                &pswp_hash("DEVNET-RECOVERY-PROOF", &[HashPart::Str(&wallet_id)], 32),
            )?;
            state.insert_recovery_plan(recovery)?;
        }
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        let previous_epoch = self.epoch_at(self.height);
        self.height = height;
        let current_epoch = self.epoch_at(height);
        if current_epoch != previous_epoch {
            for rule in self.sponsor_rules.values_mut() {
                rule.reset_epoch();
            }
        }
        for budget in self.contract_budgets.values_mut() {
            budget.maybe_reset(height);
        }
        for recovery in self.recovery_plans.values_mut() {
            recovery.refresh_status(height);
        }
    }

    pub fn insert_stealth_account(
        &mut self,
        account: StealthAccountPolicy,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        account.validate()?;
        if self.stealth_accounts.len() >= self.config.max_wallets {
            return Err("private smart wallet account capacity exceeded".to_string());
        }
        let wallet_id = account.wallet_id.clone();
        insert_unique_record(
            &mut self.stealth_accounts,
            wallet_id.clone(),
            account,
            "stealth account",
        )?;
        Ok(wallet_id)
    }

    pub fn insert_pq_session(
        &mut self,
        session: PqSessionAuthorization,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        session.validate()?;
        if self.pq_sessions.len() >= self.config.max_sessions {
            return Err("private smart wallet PQ session capacity exceeded".to_string());
        }
        if !self.stealth_accounts.contains_key(&session.wallet_id) {
            return Err("PQ session references missing stealth wallet".to_string());
        }
        let session_id = session.session_id.clone();
        insert_unique_record(
            &mut self.pq_sessions,
            session_id.clone(),
            session,
            "PQ session authorization",
        )?;
        Ok(session_id)
    }

    pub fn insert_sponsor_rule(
        &mut self,
        rule: LowFeeSponsorRule,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        rule.validate()?;
        if self.sponsor_rules.len() >= self.config.max_sponsor_rules {
            return Err("private smart wallet sponsor rule capacity exceeded".to_string());
        }
        let wallet = self
            .stealth_accounts
            .get(&rule.wallet_id)
            .ok_or_else(|| "sponsor rule references missing stealth wallet".to_string())?;
        if !wallet.allow_sponsored_fees {
            return Err("sponsor rule references wallet that disallows sponsored fees".to_string());
        }
        if rule.min_privacy_set_size < self.config.min_privacy_set_size {
            return Err("sponsor rule privacy floor below config minimum".to_string());
        }
        let rule_id = rule.rule_id.clone();
        insert_unique_record(
            &mut self.sponsor_rules,
            rule_id.clone(),
            rule,
            "low fee sponsor rule",
        )?;
        Ok(rule_id)
    }

    pub fn insert_contract_budget(
        &mut self,
        budget: PrivateContractCallBudget,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        budget.validate()?;
        if self.contract_budgets.len() >= self.config.max_contract_budgets {
            return Err("private contract budget capacity exceeded".to_string());
        }
        let wallet = self
            .stealth_accounts
            .get(&budget.wallet_id)
            .ok_or_else(|| "contract budget references missing stealth wallet".to_string())?;
        if !wallet.allow_contract_calls {
            return Err(
                "contract budget references wallet that disallows contract calls".to_string(),
            );
        }
        let session = self
            .pq_sessions
            .get(&budget.session_id)
            .ok_or_else(|| "contract budget references missing PQ session".to_string())?;
        if session.wallet_id != budget.wallet_id {
            return Err("contract budget session belongs to a different wallet".to_string());
        }
        let budget_id = budget.budget_id.clone();
        insert_unique_record(
            &mut self.contract_budgets,
            budget_id.clone(),
            budget,
            "private contract call budget",
        )?;
        Ok(budget_id)
    }

    pub fn insert_recovery_plan(
        &mut self,
        recovery: WalletRecoveryPlan,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        recovery.validate()?;
        if self.recovery_plans.len() >= self.config.max_recovery_plans {
            return Err("wallet recovery plan capacity exceeded".to_string());
        }
        if !self.stealth_accounts.contains_key(&recovery.wallet_id) {
            return Err("recovery plan references missing stealth wallet".to_string());
        }
        let recovery_id = recovery.recovery_id.clone();
        insert_unique_record(
            &mut self.recovery_plans,
            recovery_id.clone(),
            recovery,
            "wallet recovery plan",
        )?;
        Ok(recovery_id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn reserve_fee_receipt(
        &mut self,
        wallet_id: &str,
        session_id: &str,
        sponsor_rule_id: &str,
        operation: PrivateWalletOperation,
        fee_asset_id: &str,
        sponsored_fee_units: u64,
        relayer_tip_units: u64,
        private_call_root: &str,
        fee_commitment_root: &str,
        pq_attestation_root: &str,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        if self.fee_receipts.len() >= self.config.max_fee_receipts {
            return Err("private fee receipt capacity exceeded".to_string());
        }
        let wallet = self
            .stealth_accounts
            .get(wallet_id)
            .ok_or_else(|| "fee receipt references missing stealth wallet".to_string())?;
        if !wallet.status.can_execute() {
            return Err("fee receipt references wallet that cannot execute".to_string());
        }
        let session = self
            .pq_sessions
            .get(session_id)
            .ok_or_else(|| "fee receipt references missing PQ session".to_string())?;
        if session.wallet_id != wallet_id {
            return Err("fee receipt session belongs to a different wallet".to_string());
        }
        if !session.is_live_at(self.height) {
            return Err("fee receipt session is not live".to_string());
        }
        let sponsor_rule = self
            .sponsor_rules
            .get_mut(sponsor_rule_id)
            .ok_or_else(|| "fee receipt references missing sponsor rule".to_string())?;
        if sponsor_rule.wallet_id != wallet_id {
            return Err("fee receipt sponsor rule belongs to a different wallet".to_string());
        }
        if sponsor_rule.fee_asset_id != fee_asset_id {
            return Err("fee receipt sponsor rule fee asset mismatch".to_string());
        }
        sponsor_rule.reserve_fee(sponsored_fee_units, self.height)?;
        let nullifier = pswp_hash(
            "FEE-RECEIPT-NULLIFIER",
            &[
                HashPart::Str(wallet_id),
                HashPart::Str(session_id),
                HashPart::Str(private_call_root),
                HashPart::Str(fee_commitment_root),
            ],
            32,
        );
        if !self.spent_nullifiers.insert(nullifier) {
            return Err("private fee receipt nullifier already spent".to_string());
        }
        let receipt = PrivateFeeReceipt::new(
            wallet_id,
            session_id,
            sponsor_rule_id,
            operation,
            fee_asset_id,
            sponsored_fee_units,
            relayer_tip_units,
            private_call_root,
            fee_commitment_root,
            pq_attestation_root,
            self.height,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        insert_unique_record(
            &mut self.fee_receipts,
            receipt_id.clone(),
            receipt,
            "private fee receipt",
        )?;
        Ok(receipt_id)
    }

    pub fn settle_fee_receipt(
        &mut self,
        receipt_id: &str,
        height: u64,
    ) -> PrivateSmartWalletPaymasterResult<()> {
        let receipt = self
            .fee_receipts
            .get_mut(receipt_id)
            .ok_or_else(|| format!("private fee receipt not found: {receipt_id}"))?;
        receipt.settle(height)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        record: Value,
    ) -> PrivateSmartWalletPaymasterResult<String> {
        ensure_non_empty(label, "private smart wallet public record label")?;
        let record_id = pswp_hash(
            "PUBLIC-RECORD-ID",
            &[HashPart::Str(label), HashPart::Json(&record)],
            24,
        );
        insert_unique_record(
            &mut self.public_records,
            record_id.clone(),
            json!({
                "kind": "private_smart_wallet_public_record",
                "chain_id": CHAIN_ID,
                "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
                "record_id": record_id,
                "label": label,
                "record": record,
                "height": self.height,
            }),
            "private smart wallet public record",
        )?;
        Ok(record_id)
    }

    pub fn counters(&self) -> PrivateSmartWalletPaymasterCounters {
        PrivateSmartWalletPaymasterCounters {
            stealth_accounts: self.stealth_accounts.len() as u64,
            executable_wallets: self
                .stealth_accounts
                .values()
                .filter(|account| account.status.can_execute())
                .count() as u64,
            pq_sessions: self.pq_sessions.len() as u64,
            live_pq_sessions: self
                .pq_sessions
                .values()
                .filter(|session| session.is_live_at(self.height))
                .count() as u64,
            sponsor_rules: self.sponsor_rules.len() as u64,
            live_sponsor_rules: self
                .sponsor_rules
                .values()
                .filter(|rule| {
                    !rule.paused
                        && rule.active_from_height <= self.height
                        && self.height <= rule.expires_at_height
                })
                .count() as u64,
            contract_budgets: self.contract_budgets.len() as u64,
            recovery_plans: self.recovery_plans.len() as u64,
            executable_recovery_plans: self
                .recovery_plans
                .values()
                .filter(|plan| plan.can_execute_at(self.height))
                .count() as u64,
            fee_receipts: self.fee_receipts.len() as u64,
            settled_fee_receipts: self
                .fee_receipts
                .values()
                .filter(|receipt| receipt.status == FeeReceiptStatus::Settled)
                .count() as u64,
            spent_nullifiers: self.spent_nullifiers.len() as u64,
        }
    }

    pub fn roots(&self) -> PrivateSmartWalletPaymasterRoots {
        let config_root = self.config.config_root();
        let stealth_account_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-STEALTH-ACCOUNT",
            self.stealth_accounts
                .values()
                .map(|account| (account.wallet_id.clone(), account.public_record()))
                .collect(),
        );
        let pq_session_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-PQ-SESSION",
            self.pq_sessions
                .values()
                .map(|session| (session.session_id.clone(), session.public_record()))
                .collect(),
        );
        let sponsor_rule_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-SPONSOR-RULE",
            self.sponsor_rules
                .values()
                .map(|rule| (rule.rule_id.clone(), rule.public_record()))
                .collect(),
        );
        let contract_budget_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-CONTRACT-BUDGET",
            self.contract_budgets
                .values()
                .map(|budget| (budget.budget_id.clone(), budget.public_record()))
                .collect(),
        );
        let recovery_plan_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-RECOVERY-PLAN",
            self.recovery_plans
                .values()
                .map(|plan| (plan.recovery_id.clone(), plan.public_record()))
                .collect(),
        );
        let fee_receipt_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-FEE-RECEIPT",
            self.fee_receipts
                .values()
                .map(|receipt| (receipt.receipt_id.clone(), receipt.public_record()))
                .collect(),
        );
        let spent_nullifier_root = merkle_root(
            "PRIVATE-SMART-WALLET-SPENT-NULLIFIER",
            &self
                .spent_nullifiers
                .iter()
                .map(|nullifier| json!({"nullifier": nullifier}))
                .collect::<Vec<_>>(),
        );
        let public_record_root = keyed_record_root(
            "PRIVATE-SMART-WALLET-PUBLIC-RECORD",
            self.public_records
                .iter()
                .map(|(record_id, record)| (record_id.clone(), record.clone()))
                .collect(),
        );
        let state_record = json!({
            "config_root": config_root,
            "stealth_account_root": stealth_account_root,
            "pq_session_root": pq_session_root,
            "sponsor_rule_root": sponsor_rule_root,
            "contract_budget_root": contract_budget_root,
            "recovery_plan_root": recovery_plan_root,
            "fee_receipt_root": fee_receipt_root,
            "spent_nullifier_root": spent_nullifier_root,
            "public_record_root": public_record_root,
            "height": self.height,
        });
        let state_root = private_smart_wallet_paymaster_state_root_from_record(&state_record);
        PrivateSmartWalletPaymasterRoots {
            config_root,
            stealth_account_root,
            pq_session_root,
            sponsor_rule_root,
            contract_budget_root,
            recovery_plan_root,
            fee_receipt_root,
            spent_nullifier_root,
            public_record_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(map) = &mut record {
            map.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "private_smart_wallet_paymaster_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "stealth_accounts": self.stealth_accounts.values().map(StealthAccountPolicy::public_record).collect::<Vec<_>>(),
            "pq_sessions": self.pq_sessions.values().map(PqSessionAuthorization::public_record).collect::<Vec<_>>(),
            "sponsor_rules": self.sponsor_rules.values().map(LowFeeSponsorRule::public_record).collect::<Vec<_>>(),
            "contract_budgets": self.contract_budgets.values().map(PrivateContractCallBudget::public_record).collect::<Vec<_>>(),
            "recovery_plans": self.recovery_plans.values().map(WalletRecoveryPlan::public_record).collect::<Vec<_>>(),
            "fee_receipts": self.fee_receipts.values().map(PrivateFeeReceipt::public_record).collect::<Vec<_>>(),
            "spent_nullifier_count": self.spent_nullifiers.len() as u64,
            "public_records": self.public_records.values().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn validate(&self) -> PrivateSmartWalletPaymasterResult<()> {
        self.config.validate()?;
        self.validate_counts()?;
        self.validate_stealth_accounts()?;
        self.validate_pq_sessions()?;
        self.validate_sponsor_rules()?;
        self.validate_contract_budgets()?;
        self.validate_recovery_plans()?;
        self.validate_fee_receipts()?;
        Ok(())
    }

    fn epoch_at(&self, height: u64) -> u64 {
        if self.config.default_budget_window_blocks == 0 {
            0
        } else {
            height / self.config.default_budget_window_blocks
        }
    }

    fn validate_counts(&self) -> PrivateSmartWalletPaymasterResult<()> {
        if self.stealth_accounts.len() > self.config.max_wallets {
            return Err("too many private smart wallets".to_string());
        }
        if self.pq_sessions.len() > self.config.max_sessions {
            return Err("too many PQ session authorizations".to_string());
        }
        if self.sponsor_rules.len() > self.config.max_sponsor_rules {
            return Err("too many low fee sponsor rules".to_string());
        }
        if self.contract_budgets.len() > self.config.max_contract_budgets {
            return Err("too many private contract budgets".to_string());
        }
        if self.recovery_plans.len() > self.config.max_recovery_plans {
            return Err("too many wallet recovery plans".to_string());
        }
        if self.fee_receipts.len() > self.config.max_fee_receipts {
            return Err("too many private fee receipts".to_string());
        }
        Ok(())
    }

    fn validate_stealth_accounts(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (wallet_id, account) in &self.stealth_accounts {
            account.validate()?;
            if wallet_id != &account.wallet_id {
                return Err("stealth wallet map key does not match wallet id".to_string());
            }
            if account.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("stealth wallet privacy floor below config minimum".to_string());
            }
            if account.min_pq_security_bits < self.config.min_pq_security_bits {
                return Err("stealth wallet PQ security below config minimum".to_string());
            }
        }
        Ok(())
    }

    fn validate_pq_sessions(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (session_id, session) in &self.pq_sessions {
            session.validate()?;
            if session_id != &session.session_id {
                return Err("PQ session map key does not match session id".to_string());
            }
            if !self.stealth_accounts.contains_key(&session.wallet_id) {
                return Err("PQ session references missing stealth wallet".to_string());
            }
            if session.min_pq_security_bits < self.config.min_pq_security_bits {
                return Err("PQ session security below config minimum".to_string());
            }
        }
        Ok(())
    }

    fn validate_sponsor_rules(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (rule_id, rule) in &self.sponsor_rules {
            rule.validate()?;
            if rule_id != &rule.rule_id {
                return Err("sponsor rule map key does not match rule id".to_string());
            }
            match self.stealth_accounts.get(&rule.wallet_id) {
                Some(wallet) if wallet.allow_sponsored_fees => {}
                Some(_) => {
                    return Err(
                        "sponsor rule references wallet that disallows sponsored fees".to_string(),
                    )
                }
                None => return Err("sponsor rule references missing stealth wallet".to_string()),
            }
            if rule.min_privacy_set_size < self.config.min_privacy_set_size {
                return Err("sponsor rule privacy floor below config minimum".to_string());
            }
        }
        Ok(())
    }

    fn validate_contract_budgets(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (budget_id, budget) in &self.contract_budgets {
            budget.validate()?;
            if budget_id != &budget.budget_id {
                return Err("contract budget map key does not match budget id".to_string());
            }
            let wallet = self
                .stealth_accounts
                .get(&budget.wallet_id)
                .ok_or_else(|| "contract budget references missing stealth wallet".to_string())?;
            if !wallet.allow_contract_calls {
                return Err(
                    "contract budget references wallet that disallows contract calls".to_string(),
                );
            }
            let session = self
                .pq_sessions
                .get(&budget.session_id)
                .ok_or_else(|| "contract budget references missing PQ session".to_string())?;
            if session.wallet_id != budget.wallet_id {
                return Err("contract budget session belongs to a different wallet".to_string());
            }
            if budget.operation.is_defi() && !wallet.allow_defi {
                return Err("DeFi budget references wallet without DeFi enabled".to_string());
            }
        }
        Ok(())
    }

    fn validate_recovery_plans(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (recovery_id, recovery) in &self.recovery_plans {
            recovery.validate()?;
            if recovery_id != &recovery.recovery_id {
                return Err("recovery plan map key does not match recovery id".to_string());
            }
            let wallet = self
                .stealth_accounts
                .get(&recovery.wallet_id)
                .ok_or_else(|| "recovery plan references missing stealth wallet".to_string())?;
            if recovery.threshold_weight < wallet.recovery_threshold {
                return Err("recovery plan threshold below wallet threshold".to_string());
            }
        }
        Ok(())
    }

    fn validate_fee_receipts(&self) -> PrivateSmartWalletPaymasterResult<()> {
        for (receipt_id, receipt) in &self.fee_receipts {
            receipt.validate()?;
            if receipt_id != &receipt.receipt_id {
                return Err("fee receipt map key does not match receipt id".to_string());
            }
            if !self.stealth_accounts.contains_key(&receipt.wallet_id) {
                return Err("fee receipt references missing stealth wallet".to_string());
            }
            match self.pq_sessions.get(&receipt.session_id) {
                Some(session) if session.wallet_id == receipt.wallet_id => {}
                Some(_) => {
                    return Err("fee receipt session belongs to a different wallet".to_string())
                }
                None => return Err("fee receipt references missing PQ session".to_string()),
            }
            match self.sponsor_rules.get(&receipt.sponsor_rule_id) {
                Some(rule)
                    if rule.wallet_id == receipt.wallet_id
                        && rule.fee_asset_id == receipt.fee_asset_id => {}
                Some(_) => return Err("fee receipt sponsor rule is incompatible".to_string()),
                None => return Err("fee receipt references missing sponsor rule".to_string()),
            }
        }
        Ok(())
    }
}

pub fn private_smart_wallet_id(
    owner_commitment: &str,
    stealth_address_root: &str,
    view_tag_root: &str,
    account_mode: PrivateSmartWalletMode,
    created_at_height: u64,
) -> String {
    pswp_hash(
        "WALLET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_commitment),
            HashPart::Str(stealth_address_root),
            HashPart::Str(view_tag_root),
            HashPart::Str(account_mode.as_str()),
            HashPart::Int(created_at_height as i128),
        ],
        24,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn pq_session_authorization_id(
    wallet_id: &str,
    authorization_kind: PqAuthorizationKind,
    public_key_commitment: &str,
    kem_ciphertext_hash: &str,
    scope_root: &str,
    contract_root: &str,
    asset_root: &str,
    opened_at_height: u64,
    expires_at_height: u64,
) -> String {
    pswp_hash(
        "PQ-SESSION-AUTHORIZATION-ID",
        &[
            HashPart::Str(wallet_id),
            HashPart::Str(authorization_kind.as_str()),
            HashPart::Str(public_key_commitment),
            HashPart::Str(kem_ciphertext_hash),
            HashPart::Str(scope_root),
            HashPart::Str(contract_root),
            HashPart::Str(asset_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        24,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn low_fee_sponsor_rule_id(
    wallet_id: &str,
    sponsor_pool_id: &str,
    fee_asset_id: &str,
    mode: SponsorRuleMode,
    max_fee_units_per_call: u64,
    max_fee_units_per_epoch: u64,
    relayer_policy_root: &str,
    active_from_height: u64,
    expires_at_height: u64,
) -> String {
    pswp_hash(
        "LOW-FEE-SPONSOR-RULE-ID",
        &[
            HashPart::Str(wallet_id),
            HashPart::Str(sponsor_pool_id),
            HashPart::Str(fee_asset_id),
            HashPart::Str(mode.as_str()),
            HashPart::Int(max_fee_units_per_call as i128),
            HashPart::Int(max_fee_units_per_epoch as i128),
            HashPart::Str(relayer_policy_root),
            HashPart::Int(active_from_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        24,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_contract_call_budget_id(
    wallet_id: &str,
    session_id: &str,
    contract_commitment: &str,
    selector_root: &str,
    operation: PrivateWalletOperation,
    window: ContractBudgetWindow,
    max_call_units: u64,
    max_fee_units: u64,
    window_start_height: u64,
    reset_interval_blocks: u64,
    privacy_proof_root: &str,
) -> String {
    pswp_hash(
        "CONTRACT-CALL-BUDGET-ID",
        &[
            HashPart::Str(wallet_id),
            HashPart::Str(session_id),
            HashPart::Str(contract_commitment),
            HashPart::Str(selector_root),
            HashPart::Str(operation.as_str()),
            HashPart::Str(window.as_str()),
            HashPart::Int(max_call_units as i128),
            HashPart::Int(max_fee_units as i128),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(reset_interval_blocks as i128),
            HashPart::Str(privacy_proof_root),
        ],
        24,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn wallet_recovery_plan_id(
    wallet_id: &str,
    guardian_root: &str,
    replacement_owner_commitment: &str,
    replacement_stealth_address_root: &str,
    threshold_weight: u16,
    delay_blocks: u64,
    requested_at_height: u64,
    expires_at_height: u64,
    recovery_proof_root: &str,
) -> String {
    pswp_hash(
        "WALLET-RECOVERY-PLAN-ID",
        &[
            HashPart::Str(wallet_id),
            HashPart::Str(guardian_root),
            HashPart::Str(replacement_owner_commitment),
            HashPart::Str(replacement_stealth_address_root),
            HashPart::Int(threshold_weight as i128),
            HashPart::Int(delay_blocks as i128),
            HashPart::Int(requested_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(recovery_proof_root),
        ],
        24,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_fee_receipt_id(
    wallet_id: &str,
    session_id: &str,
    sponsor_rule_id: &str,
    operation: PrivateWalletOperation,
    fee_asset_id: &str,
    sponsored_fee_units: u64,
    relayer_tip_units: u64,
    private_call_root: &str,
    fee_commitment_root: &str,
    pq_attestation_root: &str,
    created_at_height: u64,
) -> String {
    pswp_hash(
        "PRIVATE-FEE-RECEIPT-ID",
        &[
            HashPart::Str(wallet_id),
            HashPart::Str(session_id),
            HashPart::Str(sponsor_rule_id),
            HashPart::Str(operation.as_str()),
            HashPart::Str(fee_asset_id),
            HashPart::Int(sponsored_fee_units as i128),
            HashPart::Int(relayer_tip_units as i128),
            HashPart::Str(private_call_root),
            HashPart::Str(fee_commitment_root),
            HashPart::Str(pq_attestation_root),
            HashPart::Int(created_at_height as i128),
        ],
        24,
    )
}

pub fn private_wallet_string_set_root(domain: &str, values: &[String]) -> String {
    let mut ordered = values.iter().cloned().collect::<Vec<_>>();
    ordered.sort();
    ordered.dedup();
    merkle_root(
        domain,
        &ordered
            .iter()
            .map(|value| json!({ "value": value }))
            .collect::<Vec<_>>(),
    )
}

pub fn private_smart_wallet_paymaster_state_root_from_record(record: &Value) -> String {
    pswp_hash(
        "STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PRIVATE_SMART_WALLET_PAYMASTER_PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

fn keyed_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn insert_unique_record<T>(
    records: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    field: &str,
) -> PrivateSmartWalletPaymasterResult<()> {
    ensure_non_empty(&key, field)?;
    if records.contains_key(&key) {
        return Err(format!("{field} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, field: &str) -> PrivateSmartWalletPaymasterResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> PrivateSmartWalletPaymasterResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn pswp_hash(domain: &str, parts: &[HashPart<'_>], out_len: usize) -> String {
    domain_hash(
        &format!("PRIVATE-SMART-WALLET-PAYMASTER-{domain}"),
        parts,
        out_len,
    )
}
