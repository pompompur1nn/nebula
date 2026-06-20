use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WalletPolicyResult<T> = Result<T, String>;

pub const WALLET_POLICY_PROTOCOL_VERSION: &str = "nebula-wallet-policy-v1";
pub const WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS: u64 = 120;
pub const WALLET_POLICY_DEFAULT_WATCH_REORG_DEPTH: u64 = 32;
pub const WALLET_POLICY_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 720;
pub const WALLET_POLICY_DEFAULT_AMOUNT_BUCKET: u64 = 1_000;
pub const WALLET_POLICY_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPolicyStatus {
    Active,
    Pending,
    Approved,
    Signed,
    Used,
    Paused,
    Revoked,
    Expired,
}

impl WalletPolicyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Signed => "signed",
            Self::Used => "used",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionScopeKind {
    AccountSpend,
    OfflineSpend,
    WatchOnlySync,
    PaymasterSponsored,
    PrivateDefi,
    BridgeWithdrawal,
    Recovery,
}

impl SessionScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccountSpend => "account_spend",
            Self::OfflineSpend => "offline_spend",
            Self::WatchOnlySync => "watch_only_sync",
            Self::PaymasterSponsored => "paymaster_sponsored",
            Self::PrivateDefi => "private_defi",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendingLimitWindow {
    Transaction,
    Session,
    Block,
    Epoch,
    Day,
}

impl SpendingLimitWindow {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::Session => "session",
            Self::Block => "block",
            Self::Epoch => "epoch",
            Self::Day => "day",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineBundleKind {
    Transfer,
    ContractCall,
    PaymasterSponsoredCall,
    PrivateDefiIntent,
    BridgeWithdrawal,
    RecoveryRotation,
}

impl OfflineBundleKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::PaymasterSponsoredCall => "paymaster_sponsored_call",
            Self::PrivateDefiIntent => "private_defi_intent",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::RecoveryRotation => "recovery_rotation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchOnlySyncMode {
    LocalIndex,
    ViewKeyDelegate,
    RemoteObserver,
    AirgappedExport,
}

impl WatchOnlySyncMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalIndex => "local_index",
            Self::ViewKeyDelegate => "view_key_delegate",
            Self::RemoteObserver => "remote_observer",
            Self::AirgappedExport => "airgapped_export",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryGuardianRole {
    EmergencyFreeze,
    SocialRecovery,
    KeyRotation,
    EstateRecovery,
    ComplianceBreakGlass,
}

impl RecoveryGuardianRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmergencyFreeze => "emergency_freeze",
            Self::SocialRecovery => "social_recovery",
            Self::KeyRotation => "key_rotation",
            Self::EstateRecovery => "estate_recovery",
            Self::ComplianceBreakGlass => "compliance_break_glass",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymasterPreferenceMode {
    Disabled,
    PreferPrivateSponsor,
    RequirePrivateSponsor,
    AllowFallbackSelfPay,
}

impl PaymasterPreferenceMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::PreferPrivateSponsor => "prefer_private_sponsor",
            Self::RequirePrivateSponsor => "require_private_sponsor",
            Self::AllowFallbackSelfPay => "allow_fallback_self_pay",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateDefiIntentKind {
    AmmSwap,
    AmmRouteSwap,
    DarkPoolSwap,
    LendingBorrow,
    LendingRepay,
    LendingLiquidation,
    LiquidityAdd,
    LiquidityRemove,
}

impl PrivateDefiIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AmmSwap => "amm_swap",
            Self::AmmRouteSwap => "amm_route_swap",
            Self::DarkPoolSwap => "dark_pool_swap",
            Self::LendingBorrow => "lending_borrow",
            Self::LendingRepay => "lending_repay",
            Self::LendingLiquidation => "lending_liquidation",
            Self::LiquidityAdd => "liquidity_add",
            Self::LiquidityRemove => "liquidity_remove",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeWithdrawalApprovalKind {
    Standard,
    Expedited,
    DelayedRelease,
    MarketMakerFilled,
    GuardianOverride,
}

impl BridgeWithdrawalApprovalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Expedited => "expedited",
            Self::DelayedRelease => "delayed_release",
            Self::MarketMakerFilled => "market_maker_filled",
            Self::GuardianOverride => "guardian_override",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareKeyKind {
    SoftwareDevnet,
    HardwareWallet,
    SecureEnclave,
    AirgappedSigner,
    MultisigShard,
    RecoveryKey,
}

impl HardwareKeyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SoftwareDevnet => "software_devnet",
            Self::HardwareWallet => "hardware_wallet",
            Self::SecureEnclave => "secure_enclave",
            Self::AirgappedSigner => "airgapped_signer",
            Self::MultisigShard => "multisig_shard",
            Self::RecoveryKey => "recovery_key",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareKeyProvenanceCommitment {
    pub provenance_id: String,
    pub account_commitment: String,
    pub key_label_commitment: String,
    pub key_kind: HardwareKeyKind,
    pub vendor_commitment: String,
    pub model_commitment: String,
    pub firmware_root: String,
    pub attestation_root: String,
    pub secure_element_root: String,
    pub created_at_height: u64,
    pub status: WalletPolicyStatus,
}

impl HardwareKeyProvenanceCommitment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        key_label: &str,
        key_kind: HardwareKeyKind,
        vendor: &str,
        model: &str,
        firmware_manifest: &Value,
        attestation: &Value,
        secure_element: &Value,
        created_at_height: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(key_label, "wallet policy key label")?;
        ensure_non_empty(vendor, "wallet policy key vendor")?;
        ensure_non_empty(model, "wallet policy key model")?;
        let account_commitment = wallet_policy_account_commitment(account_label);
        let key_label_commitment = wallet_policy_label_commitment(account_label, key_label);
        let vendor_commitment = wallet_policy_string_root("WALLET-POLICY-KEY-VENDOR", vendor);
        let model_commitment = wallet_policy_string_root("WALLET-POLICY-KEY-MODEL", model);
        let firmware_root =
            wallet_policy_payload_root("WALLET-POLICY-KEY-FIRMWARE", firmware_manifest);
        let attestation_root =
            wallet_policy_payload_root("WALLET-POLICY-KEY-ATTESTATION", attestation);
        let secure_element_root =
            wallet_policy_payload_root("WALLET-POLICY-SECURE-ELEMENT", secure_element);
        let provenance_id = hardware_key_provenance_id(
            &account_commitment,
            &key_label_commitment,
            &key_kind,
            &vendor_commitment,
            &model_commitment,
            &firmware_root,
            &attestation_root,
            &secure_element_root,
        );
        Ok(Self {
            provenance_id,
            account_commitment,
            key_label_commitment,
            key_kind,
            vendor_commitment,
            model_commitment,
            firmware_root,
            attestation_root,
            secure_element_root,
            created_at_height,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(
            &self.key_label_commitment,
            "wallet policy key label commitment",
        )?;
        ensure_non_empty(&self.firmware_root, "wallet policy firmware root")?;
        ensure_non_empty(&self.attestation_root, "wallet policy attestation root")?;
        if self.provenance_id
            != hardware_key_provenance_id(
                &self.account_commitment,
                &self.key_label_commitment,
                &self.key_kind,
                &self.vendor_commitment,
                &self.model_commitment,
                &self.firmware_root,
                &self.attestation_root,
                &self.secure_element_root,
            )
        {
            return Err("wallet policy key provenance id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_key_provenance",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "provenance_id": self.provenance_id,
            "account_commitment": self.account_commitment,
            "key_label_commitment": self.key_label_commitment,
            "key_kind": self.key_kind.as_str(),
            "vendor_commitment": self.vendor_commitment,
            "model_commitment": self.model_commitment,
            "firmware_root": self.firmware_root,
            "attestation_root": self.attestation_root,
            "secure_element_root": self.secure_element_root,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendingLimit {
    pub limit_id: String,
    pub account_commitment: String,
    pub limit_label_commitment: String,
    pub asset_id: String,
    pub window: SpendingLimitWindow,
    pub max_amount: u64,
    pub spent_amount: u64,
    pub reset_interval_blocks: u64,
    pub window_start_height: u64,
    pub scope_root: String,
    pub paymaster_fee_cap: u64,
    pub status: WalletPolicyStatus,
}

impl SpendingLimit {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        limit_label: &str,
        asset_id: &str,
        window: SpendingLimitWindow,
        max_amount: u64,
        reset_interval_blocks: u64,
        window_start_height: u64,
        allowed_scope_ids: Vec<String>,
        paymaster_fee_cap: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(limit_label, "wallet policy spending limit label")?;
        ensure_non_empty(asset_id, "wallet policy spending limit asset")?;
        ensure_positive(max_amount, "wallet policy spending limit amount")?;
        if !allowed_scope_ids.is_empty() {
            ensure_unique_strings(&allowed_scope_ids, "wallet policy spending limit scopes")?;
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let limit_label_commitment = wallet_policy_label_commitment(account_label, limit_label);
        let scope_root = wallet_policy_string_set_root(
            "WALLET-POLICY-SPENDING-LIMIT-SCOPES",
            &allowed_scope_ids,
        );
        let limit_id = spending_limit_id(
            &account_commitment,
            &limit_label_commitment,
            asset_id,
            &window,
            max_amount,
            reset_interval_blocks,
            window_start_height,
            &scope_root,
        );
        Ok(Self {
            limit_id,
            account_commitment,
            limit_label_commitment,
            asset_id: asset_id.to_string(),
            window,
            max_amount,
            spent_amount: 0,
            reset_interval_blocks,
            window_start_height,
            scope_root,
            paymaster_fee_cap,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn remaining_amount(&self) -> u64 {
        self.max_amount.saturating_sub(self.spent_amount)
    }

    pub fn amount_bucket(&self) -> u64 {
        wallet_policy_amount_bucket(self.max_amount)
    }

    pub fn can_spend(&self, amount: u64) -> bool {
        self.status == WalletPolicyStatus::Active && amount > 0 && amount <= self.remaining_amount()
    }

    pub fn record_spend(&mut self, amount: u64) -> WalletPolicyResult<()> {
        if !self.can_spend(amount) {
            return Err("wallet policy spending limit exceeded".to_string());
        }
        self.spent_amount = self
            .spent_amount
            .checked_add(amount)
            .ok_or_else(|| "wallet policy spending limit overflow".to_string())?;
        Ok(())
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
            self.spent_amount = 0;
            self.window_start_height = height;
        }
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(&self.asset_id, "wallet policy spending limit asset")?;
        ensure_positive(self.max_amount, "wallet policy spending limit amount")?;
        if self.spent_amount > self.max_amount {
            return Err("wallet policy spending limit spent amount exceeds cap".to_string());
        }
        if self.limit_id
            != spending_limit_id(
                &self.account_commitment,
                &self.limit_label_commitment,
                &self.asset_id,
                &self.window,
                self.max_amount,
                self.reset_interval_blocks,
                self.window_start_height,
                &self.scope_root,
            )
        {
            return Err("wallet policy spending limit id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_spending_limit",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "limit_id": self.limit_id,
            "account_commitment": self.account_commitment,
            "limit_label_commitment": self.limit_label_commitment,
            "asset_id": self.asset_id,
            "window": self.window.as_str(),
            "max_amount_bucket": self.amount_bucket(),
            "spent_amount_bucket": wallet_policy_amount_bucket(self.spent_amount),
            "remaining_amount_bucket": wallet_policy_amount_bucket(self.remaining_amount()),
            "reset_interval_blocks": self.reset_interval_blocks,
            "window_start_height": self.window_start_height,
            "scope_root": self.scope_root,
            "paymaster_fee_cap": self.paymaster_fee_cap,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterPreference {
    pub preference_id: String,
    pub account_commitment: String,
    pub mode: PaymasterPreferenceMode,
    pub preferred_paymaster_ids: Vec<String>,
    pub allowed_fee_asset_ids: Vec<String>,
    pub max_fee_units_per_call: u64,
    pub max_fee_units_per_session: u64,
    pub require_private_relay: bool,
    pub allow_fallback_self_pay: bool,
    pub relayer_policy_root: String,
    pub status: WalletPolicyStatus,
}

impl PaymasterPreference {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        mode: PaymasterPreferenceMode,
        preferred_paymaster_ids: Vec<String>,
        allowed_fee_asset_ids: Vec<String>,
        max_fee_units_per_call: u64,
        max_fee_units_per_session: u64,
        require_private_relay: bool,
        allow_fallback_self_pay: bool,
        relayer_policy: &Value,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        if mode != PaymasterPreferenceMode::Disabled {
            ensure_unique_strings(
                &preferred_paymaster_ids,
                "wallet policy preferred paymasters",
            )?;
            ensure_unique_strings(&allowed_fee_asset_ids, "wallet policy fee assets")?;
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let mut preferred_paymaster_ids = preferred_paymaster_ids;
        preferred_paymaster_ids.sort();
        preferred_paymaster_ids.dedup();
        let mut allowed_fee_asset_ids = allowed_fee_asset_ids;
        allowed_fee_asset_ids.sort();
        allowed_fee_asset_ids.dedup();
        let relayer_policy_root =
            wallet_policy_payload_root("WALLET-POLICY-PAYMASTER-RELAYER", relayer_policy);
        let preference_id = paymaster_preference_id(
            &account_commitment,
            &mode,
            &preferred_paymaster_ids,
            &allowed_fee_asset_ids,
            max_fee_units_per_call,
            max_fee_units_per_session,
            require_private_relay,
            allow_fallback_self_pay,
            &relayer_policy_root,
        );
        Ok(Self {
            preference_id,
            account_commitment,
            mode,
            preferred_paymaster_ids,
            allowed_fee_asset_ids,
            max_fee_units_per_call,
            max_fee_units_per_session,
            require_private_relay,
            allow_fallback_self_pay,
            relayer_policy_root,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        if self.mode != PaymasterPreferenceMode::Disabled {
            ensure_unique_strings(
                &self.preferred_paymaster_ids,
                "wallet policy preferred paymasters",
            )?;
            ensure_unique_strings(&self.allowed_fee_asset_ids, "wallet policy fee assets")?;
        }
        if self.preference_id
            != paymaster_preference_id(
                &self.account_commitment,
                &self.mode,
                &self.preferred_paymaster_ids,
                &self.allowed_fee_asset_ids,
                self.max_fee_units_per_call,
                self.max_fee_units_per_session,
                self.require_private_relay,
                self.allow_fallback_self_pay,
                &self.relayer_policy_root,
            )
        {
            return Err("wallet policy paymaster preference id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_paymaster_preference",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "preference_id": self.preference_id,
            "account_commitment": self.account_commitment,
            "mode": self.mode.as_str(),
            "preferred_paymaster_root": wallet_policy_string_set_root("WALLET-POLICY-PREFERRED-PAYMASTERS", &self.preferred_paymaster_ids),
            "allowed_fee_asset_root": wallet_policy_string_set_root("WALLET-POLICY-ALLOWED-FEE-ASSETS", &self.allowed_fee_asset_ids),
            "max_fee_units_per_call": self.max_fee_units_per_call,
            "max_fee_units_per_session": self.max_fee_units_per_session,
            "require_private_relay": self.require_private_relay,
            "allow_fallback_self_pay": self.allow_fallback_self_pay,
            "relayer_policy_root": self.relayer_policy_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionScope {
    pub scope_id: String,
    pub account_commitment: String,
    pub delegate_commitment: String,
    pub scope_kind: SessionScopeKind,
    pub policy_id: String,
    pub allowed_action_root: String,
    pub allowed_asset_root: String,
    pub allowed_contract_root: String,
    pub spending_limit_ids: Vec<String>,
    pub max_call_count: u64,
    pub calls_used: u64,
    pub max_fee_units: u64,
    pub fee_units_used: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub offline_bundle_required: bool,
    pub watch_only: bool,
    pub hardware_provenance_id: String,
    pub status: WalletPolicyStatus,
}

impl SessionScope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        delegate_label: &str,
        scope_kind: SessionScopeKind,
        policy_id: &str,
        allowed_actions: Vec<String>,
        allowed_assets: Vec<String>,
        allowed_contracts: Vec<String>,
        spending_limit_ids: Vec<String>,
        max_call_count: u64,
        max_fee_units: u64,
        starts_at_height: u64,
        expires_at_height: u64,
        offline_bundle_required: bool,
        watch_only: bool,
        hardware_provenance_id: &str,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(delegate_label, "wallet policy session delegate")?;
        ensure_unique_strings(&allowed_actions, "wallet policy session actions")?;
        ensure_unique_strings(&spending_limit_ids, "wallet policy session spending limits")?;
        if expires_at_height <= starts_at_height {
            return Err("wallet policy session expiry must be after start".to_string());
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let delegate_commitment = wallet_policy_delegate_commitment(delegate_label);
        let allowed_action_root =
            wallet_policy_string_set_root("WALLET-POLICY-SESSION-ACTIONS", &allowed_actions);
        let allowed_asset_root =
            wallet_policy_string_set_root("WALLET-POLICY-SESSION-ASSETS", &allowed_assets);
        let allowed_contract_root =
            wallet_policy_string_set_root("WALLET-POLICY-SESSION-CONTRACTS", &allowed_contracts);
        let spending_limit_root =
            wallet_policy_string_set_root("WALLET-POLICY-SESSION-LIMITS", &spending_limit_ids);
        let scope_id = session_scope_id(
            &account_commitment,
            &delegate_commitment,
            &scope_kind,
            policy_id,
            &allowed_action_root,
            &allowed_asset_root,
            &allowed_contract_root,
            &spending_limit_root,
            starts_at_height,
            expires_at_height,
        );
        Ok(Self {
            scope_id,
            account_commitment,
            delegate_commitment,
            scope_kind,
            policy_id: policy_id.to_string(),
            allowed_action_root,
            allowed_asset_root,
            allowed_contract_root,
            spending_limit_ids,
            max_call_count,
            calls_used: 0,
            max_fee_units,
            fee_units_used: 0,
            starts_at_height,
            expires_at_height,
            offline_bundle_required,
            watch_only,
            hardware_provenance_id: hardware_provenance_id.to_string(),
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == WalletPolicyStatus::Active
            && self.starts_at_height <= height
            && height < self.expires_at_height
    }

    pub fn remaining_calls(&self) -> u64 {
        self.max_call_count.saturating_sub(self.calls_used)
    }

    pub fn remaining_fee_units(&self) -> u64 {
        self.max_fee_units.saturating_sub(self.fee_units_used)
    }

    pub fn consume_call(&mut self, fee_units: u64, height: u64) -> WalletPolicyResult<()> {
        if !self.is_active_at(height) {
            return Err("wallet policy session scope is not active".to_string());
        }
        if self.max_call_count > 0 && self.remaining_calls() == 0 {
            return Err("wallet policy session call count exceeded".to_string());
        }
        if self.max_fee_units > 0 && fee_units > self.remaining_fee_units() {
            return Err("wallet policy session fee cap exceeded".to_string());
        }
        self.calls_used = self
            .calls_used
            .checked_add(1)
            .ok_or_else(|| "wallet policy session call count overflow".to_string())?;
        self.fee_units_used = self
            .fee_units_used
            .checked_add(fee_units)
            .ok_or_else(|| "wallet policy session fee overflow".to_string())?;
        Ok(())
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(&self.delegate_commitment, "wallet policy session delegate")?;
        ensure_unique_strings(
            &self.spending_limit_ids,
            "wallet policy session spending limits",
        )?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("wallet policy session expiry must be after start".to_string());
        }
        if self.max_call_count > 0 && self.calls_used > self.max_call_count {
            return Err("wallet policy session calls exceed cap".to_string());
        }
        if self.max_fee_units > 0 && self.fee_units_used > self.max_fee_units {
            return Err("wallet policy session fees exceed cap".to_string());
        }
        let spending_limit_root =
            wallet_policy_string_set_root("WALLET-POLICY-SESSION-LIMITS", &self.spending_limit_ids);
        if self.scope_id
            != session_scope_id(
                &self.account_commitment,
                &self.delegate_commitment,
                &self.scope_kind,
                &self.policy_id,
                &self.allowed_action_root,
                &self.allowed_asset_root,
                &self.allowed_contract_root,
                &spending_limit_root,
                self.starts_at_height,
                self.expires_at_height,
            )
        {
            return Err("wallet policy session scope id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_session_scope",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "scope_id": self.scope_id,
            "account_commitment": self.account_commitment,
            "delegate_commitment": self.delegate_commitment,
            "scope_kind": self.scope_kind.as_str(),
            "policy_id": self.policy_id,
            "allowed_action_root": self.allowed_action_root,
            "allowed_asset_root": self.allowed_asset_root,
            "allowed_contract_root": self.allowed_contract_root,
            "spending_limit_root": wallet_policy_string_set_root("WALLET-POLICY-SESSION-LIMITS", &self.spending_limit_ids),
            "spending_limit_count": self.spending_limit_ids.len() as u64,
            "max_call_count": self.max_call_count,
            "calls_used": self.calls_used,
            "max_fee_units": self.max_fee_units,
            "fee_units_used": self.fee_units_used,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "offline_bundle_required": self.offline_bundle_required,
            "watch_only": self.watch_only,
            "hardware_provenance_id": self.hardware_provenance_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchOnlySyncPolicy {
    pub sync_policy_id: String,
    pub account_commitment: String,
    pub watcher_commitment: String,
    pub view_key_commitment: String,
    pub mode: WatchOnlySyncMode,
    pub scan_from_height: u64,
    pub max_reorg_depth: u64,
    pub privacy_filter_root: String,
    pub endpoint_root: String,
    pub allow_mempool_scan: bool,
    pub allow_contract_receipts: bool,
    pub allow_bridge_events: bool,
    pub allow_paymaster_events: bool,
    pub reveal_amount_buckets: bool,
    pub export_note_ids: bool,
    pub status: WalletPolicyStatus,
}

impl WatchOnlySyncPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        watcher_label: &str,
        view_key_label: &str,
        mode: WatchOnlySyncMode,
        scan_from_height: u64,
        max_reorg_depth: u64,
        privacy_filters: &Value,
        endpoints: &Value,
        allow_mempool_scan: bool,
        allow_contract_receipts: bool,
        allow_bridge_events: bool,
        allow_paymaster_events: bool,
        reveal_amount_buckets: bool,
        export_note_ids: bool,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(watcher_label, "wallet policy watcher label")?;
        ensure_non_empty(view_key_label, "wallet policy view key label")?;
        let account_commitment = wallet_policy_account_commitment(account_label);
        let watcher_commitment = wallet_policy_delegate_commitment(watcher_label);
        let view_key_commitment = wallet_policy_view_key_commitment(account_label, view_key_label);
        let privacy_filter_root =
            wallet_policy_payload_root("WALLET-POLICY-WATCH-FILTERS", privacy_filters);
        let endpoint_root = wallet_policy_payload_root("WALLET-POLICY-WATCH-ENDPOINTS", endpoints);
        let sync_policy_id = watch_only_sync_policy_id(
            &account_commitment,
            &watcher_commitment,
            &view_key_commitment,
            &mode,
            scan_from_height,
            max_reorg_depth,
            &privacy_filter_root,
            &endpoint_root,
        );
        Ok(Self {
            sync_policy_id,
            account_commitment,
            watcher_commitment,
            view_key_commitment,
            mode,
            scan_from_height,
            max_reorg_depth,
            privacy_filter_root,
            endpoint_root,
            allow_mempool_scan,
            allow_contract_receipts,
            allow_bridge_events,
            allow_paymaster_events,
            reveal_amount_buckets,
            export_note_ids,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(&self.watcher_commitment, "wallet policy watcher commitment")?;
        ensure_non_empty(
            &self.view_key_commitment,
            "wallet policy view key commitment",
        )?;
        if self.sync_policy_id
            != watch_only_sync_policy_id(
                &self.account_commitment,
                &self.watcher_commitment,
                &self.view_key_commitment,
                &self.mode,
                self.scan_from_height,
                self.max_reorg_depth,
                &self.privacy_filter_root,
                &self.endpoint_root,
            )
        {
            return Err("wallet policy watch-only sync id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_watch_only_sync",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "sync_policy_id": self.sync_policy_id,
            "account_commitment": self.account_commitment,
            "watcher_commitment": self.watcher_commitment,
            "view_key_commitment": self.view_key_commitment,
            "mode": self.mode.as_str(),
            "scan_from_height": self.scan_from_height,
            "max_reorg_depth": self.max_reorg_depth,
            "privacy_filter_root": self.privacy_filter_root,
            "endpoint_root": self.endpoint_root,
            "allow_mempool_scan": self.allow_mempool_scan,
            "allow_contract_receipts": self.allow_contract_receipts,
            "allow_bridge_events": self.allow_bridge_events,
            "allow_paymaster_events": self.allow_paymaster_events,
            "reveal_amount_buckets": self.reveal_amount_buckets,
            "export_note_ids": self.export_note_ids,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryGuardian {
    pub guardian_id: String,
    pub account_commitment: String,
    pub guardian_commitment: String,
    pub guardian_role: RecoveryGuardianRole,
    pub recovery_key_commitment: String,
    pub hardware_provenance_id: String,
    pub quorum_weight: u64,
    pub active_from_height: u64,
    pub recovery_delay_blocks: u64,
    pub status: WalletPolicyStatus,
}

impl RecoveryGuardian {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        guardian_label: &str,
        guardian_role: RecoveryGuardianRole,
        recovery_key_label: &str,
        hardware_provenance_id: &str,
        quorum_weight: u64,
        active_from_height: u64,
        recovery_delay_blocks: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(guardian_label, "wallet policy guardian label")?;
        ensure_non_empty(recovery_key_label, "wallet policy recovery key label")?;
        ensure_positive(quorum_weight, "wallet policy guardian quorum weight")?;
        let account_commitment = wallet_policy_account_commitment(account_label);
        let guardian_commitment = wallet_policy_guardian_commitment(account_label, guardian_label);
        let recovery_key_commitment =
            wallet_policy_label_commitment(account_label, recovery_key_label);
        let guardian_id = recovery_guardian_id(
            &account_commitment,
            &guardian_commitment,
            &guardian_role,
            &recovery_key_commitment,
            hardware_provenance_id,
            active_from_height,
        );
        Ok(Self {
            guardian_id,
            account_commitment,
            guardian_commitment,
            guardian_role,
            recovery_key_commitment,
            hardware_provenance_id: hardware_provenance_id.to_string(),
            quorum_weight,
            active_from_height,
            recovery_delay_blocks,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(
            &self.guardian_commitment,
            "wallet policy guardian commitment",
        )?;
        ensure_positive(self.quorum_weight, "wallet policy guardian quorum weight")?;
        if self.guardian_id
            != recovery_guardian_id(
                &self.account_commitment,
                &self.guardian_commitment,
                &self.guardian_role,
                &self.recovery_key_commitment,
                &self.hardware_provenance_id,
                self.active_from_height,
            )
        {
            return Err("wallet policy recovery guardian id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_recovery_guardian",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "guardian_id": self.guardian_id,
            "account_commitment": self.account_commitment,
            "guardian_commitment": self.guardian_commitment,
            "guardian_role": self.guardian_role.as_str(),
            "recovery_key_commitment": self.recovery_key_commitment,
            "hardware_provenance_id": self.hardware_provenance_id,
            "quorum_weight": self.quorum_weight,
            "active_from_height": self.active_from_height,
            "recovery_delay_blocks": self.recovery_delay_blocks,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSpendPolicy {
    pub policy_id: String,
    pub account_commitment: String,
    pub policy_label_commitment: String,
    pub session_scope_root: String,
    pub spending_limit_root: String,
    pub guardian_root: String,
    pub paymaster_preference_root: String,
    pub key_provenance_root: String,
    pub default_session_ttl_blocks: u64,
    pub approval_threshold: u64,
    pub require_hardware_key: bool,
    pub require_offline_bundle_for_bridge: bool,
    pub require_guardian_for_recovery: bool,
    pub created_at_height: u64,
    pub status: WalletPolicyStatus,
}

impl AccountSpendPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        policy_label: &str,
        session_scope_root: &str,
        spending_limit_root: &str,
        guardian_root: &str,
        paymaster_preference_root: &str,
        key_provenance_root: &str,
        default_session_ttl_blocks: u64,
        approval_threshold: u64,
        require_hardware_key: bool,
        require_offline_bundle_for_bridge: bool,
        require_guardian_for_recovery: bool,
        created_at_height: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(policy_label, "wallet policy policy label")?;
        ensure_non_empty(session_scope_root, "wallet policy session root")?;
        ensure_non_empty(spending_limit_root, "wallet policy spending limit root")?;
        ensure_non_empty(guardian_root, "wallet policy guardian root")?;
        ensure_non_empty(
            paymaster_preference_root,
            "wallet policy paymaster preference root",
        )?;
        ensure_non_empty(key_provenance_root, "wallet policy key provenance root")?;
        ensure_positive(
            default_session_ttl_blocks,
            "wallet policy default session ttl",
        )?;
        ensure_positive(approval_threshold, "wallet policy approval threshold")?;
        let account_commitment = wallet_policy_account_commitment(account_label);
        let policy_label_commitment = wallet_policy_label_commitment(account_label, policy_label);
        let policy_id = account_spend_policy_id(
            &account_commitment,
            &policy_label_commitment,
            session_scope_root,
            spending_limit_root,
            guardian_root,
            paymaster_preference_root,
            key_provenance_root,
            default_session_ttl_blocks,
            approval_threshold,
            created_at_height,
        );
        Ok(Self {
            policy_id,
            account_commitment,
            policy_label_commitment,
            session_scope_root: session_scope_root.to_string(),
            spending_limit_root: spending_limit_root.to_string(),
            guardian_root: guardian_root.to_string(),
            paymaster_preference_root: paymaster_preference_root.to_string(),
            key_provenance_root: key_provenance_root.to_string(),
            default_session_ttl_blocks,
            approval_threshold,
            require_hardware_key,
            require_offline_bundle_for_bridge,
            require_guardian_for_recovery,
            created_at_height,
            status: WalletPolicyStatus::Active,
        })
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_positive(
            self.default_session_ttl_blocks,
            "wallet policy default session ttl",
        )?;
        ensure_positive(self.approval_threshold, "wallet policy approval threshold")?;
        if self.policy_id
            != account_spend_policy_id(
                &self.account_commitment,
                &self.policy_label_commitment,
                &self.session_scope_root,
                &self.spending_limit_root,
                &self.guardian_root,
                &self.paymaster_preference_root,
                &self.key_provenance_root,
                self.default_session_ttl_blocks,
                self.approval_threshold,
                self.created_at_height,
            )
        {
            return Err("wallet policy account spend policy id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_account_spend",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "account_commitment": self.account_commitment,
            "policy_label_commitment": self.policy_label_commitment,
            "session_scope_root": self.session_scope_root,
            "spending_limit_root": self.spending_limit_root,
            "guardian_root": self.guardian_root,
            "paymaster_preference_root": self.paymaster_preference_root,
            "key_provenance_root": self.key_provenance_root,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "approval_threshold": self.approval_threshold,
            "require_hardware_key": self.require_hardware_key,
            "require_offline_bundle_for_bridge": self.require_offline_bundle_for_bridge,
            "require_guardian_for_recovery": self.require_guardian_for_recovery,
            "created_at_height": self.created_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSigningBundle {
    pub bundle_id: String,
    pub account_commitment: String,
    pub session_scope_id: String,
    pub bundle_kind: OfflineBundleKind,
    pub payload_root: String,
    pub unsigned_tx_root: String,
    pub policy_snapshot_root: String,
    pub spending_limit_root: String,
    pub paymaster_preference_root: String,
    pub key_provenance_id: String,
    pub signer_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub signature_root: String,
    pub status: WalletPolicyStatus,
}

impl OfflineSigningBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        session_scope_id: &str,
        bundle_kind: OfflineBundleKind,
        payload: &Value,
        unsigned_tx: &Value,
        policy_snapshot: &Value,
        spending_limit_root: &str,
        paymaster_preference_root: &str,
        key_provenance_id: &str,
        signer_label: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(session_scope_id, "wallet policy offline session scope")?;
        ensure_non_empty(
            spending_limit_root,
            "wallet policy offline spending limit root",
        )?;
        ensure_non_empty(
            paymaster_preference_root,
            "wallet policy offline paymaster preference root",
        )?;
        ensure_non_empty(key_provenance_id, "wallet policy offline key provenance")?;
        ensure_non_empty(signer_label, "wallet policy offline signer")?;
        if expires_at_height <= created_at_height {
            return Err("wallet policy offline bundle expiry must be after creation".to_string());
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let payload_root = wallet_policy_payload_root("WALLET-POLICY-OFFLINE-PAYLOAD", payload);
        let unsigned_tx_root =
            wallet_policy_payload_root("WALLET-POLICY-OFFLINE-UNSIGNED-TX", unsigned_tx);
        let policy_snapshot_root =
            wallet_policy_payload_root("WALLET-POLICY-OFFLINE-SNAPSHOT", policy_snapshot);
        let signer_commitment = wallet_policy_delegate_commitment(signer_label);
        let bundle_id = offline_signing_bundle_id(
            &account_commitment,
            session_scope_id,
            &bundle_kind,
            &payload_root,
            &unsigned_tx_root,
            &policy_snapshot_root,
            spending_limit_root,
            paymaster_preference_root,
            key_provenance_id,
            created_at_height,
            expires_at_height,
        );
        Ok(Self {
            bundle_id,
            account_commitment,
            session_scope_id: session_scope_id.to_string(),
            bundle_kind,
            payload_root,
            unsigned_tx_root,
            policy_snapshot_root,
            spending_limit_root: spending_limit_root.to_string(),
            paymaster_preference_root: paymaster_preference_root.to_string(),
            key_provenance_id: key_provenance_id.to_string(),
            signer_commitment,
            created_at_height,
            expires_at_height,
            signature_root: String::new(),
            status: WalletPolicyStatus::Pending,
        })
    }

    pub fn attach_signature(&mut self, signature_payload: &Value) -> WalletPolicyResult<()> {
        if self.status != WalletPolicyStatus::Pending {
            return Err("wallet policy offline bundle is not pending".to_string());
        }
        self.signature_root =
            wallet_policy_payload_root("WALLET-POLICY-OFFLINE-SIGNATURE", signature_payload);
        self.status = WalletPolicyStatus::Signed;
        Ok(())
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(
            &self.session_scope_id,
            "wallet policy offline session scope",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("wallet policy offline bundle expiry must be after creation".to_string());
        }
        if self.bundle_id
            != offline_signing_bundle_id(
                &self.account_commitment,
                &self.session_scope_id,
                &self.bundle_kind,
                &self.payload_root,
                &self.unsigned_tx_root,
                &self.policy_snapshot_root,
                &self.spending_limit_root,
                &self.paymaster_preference_root,
                &self.key_provenance_id,
                self.created_at_height,
                self.expires_at_height,
            )
        {
            return Err("wallet policy offline bundle id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_offline_signing_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "account_commitment": self.account_commitment,
            "session_scope_id": self.session_scope_id,
            "bundle_kind": self.bundle_kind.as_str(),
            "payload_root": self.payload_root,
            "unsigned_tx_root": self.unsigned_tx_root,
            "policy_snapshot_root": self.policy_snapshot_root,
            "spending_limit_root": self.spending_limit_root,
            "paymaster_preference_root": self.paymaster_preference_root,
            "key_provenance_id": self.key_provenance_id,
            "signer_commitment": self.signer_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "signature_root": self.signature_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateDefiIntentApproval {
    pub approval_id: String,
    pub account_commitment: String,
    pub session_scope_id: String,
    pub intent_kind: PrivateDefiIntentKind,
    pub protocol_id: String,
    pub market_commitment: String,
    pub input_asset_root: String,
    pub output_asset_root: String,
    pub amount_in_bucket: u64,
    pub min_amount_out_bucket: u64,
    pub max_slippage_bps: u64,
    pub privacy_proof_root: String,
    pub encrypted_intent_root: String,
    pub paymaster_preference_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: WalletPolicyStatus,
}

impl PrivateDefiIntentApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        session_scope_id: &str,
        intent_kind: PrivateDefiIntentKind,
        protocol_id: &str,
        market_id: &str,
        input_asset_ids: Vec<String>,
        output_asset_ids: Vec<String>,
        amount_in: u64,
        min_amount_out: u64,
        max_slippage_bps: u64,
        privacy_proof: &Value,
        encrypted_intent: &Value,
        paymaster_preference_id: &str,
        created_at_height: u64,
        expires_at_height: u64,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(session_scope_id, "wallet policy defi session scope")?;
        ensure_non_empty(protocol_id, "wallet policy defi protocol")?;
        ensure_non_empty(market_id, "wallet policy defi market")?;
        ensure_unique_strings(&input_asset_ids, "wallet policy defi input assets")?;
        ensure_unique_strings(&output_asset_ids, "wallet policy defi output assets")?;
        ensure_positive(amount_in, "wallet policy defi input amount")?;
        if max_slippage_bps > WALLET_POLICY_MAX_BPS {
            return Err("wallet policy defi slippage exceeds max bps".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("wallet policy defi approval expiry must be after creation".to_string());
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let market_commitment = wallet_policy_string_root("WALLET-POLICY-DEFI-MARKET", market_id);
        let input_asset_root =
            wallet_policy_string_set_root("WALLET-POLICY-DEFI-INPUT-ASSETS", &input_asset_ids);
        let output_asset_root =
            wallet_policy_string_set_root("WALLET-POLICY-DEFI-OUTPUT-ASSETS", &output_asset_ids);
        let amount_in_bucket = wallet_policy_amount_bucket(amount_in);
        let min_amount_out_bucket = wallet_policy_amount_bucket(min_amount_out);
        let privacy_proof_root =
            wallet_policy_payload_root("WALLET-POLICY-DEFI-PRIVACY-PROOF", privacy_proof);
        let encrypted_intent_root =
            wallet_policy_payload_root("WALLET-POLICY-DEFI-ENCRYPTED-INTENT", encrypted_intent);
        let approval_id = private_defi_intent_approval_id(
            &account_commitment,
            session_scope_id,
            &intent_kind,
            protocol_id,
            &market_commitment,
            &input_asset_root,
            &output_asset_root,
            amount_in_bucket,
            min_amount_out_bucket,
            max_slippage_bps,
            &privacy_proof_root,
            &encrypted_intent_root,
            paymaster_preference_id,
            created_at_height,
            expires_at_height,
        );
        Ok(Self {
            approval_id,
            account_commitment,
            session_scope_id: session_scope_id.to_string(),
            intent_kind,
            protocol_id: protocol_id.to_string(),
            market_commitment,
            input_asset_root,
            output_asset_root,
            amount_in_bucket,
            min_amount_out_bucket,
            max_slippage_bps,
            privacy_proof_root,
            encrypted_intent_root,
            paymaster_preference_id: paymaster_preference_id.to_string(),
            created_at_height,
            expires_at_height,
            status: WalletPolicyStatus::Approved,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == WalletPolicyStatus::Approved
            && self.created_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(&self.session_scope_id, "wallet policy defi session scope")?;
        ensure_non_empty(&self.protocol_id, "wallet policy defi protocol")?;
        if self.max_slippage_bps > WALLET_POLICY_MAX_BPS {
            return Err("wallet policy defi slippage exceeds max bps".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("wallet policy defi approval expiry must be after creation".to_string());
        }
        if self.approval_id
            != private_defi_intent_approval_id(
                &self.account_commitment,
                &self.session_scope_id,
                &self.intent_kind,
                &self.protocol_id,
                &self.market_commitment,
                &self.input_asset_root,
                &self.output_asset_root,
                self.amount_in_bucket,
                self.min_amount_out_bucket,
                self.max_slippage_bps,
                &self.privacy_proof_root,
                &self.encrypted_intent_root,
                &self.paymaster_preference_id,
                self.created_at_height,
                self.expires_at_height,
            )
        {
            return Err("wallet policy private defi approval id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_private_defi_intent_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "account_commitment": self.account_commitment,
            "session_scope_id": self.session_scope_id,
            "intent_kind": self.intent_kind.as_str(),
            "protocol_id": self.protocol_id,
            "market_commitment": self.market_commitment,
            "input_asset_root": self.input_asset_root,
            "output_asset_root": self.output_asset_root,
            "amount_in_bucket": self.amount_in_bucket,
            "min_amount_out_bucket": self.min_amount_out_bucket,
            "max_slippage_bps": self.max_slippage_bps,
            "privacy_proof_root": self.privacy_proof_root,
            "encrypted_intent_root": self.encrypted_intent_root,
            "paymaster_preference_id": self.paymaster_preference_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeWithdrawalApproval {
    pub approval_id: String,
    pub account_commitment: String,
    pub session_scope_id: String,
    pub approval_kind: BridgeWithdrawalApprovalKind,
    pub withdrawal_id: String,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub recipient_address_hash: String,
    pub bridge_policy_root: String,
    pub route_preference_root: String,
    pub max_bridge_fee_units: u64,
    pub release_not_before_height: u64,
    pub expires_at_height: u64,
    pub guardian_approval_root: String,
    pub offline_bundle_id: String,
    pub status: WalletPolicyStatus,
}

impl BridgeWithdrawalApproval {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_label: &str,
        session_scope_id: &str,
        approval_kind: BridgeWithdrawalApprovalKind,
        withdrawal_id: &str,
        asset_id: &str,
        amount: u64,
        recipient_address: &str,
        bridge_policy: &Value,
        route_preference: &Value,
        max_bridge_fee_units: u64,
        release_not_before_height: u64,
        expires_at_height: u64,
        guardian_ids: Vec<String>,
        offline_bundle_id: &str,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(account_label, "wallet policy account label")?;
        ensure_non_empty(session_scope_id, "wallet policy bridge session scope")?;
        ensure_non_empty(withdrawal_id, "wallet policy bridge withdrawal id")?;
        ensure_non_empty(asset_id, "wallet policy bridge asset")?;
        ensure_non_empty(recipient_address, "wallet policy bridge recipient")?;
        ensure_positive(amount, "wallet policy bridge amount")?;
        if expires_at_height <= release_not_before_height {
            return Err(
                "wallet policy bridge approval expiry must be after release height".to_string(),
            );
        }
        let account_commitment = wallet_policy_account_commitment(account_label);
        let amount_bucket = wallet_policy_amount_bucket(amount);
        let recipient_address_hash =
            wallet_policy_string_root("WALLET-POLICY-BRIDGE-RECIPIENT", recipient_address);
        let bridge_policy_root =
            wallet_policy_payload_root("WALLET-POLICY-BRIDGE-WITHDRAWAL", bridge_policy);
        let route_preference_root =
            wallet_policy_payload_root("WALLET-POLICY-BRIDGE-ROUTE", route_preference);
        let guardian_approval_root =
            wallet_policy_string_set_root("WALLET-POLICY-BRIDGE-GUARDIANS", &guardian_ids);
        let approval_id = bridge_withdrawal_approval_id(
            &account_commitment,
            session_scope_id,
            &approval_kind,
            withdrawal_id,
            asset_id,
            amount_bucket,
            &recipient_address_hash,
            &bridge_policy_root,
            &route_preference_root,
            max_bridge_fee_units,
            release_not_before_height,
            expires_at_height,
            &guardian_approval_root,
            offline_bundle_id,
        );
        Ok(Self {
            approval_id,
            account_commitment,
            session_scope_id: session_scope_id.to_string(),
            approval_kind,
            withdrawal_id: withdrawal_id.to_string(),
            asset_id: asset_id.to_string(),
            amount_bucket,
            recipient_address_hash,
            bridge_policy_root,
            route_preference_root,
            max_bridge_fee_units,
            release_not_before_height,
            expires_at_height,
            guardian_approval_root,
            offline_bundle_id: offline_bundle_id.to_string(),
            status: WalletPolicyStatus::Approved,
        })
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == WalletPolicyStatus::Approved && height < self.expires_at_height
    }

    pub fn validate(&self) -> WalletPolicyResult<()> {
        ensure_non_empty(&self.account_commitment, "wallet policy account commitment")?;
        ensure_non_empty(&self.session_scope_id, "wallet policy bridge session scope")?;
        ensure_non_empty(&self.withdrawal_id, "wallet policy bridge withdrawal id")?;
        ensure_non_empty(&self.asset_id, "wallet policy bridge asset")?;
        if self.expires_at_height <= self.release_not_before_height {
            return Err(
                "wallet policy bridge approval expiry must be after release height".to_string(),
            );
        }
        if self.approval_id
            != bridge_withdrawal_approval_id(
                &self.account_commitment,
                &self.session_scope_id,
                &self.approval_kind,
                &self.withdrawal_id,
                &self.asset_id,
                self.amount_bucket,
                &self.recipient_address_hash,
                &self.bridge_policy_root,
                &self.route_preference_root,
                self.max_bridge_fee_units,
                self.release_not_before_height,
                self.expires_at_height,
                &self.guardian_approval_root,
                &self.offline_bundle_id,
            )
        {
            return Err("wallet policy bridge withdrawal approval id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_bridge_withdrawal_approval",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "approval_id": self.approval_id,
            "account_commitment": self.account_commitment,
            "session_scope_id": self.session_scope_id,
            "approval_kind": self.approval_kind.as_str(),
            "withdrawal_id": self.withdrawal_id,
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "recipient_address_hash": self.recipient_address_hash,
            "bridge_policy_root": self.bridge_policy_root,
            "route_preference_root": self.route_preference_root,
            "max_bridge_fee_units": self.max_bridge_fee_units,
            "release_not_before_height": self.release_not_before_height,
            "expires_at_height": self.expires_at_height,
            "guardian_approval_root": self.guardian_approval_root,
            "offline_bundle_id": self.offline_bundle_id,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPolicyAuditEvent {
    pub event_id: String,
    pub event_kind: String,
    pub subject_id: String,
    pub actor_commitment: String,
    pub height: u64,
    pub record_root: String,
    pub status: WalletPolicyStatus,
}

impl WalletPolicyAuditEvent {
    pub fn new(
        event_kind: &str,
        subject_id: &str,
        actor_commitment: String,
        height: u64,
        record_root: String,
        status: WalletPolicyStatus,
    ) -> WalletPolicyResult<Self> {
        ensure_non_empty(event_kind, "wallet policy audit event kind")?;
        ensure_non_empty(subject_id, "wallet policy audit subject")?;
        ensure_non_empty(&actor_commitment, "wallet policy audit actor")?;
        ensure_non_empty(&record_root, "wallet policy audit record root")?;
        let event_id = wallet_policy_audit_event_id(
            event_kind,
            subject_id,
            &actor_commitment,
            height,
            &record_root,
            &status,
        );
        Ok(Self {
            event_id,
            event_kind: event_kind.to_string(),
            subject_id: subject_id.to_string(),
            actor_commitment,
            height,
            record_root,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_policy_audit_event",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "subject_id": self.subject_id,
            "actor_commitment": self.actor_commitment,
            "height": self.height,
            "record_root": self.record_root,
            "status": self.status.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPolicyStateRoots {
    pub account_spend_policy_root: String,
    pub session_scope_root: String,
    pub offline_signing_bundle_root: String,
    pub watch_only_sync_policy_root: String,
    pub recovery_guardian_root: String,
    pub spending_limit_root: String,
    pub paymaster_preference_root: String,
    pub private_defi_intent_approval_root: String,
    pub bridge_withdrawal_approval_root: String,
    pub key_provenance_root: String,
    pub audit_event_root: String,
}

impl WalletPolicyStateRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "account_spend_policy_root": self.account_spend_policy_root,
            "session_scope_root": self.session_scope_root,
            "offline_signing_bundle_root": self.offline_signing_bundle_root,
            "watch_only_sync_policy_root": self.watch_only_sync_policy_root,
            "recovery_guardian_root": self.recovery_guardian_root,
            "spending_limit_root": self.spending_limit_root,
            "paymaster_preference_root": self.paymaster_preference_root,
            "private_defi_intent_approval_root": self.private_defi_intent_approval_root,
            "bridge_withdrawal_approval_root": self.bridge_withdrawal_approval_root,
            "key_provenance_root": self.key_provenance_root,
            "audit_event_root": self.audit_event_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPolicyState {
    pub height: u64,
    pub account_spend_policies: BTreeMap<String, AccountSpendPolicy>,
    pub session_scopes: BTreeMap<String, SessionScope>,
    pub offline_signing_bundles: BTreeMap<String, OfflineSigningBundle>,
    pub watch_only_sync_policies: BTreeMap<String, WatchOnlySyncPolicy>,
    pub recovery_guardians: BTreeMap<String, RecoveryGuardian>,
    pub spending_limits: BTreeMap<String, SpendingLimit>,
    pub paymaster_preferences: BTreeMap<String, PaymasterPreference>,
    pub private_defi_intent_approvals: BTreeMap<String, PrivateDefiIntentApproval>,
    pub bridge_withdrawal_approvals: BTreeMap<String, BridgeWithdrawalApproval>,
    pub key_provenance_commitments: BTreeMap<String, HardwareKeyProvenanceCommitment>,
    pub audit_events: BTreeMap<String, WalletPolicyAuditEvent>,
}

impl WalletPolicyState {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            ..Self::default()
        }
    }

    pub fn devnet() -> WalletPolicyResult<Self> {
        let mut state = Self::new(0);
        let account_label = "devnet-wallet-owner";
        let operator_label = "devnet-wallet-policy-operator";

        let signing_key = HardwareKeyProvenanceCommitment::new(
            account_label,
            "primary-spend-key",
            HardwareKeyKind::HardwareWallet,
            "nebula-labs",
            "devnet-pq-wallet",
            &json!({
                "firmware_family": "nebula-pq-devnet",
                "ml_dsa": "65",
                "slh_dsa": "shake-128s",
            }),
            &json!({
                "attestation": "devnet-attested",
                "supply_chain_rooted": true,
            }),
            &json!({
                "secure_element": "devnet-se",
                "anti_exfiltration": true,
            }),
            0,
        )?;
        let recovery_key = HardwareKeyProvenanceCommitment::new(
            account_label,
            "recovery-shard-key",
            HardwareKeyKind::RecoveryKey,
            "nebula-labs",
            "guardian-shard",
            &json!({"firmware_family": "guardian-devnet"}),
            &json!({"attestation": "guardian-devnet-attested"}),
            &json!({"secure_element": "guardian-devnet-se"}),
            0,
        )?;
        let signing_key_id = state.add_key_provenance(signing_key, operator_label)?;
        let recovery_key_id = state.add_key_provenance(recovery_key, operator_label)?;

        let guardian_a = RecoveryGuardian::new(
            account_label,
            "guardian-a",
            RecoveryGuardianRole::SocialRecovery,
            "guardian-a-recovery-key",
            &recovery_key_id,
            1,
            0,
            WALLET_POLICY_DEFAULT_RECOVERY_DELAY_BLOCKS,
        )?;
        let guardian_b = RecoveryGuardian::new(
            account_label,
            "guardian-b",
            RecoveryGuardianRole::KeyRotation,
            "guardian-b-recovery-key",
            &recovery_key_id,
            1,
            0,
            WALLET_POLICY_DEFAULT_RECOVERY_DELAY_BLOCKS,
        )?;
        state.add_recovery_guardian(guardian_a, operator_label)?;
        state.add_recovery_guardian(guardian_b, operator_label)?;

        let paymaster_preference = PaymasterPreference::new(
            account_label,
            PaymasterPreferenceMode::PreferPrivateSponsor,
            vec![
                "devnet-paymaster-primary".to_string(),
                "devnet-paymaster-backup".to_string(),
            ],
            vec!["wxmr-devnet".to_string(), "dusd-devnet".to_string()],
            10,
            50,
            true,
            true,
            &json!({
                "relay": "private",
                "max_path_length": 3,
                "allow_relayer_bonded_only": true,
            }),
        )?;
        let paymaster_preference_id =
            state.add_paymaster_preference(paymaster_preference, operator_label)?;

        let policy_seed_root = state.roots();
        let spend_policy = AccountSpendPolicy::new(
            account_label,
            "devnet-default-spend-policy",
            &policy_seed_root.session_scope_root,
            &policy_seed_root.spending_limit_root,
            &policy_seed_root.recovery_guardian_root,
            &policy_seed_root.paymaster_preference_root,
            &policy_seed_root.key_provenance_root,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
            2,
            true,
            true,
            true,
            0,
        )?;
        let spend_policy_id = state.add_account_spend_policy(spend_policy, operator_label)?;

        let transfer_limit = SpendingLimit::new(
            account_label,
            "devnet-wxmr-session-limit",
            "wxmr-devnet",
            SpendingLimitWindow::Session,
            250_000,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
            0,
            Vec::new(),
            25,
        )?;
        let limit_id = state.add_spending_limit(transfer_limit, operator_label)?;

        let session = SessionScope::new(
            account_label,
            "devnet-mobile-session",
            SessionScopeKind::PrivateDefi,
            &spend_policy_id,
            vec![
                "defi.intent.approve".to_string(),
                "bridge.withdrawal.approve".to_string(),
                "paymaster.sponsored_call".to_string(),
            ],
            vec!["wxmr-devnet".to_string(), "dusd-devnet".to_string()],
            vec![
                "devnet-amm".to_string(),
                "devnet-lending".to_string(),
                "devnet-bridge".to_string(),
            ],
            vec![limit_id.clone()],
            12,
            50,
            0,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
            false,
            false,
            &signing_key_id,
        )?;
        let session_scope_id = state.add_session_scope(session, operator_label)?;

        let watch_policy = WatchOnlySyncPolicy::new(
            account_label,
            "devnet-watchtower",
            "view-key-devnet",
            WatchOnlySyncMode::RemoteObserver,
            0,
            WALLET_POLICY_DEFAULT_WATCH_REORG_DEPTH,
            &json!({
                "scan_tags": ["payments", "bridge", "defi"],
                "nullifier_discovery": "committed",
            }),
            &json!({
                "transport": "tor",
                "endpoint_commitment": wallet_policy_string_root("WALLET-POLICY-DEVNET-ENDPOINT", "devnet-watchtower"),
            }),
            true,
            true,
            true,
            true,
            true,
            false,
        )?;
        state.add_watch_only_sync_policy(watch_policy, operator_label)?;

        let bundle = OfflineSigningBundle::new(
            account_label,
            &session_scope_id,
            OfflineBundleKind::BridgeWithdrawal,
            &json!({"intent": "devnet-bridge-withdrawal"}),
            &json!({"unsigned_tx_root": "devnet-withdrawal-root"}),
            &state.public_record(),
            &state.spending_limit_root(),
            &state.paymaster_preference_root(),
            &signing_key_id,
            "devnet-hardware-signer",
            0,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
        )?;
        let offline_bundle_id = state.add_offline_signing_bundle(bundle, operator_label)?;

        let defi_approval = PrivateDefiIntentApproval::new(
            account_label,
            &session_scope_id,
            PrivateDefiIntentKind::AmmRouteSwap,
            "nebula-defi-v1",
            "devnet-amm-route",
            vec!["wxmr-devnet".to_string()],
            vec!["dusd-devnet".to_string()],
            10_000,
            9_700,
            75,
            &json!({"proof_root": "devnet-private-defi-proof"}),
            &json!({"encrypted_intent": "devnet-sealed-route"}),
            &paymaster_preference_id,
            0,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
        )?;
        state.approve_private_defi_intent(defi_approval, operator_label)?;

        let bridge_approval = BridgeWithdrawalApproval::new(
            account_label,
            &session_scope_id,
            BridgeWithdrawalApprovalKind::DelayedRelease,
            "devnet-withdrawal-1",
            "wxmr-devnet",
            50_000,
            "devnet-monero-recipient",
            &json!({"min_confirmations": 10, "route": "private-delayed-release"}),
            &json!({"prefer_lane": "devnet-hot", "allow_market_maker": true}),
            20,
            2,
            WALLET_POLICY_DEFAULT_SESSION_TTL_BLOCKS,
            state.recovery_guardians.keys().cloned().collect::<Vec<_>>(),
            &offline_bundle_id,
        )?;
        state.approve_bridge_withdrawal(bridge_approval, operator_label)?;

        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
        for limit in self.spending_limits.values_mut() {
            limit.maybe_reset(height);
        }
    }

    pub fn add_key_provenance(
        &mut self,
        provenance: HardwareKeyProvenanceCommitment,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        provenance.validate()?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-KEY", &provenance.public_record());
        let provenance_id = provenance.provenance_id.clone();
        insert_unique_record(
            &mut self.key_provenance_commitments,
            provenance_id.clone(),
            provenance,
            "wallet policy key provenance",
        )?;
        self.audit("key_provenance_added", &provenance_id, actor, record_root)?;
        Ok(provenance_id)
    }

    pub fn add_account_spend_policy(
        &mut self,
        policy: AccountSpendPolicy,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        policy.validate()?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-SPEND", &policy.public_record());
        let policy_id = policy.policy_id.clone();
        insert_unique_record(
            &mut self.account_spend_policies,
            policy_id.clone(),
            policy,
            "wallet policy account spend policy",
        )?;
        self.audit("account_spend_policy_added", &policy_id, actor, record_root)?;
        Ok(policy_id)
    }

    pub fn add_session_scope(
        &mut self,
        scope: SessionScope,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        scope.validate()?;
        if !scope.policy_id.is_empty()
            && !self.account_spend_policies.contains_key(&scope.policy_id)
        {
            return Err("wallet policy session references unknown spend policy".to_string());
        }
        for limit_id in &scope.spending_limit_ids {
            if !self.spending_limits.contains_key(limit_id) {
                return Err("wallet policy session references unknown spending limit".to_string());
            }
        }
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-SESSION", &scope.public_record());
        let scope_id = scope.scope_id.clone();
        insert_unique_record(
            &mut self.session_scopes,
            scope_id.clone(),
            scope,
            "wallet policy session scope",
        )?;
        self.audit("session_scope_added", &scope_id, actor, record_root)?;
        Ok(scope_id)
    }

    pub fn add_offline_signing_bundle(
        &mut self,
        bundle: OfflineSigningBundle,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        bundle.validate()?;
        if !self.session_scopes.contains_key(&bundle.session_scope_id) {
            return Err("wallet policy offline bundle references unknown session".to_string());
        }
        if !self
            .key_provenance_commitments
            .contains_key(&bundle.key_provenance_id)
        {
            return Err(
                "wallet policy offline bundle references unknown key provenance".to_string(),
            );
        }
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-OFFLINE", &bundle.public_record());
        let bundle_id = bundle.bundle_id.clone();
        insert_unique_record(
            &mut self.offline_signing_bundles,
            bundle_id.clone(),
            bundle,
            "wallet policy offline signing bundle",
        )?;
        self.audit(
            "offline_signing_bundle_added",
            &bundle_id,
            actor,
            record_root,
        )?;
        Ok(bundle_id)
    }

    pub fn add_watch_only_sync_policy(
        &mut self,
        policy: WatchOnlySyncPolicy,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        policy.validate()?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-WATCH", &policy.public_record());
        let policy_id = policy.sync_policy_id.clone();
        insert_unique_record(
            &mut self.watch_only_sync_policies,
            policy_id.clone(),
            policy,
            "wallet policy watch-only sync policy",
        )?;
        self.audit(
            "watch_only_sync_policy_added",
            &policy_id,
            actor,
            record_root,
        )?;
        Ok(policy_id)
    }

    pub fn add_recovery_guardian(
        &mut self,
        guardian: RecoveryGuardian,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        guardian.validate()?;
        if !guardian.hardware_provenance_id.is_empty()
            && !self
                .key_provenance_commitments
                .contains_key(&guardian.hardware_provenance_id)
        {
            return Err("wallet policy guardian references unknown key provenance".to_string());
        }
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-GUARDIAN", &guardian.public_record());
        let guardian_id = guardian.guardian_id.clone();
        insert_unique_record(
            &mut self.recovery_guardians,
            guardian_id.clone(),
            guardian,
            "wallet policy recovery guardian",
        )?;
        self.audit("recovery_guardian_added", &guardian_id, actor, record_root)?;
        Ok(guardian_id)
    }

    pub fn add_spending_limit(
        &mut self,
        limit: SpendingLimit,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        limit.validate()?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-LIMIT", &limit.public_record());
        let limit_id = limit.limit_id.clone();
        insert_unique_record(
            &mut self.spending_limits,
            limit_id.clone(),
            limit,
            "wallet policy spending limit",
        )?;
        self.audit("spending_limit_added", &limit_id, actor, record_root)?;
        Ok(limit_id)
    }

    pub fn add_paymaster_preference(
        &mut self,
        preference: PaymasterPreference,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        preference.validate()?;
        let record_root = wallet_policy_payload_root(
            "WALLET-POLICY-AUDIT-PAYMASTER",
            &preference.public_record(),
        );
        let preference_id = preference.preference_id.clone();
        insert_unique_record(
            &mut self.paymaster_preferences,
            preference_id.clone(),
            preference,
            "wallet policy paymaster preference",
        )?;
        self.audit(
            "paymaster_preference_added",
            &preference_id,
            actor,
            record_root,
        )?;
        Ok(preference_id)
    }

    pub fn approve_private_defi_intent(
        &mut self,
        approval: PrivateDefiIntentApproval,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        approval.validate()?;
        if !self.session_scopes.contains_key(&approval.session_scope_id) {
            return Err("wallet policy defi approval references unknown session".to_string());
        }
        if !approval.paymaster_preference_id.is_empty()
            && !self
                .paymaster_preferences
                .contains_key(&approval.paymaster_preference_id)
        {
            return Err(
                "wallet policy defi approval references unknown paymaster preference".to_string(),
            );
        }
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-DEFI", &approval.public_record());
        let approval_id = approval.approval_id.clone();
        insert_unique_record(
            &mut self.private_defi_intent_approvals,
            approval_id.clone(),
            approval,
            "wallet policy private defi approval",
        )?;
        self.audit(
            "private_defi_intent_approved",
            &approval_id,
            actor,
            record_root,
        )?;
        Ok(approval_id)
    }

    pub fn approve_bridge_withdrawal(
        &mut self,
        approval: BridgeWithdrawalApproval,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        approval.validate()?;
        if !self.session_scopes.contains_key(&approval.session_scope_id) {
            return Err("wallet policy bridge approval references unknown session".to_string());
        }
        if !approval.offline_bundle_id.is_empty()
            && !self
                .offline_signing_bundles
                .contains_key(&approval.offline_bundle_id)
        {
            return Err(
                "wallet policy bridge approval references unknown offline bundle".to_string(),
            );
        }
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-BRIDGE", &approval.public_record());
        let approval_id = approval.approval_id.clone();
        insert_unique_record(
            &mut self.bridge_withdrawal_approvals,
            approval_id.clone(),
            approval,
            "wallet policy bridge withdrawal approval",
        )?;
        self.audit(
            "bridge_withdrawal_approved",
            &approval_id,
            actor,
            record_root,
        )?;
        Ok(approval_id)
    }

    pub fn attach_offline_signature(
        &mut self,
        bundle_id: &str,
        signature_payload: &Value,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        let bundle = self
            .offline_signing_bundles
            .get_mut(bundle_id)
            .ok_or_else(|| "wallet policy unknown offline bundle".to_string())?;
        bundle.attach_signature(signature_payload)?;
        let record_root = wallet_policy_payload_root(
            "WALLET-POLICY-AUDIT-OFFLINE-SIGNED",
            &bundle.public_record(),
        );
        self.audit(
            "offline_signing_bundle_signed",
            bundle_id,
            actor,
            record_root,
        )
    }

    pub fn consume_session_call(
        &mut self,
        scope_id: &str,
        fee_units: u64,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        let scope = self
            .session_scopes
            .get_mut(scope_id)
            .ok_or_else(|| "wallet policy unknown session scope".to_string())?;
        scope.consume_call(fee_units, self.height)?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-SESSION-CALL", &scope.public_record());
        self.audit("session_scope_call_consumed", scope_id, actor, record_root)
    }

    pub fn consume_spending_limit(
        &mut self,
        limit_id: &str,
        amount: u64,
        actor: &str,
    ) -> WalletPolicyResult<String> {
        let limit = self
            .spending_limits
            .get_mut(limit_id)
            .ok_or_else(|| "wallet policy unknown spending limit".to_string())?;
        limit.record_spend(amount)?;
        let record_root =
            wallet_policy_payload_root("WALLET-POLICY-AUDIT-LIMIT-SPEND", &limit.public_record());
        self.audit("spending_limit_consumed", limit_id, actor, record_root)
    }

    pub fn revoke_session_scope(
        &mut self,
        scope_id: &str,
        actor: &str,
        reason: &str,
    ) -> WalletPolicyResult<String> {
        let scope = self
            .session_scopes
            .get_mut(scope_id)
            .ok_or_else(|| "wallet policy unknown session scope".to_string())?;
        scope.status = WalletPolicyStatus::Revoked;
        let record_root = wallet_policy_payload_root(
            "WALLET-POLICY-AUDIT-SESSION-REVOKED",
            &json!({
                "scope": scope.public_record(),
                "reason_hash": wallet_policy_string_root("WALLET-POLICY-REVOKE-REASON", reason),
            }),
        );
        self.audit("session_scope_revoked", scope_id, actor, record_root)
    }

    pub fn account_spend_policy_root(&self) -> String {
        account_spend_policy_root(
            &self
                .account_spend_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn session_scope_root(&self) -> String {
        session_scope_root(&self.session_scopes.values().cloned().collect::<Vec<_>>())
    }

    pub fn offline_signing_bundle_root(&self) -> String {
        offline_signing_bundle_root(
            &self
                .offline_signing_bundles
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn watch_only_sync_policy_root(&self) -> String {
        watch_only_sync_policy_root(
            &self
                .watch_only_sync_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn recovery_guardian_root(&self) -> String {
        recovery_guardian_root(
            &self
                .recovery_guardians
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn spending_limit_root(&self) -> String {
        spending_limit_root(&self.spending_limits.values().cloned().collect::<Vec<_>>())
    }

    pub fn paymaster_preference_root(&self) -> String {
        paymaster_preference_root(
            &self
                .paymaster_preferences
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn private_defi_intent_approval_root(&self) -> String {
        private_defi_intent_approval_root(
            &self
                .private_defi_intent_approvals
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn bridge_withdrawal_approval_root(&self) -> String {
        bridge_withdrawal_approval_root(
            &self
                .bridge_withdrawal_approvals
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn key_provenance_root(&self) -> String {
        hardware_key_provenance_root(
            &self
                .key_provenance_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_event_root(&self) -> String {
        wallet_policy_audit_event_root(&self.audit_events.values().cloned().collect::<Vec<_>>())
    }

    pub fn roots(&self) -> WalletPolicyStateRoots {
        WalletPolicyStateRoots {
            account_spend_policy_root: self.account_spend_policy_root(),
            session_scope_root: self.session_scope_root(),
            offline_signing_bundle_root: self.offline_signing_bundle_root(),
            watch_only_sync_policy_root: self.watch_only_sync_policy_root(),
            recovery_guardian_root: self.recovery_guardian_root(),
            spending_limit_root: self.spending_limit_root(),
            paymaster_preference_root: self.paymaster_preference_root(),
            private_defi_intent_approval_root: self.private_defi_intent_approval_root(),
            bridge_withdrawal_approval_root: self.bridge_withdrawal_approval_root(),
            key_provenance_root: self.key_provenance_root(),
            audit_event_root: self.audit_event_root(),
        }
    }

    pub fn state_root(&self) -> String {
        wallet_policy_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("wallet policy state public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "wallet_policy_state",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_POLICY_PROTOCOL_VERSION,
            "height": self.height,
            "roots": roots.public_record(),
            "account_spend_policy_count": self.account_spend_policies.len() as u64,
            "session_scope_count": self.session_scopes.len() as u64,
            "offline_signing_bundle_count": self.offline_signing_bundles.len() as u64,
            "watch_only_sync_policy_count": self.watch_only_sync_policies.len() as u64,
            "recovery_guardian_count": self.recovery_guardians.len() as u64,
            "spending_limit_count": self.spending_limits.len() as u64,
            "paymaster_preference_count": self.paymaster_preferences.len() as u64,
            "private_defi_intent_approval_count": self.private_defi_intent_approvals.len() as u64,
            "bridge_withdrawal_approval_count": self.bridge_withdrawal_approvals.len() as u64,
            "key_provenance_count": self.key_provenance_commitments.len() as u64,
            "audit_event_count": self.audit_events.len() as u64,
            "active_session_count": self.session_scopes.values().filter(|scope| scope.is_active_at(self.height)).count() as u64,
            "active_defi_approval_count": self.private_defi_intent_approvals.values().filter(|approval| approval.is_active_at(self.height)).count() as u64,
            "active_bridge_approval_count": self.bridge_withdrawal_approvals.values().filter(|approval| approval.is_active_at(self.height)).count() as u64,
        })
    }

    fn audit(
        &mut self,
        event_kind: &str,
        subject_id: &str,
        actor: &str,
        record_root: String,
    ) -> WalletPolicyResult<String> {
        let event = WalletPolicyAuditEvent::new(
            event_kind,
            subject_id,
            wallet_policy_delegate_commitment(actor),
            self.height,
            record_root,
            WalletPolicyStatus::Used,
        )?;
        let event_id = event.event_id.clone();
        insert_unique_record(
            &mut self.audit_events,
            event_id.clone(),
            event,
            "wallet policy audit event",
        )?;
        Ok(event_id)
    }
}

pub fn wallet_policy_account_commitment(account_label: &str) -> String {
    domain_hash(
        "WALLET-POLICY-ACCOUNT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(account_label)],
        32,
    )
}

pub fn wallet_policy_delegate_commitment(delegate_label: &str) -> String {
    domain_hash(
        "WALLET-POLICY-DELEGATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(delegate_label)],
        32,
    )
}

pub fn wallet_policy_guardian_commitment(account_label: &str, guardian_label: &str) -> String {
    domain_hash(
        "WALLET-POLICY-GUARDIAN",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
            HashPart::Str(guardian_label),
        ],
        32,
    )
}

pub fn wallet_policy_view_key_commitment(account_label: &str, view_key_label: &str) -> String {
    domain_hash(
        "WALLET-POLICY-VIEW-KEY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
            HashPart::Str(view_key_label),
        ],
        32,
    )
}

pub fn wallet_policy_label_commitment(account_label: &str, label: &str) -> String {
    domain_hash(
        "WALLET-POLICY-LABEL",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_label),
            HashPart::Str(label),
        ],
        32,
    )
}

pub fn wallet_policy_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn wallet_policy_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn wallet_policy_string_set_root(domain: &str, values: &[String]) -> String {
    let ordered = values.iter().cloned().collect::<BTreeSet<_>>();
    merkle_root(
        domain,
        &ordered
            .iter()
            .map(|value| {
                json!({
                    "value_commitment": wallet_policy_string_root(domain, value),
                })
            })
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_policy_amount_bucket(amount: u64) -> u64 {
    if amount == 0 {
        0
    } else {
        amount.div_ceil(WALLET_POLICY_DEFAULT_AMOUNT_BUCKET) * WALLET_POLICY_DEFAULT_AMOUNT_BUCKET
    }
}

#[allow(clippy::too_many_arguments)]
pub fn hardware_key_provenance_id(
    account_commitment: &str,
    key_label_commitment: &str,
    key_kind: &HardwareKeyKind,
    vendor_commitment: &str,
    model_commitment: &str,
    firmware_root: &str,
    attestation_root: &str,
    secure_element_root: &str,
) -> String {
    domain_hash(
        "WALLET-POLICY-KEY-PROVENANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(key_label_commitment),
            HashPart::Str(key_kind.as_str()),
            HashPart::Str(vendor_commitment),
            HashPart::Str(model_commitment),
            HashPart::Str(firmware_root),
            HashPart::Str(attestation_root),
            HashPart::Str(secure_element_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn spending_limit_id(
    account_commitment: &str,
    limit_label_commitment: &str,
    asset_id: &str,
    window: &SpendingLimitWindow,
    max_amount: u64,
    reset_interval_blocks: u64,
    window_start_height: u64,
    scope_root: &str,
) -> String {
    domain_hash(
        "WALLET-POLICY-SPENDING-LIMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(limit_label_commitment),
            HashPart::Str(asset_id),
            HashPart::Str(window.as_str()),
            HashPart::Int(max_amount as i128),
            HashPart::Int(reset_interval_blocks as i128),
            HashPart::Int(window_start_height as i128),
            HashPart::Str(scope_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn paymaster_preference_id(
    account_commitment: &str,
    mode: &PaymasterPreferenceMode,
    preferred_paymaster_ids: &[String],
    allowed_fee_asset_ids: &[String],
    max_fee_units_per_call: u64,
    max_fee_units_per_session: u64,
    require_private_relay: bool,
    allow_fallback_self_pay: bool,
    relayer_policy_root: &str,
) -> String {
    domain_hash(
        "WALLET-POLICY-PAYMASTER-PREFERENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Str(&wallet_policy_string_set_root(
                "WALLET-POLICY-PAYMASTER-ID-SET",
                preferred_paymaster_ids,
            )),
            HashPart::Str(&wallet_policy_string_set_root(
                "WALLET-POLICY-PAYMASTER-ASSET-SET",
                allowed_fee_asset_ids,
            )),
            HashPart::Int(max_fee_units_per_call as i128),
            HashPart::Int(max_fee_units_per_session as i128),
            HashPart::Str(if require_private_relay {
                "true"
            } else {
                "false"
            }),
            HashPart::Str(if allow_fallback_self_pay {
                "true"
            } else {
                "false"
            }),
            HashPart::Str(relayer_policy_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn session_scope_id(
    account_commitment: &str,
    delegate_commitment: &str,
    scope_kind: &SessionScopeKind,
    policy_id: &str,
    allowed_action_root: &str,
    allowed_asset_root: &str,
    allowed_contract_root: &str,
    spending_limit_root: &str,
    starts_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-POLICY-SESSION-SCOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(delegate_commitment),
            HashPart::Str(scope_kind.as_str()),
            HashPart::Str(policy_id),
            HashPart::Str(allowed_action_root),
            HashPart::Str(allowed_asset_root),
            HashPart::Str(allowed_contract_root),
            HashPart::Str(spending_limit_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn watch_only_sync_policy_id(
    account_commitment: &str,
    watcher_commitment: &str,
    view_key_commitment: &str,
    mode: &WatchOnlySyncMode,
    scan_from_height: u64,
    max_reorg_depth: u64,
    privacy_filter_root: &str,
    endpoint_root: &str,
) -> String {
    domain_hash(
        "WALLET-POLICY-WATCH-ONLY-SYNC-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(watcher_commitment),
            HashPart::Str(view_key_commitment),
            HashPart::Str(mode.as_str()),
            HashPart::Int(scan_from_height as i128),
            HashPart::Int(max_reorg_depth as i128),
            HashPart::Str(privacy_filter_root),
            HashPart::Str(endpoint_root),
        ],
        32,
    )
}

pub fn recovery_guardian_id(
    account_commitment: &str,
    guardian_commitment: &str,
    guardian_role: &RecoveryGuardianRole,
    recovery_key_commitment: &str,
    hardware_provenance_id: &str,
    active_from_height: u64,
) -> String {
    domain_hash(
        "WALLET-POLICY-RECOVERY-GUARDIAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(guardian_commitment),
            HashPart::Str(guardian_role.as_str()),
            HashPart::Str(recovery_key_commitment),
            HashPart::Str(hardware_provenance_id),
            HashPart::Int(active_from_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn account_spend_policy_id(
    account_commitment: &str,
    policy_label_commitment: &str,
    session_scope_root: &str,
    spending_limit_root: &str,
    guardian_root: &str,
    paymaster_preference_root: &str,
    key_provenance_root: &str,
    default_session_ttl_blocks: u64,
    approval_threshold: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-POLICY-ACCOUNT-SPEND-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(policy_label_commitment),
            HashPart::Str(session_scope_root),
            HashPart::Str(spending_limit_root),
            HashPart::Str(guardian_root),
            HashPart::Str(paymaster_preference_root),
            HashPart::Str(key_provenance_root),
            HashPart::Int(default_session_ttl_blocks as i128),
            HashPart::Int(approval_threshold as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn offline_signing_bundle_id(
    account_commitment: &str,
    session_scope_id: &str,
    bundle_kind: &OfflineBundleKind,
    payload_root: &str,
    unsigned_tx_root: &str,
    policy_snapshot_root: &str,
    spending_limit_root: &str,
    paymaster_preference_root: &str,
    key_provenance_id: &str,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-POLICY-OFFLINE-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(session_scope_id),
            HashPart::Str(bundle_kind.as_str()),
            HashPart::Str(payload_root),
            HashPart::Str(unsigned_tx_root),
            HashPart::Str(policy_snapshot_root),
            HashPart::Str(spending_limit_root),
            HashPart::Str(paymaster_preference_root),
            HashPart::Str(key_provenance_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn private_defi_intent_approval_id(
    account_commitment: &str,
    session_scope_id: &str,
    intent_kind: &PrivateDefiIntentKind,
    protocol_id: &str,
    market_commitment: &str,
    input_asset_root: &str,
    output_asset_root: &str,
    amount_in_bucket: u64,
    min_amount_out_bucket: u64,
    max_slippage_bps: u64,
    privacy_proof_root: &str,
    encrypted_intent_root: &str,
    paymaster_preference_id: &str,
    created_at_height: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-POLICY-DEFI-INTENT-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(session_scope_id),
            HashPart::Str(intent_kind.as_str()),
            HashPart::Str(protocol_id),
            HashPart::Str(market_commitment),
            HashPart::Str(input_asset_root),
            HashPart::Str(output_asset_root),
            HashPart::Int(amount_in_bucket as i128),
            HashPart::Int(min_amount_out_bucket as i128),
            HashPart::Int(max_slippage_bps as i128),
            HashPart::Str(privacy_proof_root),
            HashPart::Str(encrypted_intent_root),
            HashPart::Str(paymaster_preference_id),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn bridge_withdrawal_approval_id(
    account_commitment: &str,
    session_scope_id: &str,
    approval_kind: &BridgeWithdrawalApprovalKind,
    withdrawal_id: &str,
    asset_id: &str,
    amount_bucket: u64,
    recipient_address_hash: &str,
    bridge_policy_root: &str,
    route_preference_root: &str,
    max_bridge_fee_units: u64,
    release_not_before_height: u64,
    expires_at_height: u64,
    guardian_approval_root: &str,
    offline_bundle_id: &str,
) -> String {
    domain_hash(
        "WALLET-POLICY-BRIDGE-WITHDRAWAL-APPROVAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_commitment),
            HashPart::Str(session_scope_id),
            HashPart::Str(approval_kind.as_str()),
            HashPart::Str(withdrawal_id),
            HashPart::Str(asset_id),
            HashPart::Int(amount_bucket as i128),
            HashPart::Str(recipient_address_hash),
            HashPart::Str(bridge_policy_root),
            HashPart::Str(route_preference_root),
            HashPart::Int(max_bridge_fee_units as i128),
            HashPart::Int(release_not_before_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(guardian_approval_root),
            HashPart::Str(offline_bundle_id),
        ],
        32,
    )
}

pub fn wallet_policy_audit_event_id(
    event_kind: &str,
    subject_id: &str,
    actor_commitment: &str,
    height: u64,
    record_root: &str,
    status: &WalletPolicyStatus,
) -> String {
    domain_hash(
        "WALLET-POLICY-AUDIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(subject_id),
            HashPart::Str(actor_commitment),
            HashPart::Int(height as i128),
            HashPart::Str(record_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

pub fn account_spend_policy_root(values: &[AccountSpendPolicy]) -> String {
    keyed_record_root(
        "WALLET-POLICY-ACCOUNT-SPEND",
        values
            .iter()
            .map(|policy| (policy.policy_id.clone(), policy.public_record()))
            .collect(),
    )
}

pub fn session_scope_root(values: &[SessionScope]) -> String {
    keyed_record_root(
        "WALLET-POLICY-SESSION-SCOPE",
        values
            .iter()
            .map(|scope| (scope.scope_id.clone(), scope.public_record()))
            .collect(),
    )
}

pub fn offline_signing_bundle_root(values: &[OfflineSigningBundle]) -> String {
    keyed_record_root(
        "WALLET-POLICY-OFFLINE-SIGNING-BUNDLE",
        values
            .iter()
            .map(|bundle| (bundle.bundle_id.clone(), bundle.public_record()))
            .collect(),
    )
}

pub fn watch_only_sync_policy_root(values: &[WatchOnlySyncPolicy]) -> String {
    keyed_record_root(
        "WALLET-POLICY-WATCH-ONLY-SYNC",
        values
            .iter()
            .map(|policy| (policy.sync_policy_id.clone(), policy.public_record()))
            .collect(),
    )
}

pub fn recovery_guardian_root(values: &[RecoveryGuardian]) -> String {
    keyed_record_root(
        "WALLET-POLICY-RECOVERY-GUARDIAN",
        values
            .iter()
            .map(|guardian| (guardian.guardian_id.clone(), guardian.public_record()))
            .collect(),
    )
}

pub fn spending_limit_root(values: &[SpendingLimit]) -> String {
    keyed_record_root(
        "WALLET-POLICY-SPENDING-LIMIT",
        values
            .iter()
            .map(|limit| (limit.limit_id.clone(), limit.public_record()))
            .collect(),
    )
}

pub fn paymaster_preference_root(values: &[PaymasterPreference]) -> String {
    keyed_record_root(
        "WALLET-POLICY-PAYMASTER-PREFERENCE",
        values
            .iter()
            .map(|preference| (preference.preference_id.clone(), preference.public_record()))
            .collect(),
    )
}

pub fn private_defi_intent_approval_root(values: &[PrivateDefiIntentApproval]) -> String {
    keyed_record_root(
        "WALLET-POLICY-DEFI-INTENT-APPROVAL",
        values
            .iter()
            .map(|approval| (approval.approval_id.clone(), approval.public_record()))
            .collect(),
    )
}

pub fn bridge_withdrawal_approval_root(values: &[BridgeWithdrawalApproval]) -> String {
    keyed_record_root(
        "WALLET-POLICY-BRIDGE-WITHDRAWAL-APPROVAL",
        values
            .iter()
            .map(|approval| (approval.approval_id.clone(), approval.public_record()))
            .collect(),
    )
}

pub fn hardware_key_provenance_root(values: &[HardwareKeyProvenanceCommitment]) -> String {
    keyed_record_root(
        "WALLET-POLICY-KEY-PROVENANCE",
        values
            .iter()
            .map(|provenance| (provenance.provenance_id.clone(), provenance.public_record()))
            .collect(),
    )
}

pub fn wallet_policy_audit_event_root(values: &[WalletPolicyAuditEvent]) -> String {
    keyed_record_root(
        "WALLET-POLICY-AUDIT-EVENT",
        values
            .iter()
            .map(|event| (event.event_id.clone(), event.public_record()))
            .collect(),
    )
}

pub fn wallet_policy_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "WALLET-POLICY-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
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
) -> WalletPolicyResult<()> {
    ensure_non_empty(&key, field)?;
    if records.contains_key(&key) {
        return Err(format!("{field} already exists"));
    }
    records.insert(key, value);
    Ok(())
}

fn ensure_non_empty(value: &str, field: &str) -> WalletPolicyResult<()> {
    if value.trim().is_empty() {
        Err(format!("{field} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, field: &str) -> WalletPolicyResult<()> {
    if value == 0 {
        Err(format!("{field} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], field: &str) -> WalletPolicyResult<()> {
    if values.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    let mut seen = BTreeSet::new();
    for value in values {
        ensure_non_empty(value, field)?;
        if !seen.insert(value) {
            return Err(format!("{field} contains duplicate value"));
        }
    }
    Ok(())
}
