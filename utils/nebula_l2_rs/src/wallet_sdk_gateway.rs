use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WalletSdkGatewayResult<T> = Result<T, String>;

pub const WALLET_SDK_GATEWAY_PROTOCOL_VERSION: &str = "nebula-wallet-sdk-gateway-v1";
pub const WALLET_SDK_GATEWAY_SECURITY_MODEL: &str =
    "deterministic-devnet-wallet-gateway-not-real-crypto";
pub const WALLET_SDK_GATEWAY_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const WALLET_SDK_GATEWAY_LOW_FEE_STRATEGY: &str =
    "privacy-preserving-low-fee-quote-envelope-v1";
pub const WALLET_SDK_GATEWAY_DEVNET_HEIGHT: u64 = 144;
pub const WALLET_SDK_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const WALLET_SDK_GATEWAY_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const WALLET_SDK_GATEWAY_DEFAULT_BUILDER_TTL_BLOCKS: u64 = 48;
pub const WALLET_SDK_GATEWAY_DEFAULT_CONTRACT_TTL_BLOCKS: u64 = 72;
pub const WALLET_SDK_GATEWAY_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 720;
pub const WALLET_SDK_GATEWAY_DEFAULT_OFFLINE_SIGNING_TTL_BLOCKS: u64 = 288;
pub const WALLET_SDK_GATEWAY_DEFAULT_RATE_LIMIT_WINDOW_BLOCKS: u64 = 60;
pub const WALLET_SDK_GATEWAY_DEFAULT_RECOVERY_TIMELOCK_BLOCKS: u64 = 1_440;
pub const WALLET_SDK_GATEWAY_DEFAULT_LOW_FEE_ASSET_ID: &str = "xmr-devnet";
pub const WALLET_SDK_GATEWAY_DEFAULT_MONERO_NETWORK: &str = "stagenet";
pub const WALLET_SDK_GATEWAY_DEFAULT_FAST_LANE_ID: &str = "private-fast-lane";
pub const WALLET_SDK_GATEWAY_DEFAULT_DEFI_LANE_ID: &str = "small-defi-lane";
pub const WALLET_SDK_GATEWAY_MAX_BPS: u64 = 10_000;
pub const WALLET_SDK_GATEWAY_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const WALLET_SDK_GATEWAY_MAX_PROFILES: usize = 32;
pub const WALLET_SDK_GATEWAY_MAX_SESSIONS: usize = 96;
pub const WALLET_SDK_GATEWAY_MAX_BRIDGE_PROFILES: usize = 32;
pub const WALLET_SDK_GATEWAY_MAX_QUOTES: usize = 128;
pub const WALLET_SDK_GATEWAY_MAX_BUILDER_INTENTS: usize = 128;
pub const WALLET_SDK_GATEWAY_MAX_CONTRACT_MANIFESTS: usize = 128;
pub const WALLET_SDK_GATEWAY_MAX_RECOVERY_POLICIES: usize = 32;
pub const WALLET_SDK_GATEWAY_MAX_DISCLOSURE_TICKETS: usize = 128;
pub const WALLET_SDK_GATEWAY_MAX_RATE_LIMITS: usize = 64;
pub const WALLET_SDK_GATEWAY_MAX_OFFLINE_BUNDLES: usize = 96;
pub const WALLET_SDK_GATEWAY_MAX_COMPATIBILITY_MANIFESTS: usize = 32;
pub const WALLET_SDK_GATEWAY_MAX_PUBLIC_RECORDS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletSdkClientKind {
    Mobile,
    Browser,
    Desktop,
    Hardware,
    WatchOnly,
    BridgeOperator,
    RecoveryAgent,
    DevnetFixture,
}

impl WalletSdkClientKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mobile => "mobile",
            Self::Browser => "browser",
            Self::Desktop => "desktop",
            Self::Hardware => "hardware",
            Self::WatchOnly => "watch_only",
            Self::BridgeOperator => "bridge_operator",
            Self::RecoveryAgent => "recovery_agent",
            Self::DevnetFixture => "devnet_fixture",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletSdkCapability {
    PqSessions,
    ViewOnlyMoneroBridge,
    LowFeeQuotes,
    PrivateTxBuilder,
    SmartContractCalls,
    RecoveryPolicies,
    SelectiveDisclosure,
    RateLimitHints,
    OfflineSigning,
    SdkCompatibility,
}

impl WalletSdkCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PqSessions => "pq_sessions",
            Self::ViewOnlyMoneroBridge => "view_only_monero_bridge",
            Self::LowFeeQuotes => "low_fee_quotes",
            Self::PrivateTxBuilder => "private_tx_builder",
            Self::SmartContractCalls => "smart_contract_calls",
            Self::RecoveryPolicies => "recovery_policies",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::RateLimitHints => "rate_limit_hints",
            Self::OfflineSigning => "offline_signing",
            Self::SdkCompatibility => "sdk_compatibility",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletSdkGatewayStatus {
    Draft,
    Active,
    Pending,
    Quoted,
    Prepared,
    Submitted,
    Used,
    Expired,
    Revoked,
    Cancelled,
    Quarantined,
}

impl WalletSdkGatewayStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Quoted => "quoted",
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::Pending | Self::Quoted | Self::Prepared | Self::Submitted
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Used | Self::Expired | Self::Revoked | Self::Cancelled | Self::Quarantined
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSessionPurpose {
    SubmitPrivateTx,
    QuoteLowFee,
    ViewOnlyBridgeSync,
    ContractCall,
    Recovery,
    Disclosure,
    OfflineSigning,
}

impl PqSessionPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SubmitPrivateTx => "submit_private_tx",
            Self::QuoteLowFee => "quote_low_fee",
            Self::ViewOnlyBridgeSync => "view_only_bridge_sync",
            Self::ContractCall => "contract_call",
            Self::Recovery => "recovery",
            Self::Disclosure => "disclosure",
            Self::OfflineSigning => "offline_signing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroBridgeProfileMode {
    ViewOnly,
    DepositWatch,
    WithdrawalWatch,
    BridgeOperatorView,
}

impl MoneroBridgeProfileMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ViewOnly => "view_only",
            Self::DepositWatch => "deposit_watch",
            Self::WithdrawalWatch => "withdrawal_watch",
            Self::BridgeOperatorView => "bridge_operator_view",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowFeeQuoteStrategy {
    SponsoredPrivateLane,
    BatchedSettlement,
    ProofCompressed,
    PaymasterAuction,
    SpeedPriority,
}

impl LowFeeQuoteStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SponsoredPrivateLane => "sponsored_private_lane",
            Self::BatchedSettlement => "batched_settlement",
            Self::ProofCompressed => "proof_compressed",
            Self::PaymasterAuction => "paymaster_auction",
            Self::SpeedPriority => "speed_priority",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTxIntentKind {
    ShieldedTransfer,
    BridgeDeposit,
    BridgeWithdrawal,
    ConfidentialSwap,
    LiquidityProvision,
    ContractCall,
}

impl PrivateTxIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ShieldedTransfer => "shielded_transfer",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ConfidentialSwap => "confidential_swap",
            Self::LiquidityProvision => "liquidity_provision",
            Self::ContractCall => "contract_call",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxPrivacyLevel {
    StandardStealth,
    ShieldedNotes,
    DecoyHeavy,
    MaxPrivacy,
}

impl TxPrivacyLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StandardStealth => "standard_stealth",
            Self::ShieldedNotes => "shielded_notes",
            Self::DecoyHeavy => "decoy_heavy",
            Self::MaxPrivacy => "max_privacy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmartContractCallKind {
    ReadOnly,
    PrivateWrite,
    DefiSwap,
    VaultAction,
    GovernanceVote,
}

impl SmartContractCallKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::PrivateWrite => "private_write",
            Self::DefiSwap => "defi_swap",
            Self::VaultAction => "vault_action",
            Self::GovernanceVote => "governance_vote",
        }
    }

    pub fn requires_private_witness(&self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPolicyKind {
    GuardianQuorum,
    SeedlessSocial,
    TimeLockedColdKey,
    HardwareMigration,
    PqEmergencyRotate,
}

impl RecoveryPolicyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GuardianQuorum => "guardian_quorum",
            Self::SeedlessSocial => "seedless_social",
            Self::TimeLockedColdKey => "time_locked_cold_key",
            Self::HardwareMigration => "hardware_migration",
            Self::PqEmergencyRotate => "pq_emergency_rotate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectiveDisclosureScope {
    BalanceProof,
    TransactionStatus,
    ViewTagHit,
    FeeReceipt,
    ComplianceView,
    RecoveryAudit,
}

impl SelectiveDisclosureScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BalanceProof => "balance_proof",
            Self::TransactionStatus => "transaction_status",
            Self::ViewTagHit => "view_tag_hit",
            Self::FeeReceipt => "fee_receipt",
            Self::ComplianceView => "compliance_view",
            Self::RecoveryAudit => "recovery_audit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBucketKind {
    SessionOpen,
    FeeQuote,
    PrivateBuilder,
    ContractManifest,
    DisclosureTicket,
    OfflineSigning,
}

impl RateLimitBucketKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SessionOpen => "session_open",
            Self::FeeQuote => "fee_quote",
            Self::PrivateBuilder => "private_builder",
            Self::ContractManifest => "contract_manifest",
            Self::DisclosureTicket => "disclosure_ticket",
            Self::OfflineSigning => "offline_signing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitStatus {
    Active,
    Paused,
    Exceeded,
    Expired,
}

impl RateLimitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Exceeded => "exceeded",
            Self::Expired => "expired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineSigningStage {
    Prepared,
    Exported,
    Signed,
    BroadcastReady,
    Expired,
    Cancelled,
}

impl OfflineSigningStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Exported => "exported",
            Self::Signed => "signed",
            Self::BroadcastReady => "broadcast_ready",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn is_open(&self) -> bool {
        matches!(self, Self::Prepared | Self::Exported)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdkCompatibilityStatus {
    Supported,
    Experimental,
    Deprecated,
    Blocked,
}

impl SdkCompatibilityStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Experimental => "experimental",
            Self::Deprecated => "deprecated",
            Self::Blocked => "blocked",
        }
    }

    pub fn accepts_new_sessions(&self) -> bool {
        matches!(self, Self::Supported | Self::Experimental)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSdkGatewayConfig {
    pub protocol_version: String,
    pub security_model: String,
    pub default_session_ttl_blocks: u64,
    pub default_quote_ttl_blocks: u64,
    pub default_builder_ttl_blocks: u64,
    pub default_contract_ttl_blocks: u64,
    pub default_disclosure_ttl_blocks: u64,
    pub default_offline_signing_ttl_blocks: u64,
    pub default_rate_limit_window_blocks: u64,
    pub default_recovery_timelock_blocks: u64,
    pub default_fee_asset_id: String,
    pub monero_network: String,
    pub min_pq_security_bits: u16,
    pub max_rebate_bps: u64,
    pub max_profiles: usize,
    pub max_sessions: usize,
    pub max_bridge_profiles: usize,
    pub max_quotes: usize,
    pub max_builder_intents: usize,
    pub max_contract_manifests: usize,
    pub max_recovery_policies: usize,
    pub max_disclosure_tickets: usize,
    pub max_rate_limits: usize,
    pub max_offline_signing_bundles: usize,
    pub max_compatibility_manifests: usize,
    pub max_public_records: usize,
    pub require_pq_auth_for_private_builders: bool,
    pub require_pq_auth_for_contract_calls: bool,
    pub enable_view_only_bridge_profiles: bool,
}

impl Default for WalletSdkGatewayConfig {
    fn default() -> Self {
        Self {
            protocol_version: WALLET_SDK_GATEWAY_PROTOCOL_VERSION.to_string(),
            security_model: WALLET_SDK_GATEWAY_SECURITY_MODEL.to_string(),
            default_session_ttl_blocks: WALLET_SDK_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS,
            default_quote_ttl_blocks: WALLET_SDK_GATEWAY_DEFAULT_QUOTE_TTL_BLOCKS,
            default_builder_ttl_blocks: WALLET_SDK_GATEWAY_DEFAULT_BUILDER_TTL_BLOCKS,
            default_contract_ttl_blocks: WALLET_SDK_GATEWAY_DEFAULT_CONTRACT_TTL_BLOCKS,
            default_disclosure_ttl_blocks: WALLET_SDK_GATEWAY_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            default_offline_signing_ttl_blocks:
                WALLET_SDK_GATEWAY_DEFAULT_OFFLINE_SIGNING_TTL_BLOCKS,
            default_rate_limit_window_blocks: WALLET_SDK_GATEWAY_DEFAULT_RATE_LIMIT_WINDOW_BLOCKS,
            default_recovery_timelock_blocks: WALLET_SDK_GATEWAY_DEFAULT_RECOVERY_TIMELOCK_BLOCKS,
            default_fee_asset_id: WALLET_SDK_GATEWAY_DEFAULT_LOW_FEE_ASSET_ID.to_string(),
            monero_network: WALLET_SDK_GATEWAY_DEFAULT_MONERO_NETWORK.to_string(),
            min_pq_security_bits: WALLET_SDK_GATEWAY_MIN_PQ_SECURITY_BITS,
            max_rebate_bps: WALLET_SDK_GATEWAY_MAX_BPS,
            max_profiles: WALLET_SDK_GATEWAY_MAX_PROFILES,
            max_sessions: WALLET_SDK_GATEWAY_MAX_SESSIONS,
            max_bridge_profiles: WALLET_SDK_GATEWAY_MAX_BRIDGE_PROFILES,
            max_quotes: WALLET_SDK_GATEWAY_MAX_QUOTES,
            max_builder_intents: WALLET_SDK_GATEWAY_MAX_BUILDER_INTENTS,
            max_contract_manifests: WALLET_SDK_GATEWAY_MAX_CONTRACT_MANIFESTS,
            max_recovery_policies: WALLET_SDK_GATEWAY_MAX_RECOVERY_POLICIES,
            max_disclosure_tickets: WALLET_SDK_GATEWAY_MAX_DISCLOSURE_TICKETS,
            max_rate_limits: WALLET_SDK_GATEWAY_MAX_RATE_LIMITS,
            max_offline_signing_bundles: WALLET_SDK_GATEWAY_MAX_OFFLINE_BUNDLES,
            max_compatibility_manifests: WALLET_SDK_GATEWAY_MAX_COMPATIBILITY_MANIFESTS,
            max_public_records: WALLET_SDK_GATEWAY_MAX_PUBLIC_RECORDS,
            require_pq_auth_for_private_builders: true,
            require_pq_auth_for_contract_calls: true,
            enable_view_only_bridge_profiles: true,
        }
    }
}

impl WalletSdkGatewayConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_sdk_gateway_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "security_model": self.security_model,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_quote_ttl_blocks": self.default_quote_ttl_blocks,
            "default_builder_ttl_blocks": self.default_builder_ttl_blocks,
            "default_contract_ttl_blocks": self.default_contract_ttl_blocks,
            "default_disclosure_ttl_blocks": self.default_disclosure_ttl_blocks,
            "default_offline_signing_ttl_blocks": self.default_offline_signing_ttl_blocks,
            "default_rate_limit_window_blocks": self.default_rate_limit_window_blocks,
            "default_recovery_timelock_blocks": self.default_recovery_timelock_blocks,
            "default_fee_asset_id": self.default_fee_asset_id,
            "monero_network": self.monero_network,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_rebate_bps": self.max_rebate_bps,
            "max_profiles": self.max_profiles,
            "max_sessions": self.max_sessions,
            "max_bridge_profiles": self.max_bridge_profiles,
            "max_quotes": self.max_quotes,
            "max_builder_intents": self.max_builder_intents,
            "max_contract_manifests": self.max_contract_manifests,
            "max_recovery_policies": self.max_recovery_policies,
            "max_disclosure_tickets": self.max_disclosure_tickets,
            "max_rate_limits": self.max_rate_limits,
            "max_offline_signing_bundles": self.max_offline_signing_bundles,
            "max_compatibility_manifests": self.max_compatibility_manifests,
            "max_public_records": self.max_public_records,
            "require_pq_auth_for_private_builders": self.require_pq_auth_for_private_builders,
            "require_pq_auth_for_contract_calls": self.require_pq_auth_for_contract_calls,
            "enable_view_only_bridge_profiles": self.enable_view_only_bridge_profiles,
        })
    }

    pub fn config_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-GATEWAY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_eq_str(
            &self.protocol_version,
            WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "wallet sdk gateway protocol version",
        )?;
        ensure_eq_str(
            &self.security_model,
            WALLET_SDK_GATEWAY_SECURITY_MODEL,
            "wallet sdk gateway security model",
        )?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "wallet sdk default fee asset id",
        )?;
        ensure_non_empty(&self.monero_network, "wallet sdk monero network")?;
        if self.default_session_ttl_blocks == 0 {
            return Err("wallet sdk default session ttl must be positive".to_string());
        }
        if self.default_quote_ttl_blocks == 0 {
            return Err("wallet sdk default quote ttl must be positive".to_string());
        }
        if self.default_rate_limit_window_blocks == 0 {
            return Err("wallet sdk default rate limit window must be positive".to_string());
        }
        if self.min_pq_security_bits < WALLET_SDK_GATEWAY_MIN_PQ_SECURITY_BITS {
            return Err("wallet sdk pq security bits below devnet minimum".to_string());
        }
        if self.max_rebate_bps > WALLET_SDK_GATEWAY_MAX_BPS {
            return Err("wallet sdk max rebate bps exceeds 10000".to_string());
        }
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletClientProfile {
    pub profile_id: String,
    pub client_label: String,
    pub client_kind: WalletSdkClientKind,
    pub sdk_name: String,
    pub sdk_semver: String,
    pub account_commitment: String,
    pub device_commitment: String,
    pub spend_authority_root: String,
    pub view_authority_root: String,
    pub capability_root: String,
    pub capabilities: BTreeSet<WalletSdkCapability>,
    pub default_fee_asset_id: String,
    pub created_at_height: u64,
    pub last_seen_height: u64,
    pub status: WalletSdkGatewayStatus,
    pub metadata_root: String,
}

impl WalletClientProfile {
    pub fn deterministic(
        client_label: &str,
        client_kind: WalletSdkClientKind,
        sdk_name: &str,
        sdk_semver: &str,
        default_fee_asset_id: &str,
        created_at_height: u64,
        capabilities: Vec<WalletSdkCapability>,
        metadata: &Value,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(client_label, "wallet client label")?;
        ensure_non_empty(sdk_name, "wallet sdk name")?;
        ensure_non_empty(sdk_semver, "wallet sdk semver")?;
        ensure_non_empty(default_fee_asset_id, "wallet client default fee asset id")?;
        let capability_set = capabilities.into_iter().collect::<BTreeSet<_>>();
        ensure_non_empty_set(&capability_set, "wallet client capabilities")?;
        let account_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-ACCOUNT-COMMITMENT",
            &json!({
                "client_label": client_label,
                "client_kind": client_kind.as_str(),
                "height": created_at_height,
            }),
        );
        let device_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-DEVICE-COMMITMENT",
            &json!({
                "client_label": client_label,
                "sdk_name": sdk_name,
                "sdk_semver": sdk_semver,
                "height": created_at_height,
            }),
        );
        let spend_authority_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-SPEND-AUTHORITY",
            &json!({
                "profile": client_label,
                "authority": "shielded-spend-authority",
                "pq_required": true,
            }),
        );
        let view_authority_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-VIEW-AUTHORITY",
            &json!({
                "profile": client_label,
                "authority": "view-only-bridge-authority",
                "spend_key_absent": true,
            }),
        );
        let capability_root = wallet_sdk_capability_root(&capability_set);
        let metadata_root =
            wallet_sdk_gateway_payload_root("WALLET-SDK-PROFILE-METADATA", metadata);
        let profile_id = wallet_sdk_client_profile_id(
            client_label,
            &client_kind,
            &account_commitment,
            &device_commitment,
            created_at_height,
        );
        let profile = Self {
            profile_id,
            client_label: client_label.to_string(),
            client_kind,
            sdk_name: sdk_name.to_string(),
            sdk_semver: sdk_semver.to_string(),
            account_commitment,
            device_commitment,
            spend_authority_root,
            view_authority_root,
            capability_root,
            capabilities: capability_set,
            default_fee_asset_id: default_fee_asset_id.to_string(),
            created_at_height,
            last_seen_height: created_at_height,
            status: WalletSdkGatewayStatus::Active,
            metadata_root,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn supports(&self, capability: &WalletSdkCapability) -> bool {
        self.capabilities.contains(capability)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_client_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "profile_id": self.profile_id,
            "client_label": self.client_label,
            "client_kind": self.client_kind.as_str(),
            "sdk_name": self.sdk_name,
            "sdk_semver": self.sdk_semver,
            "account_commitment": self.account_commitment,
            "device_commitment": self.device_commitment,
            "spend_authority_root": self.spend_authority_root,
            "view_authority_root": self.view_authority_root,
            "capability_root": self.capability_root,
            "capabilities": capability_names(&self.capabilities),
            "default_fee_asset_id": self.default_fee_asset_id,
            "created_at_height": self.created_at_height,
            "last_seen_height": self.last_seen_height,
            "status": self.status.as_str(),
            "metadata_root": self.metadata_root,
        })
    }

    pub fn profile_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-CLIENT-PROFILE", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.profile_id, "wallet client profile id")?;
        ensure_non_empty(&self.client_label, "wallet client label")?;
        ensure_non_empty(&self.sdk_name, "wallet sdk name")?;
        ensure_non_empty(&self.sdk_semver, "wallet sdk semver")?;
        ensure_non_empty(&self.account_commitment, "wallet account commitment")?;
        ensure_non_empty(&self.device_commitment, "wallet device commitment")?;
        ensure_non_empty(&self.spend_authority_root, "wallet spend authority root")?;
        ensure_non_empty(&self.view_authority_root, "wallet view authority root")?;
        ensure_non_empty(&self.capability_root, "wallet capability root")?;
        ensure_non_empty_set(&self.capabilities, "wallet client capabilities")?;
        ensure_non_empty(&self.default_fee_asset_id, "wallet default fee asset id")?;
        ensure_non_empty(&self.metadata_root, "wallet profile metadata root")?;
        if self.last_seen_height < self.created_at_height {
            return Err("wallet client last seen height precedes creation".to_string());
        }
        let expected = wallet_sdk_client_profile_id(
            &self.client_label,
            &self.client_kind,
            &self.account_commitment,
            &self.device_commitment,
            self.created_at_height,
        );
        ensure_eq_str(&self.profile_id, &expected, "wallet client profile id")?;
        Ok(self.profile_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAuthenticatedSession {
    pub session_id: String,
    pub profile_id: String,
    pub purpose: PqSessionPurpose,
    pub peer_label: String,
    pub suite: String,
    pub ml_kem_key_root: String,
    pub ml_dsa_key_root: String,
    pub slh_dsa_key_root: String,
    pub kem_ciphertext_root: String,
    pub transcript_root: String,
    pub auth_root: String,
    pub replay_nonce_root: String,
    pub encrypted_channel_root: String,
    pub grants: BTreeSet<String>,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub security_bits: u16,
    pub status: WalletSdkGatewayStatus,
}

impl PqAuthenticatedSession {
    pub fn deterministic(
        profile_id: &str,
        purpose: PqSessionPurpose,
        peer_label: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "pq session profile id")?;
        ensure_non_empty(peer_label, "pq session peer label")?;
        if ttl_blocks == 0 {
            return Err("pq session ttl must be positive".to_string());
        }
        let suite = WALLET_SDK_GATEWAY_PQ_SUITE.to_string();
        let ml_kem_key_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-ML-KEM-KEY",
            &json!({
                "profile_id": profile_id,
                "peer_label": peer_label,
                "purpose": purpose.as_str(),
                "nonce": nonce,
            }),
        );
        let ml_dsa_key_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-ML-DSA-KEY",
            &json!({
                "profile_id": profile_id,
                "peer_label": peer_label,
                "purpose": purpose.as_str(),
                "nonce": nonce,
            }),
        );
        let slh_dsa_key_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-SLH-DSA-KEY",
            &json!({
                "profile_id": profile_id,
                "peer_label": peer_label,
                "purpose": purpose.as_str(),
                "nonce": nonce,
            }),
        );
        let kem_ciphertext_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-KEM-CIPHERTEXT",
            &json!({
                "profile_id": profile_id,
                "peer_label": peer_label,
                "opened_at_height": opened_at_height,
                "nonce": nonce,
            }),
        );
        let replay_nonce_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-REPLAY-NONCE",
            &json!({
                "profile_id": profile_id,
                "purpose": purpose.as_str(),
                "opened_at_height": opened_at_height,
                "nonce": nonce,
            }),
        );
        let transcript_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-SESSION-TRANSCRIPT",
            &json!({
                "profile_id": profile_id,
                "purpose": purpose.as_str(),
                "peer_label": peer_label,
                "suite": suite,
                "ml_kem_key_root": ml_kem_key_root,
                "ml_dsa_key_root": ml_dsa_key_root,
                "slh_dsa_key_root": slh_dsa_key_root,
                "kem_ciphertext_root": kem_ciphertext_root,
                "replay_nonce_root": replay_nonce_root,
                "opened_at_height": opened_at_height,
                "expires_at_height": opened_at_height.saturating_add(ttl_blocks),
            }),
        );
        let auth_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-AUTH",
            &json!({
                "profile_id": profile_id,
                "transcript_root": transcript_root,
                "ml_dsa_required": true,
                "slh_dsa_recovery_witness": true,
            }),
        );
        let encrypted_channel_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-ENCRYPTED-CHANNEL",
            &json!({
                "profile_id": profile_id,
                "transcript_root": transcript_root,
                "kem_ciphertext_root": kem_ciphertext_root,
                "lane": "sdk-gateway-private-payloads",
            }),
        );
        let mut grants = BTreeSet::new();
        grants.insert(purpose.as_str().to_string());
        grants.insert("selective_payload_encryption".to_string());
        let session_id = wallet_sdk_pq_session_id(
            profile_id,
            &purpose,
            peer_label,
            &transcript_root,
            opened_at_height,
            nonce,
        );
        let session = Self {
            session_id,
            profile_id: profile_id.to_string(),
            purpose,
            peer_label: peer_label.to_string(),
            suite,
            ml_kem_key_root,
            ml_dsa_key_root,
            slh_dsa_key_root,
            kem_ciphertext_root,
            transcript_root,
            auth_root,
            replay_nonce_root,
            encrypted_channel_root,
            grants,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            security_bits: WALLET_SDK_GATEWAY_MIN_PQ_SECURITY_BITS,
            status: WalletSdkGatewayStatus::Active,
        };
        session.validate()?;
        Ok(session)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_authenticated_session",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "session_id": self.session_id,
            "profile_id": self.profile_id,
            "purpose": self.purpose.as_str(),
            "peer_label": self.peer_label,
            "suite": self.suite,
            "ml_kem_key_root": self.ml_kem_key_root,
            "ml_dsa_key_root": self.ml_dsa_key_root,
            "slh_dsa_key_root": self.slh_dsa_key_root,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "transcript_root": self.transcript_root,
            "auth_root": self.auth_root,
            "replay_nonce_root": self.replay_nonce_root,
            "encrypted_channel_root": self.encrypted_channel_root,
            "grants": self.grants,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "security_bits": self.security_bits,
            "status": self.status.as_str(),
        })
    }

    pub fn session_root(&self) -> String {
        wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PQ-AUTHENTICATED-SESSION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.session_id, "pq session id")?;
        ensure_non_empty(&self.profile_id, "pq session profile id")?;
        ensure_non_empty(&self.peer_label, "pq session peer label")?;
        ensure_eq_str(&self.suite, WALLET_SDK_GATEWAY_PQ_SUITE, "pq session suite")?;
        ensure_non_empty(&self.ml_kem_key_root, "pq session ml kem key root")?;
        ensure_non_empty(&self.ml_dsa_key_root, "pq session ml dsa key root")?;
        ensure_non_empty(&self.slh_dsa_key_root, "pq session slh dsa key root")?;
        ensure_non_empty(&self.kem_ciphertext_root, "pq session kem ciphertext root")?;
        ensure_non_empty(&self.transcript_root, "pq session transcript root")?;
        ensure_non_empty(&self.auth_root, "pq session auth root")?;
        ensure_non_empty(&self.replay_nonce_root, "pq session replay nonce root")?;
        ensure_non_empty(
            &self.encrypted_channel_root,
            "pq session encrypted channel root",
        )?;
        ensure_non_empty_set(&self.grants, "pq session grants")?;
        ensure_height_window(
            self.opened_at_height,
            self.expires_at_height,
            "pq authenticated session",
        )?;
        if self.security_bits < WALLET_SDK_GATEWAY_MIN_PQ_SECURITY_BITS {
            return Err("pq session security bits below gateway minimum".to_string());
        }
        Ok(self.session_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewOnlyMoneroBridgeProfile {
    pub bridge_profile_id: String,
    pub profile_id: String,
    pub mode: MoneroBridgeProfileMode,
    pub monero_network: String,
    pub bridge_address_commitment: String,
    pub private_view_key_commitment: String,
    pub view_tag_root: String,
    pub scan_from_height: u64,
    pub scan_tip_height: u64,
    pub allowed_scopes: BTreeSet<String>,
    pub spend_key_absent: bool,
    pub bridge_operator_id: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: WalletSdkGatewayStatus,
}

impl ViewOnlyMoneroBridgeProfile {
    pub fn deterministic_view_only(
        profile_id: &str,
        monero_network: &str,
        bridge_operator_id: &str,
        scan_from_height: u64,
        scan_tip_height: u64,
        allowed_scopes: Vec<String>,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "view only bridge profile id")?;
        ensure_non_empty(monero_network, "view only bridge monero network")?;
        ensure_non_empty(bridge_operator_id, "view only bridge operator id")?;
        if scan_tip_height < scan_from_height {
            return Err("view only bridge scan tip precedes scan start".to_string());
        }
        if ttl_blocks == 0 {
            return Err("view only bridge ttl must be positive".to_string());
        }
        let scope_set = allowed_scopes.into_iter().collect::<BTreeSet<_>>();
        ensure_non_empty_set(&scope_set, "view only bridge scopes")?;
        let bridge_address_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-MONERO-BRIDGE-ADDRESS",
            &json!({
                "profile_id": profile_id,
                "monero_network": monero_network,
                "bridge_operator_id": bridge_operator_id,
                "nonce": nonce,
            }),
        );
        let private_view_key_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-MONERO-VIEW-KEY",
            &json!({
                "profile_id": profile_id,
                "monero_network": monero_network,
                "view_only": true,
                "nonce": nonce,
            }),
        );
        let view_tag_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-MONERO-VIEW-TAGS",
            &json!({
                "profile_id": profile_id,
                "scan_from_height": scan_from_height,
                "scan_tip_height": scan_tip_height,
                "scopes": scope_set,
            }),
        );
        let bridge_profile_id = wallet_sdk_monero_bridge_profile_id(
            profile_id,
            monero_network,
            &bridge_address_commitment,
            &private_view_key_commitment,
            created_at_height,
            nonce,
        );
        let profile = Self {
            bridge_profile_id,
            profile_id: profile_id.to_string(),
            mode: MoneroBridgeProfileMode::ViewOnly,
            monero_network: monero_network.to_string(),
            bridge_address_commitment,
            private_view_key_commitment,
            view_tag_root,
            scan_from_height,
            scan_tip_height,
            allowed_scopes: scope_set,
            spend_key_absent: true,
            bridge_operator_id: bridge_operator_id.to_string(),
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: WalletSdkGatewayStatus::Active,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_only_monero_bridge_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "bridge_profile_id": self.bridge_profile_id,
            "profile_id": self.profile_id,
            "mode": self.mode.as_str(),
            "monero_network": self.monero_network,
            "bridge_address_commitment": self.bridge_address_commitment,
            "private_view_key_commitment": self.private_view_key_commitment,
            "view_tag_root": self.view_tag_root,
            "scan_from_height": self.scan_from_height,
            "scan_tip_height": self.scan_tip_height,
            "allowed_scopes": self.allowed_scopes,
            "spend_key_absent": self.spend_key_absent,
            "bridge_operator_id": self.bridge_operator_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn bridge_profile_root(&self) -> String {
        wallet_sdk_gateway_payload_root(
            "WALLET-SDK-VIEW-ONLY-MONERO-BRIDGE-PROFILE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.bridge_profile_id, "view only bridge profile id")?;
        ensure_non_empty(&self.profile_id, "view only bridge owner profile id")?;
        ensure_non_empty(&self.monero_network, "view only bridge monero network")?;
        ensure_non_empty(
            &self.bridge_address_commitment,
            "view only bridge address commitment",
        )?;
        ensure_non_empty(
            &self.private_view_key_commitment,
            "view only bridge private view key commitment",
        )?;
        ensure_non_empty(&self.view_tag_root, "view only bridge view tag root")?;
        ensure_non_empty_set(&self.allowed_scopes, "view only bridge scopes")?;
        ensure_non_empty(&self.bridge_operator_id, "view only bridge operator id")?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "view only bridge profile",
        )?;
        if !self.spend_key_absent {
            return Err("view only bridge profile must not retain spend key material".to_string());
        }
        if self.scan_tip_height < self.scan_from_height {
            return Err("view only bridge scan tip precedes scan start".to_string());
        }
        Ok(self.bridge_profile_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeQuoteEnvelope {
    pub quote_id: String,
    pub profile_id: String,
    pub session_id: Option<String>,
    pub lane_id: String,
    pub strategy: LowFeeQuoteStrategy,
    pub fee_asset_id: String,
    pub base_fee_units: u64,
    pub privacy_surcharge_units: u64,
    pub sponsor_discount_units: u64,
    pub quoted_fee_units: u64,
    pub max_total_fee_units: u64,
    pub rebate_bps: u64,
    pub speed_target_blocks: u64,
    pub proof_size_bucket: String,
    pub quote_commitment_root: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: WalletSdkGatewayStatus,
}

impl LowFeeQuoteEnvelope {
    pub fn deterministic(
        profile_id: &str,
        session_id: Option<String>,
        lane_id: &str,
        strategy: LowFeeQuoteStrategy,
        fee_asset_id: &str,
        base_fee_units: u64,
        privacy_surcharge_units: u64,
        sponsor_discount_units: u64,
        valid_from_height: u64,
        ttl_blocks: u64,
        speed_target_blocks: u64,
        proof_size_bucket: &str,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "low fee quote profile id")?;
        ensure_non_empty(lane_id, "low fee quote lane id")?;
        ensure_non_empty(fee_asset_id, "low fee quote fee asset id")?;
        ensure_non_empty(proof_size_bucket, "low fee quote proof size bucket")?;
        if ttl_blocks == 0 {
            return Err("low fee quote ttl must be positive".to_string());
        }
        let undiscounted = base_fee_units.saturating_add(privacy_surcharge_units);
        if sponsor_discount_units > undiscounted {
            return Err("low fee quote sponsor discount exceeds undiscounted fee".to_string());
        }
        let quoted_fee_units = undiscounted.saturating_sub(sponsor_discount_units);
        let rebate_bps = if undiscounted == 0 {
            0
        } else {
            ((sponsor_discount_units as u128 * WALLET_SDK_GATEWAY_MAX_BPS as u128)
                / undiscounted as u128) as u64
        };
        let quote_commitment_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-LOW-FEE-QUOTE-COMMITMENT",
            &json!({
                "profile_id": profile_id,
                "session_id": session_id,
                "lane_id": lane_id,
                "strategy": strategy.as_str(),
                "fee_asset_id": fee_asset_id,
                "quoted_fee_units": quoted_fee_units,
                "speed_target_blocks": speed_target_blocks,
                "proof_size_bucket": proof_size_bucket,
                "nonce": nonce,
            }),
        );
        let quote_id = wallet_sdk_low_fee_quote_id(
            profile_id,
            lane_id,
            &strategy,
            &quote_commitment_root,
            valid_from_height,
            nonce,
        );
        let quote = Self {
            quote_id,
            profile_id: profile_id.to_string(),
            session_id,
            lane_id: lane_id.to_string(),
            strategy,
            fee_asset_id: fee_asset_id.to_string(),
            base_fee_units,
            privacy_surcharge_units,
            sponsor_discount_units,
            quoted_fee_units,
            max_total_fee_units: quoted_fee_units.saturating_add(privacy_surcharge_units / 4),
            rebate_bps,
            speed_target_blocks,
            proof_size_bucket: proof_size_bucket.to_string(),
            quote_commitment_root,
            valid_from_height,
            expires_at_height: valid_from_height.saturating_add(ttl_blocks),
            status: WalletSdkGatewayStatus::Quoted,
        };
        quote.validate()?;
        Ok(quote)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height >= self.valid_from_height && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_quote_envelope",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "quote_id": self.quote_id,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "lane_id": self.lane_id,
            "strategy": self.strategy.as_str(),
            "strategy_version": WALLET_SDK_GATEWAY_LOW_FEE_STRATEGY,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_units": self.base_fee_units,
            "privacy_surcharge_units": self.privacy_surcharge_units,
            "sponsor_discount_units": self.sponsor_discount_units,
            "quoted_fee_units": self.quoted_fee_units,
            "max_total_fee_units": self.max_total_fee_units,
            "rebate_bps": self.rebate_bps,
            "speed_target_blocks": self.speed_target_blocks,
            "proof_size_bucket": self.proof_size_bucket,
            "quote_commitment_root": self.quote_commitment_root,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn quote_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-LOW-FEE-QUOTE", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.quote_id, "low fee quote id")?;
        ensure_non_empty(&self.profile_id, "low fee quote profile id")?;
        ensure_non_empty(&self.lane_id, "low fee quote lane id")?;
        ensure_non_empty(&self.fee_asset_id, "low fee quote fee asset id")?;
        ensure_non_empty(&self.proof_size_bucket, "low fee quote proof size bucket")?;
        ensure_non_empty(&self.quote_commitment_root, "low fee quote commitment root")?;
        ensure_height_window(
            self.valid_from_height,
            self.expires_at_height,
            "low fee quote",
        )?;
        let undiscounted = self
            .base_fee_units
            .saturating_add(self.privacy_surcharge_units);
        if self.sponsor_discount_units > undiscounted {
            return Err("low fee quote discount exceeds fee".to_string());
        }
        let expected_quote = undiscounted.saturating_sub(self.sponsor_discount_units);
        if self.quoted_fee_units != expected_quote {
            return Err("low fee quote units mismatch".to_string());
        }
        if self.max_total_fee_units < self.quoted_fee_units {
            return Err("low fee quote max total below quoted fee".to_string());
        }
        if self.rebate_bps > WALLET_SDK_GATEWAY_MAX_BPS {
            return Err("low fee quote rebate bps exceeds 10000".to_string());
        }
        Ok(self.quote_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTxBuilderIntent {
    pub builder_intent_id: String,
    pub profile_id: String,
    pub session_id: Option<String>,
    pub intent_kind: PrivateTxIntentKind,
    pub privacy_level: TxPrivacyLevel,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub recipient_commitment: String,
    pub change_commitment: String,
    pub nullifier_set_root: String,
    pub encrypted_memo_root: String,
    pub route_hint_root: String,
    pub fee_quote_id: Option<String>,
    pub requires_offline_signing: bool,
    pub created_at_height: u64,
    pub deadline_height: u64,
    pub status: WalletSdkGatewayStatus,
}

impl PrivateTxBuilderIntent {
    pub fn deterministic(
        profile_id: &str,
        session_id: Option<String>,
        intent_kind: PrivateTxIntentKind,
        privacy_level: TxPrivacyLevel,
        asset_id: &str,
        amount_bucket: u64,
        fee_quote_id: Option<String>,
        requires_offline_signing: bool,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "private tx builder profile id")?;
        ensure_non_empty(asset_id, "private tx builder asset id")?;
        if amount_bucket == 0 {
            return Err("private tx builder amount bucket must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("private tx builder ttl must be positive".to_string());
        }
        let recipient_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-RECIPIENT",
            &json!({
                "profile_id": profile_id,
                "intent_kind": intent_kind.as_str(),
                "asset_id": asset_id,
                "amount_bucket": amount_bucket,
                "nonce": nonce,
            }),
        );
        let change_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-CHANGE",
            &json!({
                "profile_id": profile_id,
                "asset_id": asset_id,
                "privacy_level": privacy_level.as_str(),
                "nonce": nonce,
            }),
        );
        let nullifier_set_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-NULLIFIERS",
            &json!({
                "profile_id": profile_id,
                "intent_kind": intent_kind.as_str(),
                "nonce": nonce,
            }),
        );
        let encrypted_memo_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-ENCRYPTED-MEMO",
            &json!({
                "profile_id": profile_id,
                "session_id": session_id,
                "memo": "deterministic-devnet-encrypted-memo",
                "nonce": nonce,
            }),
        );
        let route_hint_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-ROUTE-HINT",
            &json!({
                "intent_kind": intent_kind.as_str(),
                "privacy_level": privacy_level.as_str(),
                "lane": WALLET_SDK_GATEWAY_DEFAULT_FAST_LANE_ID,
                "nonce": nonce,
            }),
        );
        let builder_intent_id = wallet_sdk_private_tx_builder_intent_id(
            profile_id,
            &intent_kind,
            &privacy_level,
            &recipient_commitment,
            created_at_height,
            nonce,
        );
        let intent = Self {
            builder_intent_id,
            profile_id: profile_id.to_string(),
            session_id,
            intent_kind,
            privacy_level,
            asset_id: asset_id.to_string(),
            amount_bucket,
            recipient_commitment,
            change_commitment,
            nullifier_set_root,
            encrypted_memo_root,
            route_hint_root,
            fee_quote_id,
            requires_offline_signing,
            created_at_height,
            deadline_height: created_at_height.saturating_add(ttl_blocks),
            status: WalletSdkGatewayStatus::Prepared,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.deadline_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_tx_builder_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "builder_intent_id": self.builder_intent_id,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "intent_kind": self.intent_kind.as_str(),
            "privacy_level": self.privacy_level.as_str(),
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "recipient_commitment": self.recipient_commitment,
            "change_commitment": self.change_commitment,
            "nullifier_set_root": self.nullifier_set_root,
            "encrypted_memo_root": self.encrypted_memo_root,
            "route_hint_root": self.route_hint_root,
            "fee_quote_id": self.fee_quote_id,
            "requires_offline_signing": self.requires_offline_signing,
            "created_at_height": self.created_at_height,
            "deadline_height": self.deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        wallet_sdk_gateway_payload_root(
            "WALLET-SDK-PRIVATE-TX-BUILDER-INTENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.builder_intent_id, "private tx builder intent id")?;
        ensure_non_empty(&self.profile_id, "private tx builder profile id")?;
        ensure_non_empty(&self.asset_id, "private tx builder asset id")?;
        if self.amount_bucket == 0 {
            return Err("private tx builder amount bucket must be positive".to_string());
        }
        ensure_non_empty(
            &self.recipient_commitment,
            "private tx builder recipient commitment",
        )?;
        ensure_non_empty(
            &self.change_commitment,
            "private tx builder change commitment",
        )?;
        ensure_non_empty(
            &self.nullifier_set_root,
            "private tx builder nullifier root",
        )?;
        ensure_non_empty(&self.encrypted_memo_root, "private tx builder memo root")?;
        ensure_non_empty(&self.route_hint_root, "private tx builder route hint root")?;
        ensure_height_window(
            self.created_at_height,
            self.deadline_height,
            "private tx builder intent",
        )?;
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartContractCallManifest {
    pub manifest_id: String,
    pub profile_id: String,
    pub session_id: Option<String>,
    pub call_kind: SmartContractCallKind,
    pub contract_label: String,
    pub contract_address_commitment: String,
    pub method_selector_root: String,
    pub calldata_root: String,
    pub encrypted_witness_root: String,
    pub value_asset_id: Option<String>,
    pub value_amount_bucket: u64,
    pub gas_limit: u64,
    pub max_fee_units: u64,
    pub allow_private_orderflow: bool,
    pub dependency_root: String,
    pub dependency_ids: BTreeSet<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub status: WalletSdkGatewayStatus,
}

impl SmartContractCallManifest {
    pub fn deterministic(
        profile_id: &str,
        session_id: Option<String>,
        call_kind: SmartContractCallKind,
        contract_label: &str,
        value_asset_id: Option<String>,
        value_amount_bucket: u64,
        gas_limit: u64,
        max_fee_units: u64,
        dependency_ids: Vec<String>,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "contract manifest profile id")?;
        ensure_non_empty(contract_label, "contract manifest label")?;
        if gas_limit == 0 {
            return Err("contract manifest gas limit must be positive".to_string());
        }
        if max_fee_units == 0 {
            return Err("contract manifest max fee must be positive".to_string());
        }
        if ttl_blocks == 0 {
            return Err("contract manifest ttl must be positive".to_string());
        }
        let dependency_set = dependency_ids.into_iter().collect::<BTreeSet<_>>();
        let contract_address_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-CONTRACT-ADDRESS",
            &json!({
                "profile_id": profile_id,
                "contract_label": contract_label,
                "nonce": nonce,
            }),
        );
        let method_selector_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-CONTRACT-METHOD-SELECTOR",
            &json!({
                "contract_label": contract_label,
                "call_kind": call_kind.as_str(),
                "nonce": nonce,
            }),
        );
        let calldata_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-CONTRACT-CALLDATA",
            &json!({
                "profile_id": profile_id,
                "call_kind": call_kind.as_str(),
                "privacy_preserving": true,
                "nonce": nonce,
            }),
        );
        let encrypted_witness_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-CONTRACT-ENCRYPTED-WITNESS",
            &json!({
                "profile_id": profile_id,
                "session_id": session_id,
                "requires_private_witness": call_kind.requires_private_witness(),
                "nonce": nonce,
            }),
        );
        let dependency_root =
            wallet_sdk_string_set_root("WALLET-SDK-CONTRACT-DEPENDENCIES", &dependency_set);
        let manifest_id = wallet_sdk_contract_call_manifest_id(
            profile_id,
            &call_kind,
            &contract_address_commitment,
            &method_selector_root,
            created_at_height,
            nonce,
        );
        let manifest = Self {
            manifest_id,
            profile_id: profile_id.to_string(),
            session_id,
            call_kind,
            contract_label: contract_label.to_string(),
            contract_address_commitment,
            method_selector_root,
            calldata_root,
            encrypted_witness_root,
            value_asset_id,
            value_amount_bucket,
            gas_limit,
            max_fee_units,
            allow_private_orderflow: true,
            dependency_root,
            dependency_ids: dependency_set,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            status: WalletSdkGatewayStatus::Prepared,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "smart_contract_call_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "manifest_id": self.manifest_id,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "call_kind": self.call_kind.as_str(),
            "contract_label": self.contract_label,
            "contract_address_commitment": self.contract_address_commitment,
            "method_selector_root": self.method_selector_root,
            "calldata_root": self.calldata_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "value_asset_id": self.value_asset_id,
            "value_amount_bucket": self.value_amount_bucket,
            "gas_limit": self.gas_limit,
            "max_fee_units": self.max_fee_units,
            "allow_private_orderflow": self.allow_private_orderflow,
            "dependency_root": self.dependency_root,
            "dependency_ids": self.dependency_ids,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        wallet_sdk_gateway_payload_root(
            "WALLET-SDK-SMART-CONTRACT-CALL-MANIFEST",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.manifest_id, "contract call manifest id")?;
        ensure_non_empty(&self.profile_id, "contract call profile id")?;
        ensure_non_empty(&self.contract_label, "contract call label")?;
        ensure_non_empty(
            &self.contract_address_commitment,
            "contract address commitment",
        )?;
        ensure_non_empty(&self.method_selector_root, "contract method selector root")?;
        ensure_non_empty(&self.calldata_root, "contract calldata root")?;
        ensure_non_empty(
            &self.encrypted_witness_root,
            "contract encrypted witness root",
        )?;
        ensure_non_empty(&self.dependency_root, "contract dependency root")?;
        if self.gas_limit == 0 {
            return Err("contract call gas limit must be positive".to_string());
        }
        if self.max_fee_units == 0 {
            return Err("contract call max fee units must be positive".to_string());
        }
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "smart contract call manifest",
        )?;
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub policy_id: String,
    pub profile_id: String,
    pub policy_kind: RecoveryPolicyKind,
    pub guardian_set_root: String,
    pub guardian_count: u64,
    pub threshold: u64,
    pub timelock_blocks: u64,
    pub cold_storage_commitment: String,
    pub pq_recovery_key_root: String,
    pub allowed_recovery_scopes: BTreeSet<String>,
    pub last_rotated_height: u64,
    pub status: WalletSdkGatewayStatus,
}

impl RecoveryPolicy {
    pub fn deterministic(
        profile_id: &str,
        policy_kind: RecoveryPolicyKind,
        guardian_labels: Vec<String>,
        threshold: u64,
        timelock_blocks: u64,
        last_rotated_height: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "recovery policy profile id")?;
        if guardian_labels.is_empty() {
            return Err("recovery policy guardian labels cannot be empty".to_string());
        }
        let guardian_set = guardian_labels.into_iter().collect::<BTreeSet<_>>();
        if threshold == 0 || threshold > guardian_set.len() as u64 {
            return Err("recovery policy threshold must be within guardian count".to_string());
        }
        let guardian_set_root =
            wallet_sdk_string_set_root("WALLET-SDK-RECOVERY-GUARDIANS", &guardian_set);
        let cold_storage_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-RECOVERY-COLD-STORAGE",
            &json!({
                "profile_id": profile_id,
                "policy_kind": policy_kind.as_str(),
                "nonce": nonce,
            }),
        );
        let pq_recovery_key_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-RECOVERY-PQ-KEY",
            &json!({
                "profile_id": profile_id,
                "suite": WALLET_SDK_GATEWAY_PQ_SUITE,
                "nonce": nonce,
            }),
        );
        let mut scopes = BTreeSet::new();
        scopes.insert("rotate_pq_session_keys".to_string());
        scopes.insert("replace_view_authority".to_string());
        scopes.insert("freeze_private_builder".to_string());
        let policy_id = wallet_sdk_recovery_policy_id(
            profile_id,
            &policy_kind,
            &guardian_set_root,
            threshold,
            last_rotated_height,
            nonce,
        );
        let policy = Self {
            policy_id,
            profile_id: profile_id.to_string(),
            policy_kind,
            guardian_set_root,
            guardian_count: guardian_set.len() as u64,
            threshold,
            timelock_blocks,
            cold_storage_commitment,
            pq_recovery_key_root,
            allowed_recovery_scopes: scopes,
            last_rotated_height,
            status: WalletSdkGatewayStatus::Active,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_recovery_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "profile_id": self.profile_id,
            "policy_kind": self.policy_kind.as_str(),
            "guardian_set_root": self.guardian_set_root,
            "guardian_count": self.guardian_count,
            "threshold": self.threshold,
            "timelock_blocks": self.timelock_blocks,
            "cold_storage_commitment": self.cold_storage_commitment,
            "pq_recovery_key_root": self.pq_recovery_key_root,
            "allowed_recovery_scopes": self.allowed_recovery_scopes,
            "last_rotated_height": self.last_rotated_height,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-RECOVERY-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.policy_id, "recovery policy id")?;
        ensure_non_empty(&self.profile_id, "recovery policy profile id")?;
        ensure_non_empty(&self.guardian_set_root, "recovery guardian set root")?;
        if self.guardian_count == 0 {
            return Err("recovery policy guardian count must be positive".to_string());
        }
        if self.threshold == 0 || self.threshold > self.guardian_count {
            return Err("recovery policy threshold must be within guardian count".to_string());
        }
        if self.timelock_blocks == 0 {
            return Err("recovery policy timelock must be positive".to_string());
        }
        ensure_non_empty(
            &self.cold_storage_commitment,
            "recovery cold storage commitment",
        )?;
        ensure_non_empty(&self.pq_recovery_key_root, "recovery pq key root")?;
        ensure_non_empty_set(&self.allowed_recovery_scopes, "recovery scopes")?;
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectiveDisclosureTicket {
    pub ticket_id: String,
    pub profile_id: String,
    pub scope: SelectiveDisclosureScope,
    pub subject_kind: String,
    pub subject_id: String,
    pub disclosed_field_root: String,
    pub audience_commitment: String,
    pub redaction_root: String,
    pub proof_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub one_time: bool,
    pub used_at_height: Option<u64>,
    pub status: WalletSdkGatewayStatus,
}

impl SelectiveDisclosureTicket {
    pub fn deterministic(
        profile_id: &str,
        scope: SelectiveDisclosureScope,
        subject_kind: &str,
        subject_id: &str,
        disclosed_fields: Vec<String>,
        audience_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
        one_time: bool,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "disclosure ticket profile id")?;
        ensure_non_empty(subject_kind, "disclosure ticket subject kind")?;
        ensure_non_empty(subject_id, "disclosure ticket subject id")?;
        ensure_non_empty(audience_label, "disclosure ticket audience label")?;
        if ttl_blocks == 0 {
            return Err("disclosure ticket ttl must be positive".to_string());
        }
        let disclosed_field_set = disclosed_fields.into_iter().collect::<BTreeSet<_>>();
        ensure_non_empty_set(&disclosed_field_set, "disclosed fields")?;
        let disclosed_field_root =
            wallet_sdk_string_set_root("WALLET-SDK-DISCLOSED-FIELDS", &disclosed_field_set);
        let audience_commitment = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-DISCLOSURE-AUDIENCE",
            &json!({
                "profile_id": profile_id,
                "audience_label": audience_label,
                "scope": scope.as_str(),
                "nonce": nonce,
            }),
        );
        let redaction_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-DISCLOSURE-REDACTIONS",
            &json!({
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "privacy": "only committed fields leave the wallet",
                "nonce": nonce,
            }),
        );
        let proof_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-DISCLOSURE-PROOF",
            &json!({
                "profile_id": profile_id,
                "scope": scope.as_str(),
                "subject_kind": subject_kind,
                "subject_id": subject_id,
                "disclosed_field_root": disclosed_field_root,
                "audience_commitment": audience_commitment,
                "nonce": nonce,
            }),
        );
        let ticket_id = wallet_sdk_disclosure_ticket_id(
            profile_id,
            &scope,
            subject_kind,
            subject_id,
            &proof_root,
            created_at_height,
            nonce,
        );
        let ticket = Self {
            ticket_id,
            profile_id: profile_id.to_string(),
            scope,
            subject_kind: subject_kind.to_string(),
            subject_id: subject_id.to_string(),
            disclosed_field_root,
            audience_commitment,
            redaction_root,
            proof_root,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            one_time,
            used_at_height: None,
            status: WalletSdkGatewayStatus::Active,
        };
        ticket.validate()?;
        Ok(ticket)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        if !self.status.is_live() || height >= self.expires_at_height {
            return false;
        }
        !(self.one_time && self.used_at_height.is_some())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "selective_disclosure_ticket",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "ticket_id": self.ticket_id,
            "profile_id": self.profile_id,
            "scope": self.scope.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "disclosed_field_root": self.disclosed_field_root,
            "audience_commitment": self.audience_commitment,
            "redaction_root": self.redaction_root,
            "proof_root": self.proof_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "one_time": self.one_time,
            "used_at_height": self.used_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn ticket_root(&self) -> String {
        wallet_sdk_gateway_payload_root(
            "WALLET-SDK-SELECTIVE-DISCLOSURE-TICKET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.ticket_id, "disclosure ticket id")?;
        ensure_non_empty(&self.profile_id, "disclosure ticket profile id")?;
        ensure_non_empty(&self.subject_kind, "disclosure ticket subject kind")?;
        ensure_non_empty(&self.subject_id, "disclosure ticket subject id")?;
        ensure_non_empty(&self.disclosed_field_root, "disclosure field root")?;
        ensure_non_empty(&self.audience_commitment, "disclosure audience commitment")?;
        ensure_non_empty(&self.redaction_root, "disclosure redaction root")?;
        ensure_non_empty(&self.proof_root, "disclosure proof root")?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "selective disclosure ticket",
        )?;
        if let Some(used_at_height) = self.used_at_height {
            if used_at_height < self.created_at_height {
                return Err("disclosure ticket used before creation".to_string());
            }
        }
        Ok(self.ticket_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkRateLimit {
    pub limit_id: String,
    pub profile_id: Option<String>,
    pub bucket_kind: RateLimitBucketKind,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_units: u64,
    pub used_units: u64,
    pub privacy_budget_units: u64,
    pub enforcement_root: String,
    pub status: RateLimitStatus,
}

impl SdkRateLimit {
    pub fn deterministic(
        profile_id: Option<String>,
        bucket_kind: RateLimitBucketKind,
        window_start_height: u64,
        window_blocks: u64,
        max_units: u64,
        used_units: u64,
        privacy_budget_units: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        if window_blocks == 0 {
            return Err("sdk rate limit window must be positive".to_string());
        }
        if max_units == 0 {
            return Err("sdk rate limit max units must be positive".to_string());
        }
        if used_units > max_units {
            return Err("sdk rate limit used units exceeds max units".to_string());
        }
        if privacy_budget_units > max_units {
            return Err("sdk rate limit privacy budget exceeds max units".to_string());
        }
        let enforcement_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-RATE-LIMIT-ENFORCEMENT",
            &json!({
                "profile_id": profile_id,
                "bucket_kind": bucket_kind.as_str(),
                "window_start_height": window_start_height,
                "window_blocks": window_blocks,
                "max_units": max_units,
                "privacy_budget_units": privacy_budget_units,
                "nonce": nonce,
            }),
        );
        let limit_id = wallet_sdk_rate_limit_id(
            profile_id.as_deref(),
            &bucket_kind,
            window_start_height,
            window_start_height.saturating_add(window_blocks),
            &enforcement_root,
            nonce,
        );
        let limit = Self {
            limit_id,
            profile_id,
            bucket_kind,
            window_start_height,
            window_end_height: window_start_height.saturating_add(window_blocks),
            max_units,
            used_units,
            privacy_budget_units,
            enforcement_root,
            status: RateLimitStatus::Active,
        };
        limit.validate()?;
        Ok(limit)
    }

    pub fn remaining_units(&self) -> u64 {
        self.max_units.saturating_sub(self.used_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.window_start_height
            && height < self.window_end_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sdk_rate_limit",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "limit_id": self.limit_id,
            "profile_id": self.profile_id,
            "bucket_kind": self.bucket_kind.as_str(),
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_units": self.max_units,
            "used_units": self.used_units,
            "remaining_units": self.remaining_units(),
            "privacy_budget_units": self.privacy_budget_units,
            "enforcement_root": self.enforcement_root,
            "status": self.status.as_str(),
        })
    }

    pub fn limit_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-RATE-LIMIT", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.limit_id, "sdk rate limit id")?;
        ensure_non_empty(&self.enforcement_root, "sdk rate limit enforcement root")?;
        ensure_height_window(
            self.window_start_height,
            self.window_end_height,
            "sdk rate limit",
        )?;
        if self.max_units == 0 {
            return Err("sdk rate limit max units must be positive".to_string());
        }
        if self.used_units > self.max_units && self.status != RateLimitStatus::Exceeded {
            return Err("sdk rate limit used units exceed max without exceeded status".to_string());
        }
        if self.privacy_budget_units > self.max_units {
            return Err("sdk rate limit privacy budget exceeds max units".to_string());
        }
        Ok(self.limit_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSigningBundle {
    pub bundle_id: String,
    pub profile_id: String,
    pub session_id: Option<String>,
    pub builder_intent_id: Option<String>,
    pub contract_manifest_id: Option<String>,
    pub device_policy_root: String,
    pub unsigned_payload_root: String,
    pub airgap_export_root: String,
    pub hardware_prompt_root: String,
    pub pq_auth_challenge_root: String,
    pub signature_root: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub stage: OfflineSigningStage,
}

impl OfflineSigningBundle {
    pub fn deterministic(
        profile_id: &str,
        session_id: Option<String>,
        builder_intent_id: Option<String>,
        contract_manifest_id: Option<String>,
        device_label: &str,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(profile_id, "offline signing profile id")?;
        ensure_non_empty(device_label, "offline signing device label")?;
        if builder_intent_id.is_none() && contract_manifest_id.is_none() {
            return Err(
                "offline signing bundle requires builder intent or contract manifest".to_string(),
            );
        }
        if ttl_blocks == 0 {
            return Err("offline signing ttl must be positive".to_string());
        }
        let device_policy_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-OFFLINE-SIGNING-DEVICE-POLICY",
            &json!({
                "profile_id": profile_id,
                "device_label": device_label,
                "hardware_required": true,
                "nonce": nonce,
            }),
        );
        let unsigned_payload_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-OFFLINE-SIGNING-UNSIGNED-PAYLOAD",
            &json!({
                "profile_id": profile_id,
                "builder_intent_id": builder_intent_id,
                "contract_manifest_id": contract_manifest_id,
                "nonce": nonce,
            }),
        );
        let airgap_export_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-OFFLINE-SIGNING-AIRGAP-EXPORT",
            &json!({
                "profile_id": profile_id,
                "unsigned_payload_root": unsigned_payload_root,
                "format": "canonical-json-devnet-bundle",
                "nonce": nonce,
            }),
        );
        let hardware_prompt_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-OFFLINE-SIGNING-HARDWARE-PROMPT",
            &json!({
                "profile_id": profile_id,
                "device_label": device_label,
                "amounts_bucketed": true,
                "nonce": nonce,
            }),
        );
        let pq_auth_challenge_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-OFFLINE-SIGNING-PQ-CHALLENGE",
            &json!({
                "profile_id": profile_id,
                "session_id": session_id,
                "unsigned_payload_root": unsigned_payload_root,
                "suite": WALLET_SDK_GATEWAY_PQ_SUITE,
                "nonce": nonce,
            }),
        );
        let bundle_id = wallet_sdk_offline_signing_bundle_id(
            profile_id,
            &unsigned_payload_root,
            &device_policy_root,
            created_at_height,
            nonce,
        );
        let bundle = Self {
            bundle_id,
            profile_id: profile_id.to_string(),
            session_id,
            builder_intent_id,
            contract_manifest_id,
            device_policy_root,
            unsigned_payload_root,
            airgap_export_root,
            hardware_prompt_root,
            pq_auth_challenge_root,
            signature_root: None,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            stage: OfflineSigningStage::Prepared,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn is_open_at(&self, height: u64) -> bool {
        self.stage.is_open() && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "offline_signing_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "profile_id": self.profile_id,
            "session_id": self.session_id,
            "builder_intent_id": self.builder_intent_id,
            "contract_manifest_id": self.contract_manifest_id,
            "device_policy_root": self.device_policy_root,
            "unsigned_payload_root": self.unsigned_payload_root,
            "airgap_export_root": self.airgap_export_root,
            "hardware_prompt_root": self.hardware_prompt_root,
            "pq_auth_challenge_root": self.pq_auth_challenge_root,
            "signature_root": self.signature_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "stage": self.stage.as_str(),
        })
    }

    pub fn bundle_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-OFFLINE-SIGNING-BUNDLE", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.bundle_id, "offline signing bundle id")?;
        ensure_non_empty(&self.profile_id, "offline signing profile id")?;
        if self.builder_intent_id.is_none() && self.contract_manifest_id.is_none() {
            return Err(
                "offline signing bundle requires builder intent or contract manifest".to_string(),
            );
        }
        ensure_non_empty(
            &self.device_policy_root,
            "offline signing device policy root",
        )?;
        ensure_non_empty(
            &self.unsigned_payload_root,
            "offline signing unsigned payload root",
        )?;
        ensure_non_empty(
            &self.airgap_export_root,
            "offline signing airgap export root",
        )?;
        ensure_non_empty(&self.hardware_prompt_root, "offline signing prompt root")?;
        ensure_non_empty(
            &self.pq_auth_challenge_root,
            "offline signing pq auth challenge root",
        )?;
        ensure_height_window(
            self.created_at_height,
            self.expires_at_height,
            "offline signing bundle",
        )?;
        if matches!(
            self.stage,
            OfflineSigningStage::Signed | OfflineSigningStage::BroadcastReady
        ) && self.signature_root.is_none()
        {
            return Err("offline signing signed stages require signature root".to_string());
        }
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdkCompatibilityManifest {
    pub compatibility_id: String,
    pub sdk_name: String,
    pub sdk_semver: String,
    pub min_gateway_protocol_version: String,
    pub status: SdkCompatibilityStatus,
    pub supported_features: BTreeSet<WalletSdkCapability>,
    pub required_pq_suite: String,
    pub api_surface_root: String,
    pub migration_notes_root: String,
    pub published_height: u64,
    pub expires_at_height: Option<u64>,
}

impl SdkCompatibilityManifest {
    pub fn deterministic(
        sdk_name: &str,
        sdk_semver: &str,
        status: SdkCompatibilityStatus,
        supported_features: Vec<WalletSdkCapability>,
        published_height: u64,
        expires_at_height: Option<u64>,
        nonce: u64,
    ) -> WalletSdkGatewayResult<Self> {
        ensure_non_empty(sdk_name, "sdk compatibility name")?;
        ensure_non_empty(sdk_semver, "sdk compatibility semver")?;
        let feature_set = supported_features.into_iter().collect::<BTreeSet<_>>();
        ensure_non_empty_set(&feature_set, "sdk compatibility features")?;
        if let Some(expires) = expires_at_height {
            if expires <= published_height {
                return Err("sdk compatibility expiry must follow publish height".to_string());
            }
        }
        let api_surface_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-COMPATIBILITY-API-SURFACE",
            &json!({
                "sdk_name": sdk_name,
                "sdk_semver": sdk_semver,
                "features": capability_names(&feature_set),
                "nonce": nonce,
            }),
        );
        let migration_notes_root = wallet_sdk_gateway_payload_root(
            "WALLET-SDK-COMPATIBILITY-MIGRATION-NOTES",
            &json!({
                "sdk_name": sdk_name,
                "sdk_semver": sdk_semver,
                "status": status.as_str(),
                "pq_suite": WALLET_SDK_GATEWAY_PQ_SUITE,
                "nonce": nonce,
            }),
        );
        let compatibility_id = wallet_sdk_compatibility_manifest_id(
            sdk_name,
            sdk_semver,
            &status,
            &api_surface_root,
            published_height,
            nonce,
        );
        let manifest = Self {
            compatibility_id,
            sdk_name: sdk_name.to_string(),
            sdk_semver: sdk_semver.to_string(),
            min_gateway_protocol_version: WALLET_SDK_GATEWAY_PROTOCOL_VERSION.to_string(),
            status,
            supported_features: feature_set,
            required_pq_suite: WALLET_SDK_GATEWAY_PQ_SUITE.to_string(),
            api_surface_root,
            migration_notes_root,
            published_height,
            expires_at_height,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn accepts_new_sessions_at(&self, height: u64) -> bool {
        if !self.status.accepts_new_sessions() {
            return false;
        }
        match self.expires_at_height {
            Some(expires_at_height) => height < expires_at_height,
            None => true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "sdk_compatibility_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "compatibility_id": self.compatibility_id,
            "sdk_name": self.sdk_name,
            "sdk_semver": self.sdk_semver,
            "min_gateway_protocol_version": self.min_gateway_protocol_version,
            "status": self.status.as_str(),
            "supported_features": capability_names(&self.supported_features),
            "required_pq_suite": self.required_pq_suite,
            "api_surface_root": self.api_surface_root,
            "migration_notes_root": self.migration_notes_root,
            "published_height": self.published_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn manifest_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-COMPATIBILITY-MANIFEST", &self.public_record())
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(&self.compatibility_id, "sdk compatibility id")?;
        ensure_non_empty(&self.sdk_name, "sdk compatibility name")?;
        ensure_non_empty(&self.sdk_semver, "sdk compatibility semver")?;
        ensure_eq_str(
            &self.min_gateway_protocol_version,
            WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "sdk compatibility protocol version",
        )?;
        ensure_eq_str(
            &self.required_pq_suite,
            WALLET_SDK_GATEWAY_PQ_SUITE,
            "sdk compatibility pq suite",
        )?;
        ensure_non_empty_set(&self.supported_features, "sdk compatibility features")?;
        ensure_non_empty(&self.api_surface_root, "sdk compatibility api surface root")?;
        ensure_non_empty(
            &self.migration_notes_root,
            "sdk compatibility migration notes root",
        )?;
        if let Some(expires) = self.expires_at_height {
            if expires <= self.published_height {
                return Err("sdk compatibility expiry must follow publish height".to_string());
            }
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSdkGatewayRoots {
    pub config_root: String,
    pub client_profile_root: String,
    pub pq_session_root: String,
    pub view_bridge_profile_root: String,
    pub low_fee_quote_root: String,
    pub private_builder_intent_root: String,
    pub contract_manifest_root: String,
    pub recovery_policy_root: String,
    pub disclosure_ticket_root: String,
    pub rate_limit_root: String,
    pub offline_signing_bundle_root: String,
    pub compatibility_manifest_root: String,
    pub public_record_root: String,
}

impl WalletSdkGatewayRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_sdk_gateway_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "client_profile_root": self.client_profile_root,
            "pq_session_root": self.pq_session_root,
            "view_bridge_profile_root": self.view_bridge_profile_root,
            "low_fee_quote_root": self.low_fee_quote_root,
            "private_builder_intent_root": self.private_builder_intent_root,
            "contract_manifest_root": self.contract_manifest_root,
            "recovery_policy_root": self.recovery_policy_root,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "rate_limit_root": self.rate_limit_root,
            "offline_signing_bundle_root": self.offline_signing_bundle_root,
            "compatibility_manifest_root": self.compatibility_manifest_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-GATEWAY-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSdkGatewayCounters {
    pub height: u64,
    pub client_profile_count: u64,
    pub active_client_profile_count: u64,
    pub pq_session_count: u64,
    pub active_pq_session_count: u64,
    pub view_bridge_profile_count: u64,
    pub active_view_bridge_profile_count: u64,
    pub low_fee_quote_count: u64,
    pub live_low_fee_quote_count: u64,
    pub sponsored_quote_count: u64,
    pub private_builder_intent_count: u64,
    pub live_private_builder_intent_count: u64,
    pub contract_manifest_count: u64,
    pub private_contract_manifest_count: u64,
    pub recovery_policy_count: u64,
    pub active_recovery_policy_count: u64,
    pub disclosure_ticket_count: u64,
    pub active_disclosure_ticket_count: u64,
    pub rate_limit_count: u64,
    pub exceeded_rate_limit_count: u64,
    pub offline_signing_bundle_count: u64,
    pub open_offline_signing_bundle_count: u64,
    pub compatibility_manifest_count: u64,
    pub supported_compatibility_manifest_count: u64,
    pub public_record_count: u64,
    pub total_quoted_fee_units: u64,
    pub total_sponsor_discount_units: u64,
    pub total_private_amount_bucket: u64,
    pub total_contract_value_bucket: u64,
}

impl WalletSdkGatewayCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_sdk_gateway_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "height": self.height,
            "client_profile_count": self.client_profile_count,
            "active_client_profile_count": self.active_client_profile_count,
            "pq_session_count": self.pq_session_count,
            "active_pq_session_count": self.active_pq_session_count,
            "view_bridge_profile_count": self.view_bridge_profile_count,
            "active_view_bridge_profile_count": self.active_view_bridge_profile_count,
            "low_fee_quote_count": self.low_fee_quote_count,
            "live_low_fee_quote_count": self.live_low_fee_quote_count,
            "sponsored_quote_count": self.sponsored_quote_count,
            "private_builder_intent_count": self.private_builder_intent_count,
            "live_private_builder_intent_count": self.live_private_builder_intent_count,
            "contract_manifest_count": self.contract_manifest_count,
            "private_contract_manifest_count": self.private_contract_manifest_count,
            "recovery_policy_count": self.recovery_policy_count,
            "active_recovery_policy_count": self.active_recovery_policy_count,
            "disclosure_ticket_count": self.disclosure_ticket_count,
            "active_disclosure_ticket_count": self.active_disclosure_ticket_count,
            "rate_limit_count": self.rate_limit_count,
            "exceeded_rate_limit_count": self.exceeded_rate_limit_count,
            "offline_signing_bundle_count": self.offline_signing_bundle_count,
            "open_offline_signing_bundle_count": self.open_offline_signing_bundle_count,
            "compatibility_manifest_count": self.compatibility_manifest_count,
            "supported_compatibility_manifest_count": self.supported_compatibility_manifest_count,
            "public_record_count": self.public_record_count,
            "total_quoted_fee_units": self.total_quoted_fee_units,
            "total_sponsor_discount_units": self.total_sponsor_discount_units,
            "total_private_amount_bucket": self.total_private_amount_bucket,
            "total_contract_value_bucket": self.total_contract_value_bucket,
        })
    }

    pub fn counters_root(&self) -> String {
        wallet_sdk_gateway_payload_root("WALLET-SDK-GATEWAY-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSdkGatewayState {
    pub height: u64,
    pub active_profile_id: Option<String>,
    pub config: WalletSdkGatewayConfig,
    pub client_profiles: BTreeMap<String, WalletClientProfile>,
    pub pq_sessions: BTreeMap<String, PqAuthenticatedSession>,
    pub view_bridge_profiles: BTreeMap<String, ViewOnlyMoneroBridgeProfile>,
    pub low_fee_quotes: BTreeMap<String, LowFeeQuoteEnvelope>,
    pub private_builder_intents: BTreeMap<String, PrivateTxBuilderIntent>,
    pub contract_manifests: BTreeMap<String, SmartContractCallManifest>,
    pub recovery_policies: BTreeMap<String, RecoveryPolicy>,
    pub disclosure_tickets: BTreeMap<String, SelectiveDisclosureTicket>,
    pub rate_limits: BTreeMap<String, SdkRateLimit>,
    pub offline_signing_bundles: BTreeMap<String, OfflineSigningBundle>,
    pub compatibility_manifests: BTreeMap<String, SdkCompatibilityManifest>,
    pub public_records: BTreeMap<String, Value>,
}

impl WalletSdkGatewayState {
    pub fn new(config: WalletSdkGatewayConfig) -> WalletSdkGatewayResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            active_profile_id: None,
            config,
            client_profiles: BTreeMap::new(),
            pq_sessions: BTreeMap::new(),
            view_bridge_profiles: BTreeMap::new(),
            low_fee_quotes: BTreeMap::new(),
            private_builder_intents: BTreeMap::new(),
            contract_manifests: BTreeMap::new(),
            recovery_policies: BTreeMap::new(),
            disclosure_tickets: BTreeMap::new(),
            rate_limits: BTreeMap::new(),
            offline_signing_bundles: BTreeMap::new(),
            compatibility_manifests: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> WalletSdkGatewayResult<Self> {
        let mut state = Self::new(WalletSdkGatewayConfig::default())?;
        state.set_height(WALLET_SDK_GATEWAY_DEVNET_HEIGHT)?;

        let fee_asset_id = state.config.default_fee_asset_id.clone();
        let monero_network = state.config.monero_network.clone();
        let session_ttl = state.config.default_session_ttl_blocks;
        let quote_ttl = state.config.default_quote_ttl_blocks;
        let builder_ttl = state.config.default_builder_ttl_blocks;
        let contract_ttl = state.config.default_contract_ttl_blocks;
        let disclosure_ttl = state.config.default_disclosure_ttl_blocks;
        let offline_ttl = state.config.default_offline_signing_ttl_blocks;
        let rate_window = state.config.default_rate_limit_window_blocks;
        let recovery_timelock = state.config.default_recovery_timelock_blocks;

        let alice = WalletClientProfile::deterministic(
            "devnet-alice-sdk",
            WalletSdkClientKind::Hardware,
            "nebula-wallet-rs",
            "0.1.0-devnet",
            &fee_asset_id,
            state.height,
            vec![
                WalletSdkCapability::PqSessions,
                WalletSdkCapability::ViewOnlyMoneroBridge,
                WalletSdkCapability::LowFeeQuotes,
                WalletSdkCapability::PrivateTxBuilder,
                WalletSdkCapability::SmartContractCalls,
                WalletSdkCapability::RecoveryPolicies,
                WalletSdkCapability::SelectiveDisclosure,
                WalletSdkCapability::OfflineSigning,
            ],
            &json!({
                "privacy_posture": "hardware-gated max privacy",
                "fee_preference": "sponsored private lane",
            }),
        )?;
        let watch = WalletClientProfile::deterministic(
            "devnet-watch-sdk",
            WalletSdkClientKind::WatchOnly,
            "nebula-watch-sdk",
            "0.1.0-devnet",
            &fee_asset_id,
            state.height,
            vec![
                WalletSdkCapability::PqSessions,
                WalletSdkCapability::ViewOnlyMoneroBridge,
                WalletSdkCapability::SelectiveDisclosure,
                WalletSdkCapability::SdkCompatibility,
            ],
            &json!({
                "privacy_posture": "view-only bridge scans",
                "spend_key_absent": true,
            }),
        )?;
        let alice_profile_id = state.insert_client_profile(alice)?;
        let watch_profile_id = state.insert_client_profile(watch)?;
        state.active_profile_id = Some(alice_profile_id.clone());

        let private_session = PqAuthenticatedSession::deterministic(
            &alice_profile_id,
            PqSessionPurpose::SubmitPrivateTx,
            "devnet-sequencer-a",
            state.height,
            session_ttl,
            1,
        )?;
        let contract_session = PqAuthenticatedSession::deterministic(
            &alice_profile_id,
            PqSessionPurpose::ContractCall,
            "devnet-private-orderflow-a",
            state.height,
            session_ttl,
            2,
        )?;
        let watch_session = PqAuthenticatedSession::deterministic(
            &watch_profile_id,
            PqSessionPurpose::ViewOnlyBridgeSync,
            "devnet-bridge-watchtower",
            state.height,
            session_ttl,
            3,
        )?;
        let private_session_id = state.insert_pq_session(private_session)?;
        let contract_session_id = state.insert_pq_session(contract_session)?;
        let watch_session_id = state.insert_pq_session(watch_session)?;

        let bridge_profile = ViewOnlyMoneroBridgeProfile::deterministic_view_only(
            &watch_profile_id,
            &monero_network,
            "devnet-bridge-operator-a",
            1,
            32,
            vec![
                "view_tag_hits".to_string(),
                "deposit_detection".to_string(),
                "withdrawal_status".to_string(),
            ],
            state.height,
            disclosure_ttl,
            4,
        )?;
        let bridge_profile_id = state.insert_view_bridge_profile(bridge_profile)?;

        let quote = LowFeeQuoteEnvelope::deterministic(
            &alice_profile_id,
            Some(private_session_id.clone()),
            WALLET_SDK_GATEWAY_DEFAULT_FAST_LANE_ID,
            LowFeeQuoteStrategy::SponsoredPrivateLane,
            &fee_asset_id,
            1_200,
            300,
            900,
            state.height,
            quote_ttl,
            2,
            "proof-bucket-small",
            5,
        )?;
        let defi_quote = LowFeeQuoteEnvelope::deterministic(
            &alice_profile_id,
            Some(contract_session_id.clone()),
            WALLET_SDK_GATEWAY_DEFAULT_DEFI_LANE_ID,
            LowFeeQuoteStrategy::ProofCompressed,
            &fee_asset_id,
            2_400,
            500,
            1_000,
            state.height,
            quote_ttl,
            1,
            "proof-bucket-defi",
            6,
        )?;
        let quote_id = state.insert_low_fee_quote(quote)?;
        let defi_quote_id = state.insert_low_fee_quote(defi_quote)?;

        let builder_intent = PrivateTxBuilderIntent::deterministic(
            &alice_profile_id,
            Some(private_session_id.clone()),
            PrivateTxIntentKind::ShieldedTransfer,
            TxPrivacyLevel::MaxPrivacy,
            &fee_asset_id,
            1_000_000,
            Some(quote_id.clone()),
            true,
            state.height,
            builder_ttl,
            7,
        )?;
        let builder_intent_id = state.insert_private_builder_intent(builder_intent)?;

        let contract_manifest = SmartContractCallManifest::deterministic(
            &alice_profile_id,
            Some(contract_session_id.clone()),
            SmartContractCallKind::DefiSwap,
            "devnet-private-amm",
            Some(fee_asset_id.clone()),
            250_000,
            450_000,
            1_900,
            vec![defi_quote_id.clone()],
            state.height,
            contract_ttl,
            8,
        )?;
        let contract_manifest_id = state.insert_contract_manifest(contract_manifest)?;

        let recovery_policy = RecoveryPolicy::deterministic(
            &alice_profile_id,
            RecoveryPolicyKind::GuardianQuorum,
            vec![
                "devnet-guardian-a".to_string(),
                "devnet-guardian-b".to_string(),
                "devnet-guardian-c".to_string(),
            ],
            2,
            recovery_timelock,
            state.height,
            9,
        )?;
        state.insert_recovery_policy(recovery_policy)?;

        let disclosure_ticket = SelectiveDisclosureTicket::deterministic(
            &alice_profile_id,
            SelectiveDisclosureScope::FeeReceipt,
            "low_fee_quote_envelope",
            &quote_id,
            vec![
                "quote_id".to_string(),
                "quoted_fee_units".to_string(),
                "sponsor_discount_units".to_string(),
            ],
            "devnet-auditor",
            state.height,
            disclosure_ttl,
            true,
            10,
        )?;
        state.insert_disclosure_ticket(disclosure_ticket)?;

        state.insert_rate_limit(SdkRateLimit::deterministic(
            Some(alice_profile_id.clone()),
            RateLimitBucketKind::PrivateBuilder,
            state.height,
            rate_window,
            24,
            3,
            8,
            11,
        )?)?;
        state.insert_rate_limit(SdkRateLimit::deterministic(
            Some(watch_profile_id.clone()),
            RateLimitBucketKind::DisclosureTicket,
            state.height,
            rate_window,
            16,
            1,
            4,
            12,
        )?)?;

        let offline_bundle = OfflineSigningBundle::deterministic(
            &alice_profile_id,
            Some(private_session_id.clone()),
            Some(builder_intent_id.clone()),
            None,
            "devnet-hardware-signer-a",
            state.height,
            offline_ttl,
            13,
        )?;
        state.insert_offline_signing_bundle(offline_bundle)?;

        let contract_offline_bundle = OfflineSigningBundle::deterministic(
            &alice_profile_id,
            Some(contract_session_id),
            None,
            Some(contract_manifest_id.clone()),
            "devnet-hardware-signer-a",
            state.height,
            offline_ttl,
            14,
        )?;
        state.insert_offline_signing_bundle(contract_offline_bundle)?;

        let full_manifest = SdkCompatibilityManifest::deterministic(
            "nebula-wallet-rs",
            "0.1.0-devnet",
            SdkCompatibilityStatus::Supported,
            vec![
                WalletSdkCapability::PqSessions,
                WalletSdkCapability::ViewOnlyMoneroBridge,
                WalletSdkCapability::LowFeeQuotes,
                WalletSdkCapability::PrivateTxBuilder,
                WalletSdkCapability::SmartContractCalls,
                WalletSdkCapability::RecoveryPolicies,
                WalletSdkCapability::SelectiveDisclosure,
                WalletSdkCapability::RateLimitHints,
                WalletSdkCapability::OfflineSigning,
            ],
            state.height,
            None,
            15,
        )?;
        let watch_manifest = SdkCompatibilityManifest::deterministic(
            "nebula-watch-sdk",
            "0.1.0-devnet",
            SdkCompatibilityStatus::Experimental,
            vec![
                WalletSdkCapability::PqSessions,
                WalletSdkCapability::ViewOnlyMoneroBridge,
                WalletSdkCapability::SelectiveDisclosure,
                WalletSdkCapability::SdkCompatibility,
            ],
            state.height,
            Some(state.height.saturating_add(2_880)),
            16,
        )?;
        state.insert_compatibility_manifest(full_manifest)?;
        state.insert_compatibility_manifest(watch_manifest)?;

        let bootstrap_record = json!({
            "active_profile_id": alice_profile_id,
            "watch_profile_id": watch_profile_id,
            "watch_session_id": watch_session_id,
            "bridge_profile_id": bridge_profile_id,
            "private_builder_intent_id": builder_intent_id,
            "contract_manifest_id": contract_manifest_id,
        });
        state.record_public_record("devnet-wallet-sdk-gateway-bootstrap", &bootstrap_record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> WalletSdkGatewayResult<String> {
        self.height = height;
        for session in self.pq_sessions.values_mut() {
            if session.status.is_live() && height >= session.expires_at_height {
                session.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for profile in self.view_bridge_profiles.values_mut() {
            if profile.status.is_live() && height >= profile.expires_at_height {
                profile.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for quote in self.low_fee_quotes.values_mut() {
            if quote.status.is_live() && height >= quote.expires_at_height {
                quote.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for intent in self.private_builder_intents.values_mut() {
            if intent.status.is_live() && height >= intent.deadline_height {
                intent.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for manifest in self.contract_manifests.values_mut() {
            if manifest.status.is_live() && height >= manifest.expires_at_height {
                manifest.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for ticket in self.disclosure_tickets.values_mut() {
            if ticket.status.is_live() && height >= ticket.expires_at_height {
                ticket.status = WalletSdkGatewayStatus::Expired;
            }
        }
        for limit in self.rate_limits.values_mut() {
            if limit.status == RateLimitStatus::Active && height >= limit.window_end_height {
                limit.status = RateLimitStatus::Expired;
            }
        }
        for bundle in self.offline_signing_bundles.values_mut() {
            if bundle.stage.is_open() && height >= bundle.expires_at_height {
                bundle.stage = OfflineSigningStage::Expired;
            }
        }
        for manifest in self.compatibility_manifests.values_mut() {
            if let Some(expires_at_height) = manifest.expires_at_height {
                if manifest.status.accepts_new_sessions() && height >= expires_at_height {
                    manifest.status = SdkCompatibilityStatus::Deprecated;
                }
            }
        }
        self.validate()
    }

    pub fn insert_client_profile(
        &mut self,
        profile: WalletClientProfile,
    ) -> WalletSdkGatewayResult<String> {
        profile.validate()?;
        ensure_map_absent(
            &self.client_profiles,
            &profile.profile_id,
            "wallet client profile",
        )?;
        let profile_id = profile.profile_id.clone();
        self.client_profiles.insert(profile_id.clone(), profile);
        self.validate()?;
        Ok(profile_id)
    }

    pub fn insert_pq_session(
        &mut self,
        session: PqAuthenticatedSession,
    ) -> WalletSdkGatewayResult<String> {
        session.validate()?;
        ensure_map_absent(&self.pq_sessions, &session.session_id, "pq session")?;
        self.ensure_profile_exists(&session.profile_id, "pq session")?;
        let session_id = session.session_id.clone();
        self.pq_sessions.insert(session_id.clone(), session);
        self.validate()?;
        Ok(session_id)
    }

    pub fn insert_view_bridge_profile(
        &mut self,
        profile: ViewOnlyMoneroBridgeProfile,
    ) -> WalletSdkGatewayResult<String> {
        profile.validate()?;
        ensure_map_absent(
            &self.view_bridge_profiles,
            &profile.bridge_profile_id,
            "view bridge profile",
        )?;
        self.ensure_profile_exists(&profile.profile_id, "view bridge profile")?;
        let profile_id = profile.bridge_profile_id.clone();
        self.view_bridge_profiles
            .insert(profile_id.clone(), profile);
        self.validate()?;
        Ok(profile_id)
    }

    pub fn insert_low_fee_quote(
        &mut self,
        quote: LowFeeQuoteEnvelope,
    ) -> WalletSdkGatewayResult<String> {
        quote.validate()?;
        ensure_map_absent(&self.low_fee_quotes, &quote.quote_id, "low fee quote")?;
        self.ensure_profile_exists(&quote.profile_id, "low fee quote")?;
        self.ensure_optional_session_for_profile(
            &quote.session_id,
            &quote.profile_id,
            "low fee quote",
        )?;
        let quote_id = quote.quote_id.clone();
        self.low_fee_quotes.insert(quote_id.clone(), quote);
        self.validate()?;
        Ok(quote_id)
    }

    pub fn insert_private_builder_intent(
        &mut self,
        intent: PrivateTxBuilderIntent,
    ) -> WalletSdkGatewayResult<String> {
        intent.validate()?;
        ensure_map_absent(
            &self.private_builder_intents,
            &intent.builder_intent_id,
            "private builder intent",
        )?;
        self.ensure_profile_exists(&intent.profile_id, "private builder intent")?;
        self.ensure_optional_session_for_profile(
            &intent.session_id,
            &intent.profile_id,
            "private builder intent",
        )?;
        if let Some(quote_id) = &intent.fee_quote_id {
            self.ensure_quote_exists(quote_id, "private builder intent")?;
        }
        let intent_id = intent.builder_intent_id.clone();
        self.private_builder_intents
            .insert(intent_id.clone(), intent);
        self.validate()?;
        Ok(intent_id)
    }

    pub fn insert_contract_manifest(
        &mut self,
        manifest: SmartContractCallManifest,
    ) -> WalletSdkGatewayResult<String> {
        manifest.validate()?;
        ensure_map_absent(
            &self.contract_manifests,
            &manifest.manifest_id,
            "contract manifest",
        )?;
        self.ensure_profile_exists(&manifest.profile_id, "contract manifest")?;
        self.ensure_optional_session_for_profile(
            &manifest.session_id,
            &manifest.profile_id,
            "contract manifest",
        )?;
        let manifest_id = manifest.manifest_id.clone();
        self.contract_manifests
            .insert(manifest_id.clone(), manifest);
        self.validate()?;
        Ok(manifest_id)
    }

    pub fn insert_recovery_policy(
        &mut self,
        policy: RecoveryPolicy,
    ) -> WalletSdkGatewayResult<String> {
        policy.validate()?;
        ensure_map_absent(
            &self.recovery_policies,
            &policy.policy_id,
            "recovery policy",
        )?;
        self.ensure_profile_exists(&policy.profile_id, "recovery policy")?;
        let policy_id = policy.policy_id.clone();
        self.recovery_policies.insert(policy_id.clone(), policy);
        self.validate()?;
        Ok(policy_id)
    }

    pub fn insert_disclosure_ticket(
        &mut self,
        ticket: SelectiveDisclosureTicket,
    ) -> WalletSdkGatewayResult<String> {
        ticket.validate()?;
        ensure_map_absent(
            &self.disclosure_tickets,
            &ticket.ticket_id,
            "disclosure ticket",
        )?;
        self.ensure_profile_exists(&ticket.profile_id, "disclosure ticket")?;
        self.ensure_subject_exists(&ticket.subject_kind, &ticket.subject_id)?;
        let ticket_id = ticket.ticket_id.clone();
        self.disclosure_tickets.insert(ticket_id.clone(), ticket);
        self.validate()?;
        Ok(ticket_id)
    }

    pub fn insert_rate_limit(&mut self, limit: SdkRateLimit) -> WalletSdkGatewayResult<String> {
        limit.validate()?;
        ensure_map_absent(&self.rate_limits, &limit.limit_id, "sdk rate limit")?;
        if let Some(profile_id) = &limit.profile_id {
            self.ensure_profile_exists(profile_id, "sdk rate limit")?;
        }
        let limit_id = limit.limit_id.clone();
        self.rate_limits.insert(limit_id.clone(), limit);
        self.validate()?;
        Ok(limit_id)
    }

    pub fn insert_offline_signing_bundle(
        &mut self,
        bundle: OfflineSigningBundle,
    ) -> WalletSdkGatewayResult<String> {
        bundle.validate()?;
        ensure_map_absent(
            &self.offline_signing_bundles,
            &bundle.bundle_id,
            "offline signing bundle",
        )?;
        self.ensure_profile_exists(&bundle.profile_id, "offline signing bundle")?;
        self.ensure_optional_session_for_profile(
            &bundle.session_id,
            &bundle.profile_id,
            "offline signing bundle",
        )?;
        if let Some(intent_id) = &bundle.builder_intent_id {
            self.ensure_builder_intent_exists(intent_id, "offline signing bundle")?;
        }
        if let Some(manifest_id) = &bundle.contract_manifest_id {
            self.ensure_contract_manifest_exists(manifest_id, "offline signing bundle")?;
        }
        let bundle_id = bundle.bundle_id.clone();
        self.offline_signing_bundles
            .insert(bundle_id.clone(), bundle);
        self.validate()?;
        Ok(bundle_id)
    }

    pub fn insert_compatibility_manifest(
        &mut self,
        manifest: SdkCompatibilityManifest,
    ) -> WalletSdkGatewayResult<String> {
        manifest.validate()?;
        ensure_map_absent(
            &self.compatibility_manifests,
            &manifest.compatibility_id,
            "sdk compatibility manifest",
        )?;
        let manifest_id = manifest.compatibility_id.clone();
        self.compatibility_manifests
            .insert(manifest_id.clone(), manifest);
        self.validate()?;
        Ok(manifest_id)
    }

    pub fn record_public_record(
        &mut self,
        label: &str,
        record: &Value,
    ) -> WalletSdkGatewayResult<String> {
        ensure_non_empty(label, "wallet sdk public record label")?;
        let wrapped = json!({
            "kind": "wallet_sdk_gateway_public_record",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "label": label,
            "record": record,
            "record_root": wallet_sdk_gateway_payload_root("WALLET-SDK-GATEWAY-PUBLIC-RECORD-PAYLOAD", record),
            "height": self.height,
        });
        let record_id = wallet_sdk_public_record_id(label, &wrapped);
        ensure_map_absent(&self.public_records, &record_id, "wallet sdk public record")?;
        self.public_records.insert(record_id.clone(), wrapped);
        self.validate()?;
        Ok(record_id)
    }

    pub fn roots(&self) -> WalletSdkGatewayRoots {
        WalletSdkGatewayRoots {
            config_root: self.config.config_root(),
            client_profile_root: wallet_sdk_client_profile_collection_root(
                &self.client_profiles.values().cloned().collect::<Vec<_>>(),
            ),
            pq_session_root: wallet_sdk_pq_session_collection_root(
                &self.pq_sessions.values().cloned().collect::<Vec<_>>(),
            ),
            view_bridge_profile_root: wallet_sdk_view_bridge_profile_collection_root(
                &self
                    .view_bridge_profiles
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            low_fee_quote_root: wallet_sdk_low_fee_quote_collection_root(
                &self.low_fee_quotes.values().cloned().collect::<Vec<_>>(),
            ),
            private_builder_intent_root: wallet_sdk_private_builder_intent_collection_root(
                &self
                    .private_builder_intents
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            contract_manifest_root: wallet_sdk_contract_manifest_collection_root(
                &self
                    .contract_manifests
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            recovery_policy_root: wallet_sdk_recovery_policy_collection_root(
                &self.recovery_policies.values().cloned().collect::<Vec<_>>(),
            ),
            disclosure_ticket_root: wallet_sdk_disclosure_ticket_collection_root(
                &self
                    .disclosure_tickets
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            rate_limit_root: wallet_sdk_rate_limit_collection_root(
                &self.rate_limits.values().cloned().collect::<Vec<_>>(),
            ),
            offline_signing_bundle_root: wallet_sdk_offline_signing_bundle_collection_root(
                &self
                    .offline_signing_bundles
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            compatibility_manifest_root: wallet_sdk_compatibility_manifest_collection_root(
                &self
                    .compatibility_manifests
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            public_record_root: wallet_sdk_value_collection_root(
                "WALLET-SDK-GATEWAY-PUBLIC-RECORD-COLLECTION",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> WalletSdkGatewayCounters {
        WalletSdkGatewayCounters {
            height: self.height,
            client_profile_count: self.client_profiles.len() as u64,
            active_client_profile_count: self
                .client_profiles
                .values()
                .filter(|profile| profile.status == WalletSdkGatewayStatus::Active)
                .count() as u64,
            pq_session_count: self.pq_sessions.len() as u64,
            active_pq_session_count: self
                .pq_sessions
                .values()
                .filter(|session| session.is_active_at(self.height))
                .count() as u64,
            view_bridge_profile_count: self.view_bridge_profiles.len() as u64,
            active_view_bridge_profile_count: self
                .view_bridge_profiles
                .values()
                .filter(|profile| profile.is_active_at(self.height))
                .count() as u64,
            low_fee_quote_count: self.low_fee_quotes.len() as u64,
            live_low_fee_quote_count: self
                .low_fee_quotes
                .values()
                .filter(|quote| quote.is_live_at(self.height))
                .count() as u64,
            sponsored_quote_count: self
                .low_fee_quotes
                .values()
                .filter(|quote| quote.sponsor_discount_units > 0)
                .count() as u64,
            private_builder_intent_count: self.private_builder_intents.len() as u64,
            live_private_builder_intent_count: self
                .private_builder_intents
                .values()
                .filter(|intent| intent.is_live_at(self.height))
                .count() as u64,
            contract_manifest_count: self.contract_manifests.len() as u64,
            private_contract_manifest_count: self
                .contract_manifests
                .values()
                .filter(|manifest| manifest.call_kind.requires_private_witness())
                .count() as u64,
            recovery_policy_count: self.recovery_policies.len() as u64,
            active_recovery_policy_count: self
                .recovery_policies
                .values()
                .filter(|policy| policy.status == WalletSdkGatewayStatus::Active)
                .count() as u64,
            disclosure_ticket_count: self.disclosure_tickets.len() as u64,
            active_disclosure_ticket_count: self
                .disclosure_tickets
                .values()
                .filter(|ticket| ticket.is_active_at(self.height))
                .count() as u64,
            rate_limit_count: self.rate_limits.len() as u64,
            exceeded_rate_limit_count: self
                .rate_limits
                .values()
                .filter(|limit| limit.status == RateLimitStatus::Exceeded)
                .count() as u64,
            offline_signing_bundle_count: self.offline_signing_bundles.len() as u64,
            open_offline_signing_bundle_count: self
                .offline_signing_bundles
                .values()
                .filter(|bundle| bundle.is_open_at(self.height))
                .count() as u64,
            compatibility_manifest_count: self.compatibility_manifests.len() as u64,
            supported_compatibility_manifest_count: self
                .compatibility_manifests
                .values()
                .filter(|manifest| manifest.accepts_new_sessions_at(self.height))
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
            total_quoted_fee_units: self
                .low_fee_quotes
                .values()
                .map(|quote| quote.quoted_fee_units)
                .sum(),
            total_sponsor_discount_units: self
                .low_fee_quotes
                .values()
                .map(|quote| quote.sponsor_discount_units)
                .sum(),
            total_private_amount_bucket: self
                .private_builder_intents
                .values()
                .map(|intent| intent.amount_bucket)
                .sum(),
            total_contract_value_bucket: self
                .contract_manifests
                .values()
                .map(|manifest| manifest.value_amount_bucket)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        wallet_sdk_gateway_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> WalletSdkGatewayResult<String> {
        self.config.validate()?;
        if let Some(active_profile_id) = &self.active_profile_id {
            self.ensure_profile_exists(active_profile_id, "active wallet sdk profile")?;
        }
        ensure_len_at_most(
            self.client_profiles.len(),
            self.config.max_profiles,
            "wallet sdk client profiles",
        )?;
        ensure_len_at_most(
            self.pq_sessions.len(),
            self.config.max_sessions,
            "wallet sdk pq sessions",
        )?;
        ensure_len_at_most(
            self.view_bridge_profiles.len(),
            self.config.max_bridge_profiles,
            "wallet sdk bridge profiles",
        )?;
        ensure_len_at_most(
            self.low_fee_quotes.len(),
            self.config.max_quotes,
            "wallet sdk low fee quotes",
        )?;
        ensure_len_at_most(
            self.private_builder_intents.len(),
            self.config.max_builder_intents,
            "wallet sdk private builder intents",
        )?;
        ensure_len_at_most(
            self.contract_manifests.len(),
            self.config.max_contract_manifests,
            "wallet sdk contract manifests",
        )?;
        ensure_len_at_most(
            self.recovery_policies.len(),
            self.config.max_recovery_policies,
            "wallet sdk recovery policies",
        )?;
        ensure_len_at_most(
            self.disclosure_tickets.len(),
            self.config.max_disclosure_tickets,
            "wallet sdk disclosure tickets",
        )?;
        ensure_len_at_most(
            self.rate_limits.len(),
            self.config.max_rate_limits,
            "wallet sdk rate limits",
        )?;
        ensure_len_at_most(
            self.offline_signing_bundles.len(),
            self.config.max_offline_signing_bundles,
            "wallet sdk offline signing bundles",
        )?;
        ensure_len_at_most(
            self.compatibility_manifests.len(),
            self.config.max_compatibility_manifests,
            "wallet sdk compatibility manifests",
        )?;
        ensure_len_at_most(
            self.public_records.len(),
            self.config.max_public_records,
            "wallet sdk public records",
        )?;
        if !self.config.enable_view_only_bridge_profiles && !self.view_bridge_profiles.is_empty() {
            return Err("wallet sdk bridge profiles disabled by config".to_string());
        }

        for (profile_id, profile) in &self.client_profiles {
            profile.validate()?;
            ensure_eq_str(
                profile_id,
                &profile.profile_id,
                "wallet sdk profile map key",
            )?;
        }
        for (session_id, session) in &self.pq_sessions {
            session.validate()?;
            ensure_eq_str(
                session_id,
                &session.session_id,
                "wallet sdk session map key",
            )?;
            self.ensure_profile_exists(&session.profile_id, "wallet sdk session")?;
            if session.security_bits < self.config.min_pq_security_bits {
                return Err("wallet sdk session security below config minimum".to_string());
            }
        }
        for (profile_id, bridge_profile) in &self.view_bridge_profiles {
            bridge_profile.validate()?;
            ensure_eq_str(
                profile_id,
                &bridge_profile.bridge_profile_id,
                "wallet sdk bridge profile map key",
            )?;
            self.ensure_profile_exists(&bridge_profile.profile_id, "wallet sdk bridge profile")?;
        }
        for (quote_id, quote) in &self.low_fee_quotes {
            quote.validate()?;
            ensure_eq_str(quote_id, &quote.quote_id, "wallet sdk quote map key")?;
            self.ensure_profile_exists(&quote.profile_id, "wallet sdk quote")?;
            self.ensure_optional_session_for_profile(
                &quote.session_id,
                &quote.profile_id,
                "wallet sdk quote",
            )?;
            if quote.rebate_bps > self.config.max_rebate_bps {
                return Err("wallet sdk quote rebate exceeds config maximum".to_string());
            }
        }
        for (intent_id, intent) in &self.private_builder_intents {
            intent.validate()?;
            ensure_eq_str(
                intent_id,
                &intent.builder_intent_id,
                "wallet sdk private builder map key",
            )?;
            self.ensure_profile_exists(&intent.profile_id, "wallet sdk private builder")?;
            self.ensure_optional_session_for_profile(
                &intent.session_id,
                &intent.profile_id,
                "wallet sdk private builder",
            )?;
            if self.config.require_pq_auth_for_private_builders && intent.session_id.is_none() {
                return Err("wallet sdk private builder requires pq session".to_string());
            }
            if let Some(quote_id) = &intent.fee_quote_id {
                self.ensure_quote_exists(quote_id, "wallet sdk private builder")?;
            }
        }
        for (manifest_id, manifest) in &self.contract_manifests {
            manifest.validate()?;
            ensure_eq_str(
                manifest_id,
                &manifest.manifest_id,
                "wallet sdk contract manifest map key",
            )?;
            self.ensure_profile_exists(&manifest.profile_id, "wallet sdk contract manifest")?;
            self.ensure_optional_session_for_profile(
                &manifest.session_id,
                &manifest.profile_id,
                "wallet sdk contract manifest",
            )?;
            if self.config.require_pq_auth_for_contract_calls
                && manifest.call_kind.requires_private_witness()
                && manifest.session_id.is_none()
            {
                return Err("wallet sdk private contract manifest requires pq session".to_string());
            }
        }
        for (policy_id, policy) in &self.recovery_policies {
            policy.validate()?;
            ensure_eq_str(
                policy_id,
                &policy.policy_id,
                "wallet sdk recovery policy map key",
            )?;
            self.ensure_profile_exists(&policy.profile_id, "wallet sdk recovery policy")?;
        }
        for (ticket_id, ticket) in &self.disclosure_tickets {
            ticket.validate()?;
            ensure_eq_str(
                ticket_id,
                &ticket.ticket_id,
                "wallet sdk disclosure ticket map key",
            )?;
            self.ensure_profile_exists(&ticket.profile_id, "wallet sdk disclosure ticket")?;
            self.ensure_subject_exists(&ticket.subject_kind, &ticket.subject_id)?;
        }
        for (limit_id, limit) in &self.rate_limits {
            limit.validate()?;
            ensure_eq_str(limit_id, &limit.limit_id, "wallet sdk rate limit map key")?;
            if let Some(profile_id) = &limit.profile_id {
                self.ensure_profile_exists(profile_id, "wallet sdk rate limit")?;
            }
        }
        for (bundle_id, bundle) in &self.offline_signing_bundles {
            bundle.validate()?;
            ensure_eq_str(
                bundle_id,
                &bundle.bundle_id,
                "wallet sdk offline bundle map key",
            )?;
            self.ensure_profile_exists(&bundle.profile_id, "wallet sdk offline bundle")?;
            self.ensure_optional_session_for_profile(
                &bundle.session_id,
                &bundle.profile_id,
                "wallet sdk offline bundle",
            )?;
            if let Some(intent_id) = &bundle.builder_intent_id {
                self.ensure_builder_intent_exists(intent_id, "wallet sdk offline bundle")?;
            }
            if let Some(manifest_id) = &bundle.contract_manifest_id {
                self.ensure_contract_manifest_exists(manifest_id, "wallet sdk offline bundle")?;
            }
        }
        for (compatibility_id, manifest) in &self.compatibility_manifests {
            manifest.validate()?;
            ensure_eq_str(
                compatibility_id,
                &manifest.compatibility_id,
                "wallet sdk compatibility map key",
            )?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "wallet_sdk_gateway_state",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_SDK_GATEWAY_PROTOCOL_VERSION,
            "height": self.height,
            "active_profile_id": self.active_profile_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counters_root": counters.counters_root(),
        })
    }

    fn ensure_profile_exists(&self, profile_id: &str, context: &str) -> WalletSdkGatewayResult<()> {
        if self.client_profiles.contains_key(profile_id) {
            Ok(())
        } else {
            Err(format!(
                "{context} references unknown wallet client profile"
            ))
        }
    }

    fn ensure_quote_exists(&self, quote_id: &str, context: &str) -> WalletSdkGatewayResult<()> {
        if self.low_fee_quotes.contains_key(quote_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown low fee quote"))
        }
    }

    fn ensure_builder_intent_exists(
        &self,
        intent_id: &str,
        context: &str,
    ) -> WalletSdkGatewayResult<()> {
        if self.private_builder_intents.contains_key(intent_id) {
            Ok(())
        } else {
            Err(format!(
                "{context} references unknown private builder intent"
            ))
        }
    }

    fn ensure_contract_manifest_exists(
        &self,
        manifest_id: &str,
        context: &str,
    ) -> WalletSdkGatewayResult<()> {
        if self.contract_manifests.contains_key(manifest_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown contract manifest"))
        }
    }

    fn ensure_optional_session_for_profile(
        &self,
        session_id: &Option<String>,
        profile_id: &str,
        context: &str,
    ) -> WalletSdkGatewayResult<()> {
        if let Some(session_id) = session_id {
            let session = self
                .pq_sessions
                .get(session_id)
                .ok_or_else(|| format!("{context} references unknown pq session"))?;
            if session.profile_id != profile_id {
                return Err(format!("{context} pq session profile mismatch"));
            }
        }
        Ok(())
    }

    fn ensure_subject_exists(
        &self,
        subject_kind: &str,
        subject_id: &str,
    ) -> WalletSdkGatewayResult<()> {
        let exists = match subject_kind {
            "wallet_client_profile" => self.client_profiles.contains_key(subject_id),
            "pq_authenticated_session" => self.pq_sessions.contains_key(subject_id),
            "view_only_monero_bridge_profile" => self.view_bridge_profiles.contains_key(subject_id),
            "low_fee_quote_envelope" => self.low_fee_quotes.contains_key(subject_id),
            "private_tx_builder_intent" => self.private_builder_intents.contains_key(subject_id),
            "smart_contract_call_manifest" => self.contract_manifests.contains_key(subject_id),
            "recovery_policy" => self.recovery_policies.contains_key(subject_id),
            "offline_signing_bundle" => self.offline_signing_bundles.contains_key(subject_id),
            "external_attestation" => true,
            _ => true,
        };
        if exists {
            Ok(())
        } else {
            Err("wallet sdk disclosure subject is unknown".to_string())
        }
    }
}

pub fn wallet_sdk_gateway_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn wallet_sdk_gateway_state_root_from_record(record: &Value) -> String {
    wallet_sdk_gateway_payload_root("WALLET-SDK-GATEWAY-STATE", record)
}

pub fn wallet_sdk_string_set_root(domain: &str, values: &BTreeSet<String>) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .cloned()
            .map(Value::String)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_value_collection_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn wallet_sdk_capability_root(capabilities: &BTreeSet<WalletSdkCapability>) -> String {
    merkle_root(
        "WALLET-SDK-CAPABILITIES",
        &capability_names(capabilities)
            .into_iter()
            .map(|capability| Value::String(capability.to_string()))
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_client_profile_id(
    client_label: &str,
    client_kind: &WalletSdkClientKind,
    account_commitment: &str,
    device_commitment: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-CLIENT-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(client_label),
            HashPart::Str(client_kind.as_str()),
            HashPart::Str(account_commitment),
            HashPart::Str(device_commitment),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_pq_session_id(
    profile_id: &str,
    purpose: &PqSessionPurpose,
    peer_label: &str,
    transcript_root: &str,
    opened_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-PQ-SESSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(purpose.as_str()),
            HashPart::Str(peer_label),
            HashPart::Str(transcript_root),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_monero_bridge_profile_id(
    profile_id: &str,
    monero_network: &str,
    bridge_address_commitment: &str,
    private_view_key_commitment: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-MONERO-BRIDGE-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(monero_network),
            HashPart::Str(bridge_address_commitment),
            HashPart::Str(private_view_key_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_low_fee_quote_id(
    profile_id: &str,
    lane_id: &str,
    strategy: &LowFeeQuoteStrategy,
    quote_commitment_root: &str,
    valid_from_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-LOW-FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(lane_id),
            HashPart::Str(strategy.as_str()),
            HashPart::Str(quote_commitment_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_private_tx_builder_intent_id(
    profile_id: &str,
    intent_kind: &PrivateTxIntentKind,
    privacy_level: &TxPrivacyLevel,
    recipient_commitment: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-PRIVATE-TX-BUILDER-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(intent_kind.as_str()),
            HashPart::Str(privacy_level.as_str()),
            HashPart::Str(recipient_commitment),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_contract_call_manifest_id(
    profile_id: &str,
    call_kind: &SmartContractCallKind,
    contract_address_commitment: &str,
    method_selector_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-CONTRACT-CALL-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(call_kind.as_str()),
            HashPart::Str(contract_address_commitment),
            HashPart::Str(method_selector_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_recovery_policy_id(
    profile_id: &str,
    policy_kind: &RecoveryPolicyKind,
    guardian_set_root: &str,
    threshold: u64,
    last_rotated_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-RECOVERY-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(policy_kind.as_str()),
            HashPart::Str(guardian_set_root),
            HashPart::Int(threshold as i128),
            HashPart::Int(last_rotated_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_disclosure_ticket_id(
    profile_id: &str,
    scope: &SelectiveDisclosureScope,
    subject_kind: &str,
    subject_id: &str,
    proof_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-DISCLOSURE-TICKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(proof_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_rate_limit_id(
    profile_id: Option<&str>,
    bucket_kind: &RateLimitBucketKind,
    window_start_height: u64,
    window_end_height: u64,
    enforcement_root: &str,
    nonce: u64,
) -> String {
    let profile_part = match profile_id {
        Some(value) => value,
        None => "global",
    };
    domain_hash(
        "WALLET-SDK-RATE-LIMIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_part),
            HashPart::Str(bucket_kind.as_str()),
            HashPart::Int(window_start_height as i128),
            HashPart::Int(window_end_height as i128),
            HashPart::Str(enforcement_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_offline_signing_bundle_id(
    profile_id: &str,
    unsigned_payload_root: &str,
    device_policy_root: &str,
    created_at_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-OFFLINE-SIGNING-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(profile_id),
            HashPart::Str(unsigned_payload_root),
            HashPart::Str(device_policy_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_compatibility_manifest_id(
    sdk_name: &str,
    sdk_semver: &str,
    status: &SdkCompatibilityStatus,
    api_surface_root: &str,
    published_height: u64,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-SDK-COMPATIBILITY-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(sdk_name),
            HashPart::Str(sdk_semver),
            HashPart::Str(status.as_str()),
            HashPart::Str(api_surface_root),
            HashPart::Int(published_height as i128),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn wallet_sdk_public_record_id(label: &str, record: &Value) -> String {
    domain_hash(
        "WALLET-SDK-GATEWAY-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(WALLET_SDK_GATEWAY_PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn wallet_sdk_client_profile_collection_root(profiles: &[WalletClientProfile]) -> String {
    merkle_root(
        "WALLET-SDK-CLIENT-PROFILE-COLLECTION",
        &profiles
            .iter()
            .map(WalletClientProfile::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_pq_session_collection_root(sessions: &[PqAuthenticatedSession]) -> String {
    merkle_root(
        "WALLET-SDK-PQ-SESSION-COLLECTION",
        &sessions
            .iter()
            .map(PqAuthenticatedSession::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_view_bridge_profile_collection_root(
    profiles: &[ViewOnlyMoneroBridgeProfile],
) -> String {
    merkle_root(
        "WALLET-SDK-VIEW-BRIDGE-PROFILE-COLLECTION",
        &profiles
            .iter()
            .map(ViewOnlyMoneroBridgeProfile::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_low_fee_quote_collection_root(quotes: &[LowFeeQuoteEnvelope]) -> String {
    merkle_root(
        "WALLET-SDK-LOW-FEE-QUOTE-COLLECTION",
        &quotes
            .iter()
            .map(LowFeeQuoteEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_private_builder_intent_collection_root(
    intents: &[PrivateTxBuilderIntent],
) -> String {
    merkle_root(
        "WALLET-SDK-PRIVATE-BUILDER-INTENT-COLLECTION",
        &intents
            .iter()
            .map(PrivateTxBuilderIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_contract_manifest_collection_root(
    manifests: &[SmartContractCallManifest],
) -> String {
    merkle_root(
        "WALLET-SDK-CONTRACT-MANIFEST-COLLECTION",
        &manifests
            .iter()
            .map(SmartContractCallManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_recovery_policy_collection_root(policies: &[RecoveryPolicy]) -> String {
    merkle_root(
        "WALLET-SDK-RECOVERY-POLICY-COLLECTION",
        &policies
            .iter()
            .map(RecoveryPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_disclosure_ticket_collection_root(
    tickets: &[SelectiveDisclosureTicket],
) -> String {
    merkle_root(
        "WALLET-SDK-DISCLOSURE-TICKET-COLLECTION",
        &tickets
            .iter()
            .map(SelectiveDisclosureTicket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_rate_limit_collection_root(limits: &[SdkRateLimit]) -> String {
    merkle_root(
        "WALLET-SDK-RATE-LIMIT-COLLECTION",
        &limits
            .iter()
            .map(SdkRateLimit::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_offline_signing_bundle_collection_root(
    bundles: &[OfflineSigningBundle],
) -> String {
    merkle_root(
        "WALLET-SDK-OFFLINE-SIGNING-BUNDLE-COLLECTION",
        &bundles
            .iter()
            .map(OfflineSigningBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_sdk_compatibility_manifest_collection_root(
    manifests: &[SdkCompatibilityManifest],
) -> String {
    merkle_root(
        "WALLET-SDK-COMPATIBILITY-MANIFEST-COLLECTION",
        &manifests
            .iter()
            .map(SdkCompatibilityManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

fn capability_names(capabilities: &BTreeSet<WalletSdkCapability>) -> Vec<&'static str> {
    capabilities
        .iter()
        .map(WalletSdkCapability::as_str)
        .collect()
}

fn ensure_non_empty(value: &str, label: &str) -> WalletSdkGatewayResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_non_empty_set<T>(items: &BTreeSet<T>, label: &str) -> WalletSdkGatewayResult<()> {
    if items.is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn ensure_eq_str(left: &str, right: &str, label: &str) -> WalletSdkGatewayResult<()> {
    if left == right {
        Ok(())
    } else {
        Err(format!("{label} mismatch"))
    }
}

fn ensure_height_window(start: u64, end: u64, label: &str) -> WalletSdkGatewayResult<()> {
    if end <= start {
        Err(format!("{label} end height must be after start height"))
    } else {
        Ok(())
    }
}

fn ensure_len_at_most(value: usize, max: usize, label: &str) -> WalletSdkGatewayResult<()> {
    if value > max {
        Err(format!("{label} exceeds configured maximum"))
    } else {
        Ok(())
    }
}

fn ensure_map_absent<T>(
    map: &BTreeMap<String, T>,
    key: &str,
    label: &str,
) -> WalletSdkGatewayResult<()> {
    if map.contains_key(key) {
        Err(format!("{label} already exists"))
    } else {
        Ok(())
    }
}
