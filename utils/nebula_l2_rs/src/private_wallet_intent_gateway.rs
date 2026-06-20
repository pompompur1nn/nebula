use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateWalletIntentGatewayResult<T> = Result<T, String>;

pub const PRIVATE_WALLET_INTENT_GATEWAY_PROTOCOL_VERSION: &str =
    "nebula-private-wallet-intent-gateway-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_ENCRYPTION_SCHEME: &str =
    "ml-kem-1024-wallet-intent-envelope-shake256-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_PQ_SESSION_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87-wallet-session-auth-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_VIEW_KEY_HINT_SCHEME: &str =
    "monero-view-key-selective-disclosure-hint-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_PRIVACY_BUDGET_SCHEME: &str =
    "wallet-privacy-budget-nullifier-bucket-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_SPONSORSHIP_SCHEME: &str =
    "low-fee-sponsored-private-intent-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_BATCHING_SCHEME: &str =
    "fast-private-wallet-intent-batch-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_ACCOUNT_POLICY_SCHEME: &str =
    "pq-account-abstraction-policy-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_RECEIPT_SCHEME: &str = "relayer-private-intent-receipt-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_RECOVERY_SCHEME: &str =
    "delegated-pq-wallet-recovery-timelock-v1";
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_HEIGHT: u64 = 384;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS: u64 = 96;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_INTENT_TTL_BLOCKS: u64 = 48;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_BATCH_TTL_BLOCKS: u64 = 12;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 720;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RATE_WINDOW_BLOCKS: u64 = 60;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RECOVERY_TIMELOCK_BLOCKS: u64 = 1_440;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_INTENTS_PER_BATCH: usize = 64;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_INTENTS_PER_SESSION: u64 = 128;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_SPONSORED_FEE_MICRO_UNITS: u64 = 1_250;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID: &str = "devnet-private-fast-lane";
pub const PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID: &str = "devnet-private-defi-lane";
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_WALLETS: usize = 2_048;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_SESSIONS: usize = 16_384;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_INTENTS: usize = 65_536;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_HINTS: usize = 65_536;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_SPONSORSHIPS: usize = 65_536;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_BATCHES: usize = 8_192;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_POLICIES: usize = 8_192;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECEIPTS: usize = 131_072;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_NULLIFIERS: usize = 262_144;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_RATE_LIMITS: usize = 16_384;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECOVERY_DELEGATIONS: usize = 8_192;
pub const PRIVATE_WALLET_INTENT_GATEWAY_MAX_PUBLIC_RECORDS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletIntentKind {
    PrivateTransfer,
    SwapExactIn,
    SwapExactOut,
    LendSupply,
    LendBorrow,
    LendRepay,
    LendWithdraw,
    TokenMint,
    TokenBurn,
    ContractCall,
    SmartAccountAction,
    BridgeIn,
    BridgeOut,
    RecoveryAction,
    Composite,
    Custom(String),
}

impl WalletIntentKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::PrivateTransfer => "private_transfer".to_string(),
            Self::SwapExactIn => "swap_exact_in".to_string(),
            Self::SwapExactOut => "swap_exact_out".to_string(),
            Self::LendSupply => "lend_supply".to_string(),
            Self::LendBorrow => "lend_borrow".to_string(),
            Self::LendRepay => "lend_repay".to_string(),
            Self::LendWithdraw => "lend_withdraw".to_string(),
            Self::TokenMint => "token_mint".to_string(),
            Self::TokenBurn => "token_burn".to_string(),
            Self::ContractCall => "contract_call".to_string(),
            Self::SmartAccountAction => "smart_account_action".to_string(),
            Self::BridgeIn => "bridge_in".to_string(),
            Self::BridgeOut => "bridge_out".to_string(),
            Self::RecoveryAction => "recovery_action".to_string(),
            Self::Composite => "composite".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn default_lane_id(&self) -> &'static str {
        match self {
            Self::PrivateTransfer | Self::BridgeIn | Self::BridgeOut | Self::RecoveryAction => {
                PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID
            }
            Self::SwapExactIn
            | Self::SwapExactOut
            | Self::LendSupply
            | Self::LendBorrow
            | Self::LendRepay
            | Self::LendWithdraw
            | Self::TokenMint
            | Self::TokenBurn
            | Self::ContractCall
            | Self::SmartAccountAction
            | Self::Composite
            | Self::Custom(_) => PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRole {
    Owner,
    SessionSigner,
    Paymaster,
    Relayer,
    WatchOnly,
    RecoveryGuardian,
    PolicyDelegate,
    DevnetFixture,
}

impl WalletRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::SessionSigner => "session_signer",
            Self::Paymaster => "paymaster",
            Self::Relayer => "relayer",
            Self::WatchOnly => "watch_only",
            Self::RecoveryGuardian => "recovery_guardian",
            Self::PolicyDelegate => "policy_delegate",
            Self::DevnetFixture => "devnet_fixture",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletIntentStatus {
    Encrypted,
    Admitted,
    Sponsored,
    Batched,
    Submitted,
    Preconfirmed,
    Settled,
    Rejected,
    Expired,
    Cancelled,
    Quarantined,
}

impl WalletIntentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encrypted => "encrypted",
            Self::Admitted => "admitted",
            Self::Sponsored => "sponsored",
            Self::Batched => "batched",
            Self::Submitted => "submitted",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn live(&self) -> bool {
        matches!(
            self,
            Self::Encrypted
                | Self::Admitted
                | Self::Sponsored
                | Self::Batched
                | Self::Submitted
                | Self::Preconfirmed
        )
    }

    pub fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Rejected | Self::Expired | Self::Cancelled | Self::Quarantined
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSessionStatus {
    Pending,
    Active,
    Rotating,
    Expired,
    Revoked,
    Quarantined,
}

impl PqSessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn usable(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKeyHintScope {
    None,
    BalanceOnly,
    AmountBucket,
    AssetBucket,
    RouteBucket,
    ComplianceTicket,
    RecoveryAudit,
}

impl ViewKeyHintScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::BalanceOnly => "balance_only",
            Self::AmountBucket => "amount_bucket",
            Self::AssetBucket => "asset_bucket",
            Self::RouteBucket => "route_bucket",
            Self::ComplianceTicket => "compliance_ticket",
            Self::RecoveryAudit => "recovery_audit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetClass {
    Strict,
    Standard,
    Sponsored,
    Defi,
    Contract,
    Recovery,
    Emergency,
}

impl PrivacyBudgetClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Standard => "standard",
            Self::Sponsored => "sponsored",
            Self::Defi => "defi",
            Self::Contract => "contract",
            Self::Recovery => "recovery",
            Self::Emergency => "emergency",
        }
    }

    pub fn default_budget_units(&self) -> u64 {
        match self {
            Self::Strict => 1,
            Self::Standard => 3,
            Self::Sponsored => 4,
            Self::Defi => 6,
            Self::Contract => 8,
            Self::Recovery => 2,
            Self::Emergency => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Quoted,
    Reserved,
    Applied,
    Settled,
    Reimbursed,
    Exhausted,
    Revoked,
    Expired,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quoted => "quoted",
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Settled => "settled",
            Self::Reimbursed => "reimbursed",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn spendable(&self) -> bool {
        matches!(self, Self::Quoted | Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Collecting,
    Sealed,
    Submitted,
    Preconfirmed,
    Settled,
    Challenged,
    Expired,
}

impl BatchStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Sealed => "sealed",
            Self::Submitted => "submitted",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Challenged => "challenged",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountPolicyMode {
    OwnerOnly,
    SessionKey,
    SpendingLimit,
    DefiAllowlist,
    ContractAllowlist,
    SponsoredLowFee,
    RecoveryDelegate,
    EmergencyFreeze,
}

impl AccountPolicyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OwnerOnly => "owner_only",
            Self::SessionKey => "session_key",
            Self::SpendingLimit => "spending_limit",
            Self::DefiAllowlist => "defi_allowlist",
            Self::ContractAllowlist => "contract_allowlist",
            Self::SponsoredLowFee => "sponsored_low_fee",
            Self::RecoveryDelegate => "recovery_delegate",
            Self::EmergencyFreeze => "emergency_freeze",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Accepted,
    Forwarded,
    Preconfirmed,
    Settled,
    Failed,
    Disputed,
    Expired,
}

impl ReceiptStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Forwarded => "forwarded",
            Self::Preconfirmed => "preconfirmed",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Disputed => "disputed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDelegationStatus {
    Pending,
    Active,
    Timelocked,
    Executed,
    Revoked,
    Expired,
}

impl RecoveryDelegationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Timelocked => "timelocked",
            Self::Executed => "executed",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletIntentGatewayConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub encryption_scheme: String,
    pub pq_session_scheme: String,
    pub view_key_hint_scheme: String,
    pub privacy_budget_scheme: String,
    pub sponsorship_scheme: String,
    pub batching_scheme: String,
    pub account_policy_scheme: String,
    pub receipt_scheme: String,
    pub recovery_scheme: String,
    pub current_height: u64,
    pub session_ttl_blocks: u64,
    pub intent_ttl_blocks: u64,
    pub batch_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub rate_window_blocks: u64,
    pub recovery_timelock_blocks: u64,
    pub max_intents_per_batch: usize,
    pub max_intents_per_session: u64,
    pub max_sponsored_fee_micro_units: u64,
    pub min_pq_security_bits: u16,
    pub fee_asset_id: String,
    pub default_fast_lane_id: String,
    pub default_defi_lane_id: String,
    pub low_fee_rebate_bps: u64,
    pub sponsor_exposure_bps: u64,
    pub require_replay_nullifier: bool,
    pub require_pq_auth: bool,
}

impl PrivateWalletIntentGatewayConfig {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PRIVATE_WALLET_INTENT_GATEWAY_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            encryption_scheme: PRIVATE_WALLET_INTENT_GATEWAY_ENCRYPTION_SCHEME.to_string(),
            pq_session_scheme: PRIVATE_WALLET_INTENT_GATEWAY_PQ_SESSION_SCHEME.to_string(),
            view_key_hint_scheme: PRIVATE_WALLET_INTENT_GATEWAY_VIEW_KEY_HINT_SCHEME.to_string(),
            privacy_budget_scheme: PRIVATE_WALLET_INTENT_GATEWAY_PRIVACY_BUDGET_SCHEME.to_string(),
            sponsorship_scheme: PRIVATE_WALLET_INTENT_GATEWAY_SPONSORSHIP_SCHEME.to_string(),
            batching_scheme: PRIVATE_WALLET_INTENT_GATEWAY_BATCHING_SCHEME.to_string(),
            account_policy_scheme: PRIVATE_WALLET_INTENT_GATEWAY_ACCOUNT_POLICY_SCHEME.to_string(),
            receipt_scheme: PRIVATE_WALLET_INTENT_GATEWAY_RECEIPT_SCHEME.to_string(),
            recovery_scheme: PRIVATE_WALLET_INTENT_GATEWAY_RECOVERY_SCHEME.to_string(),
            current_height: PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_HEIGHT,
            session_ttl_blocks: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_SESSION_TTL_BLOCKS,
            intent_ttl_blocks: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_INTENT_TTL_BLOCKS,
            batch_ttl_blocks: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_BATCH_TTL_BLOCKS,
            receipt_ttl_blocks: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RECEIPT_TTL_BLOCKS,
            rate_window_blocks: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RATE_WINDOW_BLOCKS,
            recovery_timelock_blocks:
                PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_RECOVERY_TIMELOCK_BLOCKS,
            max_intents_per_batch: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_INTENTS_PER_BATCH,
            max_intents_per_session: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_INTENTS_PER_SESSION,
            max_sponsored_fee_micro_units:
                PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MAX_SPONSORED_FEE_MICRO_UNITS,
            min_pq_security_bits: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            fee_asset_id: PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FEE_ASSET_ID.to_string(),
            default_fast_lane_id: PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID.to_string(),
            default_defi_lane_id: PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID.to_string(),
            low_fee_rebate_bps: 7_500,
            sponsor_exposure_bps: 4_000,
            require_replay_nullifier: true,
            require_pq_auth: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_wallet_intent_gateway_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "encryption_scheme": self.encryption_scheme,
            "pq_session_scheme": self.pq_session_scheme,
            "view_key_hint_scheme": self.view_key_hint_scheme,
            "privacy_budget_scheme": self.privacy_budget_scheme,
            "sponsorship_scheme": self.sponsorship_scheme,
            "batching_scheme": self.batching_scheme,
            "account_policy_scheme": self.account_policy_scheme,
            "receipt_scheme": self.receipt_scheme,
            "recovery_scheme": self.recovery_scheme,
            "current_height": self.current_height,
            "session_ttl_blocks": self.session_ttl_blocks,
            "intent_ttl_blocks": self.intent_ttl_blocks,
            "batch_ttl_blocks": self.batch_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "rate_window_blocks": self.rate_window_blocks,
            "recovery_timelock_blocks": self.recovery_timelock_blocks,
            "max_intents_per_batch": self.max_intents_per_batch,
            "max_intents_per_session": self.max_intents_per_session,
            "max_sponsored_fee_micro_units": self.max_sponsored_fee_micro_units,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fee_asset_id": self.fee_asset_id,
            "default_fast_lane_id": self.default_fast_lane_id,
            "default_defi_lane_id": self.default_defi_lane_id,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "sponsor_exposure_bps": self.sponsor_exposure_bps,
            "require_replay_nullifier": self.require_replay_nullifier,
            "require_pq_auth": self.require_pq_auth,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("encryption_scheme", &self.encryption_scheme)?;
        require_non_empty("pq_session_scheme", &self.pq_session_scheme)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_zero("session_ttl_blocks", self.session_ttl_blocks)?;
        require_non_zero("intent_ttl_blocks", self.intent_ttl_blocks)?;
        require_non_zero("batch_ttl_blocks", self.batch_ttl_blocks)?;
        require_non_zero("rate_window_blocks", self.rate_window_blocks)?;
        require_non_zero("recovery_timelock_blocks", self.recovery_timelock_blocks)?;
        if self.max_intents_per_batch == 0 {
            return Err("max_intents_per_batch must be non-zero".to_string());
        }
        if self.min_pq_security_bits < PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err("min_pq_security_bits is below devnet policy".to_string());
        }
        validate_bps("low_fee_rebate_bps", self.low_fee_rebate_bps)?;
        validate_bps("sponsor_exposure_bps", self.sponsor_exposure_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletIdentity {
    pub wallet_id: String,
    pub owner_commitment: String,
    pub account_commitment: String,
    pub roles: BTreeSet<WalletRole>,
    pub pq_identity_root: String,
    pub view_key_commitment: String,
    pub recovery_root: String,
    pub created_at_height: u64,
    pub metadata_commitment: String,
}

impl WalletIdentity {
    pub fn new(
        label: &str,
        roles: BTreeSet<WalletRole>,
        created_at_height: u64,
        metadata: &Value,
    ) -> Self {
        let wallet_id = private_wallet_intent_gateway_id("WALLET", &[label]);
        Self {
            owner_commitment: devnet_hash(&format!("{label}:owner")),
            account_commitment: devnet_hash(&format!("{label}:account")),
            pq_identity_root: devnet_hash(&format!("{label}:pq-identity")),
            view_key_commitment: devnet_hash(&format!("{label}:view-key")),
            recovery_root: domain_hash(
                "PRIVATE-WALLET-INTENT-GATEWAY-RECOVERY-ROOT",
                &[HashPart::Str(label), HashPart::Json(metadata)],
                32,
            ),
            wallet_id,
            roles,
            created_at_height,
            metadata_commitment: domain_hash(
                "PRIVATE-WALLET-INTENT-GATEWAY-WALLET-METADATA",
                &[HashPart::Json(metadata)],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_identity",
            "wallet_id": self.wallet_id,
            "owner_commitment": self.owner_commitment,
            "account_commitment": self.account_commitment,
            "roles": self.roles.iter().map(WalletRole::as_str).collect::<Vec<_>>(),
            "pq_identity_root": self.pq_identity_root,
            "view_key_commitment": self.view_key_commitment,
            "recovery_root": self.recovery_root,
            "created_at_height": self.created_at_height,
            "metadata_commitment": self.metadata_commitment,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("owner_commitment", &self.owner_commitment)?;
        require_non_empty("account_commitment", &self.account_commitment)?;
        require_non_empty("pq_identity_root", &self.pq_identity_root)?;
        require_non_empty("view_key_commitment", &self.view_key_commitment)?;
        if self.roles.is_empty() {
            return Err(format!("wallet {} has no roles", self.wallet_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqWalletSession {
    pub session_id: String,
    pub wallet_id: String,
    pub session_public_key_commitment: String,
    pub auth_transcript_hash: String,
    pub handshake_root: String,
    pub status: PqSessionStatus,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub max_intents: u64,
    pub used_intents: u64,
    pub allowed_kinds: BTreeSet<WalletIntentKind>,
    pub policy_ids: BTreeSet<String>,
    pub replay_domain: String,
    pub pq_security_bits: u16,
}

impl PqWalletSession {
    pub fn new(
        wallet_id: &str,
        label: &str,
        opened_at_height: u64,
        ttl_blocks: u64,
        max_intents: u64,
        allowed_kinds: BTreeSet<WalletIntentKind>,
        policy_ids: BTreeSet<String>,
    ) -> Self {
        let session_id = private_wallet_intent_gateway_id("SESSION", &[wallet_id, label]);
        Self {
            session_public_key_commitment: devnet_hash(&format!("{label}:session-pubkey")),
            auth_transcript_hash: devnet_hash(&format!("{label}:auth-transcript")),
            handshake_root: devnet_hash(&format!("{label}:handshake")),
            status: PqSessionStatus::Active,
            opened_at_height,
            expires_at_height: opened_at_height.saturating_add(ttl_blocks),
            max_intents,
            used_intents: 0,
            replay_domain: private_wallet_intent_gateway_id("REPLAY-DOMAIN", &[wallet_id, label]),
            pq_security_bits: PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS,
            session_id,
            wallet_id: wallet_id.to_string(),
            allowed_kinds,
            policy_ids,
        }
    }

    pub fn accepts_kind(&self, kind: &WalletIntentKind) -> bool {
        self.allowed_kinds.contains(kind)
            || self.allowed_kinds.contains(&WalletIntentKind::Composite)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_wallet_session",
            "session_id": self.session_id,
            "wallet_id": self.wallet_id,
            "session_public_key_commitment": self.session_public_key_commitment,
            "auth_transcript_hash": self.auth_transcript_hash,
            "handshake_root": self.handshake_root,
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "max_intents": self.max_intents,
            "used_intents": self.used_intents,
            "allowed_kinds": self.allowed_kinds.iter().map(WalletIntentKind::as_str).collect::<Vec<_>>(),
            "policy_ids": self.policy_ids.iter().cloned().collect::<Vec<_>>(),
            "replay_domain": self.replay_domain,
            "pq_security_bits": self.pq_security_bits,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty(
            "session_public_key_commitment",
            &self.session_public_key_commitment,
        )?;
        require_non_empty("auth_transcript_hash", &self.auth_transcript_hash)?;
        if self.expires_at_height <= self.opened_at_height {
            return Err(format!("session {} has invalid expiry", self.session_id));
        }
        if self.used_intents > self.max_intents {
            return Err(format!("session {} exceeded intent cap", self.session_id));
        }
        if self.allowed_kinds.is_empty() {
            return Err(format!("session {} has no allowed kinds", self.session_id));
        }
        if self.pq_security_bits < PRIVATE_WALLET_INTENT_GATEWAY_DEFAULT_MIN_PQ_SECURITY_BITS {
            return Err(format!("session {} pq security too low", self.session_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewKeyPrivacyHint {
    pub hint_id: String,
    pub wallet_id: String,
    pub intent_id: String,
    pub scope: ViewKeyHintScope,
    pub privacy_budget_class: PrivacyBudgetClass,
    pub budget_units: u64,
    pub view_tag_root: String,
    pub disclosure_commitment: String,
    pub audit_nullifier: String,
    pub expires_at_height: u64,
}

impl ViewKeyPrivacyHint {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "view_key_privacy_hint",
            "hint_id": self.hint_id,
            "wallet_id": self.wallet_id,
            "intent_id": self.intent_id,
            "scope": self.scope.as_str(),
            "privacy_budget_class": self.privacy_budget_class.as_str(),
            "budget_units": self.budget_units,
            "view_tag_root": self.view_tag_root,
            "disclosure_commitment": self.disclosure_commitment,
            "audit_nullifier": self.audit_nullifier,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("hint_id", &self.hint_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("view_tag_root", &self.view_tag_root)?;
        require_non_empty("audit_nullifier", &self.audit_nullifier)?;
        require_non_zero("budget_units", self.budget_units)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedWalletIntent {
    pub intent_id: String,
    pub wallet_id: String,
    pub session_id: String,
    pub kind: WalletIntentKind,
    pub status: WalletIntentStatus,
    pub encrypted_payload_root: String,
    pub payload_ciphertext_commitment: String,
    pub note_commitment_root: String,
    pub account_policy_id: String,
    pub lane_id: String,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub sponsorship_id: Option<String>,
    pub view_hint_id: Option<String>,
    pub replay_nullifier: String,
    pub intent_nullifier: String,
    pub dependency_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub priority_score: u64,
}

impl EncryptedWalletIntent {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "encrypted_wallet_intent",
            "intent_id": self.intent_id,
            "wallet_id": self.wallet_id,
            "session_id": self.session_id,
            "intent_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "encrypted_payload_root": self.encrypted_payload_root,
            "payload_ciphertext_commitment": self.payload_ciphertext_commitment,
            "note_commitment_root": self.note_commitment_root,
            "account_policy_id": self.account_policy_id,
            "lane_id": self.lane_id,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "sponsorship_id": self.sponsorship_id,
            "view_hint_id": self.view_hint_id,
            "replay_nullifier": self.replay_nullifier,
            "intent_nullifier": self.intent_nullifier,
            "dependency_root": self.dependency_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "priority_score": self.priority_score,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_non_empty(
            "payload_ciphertext_commitment",
            &self.payload_ciphertext_commitment,
        )?;
        require_non_empty("note_commitment_root", &self.note_commitment_root)?;
        require_non_empty("account_policy_id", &self.account_policy_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("replay_nullifier", &self.replay_nullifier)?;
        require_non_empty("intent_nullifier", &self.intent_nullifier)?;
        if self.expires_at_height <= self.created_at_height {
            return Err(format!("intent {} has invalid expiry", self.intent_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorship {
    pub sponsorship_id: String,
    pub sponsor_wallet_id: String,
    pub beneficiary_wallet_id: String,
    pub intent_id: String,
    pub lane_id: String,
    pub status: SponsorshipStatus,
    pub fee_asset_id: String,
    pub reserved_fee_micro_units: u64,
    pub rebate_bps: u64,
    pub sponsor_budget_root: String,
    pub eligibility_proof_root: String,
    pub spend_nullifier: String,
    pub expires_at_height: u64,
}

impl LowFeeSponsorship {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsorship",
            "sponsorship_id": self.sponsorship_id,
            "sponsor_wallet_id": self.sponsor_wallet_id,
            "beneficiary_wallet_id": self.beneficiary_wallet_id,
            "intent_id": self.intent_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "reserved_fee_micro_units": self.reserved_fee_micro_units,
            "rebate_bps": self.rebate_bps,
            "sponsor_budget_root": self.sponsor_budget_root,
            "eligibility_proof_root": self.eligibility_proof_root,
            "spend_nullifier": self.spend_nullifier,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("sponsorship_id", &self.sponsorship_id)?;
        require_non_empty("sponsor_wallet_id", &self.sponsor_wallet_id)?;
        require_non_empty("beneficiary_wallet_id", &self.beneficiary_wallet_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_non_empty("spend_nullifier", &self.spend_nullifier)?;
        require_non_zero("reserved_fee_micro_units", self.reserved_fee_micro_units)?;
        validate_bps("rebate_bps", self.rebate_bps)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSubmissionBatch {
    pub batch_id: String,
    pub relayer_wallet_id: String,
    pub lane_id: String,
    pub status: BatchStatus,
    pub intent_ids: Vec<String>,
    pub intent_root: String,
    pub encrypted_payload_root: String,
    pub sponsorship_root: String,
    pub nullifier_root: String,
    pub account_policy_root: String,
    pub batch_fee_micro_units: u64,
    pub sealed_at_height: u64,
    pub expires_at_height: u64,
    pub sequencer_preconfirmation: Option<String>,
}

impl IntentSubmissionBatch {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_submission_batch",
            "batch_id": self.batch_id,
            "relayer_wallet_id": self.relayer_wallet_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "intent_ids": self.intent_ids,
            "intent_root": self.intent_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "sponsorship_root": self.sponsorship_root,
            "nullifier_root": self.nullifier_root,
            "account_policy_root": self.account_policy_root,
            "batch_fee_micro_units": self.batch_fee_micro_units,
            "sealed_at_height": self.sealed_at_height,
            "expires_at_height": self.expires_at_height,
            "sequencer_preconfirmation": self.sequencer_preconfirmation,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("batch_id", &self.batch_id)?;
        require_non_empty("relayer_wallet_id", &self.relayer_wallet_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        require_non_empty("intent_root", &self.intent_root)?;
        require_non_empty("encrypted_payload_root", &self.encrypted_payload_root)?;
        require_non_empty("nullifier_root", &self.nullifier_root)?;
        if self.intent_ids.is_empty() {
            return Err(format!("batch {} has no intents", self.batch_id));
        }
        if self.expires_at_height <= self.sealed_at_height {
            return Err(format!("batch {} has invalid expiry", self.batch_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountAbstractionPolicy {
    pub policy_id: String,
    pub wallet_id: String,
    pub mode: AccountPolicyMode,
    pub status: PqSessionStatus,
    pub allowed_contract_root: String,
    pub allowed_asset_root: String,
    pub spend_limit_commitment: String,
    pub session_scope_root: String,
    pub paymaster_scope_root: String,
    pub recovery_scope_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
}

impl AccountAbstractionPolicy {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "account_abstraction_policy",
            "policy_id": self.policy_id,
            "wallet_id": self.wallet_id,
            "mode": self.mode.as_str(),
            "status": self.status.as_str(),
            "allowed_contract_root": self.allowed_contract_root,
            "allowed_asset_root": self.allowed_asset_root,
            "spend_limit_commitment": self.spend_limit_commitment,
            "session_scope_root": self.session_scope_root,
            "paymaster_scope_root": self.paymaster_scope_root,
            "recovery_scope_root": self.recovery_scope_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("policy_id", &self.policy_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("allowed_contract_root", &self.allowed_contract_root)?;
        require_non_empty("allowed_asset_root", &self.allowed_asset_root)?;
        require_non_empty("spend_limit_commitment", &self.spend_limit_commitment)?;
        if self.expires_at_height <= self.created_at_height {
            return Err(format!("policy {} has invalid expiry", self.policy_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerReceipt {
    pub receipt_id: String,
    pub relayer_wallet_id: String,
    pub intent_id: String,
    pub batch_id: Option<String>,
    pub status: ReceiptStatus,
    pub received_at_height: u64,
    pub expires_at_height: u64,
    pub relay_fee_micro_units: u64,
    pub delivery_proof_root: String,
    pub preconfirmation_root: String,
    pub settlement_root: String,
    pub failure_code: Option<String>,
}

impl RelayerReceipt {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "relayer_receipt",
            "receipt_id": self.receipt_id,
            "relayer_wallet_id": self.relayer_wallet_id,
            "intent_id": self.intent_id,
            "batch_id": self.batch_id,
            "status": self.status.as_str(),
            "received_at_height": self.received_at_height,
            "expires_at_height": self.expires_at_height,
            "relay_fee_micro_units": self.relay_fee_micro_units,
            "delivery_proof_root": self.delivery_proof_root,
            "preconfirmation_root": self.preconfirmation_root,
            "settlement_root": self.settlement_root,
            "failure_code": self.failure_code,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("receipt_id", &self.receipt_id)?;
        require_non_empty("relayer_wallet_id", &self.relayer_wallet_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("delivery_proof_root", &self.delivery_proof_root)?;
        if self.expires_at_height <= self.received_at_height {
            return Err(format!("receipt {} has invalid expiry", self.receipt_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayNullifierRecord {
    pub nullifier: String,
    pub wallet_id: String,
    pub session_id: String,
    pub intent_id: String,
    pub domain: String,
    pub first_seen_height: u64,
    pub spent: bool,
}

impl ReplayNullifierRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "replay_nullifier_record",
            "nullifier": self.nullifier,
            "wallet_id": self.wallet_id,
            "session_id": self.session_id,
            "intent_id": self.intent_id,
            "domain": self.domain,
            "first_seen_height": self.first_seen_height,
            "spent": self.spent,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("nullifier", &self.nullifier)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("intent_id", &self.intent_id)?;
        require_non_empty("domain", &self.domain)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitBucket {
    pub bucket_id: String,
    pub wallet_id: String,
    pub lane_id: String,
    pub window_start_height: u64,
    pub window_end_height: u64,
    pub max_intents: u64,
    pub used_intents: u64,
    pub max_fee_micro_units: u64,
    pub used_fee_micro_units: u64,
    pub nullifier_root: String,
}

impl RateLimitBucket {
    pub fn remaining_intents(&self) -> u64 {
        self.max_intents.saturating_sub(self.used_intents)
    }

    pub fn remaining_fee_micro_units(&self) -> u64 {
        self.max_fee_micro_units
            .saturating_sub(self.used_fee_micro_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "rate_limit_bucket",
            "bucket_id": self.bucket_id,
            "wallet_id": self.wallet_id,
            "lane_id": self.lane_id,
            "window_start_height": self.window_start_height,
            "window_end_height": self.window_end_height,
            "max_intents": self.max_intents,
            "used_intents": self.used_intents,
            "max_fee_micro_units": self.max_fee_micro_units,
            "used_fee_micro_units": self.used_fee_micro_units,
            "nullifier_root": self.nullifier_root,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("bucket_id", &self.bucket_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("lane_id", &self.lane_id)?;
        if self.window_end_height <= self.window_start_height {
            return Err(format!("rate bucket {} has invalid window", self.bucket_id));
        }
        if self.used_intents > self.max_intents {
            return Err(format!("rate bucket {} exceeds intents", self.bucket_id));
        }
        if self.used_fee_micro_units > self.max_fee_micro_units {
            return Err(format!("rate bucket {} exceeds fee", self.bucket_id));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryDelegation {
    pub delegation_id: String,
    pub wallet_id: String,
    pub guardian_wallet_id: String,
    pub status: RecoveryDelegationStatus,
    pub recovery_policy_root: String,
    pub guardian_auth_root: String,
    pub timelock_start_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub recovery_nullifier: String,
}

impl RecoveryDelegation {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "recovery_delegation",
            "delegation_id": self.delegation_id,
            "wallet_id": self.wallet_id,
            "guardian_wallet_id": self.guardian_wallet_id,
            "status": self.status.as_str(),
            "recovery_policy_root": self.recovery_policy_root,
            "guardian_auth_root": self.guardian_auth_root,
            "timelock_start_height": self.timelock_start_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "recovery_nullifier": self.recovery_nullifier,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("delegation_id", &self.delegation_id)?;
        require_non_empty("wallet_id", &self.wallet_id)?;
        require_non_empty("guardian_wallet_id", &self.guardian_wallet_id)?;
        require_non_empty("recovery_policy_root", &self.recovery_policy_root)?;
        require_non_empty("guardian_auth_root", &self.guardian_auth_root)?;
        require_non_empty("recovery_nullifier", &self.recovery_nullifier)?;
        if self.executable_at_height < self.timelock_start_height {
            return Err(format!(
                "recovery delegation {} has invalid timelock",
                self.delegation_id
            ));
        }
        if self.expires_at_height <= self.executable_at_height {
            return Err(format!(
                "recovery delegation {} has invalid expiry",
                self.delegation_id
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletIntentGatewayPublicRecord {
    pub record_id: String,
    pub record_type: String,
    pub subject_id: String,
    pub height: u64,
    pub payload_hash: String,
    pub payload: Value,
}

impl PrivateWalletIntentGatewayPublicRecord {
    pub fn new(record_type: &str, subject_id: &str, height: u64, payload: &Value) -> Self {
        let payload_hash = domain_hash(
            "PRIVATE-WALLET-INTENT-GATEWAY-PUBLIC-PAYLOAD",
            &[HashPart::Json(payload)],
            32,
        );
        let record_id = private_wallet_intent_gateway_id(
            "PUBLIC-RECORD",
            &[record_type, subject_id, &height.to_string(), &payload_hash],
        );
        Self {
            record_id,
            record_type: record_type.to_string(),
            subject_id: subject_id.to_string(),
            height,
            payload_hash,
            payload: payload.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_wallet_intent_gateway_public_record",
            "record_id": self.record_id,
            "record_type": self.record_type,
            "subject_id": self.subject_id,
            "height": self.height,
            "payload_hash": self.payload_hash,
            "payload": self.payload,
        })
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<()> {
        require_non_empty("record_id", &self.record_id)?;
        require_non_empty("record_type", &self.record_type)?;
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("payload_hash", &self.payload_hash)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletIntentGatewayRoots {
    pub wallet_root: String,
    pub session_root: String,
    pub intent_root: String,
    pub view_hint_root: String,
    pub sponsorship_root: String,
    pub batch_root: String,
    pub account_policy_root: String,
    pub receipt_root: String,
    pub replay_nullifier_root: String,
    pub rate_limit_root: String,
    pub recovery_delegation_root: String,
    pub public_record_root: String,
}

impl PrivateWalletIntentGatewayRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_wallet_intent_gateway_roots",
            "wallet_root": self.wallet_root,
            "session_root": self.session_root,
            "intent_root": self.intent_root,
            "view_hint_root": self.view_hint_root,
            "sponsorship_root": self.sponsorship_root,
            "batch_root": self.batch_root,
            "account_policy_root": self.account_policy_root,
            "receipt_root": self.receipt_root,
            "replay_nullifier_root": self.replay_nullifier_root,
            "rate_limit_root": self.rate_limit_root,
            "recovery_delegation_root": self.recovery_delegation_root,
            "public_record_root": self.public_record_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletIntentGatewayCounters {
    pub wallet_count: u64,
    pub active_session_count: u64,
    pub live_intent_count: u64,
    pub sponsored_intent_count: u64,
    pub batch_count: u64,
    pub receipt_count: u64,
    pub spent_nullifier_count: u64,
    pub active_rate_limit_count: u64,
    pub active_recovery_delegation_count: u64,
    pub public_record_count: u64,
}

impl PrivateWalletIntentGatewayCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_wallet_intent_gateway_counters",
            "wallet_count": self.wallet_count,
            "active_session_count": self.active_session_count,
            "live_intent_count": self.live_intent_count,
            "sponsored_intent_count": self.sponsored_intent_count,
            "batch_count": self.batch_count,
            "receipt_count": self.receipt_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "active_rate_limit_count": self.active_rate_limit_count,
            "active_recovery_delegation_count": self.active_recovery_delegation_count,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletIntentRequest {
    pub wallet_id: String,
    pub session_id: String,
    pub kind: WalletIntentKind,
    pub encrypted_payload: Value,
    pub account_policy_id: String,
    pub lane_id: Option<String>,
    pub fee_asset_id: Option<String>,
    pub max_fee_micro_units: u64,
    pub privacy_budget_class: PrivacyBudgetClass,
    pub view_hint_scope: ViewKeyHintScope,
    pub priority_score: u64,
    pub dependency_commitments: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateWalletIntentGatewayState {
    pub config: PrivateWalletIntentGatewayConfig,
    pub wallets: BTreeMap<String, WalletIdentity>,
    pub sessions: BTreeMap<String, PqWalletSession>,
    pub intents: BTreeMap<String, EncryptedWalletIntent>,
    pub view_hints: BTreeMap<String, ViewKeyPrivacyHint>,
    pub sponsorships: BTreeMap<String, LowFeeSponsorship>,
    pub batches: BTreeMap<String, IntentSubmissionBatch>,
    pub account_policies: BTreeMap<String, AccountAbstractionPolicy>,
    pub receipts: BTreeMap<String, RelayerReceipt>,
    pub replay_nullifiers: BTreeMap<String, ReplayNullifierRecord>,
    pub rate_limits: BTreeMap<String, RateLimitBucket>,
    pub recovery_delegations: BTreeMap<String, RecoveryDelegation>,
    pub public_records: BTreeMap<String, PrivateWalletIntentGatewayPublicRecord>,
}

impl PrivateWalletIntentGatewayState {
    pub fn with_config(config: PrivateWalletIntentGatewayConfig) -> Self {
        Self {
            config,
            wallets: BTreeMap::new(),
            sessions: BTreeMap::new(),
            intents: BTreeMap::new(),
            view_hints: BTreeMap::new(),
            sponsorships: BTreeMap::new(),
            batches: BTreeMap::new(),
            account_policies: BTreeMap::new(),
            receipts: BTreeMap::new(),
            replay_nullifiers: BTreeMap::new(),
            rate_limits: BTreeMap::new(),
            recovery_delegations: BTreeMap::new(),
            public_records: BTreeMap::new(),
        }
    }

    pub fn devnet() -> PrivateWalletIntentGatewayResult<Self> {
        let mut state = Self::with_config(PrivateWalletIntentGatewayConfig::devnet());
        let owner_roles = BTreeSet::from([WalletRole::Owner, WalletRole::SessionSigner]);
        let sponsor_roles = BTreeSet::from([WalletRole::Paymaster, WalletRole::DevnetFixture]);
        let relayer_roles = BTreeSet::from([WalletRole::Relayer, WalletRole::DevnetFixture]);
        let guardian_roles = BTreeSet::from([WalletRole::RecoveryGuardian, WalletRole::WatchOnly]);

        let alice = state.register_wallet(
            WalletIdentity::new(
                "devnet-alice-wallet",
                owner_roles,
                state.config.current_height,
                &json!({"profile": "mobile private DeFi wallet"}),
            ),
            true,
        )?;
        let sponsor = state.register_wallet(
            WalletIdentity::new(
                "devnet-low-fee-sponsor",
                sponsor_roles,
                state.config.current_height,
                &json!({"profile": "sponsored fee budget"}),
            ),
            true,
        )?;
        let relayer = state.register_wallet(
            WalletIdentity::new(
                "devnet-fast-relayer",
                relayer_roles,
                state.config.current_height,
                &json!({"profile": "fast private relayer"}),
            ),
            true,
        )?;
        let guardian = state.register_wallet(
            WalletIdentity::new(
                "devnet-recovery-guardian",
                guardian_roles,
                state.config.current_height,
                &json!({"profile": "pq recovery guardian"}),
            ),
            true,
        )?;

        let owner_policy = state.add_account_policy(
            &alice,
            AccountPolicyMode::SessionKey,
            &["private-transfer", "defi-vault", "token-router"],
            &["wxmr-devnet", "dusd-devnet"],
            state.config.current_height + 7_200,
        )?;
        let sponsor_policy = state.add_account_policy(
            &sponsor,
            AccountPolicyMode::SponsoredLowFee,
            &["paymaster"],
            &["wxmr-devnet"],
            state.config.current_height + 7_200,
        )?;

        let allowed_kinds = BTreeSet::from([
            WalletIntentKind::PrivateTransfer,
            WalletIntentKind::SwapExactIn,
            WalletIntentKind::LendSupply,
            WalletIntentKind::ContractCall,
            WalletIntentKind::Composite,
        ]);
        let session_id = state.open_pq_session(
            &alice,
            "devnet-alice-primary-session",
            allowed_kinds,
            BTreeSet::from([owner_policy.clone()]),
        )?;

        state.create_rate_limit_bucket(
            &alice,
            PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID,
            32,
            40_000,
        )?;
        state.create_rate_limit_bucket(
            &alice,
            PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID,
            64,
            25_000,
        )?;

        let swap_intent = state.submit_encrypted_intent(WalletIntentRequest {
            wallet_id: alice.clone(),
            session_id: session_id.clone(),
            kind: WalletIntentKind::SwapExactIn,
            encrypted_payload: json!({
                "ciphertext": devnet_hash("alice-swap-ciphertext"),
                "amount_bucket": "small",
                "route": "sealed"
            }),
            account_policy_id: owner_policy.clone(),
            lane_id: Some(PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID.to_string()),
            fee_asset_id: None,
            max_fee_micro_units: 900,
            privacy_budget_class: PrivacyBudgetClass::Defi,
            view_hint_scope: ViewKeyHintScope::AmountBucket,
            priority_score: 80,
            dependency_commitments: vec![devnet_hash("alice-swap-note")],
        })?;
        let transfer_intent = state.submit_encrypted_intent(WalletIntentRequest {
            wallet_id: alice.clone(),
            session_id,
            kind: WalletIntentKind::PrivateTransfer,
            encrypted_payload: json!({
                "ciphertext": devnet_hash("alice-transfer-ciphertext"),
                "amount_bucket": "micro",
                "recipient": "stealth"
            }),
            account_policy_id: owner_policy,
            lane_id: Some(PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID.to_string()),
            fee_asset_id: None,
            max_fee_micro_units: 400,
            privacy_budget_class: PrivacyBudgetClass::Sponsored,
            view_hint_scope: ViewKeyHintScope::BalanceOnly,
            priority_score: 96,
            dependency_commitments: vec![devnet_hash("alice-transfer-note")],
        })?;

        state.reserve_sponsorship(
            &sponsor,
            &swap_intent,
            PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_DEFI_LANE_ID,
            750,
            sponsor_policy.clone(),
        )?;
        state.reserve_sponsorship(
            &sponsor,
            &transfer_intent,
            PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID,
            350,
            sponsor_policy,
        )?;

        let batch_id = state.seal_batch(
            &relayer,
            PRIVATE_WALLET_INTENT_GATEWAY_DEVNET_FAST_LANE_ID,
            &[transfer_intent.clone()],
        )?;
        state.record_relayer_receipt(
            &relayer,
            &transfer_intent,
            Some(batch_id),
            ReceiptStatus::Preconfirmed,
            25,
            None,
        )?;
        state.delegate_recovery(&alice, &guardian, "devnet-guardian-policy")?;

        let snapshot = state.public_record_without_root();
        state.publish_public_record("gateway_snapshot", "devnet", &snapshot)?;
        state.validate()?;
        Ok(state)
    }

    pub fn register_wallet(
        &mut self,
        wallet: WalletIdentity,
        publish: bool,
    ) -> PrivateWalletIntentGatewayResult<String> {
        wallet.validate()?;
        if self.wallets.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_WALLETS {
            return Err("wallet capacity exhausted".to_string());
        }
        if self.wallets.contains_key(&wallet.wallet_id) {
            return Err(format!("wallet {} already exists", wallet.wallet_id));
        }
        let wallet_id = wallet.wallet_id.clone();
        if publish {
            self.publish_public_record("wallet_identity", &wallet_id, &wallet.public_record())?;
        }
        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(wallet_id)
    }

    pub fn open_pq_session(
        &mut self,
        wallet_id: &str,
        label: &str,
        allowed_kinds: BTreeSet<WalletIntentKind>,
        policy_ids: BTreeSet<String>,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(wallet_id)?;
        if self.sessions.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_SESSIONS {
            return Err("session capacity exhausted".to_string());
        }
        for policy_id in &policy_ids {
            self.ensure_policy(policy_id)?;
        }
        let session = PqWalletSession::new(
            wallet_id,
            label,
            self.config.current_height,
            self.config.session_ttl_blocks,
            self.config.max_intents_per_session,
            allowed_kinds,
            policy_ids,
        );
        session.validate()?;
        let session_id = session.session_id.clone();
        self.publish_public_record("pq_wallet_session", &session_id, &session.public_record())?;
        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    pub fn add_account_policy(
        &mut self,
        wallet_id: &str,
        mode: AccountPolicyMode,
        allowed_contracts: &[&str],
        allowed_assets: &[&str],
        expires_at_height: u64,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(wallet_id)?;
        if self.account_policies.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_POLICIES {
            return Err("account policy capacity exhausted".to_string());
        }
        let contract_leaves = allowed_contracts
            .iter()
            .map(|value| Value::String((*value).to_string()))
            .collect::<Vec<_>>();
        let asset_leaves = allowed_assets
            .iter()
            .map(|value| Value::String((*value).to_string()))
            .collect::<Vec<_>>();
        let policy_id = private_wallet_intent_gateway_id(
            "ACCOUNT-POLICY",
            &[wallet_id, mode.as_str(), &expires_at_height.to_string()],
        );
        let policy = AccountAbstractionPolicy {
            allowed_contract_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-ALLOWED-CONTRACT",
                &contract_leaves,
            ),
            allowed_asset_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-ALLOWED-ASSET",
                &asset_leaves,
            ),
            spend_limit_commitment: devnet_hash(&format!("{policy_id}:spend-limit")),
            session_scope_root: devnet_hash(&format!("{policy_id}:session-scope")),
            paymaster_scope_root: devnet_hash(&format!("{policy_id}:paymaster-scope")),
            recovery_scope_root: devnet_hash(&format!("{policy_id}:recovery-scope")),
            status: PqSessionStatus::Active,
            created_at_height: self.config.current_height,
            expires_at_height,
            policy_id: policy_id.clone(),
            wallet_id: wallet_id.to_string(),
            mode,
        };
        policy.validate()?;
        self.publish_public_record("account_policy", &policy_id, &policy.public_record())?;
        self.account_policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn submit_encrypted_intent(
        &mut self,
        request: WalletIntentRequest,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(&request.wallet_id)?;
        self.ensure_policy(&request.account_policy_id)?;
        self.enforce_session(&request.session_id, &request.wallet_id, &request.kind)?;
        let lane_id = request
            .lane_id
            .clone()
            .unwrap_or_else(|| request.kind.default_lane_id().to_string());
        self.consume_rate_limit(
            &request.wallet_id,
            &lane_id,
            request.max_fee_micro_units,
            &request.kind,
        )?;
        if self.intents.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_INTENTS {
            return Err("intent capacity exhausted".to_string());
        }
        let fee_asset_id = request
            .fee_asset_id
            .unwrap_or_else(|| self.config.fee_asset_id.clone());
        let payload_root = domain_hash(
            "PRIVATE-WALLET-INTENT-GATEWAY-ENCRYPTED-PAYLOAD",
            &[HashPart::Json(&request.encrypted_payload)],
            32,
        );
        let intent_id = private_wallet_intent_gateway_id(
            "INTENT",
            &[
                &request.wallet_id,
                &request.session_id,
                &request.kind.as_str(),
                &payload_root,
            ],
        );
        let replay_nullifier = private_wallet_intent_gateway_id(
            "REPLAY-NULLIFIER",
            &[&request.session_id, &intent_id, &payload_root],
        );
        if self.replay_nullifiers.contains_key(&replay_nullifier) {
            return Err(format!(
                "replay nullifier {} already seen",
                replay_nullifier
            ));
        }
        let intent_nullifier =
            private_wallet_intent_gateway_id("INTENT-NULLIFIER", &[&intent_id, &replay_nullifier]);
        let dependency_root = merkle_root(
            "PRIVATE-WALLET-INTENT-GATEWAY-DEPENDENCY",
            &request
                .dependency_commitments
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect::<Vec<_>>(),
        );
        let hint_id = self.create_view_hint(
            &request.wallet_id,
            &intent_id,
            request.view_hint_scope,
            request.privacy_budget_class,
        )?;
        let intent = EncryptedWalletIntent {
            wallet_id: request.wallet_id.clone(),
            session_id: request.session_id.clone(),
            kind: request.kind,
            status: WalletIntentStatus::Admitted,
            encrypted_payload_root: payload_root,
            payload_ciphertext_commitment: domain_hash(
                "PRIVATE-WALLET-INTENT-GATEWAY-CIPHERTEXT-COMMITMENT",
                &[HashPart::Json(&request.encrypted_payload)],
                32,
            ),
            note_commitment_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-NOTE-COMMITMENT",
                &request
                    .dependency_commitments
                    .iter()
                    .map(|value| Value::String(value.clone()))
                    .collect::<Vec<_>>(),
            ),
            account_policy_id: request.account_policy_id,
            lane_id,
            fee_asset_id,
            max_fee_micro_units: request.max_fee_micro_units,
            sponsorship_id: None,
            view_hint_id: Some(hint_id),
            replay_nullifier: replay_nullifier.clone(),
            intent_nullifier,
            dependency_root,
            created_at_height: self.config.current_height,
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.intent_ttl_blocks),
            priority_score: request.priority_score,
            intent_id: intent_id.clone(),
        };
        intent.validate()?;
        let nullifier_record = ReplayNullifierRecord {
            nullifier: replay_nullifier.clone(),
            wallet_id: request.wallet_id,
            session_id: request.session_id,
            intent_id: intent_id.clone(),
            domain: PRIVATE_WALLET_INTENT_GATEWAY_PROTOCOL_VERSION.to_string(),
            first_seen_height: self.config.current_height,
            spent: true,
        };
        nullifier_record.validate()?;
        if let Some(session) = self.sessions.get_mut(&intent.session_id) {
            session.used_intents = session.used_intents.saturating_add(1);
        }
        self.publish_public_record(
            "encrypted_wallet_intent",
            &intent_id,
            &intent.public_record(),
        )?;
        self.replay_nullifiers
            .insert(replay_nullifier, nullifier_record);
        self.intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn reserve_sponsorship(
        &mut self,
        sponsor_wallet_id: &str,
        intent_id: &str,
        lane_id: &str,
        reserved_fee_micro_units: u64,
        sponsor_policy_id: String,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(sponsor_wallet_id)?;
        self.ensure_policy(&sponsor_policy_id)?;
        let intent = self
            .intents
            .get(intent_id)
            .cloned()
            .ok_or_else(|| format!("intent {intent_id} is missing"))?;
        if reserved_fee_micro_units > self.config.max_sponsored_fee_micro_units {
            return Err("reserved fee exceeds sponsorship cap".to_string());
        }
        if reserved_fee_micro_units > intent.max_fee_micro_units {
            return Err("reserved fee exceeds intent fee cap".to_string());
        }
        if self.sponsorships.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_SPONSORSHIPS {
            return Err("sponsorship capacity exhausted".to_string());
        }
        let sponsorship_id = private_wallet_intent_gateway_id(
            "SPONSORSHIP",
            &[sponsor_wallet_id, intent_id, lane_id, &sponsor_policy_id],
        );
        let sponsorship = LowFeeSponsorship {
            sponsorship_id: sponsorship_id.clone(),
            sponsor_wallet_id: sponsor_wallet_id.to_string(),
            beneficiary_wallet_id: intent.wallet_id.clone(),
            intent_id: intent_id.to_string(),
            lane_id: lane_id.to_string(),
            status: SponsorshipStatus::Reserved,
            fee_asset_id: intent.fee_asset_id,
            reserved_fee_micro_units,
            rebate_bps: self.config.low_fee_rebate_bps,
            sponsor_budget_root: devnet_hash(&format!("{sponsorship_id}:budget")),
            eligibility_proof_root: devnet_hash(&format!("{sponsorship_id}:eligibility")),
            spend_nullifier: private_wallet_intent_gateway_id(
                "SPONSORSHIP-SPEND",
                &[&sponsorship_id, intent_id],
            ),
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.intent_ttl_blocks),
        };
        sponsorship.validate()?;
        if let Some(stored_intent) = self.intents.get_mut(intent_id) {
            stored_intent.status = WalletIntentStatus::Sponsored;
            stored_intent.sponsorship_id = Some(sponsorship_id.clone());
        }
        self.publish_public_record(
            "low_fee_sponsorship",
            &sponsorship_id,
            &sponsorship.public_record(),
        )?;
        self.sponsorships
            .insert(sponsorship_id.clone(), sponsorship);
        Ok(sponsorship_id)
    }

    pub fn seal_batch(
        &mut self,
        relayer_wallet_id: &str,
        lane_id: &str,
        intent_ids: &[String],
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(relayer_wallet_id)?;
        if intent_ids.is_empty() {
            return Err("batch requires at least one intent".to_string());
        }
        if intent_ids.len() > self.config.max_intents_per_batch {
            return Err("batch exceeds max_intents_per_batch".to_string());
        }
        if self.batches.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_BATCHES {
            return Err("batch capacity exhausted".to_string());
        }
        let mut intent_records = Vec::with_capacity(intent_ids.len());
        let mut payload_records = Vec::with_capacity(intent_ids.len());
        let mut sponsorship_records = Vec::new();
        let mut nullifier_records = Vec::with_capacity(intent_ids.len());
        let mut policy_records = Vec::with_capacity(intent_ids.len());
        for intent_id in intent_ids {
            let intent = self
                .intents
                .get(intent_id)
                .ok_or_else(|| format!("intent {intent_id} missing"))?;
            if intent.lane_id != lane_id {
                return Err(format!("intent {intent_id} is not in lane {lane_id}"));
            }
            if intent.status.terminal() {
                return Err(format!("intent {intent_id} is terminal"));
            }
            intent_records.push(intent.public_record());
            payload_records.push(Value::String(intent.encrypted_payload_root.clone()));
            nullifier_records.push(Value::String(intent.intent_nullifier.clone()));
            policy_records.push(Value::String(intent.account_policy_id.clone()));
            if let Some(sponsorship_id) = &intent.sponsorship_id {
                sponsorship_records.push(Value::String(sponsorship_id.clone()));
            }
        }
        let intent_root = merkle_root(
            "PRIVATE-WALLET-INTENT-GATEWAY-BATCH-INTENT",
            &intent_records,
        );
        let batch_id = private_wallet_intent_gateway_id(
            "BATCH",
            &[
                relayer_wallet_id,
                lane_id,
                &intent_root,
                &self.config.current_height.to_string(),
            ],
        );
        let batch = IntentSubmissionBatch {
            batch_id: batch_id.clone(),
            relayer_wallet_id: relayer_wallet_id.to_string(),
            lane_id: lane_id.to_string(),
            status: BatchStatus::Sealed,
            intent_ids: intent_ids.to_vec(),
            intent_root,
            encrypted_payload_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-BATCH-PAYLOAD",
                &payload_records,
            ),
            sponsorship_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-BATCH-SPONSORSHIP",
                &sponsorship_records,
            ),
            nullifier_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-BATCH-NULLIFIER",
                &nullifier_records,
            ),
            account_policy_root: merkle_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-BATCH-POLICY",
                &policy_records,
            ),
            batch_fee_micro_units: intent_ids.iter().fold(0_u64, |acc, intent_id| {
                acc.saturating_add(
                    self.intents
                        .get(intent_id)
                        .map(|intent| intent.max_fee_micro_units)
                        .unwrap_or(0),
                )
            }),
            sealed_at_height: self.config.current_height,
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.batch_ttl_blocks),
            sequencer_preconfirmation: Some(devnet_hash(&format!("{batch_id}:preconfirmation"))),
        };
        batch.validate()?;
        for intent_id in intent_ids {
            if let Some(intent) = self.intents.get_mut(intent_id) {
                intent.status = WalletIntentStatus::Batched;
            }
        }
        self.publish_public_record("intent_submission_batch", &batch_id, &batch.public_record())?;
        self.batches.insert(batch_id.clone(), batch);
        Ok(batch_id)
    }

    pub fn record_relayer_receipt(
        &mut self,
        relayer_wallet_id: &str,
        intent_id: &str,
        batch_id: Option<String>,
        status: ReceiptStatus,
        relay_fee_micro_units: u64,
        failure_code: Option<String>,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(relayer_wallet_id)?;
        self.ensure_intent(intent_id)?;
        if let Some(batch_id) = &batch_id {
            self.ensure_batch(batch_id)?;
        }
        if self.receipts.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECEIPTS {
            return Err("receipt capacity exhausted".to_string());
        }
        let receipt_id = private_wallet_intent_gateway_id(
            "RECEIPT",
            &[
                relayer_wallet_id,
                intent_id,
                batch_id.as_deref().unwrap_or("unbatched"),
                status.as_str(),
            ],
        );
        let receipt = RelayerReceipt {
            receipt_id: receipt_id.clone(),
            relayer_wallet_id: relayer_wallet_id.to_string(),
            intent_id: intent_id.to_string(),
            batch_id,
            status,
            received_at_height: self.config.current_height,
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.receipt_ttl_blocks),
            relay_fee_micro_units,
            delivery_proof_root: devnet_hash(&format!("{receipt_id}:delivery")),
            preconfirmation_root: devnet_hash(&format!("{receipt_id}:preconfirmation")),
            settlement_root: devnet_hash(&format!("{receipt_id}:settlement")),
            failure_code,
        };
        receipt.validate()?;
        if let Some(intent) = self.intents.get_mut(intent_id) {
            intent.status = match receipt.status {
                ReceiptStatus::Preconfirmed => WalletIntentStatus::Preconfirmed,
                ReceiptStatus::Settled => WalletIntentStatus::Settled,
                ReceiptStatus::Failed | ReceiptStatus::Disputed => WalletIntentStatus::Rejected,
                _ => intent.status.clone(),
            };
        }
        self.publish_public_record("relayer_receipt", &receipt_id, &receipt.public_record())?;
        self.receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn create_rate_limit_bucket(
        &mut self,
        wallet_id: &str,
        lane_id: &str,
        max_intents: u64,
        max_fee_micro_units: u64,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(wallet_id)?;
        if self.rate_limits.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_RATE_LIMITS {
            return Err("rate limit capacity exhausted".to_string());
        }
        let bucket_id = private_wallet_intent_gateway_id(
            "RATE-LIMIT",
            &[wallet_id, lane_id, &self.config.current_height.to_string()],
        );
        let bucket = RateLimitBucket {
            bucket_id: bucket_id.clone(),
            wallet_id: wallet_id.to_string(),
            lane_id: lane_id.to_string(),
            window_start_height: self.config.current_height,
            window_end_height: self
                .config
                .current_height
                .saturating_add(self.config.rate_window_blocks),
            max_intents,
            used_intents: 0,
            max_fee_micro_units,
            used_fee_micro_units: 0,
            nullifier_root: merkle_root("PRIVATE-WALLET-INTENT-GATEWAY-RATE-NULLIFIER", &[]),
        };
        bucket.validate()?;
        self.publish_public_record("rate_limit_bucket", &bucket_id, &bucket.public_record())?;
        self.rate_limits.insert(bucket_id.clone(), bucket);
        Ok(bucket_id)
    }

    pub fn delegate_recovery(
        &mut self,
        wallet_id: &str,
        guardian_wallet_id: &str,
        policy_label: &str,
    ) -> PrivateWalletIntentGatewayResult<String> {
        self.ensure_wallet(wallet_id)?;
        self.ensure_wallet(guardian_wallet_id)?;
        if self.recovery_delegations.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECOVERY_DELEGATIONS
        {
            return Err("recovery delegation capacity exhausted".to_string());
        }
        let delegation_id = private_wallet_intent_gateway_id(
            "RECOVERY",
            &[wallet_id, guardian_wallet_id, policy_label],
        );
        let delegation = RecoveryDelegation {
            delegation_id: delegation_id.clone(),
            wallet_id: wallet_id.to_string(),
            guardian_wallet_id: guardian_wallet_id.to_string(),
            status: RecoveryDelegationStatus::Timelocked,
            recovery_policy_root: devnet_hash(&format!("{delegation_id}:policy")),
            guardian_auth_root: devnet_hash(&format!("{delegation_id}:guardian-auth")),
            timelock_start_height: self.config.current_height,
            executable_at_height: self
                .config
                .current_height
                .saturating_add(self.config.recovery_timelock_blocks),
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.recovery_timelock_blocks.saturating_mul(2)),
            recovery_nullifier: private_wallet_intent_gateway_id(
                "RECOVERY-NULLIFIER",
                &[wallet_id, guardian_wallet_id, policy_label],
            ),
        };
        delegation.validate()?;
        self.publish_public_record(
            "recovery_delegation",
            &delegation_id,
            &delegation.public_record(),
        )?;
        self.recovery_delegations
            .insert(delegation_id.clone(), delegation);
        Ok(delegation_id)
    }

    pub fn roots(&self) -> PrivateWalletIntentGatewayRoots {
        PrivateWalletIntentGatewayRoots {
            wallet_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-WALLET",
                self.wallets.values().map(WalletIdentity::public_record),
            ),
            session_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-SESSION",
                self.sessions.values().map(PqWalletSession::public_record),
            ),
            intent_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-INTENT",
                self.intents
                    .values()
                    .map(EncryptedWalletIntent::public_record),
            ),
            view_hint_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-VIEW-HINT",
                self.view_hints
                    .values()
                    .map(ViewKeyPrivacyHint::public_record),
            ),
            sponsorship_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-SPONSORSHIP",
                self.sponsorships
                    .values()
                    .map(LowFeeSponsorship::public_record),
            ),
            batch_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-BATCH",
                self.batches
                    .values()
                    .map(IntentSubmissionBatch::public_record),
            ),
            account_policy_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-ACCOUNT-POLICY",
                self.account_policies
                    .values()
                    .map(AccountAbstractionPolicy::public_record),
            ),
            receipt_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-RECEIPT",
                self.receipts.values().map(RelayerReceipt::public_record),
            ),
            replay_nullifier_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-REPLAY-NULLIFIER",
                self.replay_nullifiers
                    .values()
                    .map(ReplayNullifierRecord::public_record),
            ),
            rate_limit_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-RATE-LIMIT",
                self.rate_limits
                    .values()
                    .map(RateLimitBucket::public_record),
            ),
            recovery_delegation_root: map_root(
                "PRIVATE-WALLET-INTENT-GATEWAY-RECOVERY-DELEGATION",
                self.recovery_delegations
                    .values()
                    .map(RecoveryDelegation::public_record),
            ),
            public_record_root: private_wallet_intent_gateway_public_record_root(
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> PrivateWalletIntentGatewayCounters {
        PrivateWalletIntentGatewayCounters {
            wallet_count: self.wallets.len() as u64,
            active_session_count: self
                .sessions
                .values()
                .filter(|session| session.status.usable())
                .count() as u64,
            live_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.status.live())
                .count() as u64,
            sponsored_intent_count: self
                .intents
                .values()
                .filter(|intent| intent.sponsorship_id.is_some())
                .count() as u64,
            batch_count: self.batches.len() as u64,
            receipt_count: self.receipts.len() as u64,
            spent_nullifier_count: self
                .replay_nullifiers
                .values()
                .filter(|nullifier| nullifier.spent)
                .count() as u64,
            active_rate_limit_count: self
                .rate_limits
                .values()
                .filter(|bucket| bucket.remaining_intents() > 0)
                .count() as u64,
            active_recovery_delegation_count: self
                .recovery_delegations
                .values()
                .filter(|delegation| {
                    matches!(
                        delegation.status,
                        RecoveryDelegationStatus::Active | RecoveryDelegationStatus::Timelocked
                    )
                })
                .count() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        private_wallet_intent_gateway_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Some(object) = record.as_object_mut() {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn validate(&self) -> PrivateWalletIntentGatewayResult<String> {
        self.config.validate()?;
        validate_len(
            "wallets",
            self.wallets.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_WALLETS,
        )?;
        validate_len(
            "sessions",
            self.sessions.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_SESSIONS,
        )?;
        validate_len(
            "intents",
            self.intents.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_INTENTS,
        )?;
        validate_len(
            "view_hints",
            self.view_hints.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_HINTS,
        )?;
        validate_len(
            "sponsorships",
            self.sponsorships.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_SPONSORSHIPS,
        )?;
        validate_len(
            "batches",
            self.batches.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_BATCHES,
        )?;
        validate_len(
            "account_policies",
            self.account_policies.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_POLICIES,
        )?;
        validate_len(
            "receipts",
            self.receipts.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECEIPTS,
        )?;
        validate_len(
            "replay_nullifiers",
            self.replay_nullifiers.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_NULLIFIERS,
        )?;
        validate_len(
            "rate_limits",
            self.rate_limits.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_RATE_LIMITS,
        )?;
        validate_len(
            "recovery_delegations",
            self.recovery_delegations.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_RECOVERY_DELEGATIONS,
        )?;
        validate_len(
            "public_records",
            self.public_records.len(),
            PRIVATE_WALLET_INTENT_GATEWAY_MAX_PUBLIC_RECORDS,
        )?;
        for (wallet_id, wallet) in &self.wallets {
            if wallet_id != &wallet.wallet_id {
                return Err(format!("wallet map key mismatch for {wallet_id}"));
            }
            wallet.validate()?;
        }
        for session in self.sessions.values() {
            session.validate()?;
            self.ensure_wallet(&session.wallet_id)?;
            for policy_id in &session.policy_ids {
                self.ensure_policy(policy_id)?;
            }
        }
        let mut replay_seen = BTreeSet::new();
        for intent in self.intents.values() {
            intent.validate()?;
            self.ensure_wallet(&intent.wallet_id)?;
            self.ensure_policy(&intent.account_policy_id)?;
            if !self.sessions.contains_key(&intent.session_id) {
                return Err(format!(
                    "intent {} references missing session",
                    intent.intent_id
                ));
            }
            if !replay_seen.insert(intent.replay_nullifier.clone()) {
                return Err(format!(
                    "duplicate replay nullifier {}",
                    intent.replay_nullifier
                ));
            }
            if let Some(hint_id) = &intent.view_hint_id {
                if !self.view_hints.contains_key(hint_id) {
                    return Err(format!(
                        "intent {} references missing hint",
                        intent.intent_id
                    ));
                }
            }
            if let Some(sponsorship_id) = &intent.sponsorship_id {
                if !self.sponsorships.contains_key(sponsorship_id) {
                    return Err(format!(
                        "intent {} references missing sponsorship",
                        intent.intent_id
                    ));
                }
            }
        }
        for hint in self.view_hints.values() {
            hint.validate()?;
            self.ensure_wallet(&hint.wallet_id)?;
            self.ensure_intent(&hint.intent_id)?;
        }
        for sponsorship in self.sponsorships.values() {
            sponsorship.validate()?;
            self.ensure_wallet(&sponsorship.sponsor_wallet_id)?;
            self.ensure_wallet(&sponsorship.beneficiary_wallet_id)?;
            self.ensure_intent(&sponsorship.intent_id)?;
        }
        for batch in self.batches.values() {
            batch.validate()?;
            self.ensure_wallet(&batch.relayer_wallet_id)?;
            for intent_id in &batch.intent_ids {
                self.ensure_intent(intent_id)?;
            }
        }
        for policy in self.account_policies.values() {
            policy.validate()?;
            self.ensure_wallet(&policy.wallet_id)?;
        }
        for receipt in self.receipts.values() {
            receipt.validate()?;
            self.ensure_wallet(&receipt.relayer_wallet_id)?;
            self.ensure_intent(&receipt.intent_id)?;
            if let Some(batch_id) = &receipt.batch_id {
                self.ensure_batch(batch_id)?;
            }
        }
        for nullifier in self.replay_nullifiers.values() {
            nullifier.validate()?;
            self.ensure_wallet(&nullifier.wallet_id)?;
            self.ensure_intent(&nullifier.intent_id)?;
        }
        for bucket in self.rate_limits.values() {
            bucket.validate()?;
            self.ensure_wallet(&bucket.wallet_id)?;
        }
        for delegation in self.recovery_delegations.values() {
            delegation.validate()?;
            self.ensure_wallet(&delegation.wallet_id)?;
            self.ensure_wallet(&delegation.guardian_wallet_id)?;
        }
        for record in self.public_records.values() {
            record.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_wallet_intent_gateway_state",
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "wallet_root": roots.wallet_root,
            "session_root": roots.session_root,
            "intent_root": roots.intent_root,
            "view_hint_root": roots.view_hint_root,
            "sponsorship_root": roots.sponsorship_root,
            "batch_root": roots.batch_root,
            "account_policy_root": roots.account_policy_root,
            "receipt_root": roots.receipt_root,
            "replay_nullifier_root": roots.replay_nullifier_root,
            "rate_limit_root": roots.rate_limit_root,
            "recovery_delegation_root": roots.recovery_delegation_root,
            "public_record_root": roots.public_record_root,
        })
    }

    fn publish_public_record(
        &mut self,
        record_type: &str,
        subject_id: &str,
        payload: &Value,
    ) -> PrivateWalletIntentGatewayResult<String> {
        if self.public_records.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_PUBLIC_RECORDS {
            return Err("public record capacity exhausted".to_string());
        }
        let record = PrivateWalletIntentGatewayPublicRecord::new(
            record_type,
            subject_id,
            self.config.current_height,
            payload,
        );
        let record_id = record.record_id.clone();
        self.public_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    fn create_view_hint(
        &mut self,
        wallet_id: &str,
        intent_id: &str,
        scope: ViewKeyHintScope,
        privacy_budget_class: PrivacyBudgetClass,
    ) -> PrivateWalletIntentGatewayResult<String> {
        if self.view_hints.len() >= PRIVATE_WALLET_INTENT_GATEWAY_MAX_HINTS {
            return Err("view hint capacity exhausted".to_string());
        }
        let budget_units = privacy_budget_class.default_budget_units();
        let hint_id = private_wallet_intent_gateway_id(
            "VIEW-HINT",
            &[
                wallet_id,
                intent_id,
                scope.as_str(),
                privacy_budget_class.as_str(),
            ],
        );
        let hint = ViewKeyPrivacyHint {
            hint_id: hint_id.clone(),
            wallet_id: wallet_id.to_string(),
            intent_id: intent_id.to_string(),
            scope,
            privacy_budget_class,
            budget_units,
            view_tag_root: devnet_hash(&format!("{hint_id}:view-tags")),
            disclosure_commitment: devnet_hash(&format!("{hint_id}:disclosure")),
            audit_nullifier: private_wallet_intent_gateway_id(
                "VIEW-HINT-AUDIT",
                &[wallet_id, intent_id, &hint_id],
            ),
            expires_at_height: self
                .config
                .current_height
                .saturating_add(self.config.receipt_ttl_blocks),
        };
        hint.validate()?;
        self.publish_public_record("view_key_privacy_hint", &hint_id, &hint.public_record())?;
        self.view_hints.insert(hint_id.clone(), hint);
        Ok(hint_id)
    }

    fn consume_rate_limit(
        &mut self,
        wallet_id: &str,
        lane_id: &str,
        fee_micro_units: u64,
        kind: &WalletIntentKind,
    ) -> PrivateWalletIntentGatewayResult<()> {
        let mut selected_bucket_id = None;
        for (bucket_id, bucket) in &self.rate_limits {
            if bucket.wallet_id == wallet_id
                && bucket.lane_id == lane_id
                && bucket.window_start_height <= self.config.current_height
                && bucket.window_end_height >= self.config.current_height
                && bucket.remaining_intents() > 0
                && bucket.remaining_fee_micro_units() >= fee_micro_units
            {
                selected_bucket_id = Some(bucket_id.clone());
                break;
            }
        }
        let bucket_id = if let Some(bucket_id) = selected_bucket_id {
            bucket_id
        } else {
            self.create_rate_limit_bucket(
                wallet_id,
                lane_id,
                self.config.max_intents_per_session,
                self.config
                    .max_sponsored_fee_micro_units
                    .saturating_mul(self.config.max_intents_per_session),
            )?
        };
        if let Some(bucket) = self.rate_limits.get_mut(&bucket_id) {
            bucket.used_intents = bucket.used_intents.saturating_add(1);
            bucket.used_fee_micro_units =
                bucket.used_fee_micro_units.saturating_add(fee_micro_units);
            bucket.nullifier_root = domain_hash(
                "PRIVATE-WALLET-INTENT-GATEWAY-RATE-CONSUME",
                &[
                    HashPart::Str(&bucket.nullifier_root),
                    HashPart::Str(wallet_id),
                    HashPart::Str(lane_id),
                    HashPart::Str(&kind.as_str()),
                    HashPart::Int(fee_micro_units as i128),
                ],
                32,
            );
        }
        Ok(())
    }

    fn enforce_session(
        &self,
        session_id: &str,
        wallet_id: &str,
        kind: &WalletIntentKind,
    ) -> PrivateWalletIntentGatewayResult<()> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or_else(|| format!("session {session_id} is missing"))?;
        if session.wallet_id != wallet_id {
            return Err(format!(
                "session {session_id} is not owned by wallet {wallet_id}"
            ));
        }
        if !session.status.usable() {
            return Err(format!("session {session_id} is not usable"));
        }
        if session.expires_at_height < self.config.current_height {
            return Err(format!("session {session_id} expired"));
        }
        if session.used_intents >= session.max_intents {
            return Err(format!("session {session_id} reached max intents"));
        }
        if !session.accepts_kind(kind) {
            return Err(format!(
                "session {session_id} does not accept intent kind {}",
                kind.as_str()
            ));
        }
        Ok(())
    }

    fn ensure_wallet(&self, wallet_id: &str) -> PrivateWalletIntentGatewayResult<()> {
        if self.wallets.contains_key(wallet_id) {
            Ok(())
        } else {
            Err(format!("wallet {wallet_id} is missing"))
        }
    }

    fn ensure_intent(&self, intent_id: &str) -> PrivateWalletIntentGatewayResult<()> {
        if self.intents.contains_key(intent_id) {
            Ok(())
        } else {
            Err(format!("intent {intent_id} is missing"))
        }
    }

    fn ensure_policy(&self, policy_id: &str) -> PrivateWalletIntentGatewayResult<()> {
        if self.account_policies.contains_key(policy_id) {
            Ok(())
        } else {
            Err(format!("account policy {policy_id} is missing"))
        }
    }

    fn ensure_batch(&self, batch_id: &str) -> PrivateWalletIntentGatewayResult<()> {
        if self.batches.contains_key(batch_id) {
            Ok(())
        } else {
            Err(format!("batch {batch_id} is missing"))
        }
    }
}

pub fn private_wallet_intent_gateway_public_record_root(
    records: &[PrivateWalletIntentGatewayPublicRecord],
) -> String {
    merkle_root(
        "PRIVATE-WALLET-INTENT-GATEWAY-PUBLIC-RECORD",
        &records
            .iter()
            .map(PrivateWalletIntentGatewayPublicRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_wallet_intent_gateway_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-WALLET-INTENT-GATEWAY-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn private_wallet_intent_gateway_id(domain: &str, parts: &[&str]) -> String {
    let values = parts
        .iter()
        .map(|part| Value::String((*part).to_string()))
        .collect::<Vec<_>>();
    domain_hash(
        &format!("PRIVATE-WALLET-INTENT-GATEWAY-{domain}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&Value::Array(values)),
        ],
        32,
    )
}

pub fn private_wallet_intent_gateway_devnet_state_root() -> PrivateWalletIntentGatewayResult<String>
{
    PrivateWalletIntentGatewayState::devnet().map(|state| state.state_root())
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    merkle_root(domain, &records.into_iter().collect::<Vec<_>>())
}

fn devnet_hash(label: &str) -> String {
    domain_hash(
        "PRIVATE-WALLET-INTENT-GATEWAY-DEVNET",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn require_non_empty(field: &str, value: &str) -> PrivateWalletIntentGatewayResult<()> {
    if value.is_empty() {
        Err(format!("{field} is required"))
    } else {
        Ok(())
    }
}

fn require_non_zero(field: &str, value: u64) -> PrivateWalletIntentGatewayResult<()> {
    if value == 0 {
        Err(format!("{field} must be non-zero"))
    } else {
        Ok(())
    }
}

fn validate_bps(field: &str, value: u64) -> PrivateWalletIntentGatewayResult<()> {
    if value > PRIVATE_WALLET_INTENT_GATEWAY_MAX_BPS {
        Err(format!("{field} exceeds max bps"))
    } else {
        Ok(())
    }
}

fn validate_len(field: &str, value: usize, max: usize) -> PrivateWalletIntentGatewayResult<()> {
    if value > max {
        Err(format!("{field} exceeds capacity"))
    } else {
        Ok(())
    }
}
