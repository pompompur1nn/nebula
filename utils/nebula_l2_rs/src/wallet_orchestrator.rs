use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WalletOrchestratorResult<T> = Result<T, String>;

pub const WALLET_ORCHESTRATOR_PROTOCOL_VERSION: &str = "nebula-wallet-orchestrator-v1";
pub const WALLET_ORCHESTRATOR_DEFAULT_SESSION_TTL_BLOCKS: u64 = 180;
pub const WALLET_ORCHESTRATOR_DEFAULT_INTENT_TTL_BLOCKS: u64 = 720;
pub const WALLET_ORCHESTRATOR_DEFAULT_RECOVERY_DELAY_BLOCKS: u64 = 1_440;
pub const WALLET_ORCHESTRATOR_DEFAULT_DISCLOSURE_TTL_BLOCKS: u64 = 2_880;
pub const WALLET_ORCHESTRATOR_DEFAULT_AMOUNT_BUCKET_SIZE: u64 = 10_000;
pub const WALLET_ORCHESTRATOR_DEVNET_HEIGHT: u64 = 128;
pub const WALLET_ORCHESTRATOR_DEVNET_MONERO_NETWORK: &str = "stagenet";
pub const WALLET_ORCHESTRATOR_DEVNET_FEE_ASSET_ID: &str = "xmr-devnet";
pub const WALLET_ORCHESTRATOR_MAX_BPS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletProfileKind {
    Spending,
    WatchOnly,
    Recovery,
    HardwareBound,
    OperatorFixture,
}

impl WalletProfileKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Spending => "spending",
            Self::WatchOnly => "watch_only",
            Self::Recovery => "recovery",
            Self::HardwareBound => "hardware_bound",
            Self::OperatorFixture => "operator_fixture",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletOrchestratorStatus {
    Draft,
    Active,
    Pending,
    Submitted,
    Selected,
    Settled,
    Finalized,
    Used,
    Expired,
    Cancelled,
    Revoked,
    Failed,
    Quarantined,
}

impl WalletOrchestratorStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Submitted => "submitted",
            Self::Selected => "selected",
            Self::Settled => "settled",
            Self::Finalized => "finalized",
            Self::Used => "used",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Revoked => "revoked",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::Pending | Self::Submitted | Self::Selected
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Settled
                | Self::Finalized
                | Self::Used
                | Self::Expired
                | Self::Cancelled
                | Self::Revoked
                | Self::Failed
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqPeerRole {
    Wallet,
    Sequencer,
    Paymaster,
    Watchtower,
    BridgeOperator,
    RecoveryGuardian,
}

impl PqPeerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Sequencer => "sequencer",
            Self::Paymaster => "paymaster",
            Self::Watchtower => "watchtower",
            Self::BridgeOperator => "bridge_operator",
            Self::RecoveryGuardian => "recovery_guardian",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHandshakePurpose {
    MempoolSubmission,
    ViewKeyDelegation,
    BridgeDeposit,
    BridgeWithdrawal,
    ContractCall,
    FeeSponsorship,
    Recovery,
    WatchtowerSync,
}

impl PqHandshakePurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MempoolSubmission => "mempool_submission",
            Self::ViewKeyDelegation => "view_key_delegation",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::ContractCall => "contract_call",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::Recovery => "recovery",
            Self::WatchtowerSync => "watchtower_sync",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqHandshakeStage {
    Created,
    Offered,
    Encapsulated,
    Authenticated,
    Active,
    Rotating,
    Expired,
    Revoked,
}

impl PqHandshakeStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Offered => "offered",
            Self::Encapsulated => "encapsulated",
            Self::Authenticated => "authenticated",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn accepts_private_payloads(&self) -> bool {
        matches!(self, Self::Authenticated | Self::Active | Self::Rotating)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MoneroBridgeIntentKind {
    Deposit,
    Withdrawal,
}

impl MoneroBridgeIntentKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateOperationKind {
    BridgeDeposit,
    BridgeWithdrawal,
    TokenTransfer,
    ContractCall,
    SettlementSubmission,
    Disclosure,
    Recovery,
}

impl PrivateOperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::TokenTransfer => "token_transfer",
            Self::ContractCall => "contract_call",
            Self::SettlementSubmission => "settlement_submission",
            Self::Disclosure => "disclosure",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementDomainKind {
    Bridge,
    Token,
    Contract,
    Defi,
    Recovery,
    Composite,
}

impl SettlementDomainKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Token => "token",
            Self::Contract => "contract",
            Self::Defi => "defi",
            Self::Recovery => "recovery",
            Self::Composite => "composite",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorKind {
    PrivatePaymaster,
    BridgeRelayer,
    Solver,
    WalletCredit,
    OperatorVoucher,
}

impl FeeSponsorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivatePaymaster => "private_paymaster",
            Self::BridgeRelayer => "bridge_relayer",
            Self::Solver => "solver",
            Self::WalletCredit => "wallet_credit",
            Self::OperatorVoucher => "operator_voucher",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorshipMode {
    Disabled,
    SelfPayOnly,
    PreferPrivateSponsor,
    RequirePrivateSponsor,
}

impl FeeSponsorshipMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::SelfPayOnly => "self_pay_only",
            Self::PreferPrivateSponsor => "prefer_private_sponsor",
            Self::RequirePrivateSponsor => "require_private_sponsor",
        }
    }

    pub fn requires_sponsor(&self) -> bool {
        matches!(self, Self::RequirePrivateSponsor)
    }

    pub fn allows_sponsor(&self) -> bool {
        matches!(
            self,
            Self::PreferPrivateSponsor | Self::RequirePrivateSponsor
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScopeKind {
    BalanceView,
    TransactionAudit,
    BridgeProof,
    ContractCallTrace,
    TaxExport,
    EmergencyRecovery,
}

impl DisclosureScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BalanceView => "balance_view",
            Self::TransactionAudit => "transaction_audit",
            Self::BridgeProof => "bridge_proof",
            Self::ContractCallTrace => "contract_call_trace",
            Self::TaxExport => "tax_export",
            Self::EmergencyRecovery => "emergency_recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineRecoveryKind {
    SpendKeyRotation,
    ViewKeyRotation,
    GuardianQuorum,
    HardwareReplacement,
    EmergencyFreeze,
    EstateRecovery,
}

impl OfflineRecoveryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SpendKeyRotation => "spend_key_rotation",
            Self::ViewKeyRotation => "view_key_rotation",
            Self::GuardianQuorum => "guardian_quorum",
            Self::HardwareReplacement => "hardware_replacement",
            Self::EmergencyFreeze => "emergency_freeze",
            Self::EstateRecovery => "estate_recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareSignerKind {
    SoftwareDevnet,
    HardwareWallet,
    SecureEnclave,
    AirgappedSigner,
    MultisigShard,
    RecoveryKey,
}

impl HardwareSignerKind {
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwarePolicyScope {
    Transfer,
    ContractCall,
    BridgeWithdrawal,
    Recovery,
    Disclosure,
    FeeSponsorship,
}

impl HardwarePolicyScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::ContractCall => "contract_call",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::Recovery => "recovery",
            Self::Disclosure => "disclosure",
            Self::FeeSponsorship => "fee_sponsorship",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevnetFixtureKind {
    WalletProfile,
    PqHandshake,
    BridgeIntent,
    PrivateTransfer,
    ContractCall,
    SettlementSubmission,
    FeeSponsorCandidate,
    FeeSponsorshipSelection,
    ViewingKeyBundle,
    RecoveryPacket,
    HardwareSignerPolicy,
}

impl DevnetFixtureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WalletProfile => "wallet_profile",
            Self::PqHandshake => "pq_handshake",
            Self::BridgeIntent => "bridge_intent",
            Self::PrivateTransfer => "private_transfer",
            Self::ContractCall => "contract_call",
            Self::SettlementSubmission => "settlement_submission",
            Self::FeeSponsorCandidate => "fee_sponsor_candidate",
            Self::FeeSponsorshipSelection => "fee_sponsorship_selection",
            Self::ViewingKeyBundle => "viewing_key_bundle",
            Self::RecoveryPacket => "recovery_packet",
            Self::HardwareSignerPolicy => "hardware_signer_policy",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletOrchestratorConfig {
    pub protocol_version: String,
    pub chain_id: String,
    pub monero_network: String,
    pub default_fee_asset_id: String,
    pub default_session_ttl_blocks: u64,
    pub default_intent_ttl_blocks: u64,
    pub default_recovery_delay_blocks: u64,
    pub default_disclosure_ttl_blocks: u64,
    pub amount_bucket_size: u64,
    pub max_profiles: usize,
    pub max_handshakes: usize,
    pub max_bridge_intents: usize,
    pub max_private_transfers: usize,
    pub max_contract_calls: usize,
    pub max_settlement_submissions: usize,
    pub max_fee_sponsor_candidates: usize,
    pub max_viewing_key_bundles: usize,
    pub max_recovery_packets: usize,
    pub max_hardware_policies: usize,
    pub max_public_records: usize,
    pub max_operation_roots: usize,
    pub max_rebate_bps: u64,
    pub require_pq_handshake_for_private_calls: bool,
    pub require_hardware_for_bridge_withdrawals: bool,
    pub allow_fee_sponsorship: bool,
}

impl Default for WalletOrchestratorConfig {
    fn default() -> Self {
        Self {
            protocol_version: WALLET_ORCHESTRATOR_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            monero_network: WALLET_ORCHESTRATOR_DEVNET_MONERO_NETWORK.to_string(),
            default_fee_asset_id: WALLET_ORCHESTRATOR_DEVNET_FEE_ASSET_ID.to_string(),
            default_session_ttl_blocks: WALLET_ORCHESTRATOR_DEFAULT_SESSION_TTL_BLOCKS,
            default_intent_ttl_blocks: WALLET_ORCHESTRATOR_DEFAULT_INTENT_TTL_BLOCKS,
            default_recovery_delay_blocks: WALLET_ORCHESTRATOR_DEFAULT_RECOVERY_DELAY_BLOCKS,
            default_disclosure_ttl_blocks: WALLET_ORCHESTRATOR_DEFAULT_DISCLOSURE_TTL_BLOCKS,
            amount_bucket_size: WALLET_ORCHESTRATOR_DEFAULT_AMOUNT_BUCKET_SIZE,
            max_profiles: 64,
            max_handshakes: 256,
            max_bridge_intents: 512,
            max_private_transfers: 512,
            max_contract_calls: 512,
            max_settlement_submissions: 512,
            max_fee_sponsor_candidates: 128,
            max_viewing_key_bundles: 256,
            max_recovery_packets: 128,
            max_hardware_policies: 128,
            max_public_records: 1_024,
            max_operation_roots: 64,
            max_rebate_bps: 7_500,
            require_pq_handshake_for_private_calls: true,
            require_hardware_for_bridge_withdrawals: true,
            allow_fee_sponsorship: true,
        }
    }
}

impl WalletOrchestratorConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_orchestrator_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "configured_chain_id": self.chain_id,
            "monero_network": self.monero_network,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_session_ttl_blocks": self.default_session_ttl_blocks,
            "default_intent_ttl_blocks": self.default_intent_ttl_blocks,
            "default_recovery_delay_blocks": self.default_recovery_delay_blocks,
            "default_disclosure_ttl_blocks": self.default_disclosure_ttl_blocks,
            "amount_bucket_size": self.amount_bucket_size,
            "max_profiles": self.max_profiles,
            "max_handshakes": self.max_handshakes,
            "max_bridge_intents": self.max_bridge_intents,
            "max_private_transfers": self.max_private_transfers,
            "max_contract_calls": self.max_contract_calls,
            "max_settlement_submissions": self.max_settlement_submissions,
            "max_fee_sponsor_candidates": self.max_fee_sponsor_candidates,
            "max_viewing_key_bundles": self.max_viewing_key_bundles,
            "max_recovery_packets": self.max_recovery_packets,
            "max_hardware_policies": self.max_hardware_policies,
            "max_public_records": self.max_public_records,
            "max_operation_roots": self.max_operation_roots,
            "max_rebate_bps": self.max_rebate_bps,
            "require_pq_handshake_for_private_calls": self.require_pq_handshake_for_private_calls,
            "require_hardware_for_bridge_withdrawals": self.require_hardware_for_bridge_withdrawals,
            "allow_fee_sponsorship": self.allow_fee_sponsorship,
        })
    }

    pub fn config_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-ORCHESTRATOR-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_eq(
            &self.protocol_version,
            WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "wallet orchestrator protocol version",
        )?;
        ensure_eq(&self.chain_id, CHAIN_ID, "wallet orchestrator chain id")?;
        ensure_non_empty(&self.monero_network, "wallet orchestrator monero network")?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "wallet orchestrator default fee asset id",
        )?;
        ensure_positive(
            self.default_session_ttl_blocks,
            "wallet orchestrator default session ttl",
        )?;
        ensure_positive(
            self.default_intent_ttl_blocks,
            "wallet orchestrator default intent ttl",
        )?;
        ensure_positive(
            self.default_recovery_delay_blocks,
            "wallet orchestrator default recovery delay",
        )?;
        ensure_positive(
            self.default_disclosure_ttl_blocks,
            "wallet orchestrator default disclosure ttl",
        )?;
        ensure_positive(
            self.amount_bucket_size,
            "wallet orchestrator amount bucket size",
        )?;
        ensure_nonzero_usize(self.max_profiles, "wallet orchestrator max profiles")?;
        ensure_nonzero_usize(self.max_handshakes, "wallet orchestrator max handshakes")?;
        ensure_nonzero_usize(
            self.max_bridge_intents,
            "wallet orchestrator max bridge intents",
        )?;
        ensure_nonzero_usize(
            self.max_private_transfers,
            "wallet orchestrator max private transfers",
        )?;
        ensure_nonzero_usize(
            self.max_contract_calls,
            "wallet orchestrator max contract calls",
        )?;
        ensure_nonzero_usize(
            self.max_settlement_submissions,
            "wallet orchestrator max settlement submissions",
        )?;
        ensure_nonzero_usize(
            self.max_fee_sponsor_candidates,
            "wallet orchestrator max fee sponsor candidates",
        )?;
        ensure_nonzero_usize(
            self.max_viewing_key_bundles,
            "wallet orchestrator max viewing key bundles",
        )?;
        ensure_nonzero_usize(
            self.max_recovery_packets,
            "wallet orchestrator max recovery packets",
        )?;
        ensure_nonzero_usize(
            self.max_hardware_policies,
            "wallet orchestrator max hardware policies",
        )?;
        ensure_nonzero_usize(
            self.max_public_records,
            "wallet orchestrator max public records",
        )?;
        ensure_nonzero_usize(
            self.max_operation_roots,
            "wallet orchestrator max operation roots",
        )?;
        ensure_bps(self.max_rebate_bps, "wallet orchestrator max rebate bps")?;
        Ok(self.config_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletProfile {
    pub profile_id: String,
    pub label: String,
    pub profile_kind: WalletProfileKind,
    pub account_commitment: String,
    pub view_tag_root: String,
    pub spend_authority_root: String,
    pub recovery_root: String,
    pub default_fee_asset_id: String,
    pub pq_preferred_peer_id: Option<String>,
    pub signer_policy_id: Option<String>,
    pub created_at_height: u64,
    pub last_synced_height: u64,
    pub metadata_root: String,
    pub status: WalletOrchestratorStatus,
}

impl WalletProfile {
    pub fn deterministic(
        label: &str,
        profile_kind: WalletProfileKind,
        default_fee_asset_id: &str,
        created_at_height: u64,
        metadata: &Value,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(label, "wallet profile label")?;
        ensure_non_empty(default_fee_asset_id, "wallet profile default fee asset id")?;
        let account_commitment = wallet_orchestrator_payload_root(
            "WALLET-PROFILE-ACCOUNT",
            &json!({
                "label": label,
                "kind": profile_kind.as_str(),
                "chain_id": CHAIN_ID,
            }),
        );
        let view_tag_root = wallet_orchestrator_payload_root(
            "WALLET-PROFILE-VIEW-TAG",
            &json!({
                "label": label,
                "account_commitment": account_commitment,
                "metadata": metadata,
            }),
        );
        let spend_authority_root =
            wallet_orchestrator_string_root("WALLET-PROFILE-SPEND-AUTHORITY", label);
        let recovery_root = wallet_orchestrator_payload_root(
            "WALLET-PROFILE-RECOVERY",
            &json!({
                "label": label,
                "created_at_height": created_at_height,
                "metadata": metadata,
            }),
        );
        let metadata_root = wallet_orchestrator_payload_root("WALLET-PROFILE-METADATA", metadata);
        let profile_id = wallet_profile_id(label, profile_kind.as_str(), &account_commitment);
        let profile = Self {
            profile_id,
            label: label.to_string(),
            profile_kind,
            account_commitment,
            view_tag_root,
            spend_authority_root,
            recovery_root,
            default_fee_asset_id: default_fee_asset_id.to_string(),
            pq_preferred_peer_id: None,
            signer_policy_id: None,
            created_at_height,
            last_synced_height: created_at_height,
            metadata_root,
            status: WalletOrchestratorStatus::Active,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn with_preferred_peer(mut self, peer_id: impl Into<String>) -> Self {
        self.pq_preferred_peer_id = Some(peer_id.into());
        self
    }

    pub fn with_signer_policy(mut self, policy_id: impl Into<String>) -> Self {
        self.signer_policy_id = Some(policy_id.into());
        self
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_profile",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "profile_id": self.profile_id,
            "label": self.label,
            "profile_kind": self.profile_kind.as_str(),
            "account_commitment": self.account_commitment,
            "view_tag_root": self.view_tag_root,
            "spend_authority_root": self.spend_authority_root,
            "recovery_root": self.recovery_root,
            "default_fee_asset_id": self.default_fee_asset_id,
            "pq_preferred_peer_id": self.pq_preferred_peer_id,
            "signer_policy_id": self.signer_policy_id,
            "created_at_height": self.created_at_height,
            "last_synced_height": self.last_synced_height,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
        })
    }

    pub fn profile_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-PROFILE", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.profile_id, "wallet profile id")?;
        ensure_non_empty(&self.label, "wallet profile label")?;
        ensure_non_empty(
            &self.account_commitment,
            "wallet profile account commitment",
        )?;
        ensure_non_empty(&self.view_tag_root, "wallet profile view tag root")?;
        ensure_non_empty(
            &self.spend_authority_root,
            "wallet profile spend authority root",
        )?;
        ensure_non_empty(&self.recovery_root, "wallet profile recovery root")?;
        ensure_non_empty(
            &self.default_fee_asset_id,
            "wallet profile default fee asset id",
        )?;
        ensure_non_empty(&self.metadata_root, "wallet profile metadata root")?;
        if self.last_synced_height < self.created_at_height {
            return Err("wallet profile last synced height precedes creation".to_string());
        }
        Ok(self.profile_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPqSessionHandshake {
    pub handshake_id: String,
    pub profile_id: String,
    pub peer_id: String,
    pub peer_label: String,
    pub peer_role: PqPeerRole,
    pub purpose: PqHandshakePurpose,
    pub initiator_key_commitment: String,
    pub responder_key_commitment: String,
    pub kem_ciphertext_root: String,
    pub shared_secret_commitment: String,
    pub transcript_root: String,
    pub replay_nonce_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub stage: PqHandshakeStage,
    pub status: WalletOrchestratorStatus,
}

impl WalletPqSessionHandshake {
    pub fn deterministic(
        profile_id: &str,
        peer_label: &str,
        peer_role: PqPeerRole,
        purpose: PqHandshakePurpose,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "wallet pq handshake profile id")?;
        ensure_non_empty(peer_label, "wallet pq handshake peer label")?;
        ensure_positive(ttl_blocks, "wallet pq handshake ttl")?;
        let peer_id = wallet_orchestrator_payload_root(
            "WALLET-PQ-PEER-ID",
            &json!({
                "peer_label": peer_label,
                "peer_role": peer_role.as_str(),
                "purpose": purpose.as_str(),
                "nonce": nonce,
            }),
        );
        let initiator_key_commitment = wallet_orchestrator_payload_root(
            "WALLET-PQ-INITIATOR-KEY",
            &json!({
                "profile_id": profile_id,
                "peer_id": peer_id,
                "purpose": purpose.as_str(),
                "nonce": nonce,
            }),
        );
        let responder_key_commitment = wallet_orchestrator_payload_root(
            "WALLET-PQ-RESPONDER-KEY",
            &json!({
                "peer_label": peer_label,
                "peer_role": peer_role.as_str(),
                "nonce": nonce,
            }),
        );
        let kem_ciphertext_root = wallet_orchestrator_payload_root(
            "WALLET-PQ-KEM-CIPHERTEXT",
            &json!({
                "initiator_key_commitment": initiator_key_commitment,
                "responder_key_commitment": responder_key_commitment,
                "created_at_height": created_at_height,
                "nonce": nonce,
            }),
        );
        let shared_secret_commitment = wallet_orchestrator_payload_root(
            "WALLET-PQ-SHARED-SECRET",
            &json!({
                "kem_ciphertext_root": kem_ciphertext_root,
                "profile_id": profile_id,
                "peer_id": peer_id,
                "nonce": nonce,
            }),
        );
        let transcript_root = wallet_orchestrator_payload_root(
            "WALLET-PQ-TRANSCRIPT",
            &json!({
                "profile_id": profile_id,
                "peer_id": peer_id,
                "purpose": purpose.as_str(),
                "shared_secret_commitment": shared_secret_commitment,
                "created_at_height": created_at_height,
            }),
        );
        let replay_nonce_root = wallet_orchestrator_payload_root(
            "WALLET-PQ-REPLAY-NONCE",
            &json!({
                "profile_id": profile_id,
                "peer_id": peer_id,
                "transcript_root": transcript_root,
                "nonce": nonce,
            }),
        );
        let handshake_id = wallet_pq_handshake_id(
            profile_id,
            &peer_id,
            purpose.as_str(),
            &transcript_root,
            nonce,
        );
        let handshake = Self {
            handshake_id,
            profile_id: profile_id.to_string(),
            peer_id,
            peer_label: peer_label.to_string(),
            peer_role,
            purpose,
            initiator_key_commitment,
            responder_key_commitment,
            kem_ciphertext_root,
            shared_secret_commitment,
            transcript_root,
            replay_nonce_root,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            nonce,
            stage: PqHandshakeStage::Active,
            status: WalletOrchestratorStatus::Active,
        };
        handshake.validate()?;
        Ok(handshake)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_pq_session_handshake",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "handshake_id": self.handshake_id,
            "profile_id": self.profile_id,
            "peer_id": self.peer_id,
            "peer_label": self.peer_label,
            "peer_role": self.peer_role.as_str(),
            "purpose": self.purpose.as_str(),
            "initiator_key_commitment": self.initiator_key_commitment,
            "responder_key_commitment": self.responder_key_commitment,
            "kem_ciphertext_root": self.kem_ciphertext_root,
            "shared_secret_commitment": self.shared_secret_commitment,
            "transcript_root": self.transcript_root,
            "replay_nonce_root": self.replay_nonce_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "stage": self.stage.as_str(),
            "status": self.status.as_str(),
        })
    }

    pub fn handshake_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-PQ-HANDSHAKE", &self.public_record())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_live()
            && self.stage.accepts_private_payloads()
            && self.created_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.handshake_id, "wallet pq handshake id")?;
        ensure_non_empty(&self.profile_id, "wallet pq handshake profile id")?;
        ensure_non_empty(&self.peer_id, "wallet pq handshake peer id")?;
        ensure_non_empty(&self.peer_label, "wallet pq handshake peer label")?;
        ensure_non_empty(
            &self.initiator_key_commitment,
            "wallet pq handshake initiator key",
        )?;
        ensure_non_empty(
            &self.responder_key_commitment,
            "wallet pq handshake responder key",
        )?;
        ensure_non_empty(
            &self.kem_ciphertext_root,
            "wallet pq handshake kem ciphertext root",
        )?;
        ensure_non_empty(
            &self.shared_secret_commitment,
            "wallet pq handshake shared secret commitment",
        )?;
        ensure_non_empty(&self.transcript_root, "wallet pq handshake transcript root")?;
        ensure_non_empty(
            &self.replay_nonce_root,
            "wallet pq handshake replay nonce root",
        )?;
        if self.expires_at_height <= self.created_at_height {
            return Err("wallet pq handshake expiry must be after creation".to_string());
        }
        Ok(self.handshake_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoneroBridgeIntent {
    pub intent_id: String,
    pub profile_id: String,
    pub intent_kind: MoneroBridgeIntentKind,
    pub monero_network: String,
    pub asset_id: String,
    pub amount: u64,
    pub amount_bucket: u64,
    pub bridge_fee_units: u64,
    pub monero_address_commitment: String,
    pub l2_recipient_commitment: String,
    pub stealth_payment_id_root: String,
    pub deposit_view_key_root: String,
    pub withdrawal_nullifier: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl MoneroBridgeIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        profile_id: &str,
        monero_network: &str,
        asset_id: &str,
        amount: u64,
        l2_recipient_label: &str,
        amount_bucket_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        Self::deterministic(
            profile_id,
            MoneroBridgeIntentKind::Deposit,
            monero_network,
            asset_id,
            amount,
            0,
            l2_recipient_label,
            "",
            amount_bucket_size,
            created_at_height,
            ttl_blocks,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn withdrawal(
        profile_id: &str,
        monero_network: &str,
        asset_id: &str,
        amount: u64,
        bridge_fee_units: u64,
        monero_destination_label: &str,
        withdrawal_nullifier_seed: &str,
        amount_bucket_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        Self::deterministic(
            profile_id,
            MoneroBridgeIntentKind::Withdrawal,
            monero_network,
            asset_id,
            amount,
            bridge_fee_units,
            monero_destination_label,
            withdrawal_nullifier_seed,
            amount_bucket_size,
            created_at_height,
            ttl_blocks,
            nonce,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn deterministic(
        profile_id: &str,
        intent_kind: MoneroBridgeIntentKind,
        monero_network: &str,
        asset_id: &str,
        amount: u64,
        bridge_fee_units: u64,
        route_label: &str,
        withdrawal_nullifier_seed: &str,
        amount_bucket_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "monero bridge intent profile id")?;
        ensure_non_empty(monero_network, "monero bridge intent network")?;
        ensure_non_empty(asset_id, "monero bridge intent asset id")?;
        ensure_non_empty(route_label, "monero bridge intent route label")?;
        ensure_positive(amount, "monero bridge intent amount")?;
        ensure_positive(ttl_blocks, "monero bridge intent ttl")?;
        let monero_address_commitment = wallet_orchestrator_payload_root(
            "WALLET-MONERO-ADDRESS-COMMITMENT",
            &json!({
                "profile_id": profile_id,
                "intent_kind": intent_kind.as_str(),
                "network": monero_network,
                "route_label": route_label,
                "nonce": nonce,
            }),
        );
        let l2_recipient_commitment = wallet_orchestrator_payload_root(
            "WALLET-MONERO-L2-RECIPIENT",
            &json!({
                "profile_id": profile_id,
                "route_label": route_label,
                "asset_id": asset_id,
                "nonce": nonce,
            }),
        );
        let stealth_payment_id_root = wallet_orchestrator_payload_root(
            "WALLET-MONERO-STEALTH-PAYMENT-ID",
            &json!({
                "profile_id": profile_id,
                "monero_address_commitment": monero_address_commitment,
                "amount_bucket": amount_bucket(amount, amount_bucket_size),
                "nonce": nonce,
            }),
        );
        let deposit_view_key_root = wallet_orchestrator_payload_root(
            "WALLET-MONERO-DEPOSIT-VIEW-KEY",
            &json!({
                "profile_id": profile_id,
                "network": monero_network,
                "route_label": route_label,
                "nonce": nonce,
            }),
        );
        let withdrawal_nullifier = if intent_kind == MoneroBridgeIntentKind::Withdrawal {
            ensure_non_empty(
                withdrawal_nullifier_seed,
                "monero bridge withdrawal nullifier seed",
            )?;
            wallet_orchestrator_payload_root(
                "WALLET-MONERO-WITHDRAWAL-NULLIFIER",
                &json!({
                    "profile_id": profile_id,
                    "seed": withdrawal_nullifier_seed,
                    "amount": amount,
                    "nonce": nonce,
                }),
            )
        } else {
            String::new()
        };
        let intent_id = monero_bridge_intent_id(
            profile_id,
            intent_kind.as_str(),
            &monero_address_commitment,
            &stealth_payment_id_root,
            nonce,
        );
        let intent = Self {
            intent_id,
            profile_id: profile_id.to_string(),
            intent_kind,
            monero_network: monero_network.to_string(),
            asset_id: asset_id.to_string(),
            amount,
            amount_bucket: amount_bucket(amount, amount_bucket_size),
            bridge_fee_units,
            monero_address_commitment,
            l2_recipient_commitment,
            stealth_payment_id_root,
            deposit_view_key_root,
            withdrawal_nullifier,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            nonce,
            status: WalletOrchestratorStatus::Pending,
        };
        intent.validate()?;
        Ok(intent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_bridge_intent",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "intent_id": self.intent_id,
            "profile_id": self.profile_id,
            "intent_kind": self.intent_kind.as_str(),
            "monero_network": self.monero_network,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "amount_bucket": self.amount_bucket,
            "bridge_fee_units": self.bridge_fee_units,
            "monero_address_commitment": self.monero_address_commitment,
            "l2_recipient_commitment": self.l2_recipient_commitment,
            "stealth_payment_id_root": self.stealth_payment_id_root,
            "deposit_view_key_root": self.deposit_view_key_root,
            "withdrawal_nullifier": self.withdrawal_nullifier,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn intent_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-MONERO-BRIDGE-INTENT", &self.public_record())
    }

    pub fn operation_kind(&self) -> PrivateOperationKind {
        match self.intent_kind {
            MoneroBridgeIntentKind::Deposit => PrivateOperationKind::BridgeDeposit,
            MoneroBridgeIntentKind::Withdrawal => PrivateOperationKind::BridgeWithdrawal,
        }
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.intent_id, "monero bridge intent id")?;
        ensure_non_empty(&self.profile_id, "monero bridge intent profile id")?;
        ensure_non_empty(&self.monero_network, "monero bridge intent network")?;
        ensure_non_empty(&self.asset_id, "monero bridge intent asset id")?;
        ensure_positive(self.amount, "monero bridge intent amount")?;
        ensure_non_empty(
            &self.monero_address_commitment,
            "monero bridge address commitment",
        )?;
        ensure_non_empty(
            &self.l2_recipient_commitment,
            "monero bridge l2 recipient commitment",
        )?;
        ensure_non_empty(
            &self.stealth_payment_id_root,
            "monero bridge stealth payment id root",
        )?;
        ensure_non_empty(
            &self.deposit_view_key_root,
            "monero bridge deposit view key root",
        )?;
        if self.intent_kind == MoneroBridgeIntentKind::Withdrawal {
            ensure_non_empty(
                &self.withdrawal_nullifier,
                "monero bridge withdrawal nullifier",
            )?;
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("monero bridge intent expiry must be after creation".to_string());
        }
        Ok(self.intent_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenTransfer {
    pub transfer_id: String,
    pub profile_id: String,
    pub asset_id: String,
    pub amount: u64,
    pub amount_bucket: u64,
    pub recipient_commitment: String,
    pub sender_note_root: String,
    pub change_note_root: String,
    pub nullifier_commitment: String,
    pub encrypted_memo_root: String,
    pub proof_root: String,
    pub fee_asset_id: String,
    pub max_fee_units: u64,
    pub sponsor_selection_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl PrivateTokenTransfer {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        asset_id: &str,
        amount: u64,
        recipient_label: &str,
        fee_asset_id: &str,
        max_fee_units: u64,
        sponsor_selection_id: Option<String>,
        amount_bucket_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "private transfer profile id")?;
        ensure_non_empty(asset_id, "private transfer asset id")?;
        ensure_non_empty(recipient_label, "private transfer recipient label")?;
        ensure_non_empty(fee_asset_id, "private transfer fee asset id")?;
        ensure_positive(amount, "private transfer amount")?;
        ensure_positive(ttl_blocks, "private transfer ttl")?;
        let recipient_commitment = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-RECIPIENT",
            &json!({
                "profile_id": profile_id,
                "recipient_label": recipient_label,
                "asset_id": asset_id,
                "nonce": nonce,
            }),
        );
        let sender_note_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-SENDER-NOTE",
            &json!({
                "profile_id": profile_id,
                "asset_id": asset_id,
                "amount_bucket": amount_bucket(amount, amount_bucket_size),
                "nonce": nonce,
            }),
        );
        let change_note_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-CHANGE-NOTE",
            &json!({
                "profile_id": profile_id,
                "asset_id": asset_id,
                "amount": amount,
                "fee_units": max_fee_units,
                "nonce": nonce,
            }),
        );
        let nullifier_commitment = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-NULLIFIER",
            &json!({
                "sender_note_root": sender_note_root,
                "profile_id": profile_id,
                "nonce": nonce,
            }),
        );
        let encrypted_memo_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-MEMO",
            &json!({
                "recipient_commitment": recipient_commitment,
                "amount_bucket": amount_bucket(amount, amount_bucket_size),
                "nonce": nonce,
            }),
        );
        let proof_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-TRANSFER-PROOF",
            &json!({
                "sender_note_root": sender_note_root,
                "change_note_root": change_note_root,
                "nullifier_commitment": nullifier_commitment,
                "recipient_commitment": recipient_commitment,
            }),
        );
        let transfer_id = private_transfer_id(
            profile_id,
            asset_id,
            &recipient_commitment,
            &nullifier_commitment,
            nonce,
        );
        let transfer = Self {
            transfer_id,
            profile_id: profile_id.to_string(),
            asset_id: asset_id.to_string(),
            amount,
            amount_bucket: amount_bucket(amount, amount_bucket_size),
            recipient_commitment,
            sender_note_root,
            change_note_root,
            nullifier_commitment,
            encrypted_memo_root,
            proof_root,
            fee_asset_id: fee_asset_id.to_string(),
            max_fee_units,
            sponsor_selection_id,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            nonce,
            status: WalletOrchestratorStatus::Pending,
        };
        transfer.validate()?;
        Ok(transfer)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_transfer",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "transfer_id": self.transfer_id,
            "profile_id": self.profile_id,
            "asset_id": self.asset_id,
            "amount": self.amount,
            "amount_bucket": self.amount_bucket,
            "recipient_commitment": self.recipient_commitment,
            "sender_note_root": self.sender_note_root,
            "change_note_root": self.change_note_root,
            "nullifier_commitment": self.nullifier_commitment,
            "encrypted_memo_root": self.encrypted_memo_root,
            "proof_root": self.proof_root,
            "fee_asset_id": self.fee_asset_id,
            "max_fee_units": self.max_fee_units,
            "sponsor_selection_id": self.sponsor_selection_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn transfer_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-PRIVATE-TOKEN-TRANSFER", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.transfer_id, "private transfer id")?;
        ensure_non_empty(&self.profile_id, "private transfer profile id")?;
        ensure_non_empty(&self.asset_id, "private transfer asset id")?;
        ensure_positive(self.amount, "private transfer amount")?;
        ensure_non_empty(&self.recipient_commitment, "private transfer recipient")?;
        ensure_non_empty(&self.sender_note_root, "private transfer sender note root")?;
        ensure_non_empty(&self.change_note_root, "private transfer change note root")?;
        ensure_non_empty(
            &self.nullifier_commitment,
            "private transfer nullifier commitment",
        )?;
        ensure_non_empty(
            &self.encrypted_memo_root,
            "private transfer encrypted memo root",
        )?;
        ensure_non_empty(&self.proof_root, "private transfer proof root")?;
        ensure_non_empty(&self.fee_asset_id, "private transfer fee asset id")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("private transfer expiry must be after creation".to_string());
        }
        Ok(self.transfer_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateContractCall {
    pub call_id: String,
    pub profile_id: String,
    pub contract_id: String,
    pub method_selector: String,
    pub calldata_root: String,
    pub encrypted_witness_root: String,
    pub input_note_root: String,
    pub output_note_root: String,
    pub value_asset_id: String,
    pub value_amount: u64,
    pub value_amount_bucket: u64,
    pub proof_root: String,
    pub gas_limit: u64,
    pub max_fee_units: u64,
    pub sponsor_selection_id: Option<String>,
    pub pq_handshake_id: Option<String>,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl PrivateContractCall {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        contract_id: &str,
        method_selector: &str,
        value_asset_id: &str,
        value_amount: u64,
        gas_limit: u64,
        max_fee_units: u64,
        sponsor_selection_id: Option<String>,
        pq_handshake_id: Option<String>,
        amount_bucket_size: u64,
        created_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "private contract call profile id")?;
        ensure_non_empty(contract_id, "private contract call contract id")?;
        ensure_non_empty(method_selector, "private contract call method selector")?;
        ensure_non_empty(value_asset_id, "private contract call value asset id")?;
        ensure_positive(gas_limit, "private contract call gas limit")?;
        ensure_positive(ttl_blocks, "private contract call ttl")?;
        let calldata_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-CALL-CALLDATA",
            &json!({
                "profile_id": profile_id,
                "contract_id": contract_id,
                "method_selector": method_selector,
                "nonce": nonce,
            }),
        );
        let encrypted_witness_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-CALL-WITNESS",
            &json!({
                "calldata_root": calldata_root,
                "profile_id": profile_id,
                "pq_handshake_id": pq_handshake_id,
                "nonce": nonce,
            }),
        );
        let input_note_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-CALL-INPUT-NOTE",
            &json!({
                "profile_id": profile_id,
                "value_asset_id": value_asset_id,
                "value_amount_bucket": amount_bucket(value_amount, amount_bucket_size),
                "nonce": nonce,
            }),
        );
        let output_note_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-CALL-OUTPUT-NOTE",
            &json!({
                "profile_id": profile_id,
                "contract_id": contract_id,
                "method_selector": method_selector,
                "nonce": nonce,
            }),
        );
        let proof_root = wallet_orchestrator_payload_root(
            "WALLET-PRIVATE-CALL-PROOF",
            &json!({
                "calldata_root": calldata_root,
                "encrypted_witness_root": encrypted_witness_root,
                "input_note_root": input_note_root,
                "output_note_root": output_note_root,
                "gas_limit": gas_limit,
            }),
        );
        let call_id = private_contract_call_id(
            profile_id,
            contract_id,
            method_selector,
            &calldata_root,
            nonce,
        );
        let call = Self {
            call_id,
            profile_id: profile_id.to_string(),
            contract_id: contract_id.to_string(),
            method_selector: method_selector.to_string(),
            calldata_root,
            encrypted_witness_root,
            input_note_root,
            output_note_root,
            value_asset_id: value_asset_id.to_string(),
            value_amount,
            value_amount_bucket: amount_bucket(value_amount, amount_bucket_size),
            proof_root,
            gas_limit,
            max_fee_units,
            sponsor_selection_id,
            pq_handshake_id,
            created_at_height,
            expires_at_height: created_at_height.saturating_add(ttl_blocks),
            nonce,
            status: WalletOrchestratorStatus::Pending,
        };
        call.validate()?;
        Ok(call)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_contract_call",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "call_id": self.call_id,
            "profile_id": self.profile_id,
            "contract_id": self.contract_id,
            "method_selector": self.method_selector,
            "calldata_root": self.calldata_root,
            "encrypted_witness_root": self.encrypted_witness_root,
            "input_note_root": self.input_note_root,
            "output_note_root": self.output_note_root,
            "value_asset_id": self.value_asset_id,
            "value_amount": self.value_amount,
            "value_amount_bucket": self.value_amount_bucket,
            "proof_root": self.proof_root,
            "gas_limit": self.gas_limit,
            "max_fee_units": self.max_fee_units,
            "sponsor_selection_id": self.sponsor_selection_id,
            "pq_handshake_id": self.pq_handshake_id,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn call_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-PRIVATE-CONTRACT-CALL", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.call_id, "private contract call id")?;
        ensure_non_empty(&self.profile_id, "private contract call profile id")?;
        ensure_non_empty(&self.contract_id, "private contract call contract id")?;
        ensure_non_empty(
            &self.method_selector,
            "private contract call method selector",
        )?;
        ensure_non_empty(&self.calldata_root, "private contract call calldata root")?;
        ensure_non_empty(
            &self.encrypted_witness_root,
            "private contract call encrypted witness root",
        )?;
        ensure_non_empty(
            &self.input_note_root,
            "private contract call input note root",
        )?;
        ensure_non_empty(
            &self.output_note_root,
            "private contract call output note root",
        )?;
        ensure_non_empty(&self.value_asset_id, "private contract call value asset id")?;
        ensure_non_empty(&self.proof_root, "private contract call proof root")?;
        ensure_positive(self.gas_limit, "private contract call gas limit")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("private contract call expiry must be after creation".to_string());
        }
        Ok(self.call_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementSubmission {
    pub submission_id: String,
    pub profile_id: String,
    pub operation_kind: PrivateOperationKind,
    pub operation_id: String,
    pub settlement_domain: SettlementDomainKind,
    pub input_roots: Vec<String>,
    pub input_root: String,
    pub bundled_intent_root: String,
    pub solver_hint_root: String,
    pub fee_selection_id: Option<String>,
    pub bridge_intent_id: Option<String>,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub proof_root: String,
    pub status: WalletOrchestratorStatus,
}

impl IntentSettlementSubmission {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        operation_kind: PrivateOperationKind,
        operation_id: &str,
        settlement_domain: SettlementDomainKind,
        input_roots: Vec<String>,
        fee_selection_id: Option<String>,
        bridge_intent_id: Option<String>,
        submitted_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "intent settlement profile id")?;
        ensure_non_empty(operation_id, "intent settlement operation id")?;
        ensure_positive(ttl_blocks, "intent settlement ttl")?;
        ensure_non_empty_slice(&input_roots, "intent settlement input roots")?;
        for input_root in &input_roots {
            ensure_non_empty(input_root, "intent settlement input root")?;
        }
        let input_root = wallet_orchestrator_string_collection_root(
            "WALLET-INTENT-SETTLEMENT-INPUTS",
            &input_roots,
        );
        let bundled_intent_root = wallet_orchestrator_payload_root(
            "WALLET-INTENT-SETTLEMENT-BUNDLE",
            &json!({
                "profile_id": profile_id,
                "operation_kind": operation_kind.as_str(),
                "operation_id": operation_id,
                "settlement_domain": settlement_domain.as_str(),
                "input_root": input_root,
                "fee_selection_id": fee_selection_id,
                "bridge_intent_id": bridge_intent_id,
            }),
        );
        let solver_hint_root = wallet_orchestrator_payload_root(
            "WALLET-INTENT-SETTLEMENT-SOLVER-HINT",
            &json!({
                "bundled_intent_root": bundled_intent_root,
                "submitted_at_height": submitted_at_height,
                "nonce": nonce,
            }),
        );
        let proof_root = wallet_orchestrator_payload_root(
            "WALLET-INTENT-SETTLEMENT-PROOF",
            &json!({
                "input_root": input_root,
                "bundled_intent_root": bundled_intent_root,
                "solver_hint_root": solver_hint_root,
            }),
        );
        let submission_id = intent_settlement_submission_id(
            profile_id,
            operation_kind.as_str(),
            operation_id,
            &bundled_intent_root,
            nonce,
        );
        let submission = Self {
            submission_id,
            profile_id: profile_id.to_string(),
            operation_kind,
            operation_id: operation_id.to_string(),
            settlement_domain,
            input_roots,
            input_root,
            bundled_intent_root,
            solver_hint_root,
            fee_selection_id,
            bridge_intent_id,
            submitted_at_height,
            expires_at_height: submitted_at_height.saturating_add(ttl_blocks),
            nonce,
            proof_root,
            status: WalletOrchestratorStatus::Submitted,
        };
        submission.validate()?;
        Ok(submission)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "intent_settlement_submission",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "submission_id": self.submission_id,
            "profile_id": self.profile_id,
            "operation_kind": self.operation_kind.as_str(),
            "operation_id": self.operation_id,
            "settlement_domain": self.settlement_domain.as_str(),
            "input_roots": self.input_roots,
            "input_root": self.input_root,
            "bundled_intent_root": self.bundled_intent_root,
            "solver_hint_root": self.solver_hint_root,
            "fee_selection_id": self.fee_selection_id,
            "bridge_intent_id": self.bridge_intent_id,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "proof_root": self.proof_root,
            "status": self.status.as_str(),
        })
    }

    pub fn submission_root(&self) -> String {
        wallet_orchestrator_payload_root(
            "WALLET-INTENT-SETTLEMENT-SUBMISSION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.submission_id, "intent settlement submission id")?;
        ensure_non_empty(&self.profile_id, "intent settlement profile id")?;
        ensure_non_empty(&self.operation_id, "intent settlement operation id")?;
        ensure_non_empty_slice(&self.input_roots, "intent settlement input roots")?;
        for input_root in &self.input_roots {
            ensure_non_empty(input_root, "intent settlement input root")?;
        }
        ensure_non_empty(&self.input_root, "intent settlement input root aggregate")?;
        ensure_non_empty(
            &self.bundled_intent_root,
            "intent settlement bundled intent root",
        )?;
        ensure_non_empty(&self.solver_hint_root, "intent settlement solver hint root")?;
        ensure_non_empty(&self.proof_root, "intent settlement proof root")?;
        if self.expires_at_height <= self.submitted_at_height {
            return Err("intent settlement expiry must be after submission".to_string());
        }
        Ok(self.submission_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorCandidate {
    pub candidate_id: String,
    pub sponsor_id: String,
    pub sponsor_kind: FeeSponsorKind,
    pub asset_id: String,
    pub lane_id: String,
    pub max_fee_units: u64,
    pub rebate_bps: u64,
    pub privacy_budget_units: u64,
    pub valid_until_height: u64,
    pub metadata_root: String,
    pub status: WalletOrchestratorStatus,
}

impl FeeSponsorCandidate {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        sponsor_label: &str,
        sponsor_kind: FeeSponsorKind,
        asset_id: &str,
        lane_id: &str,
        max_fee_units: u64,
        rebate_bps: u64,
        privacy_budget_units: u64,
        valid_until_height: u64,
        metadata: &Value,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(sponsor_label, "fee sponsor label")?;
        ensure_non_empty(asset_id, "fee sponsor asset id")?;
        ensure_non_empty(lane_id, "fee sponsor lane id")?;
        ensure_positive(max_fee_units, "fee sponsor max fee units")?;
        ensure_bps(rebate_bps, "fee sponsor rebate bps")?;
        let sponsor_id = wallet_orchestrator_payload_root(
            "WALLET-FEE-SPONSOR-ID",
            &json!({
                "sponsor_label": sponsor_label,
                "sponsor_kind": sponsor_kind.as_str(),
                "asset_id": asset_id,
                "lane_id": lane_id,
            }),
        );
        let metadata_root = wallet_orchestrator_payload_root(
            "WALLET-FEE-SPONSOR-METADATA",
            &json!({
                "sponsor_label": sponsor_label,
                "metadata": metadata,
            }),
        );
        let candidate_id = fee_sponsor_candidate_id(
            &sponsor_id,
            sponsor_kind.as_str(),
            asset_id,
            lane_id,
            valid_until_height,
        );
        let candidate = Self {
            candidate_id,
            sponsor_id,
            sponsor_kind,
            asset_id: asset_id.to_string(),
            lane_id: lane_id.to_string(),
            max_fee_units,
            rebate_bps,
            privacy_budget_units,
            valid_until_height,
            metadata_root,
            status: WalletOrchestratorStatus::Active,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_sponsor_candidate",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "candidate_id": self.candidate_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_kind": self.sponsor_kind.as_str(),
            "asset_id": self.asset_id,
            "lane_id": self.lane_id,
            "max_fee_units": self.max_fee_units,
            "rebate_bps": self.rebate_bps,
            "privacy_budget_units": self.privacy_budget_units,
            "valid_until_height": self.valid_until_height,
            "metadata_root": self.metadata_root,
            "status": self.status.as_str(),
        })
    }

    pub fn candidate_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-FEE-SPONSOR-CANDIDATE", &self.public_record())
    }

    pub fn can_sponsor(&self, asset_id: &str, fee_units: u64, height: u64) -> bool {
        self.status == WalletOrchestratorStatus::Active
            && self.asset_id == asset_id
            && self.max_fee_units >= fee_units
            && height <= self.valid_until_height
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.candidate_id, "fee sponsor candidate id")?;
        ensure_non_empty(&self.sponsor_id, "fee sponsor id")?;
        ensure_non_empty(&self.asset_id, "fee sponsor asset id")?;
        ensure_non_empty(&self.lane_id, "fee sponsor lane id")?;
        ensure_positive(self.max_fee_units, "fee sponsor max fee units")?;
        ensure_bps(self.rebate_bps, "fee sponsor rebate bps")?;
        ensure_non_empty(&self.metadata_root, "fee sponsor metadata root")?;
        Ok(self.candidate_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorshipSelection {
    pub selection_id: String,
    pub profile_id: String,
    pub operation_kind: PrivateOperationKind,
    pub operation_id: String,
    pub asset_id: String,
    pub requested_fee_units: u64,
    pub mode: FeeSponsorshipMode,
    pub selected_candidate_id: Option<String>,
    pub candidate_root: String,
    pub fallback_self_pay: bool,
    pub rebate_bps: u64,
    pub selected_at_height: u64,
    pub status: WalletOrchestratorStatus,
}

impl FeeSponsorshipSelection {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        operation_kind: PrivateOperationKind,
        operation_id: &str,
        asset_id: &str,
        requested_fee_units: u64,
        mode: FeeSponsorshipMode,
        candidate_records: &[FeeSponsorCandidate],
        selected_candidate_id: Option<String>,
        selected_at_height: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "fee sponsorship selection profile id")?;
        ensure_non_empty(operation_id, "fee sponsorship selection operation id")?;
        ensure_non_empty(asset_id, "fee sponsorship selection asset id")?;
        let candidate_root = fee_sponsor_candidate_collection_root(candidate_records);
        let selected_candidate = selected_candidate_id.as_ref().and_then(|candidate_id| {
            candidate_records
                .iter()
                .find(|candidate| &candidate.candidate_id == candidate_id)
        });
        let rebate_bps = selected_candidate
            .map(|candidate| candidate.rebate_bps)
            .unwrap_or(0);
        let fallback_self_pay = selected_candidate_id.is_none();
        if mode.requires_sponsor() && fallback_self_pay {
            return Err("fee sponsorship mode requires a selected sponsor".to_string());
        }
        let selection_id = fee_sponsorship_selection_id(
            profile_id,
            operation_kind.as_str(),
            operation_id,
            asset_id,
            &candidate_root,
        );
        let selection = Self {
            selection_id,
            profile_id: profile_id.to_string(),
            operation_kind,
            operation_id: operation_id.to_string(),
            asset_id: asset_id.to_string(),
            requested_fee_units,
            mode,
            selected_candidate_id,
            candidate_root,
            fallback_self_pay,
            rebate_bps,
            selected_at_height,
            status: WalletOrchestratorStatus::Selected,
        };
        selection.validate()?;
        Ok(selection)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "fee_sponsorship_selection",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "selection_id": self.selection_id,
            "profile_id": self.profile_id,
            "operation_kind": self.operation_kind.as_str(),
            "operation_id": self.operation_id,
            "asset_id": self.asset_id,
            "requested_fee_units": self.requested_fee_units,
            "mode": self.mode.as_str(),
            "selected_candidate_id": self.selected_candidate_id,
            "candidate_root": self.candidate_root,
            "fallback_self_pay": self.fallback_self_pay,
            "rebate_bps": self.rebate_bps,
            "selected_at_height": self.selected_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn selection_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-FEE-SPONSORSHIP-SELECTION", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.selection_id, "fee sponsorship selection id")?;
        ensure_non_empty(&self.profile_id, "fee sponsorship selection profile id")?;
        ensure_non_empty(&self.operation_id, "fee sponsorship selection operation id")?;
        ensure_non_empty(&self.asset_id, "fee sponsorship selection asset id")?;
        ensure_non_empty(&self.candidate_root, "fee sponsorship candidate root")?;
        ensure_bps(self.rebate_bps, "fee sponsorship rebate bps")?;
        if self.mode.requires_sponsor() && self.selected_candidate_id.is_none() {
            return Err("fee sponsorship selection requires sponsor".to_string());
        }
        if self.fallback_self_pay && self.selected_candidate_id.is_some() {
            return Err("fee sponsorship fallback conflicts with selected sponsor".to_string());
        }
        Ok(self.selection_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewingKeyDisclosureBundle {
    pub bundle_id: String,
    pub profile_id: String,
    pub scope: DisclosureScopeKind,
    pub delegated_to_commitment: String,
    pub view_key_commitment: String,
    pub disclosure_root: String,
    pub allowed_record_roots: Vec<String>,
    pub allowed_record_root: String,
    pub audit_tag_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl ViewingKeyDisclosureBundle {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        scope: DisclosureScopeKind,
        delegated_to_label: &str,
        allowed_record_roots: Vec<String>,
        starts_at_height: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "viewing key bundle profile id")?;
        ensure_non_empty(delegated_to_label, "viewing key bundle delegate label")?;
        ensure_positive(ttl_blocks, "viewing key bundle ttl")?;
        for root in &allowed_record_roots {
            ensure_non_empty(root, "viewing key allowed record root")?;
        }
        let delegated_to_commitment = wallet_orchestrator_payload_root(
            "WALLET-DISCLOSURE-DELEGATE",
            &json!({
                "profile_id": profile_id,
                "delegated_to_label": delegated_to_label,
                "scope": scope.as_str(),
                "nonce": nonce,
            }),
        );
        let view_key_commitment = wallet_orchestrator_payload_root(
            "WALLET-DISCLOSURE-VIEW-KEY",
            &json!({
                "profile_id": profile_id,
                "scope": scope.as_str(),
                "starts_at_height": starts_at_height,
                "nonce": nonce,
            }),
        );
        let allowed_record_root = wallet_orchestrator_string_collection_root(
            "WALLET-DISCLOSURE-ALLOWED-RECORDS",
            &allowed_record_roots,
        );
        let disclosure_root = wallet_orchestrator_payload_root(
            "WALLET-DISCLOSURE-BUNDLE",
            &json!({
                "profile_id": profile_id,
                "scope": scope.as_str(),
                "delegated_to_commitment": delegated_to_commitment,
                "view_key_commitment": view_key_commitment,
                "allowed_record_root": allowed_record_root,
            }),
        );
        let audit_tag_root = wallet_orchestrator_payload_root(
            "WALLET-DISCLOSURE-AUDIT-TAG",
            &json!({
                "disclosure_root": disclosure_root,
                "delegated_to_commitment": delegated_to_commitment,
                "nonce": nonce,
            }),
        );
        let bundle_id = viewing_key_bundle_id(
            profile_id,
            scope.as_str(),
            &delegated_to_commitment,
            &disclosure_root,
            nonce,
        );
        let bundle = Self {
            bundle_id,
            profile_id: profile_id.to_string(),
            scope,
            delegated_to_commitment,
            view_key_commitment,
            disclosure_root,
            allowed_record_roots,
            allowed_record_root,
            audit_tag_root,
            starts_at_height,
            expires_at_height: starts_at_height.saturating_add(ttl_blocks),
            nonce,
            status: WalletOrchestratorStatus::Active,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "viewing_key_disclosure_bundle",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "bundle_id": self.bundle_id,
            "profile_id": self.profile_id,
            "scope": self.scope.as_str(),
            "delegated_to_commitment": self.delegated_to_commitment,
            "view_key_commitment": self.view_key_commitment,
            "disclosure_root": self.disclosure_root,
            "allowed_record_roots": self.allowed_record_roots,
            "allowed_record_root": self.allowed_record_root,
            "audit_tag_root": self.audit_tag_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn bundle_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-VIEWING-KEY-BUNDLE", &self.public_record())
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == WalletOrchestratorStatus::Active
            && self.starts_at_height <= height
            && height < self.expires_at_height
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.bundle_id, "viewing key bundle id")?;
        ensure_non_empty(&self.profile_id, "viewing key bundle profile id")?;
        ensure_non_empty(
            &self.delegated_to_commitment,
            "viewing key bundle delegate commitment",
        )?;
        ensure_non_empty(
            &self.view_key_commitment,
            "viewing key bundle view key commitment",
        )?;
        ensure_non_empty(&self.disclosure_root, "viewing key bundle disclosure root")?;
        ensure_non_empty(
            &self.allowed_record_root,
            "viewing key bundle allowed record root",
        )?;
        ensure_non_empty(&self.audit_tag_root, "viewing key bundle audit tag root")?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("viewing key bundle expiry must be after start".to_string());
        }
        Ok(self.bundle_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineRecoveryPacket {
    pub packet_id: String,
    pub profile_id: String,
    pub recovery_kind: OfflineRecoveryKind,
    pub recovery_epoch: u64,
    pub guardian_count: u64,
    pub threshold: u64,
    pub guardian_set_root: String,
    pub encrypted_payload_root: String,
    pub previous_policy_root: String,
    pub next_policy_root: String,
    pub challenge_root: String,
    pub produced_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl OfflineRecoveryPacket {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        recovery_kind: OfflineRecoveryKind,
        recovery_epoch: u64,
        guardian_labels: Vec<String>,
        threshold: u64,
        produced_at_height: u64,
        recovery_delay_blocks: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "offline recovery profile id")?;
        ensure_non_empty_slice(&guardian_labels, "offline recovery guardians")?;
        ensure_positive(threshold, "offline recovery threshold")?;
        ensure_positive(ttl_blocks, "offline recovery ttl")?;
        if threshold > guardian_labels.len() as u64 {
            return Err("offline recovery threshold exceeds guardian count".to_string());
        }
        for guardian in &guardian_labels {
            ensure_non_empty(guardian, "offline recovery guardian label")?;
        }
        let guardian_roots = guardian_labels
            .iter()
            .map(|guardian| {
                wallet_orchestrator_payload_root(
                    "WALLET-RECOVERY-GUARDIAN",
                    &json!({
                        "profile_id": profile_id,
                        "guardian_label": guardian,
                        "recovery_epoch": recovery_epoch,
                    }),
                )
            })
            .collect::<Vec<_>>();
        let guardian_set_root = wallet_orchestrator_string_collection_root(
            "WALLET-RECOVERY-GUARDIAN-SET",
            &guardian_roots,
        );
        let encrypted_payload_root = wallet_orchestrator_payload_root(
            "WALLET-RECOVERY-ENCRYPTED-PAYLOAD",
            &json!({
                "profile_id": profile_id,
                "recovery_kind": recovery_kind.as_str(),
                "guardian_set_root": guardian_set_root,
                "threshold": threshold,
                "nonce": nonce,
            }),
        );
        let previous_policy_root = wallet_orchestrator_payload_root(
            "WALLET-RECOVERY-PREVIOUS-POLICY",
            &json!({
                "profile_id": profile_id,
                "recovery_epoch": recovery_epoch,
                "nonce": nonce,
            }),
        );
        let next_policy_root = wallet_orchestrator_payload_root(
            "WALLET-RECOVERY-NEXT-POLICY",
            &json!({
                "profile_id": profile_id,
                "recovery_epoch": recovery_epoch.saturating_add(1),
                "recovery_kind": recovery_kind.as_str(),
                "nonce": nonce,
            }),
        );
        let challenge_root = wallet_orchestrator_payload_root(
            "WALLET-RECOVERY-CHALLENGE",
            &json!({
                "encrypted_payload_root": encrypted_payload_root,
                "previous_policy_root": previous_policy_root,
                "next_policy_root": next_policy_root,
                "produced_at_height": produced_at_height,
            }),
        );
        let packet_id = offline_recovery_packet_id(
            profile_id,
            recovery_kind.as_str(),
            recovery_epoch,
            &guardian_set_root,
            nonce,
        );
        let packet = Self {
            packet_id,
            profile_id: profile_id.to_string(),
            recovery_kind,
            recovery_epoch,
            guardian_count: guardian_labels.len() as u64,
            threshold,
            guardian_set_root,
            encrypted_payload_root,
            previous_policy_root,
            next_policy_root,
            challenge_root,
            produced_at_height,
            executable_at_height: produced_at_height.saturating_add(recovery_delay_blocks),
            expires_at_height: produced_at_height.saturating_add(ttl_blocks),
            nonce,
            status: WalletOrchestratorStatus::Active,
        };
        packet.validate()?;
        Ok(packet)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "offline_recovery_packet",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "packet_id": self.packet_id,
            "profile_id": self.profile_id,
            "recovery_kind": self.recovery_kind.as_str(),
            "recovery_epoch": self.recovery_epoch,
            "guardian_count": self.guardian_count,
            "threshold": self.threshold,
            "guardian_set_root": self.guardian_set_root,
            "encrypted_payload_root": self.encrypted_payload_root,
            "previous_policy_root": self.previous_policy_root,
            "next_policy_root": self.next_policy_root,
            "challenge_root": self.challenge_root,
            "produced_at_height": self.produced_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn packet_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-OFFLINE-RECOVERY-PACKET", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.packet_id, "offline recovery packet id")?;
        ensure_non_empty(&self.profile_id, "offline recovery profile id")?;
        ensure_positive(self.guardian_count, "offline recovery guardian count")?;
        ensure_positive(self.threshold, "offline recovery threshold")?;
        if self.threshold > self.guardian_count {
            return Err("offline recovery threshold exceeds guardian count".to_string());
        }
        ensure_non_empty(
            &self.guardian_set_root,
            "offline recovery guardian set root",
        )?;
        ensure_non_empty(
            &self.encrypted_payload_root,
            "offline recovery encrypted payload root",
        )?;
        ensure_non_empty(
            &self.previous_policy_root,
            "offline recovery previous policy root",
        )?;
        ensure_non_empty(&self.next_policy_root, "offline recovery next policy root")?;
        ensure_non_empty(&self.challenge_root, "offline recovery challenge root")?;
        if self.expires_at_height <= self.produced_at_height {
            return Err("offline recovery expiry must be after production".to_string());
        }
        if self.executable_at_height > self.expires_at_height {
            return Err("offline recovery executable height exceeds expiry".to_string());
        }
        Ok(self.packet_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareSignerPolicy {
    pub policy_id: String,
    pub profile_id: String,
    pub signer_label_commitment: String,
    pub signer_kind: HardwareSignerKind,
    pub vendor_commitment: String,
    pub model_commitment: String,
    pub firmware_root: String,
    pub attestation_root: String,
    pub allowed_scope_root: String,
    pub scope_count: u64,
    pub spending_limit_units: u64,
    pub require_display_review: bool,
    pub require_pq_confirmation: bool,
    pub created_at_height: u64,
    pub nonce: u64,
    pub status: WalletOrchestratorStatus,
}

impl HardwareSignerPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn deterministic(
        profile_id: &str,
        signer_label: &str,
        signer_kind: HardwareSignerKind,
        scopes: Vec<HardwarePolicyScope>,
        spending_limit_units: u64,
        require_display_review: bool,
        require_pq_confirmation: bool,
        created_at_height: u64,
        nonce: u64,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(profile_id, "hardware policy profile id")?;
        ensure_non_empty(signer_label, "hardware policy signer label")?;
        ensure_non_empty_slice(&scopes, "hardware policy scopes")?;
        let signer_label_commitment = wallet_orchestrator_payload_root(
            "WALLET-HARDWARE-SIGNER-LABEL",
            &json!({
                "profile_id": profile_id,
                "signer_label": signer_label,
                "signer_kind": signer_kind.as_str(),
                "nonce": nonce,
            }),
        );
        let vendor_commitment = wallet_orchestrator_payload_root(
            "WALLET-HARDWARE-VENDOR",
            &json!({
                "signer_label": signer_label,
                "signer_kind": signer_kind.as_str(),
            }),
        );
        let model_commitment = wallet_orchestrator_payload_root(
            "WALLET-HARDWARE-MODEL",
            &json!({
                "signer_label": signer_label,
                "nonce": nonce,
            }),
        );
        let firmware_root = wallet_orchestrator_payload_root(
            "WALLET-HARDWARE-FIRMWARE",
            &json!({
                "signer_label": signer_label,
                "created_at_height": created_at_height,
                "nonce": nonce,
            }),
        );
        let attestation_root = wallet_orchestrator_payload_root(
            "WALLET-HARDWARE-ATTESTATION",
            &json!({
                "profile_id": profile_id,
                "signer_label_commitment": signer_label_commitment,
                "firmware_root": firmware_root,
            }),
        );
        let scope_strings = scopes
            .iter()
            .map(|scope| scope.as_str().to_string())
            .collect::<Vec<_>>();
        let allowed_scope_root =
            wallet_orchestrator_string_collection_root("WALLET-HARDWARE-SCOPES", &scope_strings);
        let policy_id = hardware_signer_policy_id(
            profile_id,
            signer_kind.as_str(),
            &signer_label_commitment,
            &allowed_scope_root,
            nonce,
        );
        let policy = Self {
            policy_id,
            profile_id: profile_id.to_string(),
            signer_label_commitment,
            signer_kind,
            vendor_commitment,
            model_commitment,
            firmware_root,
            attestation_root,
            allowed_scope_root,
            scope_count: scopes.len() as u64,
            spending_limit_units,
            require_display_review,
            require_pq_confirmation,
            created_at_height,
            nonce,
            status: WalletOrchestratorStatus::Active,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "hardware_signer_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "profile_id": self.profile_id,
            "signer_label_commitment": self.signer_label_commitment,
            "signer_kind": self.signer_kind.as_str(),
            "vendor_commitment": self.vendor_commitment,
            "model_commitment": self.model_commitment,
            "firmware_root": self.firmware_root,
            "attestation_root": self.attestation_root,
            "allowed_scope_root": self.allowed_scope_root,
            "scope_count": self.scope_count,
            "spending_limit_units": self.spending_limit_units,
            "require_display_review": self.require_display_review,
            "require_pq_confirmation": self.require_pq_confirmation,
            "created_at_height": self.created_at_height,
            "nonce": self.nonce,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-HARDWARE-SIGNER-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.policy_id, "hardware policy id")?;
        ensure_non_empty(&self.profile_id, "hardware policy profile id")?;
        ensure_non_empty(
            &self.signer_label_commitment,
            "hardware policy signer label commitment",
        )?;
        ensure_non_empty(&self.vendor_commitment, "hardware policy vendor commitment")?;
        ensure_non_empty(&self.model_commitment, "hardware policy model commitment")?;
        ensure_non_empty(&self.firmware_root, "hardware policy firmware root")?;
        ensure_non_empty(&self.attestation_root, "hardware policy attestation root")?;
        ensure_non_empty(&self.allowed_scope_root, "hardware policy scope root")?;
        ensure_positive(self.scope_count, "hardware policy scope count")?;
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevnetFixtureRecord {
    pub fixture_id: String,
    pub label: String,
    pub fixture_kind: DevnetFixtureKind,
    pub profile_id: String,
    pub object_id: String,
    pub record_root: String,
    pub height: u64,
    pub note: String,
}

impl DevnetFixtureRecord {
    pub fn new(
        label: &str,
        fixture_kind: DevnetFixtureKind,
        profile_id: &str,
        object_id: &str,
        record: &Value,
        height: u64,
        note: &str,
    ) -> WalletOrchestratorResult<Self> {
        ensure_non_empty(label, "devnet fixture label")?;
        ensure_non_empty(profile_id, "devnet fixture profile id")?;
        ensure_non_empty(object_id, "devnet fixture object id")?;
        let record_root = wallet_orchestrator_payload_root("WALLET-DEVNET-FIXTURE-RECORD", record);
        let fixture_id = devnet_fixture_id(label, fixture_kind.as_str(), profile_id, object_id);
        let fixture = Self {
            fixture_id,
            label: label.to_string(),
            fixture_kind,
            profile_id: profile_id.to_string(),
            object_id: object_id.to_string(),
            record_root,
            height,
            note: note.to_string(),
        };
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_orchestrator_devnet_fixture",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "fixture_id": self.fixture_id,
            "label": self.label,
            "fixture_kind": self.fixture_kind.as_str(),
            "profile_id": self.profile_id,
            "object_id": self.object_id,
            "record_root": self.record_root,
            "height": self.height,
            "note": self.note,
        })
    }

    pub fn fixture_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-DEVNET-FIXTURE", &self.public_record())
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&self.fixture_id, "devnet fixture id")?;
        ensure_non_empty(&self.label, "devnet fixture label")?;
        ensure_non_empty(&self.profile_id, "devnet fixture profile id")?;
        ensure_non_empty(&self.object_id, "devnet fixture object id")?;
        ensure_non_empty(&self.record_root, "devnet fixture record root")?;
        Ok(self.fixture_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletOrchestratorRoots {
    pub config_root: String,
    pub profile_root: String,
    pub pq_handshake_root: String,
    pub bridge_intent_root: String,
    pub private_transfer_root: String,
    pub contract_call_root: String,
    pub settlement_submission_root: String,
    pub fee_sponsor_candidate_root: String,
    pub fee_sponsorship_selection_root: String,
    pub viewing_key_bundle_root: String,
    pub recovery_packet_root: String,
    pub hardware_signer_policy_root: String,
    pub devnet_fixture_root: String,
    pub public_record_root: String,
}

impl WalletOrchestratorRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_orchestrator_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "profile_root": self.profile_root,
            "pq_handshake_root": self.pq_handshake_root,
            "bridge_intent_root": self.bridge_intent_root,
            "private_transfer_root": self.private_transfer_root,
            "contract_call_root": self.contract_call_root,
            "settlement_submission_root": self.settlement_submission_root,
            "fee_sponsor_candidate_root": self.fee_sponsor_candidate_root,
            "fee_sponsorship_selection_root": self.fee_sponsorship_selection_root,
            "viewing_key_bundle_root": self.viewing_key_bundle_root,
            "recovery_packet_root": self.recovery_packet_root,
            "hardware_signer_policy_root": self.hardware_signer_policy_root,
            "devnet_fixture_root": self.devnet_fixture_root,
            "public_record_root": self.public_record_root,
        })
    }

    pub fn roots_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-ORCHESTRATOR-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletOrchestratorCounters {
    pub height: u64,
    pub profile_count: u64,
    pub active_profile_count: u64,
    pub pq_handshake_count: u64,
    pub active_pq_handshake_count: u64,
    pub bridge_intent_count: u64,
    pub deposit_intent_count: u64,
    pub withdrawal_intent_count: u64,
    pub pending_bridge_intent_count: u64,
    pub private_transfer_count: u64,
    pub pending_private_transfer_count: u64,
    pub private_contract_call_count: u64,
    pub pending_private_contract_call_count: u64,
    pub settlement_submission_count: u64,
    pub live_settlement_submission_count: u64,
    pub fee_sponsor_candidate_count: u64,
    pub active_fee_sponsor_candidate_count: u64,
    pub fee_sponsorship_selection_count: u64,
    pub viewing_key_bundle_count: u64,
    pub active_viewing_key_bundle_count: u64,
    pub recovery_packet_count: u64,
    pub active_recovery_packet_count: u64,
    pub hardware_signer_policy_count: u64,
    pub active_hardware_signer_policy_count: u64,
    pub devnet_fixture_count: u64,
    pub total_bridge_deposit_units: u64,
    pub total_bridge_withdrawal_units: u64,
    pub total_private_transfer_units: u64,
    pub total_contract_value_units: u64,
    pub total_selected_sponsored_fee_units: u64,
}

impl WalletOrchestratorCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "wallet_orchestrator_counters",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "height": self.height,
            "profile_count": self.profile_count,
            "active_profile_count": self.active_profile_count,
            "pq_handshake_count": self.pq_handshake_count,
            "active_pq_handshake_count": self.active_pq_handshake_count,
            "bridge_intent_count": self.bridge_intent_count,
            "deposit_intent_count": self.deposit_intent_count,
            "withdrawal_intent_count": self.withdrawal_intent_count,
            "pending_bridge_intent_count": self.pending_bridge_intent_count,
            "private_transfer_count": self.private_transfer_count,
            "pending_private_transfer_count": self.pending_private_transfer_count,
            "private_contract_call_count": self.private_contract_call_count,
            "pending_private_contract_call_count": self.pending_private_contract_call_count,
            "settlement_submission_count": self.settlement_submission_count,
            "live_settlement_submission_count": self.live_settlement_submission_count,
            "fee_sponsor_candidate_count": self.fee_sponsor_candidate_count,
            "active_fee_sponsor_candidate_count": self.active_fee_sponsor_candidate_count,
            "fee_sponsorship_selection_count": self.fee_sponsorship_selection_count,
            "viewing_key_bundle_count": self.viewing_key_bundle_count,
            "active_viewing_key_bundle_count": self.active_viewing_key_bundle_count,
            "recovery_packet_count": self.recovery_packet_count,
            "active_recovery_packet_count": self.active_recovery_packet_count,
            "hardware_signer_policy_count": self.hardware_signer_policy_count,
            "active_hardware_signer_policy_count": self.active_hardware_signer_policy_count,
            "devnet_fixture_count": self.devnet_fixture_count,
            "total_bridge_deposit_units": self.total_bridge_deposit_units,
            "total_bridge_withdrawal_units": self.total_bridge_withdrawal_units,
            "total_private_transfer_units": self.total_private_transfer_units,
            "total_contract_value_units": self.total_contract_value_units,
            "total_selected_sponsored_fee_units": self.total_selected_sponsored_fee_units,
        })
    }

    pub fn counter_root(&self) -> String {
        wallet_orchestrator_payload_root("WALLET-ORCHESTRATOR-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletOrchestratorState {
    pub height: u64,
    pub active_profile_id: Option<String>,
    pub config: WalletOrchestratorConfig,
    pub profiles: BTreeMap<String, WalletProfile>,
    pub pq_handshakes: BTreeMap<String, WalletPqSessionHandshake>,
    pub bridge_intents: BTreeMap<String, MoneroBridgeIntent>,
    pub private_transfers: BTreeMap<String, PrivateTokenTransfer>,
    pub contract_calls: BTreeMap<String, PrivateContractCall>,
    pub settlement_submissions: BTreeMap<String, IntentSettlementSubmission>,
    pub fee_sponsor_candidates: BTreeMap<String, FeeSponsorCandidate>,
    pub fee_sponsorship_selections: BTreeMap<String, FeeSponsorshipSelection>,
    pub viewing_key_bundles: BTreeMap<String, ViewingKeyDisclosureBundle>,
    pub recovery_packets: BTreeMap<String, OfflineRecoveryPacket>,
    pub hardware_signer_policies: BTreeMap<String, HardwareSignerPolicy>,
    pub devnet_fixtures: BTreeMap<String, DevnetFixtureRecord>,
    pub public_records: BTreeMap<String, Value>,
}

impl Default for WalletOrchestratorState {
    fn default() -> Self {
        Self::new(WalletOrchestratorConfig::default()).expect("default wallet orchestrator config")
    }
}

impl WalletOrchestratorState {
    pub fn new(config: WalletOrchestratorConfig) -> WalletOrchestratorResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            active_profile_id: None,
            config,
            profiles: BTreeMap::new(),
            pq_handshakes: BTreeMap::new(),
            bridge_intents: BTreeMap::new(),
            private_transfers: BTreeMap::new(),
            contract_calls: BTreeMap::new(),
            settlement_submissions: BTreeMap::new(),
            fee_sponsor_candidates: BTreeMap::new(),
            fee_sponsorship_selections: BTreeMap::new(),
            viewing_key_bundles: BTreeMap::new(),
            recovery_packets: BTreeMap::new(),
            hardware_signer_policies: BTreeMap::new(),
            devnet_fixtures: BTreeMap::new(),
            public_records: BTreeMap::new(),
        })
    }

    pub fn devnet() -> WalletOrchestratorResult<Self> {
        let mut state = Self::new(WalletOrchestratorConfig::default())?;
        state.height = WALLET_ORCHESTRATOR_DEVNET_HEIGHT;
        let default_fee_asset_id = state.config.default_fee_asset_id.clone();
        let monero_network = state.config.monero_network.clone();
        let amount_bucket_size = state.config.amount_bucket_size;
        let session_ttl_blocks = state.config.default_session_ttl_blocks;
        let intent_ttl_blocks = state.config.default_intent_ttl_blocks;
        let disclosure_ttl_blocks = state.config.default_disclosure_ttl_blocks;
        let recovery_delay_blocks = state.config.default_recovery_delay_blocks;

        let alice_metadata = json!({
            "display": "devnet alice",
            "spend_profile": "daily private payments",
            "recovery": "guardian quorum",
        });
        let bob_metadata = json!({
            "display": "devnet bob",
            "spend_profile": "counterparty receiving wallet",
            "sync": "watch only mirror enabled",
        });
        let operator_metadata = json!({
            "display": "devnet operator fixture",
            "role": "sequencer bridge and paymaster counterparty",
        });

        let alice = WalletProfile::deterministic(
            "devnet-alice",
            WalletProfileKind::HardwareBound,
            &default_fee_asset_id,
            state.height,
            &alice_metadata,
        )?;
        let bob = WalletProfile::deterministic(
            "devnet-bob",
            WalletProfileKind::Spending,
            &default_fee_asset_id,
            state.height,
            &bob_metadata,
        )?;
        let operator = WalletProfile::deterministic(
            "devnet-operator",
            WalletProfileKind::OperatorFixture,
            &default_fee_asset_id,
            state.height,
            &operator_metadata,
        )?;
        let alice_profile_id = alice.profile_id.clone();
        let bob_profile_id = bob.profile_id.clone();
        let operator_profile_id = operator.profile_id.clone();

        let alice_policy = HardwareSignerPolicy::deterministic(
            &alice_profile_id,
            "devnet-ledger-alice",
            HardwareSignerKind::HardwareWallet,
            vec![
                HardwarePolicyScope::Transfer,
                HardwarePolicyScope::ContractCall,
                HardwarePolicyScope::BridgeWithdrawal,
                HardwarePolicyScope::Recovery,
                HardwarePolicyScope::Disclosure,
            ],
            5_000_000_000,
            true,
            true,
            state.height,
            1,
        )?;
        let alice_policy_id = alice_policy.policy_id.clone();
        let alice = alice.with_signer_policy(alice_policy_id.clone());

        let alice_handshake = WalletPqSessionHandshake::deterministic(
            &alice_profile_id,
            "devnet-sequencer-a",
            PqPeerRole::Sequencer,
            PqHandshakePurpose::MempoolSubmission,
            state.height,
            session_ttl_blocks,
            11,
        )?;
        let bob_handshake = WalletPqSessionHandshake::deterministic(
            &bob_profile_id,
            "devnet-sequencer-a",
            PqPeerRole::Sequencer,
            PqHandshakePurpose::MempoolSubmission,
            state.height,
            session_ttl_blocks,
            12,
        )?;
        let alice = alice.with_preferred_peer(alice_handshake.peer_id.clone());

        state.insert_profile(alice.clone())?;
        state.insert_profile(bob.clone())?;
        state.insert_profile(operator.clone())?;
        state.active_profile_id = Some(alice_profile_id.clone());
        state.insert_hardware_signer_policy(alice_policy.clone())?;
        state.insert_pq_handshake(alice_handshake.clone())?;
        state.insert_pq_handshake(bob_handshake.clone())?;

        let sponsor_a = FeeSponsorCandidate::deterministic(
            "devnet-private-paymaster-a",
            FeeSponsorKind::PrivatePaymaster,
            &default_fee_asset_id,
            "private-fast-lane",
            250_000,
            5_000,
            10_000_000,
            state.height + 1_000,
            &json!({"region": "devnet", "privacy_lane": "standard"}),
        )?;
        let sponsor_b = FeeSponsorCandidate::deterministic(
            "devnet-bridge-relayer-b",
            FeeSponsorKind::BridgeRelayer,
            &default_fee_asset_id,
            "bridge-withdrawals",
            400_000,
            6_000,
            6_000_000,
            state.height + 720,
            &json!({"region": "devnet", "lane": "bridge"}),
        )?;
        state.insert_fee_sponsor_candidate(sponsor_a.clone())?;
        state.insert_fee_sponsor_candidate(sponsor_b.clone())?;

        let deposit = MoneroBridgeIntent::deposit(
            &alice_profile_id,
            &monero_network,
            &default_fee_asset_id,
            1_250_000_000,
            "alice-l2-shielded-deposit",
            amount_bucket_size,
            state.height,
            intent_ttl_blocks,
            21,
        )?;
        let withdrawal = MoneroBridgeIntent::withdrawal(
            &alice_profile_id,
            &monero_network,
            &default_fee_asset_id,
            750_000_000,
            25_000,
            "alice-monero-withdrawal-address",
            "alice-withdrawal-nullifier",
            amount_bucket_size,
            state.height,
            intent_ttl_blocks,
            22,
        )?;
        state.insert_bridge_intent(deposit.clone())?;
        state.insert_bridge_intent(withdrawal.clone())?;

        let transfer_selection = state.select_fee_sponsor(
            &alice_profile_id,
            PrivateOperationKind::TokenTransfer,
            "devnet-transfer-draft",
            &default_fee_asset_id,
            20_000,
            FeeSponsorshipMode::PreferPrivateSponsor,
        )?;
        let transfer = PrivateTokenTransfer::deterministic(
            &alice_profile_id,
            &default_fee_asset_id,
            120_000_000,
            "devnet-bob",
            &default_fee_asset_id,
            20_000,
            Some(transfer_selection.selection_id.clone()),
            amount_bucket_size,
            state.height,
            intent_ttl_blocks,
            31,
        )?;
        state.insert_private_transfer(transfer.clone())?;

        let call_selection = state.select_fee_sponsor(
            &alice_profile_id,
            PrivateOperationKind::ContractCall,
            "devnet-call-draft",
            &default_fee_asset_id,
            35_000,
            FeeSponsorshipMode::PreferPrivateSponsor,
        )?;
        let contract_call = PrivateContractCall::deterministic(
            &alice_profile_id,
            "devnet-private-swap-vault",
            "swap_exact_input",
            &default_fee_asset_id,
            45_000_000,
            2_000_000,
            35_000,
            Some(call_selection.selection_id.clone()),
            Some(alice_handshake.handshake_id.clone()),
            amount_bucket_size,
            state.height,
            intent_ttl_blocks,
            41,
        )?;
        state.insert_contract_call(contract_call.clone())?;

        let withdrawal_selection = state.select_fee_sponsor(
            &alice_profile_id,
            PrivateOperationKind::BridgeWithdrawal,
            &withdrawal.intent_id,
            &default_fee_asset_id,
            withdrawal.bridge_fee_units,
            FeeSponsorshipMode::PreferPrivateSponsor,
        )?;

        let transfer_submission = IntentSettlementSubmission::deterministic(
            &alice_profile_id,
            PrivateOperationKind::TokenTransfer,
            &transfer.transfer_id,
            SettlementDomainKind::Token,
            vec![
                transfer.transfer_root(),
                transfer_selection.selection_root(),
            ],
            Some(transfer_selection.selection_id.clone()),
            None,
            state.height + 1,
            intent_ttl_blocks,
            51,
        )?;
        let call_submission = IntentSettlementSubmission::deterministic(
            &alice_profile_id,
            PrivateOperationKind::ContractCall,
            &contract_call.call_id,
            SettlementDomainKind::Contract,
            vec![contract_call.call_root(), call_selection.selection_root()],
            Some(call_selection.selection_id.clone()),
            None,
            state.height + 1,
            intent_ttl_blocks,
            52,
        )?;
        let withdrawal_submission = IntentSettlementSubmission::deterministic(
            &alice_profile_id,
            PrivateOperationKind::BridgeWithdrawal,
            &withdrawal.intent_id,
            SettlementDomainKind::Bridge,
            vec![
                withdrawal.intent_root(),
                withdrawal_selection.selection_root(),
            ],
            Some(withdrawal_selection.selection_id.clone()),
            Some(withdrawal.intent_id.clone()),
            state.height + 2,
            intent_ttl_blocks,
            53,
        )?;
        state.insert_settlement_submission(transfer_submission.clone())?;
        state.insert_settlement_submission(call_submission.clone())?;
        state.insert_settlement_submission(withdrawal_submission.clone())?;

        let disclosure = ViewingKeyDisclosureBundle::deterministic(
            &alice_profile_id,
            DisclosureScopeKind::BridgeProof,
            "devnet-watchtower-a",
            vec![deposit.intent_root(), withdrawal.intent_root()],
            state.height,
            disclosure_ttl_blocks,
            61,
        )?;
        state.insert_viewing_key_bundle(disclosure.clone())?;

        let recovery_packet = OfflineRecoveryPacket::deterministic(
            &alice_profile_id,
            OfflineRecoveryKind::SpendKeyRotation,
            0,
            vec![
                "guardian-one".to_string(),
                "guardian-two".to_string(),
                "guardian-three".to_string(),
            ],
            2,
            state.height,
            recovery_delay_blocks,
            recovery_delay_blocks + 720,
            71,
        )?;
        state.insert_recovery_packet(recovery_packet.clone())?;

        state.record_devnet_fixture(
            "alice-profile",
            DevnetFixtureKind::WalletProfile,
            &alice_profile_id,
            &alice_profile_id,
            &alice.public_record(),
            "primary devnet hardware-bound wallet profile",
        )?;
        state.record_devnet_fixture(
            "bob-profile",
            DevnetFixtureKind::WalletProfile,
            &bob_profile_id,
            &bob_profile_id,
            &bob.public_record(),
            "counterparty devnet spending wallet profile",
        )?;
        state.record_devnet_fixture(
            "operator-profile",
            DevnetFixtureKind::WalletProfile,
            &operator_profile_id,
            &operator_profile_id,
            &operator.public_record(),
            "operator-side wallet orchestration fixture",
        )?;
        state.record_devnet_fixture(
            "alice-pq-handshake",
            DevnetFixtureKind::PqHandshake,
            &alice_profile_id,
            &alice_handshake.handshake_id,
            &alice_handshake.public_record(),
            "wallet to sequencer post-quantum encrypted session",
        )?;
        state.record_devnet_fixture(
            "alice-deposit-intent",
            DevnetFixtureKind::BridgeIntent,
            &alice_profile_id,
            &deposit.intent_id,
            &deposit.public_record(),
            "monero bridge deposit intent",
        )?;
        state.record_devnet_fixture(
            "alice-withdrawal-intent",
            DevnetFixtureKind::BridgeIntent,
            &alice_profile_id,
            &withdrawal.intent_id,
            &withdrawal.public_record(),
            "monero bridge withdrawal intent",
        )?;
        state.record_devnet_fixture(
            "alice-private-transfer",
            DevnetFixtureKind::PrivateTransfer,
            &alice_profile_id,
            &transfer.transfer_id,
            &transfer.public_record(),
            "private token transfer with sponsored fee selection",
        )?;
        state.record_devnet_fixture(
            "alice-private-contract-call",
            DevnetFixtureKind::ContractCall,
            &alice_profile_id,
            &contract_call.call_id,
            &contract_call.public_record(),
            "private contract call routed through pq session",
        )?;
        state.record_devnet_fixture(
            "alice-transfer-settlement",
            DevnetFixtureKind::SettlementSubmission,
            &alice_profile_id,
            &transfer_submission.submission_id,
            &transfer_submission.public_record(),
            "intent settlement submission for transfer",
        )?;
        state.record_devnet_fixture(
            "alice-disclosure",
            DevnetFixtureKind::ViewingKeyBundle,
            &alice_profile_id,
            &disclosure.bundle_id,
            &disclosure.public_record(),
            "viewing key disclosure bundle for bridge audit",
        )?;
        state.record_devnet_fixture(
            "alice-recovery",
            DevnetFixtureKind::RecoveryPacket,
            &alice_profile_id,
            &recovery_packet.packet_id,
            &recovery_packet.public_record(),
            "offline guardian recovery packet",
        )?;
        state.record_devnet_fixture(
            "alice-hardware-policy",
            DevnetFixtureKind::HardwareSignerPolicy,
            &alice_profile_id,
            &alice_policy_id,
            &alice_policy.public_record(),
            "hardware signer policy for high-value operations",
        )?;
        let devnet_roots_record = state.roots().public_record();
        state.insert_public_record("devnet-state-roots".to_string(), devnet_roots_record)?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> WalletOrchestratorResult<String> {
        self.height = height;
        for handshake in self.pq_handshakes.values_mut() {
            if handshake.status.is_live() && height >= handshake.expires_at_height {
                handshake.status = WalletOrchestratorStatus::Expired;
                handshake.stage = PqHandshakeStage::Expired;
            }
        }
        for intent in self.bridge_intents.values_mut() {
            if intent.status.is_live() && height >= intent.expires_at_height {
                intent.status = WalletOrchestratorStatus::Expired;
            }
        }
        for transfer in self.private_transfers.values_mut() {
            if transfer.status.is_live() && height >= transfer.expires_at_height {
                transfer.status = WalletOrchestratorStatus::Expired;
            }
        }
        for call in self.contract_calls.values_mut() {
            if call.status.is_live() && height >= call.expires_at_height {
                call.status = WalletOrchestratorStatus::Expired;
            }
        }
        for submission in self.settlement_submissions.values_mut() {
            if submission.status.is_live() && height >= submission.expires_at_height {
                submission.status = WalletOrchestratorStatus::Expired;
            }
        }
        for candidate in self.fee_sponsor_candidates.values_mut() {
            if candidate.status == WalletOrchestratorStatus::Active
                && height > candidate.valid_until_height
            {
                candidate.status = WalletOrchestratorStatus::Expired;
            }
        }
        for bundle in self.viewing_key_bundles.values_mut() {
            if bundle.status == WalletOrchestratorStatus::Active
                && height >= bundle.expires_at_height
            {
                bundle.status = WalletOrchestratorStatus::Expired;
            }
        }
        for packet in self.recovery_packets.values_mut() {
            if packet.status == WalletOrchestratorStatus::Active
                && height >= packet.expires_at_height
            {
                packet.status = WalletOrchestratorStatus::Expired;
            }
        }
        self.validate()
    }

    pub fn insert_profile(&mut self, profile: WalletProfile) -> WalletOrchestratorResult<String> {
        profile.validate()?;
        ensure_capacity(
            self.profiles.len(),
            self.config.max_profiles,
            "wallet profiles",
        )?;
        ensure_map_absent(&self.profiles, &profile.profile_id, "wallet profile")?;
        let profile_id = profile.profile_id.clone();
        self.profiles.insert(profile_id.clone(), profile);
        Ok(profile_id)
    }

    pub fn insert_pq_handshake(
        &mut self,
        handshake: WalletPqSessionHandshake,
    ) -> WalletOrchestratorResult<String> {
        handshake.validate()?;
        ensure_capacity(
            self.pq_handshakes.len(),
            self.config.max_handshakes,
            "wallet pq handshakes",
        )?;
        ensure_map_absent(
            &self.pq_handshakes,
            &handshake.handshake_id,
            "wallet pq handshake",
        )?;
        let handshake_id = handshake.handshake_id.clone();
        self.pq_handshakes.insert(handshake_id.clone(), handshake);
        Ok(handshake_id)
    }

    pub fn insert_bridge_intent(
        &mut self,
        intent: MoneroBridgeIntent,
    ) -> WalletOrchestratorResult<String> {
        intent.validate()?;
        ensure_capacity(
            self.bridge_intents.len(),
            self.config.max_bridge_intents,
            "wallet bridge intents",
        )?;
        ensure_map_absent(&self.bridge_intents, &intent.intent_id, "bridge intent")?;
        let intent_id = intent.intent_id.clone();
        self.bridge_intents.insert(intent_id.clone(), intent);
        Ok(intent_id)
    }

    pub fn insert_private_transfer(
        &mut self,
        transfer: PrivateTokenTransfer,
    ) -> WalletOrchestratorResult<String> {
        transfer.validate()?;
        ensure_capacity(
            self.private_transfers.len(),
            self.config.max_private_transfers,
            "wallet private transfers",
        )?;
        ensure_map_absent(
            &self.private_transfers,
            &transfer.transfer_id,
            "private transfer",
        )?;
        let transfer_id = transfer.transfer_id.clone();
        self.private_transfers.insert(transfer_id.clone(), transfer);
        Ok(transfer_id)
    }

    pub fn insert_contract_call(
        &mut self,
        call: PrivateContractCall,
    ) -> WalletOrchestratorResult<String> {
        call.validate()?;
        ensure_capacity(
            self.contract_calls.len(),
            self.config.max_contract_calls,
            "wallet contract calls",
        )?;
        ensure_map_absent(&self.contract_calls, &call.call_id, "private contract call")?;
        let call_id = call.call_id.clone();
        self.contract_calls.insert(call_id.clone(), call);
        Ok(call_id)
    }

    pub fn insert_settlement_submission(
        &mut self,
        submission: IntentSettlementSubmission,
    ) -> WalletOrchestratorResult<String> {
        submission.validate()?;
        ensure_capacity(
            self.settlement_submissions.len(),
            self.config.max_settlement_submissions,
            "wallet settlement submissions",
        )?;
        ensure_map_absent(
            &self.settlement_submissions,
            &submission.submission_id,
            "settlement submission",
        )?;
        let submission_id = submission.submission_id.clone();
        self.settlement_submissions
            .insert(submission_id.clone(), submission);
        Ok(submission_id)
    }

    pub fn insert_fee_sponsor_candidate(
        &mut self,
        candidate: FeeSponsorCandidate,
    ) -> WalletOrchestratorResult<String> {
        candidate.validate()?;
        ensure_capacity(
            self.fee_sponsor_candidates.len(),
            self.config.max_fee_sponsor_candidates,
            "wallet fee sponsor candidates",
        )?;
        ensure_map_absent(
            &self.fee_sponsor_candidates,
            &candidate.candidate_id,
            "fee sponsor candidate",
        )?;
        let candidate_id = candidate.candidate_id.clone();
        self.fee_sponsor_candidates
            .insert(candidate_id.clone(), candidate);
        Ok(candidate_id)
    }

    pub fn insert_fee_sponsorship_selection(
        &mut self,
        selection: FeeSponsorshipSelection,
    ) -> WalletOrchestratorResult<String> {
        selection.validate()?;
        ensure_map_absent(
            &self.fee_sponsorship_selections,
            &selection.selection_id,
            "fee sponsorship selection",
        )?;
        let selection_id = selection.selection_id.clone();
        self.fee_sponsorship_selections
            .insert(selection_id.clone(), selection);
        Ok(selection_id)
    }

    pub fn insert_viewing_key_bundle(
        &mut self,
        bundle: ViewingKeyDisclosureBundle,
    ) -> WalletOrchestratorResult<String> {
        bundle.validate()?;
        ensure_capacity(
            self.viewing_key_bundles.len(),
            self.config.max_viewing_key_bundles,
            "wallet viewing key bundles",
        )?;
        ensure_map_absent(
            &self.viewing_key_bundles,
            &bundle.bundle_id,
            "viewing key bundle",
        )?;
        let bundle_id = bundle.bundle_id.clone();
        self.viewing_key_bundles.insert(bundle_id.clone(), bundle);
        Ok(bundle_id)
    }

    pub fn insert_recovery_packet(
        &mut self,
        packet: OfflineRecoveryPacket,
    ) -> WalletOrchestratorResult<String> {
        packet.validate()?;
        ensure_capacity(
            self.recovery_packets.len(),
            self.config.max_recovery_packets,
            "wallet recovery packets",
        )?;
        ensure_map_absent(
            &self.recovery_packets,
            &packet.packet_id,
            "offline recovery packet",
        )?;
        let packet_id = packet.packet_id.clone();
        self.recovery_packets.insert(packet_id.clone(), packet);
        Ok(packet_id)
    }

    pub fn insert_hardware_signer_policy(
        &mut self,
        policy: HardwareSignerPolicy,
    ) -> WalletOrchestratorResult<String> {
        policy.validate()?;
        ensure_capacity(
            self.hardware_signer_policies.len(),
            self.config.max_hardware_policies,
            "wallet hardware signer policies",
        )?;
        ensure_map_absent(
            &self.hardware_signer_policies,
            &policy.policy_id,
            "hardware signer policy",
        )?;
        let policy_id = policy.policy_id.clone();
        self.hardware_signer_policies
            .insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    pub fn insert_public_record(
        &mut self,
        key: String,
        record: Value,
    ) -> WalletOrchestratorResult<String> {
        ensure_non_empty(&key, "wallet public record key")?;
        ensure_capacity(
            self.public_records.len(),
            self.config.max_public_records,
            "wallet public records",
        )?;
        let record_id = wallet_orchestrator_payload_root("WALLET-PUBLIC-RECORD", &record);
        self.public_records
            .insert(format!("{key}:{record_id}"), record);
        Ok(record_id)
    }

    pub fn select_fee_sponsor(
        &mut self,
        profile_id: &str,
        operation_kind: PrivateOperationKind,
        operation_id: &str,
        asset_id: &str,
        requested_fee_units: u64,
        mode: FeeSponsorshipMode,
    ) -> WalletOrchestratorResult<FeeSponsorshipSelection> {
        ensure_non_empty(profile_id, "fee sponsor selection profile id")?;
        ensure_non_empty(operation_id, "fee sponsor selection operation id")?;
        ensure_non_empty(asset_id, "fee sponsor selection asset id")?;
        if !self.profiles.contains_key(profile_id) {
            return Err("fee sponsor selection references unknown profile".to_string());
        }
        if !self.config.allow_fee_sponsorship && mode.allows_sponsor() {
            return Err("fee sponsorship is disabled by wallet orchestrator config".to_string());
        }
        let candidates = self
            .fee_sponsor_candidates
            .values()
            .filter(|candidate| candidate.can_sponsor(asset_id, requested_fee_units, self.height))
            .cloned()
            .collect::<Vec<_>>();
        let selected = if mode.allows_sponsor() {
            candidates
                .iter()
                .max_by(|left, right| {
                    (
                        left.rebate_bps,
                        left.privacy_budget_units,
                        std::cmp::Reverse(left.valid_until_height),
                        left.candidate_id.as_str(),
                    )
                        .cmp(&(
                            right.rebate_bps,
                            right.privacy_budget_units,
                            std::cmp::Reverse(right.valid_until_height),
                            right.candidate_id.as_str(),
                        ))
                })
                .map(|candidate| candidate.candidate_id.clone())
        } else {
            None
        };
        if mode.requires_sponsor() && selected.is_none() {
            return Err("no eligible fee sponsor candidate available".to_string());
        }
        let selection = FeeSponsorshipSelection::deterministic(
            profile_id,
            operation_kind,
            operation_id,
            asset_id,
            requested_fee_units,
            mode,
            &candidates,
            selected,
            self.height,
        )?;
        self.insert_fee_sponsorship_selection(selection.clone())?;
        Ok(selection)
    }

    pub fn record_devnet_fixture(
        &mut self,
        label: &str,
        fixture_kind: DevnetFixtureKind,
        profile_id: &str,
        object_id: &str,
        record: &Value,
        note: &str,
    ) -> WalletOrchestratorResult<String> {
        let fixture = DevnetFixtureRecord::new(
            label,
            fixture_kind,
            profile_id,
            object_id,
            record,
            self.height,
            note,
        )?;
        ensure_map_absent(&self.devnet_fixtures, &fixture.fixture_id, "devnet fixture")?;
        let fixture_id = fixture.fixture_id.clone();
        self.devnet_fixtures.insert(fixture_id.clone(), fixture);
        Ok(fixture_id)
    }

    pub fn roots(&self) -> WalletOrchestratorRoots {
        WalletOrchestratorRoots {
            config_root: self.config.config_root(),
            profile_root: wallet_profile_collection_root(
                &self.profiles.values().cloned().collect::<Vec<_>>(),
            ),
            pq_handshake_root: wallet_pq_handshake_collection_root(
                &self.pq_handshakes.values().cloned().collect::<Vec<_>>(),
            ),
            bridge_intent_root: monero_bridge_intent_collection_root(
                &self.bridge_intents.values().cloned().collect::<Vec<_>>(),
            ),
            private_transfer_root: private_transfer_collection_root(
                &self.private_transfers.values().cloned().collect::<Vec<_>>(),
            ),
            contract_call_root: private_contract_call_collection_root(
                &self.contract_calls.values().cloned().collect::<Vec<_>>(),
            ),
            settlement_submission_root: intent_settlement_submission_collection_root(
                &self
                    .settlement_submissions
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            fee_sponsor_candidate_root: fee_sponsor_candidate_collection_root(
                &self
                    .fee_sponsor_candidates
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            fee_sponsorship_selection_root: fee_sponsorship_selection_collection_root(
                &self
                    .fee_sponsorship_selections
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            viewing_key_bundle_root: viewing_key_bundle_collection_root(
                &self
                    .viewing_key_bundles
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            recovery_packet_root: offline_recovery_packet_collection_root(
                &self.recovery_packets.values().cloned().collect::<Vec<_>>(),
            ),
            hardware_signer_policy_root: hardware_signer_policy_collection_root(
                &self
                    .hardware_signer_policies
                    .values()
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            devnet_fixture_root: devnet_fixture_collection_root(
                &self.devnet_fixtures.values().cloned().collect::<Vec<_>>(),
            ),
            public_record_root: wallet_orchestrator_value_collection_root(
                "WALLET-PUBLIC-RECORD-COLLECTION",
                &self.public_records.values().cloned().collect::<Vec<_>>(),
            ),
        }
    }

    pub fn counters(&self) -> WalletOrchestratorCounters {
        WalletOrchestratorCounters {
            height: self.height,
            profile_count: self.profiles.len() as u64,
            active_profile_count: self
                .profiles
                .values()
                .filter(|profile| profile.status == WalletOrchestratorStatus::Active)
                .count() as u64,
            pq_handshake_count: self.pq_handshakes.len() as u64,
            active_pq_handshake_count: self
                .pq_handshakes
                .values()
                .filter(|handshake| handshake.is_active_at(self.height))
                .count() as u64,
            bridge_intent_count: self.bridge_intents.len() as u64,
            deposit_intent_count: self
                .bridge_intents
                .values()
                .filter(|intent| intent.intent_kind == MoneroBridgeIntentKind::Deposit)
                .count() as u64,
            withdrawal_intent_count: self
                .bridge_intents
                .values()
                .filter(|intent| intent.intent_kind == MoneroBridgeIntentKind::Withdrawal)
                .count() as u64,
            pending_bridge_intent_count: self
                .bridge_intents
                .values()
                .filter(|intent| intent.status.is_live())
                .count() as u64,
            private_transfer_count: self.private_transfers.len() as u64,
            pending_private_transfer_count: self
                .private_transfers
                .values()
                .filter(|transfer| transfer.status.is_live())
                .count() as u64,
            private_contract_call_count: self.contract_calls.len() as u64,
            pending_private_contract_call_count: self
                .contract_calls
                .values()
                .filter(|call| call.status.is_live())
                .count() as u64,
            settlement_submission_count: self.settlement_submissions.len() as u64,
            live_settlement_submission_count: self
                .settlement_submissions
                .values()
                .filter(|submission| submission.status.is_live())
                .count() as u64,
            fee_sponsor_candidate_count: self.fee_sponsor_candidates.len() as u64,
            active_fee_sponsor_candidate_count: self
                .fee_sponsor_candidates
                .values()
                .filter(|candidate| candidate.can_sponsor(&candidate.asset_id, 0, self.height))
                .count() as u64,
            fee_sponsorship_selection_count: self.fee_sponsorship_selections.len() as u64,
            viewing_key_bundle_count: self.viewing_key_bundles.len() as u64,
            active_viewing_key_bundle_count: self
                .viewing_key_bundles
                .values()
                .filter(|bundle| bundle.is_active_at(self.height))
                .count() as u64,
            recovery_packet_count: self.recovery_packets.len() as u64,
            active_recovery_packet_count: self
                .recovery_packets
                .values()
                .filter(|packet| packet.status == WalletOrchestratorStatus::Active)
                .count() as u64,
            hardware_signer_policy_count: self.hardware_signer_policies.len() as u64,
            active_hardware_signer_policy_count: self
                .hardware_signer_policies
                .values()
                .filter(|policy| policy.status == WalletOrchestratorStatus::Active)
                .count() as u64,
            devnet_fixture_count: self.devnet_fixtures.len() as u64,
            total_bridge_deposit_units: self
                .bridge_intents
                .values()
                .filter(|intent| intent.intent_kind == MoneroBridgeIntentKind::Deposit)
                .map(|intent| intent.amount)
                .sum(),
            total_bridge_withdrawal_units: self
                .bridge_intents
                .values()
                .filter(|intent| intent.intent_kind == MoneroBridgeIntentKind::Withdrawal)
                .map(|intent| intent.amount)
                .sum(),
            total_private_transfer_units: self
                .private_transfers
                .values()
                .map(|transfer| transfer.amount)
                .sum(),
            total_contract_value_units: self
                .contract_calls
                .values()
                .map(|call| call.value_amount)
                .sum(),
            total_selected_sponsored_fee_units: self
                .fee_sponsorship_selections
                .values()
                .filter(|selection| selection.selected_candidate_id.is_some())
                .map(|selection| selection.requested_fee_units)
                .sum(),
        }
    }

    pub fn state_root(&self) -> String {
        wallet_orchestrator_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("wallet orchestrator public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> WalletOrchestratorResult<String> {
        self.config.validate()?;
        if let Some(active_profile_id) = &self.active_profile_id {
            if !self.profiles.contains_key(active_profile_id) {
                return Err("wallet orchestrator active profile id is unknown".to_string());
            }
        }
        ensure_len_at_most(
            self.profiles.len(),
            self.config.max_profiles,
            "wallet profiles",
        )?;
        ensure_len_at_most(
            self.pq_handshakes.len(),
            self.config.max_handshakes,
            "wallet pq handshakes",
        )?;
        ensure_len_at_most(
            self.bridge_intents.len(),
            self.config.max_bridge_intents,
            "wallet bridge intents",
        )?;
        ensure_len_at_most(
            self.private_transfers.len(),
            self.config.max_private_transfers,
            "wallet private transfers",
        )?;
        ensure_len_at_most(
            self.contract_calls.len(),
            self.config.max_contract_calls,
            "wallet contract calls",
        )?;
        ensure_len_at_most(
            self.settlement_submissions.len(),
            self.config.max_settlement_submissions,
            "wallet settlement submissions",
        )?;
        ensure_len_at_most(
            self.fee_sponsor_candidates.len(),
            self.config.max_fee_sponsor_candidates,
            "wallet fee sponsor candidates",
        )?;
        ensure_len_at_most(
            self.viewing_key_bundles.len(),
            self.config.max_viewing_key_bundles,
            "wallet viewing key bundles",
        )?;
        ensure_len_at_most(
            self.recovery_packets.len(),
            self.config.max_recovery_packets,
            "wallet recovery packets",
        )?;
        ensure_len_at_most(
            self.hardware_signer_policies.len(),
            self.config.max_hardware_policies,
            "wallet hardware signer policies",
        )?;
        ensure_len_at_most(
            self.public_records.len(),
            self.config.max_public_records,
            "wallet public records",
        )?;

        for (profile_id, profile) in &self.profiles {
            profile.validate()?;
            ensure_eq(profile_id, &profile.profile_id, "wallet profile map key")?;
            if let Some(policy_id) = &profile.signer_policy_id {
                if !self.hardware_signer_policies.contains_key(policy_id) {
                    return Err("wallet profile references unknown signer policy".to_string());
                }
            }
        }
        for (handshake_id, handshake) in &self.pq_handshakes {
            handshake.validate()?;
            ensure_eq(
                handshake_id,
                &handshake.handshake_id,
                "wallet pq handshake map key",
            )?;
            self.ensure_profile_exists(&handshake.profile_id, "wallet pq handshake")?;
        }
        for (intent_id, intent) in &self.bridge_intents {
            intent.validate()?;
            ensure_eq(intent_id, &intent.intent_id, "bridge intent map key")?;
            self.ensure_profile_exists(&intent.profile_id, "bridge intent")?;
            if self.config.require_hardware_for_bridge_withdrawals
                && intent.intent_kind == MoneroBridgeIntentKind::Withdrawal
            {
                let profile = self
                    .profiles
                    .get(&intent.profile_id)
                    .ok_or_else(|| "bridge withdrawal profile missing".to_string())?;
                if profile.signer_policy_id.is_none() {
                    return Err(
                        "bridge withdrawal requires hardware signer policy for profile".to_string(),
                    );
                }
            }
        }
        for (transfer_id, transfer) in &self.private_transfers {
            transfer.validate()?;
            ensure_eq(
                transfer_id,
                &transfer.transfer_id,
                "private transfer map key",
            )?;
            self.ensure_profile_exists(&transfer.profile_id, "private transfer")?;
            if let Some(selection_id) = &transfer.sponsor_selection_id {
                self.ensure_selection_exists(selection_id, "private transfer")?;
            }
        }
        for (call_id, call) in &self.contract_calls {
            call.validate()?;
            ensure_eq(call_id, &call.call_id, "private contract call map key")?;
            self.ensure_profile_exists(&call.profile_id, "private contract call")?;
            if let Some(selection_id) = &call.sponsor_selection_id {
                self.ensure_selection_exists(selection_id, "private contract call")?;
            }
            if self.config.require_pq_handshake_for_private_calls {
                let handshake_id = call.pq_handshake_id.as_ref().ok_or_else(|| {
                    "private contract call requires pq handshake id by config".to_string()
                })?;
                let handshake = self.pq_handshakes.get(handshake_id).ok_or_else(|| {
                    "private contract call references unknown pq handshake".to_string()
                })?;
                if handshake.profile_id != call.profile_id {
                    return Err("private contract call pq handshake profile mismatch".to_string());
                }
            }
        }
        for (submission_id, submission) in &self.settlement_submissions {
            submission.validate()?;
            ensure_eq(
                submission_id,
                &submission.submission_id,
                "settlement submission map key",
            )?;
            self.ensure_profile_exists(&submission.profile_id, "settlement submission")?;
            ensure_len_at_most(
                submission.input_roots.len(),
                self.config.max_operation_roots,
                "settlement submission input roots",
            )?;
            self.ensure_operation_exists(
                &submission.operation_kind,
                &submission.operation_id,
                "settlement submission",
            )?;
            if let Some(selection_id) = &submission.fee_selection_id {
                self.ensure_selection_exists(selection_id, "settlement submission")?;
            }
            if let Some(bridge_intent_id) = &submission.bridge_intent_id {
                if !self.bridge_intents.contains_key(bridge_intent_id) {
                    return Err(
                        "settlement submission references unknown bridge intent".to_string()
                    );
                }
            }
        }
        for (candidate_id, candidate) in &self.fee_sponsor_candidates {
            candidate.validate()?;
            ensure_eq(
                candidate_id,
                &candidate.candidate_id,
                "fee sponsor candidate map key",
            )?;
            if candidate.rebate_bps > self.config.max_rebate_bps {
                return Err("fee sponsor candidate rebate exceeds config max".to_string());
            }
        }
        for (selection_id, selection) in &self.fee_sponsorship_selections {
            selection.validate()?;
            ensure_eq(
                selection_id,
                &selection.selection_id,
                "fee sponsorship selection map key",
            )?;
            self.ensure_profile_exists(&selection.profile_id, "fee sponsorship selection")?;
            if let Some(candidate_id) = &selection.selected_candidate_id {
                if !self.fee_sponsor_candidates.contains_key(candidate_id) {
                    return Err(
                        "fee sponsorship selection references unknown candidate".to_string()
                    );
                }
            }
        }
        for (bundle_id, bundle) in &self.viewing_key_bundles {
            bundle.validate()?;
            ensure_eq(bundle_id, &bundle.bundle_id, "viewing key bundle map key")?;
            self.ensure_profile_exists(&bundle.profile_id, "viewing key bundle")?;
        }
        for (packet_id, packet) in &self.recovery_packets {
            packet.validate()?;
            ensure_eq(packet_id, &packet.packet_id, "recovery packet map key")?;
            self.ensure_profile_exists(&packet.profile_id, "recovery packet")?;
        }
        for (policy_id, policy) in &self.hardware_signer_policies {
            policy.validate()?;
            ensure_eq(
                policy_id,
                &policy.policy_id,
                "hardware signer policy map key",
            )?;
            self.ensure_profile_exists(&policy.profile_id, "hardware signer policy")?;
        }
        for (fixture_id, fixture) in &self.devnet_fixtures {
            fixture.validate()?;
            ensure_eq(fixture_id, &fixture.fixture_id, "devnet fixture map key")?;
            self.ensure_profile_exists(&fixture.profile_id, "devnet fixture")?;
            self.ensure_fixture_object_exists(fixture)?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "wallet_orchestrator_state",
            "chain_id": CHAIN_ID,
            "protocol_version": WALLET_ORCHESTRATOR_PROTOCOL_VERSION,
            "height": self.height,
            "active_profile_id": self.active_profile_id,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "roots_root": roots.roots_root(),
            "counters": counters.public_record(),
            "counter_root": counters.counter_root(),
        })
    }

    fn ensure_profile_exists(
        &self,
        profile_id: &str,
        context: &str,
    ) -> WalletOrchestratorResult<()> {
        if self.profiles.contains_key(profile_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown wallet profile"))
        }
    }

    fn ensure_selection_exists(
        &self,
        selection_id: &str,
        context: &str,
    ) -> WalletOrchestratorResult<()> {
        if self.fee_sponsorship_selections.contains_key(selection_id) {
            Ok(())
        } else {
            Err(format!(
                "{context} references unknown fee sponsorship selection"
            ))
        }
    }

    fn ensure_operation_exists(
        &self,
        operation_kind: &PrivateOperationKind,
        operation_id: &str,
        context: &str,
    ) -> WalletOrchestratorResult<()> {
        let exists = match operation_kind {
            PrivateOperationKind::BridgeDeposit | PrivateOperationKind::BridgeWithdrawal => {
                self.bridge_intents.contains_key(operation_id)
            }
            PrivateOperationKind::TokenTransfer => {
                self.private_transfers.contains_key(operation_id)
            }
            PrivateOperationKind::ContractCall => self.contract_calls.contains_key(operation_id),
            PrivateOperationKind::SettlementSubmission => {
                self.settlement_submissions.contains_key(operation_id)
            }
            PrivateOperationKind::Disclosure => self.viewing_key_bundles.contains_key(operation_id),
            PrivateOperationKind::Recovery => self.recovery_packets.contains_key(operation_id),
        };
        if exists {
            Ok(())
        } else {
            Err(format!(
                "{context} references unknown {} operation",
                operation_kind.as_str()
            ))
        }
    }

    fn ensure_fixture_object_exists(
        &self,
        fixture: &DevnetFixtureRecord,
    ) -> WalletOrchestratorResult<()> {
        let exists = match fixture.fixture_kind {
            DevnetFixtureKind::WalletProfile => self.profiles.contains_key(&fixture.object_id),
            DevnetFixtureKind::PqHandshake => self.pq_handshakes.contains_key(&fixture.object_id),
            DevnetFixtureKind::BridgeIntent => self.bridge_intents.contains_key(&fixture.object_id),
            DevnetFixtureKind::PrivateTransfer => {
                self.private_transfers.contains_key(&fixture.object_id)
            }
            DevnetFixtureKind::ContractCall => self.contract_calls.contains_key(&fixture.object_id),
            DevnetFixtureKind::SettlementSubmission => {
                self.settlement_submissions.contains_key(&fixture.object_id)
            }
            DevnetFixtureKind::FeeSponsorCandidate => {
                self.fee_sponsor_candidates.contains_key(&fixture.object_id)
            }
            DevnetFixtureKind::FeeSponsorshipSelection => self
                .fee_sponsorship_selections
                .contains_key(&fixture.object_id),
            DevnetFixtureKind::ViewingKeyBundle => {
                self.viewing_key_bundles.contains_key(&fixture.object_id)
            }
            DevnetFixtureKind::RecoveryPacket => {
                self.recovery_packets.contains_key(&fixture.object_id)
            }
            DevnetFixtureKind::HardwareSignerPolicy => self
                .hardware_signer_policies
                .contains_key(&fixture.object_id),
        };
        if exists {
            Ok(())
        } else {
            Err("devnet fixture references unknown object".to_string())
        }
    }
}

pub fn wallet_orchestrator_state_root_from_record(record: &Value) -> String {
    wallet_orchestrator_payload_root("WALLET-ORCHESTRATOR-STATE", record)
}

pub fn wallet_profile_id(label: &str, profile_kind: &str, account_commitment: &str) -> String {
    domain_hash(
        "WALLET-PROFILE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(profile_kind),
            HashPart::Str(account_commitment),
        ],
        32,
    )
}

pub fn wallet_pq_handshake_id(
    profile_id: &str,
    peer_id: &str,
    purpose: &str,
    transcript_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-PQ-HANDSHAKE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(peer_id),
            HashPart::Str(purpose),
            HashPart::Str(transcript_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn monero_bridge_intent_id(
    profile_id: &str,
    intent_kind: &str,
    address_commitment: &str,
    payment_id_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-MONERO-BRIDGE-INTENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(intent_kind),
            HashPart::Str(address_commitment),
            HashPart::Str(payment_id_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_transfer_id(
    profile_id: &str,
    asset_id: &str,
    recipient_commitment: &str,
    nullifier_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-PRIVATE-TRANSFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(asset_id),
            HashPart::Str(recipient_commitment),
            HashPart::Str(nullifier_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn private_contract_call_id(
    profile_id: &str,
    contract_id: &str,
    method_selector: &str,
    calldata_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-PRIVATE-CONTRACT-CALL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(contract_id),
            HashPart::Str(method_selector),
            HashPart::Str(calldata_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn intent_settlement_submission_id(
    profile_id: &str,
    operation_kind: &str,
    operation_id: &str,
    bundled_intent_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-INTENT-SETTLEMENT-SUBMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(operation_kind),
            HashPart::Str(operation_id),
            HashPart::Str(bundled_intent_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_candidate_id(
    sponsor_id: &str,
    sponsor_kind: &str,
    asset_id: &str,
    lane_id: &str,
    valid_until_height: u64,
) -> String {
    domain_hash(
        "WALLET-FEE-SPONSOR-CANDIDATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(sponsor_id),
            HashPart::Str(sponsor_kind),
            HashPart::Str(asset_id),
            HashPart::Str(lane_id),
            HashPart::Int(valid_until_height as i128),
        ],
        32,
    )
}

pub fn fee_sponsorship_selection_id(
    profile_id: &str,
    operation_kind: &str,
    operation_id: &str,
    asset_id: &str,
    candidate_root: &str,
) -> String {
    domain_hash(
        "WALLET-FEE-SPONSORSHIP-SELECTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(operation_kind),
            HashPart::Str(operation_id),
            HashPart::Str(asset_id),
            HashPart::Str(candidate_root),
        ],
        32,
    )
}

pub fn viewing_key_bundle_id(
    profile_id: &str,
    scope: &str,
    delegated_to_commitment: &str,
    disclosure_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-VIEWING-KEY-BUNDLE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(scope),
            HashPart::Str(delegated_to_commitment),
            HashPart::Str(disclosure_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn offline_recovery_packet_id(
    profile_id: &str,
    recovery_kind: &str,
    recovery_epoch: u64,
    guardian_set_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-OFFLINE-RECOVERY-PACKET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(recovery_kind),
            HashPart::Int(recovery_epoch as i128),
            HashPart::Str(guardian_set_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn hardware_signer_policy_id(
    profile_id: &str,
    signer_kind: &str,
    signer_label_commitment: &str,
    allowed_scope_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "WALLET-HARDWARE-SIGNER-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(profile_id),
            HashPart::Str(signer_kind),
            HashPart::Str(signer_label_commitment),
            HashPart::Str(allowed_scope_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn devnet_fixture_id(
    label: &str,
    fixture_kind: &str,
    profile_id: &str,
    object_id: &str,
) -> String {
    domain_hash(
        "WALLET-DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(fixture_kind),
            HashPart::Str(profile_id),
            HashPart::Str(object_id),
        ],
        32,
    )
}

pub fn wallet_orchestrator_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn wallet_orchestrator_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn wallet_orchestrator_string_collection_root(domain: &str, values: &[String]) -> String {
    merkle_root(
        domain,
        &values
            .iter()
            .map(|value| Value::String(value.clone()))
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_orchestrator_value_collection_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn wallet_profile_collection_root(profiles: &[WalletProfile]) -> String {
    merkle_root(
        "WALLET-PROFILE-COLLECTION",
        &profiles
            .iter()
            .map(WalletProfile::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_pq_handshake_collection_root(handshakes: &[WalletPqSessionHandshake]) -> String {
    merkle_root(
        "WALLET-PQ-HANDSHAKE-COLLECTION",
        &handshakes
            .iter()
            .map(WalletPqSessionHandshake::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn monero_bridge_intent_collection_root(intents: &[MoneroBridgeIntent]) -> String {
    merkle_root(
        "WALLET-MONERO-BRIDGE-INTENT-COLLECTION",
        &intents
            .iter()
            .map(MoneroBridgeIntent::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_transfer_collection_root(transfers: &[PrivateTokenTransfer]) -> String {
    merkle_root(
        "WALLET-PRIVATE-TRANSFER-COLLECTION",
        &transfers
            .iter()
            .map(PrivateTokenTransfer::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_contract_call_collection_root(calls: &[PrivateContractCall]) -> String {
    merkle_root(
        "WALLET-PRIVATE-CONTRACT-CALL-COLLECTION",
        &calls
            .iter()
            .map(PrivateContractCall::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn intent_settlement_submission_collection_root(
    submissions: &[IntentSettlementSubmission],
) -> String {
    merkle_root(
        "WALLET-INTENT-SETTLEMENT-SUBMISSION-COLLECTION",
        &submissions
            .iter()
            .map(IntentSettlementSubmission::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_sponsor_candidate_collection_root(candidates: &[FeeSponsorCandidate]) -> String {
    merkle_root(
        "WALLET-FEE-SPONSOR-CANDIDATE-COLLECTION",
        &candidates
            .iter()
            .map(FeeSponsorCandidate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_sponsorship_selection_collection_root(selections: &[FeeSponsorshipSelection]) -> String {
    merkle_root(
        "WALLET-FEE-SPONSORSHIP-SELECTION-COLLECTION",
        &selections
            .iter()
            .map(FeeSponsorshipSelection::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn viewing_key_bundle_collection_root(bundles: &[ViewingKeyDisclosureBundle]) -> String {
    merkle_root(
        "WALLET-VIEWING-KEY-BUNDLE-COLLECTION",
        &bundles
            .iter()
            .map(ViewingKeyDisclosureBundle::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn offline_recovery_packet_collection_root(packets: &[OfflineRecoveryPacket]) -> String {
    merkle_root(
        "WALLET-OFFLINE-RECOVERY-PACKET-COLLECTION",
        &packets
            .iter()
            .map(OfflineRecoveryPacket::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn hardware_signer_policy_collection_root(policies: &[HardwareSignerPolicy]) -> String {
    merkle_root(
        "WALLET-HARDWARE-SIGNER-POLICY-COLLECTION",
        &policies
            .iter()
            .map(HardwareSignerPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn devnet_fixture_collection_root(fixtures: &[DevnetFixtureRecord]) -> String {
    merkle_root(
        "WALLET-DEVNET-FIXTURE-COLLECTION",
        &fixtures
            .iter()
            .map(DevnetFixtureRecord::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn amount_bucket(amount: u64, bucket_size: u64) -> u64 {
    if bucket_size == 0 {
        amount
    } else {
        amount.div_ceil(bucket_size) * bucket_size
    }
}

fn ensure_non_empty(value: &str, label: &str) -> WalletOrchestratorResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> WalletOrchestratorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> WalletOrchestratorResult<()> {
    if value > WALLET_ORCHESTRATOR_MAX_BPS {
        Err(format!("{label} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_nonzero_usize(value: usize, label: &str) -> WalletOrchestratorResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_len_at_most(value: usize, max: usize, label: &str) -> WalletOrchestratorResult<()> {
    if value > max {
        Err(format!("{label} exceeds configured maximum"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> WalletOrchestratorResult<()> {
    if current >= max {
        Err(format!("{label} reached configured maximum"))
    } else {
        Ok(())
    }
}

fn ensure_eq(left: &str, right: &str, label: &str) -> WalletOrchestratorResult<()> {
    if left == right {
        Ok(())
    } else {
        Err(format!("{label} mismatch"))
    }
}

fn ensure_non_empty_slice<T>(items: &[T], label: &str) -> WalletOrchestratorResult<()> {
    if items.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn ensure_map_absent<T>(
    map: &BTreeMap<String, T>,
    id: &str,
    label: &str,
) -> WalletOrchestratorResult<()> {
    if map.contains_key(id) {
        Err(format!("{label} already exists"))
    } else {
        Ok(())
    }
}

#[allow(dead_code)]
fn ensure_unique_values(values: &[String], label: &str) -> WalletOrchestratorResult<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
