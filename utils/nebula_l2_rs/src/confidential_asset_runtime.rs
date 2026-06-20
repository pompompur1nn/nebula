use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type ConfidentialAssetRuntimeResult<T> = Result<T, String>;

pub const CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-l2-confidential-asset-runtime-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const CONFIDENTIAL_ASSET_RUNTIME_COMMITMENT_SCHEME: &str =
    "devnet-shake256-private-asset-commitment-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME: &str =
    "devnet-ml-kem-sealed-asset-note-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_RANGE_PROOF_SCHEME: &str =
    "devnet-mock-pq-amount-range-proof-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_TRANSFER_PROOF_SCHEME: &str =
    "devnet-confidential-transfer-balance-proof-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_DISCLOSURE_SCHEME: &str =
    "devnet-selective-viewing-disclosure-root-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME: &str =
    "ml-dsa-87-devnet-asset-admin-authorization-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_AMM_HOOK_SCHEME: &str = "devnet-private-amm-asset-hook-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_LENDING_HOOK_SCHEME: &str =
    "devnet-private-lending-collateral-hook-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_LOW_FEE_SCHEME: &str =
    "devnet-private-sponsored-transfer-lane-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_FREEZE_SCHEME: &str =
    "devnet-pq-timelocked-freeze-ceremony-v1";
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_VIEW_GRANT_TTL_BLOCKS: u64 = 2_880;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_SPONSORSHIP_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_FREEZE_DELAY_BLOCKS: u64 = 12;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_TRANSFER_INPUTS: usize = 8;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_TRANSFER_OUTPUTS: usize = 8;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_ACTIVE_FREEZE_CEREMONIES: usize = 16;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_LOW_FEE_UNIT_CAP: u64 = 5_000_000;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_SUPPLY_CAP_UNITS: u64 = 1_000_000_000_000_000;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_RISK_PAUSE_THRESHOLD_BPS: u64 = 8_500;
pub const CONFIDENTIAL_ASSET_RUNTIME_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEVNET_HEIGHT: u64 = 128;
pub const CONFIDENTIAL_ASSET_RUNTIME_DEVNET_LOW_FEE_LANE: &str = "confidential-small-transfer";
pub const CONFIDENTIAL_ASSET_RUNTIME_DEVNET_FEE_ASSET_ID: &str = "dnr-devnet-fee";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAssetKind {
    PrivateFungible,
    PrivateStable,
    PrivateCollateral,
    PrivatePoolShare,
    PrivateReceipt,
    PrivateAdminToken,
}

impl ConfidentialAssetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateFungible => "private_fungible",
            Self::PrivateStable => "private_stable",
            Self::PrivateCollateral => "private_collateral",
            Self::PrivatePoolShare => "private_pool_share",
            Self::PrivateReceipt => "private_receipt",
            Self::PrivateAdminToken => "private_admin_token",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetVisibility {
    CommitmentOnly,
    ViewKeyAuditable,
    RegulatorDisclosable,
    PublicSupplyPrivateBalances,
    PublicMetadataPrivateSupply,
}

impl AssetVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CommitmentOnly => "commitment_only",
            Self::ViewKeyAuditable => "view_key_auditable",
            Self::RegulatorDisclosable => "regulator_disclosable",
            Self::PublicSupplyPrivateBalances => "public_supply_private_balances",
            Self::PublicMetadataPrivateSupply => "public_metadata_private_supply",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClassStatus {
    Pending,
    Active,
    MintPaused,
    TransferPaused,
    Frozen,
    RedemptionsOnly,
    Retired,
}

impl AssetClassStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::MintPaused => "mint_paused",
            Self::TransferPaused => "transfer_paused",
            Self::Frozen => "frozen",
            Self::RedemptionsOnly => "redemptions_only",
            Self::Retired => "retired",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(self, Self::Active | Self::TransferPaused)
    }

    pub fn allows_burn(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::RedemptionsOnly
        )
    }

    pub fn allows_transfer(&self) -> bool {
        matches!(self, Self::Active | Self::MintPaused)
    }

    pub fn counts_as_active(&self) -> bool {
        matches!(
            self,
            Self::Active | Self::MintPaused | Self::TransferPaused | Self::RedemptionsOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShieldedBalanceStatus {
    Pending,
    Spendable,
    Locked,
    Encumbered,
    Frozen,
    Spent,
    Burned,
    Expired,
}

impl ShieldedBalanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Spendable => "spendable",
            Self::Locked => "locked",
            Self::Encumbered => "encumbered",
            Self::Frozen => "frozen",
            Self::Spent => "spent",
            Self::Burned => "burned",
            Self::Expired => "expired",
        }
    }

    pub fn counts_as_open(&self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Spendable | Self::Locked | Self::Encumbered | Self::Frozen
        )
    }

    pub fn spendable(&self) -> bool {
        matches!(self, Self::Spendable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialOperationKind {
    Mint,
    Burn,
}

impl ConfidentialOperationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialOperationStatus {
    Requested,
    Authorized,
    Executed,
    Rejected,
    Expired,
}

impl ConfidentialOperationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Authorized => "authorized",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialTransferStatus {
    Pending,
    Admitted,
    Settled,
    Rejected,
    Expired,
    Frozen,
}

impl ConfidentialTransferStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Admitted => "admitted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Frozen => "frozen",
        }
    }

    pub fn is_live(&self) -> bool {
        matches!(self, Self::Pending | Self::Admitted)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialAmountBucket {
    Dust,
    Small,
    Medium,
    Large,
    Whale,
    Unknown,
}

impl ConfidentialAmountBucket {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dust => "dust",
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Whale => "whale",
            Self::Unknown => "unknown",
        }
    }

    pub fn ceiling_units(&self) -> u64 {
        match self {
            Self::Dust => 100_000,
            Self::Small => 5_000_000,
            Self::Medium => 250_000_000,
            Self::Large => 10_000_000_000,
            Self::Whale => u64::MAX,
            Self::Unknown => u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureScope {
    BalanceBucket,
    TransferTrace,
    MintBurnAudit,
    HolderKyc,
    ComplianceFreeze,
    ProtocolHook,
    FullViewKey,
}

impl DisclosureScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BalanceBucket => "balance_bucket",
            Self::TransferTrace => "transfer_trace",
            Self::MintBurnAudit => "mint_burn_audit",
            Self::HolderKyc => "holder_kyc",
            Self::ComplianceFreeze => "compliance_freeze",
            Self::ProtocolHook => "protocol_hook",
            Self::FullViewKey => "full_view_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureAudience {
    Owner,
    Issuer,
    Auditor,
    Regulator,
    Counterparty,
    Protocol,
}

impl DisclosureAudience {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Issuer => "issuer",
            Self::Auditor => "auditor",
            Self::Regulator => "regulator",
            Self::Counterparty => "counterparty",
            Self::Protocol => "protocol",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureStatus {
    Active,
    Revoked,
    Expired,
    Superseded,
}

impl DisclosureStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAssetAdminAction {
    CreateClass,
    UpdatePolicy,
    Mint,
    Burn,
    RotateIssuer,
    ConfigureAmmHook,
    ConfigureLendingHook,
    SponsorTransfers,
    Freeze,
    Unfreeze,
    Retire,
}

impl PqAssetAdminAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CreateClass => "create_class",
            Self::UpdatePolicy => "update_policy",
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::RotateIssuer => "rotate_issuer",
            Self::ConfigureAmmHook => "configure_amm_hook",
            Self::ConfigureLendingHook => "configure_lending_hook",
            Self::SponsorTransfers => "sponsor_transfers",
            Self::Freeze => "freeze",
            Self::Unfreeze => "unfreeze",
            Self::Retire => "retire",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationDecision {
    Approve,
    Deny,
    Watch,
    EmergencyApprove,
}

impl PqAuthorizationDecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
            Self::Watch => "watch",
            Self::EmergencyApprove => "emergency_approve",
        }
    }

    pub fn permits_execution(&self) -> bool {
        matches!(self, Self::Approve | Self::EmergencyApprove)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqAuthorizationStatus {
    Pending,
    Active,
    Used,
    Revoked,
    Expired,
}

impl PqAuthorizationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Used => "used",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookStatus {
    Pending,
    Active,
    Paused,
    Draining,
    Retired,
}

impl HookStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorshipStatus {
    Pending,
    Active,
    Exhausted,
    Paused,
    Expired,
    Revoked,
}

impl SponsorshipStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Exhausted => "exhausted",
            Self::Paused => "paused",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskControlScope {
    Class,
    Balance,
    Transfer,
    Issuer,
    AmmHook,
    LendingHook,
    Sponsor,
    Global,
}

impl RiskControlScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Balance => "balance",
            Self::Transfer => "transfer",
            Self::Issuer => "issuer",
            Self::AmmHook => "amm_hook",
            Self::LendingHook => "lending_hook",
            Self::Sponsor => "sponsor",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Info,
    Watch,
    Elevated,
    Severe,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Elevated => "elevated",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            Self::Info => 500,
            Self::Watch => 2_000,
            Self::Elevated => 5_000,
            Self::Severe => 8_000,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    Observe,
    RequireDisclosure,
    PauseMint,
    PauseTransfer,
    FreezeSubject,
    RevokeSponsor,
    RetireAsset,
}

impl RiskAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::RequireDisclosure => "require_disclosure",
            Self::PauseMint => "pause_mint",
            Self::PauseTransfer => "pause_transfer",
            Self::FreezeSubject => "freeze_subject",
            Self::RevokeSponsor => "revoke_sponsor",
            Self::RetireAsset => "retire_asset",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskControlStatus {
    Watching,
    Enforced,
    Challenged,
    Resolved,
    Expired,
}

impl RiskControlStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Watching => "watching",
            Self::Enforced => "enforced",
            Self::Challenged => "challenged",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
        }
    }

    pub fn active(&self) -> bool {
        matches!(self, Self::Watching | Self::Enforced | Self::Challenged)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeCeremonyKind {
    ClassFreeze,
    ClassUnfreeze,
    BalanceFreeze,
    BalanceUnfreeze,
    TransferFreeze,
    EmergencyPause,
    RecoveryUnpause,
}

impl FreezeCeremonyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ClassFreeze => "class_freeze",
            Self::ClassUnfreeze => "class_unfreeze",
            Self::BalanceFreeze => "balance_freeze",
            Self::BalanceUnfreeze => "balance_unfreeze",
            Self::TransferFreeze => "transfer_freeze",
            Self::EmergencyPause => "emergency_pause",
            Self::RecoveryUnpause => "recovery_unpause",
        }
    }

    pub fn freezes(&self) -> bool {
        matches!(
            self,
            Self::ClassFreeze | Self::BalanceFreeze | Self::TransferFreeze | Self::EmergencyPause
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeCeremonyStatus {
    Proposed,
    Timelocked,
    Executable,
    Executed,
    Released,
    Cancelled,
    Expired,
}

impl FreezeCeremonyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Timelocked => "timelocked",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Released => "released",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }

    pub fn active(&self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Timelocked | Self::Executable | Self::Executed
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAssetRuntimeConfig {
    pub schema_version: u64,
    pub commitment_scheme: String,
    pub note_encryption_scheme: String,
    pub range_proof_scheme: String,
    pub transfer_proof_scheme: String,
    pub disclosure_scheme: String,
    pub pq_admin_scheme: String,
    pub amm_hook_scheme: String,
    pub lending_hook_scheme: String,
    pub low_fee_scheme: String,
    pub freeze_scheme: String,
    pub max_transfer_inputs: usize,
    pub max_transfer_outputs: usize,
    pub max_active_freeze_ceremonies: usize,
    pub min_pq_security_bits: u16,
    pub default_view_grant_ttl_blocks: u64,
    pub default_sponsorship_ttl_blocks: u64,
    pub default_freeze_delay_blocks: u64,
    pub low_fee_transfer_unit_cap: u64,
    pub default_supply_cap_units: u64,
    pub risk_pause_threshold_bps: u64,
    pub default_low_fee_lane: String,
    pub fee_asset_id: String,
    pub allow_public_metadata: bool,
    pub require_pq_admin_for_supply: bool,
    pub require_disclosure_for_freeze: bool,
}

impl Default for ConfidentialAssetRuntimeConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIDENTIAL_ASSET_RUNTIME_SCHEMA_VERSION,
            commitment_scheme: CONFIDENTIAL_ASSET_RUNTIME_COMMITMENT_SCHEME.to_string(),
            note_encryption_scheme: CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME.to_string(),
            range_proof_scheme: CONFIDENTIAL_ASSET_RUNTIME_RANGE_PROOF_SCHEME.to_string(),
            transfer_proof_scheme: CONFIDENTIAL_ASSET_RUNTIME_TRANSFER_PROOF_SCHEME.to_string(),
            disclosure_scheme: CONFIDENTIAL_ASSET_RUNTIME_DISCLOSURE_SCHEME.to_string(),
            pq_admin_scheme: CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME.to_string(),
            amm_hook_scheme: CONFIDENTIAL_ASSET_RUNTIME_AMM_HOOK_SCHEME.to_string(),
            lending_hook_scheme: CONFIDENTIAL_ASSET_RUNTIME_LENDING_HOOK_SCHEME.to_string(),
            low_fee_scheme: CONFIDENTIAL_ASSET_RUNTIME_LOW_FEE_SCHEME.to_string(),
            freeze_scheme: CONFIDENTIAL_ASSET_RUNTIME_FREEZE_SCHEME.to_string(),
            max_transfer_inputs: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_TRANSFER_INPUTS,
            max_transfer_outputs: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_TRANSFER_OUTPUTS,
            max_active_freeze_ceremonies:
                CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_MAX_ACTIVE_FREEZE_CEREMONIES,
            min_pq_security_bits: CONFIDENTIAL_ASSET_RUNTIME_MIN_PQ_SECURITY_BITS,
            default_view_grant_ttl_blocks: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_VIEW_GRANT_TTL_BLOCKS,
            default_sponsorship_ttl_blocks:
                CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_SPONSORSHIP_TTL_BLOCKS,
            default_freeze_delay_blocks: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_FREEZE_DELAY_BLOCKS,
            low_fee_transfer_unit_cap: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_LOW_FEE_UNIT_CAP,
            default_supply_cap_units: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_SUPPLY_CAP_UNITS,
            risk_pause_threshold_bps: CONFIDENTIAL_ASSET_RUNTIME_DEFAULT_RISK_PAUSE_THRESHOLD_BPS,
            default_low_fee_lane: CONFIDENTIAL_ASSET_RUNTIME_DEVNET_LOW_FEE_LANE.to_string(),
            fee_asset_id: CONFIDENTIAL_ASSET_RUNTIME_DEVNET_FEE_ASSET_ID.to_string(),
            allow_public_metadata: true,
            require_pq_admin_for_supply: true,
            require_disclosure_for_freeze: true,
        }
    }
}

impl ConfidentialAssetRuntimeConfig {
    pub fn devnet() -> Self {
        Self {
            max_transfer_inputs: 6,
            max_transfer_outputs: 8,
            max_active_freeze_ceremonies: 8,
            default_view_grant_ttl_blocks: 720,
            default_sponsorship_ttl_blocks: 360,
            default_freeze_delay_blocks: 6,
            low_fee_transfer_unit_cap: 2_500_000,
            default_supply_cap_units: 25_000_000_000_000,
            risk_pause_threshold_bps: 7_500,
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_asset_runtime_config",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": self.schema_version,
            "commitment_scheme": self.commitment_scheme,
            "note_encryption_scheme": self.note_encryption_scheme,
            "range_proof_scheme": self.range_proof_scheme,
            "transfer_proof_scheme": self.transfer_proof_scheme,
            "disclosure_scheme": self.disclosure_scheme,
            "pq_admin_scheme": self.pq_admin_scheme,
            "amm_hook_scheme": self.amm_hook_scheme,
            "lending_hook_scheme": self.lending_hook_scheme,
            "low_fee_scheme": self.low_fee_scheme,
            "freeze_scheme": self.freeze_scheme,
            "max_transfer_inputs": self.max_transfer_inputs,
            "max_transfer_outputs": self.max_transfer_outputs,
            "max_active_freeze_ceremonies": self.max_active_freeze_ceremonies,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_view_grant_ttl_blocks": self.default_view_grant_ttl_blocks,
            "default_sponsorship_ttl_blocks": self.default_sponsorship_ttl_blocks,
            "default_freeze_delay_blocks": self.default_freeze_delay_blocks,
            "low_fee_transfer_unit_cap": self.low_fee_transfer_unit_cap,
            "default_supply_cap_units": self.default_supply_cap_units,
            "risk_pause_threshold_bps": self.risk_pause_threshold_bps,
            "default_low_fee_lane": self.default_low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "allow_public_metadata": self.allow_public_metadata,
            "require_pq_admin_for_supply": self.require_pq_admin_for_supply,
            "require_disclosure_for_freeze": self.require_disclosure_for_freeze,
        })
    }

    pub fn config_root(&self) -> String {
        confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-RUNTIME-CONFIG",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<()> {
        if self.schema_version != CONFIDENTIAL_ASSET_RUNTIME_SCHEMA_VERSION {
            return Err("confidential asset runtime schema version mismatch".to_string());
        }
        ensure_non_empty(&self.commitment_scheme, "config commitment_scheme")?;
        ensure_non_empty(
            &self.note_encryption_scheme,
            "config note_encryption_scheme",
        )?;
        ensure_non_empty(&self.range_proof_scheme, "config range_proof_scheme")?;
        ensure_non_empty(&self.transfer_proof_scheme, "config transfer_proof_scheme")?;
        ensure_non_empty(&self.disclosure_scheme, "config disclosure_scheme")?;
        ensure_non_empty(&self.pq_admin_scheme, "config pq_admin_scheme")?;
        ensure_non_empty(&self.amm_hook_scheme, "config amm_hook_scheme")?;
        ensure_non_empty(&self.lending_hook_scheme, "config lending_hook_scheme")?;
        ensure_non_empty(&self.low_fee_scheme, "config low_fee_scheme")?;
        ensure_non_empty(&self.freeze_scheme, "config freeze_scheme")?;
        ensure_non_empty(&self.default_low_fee_lane, "config default_low_fee_lane")?;
        ensure_non_empty(&self.fee_asset_id, "config fee_asset_id")?;
        if self.max_transfer_inputs == 0 || self.max_transfer_outputs == 0 {
            return Err("config transfer fan-in/fan-out must be non-zero".to_string());
        }
        if self.min_pq_security_bits < CONFIDENTIAL_ASSET_RUNTIME_MIN_PQ_SECURITY_BITS {
            return Err("config min_pq_security_bits below runtime floor".to_string());
        }
        validate_bps(
            "config risk_pause_threshold_bps",
            self.risk_pause_threshold_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if self.low_fee_transfer_unit_cap == 0 {
            return Err("config low_fee_transfer_unit_cap must be non-zero".to_string());
        }
        if self.default_supply_cap_units == 0 {
            return Err("config default_supply_cap_units must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTokenClass {
    pub class_id: String,
    pub symbol_commitment: String,
    pub display_name_commitment: String,
    pub metadata_root: String,
    pub issuer_commitment: String,
    pub admin_policy_root: String,
    pub asset_kind: ConfidentialAssetKind,
    pub visibility: AssetVisibility,
    pub status: AssetClassStatus,
    pub decimals: u8,
    pub supply_cap_units: u64,
    pub total_minted_upper_bound_units: u64,
    pub total_burned_upper_bound_units: u64,
    pub shielded_supply_commitment: String,
    pub mint_authorization_root: String,
    pub burn_authorization_root: String,
    pub transfer_policy_root: String,
    pub disclosure_policy_root: String,
    pub risk_control_root: String,
    pub freeze_policy_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ConfidentialTokenClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: impl Into<String>,
        display_name: impl Into<String>,
        issuer_label: impl Into<String>,
        asset_kind: ConfidentialAssetKind,
        visibility: AssetVisibility,
        decimals: u8,
        supply_cap_units: u64,
        metadata: &Value,
        admin_policy: &Value,
        transfer_policy: &Value,
        disclosure_policy: &Value,
        freeze_policy: &Value,
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let symbol = normalize_label(symbol.into());
        let display_name = display_name.into();
        let issuer_label = issuer_label.into();
        ensure_non_empty(&symbol, "token class symbol")?;
        ensure_non_empty(&display_name, "token class display_name")?;
        ensure_non_empty(&issuer_label, "token class issuer")?;
        if decimals > 18 {
            return Err("token class decimals exceed 18".to_string());
        }
        if supply_cap_units == 0 {
            return Err("token class supply cap must be non-zero".to_string());
        }
        let symbol_commitment =
            confidential_asset_runtime_string_root("CONFIDENTIAL-ASSET-SYMBOL", &symbol);
        let display_name_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-DISPLAY-NAME",
            &display_name,
        );
        let metadata_root =
            confidential_asset_runtime_payload_root("CONFIDENTIAL-ASSET-METADATA", metadata);
        let issuer_commitment = confidential_asset_runtime_account_commitment(&issuer_label);
        let admin_policy_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-ADMIN-POLICY",
            admin_policy,
        );
        let transfer_policy_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-TRANSFER-POLICY",
            transfer_policy,
        );
        let disclosure_policy_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-DISCLOSURE-POLICY",
            disclosure_policy,
        );
        let freeze_policy_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-POLICY",
            freeze_policy,
        );
        let class_id = confidential_asset_runtime_token_class_id(
            &symbol_commitment,
            &issuer_commitment,
            &metadata_root,
            nonce,
        );
        let shielded_supply_commitment =
            confidential_asset_runtime_amount_commitment("shielded_supply", 0, &class_id);
        let token_class = Self {
            class_id,
            symbol_commitment,
            display_name_commitment,
            metadata_root,
            issuer_commitment,
            admin_policy_root,
            asset_kind,
            visibility,
            status: AssetClassStatus::Pending,
            decimals,
            supply_cap_units,
            total_minted_upper_bound_units: 0,
            total_burned_upper_bound_units: 0,
            shielded_supply_commitment,
            mint_authorization_root: confidential_asset_runtime_empty_root(
                "CONFIDENTIAL-ASSET-EMPTY-MINT-AUTH",
            ),
            burn_authorization_root: confidential_asset_runtime_empty_root(
                "CONFIDENTIAL-ASSET-EMPTY-BURN-AUTH",
            ),
            transfer_policy_root,
            disclosure_policy_root,
            risk_control_root: confidential_asset_runtime_empty_root(
                "CONFIDENTIAL-ASSET-EMPTY-RISK-CONTROL",
            ),
            freeze_policy_root,
            created_at_height,
            updated_at_height: created_at_height,
        };
        token_class.validate()?;
        Ok(token_class)
    }

    pub fn activate(&mut self, height: u64) {
        self.status = AssetClassStatus::Active;
        self.updated_at_height = height;
    }

    pub fn set_status(&mut self, status: AssetClassStatus, height: u64) {
        self.status = status;
        self.updated_at_height = height;
    }

    pub fn update_supply_commitment(
        &mut self,
        minted_upper_bound_units: u64,
        burned_upper_bound_units: u64,
        blinding: &str,
        height: u64,
    ) -> ConfidentialAssetRuntimeResult<()> {
        if burned_upper_bound_units > minted_upper_bound_units {
            return Err("token class burned supply exceeds minted supply".to_string());
        }
        if minted_upper_bound_units > self.supply_cap_units {
            return Err("token class minted supply exceeds cap".to_string());
        }
        self.total_minted_upper_bound_units = minted_upper_bound_units;
        self.total_burned_upper_bound_units = burned_upper_bound_units;
        self.shielded_supply_commitment = confidential_asset_runtime_amount_commitment(
            "shielded_supply",
            self.circulating_upper_bound_units(),
            blinding,
        );
        self.updated_at_height = height;
        Ok(())
    }

    pub fn circulating_upper_bound_units(&self) -> u64 {
        self.total_minted_upper_bound_units
            .saturating_sub(self.total_burned_upper_bound_units)
    }

    pub fn available_supply_upper_bound_units(&self) -> u64 {
        self.supply_cap_units
            .saturating_sub(self.total_minted_upper_bound_units)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_class",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "class_id": self.class_id,
            "symbol_commitment": self.symbol_commitment,
            "display_name_commitment": self.display_name_commitment,
            "metadata_root": self.metadata_root,
            "issuer_commitment": self.issuer_commitment,
            "admin_policy_root": self.admin_policy_root,
            "asset_kind": self.asset_kind.as_str(),
            "visibility": self.visibility.as_str(),
            "status": self.status.as_str(),
            "decimals": self.decimals,
            "supply_cap_units": self.supply_cap_units,
            "total_minted_upper_bound_units": self.total_minted_upper_bound_units,
            "total_burned_upper_bound_units": self.total_burned_upper_bound_units,
            "circulating_upper_bound_units": self.circulating_upper_bound_units(),
            "available_supply_upper_bound_units": self.available_supply_upper_bound_units(),
            "shielded_supply_commitment": self.shielded_supply_commitment,
            "mint_authorization_root": self.mint_authorization_root,
            "burn_authorization_root": self.burn_authorization_root,
            "transfer_policy_root": self.transfer_policy_root,
            "disclosure_policy_root": self.disclosure_policy_root,
            "risk_control_root": self.risk_control_root,
            "freeze_policy_root": self.freeze_policy_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.class_id, "token class id")?;
        ensure_non_empty(&self.symbol_commitment, "token class symbol commitment")?;
        ensure_non_empty(
            &self.display_name_commitment,
            "token class display name commitment",
        )?;
        ensure_non_empty(&self.metadata_root, "token class metadata root")?;
        ensure_non_empty(&self.issuer_commitment, "token class issuer commitment")?;
        ensure_non_empty(&self.admin_policy_root, "token class admin policy root")?;
        ensure_non_empty(
            &self.shielded_supply_commitment,
            "token class supply commitment",
        )?;
        ensure_non_empty(
            &self.mint_authorization_root,
            "token class mint authorization root",
        )?;
        ensure_non_empty(
            &self.burn_authorization_root,
            "token class burn authorization root",
        )?;
        ensure_non_empty(
            &self.transfer_policy_root,
            "token class transfer policy root",
        )?;
        ensure_non_empty(
            &self.disclosure_policy_root,
            "token class disclosure policy root",
        )?;
        ensure_non_empty(&self.risk_control_root, "token class risk root")?;
        ensure_non_empty(&self.freeze_policy_root, "token class freeze policy root")?;
        if self.decimals > 18 {
            return Err("token class decimals exceed 18".to_string());
        }
        if self.supply_cap_units == 0 {
            return Err("token class supply cap must be non-zero".to_string());
        }
        if self.total_burned_upper_bound_units > self.total_minted_upper_bound_units {
            return Err("token class burned units exceed minted units".to_string());
        }
        if self.total_minted_upper_bound_units > self.supply_cap_units {
            return Err("token class minted units exceed cap".to_string());
        }
        if self.updated_at_height < self.created_at_height {
            return Err("token class updated height before created height".to_string());
        }
        Ok(self.class_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAssetBalance {
    pub balance_id: String,
    pub class_id: String,
    pub owner_commitment: String,
    pub view_tag_root: String,
    pub balance_commitment: String,
    pub amount_lower_bound_units: u64,
    pub amount_upper_bound_units: u64,
    pub lock_root: String,
    pub note_ciphertext_root: String,
    pub nullifier_root: String,
    pub disclosure_policy_id: String,
    pub status: ShieldedBalanceStatus,
    pub created_at_height: u64,
    pub last_updated_height: u64,
    pub unlock_height: u64,
}

impl ShieldedAssetBalance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        owner_label: impl Into<String>,
        amount_lower_bound_units: u64,
        amount_upper_bound_units: u64,
        blinding: impl Into<String>,
        view_tags: &[String],
        lock_payload: &Value,
        note_payload: &Value,
        disclosure_policy_id: impl Into<String>,
        created_at_height: u64,
        unlock_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let owner_label = owner_label.into();
        let blinding = blinding.into();
        let disclosure_policy_id = disclosure_policy_id.into();
        ensure_non_empty(&class_id, "shielded balance class_id")?;
        ensure_non_empty(&owner_label, "shielded balance owner")?;
        ensure_non_empty(&blinding, "shielded balance blinding")?;
        if amount_lower_bound_units > amount_upper_bound_units {
            return Err("shielded balance lower bound exceeds upper bound".to_string());
        }
        let owner_commitment = confidential_asset_runtime_account_commitment(&owner_label);
        let view_tag_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-BALANCE-VIEW-TAG",
            view_tags,
        );
        let balance_commitment = confidential_asset_runtime_amount_commitment(
            "shielded_balance",
            amount_upper_bound_units,
            &blinding,
        );
        let lock_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-BALANCE-LOCK",
            lock_payload,
        );
        let note_ciphertext_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-BALANCE-NOTE",
            note_payload,
        );
        let nullifier_root = confidential_asset_runtime_balance_nullifier_root(
            &class_id,
            &owner_commitment,
            &balance_commitment,
            nonce,
        );
        let balance_id = confidential_asset_runtime_balance_id(
            &class_id,
            &owner_commitment,
            &balance_commitment,
            nonce,
        );
        let balance = Self {
            balance_id,
            class_id,
            owner_commitment,
            view_tag_root,
            balance_commitment,
            amount_lower_bound_units,
            amount_upper_bound_units,
            lock_root,
            note_ciphertext_root,
            nullifier_root,
            disclosure_policy_id,
            status: ShieldedBalanceStatus::Spendable,
            created_at_height,
            last_updated_height: created_at_height,
            unlock_height,
        };
        balance.validate()?;
        Ok(balance)
    }

    pub fn spendable_at(&self, height: u64) -> bool {
        self.status.spendable() && height >= self.unlock_height
    }

    pub fn lock(&mut self, lock_root: impl Into<String>, height: u64) {
        self.lock_root = lock_root.into();
        self.status = ShieldedBalanceStatus::Locked;
        self.last_updated_height = height;
    }

    pub fn freeze(&mut self, height: u64) {
        self.status = ShieldedBalanceStatus::Frozen;
        self.last_updated_height = height;
    }

    pub fn unfreeze(&mut self, height: u64) {
        self.status = ShieldedBalanceStatus::Spendable;
        self.last_updated_height = height;
    }

    pub fn mark_spent(&mut self, height: u64) {
        self.status = ShieldedBalanceStatus::Spent;
        self.last_updated_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_asset_balance",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "balance_id": self.balance_id,
            "class_id": self.class_id,
            "owner_commitment": self.owner_commitment,
            "view_tag_root": self.view_tag_root,
            "balance_commitment": self.balance_commitment,
            "amount_lower_bound_units": self.amount_lower_bound_units,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "lock_root": self.lock_root,
            "note_ciphertext_root": self.note_ciphertext_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_policy_id": self.disclosure_policy_id,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "last_updated_height": self.last_updated_height,
            "unlock_height": self.unlock_height,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.balance_id, "shielded balance id")?;
        ensure_non_empty(&self.class_id, "shielded balance class id")?;
        ensure_non_empty(&self.owner_commitment, "shielded balance owner commitment")?;
        ensure_non_empty(&self.view_tag_root, "shielded balance view tag root")?;
        ensure_non_empty(&self.balance_commitment, "shielded balance commitment")?;
        ensure_non_empty(&self.lock_root, "shielded balance lock root")?;
        ensure_non_empty(&self.note_ciphertext_root, "shielded balance note root")?;
        ensure_non_empty(&self.nullifier_root, "shielded balance nullifier root")?;
        if self.amount_lower_bound_units > self.amount_upper_bound_units {
            return Err("shielded balance lower bound exceeds upper bound".to_string());
        }
        if self.last_updated_height < self.created_at_height {
            return Err("shielded balance updated height before created height".to_string());
        }
        Ok(self.balance_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialMintBurn {
    pub operation_id: String,
    pub class_id: String,
    pub balance_id: String,
    pub kind: ConfidentialOperationKind,
    pub admin_authorization_id: String,
    pub operator_commitment: String,
    pub amount_commitment: String,
    pub amount_upper_bound_units: u64,
    pub supply_before_commitment: String,
    pub supply_after_commitment: String,
    pub supply_before_upper_bound_units: u64,
    pub supply_after_upper_bound_units: u64,
    pub proof_root: String,
    pub range_proof_root: String,
    pub disclosure_root: String,
    pub pq_signature_root: String,
    pub status: ConfidentialOperationStatus,
    pub requested_at_height: u64,
    pub executed_at_height: Option<u64>,
    pub nonce: u64,
}

impl ConfidentialMintBurn {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        balance_id: impl Into<String>,
        kind: ConfidentialOperationKind,
        admin_authorization_id: impl Into<String>,
        operator_label: impl Into<String>,
        amount_upper_bound_units: u64,
        blinding: impl Into<String>,
        supply_before_upper_bound_units: u64,
        supply_after_upper_bound_units: u64,
        proof_payload: &Value,
        disclosure_payload: &Value,
        pq_signature_payload: &Value,
        requested_at_height: u64,
        executed_at_height: Option<u64>,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let balance_id = balance_id.into();
        let admin_authorization_id = admin_authorization_id.into();
        let operator_label = operator_label.into();
        let blinding = blinding.into();
        ensure_non_empty(&class_id, "mint burn class_id")?;
        ensure_non_empty(&balance_id, "mint burn balance_id")?;
        ensure_non_empty(&operator_label, "mint burn operator")?;
        ensure_non_empty(&blinding, "mint burn blinding")?;
        if amount_upper_bound_units == 0 {
            return Err("mint burn amount must be non-zero".to_string());
        }
        match kind {
            ConfidentialOperationKind::Mint => {
                if supply_after_upper_bound_units < supply_before_upper_bound_units {
                    return Err("mint supply after is below supply before".to_string());
                }
                if supply_after_upper_bound_units.saturating_sub(supply_before_upper_bound_units)
                    < amount_upper_bound_units
                {
                    return Err("mint supply delta below amount upper bound".to_string());
                }
            }
            ConfidentialOperationKind::Burn => {
                if supply_before_upper_bound_units < supply_after_upper_bound_units {
                    return Err("burn supply after exceeds supply before".to_string());
                }
                if supply_before_upper_bound_units.saturating_sub(supply_after_upper_bound_units)
                    < amount_upper_bound_units
                {
                    return Err("burn supply delta below amount upper bound".to_string());
                }
            }
        }
        let operator_commitment = confidential_asset_runtime_account_commitment(&operator_label);
        let amount_commitment = confidential_asset_runtime_amount_commitment(
            kind.as_str(),
            amount_upper_bound_units,
            &blinding,
        );
        let supply_before_commitment = confidential_asset_runtime_amount_commitment(
            "supply_before",
            supply_before_upper_bound_units,
            &blinding,
        );
        let supply_after_commitment = confidential_asset_runtime_amount_commitment(
            "supply_after",
            supply_after_upper_bound_units,
            &blinding,
        );
        let proof_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-MINT-BURN-PROOF",
            proof_payload,
        );
        let range_proof_root = confidential_asset_runtime_range_proof_root(
            &amount_commitment,
            amount_upper_bound_units,
            &proof_root,
        );
        let disclosure_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-MINT-BURN-DISCLOSURE",
            disclosure_payload,
        );
        let pq_signature_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-MINT-BURN-PQ-SIGNATURE",
            pq_signature_payload,
        );
        let operation_id = confidential_asset_runtime_mint_burn_id(
            &class_id,
            &balance_id,
            kind,
            &amount_commitment,
            nonce,
        );
        let status = if executed_at_height.is_some() {
            ConfidentialOperationStatus::Executed
        } else if admin_authorization_id.is_empty() {
            ConfidentialOperationStatus::Requested
        } else {
            ConfidentialOperationStatus::Authorized
        };
        let operation = Self {
            operation_id,
            class_id,
            balance_id,
            kind,
            admin_authorization_id,
            operator_commitment,
            amount_commitment,
            amount_upper_bound_units,
            supply_before_commitment,
            supply_after_commitment,
            supply_before_upper_bound_units,
            supply_after_upper_bound_units,
            proof_root,
            range_proof_root,
            disclosure_root,
            pq_signature_root,
            status,
            requested_at_height,
            executed_at_height,
            nonce,
        };
        operation.validate()?;
        Ok(operation)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_mint_burn",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "operation_id": self.operation_id,
            "class_id": self.class_id,
            "balance_id": self.balance_id,
            "operation_kind": self.kind.as_str(),
            "admin_authorization_id": self.admin_authorization_id,
            "operator_commitment": self.operator_commitment,
            "amount_commitment": self.amount_commitment,
            "amount_upper_bound_units": self.amount_upper_bound_units,
            "supply_before_commitment": self.supply_before_commitment,
            "supply_after_commitment": self.supply_after_commitment,
            "supply_before_upper_bound_units": self.supply_before_upper_bound_units,
            "supply_after_upper_bound_units": self.supply_after_upper_bound_units,
            "proof_root": self.proof_root,
            "range_proof_root": self.range_proof_root,
            "disclosure_root": self.disclosure_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "requested_at_height": self.requested_at_height,
            "executed_at_height": self.executed_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.operation_id, "mint burn id")?;
        ensure_non_empty(&self.class_id, "mint burn class id")?;
        ensure_non_empty(&self.balance_id, "mint burn balance id")?;
        ensure_non_empty(&self.operator_commitment, "mint burn operator commitment")?;
        ensure_non_empty(&self.amount_commitment, "mint burn amount commitment")?;
        ensure_non_empty(
            &self.supply_before_commitment,
            "mint burn supply before commitment",
        )?;
        ensure_non_empty(
            &self.supply_after_commitment,
            "mint burn supply after commitment",
        )?;
        ensure_non_empty(&self.proof_root, "mint burn proof root")?;
        ensure_non_empty(&self.range_proof_root, "mint burn range proof root")?;
        ensure_non_empty(&self.disclosure_root, "mint burn disclosure root")?;
        ensure_non_empty(&self.pq_signature_root, "mint burn pq signature root")?;
        if self.amount_upper_bound_units == 0 {
            return Err("mint burn amount must be non-zero".to_string());
        }
        match self.kind {
            ConfidentialOperationKind::Mint => {
                if self.supply_after_upper_bound_units < self.supply_before_upper_bound_units {
                    return Err("mint supply after is below before".to_string());
                }
            }
            ConfidentialOperationKind::Burn => {
                if self.supply_before_upper_bound_units < self.supply_after_upper_bound_units {
                    return Err("burn supply after exceeds before".to_string());
                }
            }
        }
        if let Some(executed_at_height) = self.executed_at_height {
            if executed_at_height < self.requested_at_height {
                return Err("mint burn executed before requested".to_string());
            }
        }
        Ok(self.operation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialTransferNote {
    pub transfer_id: String,
    pub class_id: String,
    pub input_balance_ids: Vec<String>,
    pub output_balance_ids: Vec<String>,
    pub input_nullifier_root: String,
    pub output_commitment_root: String,
    pub fee_commitment: String,
    pub fee_upper_bound_units: u64,
    pub change_commitment: String,
    pub sender_commitment: String,
    pub recipient_commitment_root: String,
    pub amount_bucket: ConfidentialAmountBucket,
    pub memo_ciphertext_root: String,
    pub proof_root: String,
    pub compliance_root: String,
    pub sponsor_id: String,
    pub status: ConfidentialTransferStatus,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub settled_at_height: Option<u64>,
    pub nonce: u64,
}

impl ConfidentialTransferNote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        input_balance_ids: Vec<String>,
        output_balance_ids: Vec<String>,
        sender_label: impl Into<String>,
        recipient_labels: &[String],
        amount_bucket: ConfidentialAmountBucket,
        fee_upper_bound_units: u64,
        fee_blinding: impl Into<String>,
        change_blinding: impl Into<String>,
        memo_payload: &Value,
        compliance_payload: &Value,
        sponsor_id: impl Into<String>,
        created_at_height: u64,
        expires_at_height: u64,
        settled_at_height: Option<u64>,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let sender_label = sender_label.into();
        let fee_blinding = fee_blinding.into();
        let change_blinding = change_blinding.into();
        let sponsor_id = sponsor_id.into();
        ensure_non_empty(&class_id, "transfer class_id")?;
        ensure_non_empty(&sender_label, "transfer sender")?;
        ensure_non_empty(&fee_blinding, "transfer fee blinding")?;
        ensure_non_empty(&change_blinding, "transfer change blinding")?;
        if input_balance_ids.is_empty() {
            return Err("transfer requires at least one input balance".to_string());
        }
        if output_balance_ids.is_empty() {
            return Err("transfer requires at least one output balance".to_string());
        }
        if expires_at_height <= created_at_height {
            return Err("transfer expiry must be after creation height".to_string());
        }
        let sender_commitment = confidential_asset_runtime_account_commitment(&sender_label);
        let input_nullifier_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-TRANSFER-INPUT-NULLIFIER",
            &input_balance_ids,
        );
        let output_commitment_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-TRANSFER-OUTPUT",
            &output_balance_ids,
        );
        let recipient_commitments = recipient_labels
            .iter()
            .map(|label| confidential_asset_runtime_account_commitment(label))
            .collect::<Vec<_>>();
        let recipient_commitment_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-TRANSFER-RECIPIENT",
            &recipient_commitments,
        );
        let fee_commitment = confidential_asset_runtime_amount_commitment(
            "transfer_fee",
            fee_upper_bound_units,
            &fee_blinding,
        );
        let change_commitment = confidential_asset_runtime_amount_commitment(
            "transfer_change",
            amount_bucket.ceiling_units(),
            &change_blinding,
        );
        let memo_ciphertext_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-TRANSFER-MEMO",
            memo_payload,
        );
        let compliance_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-TRANSFER-COMPLIANCE",
            compliance_payload,
        );
        let proof_record = json!({
            "class_id": class_id,
            "input_nullifier_root": input_nullifier_root,
            "output_commitment_root": output_commitment_root,
            "fee_commitment": fee_commitment,
            "change_commitment": change_commitment,
            "amount_bucket": amount_bucket.as_str(),
            "compliance_root": compliance_root,
        });
        let proof_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-TRANSFER-PROOF",
            &proof_record,
        );
        let transfer_id = confidential_asset_runtime_transfer_id(
            &class_id,
            &input_nullifier_root,
            &output_commitment_root,
            &fee_commitment,
            nonce,
        );
        let status = if settled_at_height.is_some() {
            ConfidentialTransferStatus::Settled
        } else {
            ConfidentialTransferStatus::Pending
        };
        let transfer = Self {
            transfer_id,
            class_id,
            input_balance_ids,
            output_balance_ids,
            input_nullifier_root,
            output_commitment_root,
            fee_commitment,
            fee_upper_bound_units,
            change_commitment,
            sender_commitment,
            recipient_commitment_root,
            amount_bucket,
            memo_ciphertext_root,
            proof_root,
            compliance_root,
            sponsor_id,
            status,
            created_at_height,
            expires_at_height,
            settled_at_height,
            nonce,
        };
        transfer.validate()?;
        Ok(transfer)
    }

    pub fn is_live_at(&self, height: u64) -> bool {
        self.status.is_live() && height < self.expires_at_height
    }

    pub fn settle(&mut self, height: u64) -> ConfidentialAssetRuntimeResult<()> {
        if height < self.created_at_height {
            return Err("transfer settlement before creation".to_string());
        }
        if height > self.expires_at_height {
            return Err("transfer settlement after expiry".to_string());
        }
        self.status = ConfidentialTransferStatus::Settled;
        self.settled_at_height = Some(height);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_transfer_note",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "transfer_id": self.transfer_id,
            "class_id": self.class_id,
            "input_balance_ids": self.input_balance_ids,
            "output_balance_ids": self.output_balance_ids,
            "input_nullifier_root": self.input_nullifier_root,
            "output_commitment_root": self.output_commitment_root,
            "fee_commitment": self.fee_commitment,
            "fee_upper_bound_units": self.fee_upper_bound_units,
            "change_commitment": self.change_commitment,
            "sender_commitment": self.sender_commitment,
            "recipient_commitment_root": self.recipient_commitment_root,
            "amount_bucket": self.amount_bucket.as_str(),
            "memo_ciphertext_root": self.memo_ciphertext_root,
            "proof_root": self.proof_root,
            "compliance_root": self.compliance_root,
            "sponsor_id": self.sponsor_id,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "settled_at_height": self.settled_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.transfer_id, "transfer id")?;
        ensure_non_empty(&self.class_id, "transfer class id")?;
        ensure_non_empty(&self.input_nullifier_root, "transfer input nullifier root")?;
        ensure_non_empty(&self.output_commitment_root, "transfer output root")?;
        ensure_non_empty(&self.fee_commitment, "transfer fee commitment")?;
        ensure_non_empty(&self.change_commitment, "transfer change commitment")?;
        ensure_non_empty(&self.sender_commitment, "transfer sender commitment")?;
        ensure_non_empty(
            &self.recipient_commitment_root,
            "transfer recipient commitment root",
        )?;
        ensure_non_empty(&self.memo_ciphertext_root, "transfer memo root")?;
        ensure_non_empty(&self.proof_root, "transfer proof root")?;
        ensure_non_empty(&self.compliance_root, "transfer compliance root")?;
        if self.input_balance_ids.is_empty() {
            return Err("transfer input set is empty".to_string());
        }
        if self.output_balance_ids.is_empty() {
            return Err("transfer output set is empty".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("transfer expiry must be after creation".to_string());
        }
        if let Some(settled_at_height) = self.settled_at_height {
            if settled_at_height < self.created_at_height {
                return Err("transfer settled before creation".to_string());
            }
            if settled_at_height > self.expires_at_height {
                return Err("transfer settled after expiry".to_string());
            }
        }
        Ok(self.transfer_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceViewingDisclosure {
    pub disclosure_id: String,
    pub class_id: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub scope: DisclosureScope,
    pub audience: DisclosureAudience,
    pub viewer_commitment: String,
    pub view_key_commitment: String,
    pub disclosed_field_root: String,
    pub disclosure_payload_root: String,
    pub redaction_root: String,
    pub legal_basis_root: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub revoked_at_height: Option<u64>,
    pub status: DisclosureStatus,
}

impl ComplianceViewingDisclosure {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        scope: DisclosureScope,
        audience: DisclosureAudience,
        viewer_label: impl Into<String>,
        view_key_label: impl Into<String>,
        disclosed_fields: &[String],
        disclosure_payload: &Value,
        redaction_payload: &Value,
        legal_basis_payload: &Value,
        created_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let subject_kind = normalize_label(subject_kind.into());
        let subject_id = subject_id.into();
        let viewer_label = viewer_label.into();
        let view_key_label = view_key_label.into();
        ensure_non_empty(&class_id, "disclosure class_id")?;
        ensure_non_empty(&subject_kind, "disclosure subject_kind")?;
        ensure_non_empty(&subject_id, "disclosure subject_id")?;
        ensure_non_empty(&viewer_label, "disclosure viewer")?;
        ensure_non_empty(&view_key_label, "disclosure view key")?;
        if expires_at_height <= created_at_height {
            return Err("disclosure expiry must be after creation".to_string());
        }
        let viewer_commitment = confidential_asset_runtime_account_commitment(&viewer_label);
        let view_key_commitment =
            confidential_asset_runtime_string_root("CONFIDENTIAL-ASSET-VIEW-KEY", &view_key_label);
        let disclosed_field_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-DISCLOSED-FIELD",
            disclosed_fields,
        );
        let disclosure_payload_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-DISCLOSURE-PAYLOAD",
            disclosure_payload,
        );
        let redaction_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-DISCLOSURE-REDACTION",
            redaction_payload,
        );
        let legal_basis_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-DISCLOSURE-LEGAL-BASIS",
            legal_basis_payload,
        );
        let disclosure_id = confidential_asset_runtime_disclosure_id(
            &class_id,
            &subject_kind,
            &subject_id,
            scope,
            &viewer_commitment,
            nonce,
        );
        let disclosure = Self {
            disclosure_id,
            class_id,
            subject_kind,
            subject_id,
            scope,
            audience,
            viewer_commitment,
            view_key_commitment,
            disclosed_field_root,
            disclosure_payload_root,
            redaction_root,
            legal_basis_root,
            created_at_height,
            expires_at_height,
            revoked_at_height: None,
            status: DisclosureStatus::Active,
        };
        disclosure.validate()?;
        Ok(disclosure)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active() && self.created_at_height <= height && height < self.expires_at_height
    }

    pub fn revoke(&mut self, height: u64) -> ConfidentialAssetRuntimeResult<()> {
        if height < self.created_at_height {
            return Err("disclosure revocation before creation".to_string());
        }
        self.status = DisclosureStatus::Revoked;
        self.revoked_at_height = Some(height);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_viewing_disclosure",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "disclosure_id": self.disclosure_id,
            "class_id": self.class_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "scope": self.scope.as_str(),
            "audience": self.audience.as_str(),
            "viewer_commitment": self.viewer_commitment,
            "view_key_commitment": self.view_key_commitment,
            "disclosed_field_root": self.disclosed_field_root,
            "disclosure_payload_root": self.disclosure_payload_root,
            "redaction_root": self.redaction_root,
            "legal_basis_root": self.legal_basis_root,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "revoked_at_height": self.revoked_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.disclosure_id, "disclosure id")?;
        ensure_non_empty(&self.class_id, "disclosure class id")?;
        ensure_non_empty(&self.subject_kind, "disclosure subject kind")?;
        ensure_non_empty(&self.subject_id, "disclosure subject id")?;
        ensure_non_empty(&self.viewer_commitment, "disclosure viewer commitment")?;
        ensure_non_empty(&self.view_key_commitment, "disclosure view key commitment")?;
        ensure_non_empty(&self.disclosed_field_root, "disclosure field root")?;
        ensure_non_empty(&self.disclosure_payload_root, "disclosure payload root")?;
        ensure_non_empty(&self.redaction_root, "disclosure redaction root")?;
        ensure_non_empty(&self.legal_basis_root, "disclosure legal basis root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("disclosure expiry must be after creation".to_string());
        }
        if let Some(revoked_at_height) = self.revoked_at_height {
            if revoked_at_height < self.created_at_height {
                return Err("disclosure revoked before creation".to_string());
            }
        }
        Ok(self.disclosure_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqAssetAdminAuthorization {
    pub authorization_id: String,
    pub class_id: String,
    pub action: PqAssetAdminAction,
    pub subject_kind: String,
    pub subject_id: String,
    pub admin_commitment: String,
    pub signer_set_root: String,
    pub public_key_root: String,
    pub payload_root: String,
    pub attestation_root: String,
    pub pq_signature_root: String,
    pub decision: PqAuthorizationDecision,
    pub status: PqAuthorizationStatus,
    pub security_bits: u16,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl PqAssetAdminAuthorization {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        action: PqAssetAdminAction,
        subject_kind: impl Into<String>,
        subject_id: impl Into<String>,
        admin_label: impl Into<String>,
        signer_labels: &[String],
        public_key_payload: &Value,
        payload: &Value,
        attestation_payload: &Value,
        pq_signature_payload: &Value,
        decision: PqAuthorizationDecision,
        security_bits: u16,
        valid_from_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let subject_kind = normalize_label(subject_kind.into());
        let subject_id = subject_id.into();
        let admin_label = admin_label.into();
        ensure_non_empty(&class_id, "pq authorization class_id")?;
        ensure_non_empty(&subject_kind, "pq authorization subject_kind")?;
        ensure_non_empty(&subject_id, "pq authorization subject_id")?;
        ensure_non_empty(&admin_label, "pq authorization admin")?;
        if signer_labels.is_empty() {
            return Err("pq authorization signer set is empty".to_string());
        }
        if expires_at_height <= valid_from_height {
            return Err("pq authorization expiry must be after valid_from".to_string());
        }
        if security_bits < CONFIDENTIAL_ASSET_RUNTIME_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security bits below runtime floor".to_string());
        }
        let admin_commitment = confidential_asset_runtime_account_commitment(&admin_label);
        let signer_commitments = signer_labels
            .iter()
            .map(|label| confidential_asset_runtime_account_commitment(label))
            .collect::<Vec<_>>();
        let signer_set_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-PQ-SIGNER",
            &signer_commitments,
        );
        let public_key_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-PQ-PUBLIC-KEY",
            public_key_payload,
        );
        let payload_root =
            confidential_asset_runtime_payload_root("CONFIDENTIAL-ASSET-PQ-AUTH-PAYLOAD", payload);
        let attestation_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-PQ-AUTH-ATTESTATION",
            attestation_payload,
        );
        let pq_signature_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-PQ-AUTH-SIGNATURE",
            pq_signature_payload,
        );
        let authorization_id = confidential_asset_runtime_pq_authorization_id(
            &class_id,
            action,
            &subject_kind,
            &subject_id,
            &admin_commitment,
            &payload_root,
            nonce,
        );
        let status = if decision.permits_execution() {
            PqAuthorizationStatus::Active
        } else {
            PqAuthorizationStatus::Pending
        };
        let authorization = Self {
            authorization_id,
            class_id,
            action,
            subject_kind,
            subject_id,
            admin_commitment,
            signer_set_root,
            public_key_root,
            payload_root,
            attestation_root,
            pq_signature_root,
            decision,
            status,
            security_bits,
            valid_from_height,
            expires_at_height,
            nonce,
        };
        authorization.validate()?;
        Ok(authorization)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.active()
            && self.decision.permits_execution()
            && self.valid_from_height <= height
            && height < self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_asset_admin_authorization",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "authorization_id": self.authorization_id,
            "class_id": self.class_id,
            "action": self.action.as_str(),
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "admin_commitment": self.admin_commitment,
            "signer_set_root": self.signer_set_root,
            "public_key_root": self.public_key_root,
            "payload_root": self.payload_root,
            "attestation_root": self.attestation_root,
            "pq_signature_root": self.pq_signature_root,
            "decision": self.decision.as_str(),
            "status": self.status.as_str(),
            "security_bits": self.security_bits,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.authorization_id, "pq authorization id")?;
        ensure_non_empty(&self.class_id, "pq authorization class id")?;
        ensure_non_empty(&self.subject_kind, "pq authorization subject kind")?;
        ensure_non_empty(&self.subject_id, "pq authorization subject id")?;
        ensure_non_empty(&self.admin_commitment, "pq authorization admin commitment")?;
        ensure_non_empty(&self.signer_set_root, "pq authorization signer root")?;
        ensure_non_empty(&self.public_key_root, "pq authorization public key root")?;
        ensure_non_empty(&self.payload_root, "pq authorization payload root")?;
        ensure_non_empty(&self.attestation_root, "pq authorization attestation root")?;
        ensure_non_empty(&self.pq_signature_root, "pq authorization signature root")?;
        if self.expires_at_height <= self.valid_from_height {
            return Err("pq authorization expiry must be after valid_from".to_string());
        }
        if self.security_bits < CONFIDENTIAL_ASSET_RUNTIME_MIN_PQ_SECURITY_BITS {
            return Err("pq authorization security bits below runtime floor".to_string());
        }
        Ok(self.authorization_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateAmmHook {
    pub hook_id: String,
    pub class_id: String,
    pub pool_commitment: String,
    pub base_asset_commitment: String,
    pub quote_asset_commitment: String,
    pub reserve_commitment_root: String,
    pub invariant_commitment: String,
    pub fee_bps: u64,
    pub slippage_guard_bps: u64,
    pub price_bucket: String,
    pub authorized_router_root: String,
    pub private_orderflow_root: String,
    pub status: HookStatus,
    pub created_at_height: u64,
    pub last_settlement_height: u64,
}

impl PrivateAmmHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        pool_label: impl Into<String>,
        base_asset_label: impl Into<String>,
        quote_asset_label: impl Into<String>,
        reserve_payload: &Value,
        invariant_label: impl Into<String>,
        fee_bps: u64,
        slippage_guard_bps: u64,
        price_bucket: impl Into<String>,
        authorized_router_labels: &[String],
        private_orderflow_payload: &Value,
        created_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let pool_label = pool_label.into();
        let base_asset_label = base_asset_label.into();
        let quote_asset_label = quote_asset_label.into();
        let invariant_label = invariant_label.into();
        let price_bucket = normalize_label(price_bucket.into());
        ensure_non_empty(&class_id, "amm hook class_id")?;
        ensure_non_empty(&pool_label, "amm hook pool")?;
        ensure_non_empty(&base_asset_label, "amm hook base asset")?;
        ensure_non_empty(&quote_asset_label, "amm hook quote asset")?;
        ensure_non_empty(&invariant_label, "amm hook invariant")?;
        ensure_non_empty(&price_bucket, "amm hook price bucket")?;
        validate_bps(
            "amm hook fee_bps",
            fee_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "amm hook slippage_guard_bps",
            slippage_guard_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        let pool_commitment =
            confidential_asset_runtime_string_root("CONFIDENTIAL-ASSET-AMM-POOL", &pool_label);
        let base_asset_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-AMM-BASE-ASSET",
            &base_asset_label,
        );
        let quote_asset_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-AMM-QUOTE-ASSET",
            &quote_asset_label,
        );
        let reserve_commitment_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-AMM-RESERVE",
            reserve_payload,
        );
        let invariant_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-AMM-INVARIANT",
            &invariant_label,
        );
        let router_commitments = authorized_router_labels
            .iter()
            .map(|label| confidential_asset_runtime_account_commitment(label))
            .collect::<Vec<_>>();
        let authorized_router_root = confidential_asset_runtime_string_set_root(
            "CONFIDENTIAL-ASSET-AMM-ROUTER",
            &router_commitments,
        );
        let private_orderflow_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-AMM-PRIVATE-ORDERFLOW",
            private_orderflow_payload,
        );
        let hook_id = confidential_asset_runtime_hook_id(
            "amm",
            &class_id,
            &pool_commitment,
            &reserve_commitment_root,
            nonce,
        );
        let hook = Self {
            hook_id,
            class_id,
            pool_commitment,
            base_asset_commitment,
            quote_asset_commitment,
            reserve_commitment_root,
            invariant_commitment,
            fee_bps,
            slippage_guard_bps,
            price_bucket,
            authorized_router_root,
            private_orderflow_root,
            status: HookStatus::Active,
            created_at_height,
            last_settlement_height: created_at_height,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_amm_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "class_id": self.class_id,
            "pool_commitment": self.pool_commitment,
            "base_asset_commitment": self.base_asset_commitment,
            "quote_asset_commitment": self.quote_asset_commitment,
            "reserve_commitment_root": self.reserve_commitment_root,
            "invariant_commitment": self.invariant_commitment,
            "fee_bps": self.fee_bps,
            "slippage_guard_bps": self.slippage_guard_bps,
            "price_bucket": self.price_bucket,
            "authorized_router_root": self.authorized_router_root,
            "private_orderflow_root": self.private_orderflow_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "last_settlement_height": self.last_settlement_height,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.hook_id, "amm hook id")?;
        ensure_non_empty(&self.class_id, "amm hook class id")?;
        ensure_non_empty(&self.pool_commitment, "amm hook pool commitment")?;
        ensure_non_empty(
            &self.base_asset_commitment,
            "amm hook base asset commitment",
        )?;
        ensure_non_empty(
            &self.quote_asset_commitment,
            "amm hook quote asset commitment",
        )?;
        ensure_non_empty(&self.reserve_commitment_root, "amm hook reserve root")?;
        ensure_non_empty(&self.invariant_commitment, "amm hook invariant commitment")?;
        ensure_non_empty(&self.price_bucket, "amm hook price bucket")?;
        ensure_non_empty(&self.authorized_router_root, "amm hook router root")?;
        ensure_non_empty(
            &self.private_orderflow_root,
            "amm hook private orderflow root",
        )?;
        validate_bps(
            "amm hook fee_bps",
            self.fee_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "amm hook slippage_guard_bps",
            self.slippage_guard_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if self.last_settlement_height < self.created_at_height {
            return Err("amm hook settlement before creation".to_string());
        }
        Ok(self.hook_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LendingCollateralHook {
    pub hook_id: String,
    pub class_id: String,
    pub market_commitment: String,
    pub collateral_factor_bps: u64,
    pub liquidation_threshold_bps: u64,
    pub oracle_feed_commitment: String,
    pub health_bucket_root: String,
    pub encumbrance_root: String,
    pub lender_view_policy_root: String,
    pub status: HookStatus,
    pub created_at_height: u64,
    pub last_oracle_height: u64,
    pub max_staleness_blocks: u64,
}

impl LendingCollateralHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        market_label: impl Into<String>,
        collateral_factor_bps: u64,
        liquidation_threshold_bps: u64,
        oracle_feed_label: impl Into<String>,
        health_payload: &Value,
        encumbrance_payload: &Value,
        lender_view_policy_payload: &Value,
        created_at_height: u64,
        last_oracle_height: u64,
        max_staleness_blocks: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let market_label = market_label.into();
        let oracle_feed_label = oracle_feed_label.into();
        ensure_non_empty(&class_id, "lending hook class_id")?;
        ensure_non_empty(&market_label, "lending hook market")?;
        ensure_non_empty(&oracle_feed_label, "lending hook oracle")?;
        validate_bps(
            "lending hook collateral_factor_bps",
            collateral_factor_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "lending hook liquidation_threshold_bps",
            liquidation_threshold_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if collateral_factor_bps >= liquidation_threshold_bps {
            return Err(
                "lending hook collateral factor must be below liquidation threshold".to_string(),
            );
        }
        if max_staleness_blocks == 0 {
            return Err("lending hook max staleness must be non-zero".to_string());
        }
        let market_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-LENDING-MARKET",
            &market_label,
        );
        let oracle_feed_commitment = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-LENDING-ORACLE",
            &oracle_feed_label,
        );
        let health_bucket_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-LENDING-HEALTH",
            health_payload,
        );
        let encumbrance_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-LENDING-ENCUMBRANCE",
            encumbrance_payload,
        );
        let lender_view_policy_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-LENDING-VIEW-POLICY",
            lender_view_policy_payload,
        );
        let hook_id = confidential_asset_runtime_hook_id(
            "lending",
            &class_id,
            &market_commitment,
            &health_bucket_root,
            nonce,
        );
        let hook = Self {
            hook_id,
            class_id,
            market_commitment,
            collateral_factor_bps,
            liquidation_threshold_bps,
            oracle_feed_commitment,
            health_bucket_root,
            encumbrance_root,
            lender_view_policy_root,
            status: HookStatus::Active,
            created_at_height,
            last_oracle_height,
            max_staleness_blocks,
        };
        hook.validate()?;
        Ok(hook)
    }

    pub fn oracle_fresh_at(&self, height: u64) -> bool {
        height.saturating_sub(self.last_oracle_height) <= self.max_staleness_blocks
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "lending_collateral_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "hook_id": self.hook_id,
            "class_id": self.class_id,
            "market_commitment": self.market_commitment,
            "collateral_factor_bps": self.collateral_factor_bps,
            "liquidation_threshold_bps": self.liquidation_threshold_bps,
            "oracle_feed_commitment": self.oracle_feed_commitment,
            "health_bucket_root": self.health_bucket_root,
            "encumbrance_root": self.encumbrance_root,
            "lender_view_policy_root": self.lender_view_policy_root,
            "status": self.status.as_str(),
            "created_at_height": self.created_at_height,
            "last_oracle_height": self.last_oracle_height,
            "max_staleness_blocks": self.max_staleness_blocks,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.hook_id, "lending hook id")?;
        ensure_non_empty(&self.class_id, "lending hook class id")?;
        ensure_non_empty(&self.market_commitment, "lending hook market commitment")?;
        ensure_non_empty(
            &self.oracle_feed_commitment,
            "lending hook oracle feed commitment",
        )?;
        ensure_non_empty(&self.health_bucket_root, "lending hook health bucket root")?;
        ensure_non_empty(&self.encumbrance_root, "lending hook encumbrance root")?;
        ensure_non_empty(
            &self.lender_view_policy_root,
            "lending hook lender view policy root",
        )?;
        validate_bps(
            "lending hook collateral_factor_bps",
            self.collateral_factor_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "lending hook liquidation_threshold_bps",
            self.liquidation_threshold_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if self.collateral_factor_bps >= self.liquidation_threshold_bps {
            return Err(
                "lending hook collateral factor must be below liquidation threshold".to_string(),
            );
        }
        if self.max_staleness_blocks == 0 {
            return Err("lending hook max staleness must be non-zero".to_string());
        }
        if self.last_oracle_height
            < self
                .created_at_height
                .saturating_sub(self.max_staleness_blocks)
        {
            return Err(
                "lending hook oracle height is outside initial staleness window".to_string(),
            );
        }
        Ok(self.hook_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsoredTransfer {
    pub sponsorship_id: String,
    pub class_id: String,
    pub sponsor_commitment: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub spent_units: u64,
    pub max_fee_units_per_transfer: u64,
    pub max_transfer_amount_units: u64,
    pub eligibility_root: String,
    pub nullifier_root: String,
    pub status: SponsorshipStatus,
    pub start_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
}

impl LowFeeSponsoredTransfer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        sponsor_label: impl Into<String>,
        beneficiary_label: impl Into<String>,
        fee_asset_id: impl Into<String>,
        lane_id: impl Into<String>,
        budget_units: u64,
        max_fee_units_per_transfer: u64,
        max_transfer_amount_units: u64,
        eligibility_payload: &Value,
        start_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let sponsor_label = sponsor_label.into();
        let beneficiary_label = beneficiary_label.into();
        let fee_asset_id = fee_asset_id.into();
        let lane_id = normalize_label(lane_id.into());
        ensure_non_empty(&class_id, "sponsorship class_id")?;
        ensure_non_empty(&sponsor_label, "sponsorship sponsor")?;
        ensure_non_empty(&beneficiary_label, "sponsorship beneficiary")?;
        ensure_non_empty(&fee_asset_id, "sponsorship fee_asset_id")?;
        ensure_non_empty(&lane_id, "sponsorship lane_id")?;
        if budget_units == 0 {
            return Err("sponsorship budget must be non-zero".to_string());
        }
        if max_fee_units_per_transfer == 0 {
            return Err("sponsorship max fee must be non-zero".to_string());
        }
        if max_transfer_amount_units == 0 {
            return Err("sponsorship max transfer amount must be non-zero".to_string());
        }
        if expires_at_height <= start_height {
            return Err("sponsorship expiry must be after start".to_string());
        }
        let sponsor_commitment = confidential_asset_runtime_account_commitment(&sponsor_label);
        let beneficiary_commitment =
            confidential_asset_runtime_account_commitment(&beneficiary_label);
        let eligibility_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-SPONSORSHIP-ELIGIBILITY",
            eligibility_payload,
        );
        let nullifier_root = confidential_asset_runtime_string_root(
            "CONFIDENTIAL-ASSET-SPONSORSHIP-NULLIFIER",
            &format!("{class_id}:{sponsor_commitment}:{beneficiary_commitment}:{nonce}"),
        );
        let sponsorship_id = confidential_asset_runtime_sponsorship_id(
            &class_id,
            &sponsor_commitment,
            &beneficiary_commitment,
            &lane_id,
            nonce,
        );
        let sponsorship = Self {
            sponsorship_id,
            class_id,
            sponsor_commitment,
            beneficiary_commitment,
            fee_asset_id,
            lane_id,
            budget_units,
            spent_units: 0,
            max_fee_units_per_transfer,
            max_transfer_amount_units,
            eligibility_root,
            nullifier_root,
            status: SponsorshipStatus::Active,
            start_height,
            expires_at_height,
            nonce,
        };
        sponsorship.validate()?;
        Ok(sponsorship)
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units.saturating_sub(self.spent_units)
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.status.active()
            && self.start_height <= height
            && height < self.expires_at_height
            && self.available_units() > 0
    }

    pub fn sponsor_fee(&mut self, fee_units: u64) -> ConfidentialAssetRuntimeResult<()> {
        if fee_units == 0 {
            return Err("sponsored fee must be non-zero".to_string());
        }
        if fee_units > self.max_fee_units_per_transfer {
            return Err("sponsored fee exceeds per-transfer cap".to_string());
        }
        if fee_units > self.available_units() {
            return Err("sponsorship budget exhausted".to_string());
        }
        self.spent_units = self.spent_units.saturating_add(fee_units);
        if self.available_units() == 0 {
            self.status = SponsorshipStatus::Exhausted;
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_sponsored_transfer",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "sponsorship_id": self.sponsorship_id,
            "class_id": self.class_id,
            "sponsor_commitment": self.sponsor_commitment,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_fee_units_per_transfer": self.max_fee_units_per_transfer,
            "max_transfer_amount_units": self.max_transfer_amount_units,
            "eligibility_root": self.eligibility_root,
            "nullifier_root": self.nullifier_root,
            "status": self.status.as_str(),
            "start_height": self.start_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.sponsorship_id, "sponsorship id")?;
        ensure_non_empty(&self.class_id, "sponsorship class id")?;
        ensure_non_empty(&self.sponsor_commitment, "sponsorship sponsor commitment")?;
        ensure_non_empty(
            &self.beneficiary_commitment,
            "sponsorship beneficiary commitment",
        )?;
        ensure_non_empty(&self.fee_asset_id, "sponsorship fee asset id")?;
        ensure_non_empty(&self.lane_id, "sponsorship lane id")?;
        ensure_non_empty(&self.eligibility_root, "sponsorship eligibility root")?;
        ensure_non_empty(&self.nullifier_root, "sponsorship nullifier root")?;
        if self.budget_units == 0 {
            return Err("sponsorship budget must be non-zero".to_string());
        }
        if self.spent_units > self.budget_units {
            return Err("sponsorship spent units exceed budget".to_string());
        }
        if self.max_fee_units_per_transfer == 0 {
            return Err("sponsorship max fee must be non-zero".to_string());
        }
        if self.max_transfer_amount_units == 0 {
            return Err("sponsorship max transfer amount must be non-zero".to_string());
        }
        if self.expires_at_height <= self.start_height {
            return Err("sponsorship expiry must be after start".to_string());
        }
        Ok(self.sponsorship_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRiskControl {
    pub control_id: String,
    pub class_id: String,
    pub scope: RiskControlScope,
    pub subject_id: String,
    pub action: RiskAction,
    pub severity: RiskSeverity,
    pub status: RiskControlStatus,
    pub observed_score_bps: u64,
    pub threshold_bps: u64,
    pub evidence_root: String,
    pub pq_attestation_root: String,
    pub disclosure_requirement_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub resolved_at_height: Option<u64>,
}

impl AssetRiskControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        scope: RiskControlScope,
        subject_id: impl Into<String>,
        action: RiskAction,
        severity: RiskSeverity,
        observed_score_bps: u64,
        threshold_bps: u64,
        evidence_payload: &Value,
        pq_attestation_payload: &Value,
        disclosure_requirement_payload: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let subject_id = subject_id.into();
        ensure_non_empty(&class_id, "risk control class_id")?;
        ensure_non_empty(&subject_id, "risk control subject_id")?;
        validate_bps(
            "risk control observed_score_bps",
            observed_score_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "risk control threshold_bps",
            threshold_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if expires_at_height <= opened_at_height {
            return Err("risk control expiry must be after open".to_string());
        }
        let evidence_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-RISK-EVIDENCE",
            evidence_payload,
        );
        let pq_attestation_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-RISK-PQ-ATTESTATION",
            pq_attestation_payload,
        );
        let disclosure_requirement_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-RISK-DISCLOSURE-REQUIREMENT",
            disclosure_requirement_payload,
        );
        let control_id = confidential_asset_runtime_risk_control_id(
            &class_id,
            scope,
            &subject_id,
            action,
            &evidence_root,
            nonce,
        );
        let status = if observed_score_bps >= threshold_bps {
            RiskControlStatus::Enforced
        } else {
            RiskControlStatus::Watching
        };
        let control = Self {
            control_id,
            class_id,
            scope,
            subject_id,
            action,
            severity,
            status,
            observed_score_bps,
            threshold_bps,
            evidence_root,
            pq_attestation_root,
            disclosure_requirement_root,
            opened_at_height,
            expires_at_height,
            resolved_at_height: None,
        };
        control.validate()?;
        Ok(control)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.active() && self.opened_at_height <= height && height < self.expires_at_height
    }

    pub fn effective_score_bps(&self) -> u64 {
        self.observed_score_bps.max(self.severity.score_bps())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "asset_risk_control",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "control_id": self.control_id,
            "class_id": self.class_id,
            "scope": self.scope.as_str(),
            "subject_id": self.subject_id,
            "action": self.action.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "observed_score_bps": self.observed_score_bps,
            "threshold_bps": self.threshold_bps,
            "effective_score_bps": self.effective_score_bps(),
            "evidence_root": self.evidence_root,
            "pq_attestation_root": self.pq_attestation_root,
            "disclosure_requirement_root": self.disclosure_requirement_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "resolved_at_height": self.resolved_at_height,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.control_id, "risk control id")?;
        ensure_non_empty(&self.class_id, "risk control class id")?;
        ensure_non_empty(&self.subject_id, "risk control subject id")?;
        ensure_non_empty(&self.evidence_root, "risk control evidence root")?;
        ensure_non_empty(
            &self.pq_attestation_root,
            "risk control pq attestation root",
        )?;
        ensure_non_empty(
            &self.disclosure_requirement_root,
            "risk control disclosure requirement root",
        )?;
        validate_bps(
            "risk control observed_score_bps",
            self.observed_score_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        validate_bps(
            "risk control threshold_bps",
            self.threshold_bps,
            CONFIDENTIAL_ASSET_RUNTIME_MAX_BPS,
        )?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("risk control expiry must be after open".to_string());
        }
        if let Some(resolved_at_height) = self.resolved_at_height {
            if resolved_at_height < self.opened_at_height {
                return Err("risk control resolved before open".to_string());
            }
        }
        Ok(self.control_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeUnfreezeCeremony {
    pub ceremony_id: String,
    pub class_id: String,
    pub kind: FreezeCeremonyKind,
    pub status: FreezeCeremonyStatus,
    pub proposer_commitment: String,
    pub affected_subject_kind: String,
    pub affected_subject_id: String,
    pub reason_root: String,
    pub quorum_root: String,
    pub authorization_root: String,
    pub disclosure_root: String,
    pub transcript_root: String,
    pub timelock_start_height: u64,
    pub executable_height: u64,
    pub expires_at_height: u64,
    pub executed_at_height: Option<u64>,
    pub release_height: Option<u64>,
}

impl FreezeUnfreezeCeremony {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: impl Into<String>,
        kind: FreezeCeremonyKind,
        proposer_label: impl Into<String>,
        affected_subject_kind: impl Into<String>,
        affected_subject_id: impl Into<String>,
        reason_payload: &Value,
        quorum_payload: &Value,
        authorization_payload: &Value,
        disclosure_payload: &Value,
        timelock_start_height: u64,
        delay_blocks: u64,
        ttl_blocks: u64,
        nonce: u64,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let class_id = class_id.into();
        let proposer_label = proposer_label.into();
        let affected_subject_kind = normalize_label(affected_subject_kind.into());
        let affected_subject_id = affected_subject_id.into();
        ensure_non_empty(&class_id, "freeze ceremony class_id")?;
        ensure_non_empty(&proposer_label, "freeze ceremony proposer")?;
        ensure_non_empty(
            &affected_subject_kind,
            "freeze ceremony affected_subject_kind",
        )?;
        ensure_non_empty(&affected_subject_id, "freeze ceremony affected_subject_id")?;
        if ttl_blocks == 0 {
            return Err("freeze ceremony ttl must be non-zero".to_string());
        }
        let proposer_commitment = confidential_asset_runtime_account_commitment(&proposer_label);
        let reason_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-REASON",
            reason_payload,
        );
        let quorum_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-QUORUM",
            quorum_payload,
        );
        let authorization_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-AUTHORIZATION",
            authorization_payload,
        );
        let disclosure_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-DISCLOSURE",
            disclosure_payload,
        );
        let executable_height = timelock_start_height.saturating_add(delay_blocks);
        let expires_at_height = executable_height.saturating_add(ttl_blocks);
        let transcript_payload = json!({
            "class_id": class_id,
            "kind": kind.as_str(),
            "affected_subject_kind": affected_subject_kind,
            "affected_subject_id": affected_subject_id,
            "reason_root": reason_root,
            "quorum_root": quorum_root,
            "authorization_root": authorization_root,
            "disclosure_root": disclosure_root,
            "executable_height": executable_height,
        });
        let transcript_root = confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-FREEZE-TRANSCRIPT",
            &transcript_payload,
        );
        let ceremony_id = confidential_asset_runtime_freeze_ceremony_id(
            &class_id,
            kind,
            &affected_subject_kind,
            &affected_subject_id,
            &authorization_root,
            nonce,
        );
        let status = if delay_blocks == 0 {
            FreezeCeremonyStatus::Executable
        } else {
            FreezeCeremonyStatus::Timelocked
        };
        let ceremony = Self {
            ceremony_id,
            class_id,
            kind,
            status,
            proposer_commitment,
            affected_subject_kind,
            affected_subject_id,
            reason_root,
            quorum_root,
            authorization_root,
            disclosure_root,
            transcript_root,
            timelock_start_height,
            executable_height,
            expires_at_height,
            executed_at_height: None,
            release_height: None,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    pub fn executable_at(&self, height: u64) -> bool {
        matches!(
            self.status,
            FreezeCeremonyStatus::Timelocked | FreezeCeremonyStatus::Executable
        ) && height >= self.executable_height
            && height < self.expires_at_height
    }

    pub fn execute(&mut self, height: u64) -> ConfidentialAssetRuntimeResult<()> {
        if !self.executable_at(height) {
            return Err("freeze ceremony is not executable at height".to_string());
        }
        self.status = FreezeCeremonyStatus::Executed;
        self.executed_at_height = Some(height);
        Ok(())
    }

    pub fn release(&mut self, height: u64) -> ConfidentialAssetRuntimeResult<()> {
        if self.executed_at_height.is_none() {
            return Err("freeze ceremony cannot release before execution".to_string());
        }
        self.status = FreezeCeremonyStatus::Released;
        self.release_height = Some(height);
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "freeze_unfreeze_ceremony",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "ceremony_id": self.ceremony_id,
            "class_id": self.class_id,
            "ceremony_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "proposer_commitment": self.proposer_commitment,
            "affected_subject_kind": self.affected_subject_kind,
            "affected_subject_id": self.affected_subject_id,
            "reason_root": self.reason_root,
            "quorum_root": self.quorum_root,
            "authorization_root": self.authorization_root,
            "disclosure_root": self.disclosure_root,
            "transcript_root": self.transcript_root,
            "timelock_start_height": self.timelock_start_height,
            "executable_height": self.executable_height,
            "expires_at_height": self.expires_at_height,
            "executed_at_height": self.executed_at_height,
            "release_height": self.release_height,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.ceremony_id, "freeze ceremony id")?;
        ensure_non_empty(&self.class_id, "freeze ceremony class id")?;
        ensure_non_empty(
            &self.proposer_commitment,
            "freeze ceremony proposer commitment",
        )?;
        ensure_non_empty(
            &self.affected_subject_kind,
            "freeze ceremony affected subject kind",
        )?;
        ensure_non_empty(
            &self.affected_subject_id,
            "freeze ceremony affected subject id",
        )?;
        ensure_non_empty(&self.reason_root, "freeze ceremony reason root")?;
        ensure_non_empty(&self.quorum_root, "freeze ceremony quorum root")?;
        ensure_non_empty(
            &self.authorization_root,
            "freeze ceremony authorization root",
        )?;
        ensure_non_empty(&self.disclosure_root, "freeze ceremony disclosure root")?;
        ensure_non_empty(&self.transcript_root, "freeze ceremony transcript root")?;
        if self.executable_height < self.timelock_start_height {
            return Err("freeze ceremony executable height before timelock".to_string());
        }
        if self.expires_at_height <= self.executable_height {
            return Err("freeze ceremony expiry must be after executable height".to_string());
        }
        if let Some(executed_at_height) = self.executed_at_height {
            if executed_at_height < self.executable_height {
                return Err("freeze ceremony executed before executable height".to_string());
            }
            if executed_at_height >= self.expires_at_height {
                return Err("freeze ceremony executed after expiry".to_string());
            }
        }
        if let Some(release_height) = self.release_height {
            if let Some(executed_at_height) = self.executed_at_height {
                if release_height < executed_at_height {
                    return Err("freeze ceremony released before execution".to_string());
                }
            } else {
                return Err("freeze ceremony has release height without execution".to_string());
            }
        }
        Ok(self.ceremony_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAssetDevnetFixture {
    pub record_id: String,
    pub label: String,
    pub object_kind: String,
    pub object_id: String,
    pub payload_root: String,
    pub height: u64,
    pub note: String,
}

impl ConfidentialAssetDevnetFixture {
    pub fn new(
        label: impl Into<String>,
        object_kind: impl Into<String>,
        object_id: impl Into<String>,
        payload: &Value,
        height: u64,
        note: impl Into<String>,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        let label = normalize_label(label.into());
        let object_kind = normalize_label(object_kind.into());
        let object_id = object_id.into();
        let note = note.into();
        ensure_non_empty(&label, "devnet fixture label")?;
        ensure_non_empty(&object_kind, "devnet fixture object kind")?;
        ensure_non_empty(&object_id, "devnet fixture object id")?;
        let payload_root =
            confidential_asset_runtime_payload_root("CONFIDENTIAL-ASSET-DEVNET-FIXTURE", payload);
        let record_id = confidential_asset_runtime_devnet_fixture_id(
            &label,
            &object_kind,
            &object_id,
            &payload_root,
        );
        let fixture = Self {
            record_id,
            label,
            object_kind,
            object_id,
            payload_root,
            height,
            note,
        };
        fixture.validate()?;
        Ok(fixture)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_asset_devnet_fixture",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "record_id": self.record_id,
            "label": self.label,
            "object_kind": self.object_kind,
            "object_id": self.object_id,
            "payload_root": self.payload_root,
            "height": self.height,
            "note": self.note,
        })
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        ensure_non_empty(&self.record_id, "devnet fixture id")?;
        ensure_non_empty(&self.label, "devnet fixture label")?;
        ensure_non_empty(&self.object_kind, "devnet fixture object kind")?;
        ensure_non_empty(&self.object_id, "devnet fixture object id")?;
        ensure_non_empty(&self.payload_root, "devnet fixture payload root")?;
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAssetRuntimeRoots {
    pub config_root: String,
    pub token_class_root: String,
    pub shielded_balance_root: String,
    pub mint_burn_root: String,
    pub transfer_note_root: String,
    pub disclosure_root: String,
    pub pq_authorization_root: String,
    pub amm_hook_root: String,
    pub lending_hook_root: String,
    pub low_fee_sponsorship_root: String,
    pub risk_control_root: String,
    pub freeze_ceremony_root: String,
    pub spent_nullifier_root: String,
    pub devnet_fixture_root: String,
}

impl ConfidentialAssetRuntimeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_asset_runtime_roots",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "config_root": self.config_root,
            "token_class_root": self.token_class_root,
            "shielded_balance_root": self.shielded_balance_root,
            "mint_burn_root": self.mint_burn_root,
            "transfer_note_root": self.transfer_note_root,
            "disclosure_root": self.disclosure_root,
            "pq_authorization_root": self.pq_authorization_root,
            "amm_hook_root": self.amm_hook_root,
            "lending_hook_root": self.lending_hook_root,
            "low_fee_sponsorship_root": self.low_fee_sponsorship_root,
            "risk_control_root": self.risk_control_root,
            "freeze_ceremony_root": self.freeze_ceremony_root,
            "spent_nullifier_root": self.spent_nullifier_root,
            "devnet_fixture_root": self.devnet_fixture_root,
        })
    }

    pub fn aggregate_root(&self) -> String {
        confidential_asset_runtime_payload_root(
            "CONFIDENTIAL-ASSET-RUNTIME-ROOTS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAssetRuntimeCounters {
    pub token_class_count: u64,
    pub active_token_class_count: u64,
    pub shielded_balance_count: u64,
    pub open_shielded_balance_count: u64,
    pub spendable_shielded_balance_count: u64,
    pub mint_operation_count: u64,
    pub burn_operation_count: u64,
    pub transfer_note_count: u64,
    pub live_transfer_note_count: u64,
    pub settled_transfer_note_count: u64,
    pub disclosure_count: u64,
    pub active_disclosure_count: u64,
    pub pq_authorization_count: u64,
    pub active_pq_authorization_count: u64,
    pub amm_hook_count: u64,
    pub active_amm_hook_count: u64,
    pub lending_hook_count: u64,
    pub active_lending_hook_count: u64,
    pub low_fee_sponsorship_count: u64,
    pub active_low_fee_sponsorship_count: u64,
    pub risk_control_count: u64,
    pub active_risk_control_count: u64,
    pub freeze_ceremony_count: u64,
    pub active_freeze_ceremony_count: u64,
    pub spent_nullifier_count: u64,
    pub devnet_fixture_count: u64,
    pub total_supply_cap_units: u64,
    pub total_minted_upper_bound_units: u64,
    pub total_burned_upper_bound_units: u64,
    pub total_balance_upper_bound_units: u64,
    pub sponsored_budget_units: u64,
    pub sponsored_spent_units: u64,
    pub max_observed_risk_score_bps: u64,
}

impl ConfidentialAssetRuntimeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "token_class_count": self.token_class_count,
            "active_token_class_count": self.active_token_class_count,
            "shielded_balance_count": self.shielded_balance_count,
            "open_shielded_balance_count": self.open_shielded_balance_count,
            "spendable_shielded_balance_count": self.spendable_shielded_balance_count,
            "mint_operation_count": self.mint_operation_count,
            "burn_operation_count": self.burn_operation_count,
            "transfer_note_count": self.transfer_note_count,
            "live_transfer_note_count": self.live_transfer_note_count,
            "settled_transfer_note_count": self.settled_transfer_note_count,
            "disclosure_count": self.disclosure_count,
            "active_disclosure_count": self.active_disclosure_count,
            "pq_authorization_count": self.pq_authorization_count,
            "active_pq_authorization_count": self.active_pq_authorization_count,
            "amm_hook_count": self.amm_hook_count,
            "active_amm_hook_count": self.active_amm_hook_count,
            "lending_hook_count": self.lending_hook_count,
            "active_lending_hook_count": self.active_lending_hook_count,
            "low_fee_sponsorship_count": self.low_fee_sponsorship_count,
            "active_low_fee_sponsorship_count": self.active_low_fee_sponsorship_count,
            "risk_control_count": self.risk_control_count,
            "active_risk_control_count": self.active_risk_control_count,
            "freeze_ceremony_count": self.freeze_ceremony_count,
            "active_freeze_ceremony_count": self.active_freeze_ceremony_count,
            "spent_nullifier_count": self.spent_nullifier_count,
            "devnet_fixture_count": self.devnet_fixture_count,
            "total_supply_cap_units": self.total_supply_cap_units,
            "total_minted_upper_bound_units": self.total_minted_upper_bound_units,
            "total_burned_upper_bound_units": self.total_burned_upper_bound_units,
            "total_balance_upper_bound_units": self.total_balance_upper_bound_units,
            "sponsored_budget_units": self.sponsored_budget_units,
            "sponsored_spent_units": self.sponsored_spent_units,
            "max_observed_risk_score_bps": self.max_observed_risk_score_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidentialAssetRuntimeState {
    pub height: u64,
    pub nonce: u64,
    pub config: ConfidentialAssetRuntimeConfig,
    pub token_classes: BTreeMap<String, ConfidentialTokenClass>,
    pub shielded_balances: BTreeMap<String, ShieldedAssetBalance>,
    pub mint_burns: BTreeMap<String, ConfidentialMintBurn>,
    pub transfer_notes: BTreeMap<String, ConfidentialTransferNote>,
    pub disclosures: BTreeMap<String, ComplianceViewingDisclosure>,
    pub pq_admin_authorizations: BTreeMap<String, PqAssetAdminAuthorization>,
    pub amm_hooks: BTreeMap<String, PrivateAmmHook>,
    pub lending_hooks: BTreeMap<String, LendingCollateralHook>,
    pub low_fee_sponsorships: BTreeMap<String, LowFeeSponsoredTransfer>,
    pub risk_controls: BTreeMap<String, AssetRiskControl>,
    pub freeze_ceremonies: BTreeMap<String, FreezeUnfreezeCeremony>,
    pub spent_nullifiers: BTreeSet<String>,
    pub devnet_fixtures: BTreeMap<String, ConfidentialAssetDevnetFixture>,
}

impl Default for ConfidentialAssetRuntimeState {
    fn default() -> Self {
        Self::new(ConfidentialAssetRuntimeConfig::default())
    }
}

impl ConfidentialAssetRuntimeState {
    pub fn new(config: ConfidentialAssetRuntimeConfig) -> Self {
        Self {
            height: 0,
            nonce: 0,
            config,
            token_classes: BTreeMap::new(),
            shielded_balances: BTreeMap::new(),
            mint_burns: BTreeMap::new(),
            transfer_notes: BTreeMap::new(),
            disclosures: BTreeMap::new(),
            pq_admin_authorizations: BTreeMap::new(),
            amm_hooks: BTreeMap::new(),
            lending_hooks: BTreeMap::new(),
            low_fee_sponsorships: BTreeMap::new(),
            risk_controls: BTreeMap::new(),
            freeze_ceremonies: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            devnet_fixtures: BTreeMap::new(),
        }
    }

    pub fn with_config(
        config: ConfidentialAssetRuntimeConfig,
    ) -> ConfidentialAssetRuntimeResult<Self> {
        config.validate()?;
        Ok(Self::new(config))
    }

    pub fn devnet() -> ConfidentialAssetRuntimeResult<Self> {
        let mut state = Self::with_config(ConfidentialAssetRuntimeConfig::devnet())?;
        state.set_height(CONFIDENTIAL_ASSET_RUNTIME_DEVNET_HEIGHT);

        let mut pxmr = ConfidentialTokenClass::new(
            "pXMR",
            "Private Wrapped Monero",
            "devnet-confidential-asset-issuer",
            ConfidentialAssetKind::PrivateCollateral,
            AssetVisibility::ViewKeyAuditable,
            12,
            5_000_000_000_000,
            &json!({
                "ticker": "pXMR",
                "public_label": "private wrapped monero",
                "bridge": "monero-devnet-lockbox",
                "metadata_disclosure": "symbol-only"
            }),
            &json!({"threshold": "2-of-3", "roles": ["issuer", "risk", "emergency"]}),
            &json!({"min_privacy_set": 128, "max_inputs": state.config.max_transfer_inputs}),
            &json!({"auditor_view": "bucket-only", "regulator_view": "case-bound"}),
            &json!({"delay_blocks": state.config.default_freeze_delay_blocks, "quorum": "2-of-3"}),
            state.height.saturating_sub(96),
            state.next_nonce(),
        )?;
        pxmr.activate(state.height.saturating_sub(95));
        let pxmr_class_id = pxmr.class_id.clone();
        state.insert_token_class(pxmr)?;

        let mut dusd = ConfidentialTokenClass::new(
            "dUSD",
            "Devnet Private Dollar",
            "devnet-confidential-stable-issuer",
            ConfidentialAssetKind::PrivateStable,
            AssetVisibility::RegulatorDisclosable,
            6,
            20_000_000_000_000,
            &json!({
                "ticker": "dUSD",
                "public_label": "devnet private dollar",
                "reserve": "fixture-only"
            }),
            &json!({"threshold": "2-of-3", "roles": ["issuer", "reserve", "risk"]}),
            &json!({"sponsored_small_transfer": true, "dust_limit": 10_000}),
            &json!({"auditor_view": "mint-burn-and-flow", "regulator_view": "case-bound"}),
            &json!({"delay_blocks": 6, "quorum": "2-of-3"}),
            state.height.saturating_sub(90),
            state.next_nonce(),
        )?;
        dusd.activate(state.height.saturating_sub(89));
        let dusd_class_id = dusd.class_id.clone();
        state.insert_token_class(dusd)?;

        let pxmr_admin = PqAssetAdminAuthorization::new(
            &pxmr_class_id,
            PqAssetAdminAction::Mint,
            "token_class",
            &pxmr_class_id,
            "devnet-confidential-asset-issuer",
            &[
                "asset-admin-ml-dsa-1".to_string(),
                "asset-admin-ml-dsa-2".to_string(),
                "asset-admin-slh-dsa-3".to_string(),
            ],
            &json!({"scheme": CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME, "rotation": 0}),
            &json!({"action": "mint_private_wrapped_monero", "cap": "devnet"}),
            &json!({"committee": "devnet-asset-admin", "decision": "approve"}),
            &json!({"aggregate_signature": "pxmr-mint-devnet-signature-root"}),
            PqAuthorizationDecision::Approve,
            256,
            state.height.saturating_sub(80),
            state.height.saturating_add(7_200),
            state.next_nonce(),
        )?;
        let pxmr_admin_id = pxmr_admin.authorization_id.clone();
        state.insert_pq_admin_authorization(pxmr_admin)?;

        let dusd_admin = PqAssetAdminAuthorization::new(
            &dusd_class_id,
            PqAssetAdminAction::Mint,
            "token_class",
            &dusd_class_id,
            "devnet-confidential-stable-issuer",
            &[
                "stable-admin-ml-dsa-1".to_string(),
                "stable-admin-ml-dsa-2".to_string(),
                "stable-admin-slh-dsa-3".to_string(),
            ],
            &json!({"scheme": CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME, "rotation": 0}),
            &json!({"action": "mint_private_dusd", "reserve": "fixture"}),
            &json!({"committee": "devnet-stable-admin", "decision": "approve"}),
            &json!({"aggregate_signature": "dusd-mint-devnet-signature-root"}),
            PqAuthorizationDecision::Approve,
            256,
            state.height.saturating_sub(76),
            state.height.saturating_add(7_200),
            state.next_nonce(),
        )?;
        let dusd_admin_id = dusd_admin.authorization_id.clone();
        state.insert_pq_admin_authorization(dusd_admin)?;

        let pxmr_alice = ShieldedAssetBalance::new(
            &pxmr_class_id,
            "devnet-alice",
            80_000_000_000,
            120_000_000_000,
            "alice-pxmr-balance-blinding",
            &[
                "alice-main-view".to_string(),
                "auditor-bucket-view".to_string(),
            ],
            &json!({"lock": "none"}),
            &json!({"ciphertext": "alice-pxmr-note", "kem": CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME}),
            "",
            state.height.saturating_sub(70),
            state.height.saturating_sub(70),
            state.next_nonce(),
        )?;
        let pxmr_alice_id = pxmr_alice.balance_id.clone();
        state.insert_shielded_balance(pxmr_alice)?;

        let pxmr_bob = ShieldedAssetBalance::new(
            &pxmr_class_id,
            "devnet-bob",
            20_000_000_000,
            40_000_000_000,
            "bob-pxmr-balance-blinding",
            &["bob-main-view".to_string()],
            &json!({"lock": "none"}),
            &json!({"ciphertext": "bob-pxmr-note", "kem": CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME}),
            "",
            state.height.saturating_sub(52),
            state.height.saturating_sub(52),
            state.next_nonce(),
        )?;
        let pxmr_bob_id = pxmr_bob.balance_id.clone();
        state.insert_shielded_balance(pxmr_bob)?;

        let dusd_alice = ShieldedAssetBalance::new(
            &dusd_class_id,
            "devnet-alice",
            2_000_000_000,
            2_500_000_000,
            "alice-dusd-balance-blinding",
            &[
                "alice-main-view".to_string(),
                "stable-auditor-view".to_string(),
            ],
            &json!({"lock": "none"}),
            &json!({"ciphertext": "alice-dusd-note", "kem": CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME}),
            "",
            state.height.saturating_sub(62),
            state.height.saturating_sub(62),
            state.next_nonce(),
        )?;
        let dusd_alice_id = dusd_alice.balance_id.clone();
        state.insert_shielded_balance(dusd_alice)?;

        let pxmr_mint = ConfidentialMintBurn::new(
            &pxmr_class_id,
            &pxmr_alice_id,
            ConfidentialOperationKind::Mint,
            &pxmr_admin_id,
            "devnet-confidential-asset-issuer",
            120_000_000_000,
            "pxmr-mint-supply-blinding",
            0,
            120_000_000_000,
            &json!({"bridge_lock": "monero-devnet-lockbox", "range": "100-120-xmr"}),
            &json!({"auditor_bucket": "100-500"}),
            &json!({"signature": "pq-pxmr-mint"}),
            state.height.saturating_sub(70),
            Some(state.height.saturating_sub(69)),
            state.next_nonce(),
        )?;
        state.insert_mint_burn(pxmr_mint)?;

        let dusd_mint = ConfidentialMintBurn::new(
            &dusd_class_id,
            &dusd_alice_id,
            ConfidentialOperationKind::Mint,
            &dusd_admin_id,
            "devnet-confidential-stable-issuer",
            2_500_000_000,
            "dusd-mint-supply-blinding",
            0,
            2_500_000_000,
            &json!({"reserve": "fixture", "range": "2k-2.5k"}),
            &json!({"auditor_bucket": "stablecoin-launch"}),
            &json!({"signature": "pq-dusd-mint"}),
            state.height.saturating_sub(62),
            Some(state.height.saturating_sub(61)),
            state.next_nonce(),
        )?;
        state.insert_mint_burn(dusd_mint)?;

        if let Some(class) = state.token_classes.get_mut(&pxmr_class_id) {
            class.update_supply_commitment(
                120_000_000_000,
                0,
                "pxmr-devnet-supply",
                state.height,
            )?;
        }
        if let Some(class) = state.token_classes.get_mut(&dusd_class_id) {
            class.update_supply_commitment(2_500_000_000, 0, "dusd-devnet-supply", state.height)?;
        }

        let sponsorship = LowFeeSponsoredTransfer::new(
            &pxmr_class_id,
            "devnet-foundation-paymaster",
            "devnet-alice",
            state.config.fee_asset_id.clone(),
            state.config.default_low_fee_lane.clone(),
            500_000,
            2_500,
            state.config.low_fee_transfer_unit_cap,
            &json!({"route": "small-confidential-transfers", "min_privacy_set": 128}),
            state.height.saturating_sub(40),
            state
                .height
                .saturating_add(state.config.default_sponsorship_ttl_blocks),
            state.next_nonce(),
        )?;
        let sponsorship_id = sponsorship.sponsorship_id.clone();
        state.insert_low_fee_sponsorship(sponsorship)?;

        let transfer = ConfidentialTransferNote::new(
            &pxmr_class_id,
            vec![pxmr_alice_id.clone()],
            vec![pxmr_bob_id.clone()],
            "devnet-alice",
            &["devnet-bob".to_string()],
            ConfidentialAmountBucket::Small,
            1_250,
            "alice-bob-fee-blinding",
            "alice-bob-change-blinding",
            &json!({"memo": "devnet-private-transfer", "encrypted": true}),
            &json!({"sanctions_screen": "commitment-only", "policy": "devnet"}),
            &sponsorship_id,
            state.height.saturating_sub(30),
            state.height.saturating_add(32),
            Some(state.height.saturating_sub(29)),
            state.next_nonce(),
        )?;
        let transfer_id = transfer.transfer_id.clone();
        let input_nullifier = transfer.input_nullifier_root.clone();
        state.insert_transfer_note(transfer)?;
        state.mark_nullifier_spent(input_nullifier)?;
        if let Some(sponsor) = state.low_fee_sponsorships.get_mut(&sponsorship_id) {
            sponsor.sponsor_fee(1_250)?;
        }

        let disclosure = ComplianceViewingDisclosure::new(
            &pxmr_class_id,
            "transfer",
            &transfer_id,
            DisclosureScope::TransferTrace,
            DisclosureAudience::Auditor,
            "devnet-auditor",
            "devnet-auditor-view-key",
            &[
                "amount_bucket".to_string(),
                "class_id".to_string(),
                "settlement_height".to_string(),
            ],
            &json!({"transfer": "alice-to-bob", "bucket": "small"}),
            &json!({"redact": ["owner_labels", "exact_amount"]}),
            &json!({"basis": "devnet-audit-fixture", "ttl": state.config.default_view_grant_ttl_blocks}),
            state.height.saturating_sub(28),
            state
                .height
                .saturating_add(state.config.default_view_grant_ttl_blocks),
            state.next_nonce(),
        )?;
        state.insert_disclosure(disclosure)?;

        let amm_hook = PrivateAmmHook::new(
            &pxmr_class_id,
            "devnet-pxmr-dusd-private-amm",
            "pxmr",
            "dusd",
            &json!({"pxmr_bucket": "100-500", "dusd_bucket": "10k-50k"}),
            "constant-product-private-invariant",
            30,
            250,
            "mid",
            &[
                "devnet-private-router".to_string(),
                "devnet-intent-settlement".to_string(),
            ],
            &json!({"batching": "private-intent", "mev": "sealed"}),
            state.height.saturating_sub(24),
            state.next_nonce(),
        )?;
        state.insert_amm_hook(amm_hook)?;

        let lending_hook = LendingCollateralHook::new(
            &pxmr_class_id,
            "devnet-private-lending-market",
            6_500,
            8_000,
            "feed-pxmr-dusd-devnet",
            &json!({"health": "healthy", "bucket": "200-250-collateral-ratio"}),
            &json!({"encumbrance": "lending-collateral-note-root"}),
            &json!({"lender_view": "health-bucket-only"}),
            state.height.saturating_sub(22),
            state.height.saturating_sub(1),
            16,
            state.next_nonce(),
        )?;
        state.insert_lending_hook(lending_hook)?;

        let risk = AssetRiskControl::new(
            &pxmr_class_id,
            RiskControlScope::Class,
            &pxmr_class_id,
            RiskAction::RequireDisclosure,
            RiskSeverity::Watch,
            1_850,
            state.config.risk_pause_threshold_bps,
            &json!({"signal": "launch-monitor", "volatility": "normal"}),
            &json!({"committee": "devnet-risk", "decision": "watch"}),
            &json!({"required_scope": "transfer_trace_on_request"}),
            state.height.saturating_sub(20),
            state.height.saturating_add(240),
            state.next_nonce(),
        )?;
        state.insert_risk_control(risk)?;

        let freeze_auth = PqAssetAdminAuthorization::new(
            &pxmr_class_id,
            PqAssetAdminAction::Freeze,
            "token_class",
            &pxmr_class_id,
            "devnet-risk-council",
            &[
                "freeze-admin-ml-dsa-1".to_string(),
                "freeze-admin-ml-dsa-2".to_string(),
                "freeze-admin-slh-dsa-3".to_string(),
            ],
            &json!({"scheme": CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME, "purpose": "freeze-drill"}),
            &json!({"action": "class_freeze_drill", "scope": "pxmr"}),
            &json!({"committee": "risk-council", "decision": "approve"}),
            &json!({"aggregate_signature": "freeze-drill-signature-root"}),
            PqAuthorizationDecision::Approve,
            256,
            state.height.saturating_sub(16),
            state.height.saturating_add(360),
            state.next_nonce(),
        )?;
        let freeze_auth_root = freeze_auth.authorization_id.clone();
        state.insert_pq_admin_authorization(freeze_auth)?;

        let freeze = FreezeUnfreezeCeremony::new(
            &pxmr_class_id,
            FreezeCeremonyKind::ClassFreeze,
            "devnet-risk-council",
            "token_class",
            &pxmr_class_id,
            &json!({"reason": "scheduled freeze-unfreeze drill", "severity": "watch"}),
            &json!({"threshold": "2-of-3", "members": 3}),
            &json!({"authorization_id": freeze_auth_root}),
            &json!({"disclosure": "auditor notified"}),
            state.height.saturating_sub(14),
            state.config.default_freeze_delay_blocks,
            96,
            state.next_nonce(),
        )?;
        state.insert_freeze_ceremony(freeze)?;

        let summary = ConfidentialAssetDevnetFixture::new(
            "confidential-asset-runtime-devnet",
            "state",
            "devnet",
            &json!({
                "height": state.height,
                "classes": [&pxmr_class_id, &dusd_class_id],
                "transfer_id": transfer_id,
                "sponsorship_id": sponsorship_id,
                "state_root": state.state_root()
            }),
            state.height,
            "seeded confidential asset runtime fixture",
        )?;
        state.insert_devnet_fixture(summary)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn next_nonce(&mut self) -> u64 {
        self.nonce = self.nonce.saturating_add(1);
        self.nonce
    }

    pub fn insert_token_class(
        &mut self,
        token_class: ConfidentialTokenClass,
    ) -> ConfidentialAssetRuntimeResult<String> {
        token_class.validate()?;
        insert_unique(
            &mut self.token_classes,
            token_class.class_id.clone(),
            token_class,
            "token class",
        )
    }

    pub fn insert_shielded_balance(
        &mut self,
        balance: ShieldedAssetBalance,
    ) -> ConfidentialAssetRuntimeResult<String> {
        balance.validate()?;
        insert_unique(
            &mut self.shielded_balances,
            balance.balance_id.clone(),
            balance,
            "shielded balance",
        )
    }

    pub fn insert_mint_burn(
        &mut self,
        operation: ConfidentialMintBurn,
    ) -> ConfidentialAssetRuntimeResult<String> {
        operation.validate()?;
        insert_unique(
            &mut self.mint_burns,
            operation.operation_id.clone(),
            operation,
            "mint burn operation",
        )
    }

    pub fn insert_transfer_note(
        &mut self,
        transfer: ConfidentialTransferNote,
    ) -> ConfidentialAssetRuntimeResult<String> {
        transfer.validate()?;
        insert_unique(
            &mut self.transfer_notes,
            transfer.transfer_id.clone(),
            transfer,
            "transfer note",
        )
    }

    pub fn insert_disclosure(
        &mut self,
        disclosure: ComplianceViewingDisclosure,
    ) -> ConfidentialAssetRuntimeResult<String> {
        disclosure.validate()?;
        insert_unique(
            &mut self.disclosures,
            disclosure.disclosure_id.clone(),
            disclosure,
            "disclosure",
        )
    }

    pub fn insert_pq_admin_authorization(
        &mut self,
        authorization: PqAssetAdminAuthorization,
    ) -> ConfidentialAssetRuntimeResult<String> {
        authorization.validate()?;
        insert_unique(
            &mut self.pq_admin_authorizations,
            authorization.authorization_id.clone(),
            authorization,
            "pq admin authorization",
        )
    }

    pub fn insert_amm_hook(
        &mut self,
        hook: PrivateAmmHook,
    ) -> ConfidentialAssetRuntimeResult<String> {
        hook.validate()?;
        insert_unique(&mut self.amm_hooks, hook.hook_id.clone(), hook, "amm hook")
    }

    pub fn insert_lending_hook(
        &mut self,
        hook: LendingCollateralHook,
    ) -> ConfidentialAssetRuntimeResult<String> {
        hook.validate()?;
        insert_unique(
            &mut self.lending_hooks,
            hook.hook_id.clone(),
            hook,
            "lending hook",
        )
    }

    pub fn insert_low_fee_sponsorship(
        &mut self,
        sponsorship: LowFeeSponsoredTransfer,
    ) -> ConfidentialAssetRuntimeResult<String> {
        sponsorship.validate()?;
        insert_unique(
            &mut self.low_fee_sponsorships,
            sponsorship.sponsorship_id.clone(),
            sponsorship,
            "low fee sponsorship",
        )
    }

    pub fn insert_risk_control(
        &mut self,
        control: AssetRiskControl,
    ) -> ConfidentialAssetRuntimeResult<String> {
        control.validate()?;
        insert_unique(
            &mut self.risk_controls,
            control.control_id.clone(),
            control,
            "risk control",
        )
    }

    pub fn insert_freeze_ceremony(
        &mut self,
        ceremony: FreezeUnfreezeCeremony,
    ) -> ConfidentialAssetRuntimeResult<String> {
        ceremony.validate()?;
        insert_unique(
            &mut self.freeze_ceremonies,
            ceremony.ceremony_id.clone(),
            ceremony,
            "freeze ceremony",
        )
    }

    pub fn insert_devnet_fixture(
        &mut self,
        fixture: ConfidentialAssetDevnetFixture,
    ) -> ConfidentialAssetRuntimeResult<String> {
        fixture.validate()?;
        insert_unique(
            &mut self.devnet_fixtures,
            fixture.record_id.clone(),
            fixture,
            "devnet fixture",
        )
    }

    pub fn mark_nullifier_spent(
        &mut self,
        nullifier_root: impl Into<String>,
    ) -> ConfidentialAssetRuntimeResult<()> {
        let nullifier_root = nullifier_root.into();
        ensure_non_empty(&nullifier_root, "spent nullifier root")?;
        if !self.spent_nullifiers.insert(nullifier_root.clone()) {
            return Err(format!("spent nullifier already present: {nullifier_root}"));
        }
        Ok(())
    }

    pub fn execute_freeze_ceremony(
        &mut self,
        ceremony_id: &str,
    ) -> ConfidentialAssetRuntimeResult<String> {
        let height = self.height;
        let (kind, subject_kind, subject_id, class_id) = {
            let ceremony = self
                .freeze_ceremonies
                .get_mut(ceremony_id)
                .ok_or_else(|| format!("missing freeze ceremony: {ceremony_id}"))?;
            ceremony.execute(height)?;
            (
                ceremony.kind,
                ceremony.affected_subject_kind.clone(),
                ceremony.affected_subject_id.clone(),
                ceremony.class_id.clone(),
            )
        };
        if kind.freezes() {
            self.apply_freeze_subject(&subject_kind, &subject_id, &class_id)?;
        } else {
            self.apply_unfreeze_subject(&subject_kind, &subject_id, &class_id)?;
        }
        Ok(self.state_root())
    }

    pub fn release_freeze_ceremony(
        &mut self,
        ceremony_id: &str,
    ) -> ConfidentialAssetRuntimeResult<String> {
        let height = self.height;
        let (subject_kind, subject_id, class_id) = {
            let ceremony = self
                .freeze_ceremonies
                .get_mut(ceremony_id)
                .ok_or_else(|| format!("missing freeze ceremony: {ceremony_id}"))?;
            ceremony.release(height)?;
            (
                ceremony.affected_subject_kind.clone(),
                ceremony.affected_subject_id.clone(),
                ceremony.class_id.clone(),
            )
        };
        self.apply_unfreeze_subject(&subject_kind, &subject_id, &class_id)?;
        Ok(self.state_root())
    }

    pub fn active_class_ids(&self) -> Vec<String> {
        self.token_classes
            .values()
            .filter(|class| class.status.counts_as_active())
            .map(|class| class.class_id.clone())
            .collect::<Vec<_>>()
    }

    pub fn spendable_balance_ids(&self) -> Vec<String> {
        self.shielded_balances
            .values()
            .filter(|balance| balance.spendable_at(self.height))
            .map(|balance| balance.balance_id.clone())
            .collect::<Vec<_>>()
    }

    pub fn roots(&self) -> ConfidentialAssetRuntimeRoots {
        ConfidentialAssetRuntimeRoots {
            config_root: self.config.config_root(),
            token_class_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-TOKEN-CLASS",
                &self.token_classes,
                ConfidentialTokenClass::public_record,
            ),
            shielded_balance_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-SHIELDED-BALANCE",
                &self.shielded_balances,
                ShieldedAssetBalance::public_record,
            ),
            mint_burn_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-MINT-BURN",
                &self.mint_burns,
                ConfidentialMintBurn::public_record,
            ),
            transfer_note_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-TRANSFER-NOTE",
                &self.transfer_notes,
                ConfidentialTransferNote::public_record,
            ),
            disclosure_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-DISCLOSURE",
                &self.disclosures,
                ComplianceViewingDisclosure::public_record,
            ),
            pq_authorization_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-PQ-AUTHORIZATION",
                &self.pq_admin_authorizations,
                PqAssetAdminAuthorization::public_record,
            ),
            amm_hook_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-AMM-HOOK",
                &self.amm_hooks,
                PrivateAmmHook::public_record,
            ),
            lending_hook_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-LENDING-HOOK",
                &self.lending_hooks,
                LendingCollateralHook::public_record,
            ),
            low_fee_sponsorship_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-LOW-FEE-SPONSORSHIP",
                &self.low_fee_sponsorships,
                LowFeeSponsoredTransfer::public_record,
            ),
            risk_control_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-RISK-CONTROL",
                &self.risk_controls,
                AssetRiskControl::public_record,
            ),
            freeze_ceremony_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-FREEZE-CEREMONY",
                &self.freeze_ceremonies,
                FreezeUnfreezeCeremony::public_record,
            ),
            spent_nullifier_root: merkle_root(
                "CONFIDENTIAL-ASSET-SPENT-NULLIFIER",
                &self
                    .spent_nullifiers
                    .iter()
                    .map(|nullifier| json!({"nullifier_root": nullifier}))
                    .collect::<Vec<_>>(),
            ),
            devnet_fixture_root: merkle_from_map(
                "CONFIDENTIAL-ASSET-DEVNET-FIXTURE",
                &self.devnet_fixtures,
                ConfidentialAssetDevnetFixture::public_record,
            ),
        }
    }

    pub fn counters(&self) -> ConfidentialAssetRuntimeCounters {
        ConfidentialAssetRuntimeCounters {
            token_class_count: self.token_classes.len() as u64,
            active_token_class_count: self
                .token_classes
                .values()
                .filter(|class| class.status.counts_as_active())
                .count() as u64,
            shielded_balance_count: self.shielded_balances.len() as u64,
            open_shielded_balance_count: self
                .shielded_balances
                .values()
                .filter(|balance| balance.status.counts_as_open())
                .count() as u64,
            spendable_shielded_balance_count: self
                .shielded_balances
                .values()
                .filter(|balance| balance.spendable_at(self.height))
                .count() as u64,
            mint_operation_count: self
                .mint_burns
                .values()
                .filter(|operation| operation.kind == ConfidentialOperationKind::Mint)
                .count() as u64,
            burn_operation_count: self
                .mint_burns
                .values()
                .filter(|operation| operation.kind == ConfidentialOperationKind::Burn)
                .count() as u64,
            transfer_note_count: self.transfer_notes.len() as u64,
            live_transfer_note_count: self
                .transfer_notes
                .values()
                .filter(|transfer| transfer.is_live_at(self.height))
                .count() as u64,
            settled_transfer_note_count: self
                .transfer_notes
                .values()
                .filter(|transfer| transfer.status == ConfidentialTransferStatus::Settled)
                .count() as u64,
            disclosure_count: self.disclosures.len() as u64,
            active_disclosure_count: self
                .disclosures
                .values()
                .filter(|disclosure| disclosure.active_at(self.height))
                .count() as u64,
            pq_authorization_count: self.pq_admin_authorizations.len() as u64,
            active_pq_authorization_count: self
                .pq_admin_authorizations
                .values()
                .filter(|authorization| authorization.is_active_at(self.height))
                .count() as u64,
            amm_hook_count: self.amm_hooks.len() as u64,
            active_amm_hook_count: self
                .amm_hooks
                .values()
                .filter(|hook| hook.status.active())
                .count() as u64,
            lending_hook_count: self.lending_hooks.len() as u64,
            active_lending_hook_count: self
                .lending_hooks
                .values()
                .filter(|hook| hook.status.active() && hook.oracle_fresh_at(self.height))
                .count() as u64,
            low_fee_sponsorship_count: self.low_fee_sponsorships.len() as u64,
            active_low_fee_sponsorship_count: self
                .low_fee_sponsorships
                .values()
                .filter(|sponsorship| sponsorship.active_at(self.height))
                .count() as u64,
            risk_control_count: self.risk_controls.len() as u64,
            active_risk_control_count: self
                .risk_controls
                .values()
                .filter(|control| control.is_active_at(self.height))
                .count() as u64,
            freeze_ceremony_count: self.freeze_ceremonies.len() as u64,
            active_freeze_ceremony_count: self
                .freeze_ceremonies
                .values()
                .filter(|ceremony| ceremony.status.active())
                .count() as u64,
            spent_nullifier_count: self.spent_nullifiers.len() as u64,
            devnet_fixture_count: self.devnet_fixtures.len() as u64,
            total_supply_cap_units: self.token_classes.values().fold(0_u64, |total, class| {
                total.saturating_add(class.supply_cap_units)
            }),
            total_minted_upper_bound_units: self
                .token_classes
                .values()
                .fold(0_u64, |total, class| {
                    total.saturating_add(class.total_minted_upper_bound_units)
                }),
            total_burned_upper_bound_units: self
                .token_classes
                .values()
                .fold(0_u64, |total, class| {
                    total.saturating_add(class.total_burned_upper_bound_units)
                }),
            total_balance_upper_bound_units: self
                .shielded_balances
                .values()
                .fold(0_u64, |total, balance| {
                    total.saturating_add(balance.amount_upper_bound_units)
                }),
            sponsored_budget_units: self
                .low_fee_sponsorships
                .values()
                .fold(0_u64, |total, sponsor| {
                    total.saturating_add(sponsor.budget_units)
                }),
            sponsored_spent_units: self
                .low_fee_sponsorships
                .values()
                .fold(0_u64, |total, sponsor| {
                    total.saturating_add(sponsor.spent_units)
                }),
            max_observed_risk_score_bps: self
                .risk_controls
                .values()
                .map(AssetRiskControl::effective_score_bps)
                .max()
                .unwrap_or(0),
        }
    }

    pub fn state_root(&self) -> String {
        confidential_asset_runtime_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record
            .as_object_mut()
            .expect("confidential asset runtime public record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    pub fn validate(&self) -> ConfidentialAssetRuntimeResult<String> {
        self.config.validate()?;
        ensure_map_keys_match(&self.token_classes, |value| &value.class_id, "token class")?;
        ensure_map_keys_match(
            &self.shielded_balances,
            |value| &value.balance_id,
            "shielded balance",
        )?;
        ensure_map_keys_match(&self.mint_burns, |value| &value.operation_id, "mint burn")?;
        ensure_map_keys_match(
            &self.transfer_notes,
            |value| &value.transfer_id,
            "transfer note",
        )?;
        ensure_map_keys_match(
            &self.disclosures,
            |value| &value.disclosure_id,
            "disclosure",
        )?;
        ensure_map_keys_match(
            &self.pq_admin_authorizations,
            |value| &value.authorization_id,
            "pq authorization",
        )?;
        ensure_map_keys_match(&self.amm_hooks, |value| &value.hook_id, "amm hook")?;
        ensure_map_keys_match(&self.lending_hooks, |value| &value.hook_id, "lending hook")?;
        ensure_map_keys_match(
            &self.low_fee_sponsorships,
            |value| &value.sponsorship_id,
            "low fee sponsorship",
        )?;
        ensure_map_keys_match(
            &self.risk_controls,
            |value| &value.control_id,
            "risk control",
        )?;
        ensure_map_keys_match(
            &self.freeze_ceremonies,
            |value| &value.ceremony_id,
            "freeze ceremony",
        )?;
        ensure_map_keys_match(
            &self.devnet_fixtures,
            |value| &value.record_id,
            "devnet fixture",
        )?;

        for class in self.token_classes.values() {
            class.validate()?;
        }
        for balance in self.shielded_balances.values() {
            balance.validate()?;
            ensure_state_class(&self.token_classes, &balance.class_id, "shielded balance")?;
        }
        for operation in self.mint_burns.values() {
            operation.validate()?;
            ensure_state_class(&self.token_classes, &operation.class_id, "mint burn")?;
            ensure_state_balance(&self.shielded_balances, &operation.balance_id, "mint burn")?;
            if !operation.admin_authorization_id.is_empty()
                && !self
                    .pq_admin_authorizations
                    .contains_key(&operation.admin_authorization_id)
            {
                return Err(format!(
                    "mint burn references missing pq authorization: {}",
                    operation.admin_authorization_id
                ));
            }
        }
        for transfer in self.transfer_notes.values() {
            transfer.validate()?;
            ensure_state_class(&self.token_classes, &transfer.class_id, "transfer")?;
            if transfer.input_balance_ids.len() > self.config.max_transfer_inputs {
                return Err(format!(
                    "transfer exceeds max input count: {}",
                    transfer.transfer_id
                ));
            }
            if transfer.output_balance_ids.len() > self.config.max_transfer_outputs {
                return Err(format!(
                    "transfer exceeds max output count: {}",
                    transfer.transfer_id
                ));
            }
            for balance_id in &transfer.input_balance_ids {
                ensure_state_balance(&self.shielded_balances, balance_id, "transfer input")?;
            }
            for balance_id in &transfer.output_balance_ids {
                ensure_state_balance(&self.shielded_balances, balance_id, "transfer output")?;
            }
            if !transfer.sponsor_id.is_empty()
                && !self.low_fee_sponsorships.contains_key(&transfer.sponsor_id)
            {
                return Err(format!(
                    "transfer references missing sponsorship: {}",
                    transfer.sponsor_id
                ));
            }
        }
        for disclosure in self.disclosures.values() {
            disclosure.validate()?;
            ensure_state_class(&self.token_classes, &disclosure.class_id, "disclosure")?;
            self.ensure_subject_exists(
                &disclosure.subject_kind,
                &disclosure.subject_id,
                "disclosure",
            )?;
        }
        for authorization in self.pq_admin_authorizations.values() {
            authorization.validate()?;
            ensure_state_class(
                &self.token_classes,
                &authorization.class_id,
                "pq authorization",
            )?;
            if authorization.security_bits < self.config.min_pq_security_bits {
                return Err(format!(
                    "pq authorization below configured security floor: {}",
                    authorization.authorization_id
                ));
            }
        }
        for hook in self.amm_hooks.values() {
            hook.validate()?;
            ensure_state_class(&self.token_classes, &hook.class_id, "amm hook")?;
        }
        for hook in self.lending_hooks.values() {
            hook.validate()?;
            ensure_state_class(&self.token_classes, &hook.class_id, "lending hook")?;
        }
        for sponsorship in self.low_fee_sponsorships.values() {
            sponsorship.validate()?;
            ensure_state_class(&self.token_classes, &sponsorship.class_id, "sponsorship")?;
            if sponsorship.max_transfer_amount_units > self.config.low_fee_transfer_unit_cap {
                return Err(format!(
                    "sponsorship exceeds configured transfer cap: {}",
                    sponsorship.sponsorship_id
                ));
            }
        }
        for control in self.risk_controls.values() {
            control.validate()?;
            ensure_state_class(&self.token_classes, &control.class_id, "risk control")?;
            if !matches!(
                control.scope,
                RiskControlScope::Global | RiskControlScope::Issuer
            ) {
                self.ensure_subject_exists(&control.scope.as_str(), &control.subject_id, "risk")?;
            }
        }
        for ceremony in self.freeze_ceremonies.values() {
            ceremony.validate()?;
            ensure_state_class(&self.token_classes, &ceremony.class_id, "freeze ceremony")?;
            self.ensure_subject_exists(
                &ceremony.affected_subject_kind,
                &ceremony.affected_subject_id,
                "freeze ceremony",
            )?;
        }
        let active_freeze_ceremonies = self
            .freeze_ceremonies
            .values()
            .filter(|ceremony| ceremony.status.active())
            .count();
        if active_freeze_ceremonies > self.config.max_active_freeze_ceremonies {
            return Err("active freeze ceremonies exceed configured cap".to_string());
        }
        for nullifier in &self.spent_nullifiers {
            ensure_non_empty(nullifier, "spent nullifier")?;
        }
        for fixture in self.devnet_fixtures.values() {
            fixture.validate()?;
        }
        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_asset_runtime_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION,
            "schema_version": CONFIDENTIAL_ASSET_RUNTIME_SCHEMA_VERSION,
            "height": self.height,
            "nonce": self.nonce,
            "commitment_scheme": CONFIDENTIAL_ASSET_RUNTIME_COMMITMENT_SCHEME,
            "note_encryption_scheme": CONFIDENTIAL_ASSET_RUNTIME_NOTE_ENCRYPTION_SCHEME,
            "range_proof_scheme": CONFIDENTIAL_ASSET_RUNTIME_RANGE_PROOF_SCHEME,
            "transfer_proof_scheme": CONFIDENTIAL_ASSET_RUNTIME_TRANSFER_PROOF_SCHEME,
            "pq_admin_scheme": CONFIDENTIAL_ASSET_RUNTIME_PQ_ADMIN_SCHEME,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "root_commitment": roots.aggregate_root(),
            "counters": counters.public_record(),
            "active_class_ids": self.active_class_ids(),
            "spendable_balance_ids": self.spendable_balance_ids(),
        })
    }

    fn apply_freeze_subject(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        class_id: &str,
    ) -> ConfidentialAssetRuntimeResult<()> {
        match subject_kind {
            "token_class" | "class" => {
                let class = self
                    .token_classes
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing token class for freeze: {subject_id}"))?;
                class.set_status(AssetClassStatus::Frozen, self.height);
            }
            "balance" | "shielded_balance" => {
                let balance = self
                    .shielded_balances
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing balance for freeze: {subject_id}"))?;
                balance.freeze(self.height);
            }
            "transfer" | "transfer_note" => {
                let transfer = self
                    .transfer_notes
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing transfer for freeze: {subject_id}"))?;
                transfer.status = ConfidentialTransferStatus::Frozen;
            }
            "class_id" => {
                let class = self
                    .token_classes
                    .get_mut(class_id)
                    .ok_or_else(|| format!("missing token class for freeze: {class_id}"))?;
                class.set_status(AssetClassStatus::Frozen, self.height);
            }
            _ => return Err(format!("unsupported freeze subject kind: {subject_kind}")),
        }
        Ok(())
    }

    fn apply_unfreeze_subject(
        &mut self,
        subject_kind: &str,
        subject_id: &str,
        class_id: &str,
    ) -> ConfidentialAssetRuntimeResult<()> {
        match subject_kind {
            "token_class" | "class" => {
                let class = self
                    .token_classes
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing token class for unfreeze: {subject_id}"))?;
                class.set_status(AssetClassStatus::Active, self.height);
            }
            "balance" | "shielded_balance" => {
                let balance = self
                    .shielded_balances
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing balance for unfreeze: {subject_id}"))?;
                balance.unfreeze(self.height);
            }
            "transfer" | "transfer_note" => {
                let transfer = self
                    .transfer_notes
                    .get_mut(subject_id)
                    .ok_or_else(|| format!("missing transfer for unfreeze: {subject_id}"))?;
                transfer.status = ConfidentialTransferStatus::Admitted;
            }
            "class_id" => {
                let class = self
                    .token_classes
                    .get_mut(class_id)
                    .ok_or_else(|| format!("missing token class for unfreeze: {class_id}"))?;
                class.set_status(AssetClassStatus::Active, self.height);
            }
            _ => return Err(format!("unsupported unfreeze subject kind: {subject_kind}")),
        }
        Ok(())
    }

    fn ensure_subject_exists(
        &self,
        subject_kind: &str,
        subject_id: &str,
        label: &str,
    ) -> ConfidentialAssetRuntimeResult<()> {
        match subject_kind {
            "token_class" | "class" | "class_id" => {
                ensure_state_class(&self.token_classes, subject_id, label)
            }
            "balance" | "shielded_balance" => {
                ensure_state_balance(&self.shielded_balances, subject_id, label)
            }
            "transfer" | "transfer_note" => {
                if self.transfer_notes.contains_key(subject_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "{label} references missing transfer note: {subject_id}"
                    ))
                }
            }
            "amm_hook" => {
                if self.amm_hooks.contains_key(subject_id) {
                    Ok(())
                } else {
                    Err(format!("{label} references missing amm hook: {subject_id}"))
                }
            }
            "lending_hook" => {
                if self.lending_hooks.contains_key(subject_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "{label} references missing lending hook: {subject_id}"
                    ))
                }
            }
            "sponsor" | "sponsorship" => {
                if self.low_fee_sponsorships.contains_key(subject_id) {
                    Ok(())
                } else {
                    Err(format!(
                        "{label} references missing sponsorship: {subject_id}"
                    ))
                }
            }
            "issuer" | "global" => Ok(()),
            other => Err(format!("{label} has unsupported subject kind: {other}")),
        }
    }
}

pub fn confidential_asset_runtime_state_root_from_record(record: &Value) -> String {
    confidential_asset_runtime_payload_root("CONFIDENTIAL-ASSET-RUNTIME-STATE", record)
}

pub fn confidential_asset_runtime_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_empty_root(domain: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_string_root(domain: &str, value: &str) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-RUNTIME-STRING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(domain),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn confidential_asset_runtime_account_commitment(label: &str) -> String {
    confidential_asset_runtime_string_root("CONFIDENTIAL-ASSET-ACCOUNT", &normalize_label(label))
}

pub fn confidential_asset_runtime_amount_commitment(
    kind: &str,
    upper_bound_units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_ASSET_RUNTIME_PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Int(upper_bound_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_range_proof_root(
    amount_commitment: &str,
    upper_bound_units: u64,
    statement_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-RANGE-PROOF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(CONFIDENTIAL_ASSET_RUNTIME_RANGE_PROOF_SCHEME),
            HashPart::Str(amount_commitment),
            HashPart::Int(upper_bound_units as i128),
            HashPart::Str(statement_root),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_token_class_id(
    symbol_commitment: &str,
    issuer_commitment: &str,
    metadata_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-TOKEN-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(symbol_commitment),
            HashPart::Str(issuer_commitment),
            HashPart::Str(metadata_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_balance_id(
    class_id: &str,
    owner_commitment: &str,
    balance_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-BALANCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(balance_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_balance_nullifier_root(
    class_id: &str,
    owner_commitment: &str,
    balance_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-BALANCE-NULLIFIER",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(owner_commitment),
            HashPart::Str(balance_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_mint_burn_id(
    class_id: &str,
    balance_id: &str,
    kind: ConfidentialOperationKind,
    amount_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-MINT-BURN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(balance_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(amount_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_transfer_id(
    class_id: &str,
    input_nullifier_root: &str,
    output_commitment_root: &str,
    fee_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-TRANSFER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(input_nullifier_root),
            HashPart::Str(output_commitment_root),
            HashPart::Str(fee_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_disclosure_id(
    class_id: &str,
    subject_kind: &str,
    subject_id: &str,
    scope: DisclosureScope,
    viewer_commitment: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-DISCLOSURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(viewer_commitment),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_pq_authorization_id(
    class_id: &str,
    action: PqAssetAdminAction,
    subject_kind: &str,
    subject_id: &str,
    admin_commitment: &str,
    payload_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-PQ-AUTHORIZATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(action.as_str()),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(admin_commitment),
            HashPart::Str(payload_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_hook_id(
    hook_kind: &str,
    class_id: &str,
    hook_commitment: &str,
    payload_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(hook_kind),
            HashPart::Str(class_id),
            HashPart::Str(hook_commitment),
            HashPart::Str(payload_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_sponsorship_id(
    class_id: &str,
    sponsor_commitment: &str,
    beneficiary_commitment: &str,
    lane_id: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(beneficiary_commitment),
            HashPart::Str(lane_id),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_risk_control_id(
    class_id: &str,
    scope: RiskControlScope,
    subject_id: &str,
    action: RiskAction,
    evidence_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-RISK-CONTROL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(action.as_str()),
            HashPart::Str(evidence_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_freeze_ceremony_id(
    class_id: &str,
    kind: FreezeCeremonyKind,
    subject_kind: &str,
    subject_id: &str,
    authorization_root: &str,
    nonce: u64,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-FREEZE-CEREMONY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_kind),
            HashPart::Str(subject_id),
            HashPart::Str(authorization_root),
            HashPart::Int(nonce as i128),
        ],
        32,
    )
}

pub fn confidential_asset_runtime_devnet_fixture_id(
    label: &str,
    object_kind: &str,
    object_id: &str,
    payload_root: &str,
) -> String {
    domain_hash(
        "CONFIDENTIAL-ASSET-DEVNET-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(object_kind),
            HashPart::Str(object_id),
            HashPart::Str(payload_root),
        ],
        32,
    )
}

fn merkle_from_map<T, F>(domain: &str, values: &BTreeMap<String, T>, mapper: F) -> String
where
    F: Fn(&T) -> Value,
{
    let records = values.values().map(mapper).collect::<Vec<_>>();
    merkle_root(domain, &records)
}

fn normalize_label(value: impl AsRef<str>) -> String {
    value
        .as_ref()
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':') {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn ensure_non_empty(value: &str, label: &str) -> ConfidentialAssetRuntimeResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_bps(label: &str, value: u64, max: u64) -> ConfidentialAssetRuntimeResult<()> {
    if value > max {
        Err(format!("{label} exceeds {max} bps"))
    } else {
        Ok(())
    }
}

fn ensure_state_class(
    classes: &BTreeMap<String, ConfidentialTokenClass>,
    class_id: &str,
    label: &str,
) -> ConfidentialAssetRuntimeResult<()> {
    if classes.contains_key(class_id) {
        Ok(())
    } else {
        Err(format!(
            "{label} references missing token class: {class_id}"
        ))
    }
}

fn ensure_state_balance(
    balances: &BTreeMap<String, ShieldedAssetBalance>,
    balance_id: &str,
    label: &str,
) -> ConfidentialAssetRuntimeResult<()> {
    if balances.contains_key(balance_id) {
        Ok(())
    } else {
        Err(format!(
            "{label} references missing shielded balance: {balance_id}"
        ))
    }
}

fn ensure_map_keys_match<T, F>(
    map: &BTreeMap<String, T>,
    id: F,
    label: &str,
) -> ConfidentialAssetRuntimeResult<()>
where
    F: Fn(&T) -> &String,
{
    for (key, value) in map {
        if key != id(value) {
            return Err(format!("{label} map key mismatch: {key}"));
        }
    }
    Ok(())
}

fn insert_unique<T>(
    map: &mut BTreeMap<String, T>,
    key: String,
    value: T,
    label: &str,
) -> ConfidentialAssetRuntimeResult<String> {
    if map.contains_key(&key) {
        return Err(format!("duplicate {label}: {key}"));
    }
    map.insert(key.clone(), value);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_fixture_validates_and_has_stable_root() {
        let state = ConfidentialAssetRuntimeState::devnet().expect("devnet fixture");
        let first_root = state.state_root();
        state.validate().expect("devnet validation");
        assert_eq!(first_root, state.state_root());
        assert!(state.counters().token_class_count >= 2);
        assert!(state.counters().transfer_note_count >= 1);
    }
}
