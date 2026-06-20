use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenRegistryResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION: &str = "nebula-private-token-registry-v1";
pub const PRIVATE_TOKEN_REGISTRY_METADATA_SCHEME: &str = "shake256-confidential-token-metadata-v1";
pub const PRIVATE_TOKEN_REGISTRY_ABI_SCHEME: &str = "canonical-json-private-contract-abi-v1";
pub const PRIVATE_TOKEN_REGISTRY_PQ_KEY_SCHEME: &str =
    "ml-kem-1024+ml-dsa-87+slh-dsa-shake-256f-devnet";
pub const PRIVATE_TOKEN_REGISTRY_PERMISSION_SCHEME: &str = "shielded-mint-burn-permission-root-v1";
pub const PRIVATE_TOKEN_REGISTRY_UPGRADE_SCHEME: &str = "pq-governed-contract-upgrade-root-v1";
pub const PRIVATE_TOKEN_REGISTRY_TRANSFER_HOOK_SCHEME: &str = "private-transfer-hook-proof-root-v1";
pub const PRIVATE_TOKEN_REGISTRY_DISCLOSURE_SCHEME: &str =
    "privacy-preserving-selective-disclosure-root-v1";
pub const PRIVATE_TOKEN_REGISTRY_SPONSORSHIP_SCHEME: &str =
    "low-fee-private-issuance-sponsorship-v1";
pub const PRIVATE_TOKEN_REGISTRY_INCENTIVE_SCHEME: &str =
    "private-liquidity-incentive-commitment-v1";
pub const PRIVATE_TOKEN_REGISTRY_AUDIT_SCHEME: &str = "private-token-audit-receipt-v1";
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_LOW_FEE_LANE: &str = "private_token_issuance";
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_DEFI_VENUE: &str = "devnet-private-amm";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_HEIGHT: u64 = 96;
pub const PRIVATE_TOKEN_REGISTRY_MAX_BPS: u64 = 10_000;
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_PERMISSION_EPOCH_BLOCKS: u64 = 720;
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_DISCLOSURE_EPOCH_BLOCKS: u64 = 2_880;
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 10_080;
pub const PRIVATE_TOKEN_REGISTRY_DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 144;
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_WXMR_SYMBOL: &str = "pXMR";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_USDD_SYMBOL: &str = "pUSD";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_LP_SYMBOL: &str = "pXMRpUSDLP";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_GOVERNANCE_LABEL: &str = "devnet-private-token-governance";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_BRIDGE_LABEL: &str = "devnet-monero-bridge-issuer";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL: &str = "devnet-private-defi-issuer";
pub const PRIVATE_TOKEN_REGISTRY_DEVNET_AUDITOR_LABEL: &str = "devnet-threshold-auditor-set";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenClassKind {
    WrappedMonero,
    StableAsset,
    Governance,
    Utility,
    LiquidityShare,
    VaultShare,
    Derivative,
    OracleReceipt,
    Custom(String),
}

impl PrivateTokenClassKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::WrappedMonero => "wrapped_monero".to_string(),
            Self::StableAsset => "stable_asset".to_string(),
            Self::Governance => "governance".to_string(),
            Self::Utility => "utility".to_string(),
            Self::LiquidityShare => "liquidity_share".to_string(),
            Self::VaultShare => "vault_share".to_string(),
            Self::Derivative => "derivative".to_string(),
            Self::OracleReceipt => "oracle_receipt".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn supports_defi(&self) -> bool {
        matches!(
            self,
            Self::WrappedMonero
                | Self::StableAsset
                | Self::LiquidityShare
                | Self::VaultShare
                | Self::Derivative
                | Self::Utility
                | Self::Custom(_)
        )
    }

    pub fn is_liquidity_share(&self) -> bool {
        matches!(self, Self::LiquidityShare | Self::VaultShare)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_class_kind",
            "chain_id": CHAIN_ID,
            "class_kind": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialSupplyMode {
    Fixed,
    ShieldedMintBurn,
    CappedShieldedMintBurn,
    BridgeMintBurn,
    PoolShare,
    VaultReceipt,
    ContractControlled,
}

impl ConfidentialSupplyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::ShieldedMintBurn => "shielded_mint_burn",
            Self::CappedShieldedMintBurn => "capped_shielded_mint_burn",
            Self::BridgeMintBurn => "bridge_mint_burn",
            Self::PoolShare => "pool_share",
            Self::VaultReceipt => "vault_receipt",
            Self::ContractControlled => "contract_controlled",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(
            self,
            Self::ShieldedMintBurn
                | Self::CappedShieldedMintBurn
                | Self::BridgeMintBurn
                | Self::PoolShare
                | Self::VaultReceipt
                | Self::ContractControlled
        )
    }

    pub fn allows_burn(&self) -> bool {
        matches!(
            self,
            Self::ShieldedMintBurn
                | Self::CappedShieldedMintBurn
                | Self::BridgeMintBurn
                | Self::PoolShare
                | Self::VaultReceipt
                | Self::ContractControlled
        )
    }

    pub fn requires_reserve_root(&self) -> bool {
        matches!(self, Self::BridgeMintBurn | Self::VaultReceipt)
    }

    pub fn is_capped(&self) -> bool {
        matches!(self, Self::Fixed | Self::CappedShieldedMintBurn)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryLifecycleStatus {
    Draft,
    Active,
    Paused,
    Frozen,
    Deprecated,
    Retired,
}

impl RegistryLifecycleStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Deprecated => "deprecated",
            Self::Retired => "retired",
        }
    }

    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Retired)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionScope {
    Mint,
    Burn,
    SponsorIssue,
    UpgradeContract,
    ListOnDex,
    AttachHook,
    DiscloseView,
    AuditRead,
    Custom(String),
}

impl PermissionScope {
    pub fn as_str(&self) -> String {
        match self {
            Self::Mint => "mint".to_string(),
            Self::Burn => "burn".to_string(),
            Self::SponsorIssue => "sponsor_issue".to_string(),
            Self::UpgradeContract => "upgrade_contract".to_string(),
            Self::ListOnDex => "list_on_dex".to_string(),
            Self::AttachHook => "attach_hook".to_string(),
            Self::DiscloseView => "disclose_view".to_string(),
            Self::AuditRead => "audit_read".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn is_mint(&self) -> bool {
        matches!(self, Self::Mint)
    }

    pub fn is_burn(&self) -> bool {
        matches!(self, Self::Burn)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqGovernanceModel {
    MultiSig,
    Council,
    TokenVote,
    Timelock,
    Emergency,
    Hybrid,
    Custom(String),
}

impl PqGovernanceModel {
    pub fn as_str(&self) -> String {
        match self {
            Self::MultiSig => "multi_sig".to_string(),
            Self::Council => "council".to_string(),
            Self::TokenVote => "token_vote".to_string(),
            Self::Timelock => "timelock".to_string(),
            Self::Emergency => "emergency".to_string(),
            Self::Hybrid => "hybrid".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn requires_timelock(&self) -> bool {
        matches!(self, Self::TokenVote | Self::Timelock | Self::Hybrid)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiVenueKind {
    AmmPool,
    StableSwap,
    LendingMarket,
    PerpMarket,
    OptionsVault,
    Router,
    Oracle,
    Custom(String),
}

impl DefiVenueKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::AmmPool => "amm_pool".to_string(),
            Self::StableSwap => "stable_swap".to_string(),
            Self::LendingMarket => "lending_market".to_string(),
            Self::PerpMarket => "perp_market".to_string(),
            Self::OptionsVault => "options_vault".to_string(),
            Self::Router => "router".to_string(),
            Self::Oracle => "oracle".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListingPermission {
    PermissionlessWithProofs,
    Curated,
    GovernanceApproved,
    Restricted,
    Deprecated,
}

impl ListingPermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PermissionlessWithProofs => "permissionless_with_proofs",
            Self::Curated => "curated",
            Self::GovernanceApproved => "governance_approved",
            Self::Restricted => "restricted",
            Self::Deprecated => "deprecated",
        }
    }

    pub fn requires_governance(&self) -> bool {
        matches!(self, Self::GovernanceApproved | Self::Restricted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferHookPhase {
    BeforeMint,
    AfterMint,
    BeforeBurn,
    AfterBurn,
    BeforeTransfer,
    AfterTransfer,
    BeforeSwap,
    AfterSwap,
    BeforeLiquidation,
    AfterLiquidation,
}

impl TransferHookPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BeforeMint => "before_mint",
            Self::AfterMint => "after_mint",
            Self::BeforeBurn => "before_burn",
            Self::AfterBurn => "after_burn",
            Self::BeforeTransfer => "before_transfer",
            Self::AfterTransfer => "after_transfer",
            Self::BeforeSwap => "before_swap",
            Self::AfterSwap => "after_swap",
            Self::BeforeLiquidation => "before_liquidation",
            Self::AfterLiquidation => "after_liquidation",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceDisclosureMode {
    None,
    ZkAttestation,
    ViewKeyEscrow,
    ThresholdDisclosure,
    RegulatorEnvelope,
    AuditOnly,
    Custom(String),
}

impl ComplianceDisclosureMode {
    pub fn as_str(&self) -> String {
        match self {
            Self::None => "none".to_string(),
            Self::ZkAttestation => "zk_attestation".to_string(),
            Self::ViewKeyEscrow => "view_key_escrow".to_string(),
            Self::ThresholdDisclosure => "threshold_disclosure".to_string(),
            Self::RegulatorEnvelope => "regulator_envelope".to_string(),
            Self::AuditOnly => "audit_only".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn preserves_default_privacy(&self) -> bool {
        matches!(
            self,
            Self::None
                | Self::ZkAttestation
                | Self::ViewKeyEscrow
                | Self::ThresholdDisclosure
                | Self::AuditOnly
                | Self::Custom(_)
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateTokenRiskFlag {
    ExperimentalAbi,
    CentralizedIssuer,
    UpgradePending,
    WeakPqQuorum,
    LowLiquidity,
    DisclosureCapExceeded,
    SponsorExhausted,
    HookPaused,
    ListingRestricted,
    ReserveAttestationStale,
    Custom(String),
}

impl PrivateTokenRiskFlag {
    pub fn as_str(&self) -> String {
        match self {
            Self::ExperimentalAbi => "experimental_abi".to_string(),
            Self::CentralizedIssuer => "centralized_issuer".to_string(),
            Self::UpgradePending => "upgrade_pending".to_string(),
            Self::WeakPqQuorum => "weak_pq_quorum".to_string(),
            Self::LowLiquidity => "low_liquidity".to_string(),
            Self::DisclosureCapExceeded => "disclosure_cap_exceeded".to_string(),
            Self::SponsorExhausted => "sponsor_exhausted".to_string(),
            Self::HookPaused => "hook_paused".to_string(),
            Self::ListingRestricted => "listing_restricted".to_string(),
            Self::ReserveAttestationStale => "reserve_attestation_stale".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }

    pub fn blocks_low_fee(&self) -> bool {
        matches!(
            self,
            Self::WeakPqQuorum
                | Self::SponsorExhausted
                | Self::HookPaused
                | Self::ReserveAttestationStale
        )
    }

    pub fn blocks_defi_listing(&self) -> bool {
        matches!(
            self,
            Self::WeakPqQuorum
                | Self::HookPaused
                | Self::ListingRestricted
                | Self::ReserveAttestationStale
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditReceiptKind {
    GenesisIssue,
    PolicyUpdate,
    UpgradeApproved,
    HookAttached,
    ListingApproved,
    MintPermissionGranted,
    BurnPermissionGranted,
    DisclosureOpened,
    SponsorFunded,
    IncentiveFunded,
    SupplyOperation,
    Custom(String),
}

impl AuditReceiptKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::GenesisIssue => "genesis_issue".to_string(),
            Self::PolicyUpdate => "policy_update".to_string(),
            Self::UpgradeApproved => "upgrade_approved".to_string(),
            Self::HookAttached => "hook_attached".to_string(),
            Self::ListingApproved => "listing_approved".to_string(),
            Self::MintPermissionGranted => "mint_permission_granted".to_string(),
            Self::BurnPermissionGranted => "burn_permission_granted".to_string(),
            Self::DisclosureOpened => "disclosure_opened".to_string(),
            Self::SponsorFunded => "sponsor_funded".to_string(),
            Self::IncentiveFunded => "incentive_funded".to_string(),
            Self::SupplyOperation => "supply_operation".to_string(),
            Self::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeySet {
    pub key_set_id: String,
    pub owner_label: String,
    pub ml_kem_root: String,
    pub ml_dsa_root: String,
    pub slh_dsa_root: String,
    pub hybrid_transcript_root: String,
    pub threshold: u16,
    pub rotation_height: u64,
    pub expires_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl PqKeySet {
    pub fn devnet(owner_label: &str, threshold: u16, height: u64) -> Self {
        let normalized = normalize_label(owner_label);
        let ml_kem_root = private_token_string_root("PRIVATE-TOKEN-PQ-ML-KEM", &normalized);
        let ml_dsa_root = private_token_string_root("PRIVATE-TOKEN-PQ-ML-DSA", &normalized);
        let slh_dsa_root = private_token_string_root("PRIVATE-TOKEN-PQ-SLH-DSA", &normalized);
        let hybrid_transcript_root =
            private_token_string_root("PRIVATE-TOKEN-PQ-HYBRID-TRANSCRIPT", &normalized);
        let key_set_id = private_token_pq_key_set_id(
            &normalized,
            &ml_kem_root,
            &ml_dsa_root,
            &slh_dsa_root,
            threshold,
            height,
        );
        Self {
            key_set_id,
            owner_label: normalized,
            ml_kem_root,
            ml_dsa_root,
            slh_dsa_root,
            hybrid_transcript_root,
            threshold,
            rotation_height: height,
            expires_at_height: height.saturating_add(52_560),
            status: RegistryLifecycleStatus::Active,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_key_set",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "key_scheme": PRIVATE_TOKEN_REGISTRY_PQ_KEY_SCHEME,
            "key_set_id": self.key_set_id,
            "owner_label": self.owner_label,
            "ml_kem_root": self.ml_kem_root,
            "ml_dsa_root": self.ml_dsa_root,
            "slh_dsa_root": self.slh_dsa_root,
            "hybrid_transcript_root": self.hybrid_transcript_root,
            "threshold": self.threshold,
            "rotation_height": self.rotation_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn key_root(&self) -> String {
        private_token_pq_key_set_root(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.rotation_height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.key_set_id, "PQ key set id")?;
        validate_non_empty(&self.owner_label, "PQ key set owner")?;
        validate_non_empty(&self.ml_kem_root, "PQ ML-KEM root")?;
        validate_non_empty(&self.ml_dsa_root, "PQ ML-DSA root")?;
        validate_non_empty(&self.slh_dsa_root, "PQ SLH-DSA root")?;
        validate_non_empty(&self.hybrid_transcript_root, "PQ hybrid transcript root")?;
        if self.threshold == 0 {
            return Err("PQ key set threshold must be positive".to_string());
        }
        if self.expires_at_height < self.rotation_height {
            return Err("PQ key set expiry precedes rotation".to_string());
        }
        let expected = private_token_pq_key_set_id(
            &self.owner_label,
            &self.ml_kem_root,
            &self.ml_dsa_root,
            &self.slh_dsa_root,
            self.threshold,
            self.rotation_height,
        );
        if self.key_set_id != expected {
            return Err("PQ key set id mismatch".to_string());
        }
        Ok(self.key_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryMetadataCommitment {
    pub schema_version: String,
    pub metadata_root: String,
    pub display_name_commitment: String,
    pub symbol_commitment: String,
    pub uri_commitment: String,
    pub icon_commitment: String,
    pub docs_commitment: String,
    pub audit_commitment: String,
    pub tags: BTreeSet<String>,
    pub confidentiality_level: String,
}

impl RegistryMetadataCommitment {
    pub fn from_metadata(
        symbol: &str,
        display_name: &str,
        metadata: &Value,
        blinding_label: &str,
    ) -> Self {
        let normalized_symbol = normalize_symbol(symbol);
        let normalized_display = display_name.trim().to_string();
        let uri = metadata_string(metadata, "uri");
        let icon = metadata_string(metadata, "icon");
        let docs = metadata_string(metadata, "docs");
        let audit = metadata_string(metadata, "audit");
        let mut tags = BTreeSet::new();
        if let Some(values) = metadata.get("tags").and_then(Value::as_array) {
            for tag in values {
                if let Some(label) = tag.as_str() {
                    let normalized = normalize_label(label);
                    if !normalized.is_empty() {
                        tags.insert(normalized);
                    }
                }
            }
        }
        Self {
            schema_version: PRIVATE_TOKEN_REGISTRY_METADATA_SCHEME.to_string(),
            metadata_root: private_token_payload_root(
                "PRIVATE-TOKEN-METADATA",
                metadata,
                blinding_label,
            ),
            display_name_commitment: private_token_string_root(
                "PRIVATE-TOKEN-METADATA-DISPLAY",
                &normalized_display,
            ),
            symbol_commitment: private_token_string_root(
                "PRIVATE-TOKEN-METADATA-SYMBOL",
                &normalized_symbol,
            ),
            uri_commitment: private_token_string_root("PRIVATE-TOKEN-METADATA-URI", &uri),
            icon_commitment: private_token_string_root("PRIVATE-TOKEN-METADATA-ICON", &icon),
            docs_commitment: private_token_string_root("PRIVATE-TOKEN-METADATA-DOCS", &docs),
            audit_commitment: private_token_string_root("PRIVATE-TOKEN-METADATA-AUDIT", &audit),
            tags,
            confidentiality_level: "public-commitments-private-descriptors".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_metadata_commitment",
            "chain_id": CHAIN_ID,
            "schema_version": self.schema_version,
            "metadata_root": self.metadata_root,
            "display_name_commitment": self.display_name_commitment,
            "symbol_commitment": self.symbol_commitment,
            "uri_commitment": self.uri_commitment,
            "icon_commitment": self.icon_commitment,
            "docs_commitment": self.docs_commitment,
            "audit_commitment": self.audit_commitment,
            "tags": self.tags,
            "confidentiality_level": self.confidentiality_level,
        })
    }

    pub fn commitment_root(&self) -> String {
        private_token_metadata_commitment_root(self)
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.schema_version, "metadata schema version")?;
        validate_non_empty(&self.metadata_root, "metadata root")?;
        validate_non_empty(&self.display_name_commitment, "metadata display commitment")?;
        validate_non_empty(&self.symbol_commitment, "metadata symbol commitment")?;
        validate_non_empty(
            &self.confidentiality_level,
            "metadata confidentiality level",
        )?;
        Ok(self.commitment_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenClass {
    pub class_id: String,
    pub symbol: String,
    pub display_name: String,
    pub decimals: u8,
    pub class_kind: PrivateTokenClassKind,
    pub supply_mode: ConfidentialSupplyMode,
    pub issuer_id: String,
    pub issuer_root: String,
    pub governance_proposal_id: String,
    pub metadata: RegistryMetadataCommitment,
    pub pq_key_set_id: String,
    pub pq_key_root: String,
    pub abi_manifest_id: String,
    pub abi_root: String,
    pub compliance_policy_id: String,
    pub compliance_policy_root: String,
    pub mint_permission_root: String,
    pub burn_permission_root: String,
    pub transfer_hook_root: String,
    pub defi_listing_root: String,
    pub sponsorship_id: String,
    pub sponsorship_root: String,
    pub incentive_id: String,
    pub incentive_root: String,
    pub current_supply_commitment: String,
    pub supply_cap_commitment: String,
    pub reserve_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: RegistryLifecycleStatus,
    pub risk_flags: BTreeSet<PrivateTokenRiskFlag>,
}

impl PrivateTokenClass {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: &str,
        display_name: &str,
        decimals: u8,
        class_kind: PrivateTokenClassKind,
        supply_mode: ConfidentialSupplyMode,
        issuer_id: &str,
        issuer_root: &str,
        metadata: &Value,
        metadata_blinding: &str,
        pq_key_set_id: &str,
        pq_key_root: &str,
        supply_cap_units: u64,
        reserve_label: &str,
        created_at_height: u64,
        governance_proposal_id: &str,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(symbol, "private token symbol")?;
        validate_non_empty(display_name, "private token display name")?;
        validate_non_empty(issuer_id, "private token issuer")?;
        validate_non_empty(issuer_root, "private token issuer root")?;
        validate_non_empty(pq_key_set_id, "private token PQ key set")?;
        validate_non_empty(pq_key_root, "private token PQ key root")?;
        validate_non_empty(governance_proposal_id, "private token genesis proposal")?;
        let normalized_symbol = normalize_symbol(symbol);
        validate_non_empty(&normalized_symbol, "normalized private token symbol")?;
        let normalized_name = display_name.trim().to_string();
        let metadata = RegistryMetadataCommitment::from_metadata(
            &normalized_symbol,
            &normalized_name,
            metadata,
            metadata_blinding,
        );
        let metadata_root = metadata.commitment_root();
        let kind = class_kind.as_str();
        let supply = supply_mode.as_str();
        let class_id = private_token_class_id(
            &normalized_symbol,
            decimals,
            &kind,
            supply,
            issuer_root,
            &metadata_root,
            created_at_height,
            governance_proposal_id,
        );
        let current_supply_commitment =
            private_token_amount_commitment(&class_id, 0, "current-supply-genesis");
        let supply_cap_commitment =
            private_token_amount_commitment(&class_id, supply_cap_units, "supply-cap");
        let reserve_root = private_token_string_root("PRIVATE-TOKEN-RESERVE", reserve_label);
        Ok(Self {
            class_id,
            symbol: normalized_symbol,
            display_name: normalized_name,
            decimals,
            class_kind,
            supply_mode,
            issuer_id: issuer_id.to_string(),
            issuer_root: issuer_root.to_string(),
            governance_proposal_id: governance_proposal_id.to_string(),
            metadata,
            pq_key_set_id: pq_key_set_id.to_string(),
            pq_key_root: pq_key_root.to_string(),
            abi_manifest_id: String::new(),
            abi_root: private_token_empty_root("PRIVATE-TOKEN-ABI"),
            compliance_policy_id: String::new(),
            compliance_policy_root: private_token_empty_root("PRIVATE-TOKEN-COMPLIANCE"),
            mint_permission_root: private_token_empty_root("PRIVATE-TOKEN-MINT-PERMISSION"),
            burn_permission_root: private_token_empty_root("PRIVATE-TOKEN-BURN-PERMISSION"),
            transfer_hook_root: private_token_empty_root("PRIVATE-TOKEN-TRANSFER-HOOK"),
            defi_listing_root: private_token_empty_root("PRIVATE-TOKEN-DEFI-LISTING"),
            sponsorship_id: String::new(),
            sponsorship_root: private_token_empty_root("PRIVATE-TOKEN-SPONSORSHIP"),
            incentive_id: String::new(),
            incentive_root: private_token_empty_root("PRIVATE-TOKEN-INCENTIVE"),
            current_supply_commitment,
            supply_cap_commitment,
            reserve_root,
            created_at_height,
            updated_at_height: created_at_height,
            status: RegistryLifecycleStatus::Draft,
            risk_flags: BTreeSet::new(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_class",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "class_id": self.class_id,
            "symbol": self.symbol,
            "display_name": self.display_name,
            "decimals": self.decimals,
            "class_kind": self.class_kind.as_str(),
            "supply_mode": self.supply_mode.as_str(),
            "issuer_id": self.issuer_id,
            "issuer_root": self.issuer_root,
            "governance_proposal_id": self.governance_proposal_id,
            "metadata": self.metadata.public_record(),
            "metadata_root": self.metadata.commitment_root(),
            "pq_key_set_id": self.pq_key_set_id,
            "pq_key_root": self.pq_key_root,
            "abi_manifest_id": self.abi_manifest_id,
            "abi_root": self.abi_root,
            "compliance_policy_id": self.compliance_policy_id,
            "compliance_policy_root": self.compliance_policy_root,
            "mint_permission_root": self.mint_permission_root,
            "burn_permission_root": self.burn_permission_root,
            "transfer_hook_root": self.transfer_hook_root,
            "defi_listing_root": self.defi_listing_root,
            "sponsorship_id": self.sponsorship_id,
            "sponsorship_root": self.sponsorship_root,
            "incentive_id": self.incentive_id,
            "incentive_root": self.incentive_root,
            "current_supply_commitment": self.current_supply_commitment,
            "supply_cap_commitment": self.supply_cap_commitment,
            "reserve_root": self.reserve_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status.as_str(),
            "risk_flags": risk_flags_public(&self.risk_flags),
            "low_fee_ready": self.low_fee_ready(),
            "defi_ready": self.defi_ready(),
        })
    }

    pub fn class_root(&self) -> String {
        private_token_class_root(self)
    }

    pub fn low_fee_ready(&self) -> bool {
        self.status.is_active()
            && !self.sponsorship_id.is_empty()
            && !self
                .risk_flags
                .iter()
                .any(PrivateTokenRiskFlag::blocks_low_fee)
    }

    pub fn defi_ready(&self) -> bool {
        self.status.is_active()
            && self.class_kind.supports_defi()
            && !self
                .risk_flags
                .iter()
                .any(PrivateTokenRiskFlag::blocks_defi_listing)
            && self.defi_listing_root != private_token_empty_root("PRIVATE-TOKEN-DEFI-LISTING")
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.class_id, "private token class id")?;
        validate_non_empty(&self.symbol, "private token symbol")?;
        validate_non_empty(&self.display_name, "private token display name")?;
        validate_non_empty(&self.issuer_id, "private token issuer")?;
        validate_non_empty(&self.issuer_root, "private token issuer root")?;
        validate_non_empty(
            &self.governance_proposal_id,
            "private token governance proposal",
        )?;
        validate_non_empty(&self.pq_key_set_id, "private token PQ key set")?;
        validate_non_empty(&self.pq_key_root, "private token PQ key root")?;
        validate_non_empty(
            &self.current_supply_commitment,
            "private token supply commitment",
        )?;
        validate_non_empty(
            &self.supply_cap_commitment,
            "private token supply cap commitment",
        )?;
        validate_non_empty(&self.reserve_root, "private token reserve root")?;
        self.metadata.validate()?;
        let kind = self.class_kind.as_str();
        let expected = private_token_class_id(
            &self.symbol,
            self.decimals,
            &kind,
            self.supply_mode.as_str(),
            &self.issuer_root,
            &self.metadata.commitment_root(),
            self.created_at_height,
            &self.governance_proposal_id,
        );
        if self.class_id != expected {
            return Err("private token class id mismatch".to_string());
        }
        if self.status.is_active() {
            validate_non_empty(&self.abi_manifest_id, "active private token ABI manifest")?;
            validate_non_empty(
                &self.compliance_policy_id,
                "active private token compliance policy",
            )?;
        }
        if self.supply_mode.requires_reserve_root()
            && self.reserve_root == private_token_empty_root("PRIVATE-TOKEN-RESERVE")
        {
            return Err("private token reserve-backed class needs reserve root".to_string());
        }
        Ok(self.class_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedMintBurnPermission {
    pub permission_id: String,
    pub class_id: String,
    pub controller_commitment: String,
    pub controller_key_root: String,
    pub scope: PermissionScope,
    pub note_commitment_root: String,
    pub proof_system: String,
    pub max_amount_per_epoch_commitment: String,
    pub epoch_window_blocks: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub grant_proposal_id: String,
    pub revoked_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl ShieldedMintBurnPermission {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        controller_label: &str,
        controller_key_root: &str,
        scope: PermissionScope,
        max_amount_per_epoch_units: u64,
        epoch_window_blocks: u64,
        valid_from_height: u64,
        expires_at_height: u64,
        grant_proposal_id: &str,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "permission class id")?;
        validate_non_empty(controller_label, "permission controller")?;
        validate_non_empty(controller_key_root, "permission controller key root")?;
        validate_non_empty(grant_proposal_id, "permission proposal")?;
        if !scope.is_mint() && !scope.is_burn() {
            return Err("shielded mint/burn permission must be mint or burn scoped".to_string());
        }
        if epoch_window_blocks == 0 {
            return Err("permission epoch window must be positive".to_string());
        }
        if expires_at_height <= valid_from_height {
            return Err("permission expiry must be after valid-from height".to_string());
        }
        let controller_commitment =
            private_token_string_root("PRIVATE-TOKEN-PERMISSION-CONTROLLER", controller_label);
        let scope_label = scope.as_str();
        let note_commitment_root = domain_hash(
            "PRIVATE-TOKEN-PERMISSION-NOTE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(class_id),
                HashPart::Str(&controller_commitment),
                HashPart::Str(&scope_label),
                HashPart::Str(grant_proposal_id),
            ],
            32,
        );
        let max_amount_per_epoch_commitment = private_token_amount_commitment(
            class_id,
            max_amount_per_epoch_units,
            &format!("permission-{scope_label}-{controller_label}"),
        );
        let permission_id = private_token_permission_id(
            class_id,
            &controller_commitment,
            &scope_label,
            &note_commitment_root,
            valid_from_height,
            grant_proposal_id,
        );
        Ok(Self {
            permission_id,
            class_id: class_id.to_string(),
            controller_commitment,
            controller_key_root: controller_key_root.to_string(),
            scope,
            note_commitment_root,
            proof_system: PRIVATE_TOKEN_REGISTRY_PERMISSION_SCHEME.to_string(),
            max_amount_per_epoch_commitment,
            epoch_window_blocks,
            valid_from_height,
            expires_at_height,
            grant_proposal_id: grant_proposal_id.to_string(),
            revoked_at_height: 0,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_mint_burn_permission",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "permission_id": self.permission_id,
            "class_id": self.class_id,
            "controller_commitment": self.controller_commitment,
            "controller_key_root": self.controller_key_root,
            "scope": self.scope.as_str(),
            "note_commitment_root": self.note_commitment_root,
            "proof_system": self.proof_system,
            "max_amount_per_epoch_commitment": self.max_amount_per_epoch_commitment,
            "epoch_window_blocks": self.epoch_window_blocks,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "grant_proposal_id": self.grant_proposal_id,
            "revoked_at_height": self.revoked_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn permission_root(&self) -> String {
        private_token_permission_root(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.valid_from_height
            && height <= self.expires_at_height
            && self.revoked_at_height == 0
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.permission_id, "permission id")?;
        validate_non_empty(&self.class_id, "permission class")?;
        validate_non_empty(&self.controller_commitment, "permission controller")?;
        validate_non_empty(&self.controller_key_root, "permission controller key root")?;
        validate_non_empty(&self.note_commitment_root, "permission note root")?;
        validate_non_empty(&self.proof_system, "permission proof system")?;
        validate_non_empty(
            &self.max_amount_per_epoch_commitment,
            "permission amount cap",
        )?;
        validate_non_empty(&self.grant_proposal_id, "permission proposal")?;
        if !self.scope.is_mint() && !self.scope.is_burn() {
            return Err("permission scope must be mint or burn".to_string());
        }
        if self.epoch_window_blocks == 0 {
            return Err("permission epoch window must be positive".to_string());
        }
        if self.expires_at_height <= self.valid_from_height {
            return Err("permission expiry must be after valid-from".to_string());
        }
        let scope_label = self.scope.as_str();
        let expected = private_token_permission_id(
            &self.class_id,
            &self.controller_commitment,
            &scope_label,
            &self.note_commitment_root,
            self.valid_from_height,
            &self.grant_proposal_id,
        );
        if self.permission_id != expected {
            return Err("permission id mismatch".to_string());
        }
        Ok(self.permission_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAbiManifest {
    pub manifest_id: String,
    pub contract_id: String,
    pub class_id: String,
    pub name: String,
    pub version: String,
    pub schema_root: String,
    pub function_roots: BTreeMap<String, String>,
    pub event_roots: BTreeMap<String, String>,
    pub storage_layout_root: String,
    pub verifier_key_root: String,
    pub bytecode_root: String,
    pub source_commitment: String,
    pub pq_build_attestation_root: String,
    pub backwards_compatible_from: BTreeSet<String>,
    pub published_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl ContractAbiManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        contract_id: &str,
        name: &str,
        version: &str,
        functions: Vec<&str>,
        events: Vec<&str>,
        storage_layout: &Value,
        bytecode_label: &str,
        published_at_height: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "ABI class id")?;
        validate_non_empty(contract_id, "ABI contract id")?;
        validate_non_empty(name, "ABI name")?;
        validate_non_empty(version, "ABI version")?;
        validate_non_empty(bytecode_label, "ABI bytecode label")?;
        let schema_root = private_token_payload_root(
            "PRIVATE-TOKEN-ABI-SCHEMA",
            &json!({
                "name": name,
                "version": version,
                "functions": functions,
                "events": events,
                "storage_layout": storage_layout,
            }),
            contract_id,
        );
        let mut function_roots = BTreeMap::new();
        for function in functions {
            let normalized = normalize_label(function);
            if !normalized.is_empty() {
                function_roots.insert(
                    normalized.clone(),
                    private_token_string_root("PRIVATE-TOKEN-ABI-FUNCTION", &normalized),
                );
            }
        }
        let mut event_roots = BTreeMap::new();
        for event in events {
            let normalized = normalize_label(event);
            if !normalized.is_empty() {
                event_roots.insert(
                    normalized.clone(),
                    private_token_string_root("PRIVATE-TOKEN-ABI-EVENT", &normalized),
                );
            }
        }
        let storage_layout_root =
            private_token_payload_root("PRIVATE-TOKEN-ABI-STORAGE", storage_layout, contract_id);
        let verifier_key_root = private_token_string_root("PRIVATE-TOKEN-ABI-VK", contract_id);
        let bytecode_root = private_token_string_root("PRIVATE-TOKEN-ABI-BYTECODE", bytecode_label);
        let source_commitment = private_token_string_root("PRIVATE-TOKEN-ABI-SOURCE", name);
        let pq_build_attestation_root =
            private_token_string_root("PRIVATE-TOKEN-ABI-PQ-BUILD", bytecode_label);
        let manifest_id = private_token_abi_manifest_id(
            class_id,
            contract_id,
            name,
            version,
            &schema_root,
            &bytecode_root,
            published_at_height,
        );
        Ok(Self {
            manifest_id,
            contract_id: contract_id.to_string(),
            class_id: class_id.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            schema_root,
            function_roots,
            event_roots,
            storage_layout_root,
            verifier_key_root,
            bytecode_root,
            source_commitment,
            pq_build_attestation_root,
            backwards_compatible_from: BTreeSet::new(),
            published_at_height,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_abi_manifest",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "abi_scheme": PRIVATE_TOKEN_REGISTRY_ABI_SCHEME,
            "manifest_id": self.manifest_id,
            "contract_id": self.contract_id,
            "class_id": self.class_id,
            "name": self.name,
            "version": self.version,
            "schema_root": self.schema_root,
            "function_roots": self.function_roots,
            "event_roots": self.event_roots,
            "storage_layout_root": self.storage_layout_root,
            "verifier_key_root": self.verifier_key_root,
            "bytecode_root": self.bytecode_root,
            "source_commitment": self.source_commitment,
            "pq_build_attestation_root": self.pq_build_attestation_root,
            "backwards_compatible_from": self.backwards_compatible_from,
            "published_at_height": self.published_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn manifest_root(&self) -> String {
        private_token_abi_manifest_root(self)
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.manifest_id, "ABI manifest id")?;
        validate_non_empty(&self.contract_id, "ABI contract id")?;
        validate_non_empty(&self.class_id, "ABI class id")?;
        validate_non_empty(&self.name, "ABI name")?;
        validate_non_empty(&self.version, "ABI version")?;
        validate_non_empty(&self.schema_root, "ABI schema root")?;
        validate_non_empty(&self.storage_layout_root, "ABI storage root")?;
        validate_non_empty(&self.verifier_key_root, "ABI verifier key root")?;
        validate_non_empty(&self.bytecode_root, "ABI bytecode root")?;
        if self.function_roots.is_empty() {
            return Err("ABI manifest must expose at least one function".to_string());
        }
        let expected = private_token_abi_manifest_id(
            &self.class_id,
            &self.contract_id,
            &self.name,
            &self.version,
            &self.schema_root,
            &self.bytecode_root,
            self.published_at_height,
        );
        if self.manifest_id != expected {
            return Err("ABI manifest id mismatch".to_string());
        }
        Ok(self.manifest_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqGovernedUpgrade {
    pub upgrade_id: String,
    pub class_id: String,
    pub contract_id: String,
    pub from_manifest_id: String,
    pub from_manifest_root: String,
    pub to_manifest_id: String,
    pub to_manifest_root: String,
    pub governance_model: PqGovernanceModel,
    pub proposal_id: String,
    pub proposal_root: String,
    pub quorum_bps: u64,
    pub timelock_start_height: u64,
    pub executable_height: u64,
    pub expires_at_height: u64,
    pub approvals_root: String,
    pub objections_root: String,
    pub migration_plan_root: String,
    pub emergency_pause_root: String,
    pub enacted_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl PqGovernedUpgrade {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        contract_id: &str,
        from_manifest: &ContractAbiManifest,
        to_manifest: &ContractAbiManifest,
        governance_model: PqGovernanceModel,
        proposal_id: &str,
        quorum_bps: u64,
        timelock_start_height: u64,
        migration_plan: &Value,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "upgrade class id")?;
        validate_non_empty(contract_id, "upgrade contract id")?;
        validate_non_empty(proposal_id, "upgrade proposal id")?;
        validate_bps(quorum_bps, "upgrade quorum")?;
        let proposal_root =
            private_token_string_root("PRIVATE-TOKEN-UPGRADE-PROPOSAL", proposal_id);
        let executable_height = timelock_start_height
            .saturating_add(PRIVATE_TOKEN_REGISTRY_DEFAULT_UPGRADE_TIMELOCK_BLOCKS);
        let expires_at_height = executable_height.saturating_add(2_880);
        let approvals_root = private_token_empty_root("PRIVATE-TOKEN-UPGRADE-APPROVAL");
        let objections_root = private_token_empty_root("PRIVATE-TOKEN-UPGRADE-OBJECTION");
        let migration_plan_root = private_token_payload_root(
            "PRIVATE-TOKEN-UPGRADE-MIGRATION",
            migration_plan,
            proposal_id,
        );
        let emergency_pause_root =
            private_token_string_root("PRIVATE-TOKEN-UPGRADE-EMERGENCY-PAUSE", proposal_id);
        let from_manifest_root = from_manifest.manifest_root();
        let to_manifest_root = to_manifest.manifest_root();
        let governance = governance_model.as_str();
        let upgrade_id = private_token_upgrade_id(
            class_id,
            contract_id,
            &from_manifest.manifest_id,
            &to_manifest.manifest_id,
            proposal_id,
            &governance,
            timelock_start_height,
        );
        Ok(Self {
            upgrade_id,
            class_id: class_id.to_string(),
            contract_id: contract_id.to_string(),
            from_manifest_id: from_manifest.manifest_id.clone(),
            from_manifest_root,
            to_manifest_id: to_manifest.manifest_id.clone(),
            to_manifest_root,
            governance_model,
            proposal_id: proposal_id.to_string(),
            proposal_root,
            quorum_bps,
            timelock_start_height,
            executable_height,
            expires_at_height,
            approvals_root,
            objections_root,
            migration_plan_root,
            emergency_pause_root,
            enacted_at_height: 0,
            status: RegistryLifecycleStatus::Draft,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_governed_upgrade",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "upgrade_scheme": PRIVATE_TOKEN_REGISTRY_UPGRADE_SCHEME,
            "upgrade_id": self.upgrade_id,
            "class_id": self.class_id,
            "contract_id": self.contract_id,
            "from_manifest_id": self.from_manifest_id,
            "from_manifest_root": self.from_manifest_root,
            "to_manifest_id": self.to_manifest_id,
            "to_manifest_root": self.to_manifest_root,
            "governance_model": self.governance_model.as_str(),
            "proposal_id": self.proposal_id,
            "proposal_root": self.proposal_root,
            "quorum_bps": self.quorum_bps,
            "timelock_start_height": self.timelock_start_height,
            "executable_height": self.executable_height,
            "expires_at_height": self.expires_at_height,
            "approvals_root": self.approvals_root,
            "objections_root": self.objections_root,
            "migration_plan_root": self.migration_plan_root,
            "emergency_pause_root": self.emergency_pause_root,
            "enacted_at_height": self.enacted_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn upgrade_root(&self) -> String {
        private_token_upgrade_root(self)
    }

    pub fn is_executable_at(&self, height: u64) -> bool {
        height >= self.executable_height
            && height <= self.expires_at_height
            && !self.status.is_terminal()
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.upgrade_id, "upgrade id")?;
        validate_non_empty(&self.class_id, "upgrade class")?;
        validate_non_empty(&self.contract_id, "upgrade contract")?;
        validate_non_empty(&self.from_manifest_id, "upgrade from manifest")?;
        validate_non_empty(&self.from_manifest_root, "upgrade from manifest root")?;
        validate_non_empty(&self.to_manifest_id, "upgrade to manifest")?;
        validate_non_empty(&self.to_manifest_root, "upgrade to manifest root")?;
        validate_non_empty(&self.proposal_id, "upgrade proposal id")?;
        validate_non_empty(&self.proposal_root, "upgrade proposal root")?;
        validate_bps(self.quorum_bps, "upgrade quorum")?;
        if self.quorum_bps < 6_667 {
            return Err("PQ governed upgrade quorum must be at least two thirds".to_string());
        }
        if self.executable_height < self.timelock_start_height {
            return Err("upgrade executable height precedes timelock".to_string());
        }
        if self.expires_at_height <= self.executable_height {
            return Err("upgrade expiry must be after executable height".to_string());
        }
        let governance = self.governance_model.as_str();
        let expected = private_token_upgrade_id(
            &self.class_id,
            &self.contract_id,
            &self.from_manifest_id,
            &self.to_manifest_id,
            &self.proposal_id,
            &governance,
            self.timelock_start_height,
        );
        if self.upgrade_id != expected {
            return Err("upgrade id mismatch".to_string());
        }
        Ok(self.upgrade_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiListingPolicy {
    pub listing_id: String,
    pub class_id: String,
    pub venue_id: String,
    pub venue_kind: DefiVenueKind,
    pub quote_assets: BTreeSet<String>,
    pub min_liquidity_commitment: String,
    pub max_pool_share_bps: u64,
    pub fee_tier_bps: u64,
    pub listing_permission: ListingPermission,
    pub oracle_root: String,
    pub risk_model_root: String,
    pub private_eligibility_proof_root: String,
    pub approved_by_proposal_id: String,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl DefiListingPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        venue_id: &str,
        venue_kind: DefiVenueKind,
        quote_assets: Vec<String>,
        min_liquidity_units: u64,
        max_pool_share_bps: u64,
        fee_tier_bps: u64,
        listing_permission: ListingPermission,
        approved_by_proposal_id: &str,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "DeFi listing class")?;
        validate_non_empty(venue_id, "DeFi listing venue")?;
        validate_non_empty(approved_by_proposal_id, "DeFi listing proposal")?;
        validate_bps(max_pool_share_bps, "DeFi max pool share")?;
        validate_bps(fee_tier_bps, "DeFi fee tier")?;
        if expires_at_height <= valid_from_height {
            return Err("DeFi listing expiry must be after valid-from".to_string());
        }
        let mut quote_set = BTreeSet::new();
        for quote in quote_assets {
            if !quote.trim().is_empty() {
                quote_set.insert(quote);
            }
        }
        if quote_set.is_empty() {
            return Err("DeFi listing requires at least one quote asset".to_string());
        }
        let min_liquidity_commitment =
            private_token_amount_commitment(class_id, min_liquidity_units, "defi-min-liquidity");
        let oracle_root = private_token_string_root("PRIVATE-TOKEN-DEFI-ORACLE", venue_id);
        let risk_model_root = private_token_string_root("PRIVATE-TOKEN-DEFI-RISK-MODEL", venue_id);
        let private_eligibility_proof_root =
            private_token_string_root("PRIVATE-TOKEN-DEFI-ELIGIBILITY", approved_by_proposal_id);
        let venue = venue_kind.as_str();
        let permission = listing_permission.as_str();
        let listing_id = private_token_defi_listing_id(
            class_id,
            venue_id,
            &venue,
            permission,
            approved_by_proposal_id,
            valid_from_height,
        );
        Ok(Self {
            listing_id,
            class_id: class_id.to_string(),
            venue_id: venue_id.to_string(),
            venue_kind,
            quote_assets: quote_set,
            min_liquidity_commitment,
            max_pool_share_bps,
            fee_tier_bps,
            listing_permission,
            oracle_root,
            risk_model_root,
            private_eligibility_proof_root,
            approved_by_proposal_id: approved_by_proposal_id.to_string(),
            valid_from_height,
            expires_at_height,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_listing_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "listing_id": self.listing_id,
            "class_id": self.class_id,
            "venue_id": self.venue_id,
            "venue_kind": self.venue_kind.as_str(),
            "quote_assets": self.quote_assets,
            "min_liquidity_commitment": self.min_liquidity_commitment,
            "max_pool_share_bps": self.max_pool_share_bps,
            "fee_tier_bps": self.fee_tier_bps,
            "listing_permission": self.listing_permission.as_str(),
            "oracle_root": self.oracle_root,
            "risk_model_root": self.risk_model_root,
            "private_eligibility_proof_root": self.private_eligibility_proof_root,
            "approved_by_proposal_id": self.approved_by_proposal_id,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn listing_root(&self) -> String {
        private_token_defi_listing_root(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.valid_from_height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.listing_id, "DeFi listing id")?;
        validate_non_empty(&self.class_id, "DeFi listing class")?;
        validate_non_empty(&self.venue_id, "DeFi listing venue")?;
        validate_non_empty(&self.min_liquidity_commitment, "DeFi listing liquidity")?;
        validate_bps(self.max_pool_share_bps, "DeFi listing max pool share")?;
        validate_bps(self.fee_tier_bps, "DeFi listing fee tier")?;
        if self.quote_assets.is_empty() {
            return Err("DeFi listing quote asset set is empty".to_string());
        }
        if self.listing_permission.requires_governance()
            && self.approved_by_proposal_id.trim().is_empty()
        {
            return Err("DeFi listing requires governance proposal".to_string());
        }
        if self.expires_at_height <= self.valid_from_height {
            return Err("DeFi listing expiry must be after valid-from".to_string());
        }
        let venue = self.venue_kind.as_str();
        let expected = private_token_defi_listing_id(
            &self.class_id,
            &self.venue_id,
            &venue,
            self.listing_permission.as_str(),
            &self.approved_by_proposal_id,
            self.valid_from_height,
        );
        if self.listing_id != expected {
            return Err("DeFi listing id mismatch".to_string());
        }
        Ok(self.listing_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTransferHook {
    pub hook_id: String,
    pub class_id: String,
    pub contract_id: String,
    pub manifest_id: String,
    pub phases: BTreeSet<TransferHookPhase>,
    pub entrypoint: String,
    pub verifier_key_root: String,
    pub hook_config_root: String,
    pub max_gas_units: u64,
    pub privacy_budget_commitment: String,
    pub sponsor_id: String,
    pub paused_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl PrivateTransferHook {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        contract_id: &str,
        manifest_id: &str,
        phases: Vec<TransferHookPhase>,
        entrypoint: &str,
        hook_config: &Value,
        max_gas_units: u64,
        privacy_budget_units: u64,
        sponsor_id: &str,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "transfer hook class")?;
        validate_non_empty(contract_id, "transfer hook contract")?;
        validate_non_empty(manifest_id, "transfer hook manifest")?;
        validate_non_empty(entrypoint, "transfer hook entrypoint")?;
        if max_gas_units == 0 {
            return Err("transfer hook max gas must be positive".to_string());
        }
        let phase_set = phases.into_iter().collect::<BTreeSet<_>>();
        if phase_set.is_empty() {
            return Err("transfer hook requires at least one phase".to_string());
        }
        let verifier_key_root = private_token_string_root("PRIVATE-TOKEN-HOOK-VK", entrypoint);
        let hook_config_root =
            private_token_payload_root("PRIVATE-TOKEN-HOOK-CONFIG", hook_config, entrypoint);
        let privacy_budget_commitment =
            private_token_amount_commitment(class_id, privacy_budget_units, "hook-privacy-budget");
        let phase_root = phase_set_root("PRIVATE-TOKEN-HOOK-PHASE", &phase_set);
        let hook_id = private_token_transfer_hook_id(
            class_id,
            contract_id,
            manifest_id,
            &phase_root,
            entrypoint,
        );
        Ok(Self {
            hook_id,
            class_id: class_id.to_string(),
            contract_id: contract_id.to_string(),
            manifest_id: manifest_id.to_string(),
            phases: phase_set,
            entrypoint: entrypoint.to_string(),
            verifier_key_root,
            hook_config_root,
            max_gas_units,
            privacy_budget_commitment,
            sponsor_id: sponsor_id.to_string(),
            paused_at_height: 0,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_transfer_hook",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "hook_scheme": PRIVATE_TOKEN_REGISTRY_TRANSFER_HOOK_SCHEME,
            "hook_id": self.hook_id,
            "class_id": self.class_id,
            "contract_id": self.contract_id,
            "manifest_id": self.manifest_id,
            "phases": transfer_hook_phases_public(&self.phases),
            "entrypoint": self.entrypoint,
            "verifier_key_root": self.verifier_key_root,
            "hook_config_root": self.hook_config_root,
            "max_gas_units": self.max_gas_units,
            "privacy_budget_commitment": self.privacy_budget_commitment,
            "sponsor_id": self.sponsor_id,
            "paused_at_height": self.paused_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn hook_root(&self) -> String {
        private_token_transfer_hook_root(self)
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.hook_id, "transfer hook id")?;
        validate_non_empty(&self.class_id, "transfer hook class")?;
        validate_non_empty(&self.contract_id, "transfer hook contract")?;
        validate_non_empty(&self.manifest_id, "transfer hook manifest")?;
        validate_non_empty(&self.entrypoint, "transfer hook entrypoint")?;
        validate_non_empty(&self.verifier_key_root, "transfer hook verifier key")?;
        validate_non_empty(&self.hook_config_root, "transfer hook config")?;
        validate_non_empty(
            &self.privacy_budget_commitment,
            "transfer hook privacy budget",
        )?;
        if self.max_gas_units == 0 {
            return Err("transfer hook max gas must be positive".to_string());
        }
        if self.phases.is_empty() {
            return Err("transfer hook phase set is empty".to_string());
        }
        let phase_root = phase_set_root("PRIVATE-TOKEN-HOOK-PHASE", &self.phases);
        let expected = private_token_transfer_hook_id(
            &self.class_id,
            &self.contract_id,
            &self.manifest_id,
            &phase_root,
            &self.entrypoint,
        );
        if self.hook_id != expected {
            return Err("transfer hook id mismatch".to_string());
        }
        Ok(self.hook_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDisclosurePolicy {
    pub policy_id: String,
    pub class_id: String,
    pub policy_label: String,
    pub disclosure_mode: ComplianceDisclosureMode,
    pub jurisdiction_commitment_root: String,
    pub rule_set_root: String,
    pub view_key_committee_root: String,
    pub allowed_purpose_roots: BTreeSet<String>,
    pub max_disclosures_per_epoch: u64,
    pub epoch_window_blocks: u64,
    pub min_threshold: u16,
    pub public_bucket_granularity: String,
    pub preserves_sender_recipient_privacy: bool,
    pub expires_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl ComplianceDisclosurePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn privacy_preserving(
        class_id: &str,
        policy_label: &str,
        disclosure_mode: ComplianceDisclosureMode,
        jurisdiction_label: &str,
        purposes: Vec<&str>,
        max_disclosures_per_epoch: u64,
        min_threshold: u16,
        expires_at_height: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "compliance class")?;
        validate_non_empty(policy_label, "compliance policy label")?;
        validate_non_empty(jurisdiction_label, "compliance jurisdiction")?;
        if !disclosure_mode.preserves_default_privacy() {
            return Err("compliance disclosure mode does not preserve default privacy".to_string());
        }
        if max_disclosures_per_epoch == 0 {
            return Err("compliance disclosure cap must be positive".to_string());
        }
        if min_threshold == 0 {
            return Err("compliance disclosure threshold must be positive".to_string());
        }
        let normalized_policy = normalize_label(policy_label);
        let jurisdiction_commitment_root =
            private_token_string_root("PRIVATE-TOKEN-COMPLIANCE-JURISDICTION", jurisdiction_label);
        let rule_set_root =
            private_token_string_root("PRIVATE-TOKEN-COMPLIANCE-RULESET", &normalized_policy);
        let view_key_committee_root =
            private_token_string_root("PRIVATE-TOKEN-COMPLIANCE-VIEW-KEYS", &normalized_policy);
        let mut allowed_purpose_roots = BTreeSet::new();
        for purpose in purposes {
            let normalized = normalize_label(purpose);
            if !normalized.is_empty() {
                allowed_purpose_roots.insert(private_token_string_root(
                    "PRIVATE-TOKEN-COMPLIANCE-PURPOSE",
                    &normalized,
                ));
            }
        }
        if allowed_purpose_roots.is_empty() {
            return Err("compliance policy requires at least one purpose root".to_string());
        }
        let mode = disclosure_mode.as_str();
        let policy_id = private_token_compliance_policy_id(
            class_id,
            &normalized_policy,
            &mode,
            &jurisdiction_commitment_root,
            expires_at_height,
        );
        Ok(Self {
            policy_id,
            class_id: class_id.to_string(),
            policy_label: normalized_policy,
            disclosure_mode,
            jurisdiction_commitment_root,
            rule_set_root,
            view_key_committee_root,
            allowed_purpose_roots,
            max_disclosures_per_epoch,
            epoch_window_blocks: PRIVATE_TOKEN_REGISTRY_DEFAULT_DISCLOSURE_EPOCH_BLOCKS,
            min_threshold,
            public_bucket_granularity: "amount-buckets-and-purpose-codes-only".to_string(),
            preserves_sender_recipient_privacy: true,
            expires_at_height,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "compliance_disclosure_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "disclosure_scheme": PRIVATE_TOKEN_REGISTRY_DISCLOSURE_SCHEME,
            "policy_id": self.policy_id,
            "class_id": self.class_id,
            "policy_label": self.policy_label,
            "disclosure_mode": self.disclosure_mode.as_str(),
            "jurisdiction_commitment_root": self.jurisdiction_commitment_root,
            "rule_set_root": self.rule_set_root,
            "view_key_committee_root": self.view_key_committee_root,
            "allowed_purpose_roots": self.allowed_purpose_roots,
            "max_disclosures_per_epoch": self.max_disclosures_per_epoch,
            "epoch_window_blocks": self.epoch_window_blocks,
            "min_threshold": self.min_threshold,
            "public_bucket_granularity": self.public_bucket_granularity,
            "preserves_sender_recipient_privacy": self.preserves_sender_recipient_privacy,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn policy_root(&self) -> String {
        private_token_compliance_policy_root(self)
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.policy_id, "compliance policy id")?;
        validate_non_empty(&self.class_id, "compliance class")?;
        validate_non_empty(&self.policy_label, "compliance policy label")?;
        validate_non_empty(
            &self.jurisdiction_commitment_root,
            "compliance jurisdiction root",
        )?;
        validate_non_empty(&self.rule_set_root, "compliance rule set root")?;
        validate_non_empty(
            &self.view_key_committee_root,
            "compliance view key committee",
        )?;
        validate_non_empty(
            &self.public_bucket_granularity,
            "compliance bucket granularity",
        )?;
        if self.allowed_purpose_roots.is_empty() {
            return Err("compliance policy purpose roots are empty".to_string());
        }
        if self.epoch_window_blocks == 0 {
            return Err("compliance epoch window must be positive".to_string());
        }
        if self.max_disclosures_per_epoch == 0 {
            return Err("compliance disclosure cap must be positive".to_string());
        }
        if self.min_threshold == 0 {
            return Err("compliance threshold must be positive".to_string());
        }
        if !self.disclosure_mode.preserves_default_privacy()
            || !self.preserves_sender_recipient_privacy
        {
            return Err("compliance policy must preserve sender and recipient privacy".to_string());
        }
        let mode = self.disclosure_mode.as_str();
        let expected = private_token_compliance_policy_id(
            &self.class_id,
            &self.policy_label,
            &mode,
            &self.jurisdiction_commitment_root,
            self.expires_at_height,
        );
        if self.policy_id != expected {
            return Err("compliance policy id mismatch".to_string());
        }
        Ok(self.policy_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueSponsorshipPolicy {
    pub sponsor_id: String,
    pub class_id: String,
    pub sponsor_commitment: String,
    pub fee_asset_id: String,
    pub low_fee_lane: String,
    pub budget_commitment: String,
    pub spent_commitment: String,
    pub max_fee_per_issue: u64,
    pub max_units_per_issue: u64,
    pub discount_bps: u64,
    pub valid_from_height: u64,
    pub expires_at_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl IssueSponsorshipPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        low_fee_lane: &str,
        budget_units: u64,
        max_fee_per_issue: u64,
        max_units_per_issue: u64,
        discount_bps: u64,
        valid_from_height: u64,
        expires_at_height: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "sponsorship class")?;
        validate_non_empty(sponsor_label, "sponsorship label")?;
        validate_non_empty(fee_asset_id, "sponsorship fee asset")?;
        validate_non_empty(low_fee_lane, "sponsorship low-fee lane")?;
        validate_bps(discount_bps, "sponsorship discount")?;
        if budget_units == 0 {
            return Err("sponsorship budget must be positive".to_string());
        }
        if max_fee_per_issue == 0 {
            return Err("sponsorship max fee must be positive".to_string());
        }
        if max_units_per_issue == 0 {
            return Err("sponsorship max units must be positive".to_string());
        }
        if expires_at_height <= valid_from_height {
            return Err("sponsorship expiry must be after valid-from".to_string());
        }
        let sponsor_commitment =
            private_token_string_root("PRIVATE-TOKEN-SPONSOR-COMMITMENT", sponsor_label);
        let budget_commitment =
            private_token_amount_commitment(class_id, budget_units, "sponsorship-budget");
        let spent_commitment = private_token_amount_commitment(class_id, 0, "sponsorship-spent");
        let sponsor_id = private_token_sponsorship_id(
            class_id,
            &sponsor_commitment,
            fee_asset_id,
            low_fee_lane,
            valid_from_height,
        );
        Ok(Self {
            sponsor_id,
            class_id: class_id.to_string(),
            sponsor_commitment,
            fee_asset_id: fee_asset_id.to_string(),
            low_fee_lane: low_fee_lane.to_string(),
            budget_commitment,
            spent_commitment,
            max_fee_per_issue,
            max_units_per_issue,
            discount_bps,
            valid_from_height,
            expires_at_height,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "issue_sponsorship_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "sponsorship_scheme": PRIVATE_TOKEN_REGISTRY_SPONSORSHIP_SCHEME,
            "sponsor_id": self.sponsor_id,
            "class_id": self.class_id,
            "sponsor_commitment": self.sponsor_commitment,
            "fee_asset_id": self.fee_asset_id,
            "low_fee_lane": self.low_fee_lane,
            "budget_commitment": self.budget_commitment,
            "spent_commitment": self.spent_commitment,
            "max_fee_per_issue": self.max_fee_per_issue,
            "max_units_per_issue": self.max_units_per_issue,
            "discount_bps": self.discount_bps,
            "valid_from_height": self.valid_from_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn sponsorship_root(&self) -> String {
        private_token_sponsorship_root(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active()
            && height >= self.valid_from_height
            && height <= self.expires_at_height
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.sponsor_id, "sponsorship id")?;
        validate_non_empty(&self.class_id, "sponsorship class")?;
        validate_non_empty(&self.sponsor_commitment, "sponsorship commitment")?;
        validate_non_empty(&self.fee_asset_id, "sponsorship fee asset")?;
        validate_non_empty(&self.low_fee_lane, "sponsorship low-fee lane")?;
        validate_non_empty(&self.budget_commitment, "sponsorship budget")?;
        validate_non_empty(&self.spent_commitment, "sponsorship spent")?;
        validate_bps(self.discount_bps, "sponsorship discount")?;
        if self.max_fee_per_issue == 0 || self.max_units_per_issue == 0 {
            return Err("sponsorship limits must be positive".to_string());
        }
        if self.expires_at_height <= self.valid_from_height {
            return Err("sponsorship expiry must be after valid-from".to_string());
        }
        let expected = private_token_sponsorship_id(
            &self.class_id,
            &self.sponsor_commitment,
            &self.fee_asset_id,
            &self.low_fee_lane,
            self.valid_from_height,
        );
        if self.sponsor_id != expected {
            return Err("sponsorship id mismatch".to_string());
        }
        Ok(self.sponsorship_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidityIncentivePolicy {
    pub incentive_id: String,
    pub class_id: String,
    pub venue_id: String,
    pub reward_asset_id: String,
    pub reward_commitment: String,
    pub emission_rate_commitment: String,
    pub eligibility_root: String,
    pub anti_sybil_root: String,
    pub private_claim_verifier_root: String,
    pub claimed_commitment: String,
    pub start_height: u64,
    pub end_height: u64,
    pub status: RegistryLifecycleStatus,
}

impl LiquidityIncentivePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        venue_id: &str,
        reward_asset_id: &str,
        reward_units: u64,
        emission_rate_units: u64,
        eligibility_label: &str,
        start_height: u64,
        end_height: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(class_id, "liquidity incentive class")?;
        validate_non_empty(venue_id, "liquidity incentive venue")?;
        validate_non_empty(reward_asset_id, "liquidity incentive reward asset")?;
        validate_non_empty(eligibility_label, "liquidity incentive eligibility")?;
        if reward_units == 0 || emission_rate_units == 0 {
            return Err("liquidity incentive amounts must be positive".to_string());
        }
        if end_height <= start_height {
            return Err("liquidity incentive end must be after start".to_string());
        }
        let reward_commitment =
            private_token_amount_commitment(class_id, reward_units, "liquidity-incentive-reward");
        let emission_rate_commitment = private_token_amount_commitment(
            class_id,
            emission_rate_units,
            "liquidity-incentive-emission",
        );
        let eligibility_root =
            private_token_string_root("PRIVATE-TOKEN-INCENTIVE-ELIGIBILITY", eligibility_label);
        let anti_sybil_root =
            private_token_string_root("PRIVATE-TOKEN-INCENTIVE-ANTI-SYBIL", eligibility_label);
        let private_claim_verifier_root =
            private_token_string_root("PRIVATE-TOKEN-INCENTIVE-CLAIM-VK", eligibility_label);
        let claimed_commitment = private_token_amount_commitment(class_id, 0, "incentive-claimed");
        let incentive_id = private_token_incentive_id(
            class_id,
            venue_id,
            reward_asset_id,
            &eligibility_root,
            start_height,
        );
        Ok(Self {
            incentive_id,
            class_id: class_id.to_string(),
            venue_id: venue_id.to_string(),
            reward_asset_id: reward_asset_id.to_string(),
            reward_commitment,
            emission_rate_commitment,
            eligibility_root,
            anti_sybil_root,
            private_claim_verifier_root,
            claimed_commitment,
            start_height,
            end_height,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "liquidity_incentive_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "incentive_scheme": PRIVATE_TOKEN_REGISTRY_INCENTIVE_SCHEME,
            "incentive_id": self.incentive_id,
            "class_id": self.class_id,
            "venue_id": self.venue_id,
            "reward_asset_id": self.reward_asset_id,
            "reward_commitment": self.reward_commitment,
            "emission_rate_commitment": self.emission_rate_commitment,
            "eligibility_root": self.eligibility_root,
            "anti_sybil_root": self.anti_sybil_root,
            "private_claim_verifier_root": self.private_claim_verifier_root,
            "claimed_commitment": self.claimed_commitment,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "status": self.status.as_str(),
        })
    }

    pub fn incentive_root(&self) -> String {
        private_token_incentive_root(self)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status.is_active() && height >= self.start_height && height <= self.end_height
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.incentive_id, "liquidity incentive id")?;
        validate_non_empty(&self.class_id, "liquidity incentive class")?;
        validate_non_empty(&self.venue_id, "liquidity incentive venue")?;
        validate_non_empty(&self.reward_asset_id, "liquidity incentive reward asset")?;
        validate_non_empty(&self.reward_commitment, "liquidity incentive reward")?;
        validate_non_empty(
            &self.emission_rate_commitment,
            "liquidity incentive emission",
        )?;
        validate_non_empty(&self.eligibility_root, "liquidity incentive eligibility")?;
        validate_non_empty(&self.anti_sybil_root, "liquidity incentive anti sybil")?;
        validate_non_empty(
            &self.private_claim_verifier_root,
            "liquidity claim verifier",
        )?;
        validate_non_empty(&self.claimed_commitment, "liquidity incentive claimed")?;
        if self.end_height <= self.start_height {
            return Err("liquidity incentive end must be after start".to_string());
        }
        let expected = private_token_incentive_id(
            &self.class_id,
            &self.venue_id,
            &self.reward_asset_id,
            &self.eligibility_root,
            self.start_height,
        );
        if self.incentive_id != expected {
            return Err("liquidity incentive id mismatch".to_string());
        }
        Ok(self.incentive_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenAuditReceipt {
    pub receipt_id: String,
    pub receipt_kind: AuditReceiptKind,
    pub subject_id: String,
    pub actor_commitment: String,
    pub amount_commitment: String,
    pub root_before: String,
    pub root_after: String,
    pub evidence_root: String,
    pub memo_commitment: String,
    pub issued_at_height: u64,
    pub sequence: u64,
    pub pq_signature_root: String,
    pub status: RegistryLifecycleStatus,
}

impl PrivateTokenAuditReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_kind: AuditReceiptKind,
        subject_id: &str,
        actor_label: &str,
        amount_units: u64,
        root_before: &str,
        root_after: &str,
        evidence: &Value,
        memo: &str,
        issued_at_height: u64,
        sequence: u64,
    ) -> PrivateTokenRegistryResult<Self> {
        validate_non_empty(subject_id, "audit receipt subject")?;
        validate_non_empty(actor_label, "audit receipt actor")?;
        validate_non_empty(root_before, "audit receipt root before")?;
        validate_non_empty(root_after, "audit receipt root after")?;
        validate_non_empty(memo, "audit receipt memo")?;
        let actor_commitment = private_token_string_root("PRIVATE-TOKEN-AUDIT-ACTOR", actor_label);
        let amount_commitment =
            private_token_amount_commitment(subject_id, amount_units, "audit-amount");
        let evidence_root =
            private_token_payload_root("PRIVATE-TOKEN-AUDIT-EVIDENCE", evidence, memo);
        let memo_commitment = private_token_string_root("PRIVATE-TOKEN-AUDIT-MEMO", memo);
        let kind = receipt_kind.as_str();
        let pq_signature_root = domain_hash(
            "PRIVATE-TOKEN-AUDIT-PQ-SIGNATURE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&kind),
                HashPart::Str(subject_id),
                HashPart::Str(&actor_commitment),
                HashPart::Str(&evidence_root),
                HashPart::Int(sequence as i128),
            ],
            32,
        );
        let receipt_id = private_token_audit_receipt_id(
            &kind,
            subject_id,
            &actor_commitment,
            &root_before,
            &root_after,
            issued_at_height,
            sequence,
        );
        Ok(Self {
            receipt_id,
            receipt_kind,
            subject_id: subject_id.to_string(),
            actor_commitment,
            amount_commitment,
            root_before: root_before.to_string(),
            root_after: root_after.to_string(),
            evidence_root,
            memo_commitment,
            issued_at_height,
            sequence,
            pq_signature_root,
            status: RegistryLifecycleStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_audit_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "audit_scheme": PRIVATE_TOKEN_REGISTRY_AUDIT_SCHEME,
            "receipt_id": self.receipt_id,
            "receipt_kind": self.receipt_kind.as_str(),
            "subject_id": self.subject_id,
            "actor_commitment": self.actor_commitment,
            "amount_commitment": self.amount_commitment,
            "root_before": self.root_before,
            "root_after": self.root_after,
            "evidence_root": self.evidence_root,
            "memo_commitment": self.memo_commitment,
            "issued_at_height": self.issued_at_height,
            "sequence": self.sequence,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
        })
    }

    pub fn receipt_root(&self) -> String {
        private_token_audit_receipt_root(self)
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(&self.receipt_id, "audit receipt id")?;
        validate_non_empty(&self.subject_id, "audit receipt subject")?;
        validate_non_empty(&self.actor_commitment, "audit receipt actor")?;
        validate_non_empty(&self.amount_commitment, "audit receipt amount")?;
        validate_non_empty(&self.root_before, "audit receipt root before")?;
        validate_non_empty(&self.root_after, "audit receipt root after")?;
        validate_non_empty(&self.evidence_root, "audit receipt evidence")?;
        validate_non_empty(&self.memo_commitment, "audit receipt memo")?;
        validate_non_empty(&self.pq_signature_root, "audit receipt PQ signature")?;
        let kind = self.receipt_kind.as_str();
        let expected = private_token_audit_receipt_id(
            &kind,
            &self.subject_id,
            &self.actor_commitment,
            &self.root_before,
            &self.root_after,
            self.issued_at_height,
            self.sequence,
        );
        if self.receipt_id != expected {
            return Err("audit receipt id mismatch".to_string());
        }
        Ok(self.receipt_root())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenRegistryRoots {
    pub pq_key_set_root: String,
    pub token_class_root: String,
    pub mint_permission_root: String,
    pub burn_permission_root: String,
    pub abi_manifest_root: String,
    pub upgrade_root: String,
    pub defi_listing_root: String,
    pub transfer_hook_root: String,
    pub compliance_policy_root: String,
    pub sponsorship_root: String,
    pub incentive_root: String,
    pub audit_receipt_root: String,
}

impl PrivateTokenRegistryRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_registry_roots",
            "chain_id": CHAIN_ID,
            "pq_key_set_root": self.pq_key_set_root,
            "token_class_root": self.token_class_root,
            "mint_permission_root": self.mint_permission_root,
            "burn_permission_root": self.burn_permission_root,
            "abi_manifest_root": self.abi_manifest_root,
            "upgrade_root": self.upgrade_root,
            "defi_listing_root": self.defi_listing_root,
            "transfer_hook_root": self.transfer_hook_root,
            "compliance_policy_root": self.compliance_policy_root,
            "sponsorship_root": self.sponsorship_root,
            "incentive_root": self.incentive_root,
            "audit_receipt_root": self.audit_receipt_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "PRIVATE-TOKEN-REGISTRY-ROOTS",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenRegistryCounters {
    pub pq_key_set_count: u64,
    pub token_class_count: u64,
    pub active_class_count: u64,
    pub low_fee_class_count: u64,
    pub defi_ready_class_count: u64,
    pub mint_permission_count: u64,
    pub burn_permission_count: u64,
    pub abi_manifest_count: u64,
    pub upgrade_count: u64,
    pub defi_listing_count: u64,
    pub transfer_hook_count: u64,
    pub compliance_policy_count: u64,
    pub sponsorship_count: u64,
    pub incentive_count: u64,
    pub audit_receipt_count: u64,
    pub next_audit_sequence: u64,
}

impl PrivateTokenRegistryCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_token_registry_counters",
            "chain_id": CHAIN_ID,
            "pq_key_set_count": self.pq_key_set_count,
            "token_class_count": self.token_class_count,
            "active_class_count": self.active_class_count,
            "low_fee_class_count": self.low_fee_class_count,
            "defi_ready_class_count": self.defi_ready_class_count,
            "mint_permission_count": self.mint_permission_count,
            "burn_permission_count": self.burn_permission_count,
            "abi_manifest_count": self.abi_manifest_count,
            "upgrade_count": self.upgrade_count,
            "defi_listing_count": self.defi_listing_count,
            "transfer_hook_count": self.transfer_hook_count,
            "compliance_policy_count": self.compliance_policy_count,
            "sponsorship_count": self.sponsorship_count,
            "incentive_count": self.incentive_count,
            "audit_receipt_count": self.audit_receipt_count,
            "next_audit_sequence": self.next_audit_sequence,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateTokenRegistryState {
    pub height: u64,
    pub pq_key_sets: BTreeMap<String, PqKeySet>,
    pub token_classes: BTreeMap<String, PrivateTokenClass>,
    pub mint_permissions: BTreeMap<String, ShieldedMintBurnPermission>,
    pub burn_permissions: BTreeMap<String, ShieldedMintBurnPermission>,
    pub abi_manifests: BTreeMap<String, ContractAbiManifest>,
    pub upgrades: BTreeMap<String, PqGovernedUpgrade>,
    pub defi_listing_policies: BTreeMap<String, DefiListingPolicy>,
    pub transfer_hooks: BTreeMap<String, PrivateTransferHook>,
    pub compliance_policies: BTreeMap<String, ComplianceDisclosurePolicy>,
    pub issuance_sponsors: BTreeMap<String, IssueSponsorshipPolicy>,
    pub liquidity_incentives: BTreeMap<String, LiquidityIncentivePolicy>,
    pub audit_receipts: BTreeMap<String, PrivateTokenAuditReceipt>,
    pub next_audit_sequence: u64,
}

impl PrivateTokenRegistryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> PrivateTokenRegistryResult<Self> {
        let mut state = Self {
            height: PRIVATE_TOKEN_REGISTRY_DEVNET_HEIGHT,
            ..Self::default()
        };
        let governance_keys = PqKeySet::devnet(
            PRIVATE_TOKEN_REGISTRY_DEVNET_GOVERNANCE_LABEL,
            3,
            state.height,
        );
        let bridge_keys =
            PqKeySet::devnet(PRIVATE_TOKEN_REGISTRY_DEVNET_BRIDGE_LABEL, 2, state.height);
        let defi_keys = PqKeySet::devnet(PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL, 2, state.height);
        let governance_key_id = state.register_pq_key_set(governance_keys.clone())?;
        let bridge_key_id = state.register_pq_key_set(bridge_keys.clone())?;
        let defi_key_id = state.register_pq_key_set(defi_keys.clone())?;

        let wxmr_class = PrivateTokenClass::new(
            PRIVATE_TOKEN_REGISTRY_DEVNET_WXMR_SYMBOL,
            "Private Wrapped Monero",
            12,
            PrivateTokenClassKind::WrappedMonero,
            ConfidentialSupplyMode::BridgeMintBurn,
            PRIVATE_TOKEN_REGISTRY_DEVNET_BRIDGE_LABEL,
            &bridge_keys.key_root(),
            &json!({
                "display_name": "Private Wrapped Monero",
                "symbol": PRIVATE_TOKEN_REGISTRY_DEVNET_WXMR_SYMBOL,
                "uri": "nebula://private-assets/pxmr",
                "docs": "nebula://docs/private-wrapped-monero",
                "audit": "nebula://audits/pxmr-genesis",
                "tags": ["monero", "bridge", "defi", "low-fee"],
            }),
            "devnet-pxmr-metadata",
            &bridge_key_id,
            &bridge_keys.key_root(),
            21_000_000_000_000_000,
            "monero-reserve-attested-devnet",
            state.height,
            "genesis-pxmr",
        )?;
        let wxmr_id = state.register_token_class(wxmr_class)?;

        let usdd_class = PrivateTokenClass::new(
            PRIVATE_TOKEN_REGISTRY_DEVNET_USDD_SYMBOL,
            "Private Nebula Dollar",
            6,
            PrivateTokenClassKind::StableAsset,
            ConfidentialSupplyMode::CappedShieldedMintBurn,
            PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL,
            &defi_keys.key_root(),
            &json!({
                "display_name": "Private Nebula Dollar",
                "symbol": PRIVATE_TOKEN_REGISTRY_DEVNET_USDD_SYMBOL,
                "uri": "nebula://private-assets/pusd",
                "docs": "nebula://docs/private-stable-asset",
                "audit": "nebula://audits/pusd-risk",
                "tags": ["stable", "private-defi", "low-fee"],
            }),
            "devnet-pusd-metadata",
            &defi_key_id,
            &defi_keys.key_root(),
            10_000_000_000_000,
            "stable-reserve-devnet",
            state.height,
            "genesis-pusd",
        )?;
        let usdd_id = state.register_token_class(usdd_class)?;

        let lp_class = PrivateTokenClass::new(
            PRIVATE_TOKEN_REGISTRY_DEVNET_LP_SYMBOL,
            "Private pXMR/pUSD LP Share",
            18,
            PrivateTokenClassKind::LiquidityShare,
            ConfidentialSupplyMode::PoolShare,
            PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL,
            &defi_keys.key_root(),
            &json!({
                "display_name": "Private pXMR/pUSD LP Share",
                "symbol": PRIVATE_TOKEN_REGISTRY_DEVNET_LP_SYMBOL,
                "uri": "nebula://private-assets/pxmr-pusd-lp",
                "docs": "nebula://docs/private-lp-shares",
                "audit": "nebula://audits/private-amm-lp",
                "tags": ["lp", "amm", "private-defi", "incentives"],
            }),
            "devnet-lp-metadata",
            &defi_key_id,
            &defi_keys.key_root(),
            1_000_000_000_000_000_000,
            "amm-pool-share-devnet",
            state.height,
            "genesis-pxmr-pusd-lp",
        )?;
        let lp_id = state.register_token_class(lp_class)?;

        let wxmr_manifest = ContractAbiManifest::new(
            &wxmr_id,
            "private-wxmr-token-contract",
            "private-wrapped-monero-token",
            "1.0.0",
            vec![
                "shielded_mint",
                "shielded_burn",
                "private_transfer",
                "bridge_reconcile",
            ],
            vec!["mint_commitment", "burn_commitment", "transfer_commitment"],
            &json!({"slots": ["balances", "nullifiers", "reserve_epochs"], "privacy": "note_commitments"}),
            "private-wxmr-bytecode-devnet",
            state.height,
        )?;
        let wxmr_manifest_id = state.register_abi_manifest(wxmr_manifest)?;
        let usdd_manifest = ContractAbiManifest::new(
            &usdd_id,
            "private-pusd-token-contract",
            "private-nebula-dollar-token",
            "1.0.0",
            vec![
                "shielded_mint",
                "shielded_burn",
                "private_transfer",
                "risk_epoch",
            ],
            vec!["supply_commitment", "burn_commitment", "risk_bucket_update"],
            &json!({"slots": ["balances", "debt_ceiling", "risk_buckets"], "privacy": "bucketed_supply"}),
            "private-pusd-bytecode-devnet",
            state.height,
        )?;
        let usdd_manifest_id = state.register_abi_manifest(usdd_manifest)?;
        let lp_manifest = ContractAbiManifest::new(
            &lp_id,
            "private-amm-lp-token-contract",
            "private-amm-lp-share-token",
            "1.0.0",
            vec!["mint_lp", "burn_lp", "private_transfer", "claim_incentive"],
            vec![
                "lp_mint_commitment",
                "lp_burn_commitment",
                "incentive_claim",
            ],
            &json!({"slots": ["lp_balances", "pool_share_notes", "claim_nullifiers"], "privacy": "share_commitments"}),
            "private-lp-bytecode-devnet",
            state.height,
        )?;
        let lp_manifest_id = state.register_abi_manifest(lp_manifest)?;

        for (class_id, key_root, controller, proposal) in [
            (
                &wxmr_id,
                bridge_keys.key_root(),
                PRIVATE_TOKEN_REGISTRY_DEVNET_BRIDGE_LABEL,
                "grant-pxmr",
            ),
            (
                &usdd_id,
                defi_keys.key_root(),
                PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL,
                "grant-pusd",
            ),
            (
                &lp_id,
                defi_keys.key_root(),
                PRIVATE_TOKEN_REGISTRY_DEVNET_DEFI_LABEL,
                "grant-lp",
            ),
        ] {
            let mint = ShieldedMintBurnPermission::new(
                class_id,
                controller,
                &key_root,
                PermissionScope::Mint,
                1_000_000_000_000,
                PRIVATE_TOKEN_REGISTRY_DEFAULT_PERMISSION_EPOCH_BLOCKS,
                state.height,
                state.height.saturating_add(52_560),
                &format!("{proposal}-mint"),
            )?;
            state.grant_mint_permission(mint)?;
            let burn = ShieldedMintBurnPermission::new(
                class_id,
                controller,
                &key_root,
                PermissionScope::Burn,
                1_000_000_000_000,
                PRIVATE_TOKEN_REGISTRY_DEFAULT_PERMISSION_EPOCH_BLOCKS,
                state.height,
                state.height.saturating_add(52_560),
                &format!("{proposal}-burn"),
            )?;
            state.grant_burn_permission(burn)?;
        }

        for (class_id, label) in [
            (&wxmr_id, "pxmr-threshold-disclosure"),
            (&usdd_id, "pusd-threshold-disclosure"),
            (&lp_id, "lp-threshold-disclosure"),
        ] {
            let policy = ComplianceDisclosurePolicy::privacy_preserving(
                class_id,
                label,
                ComplianceDisclosureMode::ThresholdDisclosure,
                "devnet-zk-compliance",
                vec!["proof-of-reserves", "court-order", "audit-sampling"],
                8,
                2,
                state.height.saturating_add(52_560),
            )?;
            state.apply_compliance_policy(policy)?;
        }

        let wxmr_sponsor = IssueSponsorshipPolicy::new(
            &wxmr_id,
            "pxmr-issuance-sponsor",
            &wxmr_id,
            PRIVATE_TOKEN_REGISTRY_DEFAULT_LOW_FEE_LANE,
            500_000_000_000,
            75_000,
            1_000_000_000,
            9_500,
            state.height,
            state
                .height
                .saturating_add(PRIVATE_TOKEN_REGISTRY_DEFAULT_SPONSOR_EPOCH_BLOCKS),
        )?;
        state.register_issuance_sponsor(wxmr_sponsor)?;
        let usdd_sponsor = IssueSponsorshipPolicy::new(
            &usdd_id,
            "pusd-issuance-sponsor",
            &wxmr_id,
            "stable-private-issuance",
            250_000_000_000,
            50_000,
            5_000_000_000,
            8_000,
            state.height,
            state
                .height
                .saturating_add(PRIVATE_TOKEN_REGISTRY_DEFAULT_SPONSOR_EPOCH_BLOCKS),
        )?;
        state.register_issuance_sponsor(usdd_sponsor)?;

        let wxmr_hook = PrivateTransferHook::new(
            &wxmr_id,
            "private-wxmr-token-contract",
            &wxmr_manifest_id,
            vec![
                TransferHookPhase::BeforeTransfer,
                TransferHookPhase::AfterTransfer,
                TransferHookPhase::AfterMint,
                TransferHookPhase::AfterBurn,
            ],
            "on_private_wxmr_flow",
            &json!({"reserve_check": "bucketed", "bridge_nullifiers": "required"}),
            80_000,
            512,
            "",
        )?;
        state.attach_transfer_hook(wxmr_hook)?;
        let usdd_hook = PrivateTransferHook::new(
            &usdd_id,
            "private-pusd-token-contract",
            &usdd_manifest_id,
            vec![
                TransferHookPhase::BeforeTransfer,
                TransferHookPhase::AfterTransfer,
                TransferHookPhase::BeforeLiquidation,
            ],
            "on_private_stable_asset_flow",
            &json!({"risk_bucket": "required", "oracle_epoch": "sealed"}),
            90_000,
            768,
            "",
        )?;
        state.attach_transfer_hook(usdd_hook)?;
        let lp_hook = PrivateTransferHook::new(
            &lp_id,
            "private-amm-lp-token-contract",
            &lp_manifest_id,
            vec![
                TransferHookPhase::AfterMint,
                TransferHookPhase::AfterBurn,
                TransferHookPhase::AfterSwap,
            ],
            "on_private_lp_flow",
            &json!({"pool_id": PRIVATE_TOKEN_REGISTRY_DEFAULT_DEFI_VENUE, "claim_nullifier": "required"}),
            70_000,
            384,
            "",
        )?;
        state.attach_transfer_hook(lp_hook)?;

        let wxmr_listing = DefiListingPolicy::new(
            &wxmr_id,
            PRIVATE_TOKEN_REGISTRY_DEFAULT_DEFI_VENUE,
            DefiVenueKind::AmmPool,
            vec![usdd_id.clone()],
            250_000_000_000,
            7_500,
            30,
            ListingPermission::GovernanceApproved,
            "list-pxmr-devnet-amm",
            state.height,
            state.height.saturating_add(52_560),
        )?;
        state.apply_defi_listing_policy(wxmr_listing)?;
        let usdd_listing = DefiListingPolicy::new(
            &usdd_id,
            PRIVATE_TOKEN_REGISTRY_DEFAULT_DEFI_VENUE,
            DefiVenueKind::StableSwap,
            vec![wxmr_id.clone()],
            1_000_000_000,
            8_000,
            5,
            ListingPermission::GovernanceApproved,
            "list-pusd-devnet-stableswap",
            state.height,
            state.height.saturating_add(52_560),
        )?;
        state.apply_defi_listing_policy(usdd_listing)?;
        let lp_listing = DefiListingPolicy::new(
            &lp_id,
            "devnet-private-incentive-router",
            DefiVenueKind::Router,
            vec![wxmr_id.clone(), usdd_id.clone()],
            100_000_000_000,
            10_000,
            0,
            ListingPermission::Curated,
            "list-lp-incentive-router",
            state.height,
            state.height.saturating_add(52_560),
        )?;
        state.apply_defi_listing_policy(lp_listing)?;

        let lp_incentive = LiquidityIncentivePolicy::new(
            &lp_id,
            PRIVATE_TOKEN_REGISTRY_DEFAULT_DEFI_VENUE,
            &usdd_id,
            1_000_000_000,
            25_000,
            "devnet-private-lp-eligibility",
            state.height,
            state.height.saturating_add(10_080),
        )?;
        state.register_liquidity_incentive(lp_incentive)?;

        state.activate_class(&wxmr_id, "activate-pxmr-devnet")?;
        state.activate_class(&usdd_id, "activate-pusd-devnet")?;
        state.activate_class(&lp_id, "activate-lp-devnet")?;

        for class_id in [&wxmr_id, &usdd_id, &lp_id] {
            let class_root = state
                .token_classes
                .get(class_id)
                .map(PrivateTokenClass::class_root)
                .ok_or_else(|| "devnet class missing for audit receipt".to_string())?;
            let receipt = PrivateTokenAuditReceipt::new(
                AuditReceiptKind::GenesisIssue,
                class_id,
                PRIVATE_TOKEN_REGISTRY_DEVNET_GOVERNANCE_LABEL,
                0,
                &private_token_empty_root("PRIVATE-TOKEN-GENESIS-BEFORE"),
                &class_root,
                &json!({
                    "class_id": class_id,
                    "governance_key_id": governance_key_id,
                    "bridge_key_id": bridge_key_id,
                    "defi_key_id": defi_key_id,
                }),
                "devnet private token class activated",
                state.height,
                state.next_audit_sequence,
            )?;
            state.append_audit_receipt(receipt)?;
        }

        let upgrade_manifest = ContractAbiManifest::new(
            &wxmr_id,
            "private-wxmr-token-contract",
            "private-wrapped-monero-token",
            "1.1.0",
            vec![
                "shielded_mint",
                "shielded_burn",
                "private_transfer",
                "bridge_reconcile",
                "batch_fee_sponsor",
            ],
            vec![
                "mint_commitment",
                "burn_commitment",
                "transfer_commitment",
                "sponsor_spend",
            ],
            &json!({"slots": ["balances", "nullifiers", "reserve_epochs", "sponsor_epochs"], "privacy": "note_commitments"}),
            "private-wxmr-bytecode-devnet-v1-1",
            state.height.saturating_add(1),
        )?;
        let upgrade_manifest_id = state.register_abi_manifest(upgrade_manifest.clone())?;
        let current_manifest = state
            .abi_manifests
            .get(&wxmr_manifest_id)
            .cloned()
            .ok_or_else(|| "devnet current manifest missing".to_string())?;
        let upgrade = PqGovernedUpgrade::new(
            &wxmr_id,
            "private-wxmr-token-contract",
            &current_manifest,
            &upgrade_manifest,
            PqGovernanceModel::Hybrid,
            "pq-upgrade-pxmr-batch-sponsor",
            7_500,
            state.height,
            &json!({
                "new_manifest_id": upgrade_manifest_id,
                "migration": "append sponsor epoch slot",
                "privacy": "no note opening",
            }),
        )?;
        state.approve_upgrade(upgrade)?;

        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> PrivateTokenRegistryResult<String> {
        if height < self.height {
            return Err("private token registry height cannot move backward".to_string());
        }
        self.height = height;
        Ok(self.state_root())
    }

    pub fn register_pq_key_set(&mut self, key_set: PqKeySet) -> PrivateTokenRegistryResult<String> {
        key_set.validate()?;
        if self.pq_key_sets.contains_key(&key_set.key_set_id) {
            return Err("PQ key set already exists".to_string());
        }
        let key_set_id = key_set.key_set_id.clone();
        self.pq_key_sets.insert(key_set_id.clone(), key_set);
        Ok(key_set_id)
    }

    pub fn register_token_class(
        &mut self,
        token_class: PrivateTokenClass,
    ) -> PrivateTokenRegistryResult<String> {
        token_class.validate()?;
        if self.token_classes.contains_key(&token_class.class_id) {
            return Err("private token class already exists".to_string());
        }
        if !self.pq_key_sets.contains_key(&token_class.pq_key_set_id) {
            return Err("private token class references unknown PQ key set".to_string());
        }
        let class_id = token_class.class_id.clone();
        self.token_classes.insert(class_id.clone(), token_class);
        Ok(class_id)
    }

    pub fn register_abi_manifest(
        &mut self,
        manifest: ContractAbiManifest,
    ) -> PrivateTokenRegistryResult<String> {
        manifest.validate()?;
        if self.abi_manifests.contains_key(&manifest.manifest_id) {
            return Err("ABI manifest already exists".to_string());
        }
        let class_id = manifest.class_id.clone();
        let manifest_id = manifest.manifest_id.clone();
        let manifest_root = manifest.manifest_root();
        let should_attach = {
            let class = self
                .token_classes
                .get(&class_id)
                .ok_or_else(|| "ABI manifest references unknown class".to_string())?;
            class.abi_manifest_id.is_empty() || !class.status.is_active()
        };
        self.abi_manifests.insert(manifest_id.clone(), manifest);
        if should_attach {
            let class = self
                .token_classes
                .get_mut(&class_id)
                .ok_or_else(|| "ABI manifest references unknown class".to_string())?;
            class.abi_manifest_id = manifest_id.clone();
            class.abi_root = manifest_root;
            class.updated_at_height = self.height;
        }
        Ok(manifest_id)
    }

    pub fn grant_mint_permission(
        &mut self,
        permission: ShieldedMintBurnPermission,
    ) -> PrivateTokenRegistryResult<String> {
        if !permission.scope.is_mint() {
            return Err("grant_mint_permission requires mint scope".to_string());
        }
        self.grant_permission(permission, true)
    }

    pub fn grant_burn_permission(
        &mut self,
        permission: ShieldedMintBurnPermission,
    ) -> PrivateTokenRegistryResult<String> {
        if !permission.scope.is_burn() {
            return Err("grant_burn_permission requires burn scope".to_string());
        }
        self.grant_permission(permission, false)
    }

    fn grant_permission(
        &mut self,
        permission: ShieldedMintBurnPermission,
        mint: bool,
    ) -> PrivateTokenRegistryResult<String> {
        permission.validate()?;
        if !self.token_classes.contains_key(&permission.class_id) {
            return Err("permission references unknown private token class".to_string());
        }
        let permission_id = permission.permission_id.clone();
        let class_id = permission.class_id.clone();
        if mint {
            if self.mint_permissions.contains_key(&permission_id) {
                return Err("mint permission already exists".to_string());
            }
            self.mint_permissions
                .insert(permission_id.clone(), permission);
            let root = self.mint_permission_root_for_class(&class_id);
            if let Some(class) = self.token_classes.get_mut(&class_id) {
                class.mint_permission_root = root;
                class.updated_at_height = self.height;
            }
        } else {
            if self.burn_permissions.contains_key(&permission_id) {
                return Err("burn permission already exists".to_string());
            }
            self.burn_permissions
                .insert(permission_id.clone(), permission);
            let root = self.burn_permission_root_for_class(&class_id);
            if let Some(class) = self.token_classes.get_mut(&class_id) {
                class.burn_permission_root = root;
                class.updated_at_height = self.height;
            }
        }
        Ok(permission_id)
    }

    pub fn apply_compliance_policy(
        &mut self,
        policy: ComplianceDisclosurePolicy,
    ) -> PrivateTokenRegistryResult<String> {
        policy.validate()?;
        let class_id = policy.class_id.clone();
        if !self.token_classes.contains_key(&class_id) {
            return Err("compliance policy references unknown class".to_string());
        }
        let policy_id = policy.policy_id.clone();
        let policy_root = policy.policy_root();
        self.compliance_policies.insert(policy_id.clone(), policy);
        if let Some(class) = self.token_classes.get_mut(&class_id) {
            class.compliance_policy_id = policy_id.clone();
            class.compliance_policy_root = policy_root;
            class.updated_at_height = self.height;
        }
        Ok(policy_id)
    }

    pub fn register_issuance_sponsor(
        &mut self,
        sponsor: IssueSponsorshipPolicy,
    ) -> PrivateTokenRegistryResult<String> {
        sponsor.validate()?;
        let class_id = sponsor.class_id.clone();
        if !self.token_classes.contains_key(&class_id) {
            return Err("sponsor references unknown class".to_string());
        }
        let sponsor_id = sponsor.sponsor_id.clone();
        let sponsor_root = sponsor.sponsorship_root();
        self.issuance_sponsors.insert(sponsor_id.clone(), sponsor);
        if let Some(class) = self.token_classes.get_mut(&class_id) {
            class.sponsorship_id = sponsor_id.clone();
            class.sponsorship_root = sponsor_root;
            class.updated_at_height = self.height;
        }
        Ok(sponsor_id)
    }

    pub fn register_liquidity_incentive(
        &mut self,
        incentive: LiquidityIncentivePolicy,
    ) -> PrivateTokenRegistryResult<String> {
        incentive.validate()?;
        let class_id = incentive.class_id.clone();
        if !self.token_classes.contains_key(&class_id) {
            return Err("liquidity incentive references unknown class".to_string());
        }
        let incentive_id = incentive.incentive_id.clone();
        let incentive_root = incentive.incentive_root();
        self.liquidity_incentives
            .insert(incentive_id.clone(), incentive);
        if let Some(class) = self.token_classes.get_mut(&class_id) {
            class.incentive_id = incentive_id.clone();
            class.incentive_root = incentive_root;
            class.updated_at_height = self.height;
        }
        Ok(incentive_id)
    }

    pub fn attach_transfer_hook(
        &mut self,
        hook: PrivateTransferHook,
    ) -> PrivateTokenRegistryResult<String> {
        hook.validate()?;
        if !self.abi_manifests.contains_key(&hook.manifest_id) {
            return Err("transfer hook references unknown ABI manifest".to_string());
        }
        if !self.token_classes.contains_key(&hook.class_id) {
            return Err("transfer hook references unknown class".to_string());
        }
        let hook_id = hook.hook_id.clone();
        let class_id = hook.class_id.clone();
        self.transfer_hooks.insert(hook_id.clone(), hook);
        let root = self.transfer_hook_root_for_class(&class_id);
        if let Some(class) = self.token_classes.get_mut(&class_id) {
            class.transfer_hook_root = root;
            class.updated_at_height = self.height;
        }
        Ok(hook_id)
    }

    pub fn apply_defi_listing_policy(
        &mut self,
        listing: DefiListingPolicy,
    ) -> PrivateTokenRegistryResult<String> {
        listing.validate()?;
        let class_id = listing.class_id.clone();
        let class = self
            .token_classes
            .get(&class_id)
            .ok_or_else(|| "DeFi listing references unknown class".to_string())?;
        if !class.class_kind.supports_defi() {
            return Err("class kind does not support DeFi listing".to_string());
        }
        let listing_id = listing.listing_id.clone();
        self.defi_listing_policies
            .insert(listing_id.clone(), listing);
        let root = self.defi_listing_root_for_class(&class_id);
        if let Some(class) = self.token_classes.get_mut(&class_id) {
            class.defi_listing_root = root;
            class.updated_at_height = self.height;
        }
        Ok(listing_id)
    }

    pub fn approve_upgrade(
        &mut self,
        upgrade: PqGovernedUpgrade,
    ) -> PrivateTokenRegistryResult<String> {
        upgrade.validate()?;
        if !self.token_classes.contains_key(&upgrade.class_id) {
            return Err("upgrade references unknown class".to_string());
        }
        if !self.abi_manifests.contains_key(&upgrade.from_manifest_id) {
            return Err("upgrade references unknown from manifest".to_string());
        }
        if !self.abi_manifests.contains_key(&upgrade.to_manifest_id) {
            return Err("upgrade references unknown to manifest".to_string());
        }
        let upgrade_id = upgrade.upgrade_id.clone();
        self.upgrades.insert(upgrade_id.clone(), upgrade);
        Ok(upgrade_id)
    }

    pub fn activate_class(
        &mut self,
        class_id: &str,
        governance_proposal_id: &str,
    ) -> PrivateTokenRegistryResult<String> {
        validate_non_empty(governance_proposal_id, "class activation proposal")?;
        let class_snapshot = self
            .token_classes
            .get(class_id)
            .cloned()
            .ok_or_else(|| "activation references unknown class".to_string())?;
        if class_snapshot.abi_manifest_id.is_empty() {
            return Err("activation requires ABI manifest".to_string());
        }
        if class_snapshot.compliance_policy_id.is_empty() {
            return Err("activation requires compliance policy".to_string());
        }
        if class_snapshot.supply_mode.allows_mint()
            && !self.has_active_permission(class_id, true, self.height)
        {
            return Err("activation requires active mint permission".to_string());
        }
        if class_snapshot.supply_mode.allows_burn()
            && !self.has_active_permission(class_id, false, self.height)
        {
            return Err("activation requires active burn permission".to_string());
        }
        let mut updated = class_snapshot;
        updated.status = RegistryLifecycleStatus::Active;
        updated.updated_at_height = self.height;
        let root = updated.class_root();
        self.token_classes.insert(class_id.to_string(), updated);
        Ok(root)
    }

    pub fn append_audit_receipt(
        &mut self,
        receipt: PrivateTokenAuditReceipt,
    ) -> PrivateTokenRegistryResult<String> {
        receipt.validate()?;
        if receipt.sequence != self.next_audit_sequence {
            return Err("audit receipt sequence mismatch".to_string());
        }
        if self.audit_receipts.contains_key(&receipt.receipt_id) {
            return Err("audit receipt already exists".to_string());
        }
        let receipt_id = receipt.receipt_id.clone();
        self.next_audit_sequence = self.next_audit_sequence.saturating_add(1);
        self.audit_receipts.insert(receipt_id.clone(), receipt);
        Ok(receipt_id)
    }

    pub fn roots(&self) -> PrivateTokenRegistryRoots {
        PrivateTokenRegistryRoots {
            pq_key_set_root: self.pq_key_set_root(),
            token_class_root: self.token_class_root(),
            mint_permission_root: self.mint_permission_root(),
            burn_permission_root: self.burn_permission_root(),
            abi_manifest_root: self.abi_manifest_root(),
            upgrade_root: self.upgrade_root(),
            defi_listing_root: self.defi_listing_root(),
            transfer_hook_root: self.transfer_hook_root(),
            compliance_policy_root: self.compliance_policy_root(),
            sponsorship_root: self.sponsorship_root(),
            incentive_root: self.incentive_root(),
            audit_receipt_root: self.audit_receipt_root(),
        }
    }

    pub fn counters(&self) -> PrivateTokenRegistryCounters {
        PrivateTokenRegistryCounters {
            pq_key_set_count: self.pq_key_sets.len() as u64,
            token_class_count: self.token_classes.len() as u64,
            active_class_count: self
                .token_classes
                .values()
                .filter(|class| class.status.is_active())
                .count() as u64,
            low_fee_class_count: self.low_fee_class_ids().len() as u64,
            defi_ready_class_count: self.defi_ready_class_ids().len() as u64,
            mint_permission_count: self.mint_permissions.len() as u64,
            burn_permission_count: self.burn_permissions.len() as u64,
            abi_manifest_count: self.abi_manifests.len() as u64,
            upgrade_count: self.upgrades.len() as u64,
            defi_listing_count: self.defi_listing_policies.len() as u64,
            transfer_hook_count: self.transfer_hooks.len() as u64,
            compliance_policy_count: self.compliance_policies.len() as u64,
            sponsorship_count: self.issuance_sponsors.len() as u64,
            incentive_count: self.liquidity_incentives.len() as u64,
            audit_receipt_count: self.audit_receipts.len() as u64,
            next_audit_sequence: self.next_audit_sequence,
        }
    }

    pub fn pq_key_set_root(&self) -> String {
        private_token_pq_key_set_root_set(&self.pq_key_sets.values().cloned().collect::<Vec<_>>())
    }

    pub fn token_class_root(&self) -> String {
        private_token_class_set_root(&self.token_classes.values().cloned().collect::<Vec<_>>())
    }

    pub fn mint_permission_root(&self) -> String {
        private_token_permission_set_root(
            "PRIVATE-TOKEN-MINT-PERMISSION",
            &self.mint_permissions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn burn_permission_root(&self) -> String {
        private_token_permission_set_root(
            "PRIVATE-TOKEN-BURN-PERMISSION",
            &self.burn_permissions.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn abi_manifest_root(&self) -> String {
        private_token_abi_manifest_set_root(
            &self.abi_manifests.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn upgrade_root(&self) -> String {
        private_token_upgrade_set_root(&self.upgrades.values().cloned().collect::<Vec<_>>())
    }

    pub fn defi_listing_root(&self) -> String {
        private_token_defi_listing_set_root(
            &self
                .defi_listing_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn transfer_hook_root(&self) -> String {
        private_token_transfer_hook_set_root(
            &self.transfer_hooks.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn compliance_policy_root(&self) -> String {
        private_token_compliance_policy_set_root(
            &self
                .compliance_policies
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn sponsorship_root(&self) -> String {
        private_token_sponsorship_set_root(
            &self.issuance_sponsors.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn incentive_root(&self) -> String {
        private_token_incentive_set_root(
            &self
                .liquidity_incentives
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn audit_receipt_root(&self) -> String {
        private_token_audit_receipt_set_root(
            &self.audit_receipts.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn low_fee_class_ids(&self) -> Vec<String> {
        self.token_classes
            .values()
            .filter(|class| {
                class.low_fee_ready()
                    && self
                        .issuance_sponsors
                        .get(&class.sponsorship_id)
                        .map_or(false, |sponsor| sponsor.is_active_at(self.height))
            })
            .map(|class| class.class_id.clone())
            .collect()
    }

    pub fn defi_ready_class_ids(&self) -> Vec<String> {
        self.token_classes
            .values()
            .filter(|class| class.defi_ready())
            .map(|class| class.class_id.clone())
            .collect()
    }

    pub fn state_root(&self) -> String {
        private_token_registry_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    fn public_record_without_state_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "private_token_registry_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_REGISTRY_PROTOCOL_VERSION,
            "height": self.height,
            "roots": roots.public_record(),
            "root_commitment": roots.state_root(),
            "counters": counters.public_record(),
            "low_fee_class_ids": self.low_fee_class_ids(),
            "defi_ready_class_ids": self.defi_ready_class_ids(),
        })
    }

    pub fn validate(&self) -> PrivateTokenRegistryResult<String> {
        for key_set in self.pq_key_sets.values() {
            key_set.validate()?;
        }
        for manifest in self.abi_manifests.values() {
            manifest.validate()?;
            if !self.token_classes.contains_key(&manifest.class_id) {
                return Err("ABI manifest references unknown class".to_string());
            }
        }
        for permission in self.mint_permissions.values() {
            permission.validate()?;
            if !permission.scope.is_mint() {
                return Err("mint permission map contains non-mint scope".to_string());
            }
            if !self.token_classes.contains_key(&permission.class_id) {
                return Err("mint permission references unknown class".to_string());
            }
        }
        for permission in self.burn_permissions.values() {
            permission.validate()?;
            if !permission.scope.is_burn() {
                return Err("burn permission map contains non-burn scope".to_string());
            }
            if !self.token_classes.contains_key(&permission.class_id) {
                return Err("burn permission references unknown class".to_string());
            }
        }
        for policy in self.compliance_policies.values() {
            policy.validate()?;
            if !self.token_classes.contains_key(&policy.class_id) {
                return Err("compliance policy references unknown class".to_string());
            }
        }
        for sponsor in self.issuance_sponsors.values() {
            sponsor.validate()?;
            if !self.token_classes.contains_key(&sponsor.class_id) {
                return Err("sponsor references unknown class".to_string());
            }
        }
        for hook in self.transfer_hooks.values() {
            hook.validate()?;
            if !self.token_classes.contains_key(&hook.class_id) {
                return Err("transfer hook references unknown class".to_string());
            }
            if !self.abi_manifests.contains_key(&hook.manifest_id) {
                return Err("transfer hook references unknown ABI manifest".to_string());
            }
        }
        for listing in self.defi_listing_policies.values() {
            listing.validate()?;
            let class = self
                .token_classes
                .get(&listing.class_id)
                .ok_or_else(|| "DeFi listing references unknown class".to_string())?;
            if !class.class_kind.supports_defi() {
                return Err("DeFi listing class kind unsupported".to_string());
            }
        }
        for incentive in self.liquidity_incentives.values() {
            incentive.validate()?;
            if !self.token_classes.contains_key(&incentive.class_id) {
                return Err("liquidity incentive references unknown class".to_string());
            }
        }
        for upgrade in self.upgrades.values() {
            upgrade.validate()?;
            if !self.token_classes.contains_key(&upgrade.class_id) {
                return Err("upgrade references unknown class".to_string());
            }
            let from_manifest = self
                .abi_manifests
                .get(&upgrade.from_manifest_id)
                .ok_or_else(|| "upgrade from manifest missing".to_string())?;
            if from_manifest.manifest_root() != upgrade.from_manifest_root {
                return Err("upgrade from manifest root mismatch".to_string());
            }
            let to_manifest = self
                .abi_manifests
                .get(&upgrade.to_manifest_id)
                .ok_or_else(|| "upgrade to manifest missing".to_string())?;
            if to_manifest.manifest_root() != upgrade.to_manifest_root {
                return Err("upgrade to manifest root mismatch".to_string());
            }
        }
        for receipt in self.audit_receipts.values() {
            receipt.validate()?;
        }
        for class in self.token_classes.values() {
            class.validate()?;
            let key_set = self
                .pq_key_sets
                .get(&class.pq_key_set_id)
                .ok_or_else(|| "class references unknown PQ key set".to_string())?;
            if key_set.key_root() != class.pq_key_root {
                return Err("class PQ key root mismatch".to_string());
            }
            if !class.abi_manifest_id.is_empty() {
                let manifest = self
                    .abi_manifests
                    .get(&class.abi_manifest_id)
                    .ok_or_else(|| "class ABI manifest missing".to_string())?;
                if manifest.manifest_root() != class.abi_root {
                    return Err("class ABI root mismatch".to_string());
                }
            }
            if !class.compliance_policy_id.is_empty() {
                let policy = self
                    .compliance_policies
                    .get(&class.compliance_policy_id)
                    .ok_or_else(|| "class compliance policy missing".to_string())?;
                if policy.policy_root() != class.compliance_policy_root {
                    return Err("class compliance root mismatch".to_string());
                }
            }
            if class.mint_permission_root != self.mint_permission_root_for_class(&class.class_id) {
                return Err("class mint permission root mismatch".to_string());
            }
            if class.burn_permission_root != self.burn_permission_root_for_class(&class.class_id) {
                return Err("class burn permission root mismatch".to_string());
            }
            if class.transfer_hook_root != self.transfer_hook_root_for_class(&class.class_id) {
                return Err("class transfer hook root mismatch".to_string());
            }
            if class.defi_listing_root != self.defi_listing_root_for_class(&class.class_id) {
                return Err("class DeFi listing root mismatch".to_string());
            }
            if !class.sponsorship_id.is_empty() {
                let sponsor = self
                    .issuance_sponsors
                    .get(&class.sponsorship_id)
                    .ok_or_else(|| "class sponsor missing".to_string())?;
                if sponsor.sponsorship_root() != class.sponsorship_root {
                    return Err("class sponsorship root mismatch".to_string());
                }
            }
            if !class.incentive_id.is_empty() {
                let incentive = self
                    .liquidity_incentives
                    .get(&class.incentive_id)
                    .ok_or_else(|| "class incentive missing".to_string())?;
                if incentive.incentive_root() != class.incentive_root {
                    return Err("class incentive root mismatch".to_string());
                }
            }
            if class.status.is_active() {
                if class.supply_mode.allows_mint()
                    && !self.has_active_permission(&class.class_id, true, self.height)
                {
                    return Err("active class lacks active mint permission".to_string());
                }
                if class.supply_mode.allows_burn()
                    && !self.has_active_permission(&class.class_id, false, self.height)
                {
                    return Err("active class lacks active burn permission".to_string());
                }
            }
        }
        Ok(self.state_root())
    }

    fn has_active_permission(&self, class_id: &str, mint: bool, height: u64) -> bool {
        if mint {
            self.mint_permissions.values().any(|permission| {
                permission.class_id == class_id && permission.is_active_at(height)
            })
        } else {
            self.burn_permissions.values().any(|permission| {
                permission.class_id == class_id && permission.is_active_at(height)
            })
        }
    }

    fn mint_permission_root_for_class(&self, class_id: &str) -> String {
        let permissions = self
            .mint_permissions
            .values()
            .filter(|permission| permission.class_id == class_id)
            .cloned()
            .collect::<Vec<_>>();
        private_token_permission_set_root("PRIVATE-TOKEN-MINT-PERMISSION", &permissions)
    }

    fn burn_permission_root_for_class(&self, class_id: &str) -> String {
        let permissions = self
            .burn_permissions
            .values()
            .filter(|permission| permission.class_id == class_id)
            .cloned()
            .collect::<Vec<_>>();
        private_token_permission_set_root("PRIVATE-TOKEN-BURN-PERMISSION", &permissions)
    }

    fn transfer_hook_root_for_class(&self, class_id: &str) -> String {
        let hooks = self
            .transfer_hooks
            .values()
            .filter(|hook| hook.class_id == class_id)
            .cloned()
            .collect::<Vec<_>>();
        private_token_transfer_hook_set_root(&hooks)
    }

    fn defi_listing_root_for_class(&self, class_id: &str) -> String {
        let listings = self
            .defi_listing_policies
            .values()
            .filter(|listing| listing.class_id == class_id)
            .cloned()
            .collect::<Vec<_>>();
        private_token_defi_listing_set_root(&listings)
    }
}

pub fn private_token_registry_state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-TOKEN-REGISTRY-STATE",
        &[HashPart::Str(CHAIN_ID), HashPart::Json(record)],
        32,
    )
}

pub fn private_token_class_id(
    symbol: &str,
    decimals: u8,
    class_kind: &str,
    supply_mode: &str,
    issuer_root: &str,
    metadata_root: &str,
    created_at_height: u64,
    governance_proposal_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&normalize_symbol(symbol)),
            HashPart::Int(decimals as i128),
            HashPart::Str(class_kind),
            HashPart::Str(supply_mode),
            HashPart::Str(issuer_root),
            HashPart::Str(metadata_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(governance_proposal_id),
        ],
        32,
    )
}

pub fn private_token_pq_key_set_id(
    owner_label: &str,
    ml_kem_root: &str,
    ml_dsa_root: &str,
    slh_dsa_root: &str,
    threshold: u16,
    rotation_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-PQ-KEY-SET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(owner_label),
            HashPart::Str(ml_kem_root),
            HashPart::Str(ml_dsa_root),
            HashPart::Str(slh_dsa_root),
            HashPart::Int(threshold as i128),
            HashPart::Int(rotation_height as i128),
        ],
        32,
    )
}

pub fn private_token_permission_id(
    class_id: &str,
    controller_commitment: &str,
    scope: &str,
    note_commitment_root: &str,
    valid_from_height: u64,
    grant_proposal_id: &str,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-PERMISSION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(controller_commitment),
            HashPart::Str(scope),
            HashPart::Str(note_commitment_root),
            HashPart::Int(valid_from_height as i128),
            HashPart::Str(grant_proposal_id),
        ],
        32,
    )
}

pub fn private_token_abi_manifest_id(
    class_id: &str,
    contract_id: &str,
    name: &str,
    version: &str,
    schema_root: &str,
    bytecode_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-ABI-MANIFEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(contract_id),
            HashPart::Str(name),
            HashPart::Str(version),
            HashPart::Str(schema_root),
            HashPart::Str(bytecode_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn private_token_upgrade_id(
    class_id: &str,
    contract_id: &str,
    from_manifest_id: &str,
    to_manifest_id: &str,
    proposal_id: &str,
    governance_model: &str,
    timelock_start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-UPGRADE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(contract_id),
            HashPart::Str(from_manifest_id),
            HashPart::Str(to_manifest_id),
            HashPart::Str(proposal_id),
            HashPart::Str(governance_model),
            HashPart::Int(timelock_start_height as i128),
        ],
        32,
    )
}

pub fn private_token_defi_listing_id(
    class_id: &str,
    venue_id: &str,
    venue_kind: &str,
    listing_permission: &str,
    proposal_id: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-DEFI-LISTING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(venue_id),
            HashPart::Str(venue_kind),
            HashPart::Str(listing_permission),
            HashPart::Str(proposal_id),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn private_token_transfer_hook_id(
    class_id: &str,
    contract_id: &str,
    manifest_id: &str,
    phase_root: &str,
    entrypoint: &str,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-TRANSFER-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(contract_id),
            HashPart::Str(manifest_id),
            HashPart::Str(phase_root),
            HashPart::Str(entrypoint),
        ],
        32,
    )
}

pub fn private_token_compliance_policy_id(
    class_id: &str,
    policy_label: &str,
    disclosure_mode: &str,
    jurisdiction_commitment_root: &str,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-COMPLIANCE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(policy_label),
            HashPart::Str(disclosure_mode),
            HashPart::Str(jurisdiction_commitment_root),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn private_token_sponsorship_id(
    class_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    low_fee_lane: &str,
    valid_from_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(low_fee_lane),
            HashPart::Int(valid_from_height as i128),
        ],
        32,
    )
}

pub fn private_token_incentive_id(
    class_id: &str,
    venue_id: &str,
    reward_asset_id: &str,
    eligibility_root: &str,
    start_height: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-INCENTIVE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(venue_id),
            HashPart::Str(reward_asset_id),
            HashPart::Str(eligibility_root),
            HashPart::Int(start_height as i128),
        ],
        32,
    )
}

pub fn private_token_audit_receipt_id(
    receipt_kind: &str,
    subject_id: &str,
    actor_commitment: &str,
    root_before: &str,
    root_after: &str,
    issued_at_height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-AUDIT-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(receipt_kind),
            HashPart::Str(subject_id),
            HashPart::Str(actor_commitment),
            HashPart::Str(root_before),
            HashPart::Str(root_after),
            HashPart::Int(issued_at_height as i128),
            HashPart::Int(sequence as i128),
        ],
        32,
    )
}

pub fn private_token_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn private_token_payload_root(domain: &str, payload: &Value, blinding_label: &str) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(payload),
            HashPart::Str(blinding_label),
        ],
        32,
    )
}

pub fn private_token_amount_commitment(
    subject_id: &str,
    amount_units: u64,
    blinding: &str,
) -> String {
    domain_hash(
        "PRIVATE-TOKEN-AMOUNT-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(subject_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn private_token_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn private_token_metadata_commitment_root(metadata: &RegistryMetadataCommitment) -> String {
    domain_hash(
        "PRIVATE-TOKEN-METADATA-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&metadata.public_record()),
        ],
        32,
    )
}

pub fn private_token_pq_key_set_root(key_set: &PqKeySet) -> String {
    domain_hash(
        "PRIVATE-TOKEN-PQ-KEY-SET",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&key_set.public_record()),
        ],
        32,
    )
}

pub fn private_token_class_root(token_class: &PrivateTokenClass) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CLASS",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&token_class.public_record()),
        ],
        32,
    )
}

pub fn private_token_permission_root(permission: &ShieldedMintBurnPermission) -> String {
    domain_hash(
        "PRIVATE-TOKEN-PERMISSION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&permission.public_record()),
        ],
        32,
    )
}

pub fn private_token_abi_manifest_root(manifest: &ContractAbiManifest) -> String {
    domain_hash(
        "PRIVATE-TOKEN-ABI-MANIFEST",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&manifest.public_record()),
        ],
        32,
    )
}

pub fn private_token_upgrade_root(upgrade: &PqGovernedUpgrade) -> String {
    domain_hash(
        "PRIVATE-TOKEN-UPGRADE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&upgrade.public_record()),
        ],
        32,
    )
}

pub fn private_token_defi_listing_root(listing: &DefiListingPolicy) -> String {
    domain_hash(
        "PRIVATE-TOKEN-DEFI-LISTING",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&listing.public_record()),
        ],
        32,
    )
}

pub fn private_token_transfer_hook_root(hook: &PrivateTransferHook) -> String {
    domain_hash(
        "PRIVATE-TOKEN-TRANSFER-HOOK",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&hook.public_record()),
        ],
        32,
    )
}

pub fn private_token_compliance_policy_root(policy: &ComplianceDisclosurePolicy) -> String {
    domain_hash(
        "PRIVATE-TOKEN-COMPLIANCE-POLICY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&policy.public_record()),
        ],
        32,
    )
}

pub fn private_token_sponsorship_root(sponsor: &IssueSponsorshipPolicy) -> String {
    domain_hash(
        "PRIVATE-TOKEN-SPONSORSHIP",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&sponsor.public_record()),
        ],
        32,
    )
}

pub fn private_token_incentive_root(incentive: &LiquidityIncentivePolicy) -> String {
    domain_hash(
        "PRIVATE-TOKEN-INCENTIVE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&incentive.public_record()),
        ],
        32,
    )
}

pub fn private_token_audit_receipt_root(receipt: &PrivateTokenAuditReceipt) -> String {
    domain_hash(
        "PRIVATE-TOKEN-AUDIT-RECEIPT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Json(&receipt.public_record()),
        ],
        32,
    )
}

pub fn private_token_pq_key_set_root_set(key_sets: &[PqKeySet]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-PQ-KEY-SET",
        &key_sets
            .iter()
            .map(PqKeySet::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_class_set_root(classes: &[PrivateTokenClass]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-CLASS",
        &classes
            .iter()
            .map(PrivateTokenClass::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_permission_set_root(
    domain: &str,
    permissions: &[ShieldedMintBurnPermission],
) -> String {
    merkle_root(
        domain,
        &permissions
            .iter()
            .map(ShieldedMintBurnPermission::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_abi_manifest_set_root(manifests: &[ContractAbiManifest]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-ABI-MANIFEST",
        &manifests
            .iter()
            .map(ContractAbiManifest::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_upgrade_set_root(upgrades: &[PqGovernedUpgrade]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-UPGRADE",
        &upgrades
            .iter()
            .map(PqGovernedUpgrade::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_defi_listing_set_root(listings: &[DefiListingPolicy]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-DEFI-LISTING",
        &listings
            .iter()
            .map(DefiListingPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_transfer_hook_set_root(hooks: &[PrivateTransferHook]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-TRANSFER-HOOK",
        &hooks
            .iter()
            .map(PrivateTransferHook::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_compliance_policy_set_root(policies: &[ComplianceDisclosurePolicy]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-COMPLIANCE-POLICY",
        &policies
            .iter()
            .map(ComplianceDisclosurePolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_sponsorship_set_root(sponsors: &[IssueSponsorshipPolicy]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-SPONSORSHIP",
        &sponsors
            .iter()
            .map(IssueSponsorshipPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_incentive_set_root(incentives: &[LiquidityIncentivePolicy]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-INCENTIVE",
        &incentives
            .iter()
            .map(LiquidityIncentivePolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn private_token_audit_receipt_set_root(receipts: &[PrivateTokenAuditReceipt]) -> String {
    merkle_root(
        "PRIVATE-TOKEN-AUDIT-RECEIPT",
        &receipts
            .iter()
            .map(PrivateTokenAuditReceipt::public_record)
            .collect::<Vec<_>>(),
    )
}

fn phase_set_root(domain: &str, phases: &BTreeSet<TransferHookPhase>) -> String {
    merkle_root(
        domain,
        &phases
            .iter()
            .map(|phase| Value::String(phase.as_str().to_string()))
            .collect::<Vec<_>>(),
    )
}

fn risk_flags_public(flags: &BTreeSet<PrivateTokenRiskFlag>) -> Vec<String> {
    flags.iter().map(PrivateTokenRiskFlag::as_str).collect()
}

fn transfer_hook_phases_public(phases: &BTreeSet<TransferHookPhase>) -> Vec<String> {
    phases
        .iter()
        .map(|phase| phase.as_str().to_string())
        .collect()
}

fn metadata_string(metadata: &Value, key: &str) -> String {
    match metadata.get(key).and_then(Value::as_str) {
        Some(value) => value.to_string(),
        None => String::new(),
    }
}

fn normalize_symbol(value: &str) -> String {
    let mut normalized = String::new();
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
        } else if ch == '-' || ch == '_' {
            normalized.push(ch);
        }
    }
    normalized
}

fn normalize_label(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if ch == ':' || ch == '_' || ch == '.' {
            normalized.push(ch);
            last_dash = false;
        } else if !last_dash {
            normalized.push('-');
            last_dash = true;
        }
    }
    while normalized.ends_with('-') {
        normalized.pop();
    }
    normalized
}

fn validate_non_empty(value: &str, label: &str) -> PrivateTokenRegistryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> PrivateTokenRegistryResult<()> {
    if value > PRIVATE_TOKEN_REGISTRY_MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}
