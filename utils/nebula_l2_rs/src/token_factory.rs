use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type TokenFactoryResult<T> = Result<T, String>;

pub const TOKEN_FACTORY_PROTOCOL_VERSION: &str = "nebula-l2-token-factory-v1";
pub const TOKEN_FACTORY_METADATA_SCHEMA: &str = "nebula-l2-asset-metadata-v1";
pub const TOKEN_FACTORY_REGISTRY_SCHEMA: &str = "nebula-l2-private-asset-registry-v1";
pub const TOKEN_FACTORY_DEFAULT_PQ_SCHEME: &str = "ml-dsa-87+shake256-merkle";
pub const TOKEN_FACTORY_DEFAULT_CONFIDENTIALITY: &str = "commitment_only";
pub const TOKEN_FACTORY_DEFAULT_TRANSFER_ENGINE: &str = "pq-confidential-note-transfer-v1";
pub const TOKEN_FACTORY_DEFAULT_MEMO_POLICY: &str = "memo-commitment-only";
pub const TOKEN_FACTORY_DEFAULT_POLICY_LABEL: &str = "default_private_transfer";
pub const TOKEN_FACTORY_DEFAULT_UPGRADE_SCOPE: &str = "token_factory_governance";
pub const TOKEN_FACTORY_DEFAULT_LOW_FEE_LANE: &str = "asset_issuance";
pub const TOKEN_FACTORY_DEFAULT_PAYMASTER_LABEL: &str = "devnet-token-factory-paymaster";
pub const TOKEN_FACTORY_WXMR_SYMBOL: &str = "wXMR";
pub const TOKEN_FACTORY_WXMR_DISPLAY_NAME: &str = "Wrapped Monero";
pub const TOKEN_FACTORY_WXMR_DECIMALS: u8 = 12;
pub const TOKEN_FACTORY_WXMR_RESERVE_NETWORK: &str = "monero-mainnet";
pub const TOKEN_FACTORY_WXMR_RESERVE_POLICY: &str = "full-reserve-view-key-attested";
pub const TOKEN_FACTORY_MAX_SYMBOL_LEN: usize = 24;
pub const TOKEN_FACTORY_MAX_BPS: u64 = 10_000;
pub const TOKEN_FACTORY_MAX_HOOK_GAS_UNITS: u64 = 10_000_000;
pub const TOKEN_FACTORY_MIN_TIMELOCK_BLOCKS: u64 = 1;
pub const TOKEN_FACTORY_DEVNET_HEIGHT: u64 = 42;
pub const TOKEN_FACTORY_DEVNET_EPOCH: u64 = 1;
pub const TOKEN_FACTORY_DEVNET_GOVERNANCE_LABEL: &str = "nebula-devnet-token-council";
pub const TOKEN_FACTORY_DEVNET_BRIDGE_LABEL: &str = "nebula-devnet-monero-bridge";
pub const TOKEN_FACTORY_DEVNET_DEFI_LABEL: &str = "nebula-devnet-defi-treasury";
pub const TOKEN_FACTORY_DEVNET_DNR_SYMBOL: &str = "DNR";
pub const TOKEN_FACTORY_DEVNET_DNR_NAME: &str = "Nebula Governance";
pub const TOKEN_FACTORY_DEVNET_USDD_SYMBOL: &str = "USDD";
pub const TOKEN_FACTORY_DEVNET_USDD_NAME: &str = "Nebula Private Dollar";
pub const TOKEN_FACTORY_DEVNET_LP_SYMBOL: &str = "WXMRUSDD-LP";
pub const TOKEN_FACTORY_STATUS_ACTIVE: &str = "active";
pub const TOKEN_FACTORY_STATUS_PENDING: &str = "pending";
pub const TOKEN_FACTORY_STATUS_PAUSED: &str = "paused";
pub const TOKEN_FACTORY_STATUS_FROZEN: &str = "frozen";
pub const TOKEN_FACTORY_STATUS_RETIRED: &str = "retired";
pub const TOKEN_FACTORY_STATUS_EXHAUSTED: &str = "exhausted";
pub const TOKEN_FACTORY_STATUS_REVOKED: &str = "revoked";
pub const TOKEN_FACTORY_STATUS_EXECUTED: &str = "executed";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactoryAssetKind {
    Fungible,
    ConfidentialFungible,
    WrappedMonero,
    LiquidityShare,
    Governance,
    Stable,
    Synthetic,
    ContractBound,
    Receipt,
    Custom(String),
}

impl TokenFactoryAssetKind {
    pub fn as_str(&self) -> String {
        match self {
            Self::Fungible => "fungible".to_string(),
            Self::ConfidentialFungible => "confidential_fungible".to_string(),
            Self::WrappedMonero => "wrapped_monero".to_string(),
            Self::LiquidityShare => "liquidity_share".to_string(),
            Self::Governance => "governance".to_string(),
            Self::Stable => "stable".to_string(),
            Self::Synthetic => "synthetic".to_string(),
            Self::ContractBound => "contract_bound".to_string(),
            Self::Receipt => "receipt".to_string(),
            Self::Custom(value) => value.clone(),
        }
    }

    pub fn default_decimals(&self) -> u8 {
        match self {
            Self::WrappedMonero => TOKEN_FACTORY_WXMR_DECIMALS,
            Self::LiquidityShare => 18,
            Self::Governance => 12,
            Self::Stable => 6,
            _ => 12,
        }
    }

    pub fn requires_reserve(&self) -> bool {
        matches!(self, Self::WrappedMonero | Self::Synthetic | Self::Stable)
    }

    pub fn supports_hooks(&self) -> bool {
        !matches!(self, Self::Receipt)
    }

    pub fn is_lp_share(&self) -> bool {
        matches!(self, Self::LiquidityShare)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_asset_kind",
            "chain_id": CHAIN_ID,
            "asset_kind": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactorySupplyMode {
    Fixed,
    MintBurn,
    CappedMintBurn,
    WrappedReserve,
    GovernanceMint,
    PoolShare,
    ContractControlled,
    BurnOnly,
}

impl TokenFactorySupplyMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fixed => "fixed",
            Self::MintBurn => "mint_burn",
            Self::CappedMintBurn => "capped_mint_burn",
            Self::WrappedReserve => "wrapped_reserve",
            Self::GovernanceMint => "governance_mint",
            Self::PoolShare => "pool_share",
            Self::ContractControlled => "contract_controlled",
            Self::BurnOnly => "burn_only",
        }
    }

    pub fn allows_mint(&self) -> bool {
        matches!(
            self,
            Self::MintBurn
                | Self::CappedMintBurn
                | Self::WrappedReserve
                | Self::GovernanceMint
                | Self::PoolShare
                | Self::ContractControlled
        )
    }

    pub fn allows_burn(&self) -> bool {
        !matches!(self, Self::Fixed)
    }

    pub fn requires_cap(&self) -> bool {
        matches!(self, Self::CappedMintBurn | Self::GovernanceMint)
    }

    pub fn requires_reserve_proof(&self) -> bool {
        matches!(self, Self::WrappedReserve)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_supply_mode",
            "chain_id": CHAIN_ID,
            "supply_mode": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactoryTransferMode {
    PrivateOnly,
    PublicOnly,
    Hybrid,
    ContractOnly,
    Frozen,
}

impl TokenFactoryTransferMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PrivateOnly => "private_only",
            Self::PublicOnly => "public_only",
            Self::Hybrid => "hybrid",
            Self::ContractOnly => "contract_only",
            Self::Frozen => "frozen",
        }
    }

    pub fn allows_private(&self) -> bool {
        matches!(self, Self::PrivateOnly | Self::Hybrid)
    }

    pub fn allows_public(&self) -> bool {
        matches!(self, Self::PublicOnly | Self::Hybrid)
    }

    pub fn requires_contract(&self) -> bool {
        matches!(self, Self::ContractOnly)
    }

    pub fn blocks_transfer(&self) -> bool {
        matches!(self, Self::Frozen)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_transfer_mode",
            "chain_id": CHAIN_ID,
            "transfer_mode": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactoryListMode {
    Open,
    AllowList,
    DenyList,
    AllowAndDeny,
    GovernanceManaged,
}

impl TokenFactoryListMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AllowList => "allow_list",
            Self::DenyList => "deny_list",
            Self::AllowAndDeny => "allow_and_deny",
            Self::GovernanceManaged => "governance_managed",
        }
    }

    pub fn uses_allowlist(&self) -> bool {
        matches!(
            self,
            Self::AllowList | Self::AllowAndDeny | Self::GovernanceManaged
        )
    }

    pub fn uses_denylist(&self) -> bool {
        matches!(
            self,
            Self::DenyList | Self::AllowAndDeny | Self::GovernanceManaged
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenHookFailureMode {
    Revert,
    SkipAndAudit,
    PauseAsset,
    GovernanceEscalate,
}

impl TokenHookFailureMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Revert => "revert",
            Self::SkipAndAudit => "skip_and_audit",
            Self::PauseAsset => "pause_asset",
            Self::GovernanceEscalate => "governance_escalate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactoryUpgradeScope {
    Metadata,
    SupplyPolicy,
    TransferPolicy,
    HookSet,
    IssuerAuthorization,
    Sponsor,
    LpBinding,
    EmergencyPause,
}

impl TokenFactoryUpgradeScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::SupplyPolicy => "supply_policy",
            Self::TransferPolicy => "transfer_policy",
            Self::HookSet => "hook_set",
            Self::IssuerAuthorization => "issuer_authorization",
            Self::Sponsor => "sponsor",
            Self::LpBinding => "lp_binding",
            Self::EmergencyPause => "emergency_pause",
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_upgrade_scope",
            "chain_id": CHAIN_ID,
            "scope": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TokenFactoryAuditEventKind {
    IssuerRegistered,
    IssuerRotated,
    AssetIssued,
    AssetRetired,
    RegistryCommitted,
    TransferPolicyUpdated,
    HookAttached,
    HookRetired,
    LpShareBound,
    UpgradePolicyUpdated,
    SponsorCreated,
    SponsorSpent,
    MintApplied,
    BurnApplied,
    GovernanceUpgradeExecuted,
    EmergencyPause,
    ReserveAttested,
    DevnetGenesis,
}

impl TokenFactoryAuditEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IssuerRegistered => "issuer_registered",
            Self::IssuerRotated => "issuer_rotated",
            Self::AssetIssued => "asset_issued",
            Self::AssetRetired => "asset_retired",
            Self::RegistryCommitted => "registry_committed",
            Self::TransferPolicyUpdated => "transfer_policy_updated",
            Self::HookAttached => "hook_attached",
            Self::HookRetired => "hook_retired",
            Self::LpShareBound => "lp_share_bound",
            Self::UpgradePolicyUpdated => "upgrade_policy_updated",
            Self::SponsorCreated => "sponsor_created",
            Self::SponsorSpent => "sponsor_spent",
            Self::MintApplied => "mint_applied",
            Self::BurnApplied => "burn_applied",
            Self::GovernanceUpgradeExecuted => "governance_upgrade_executed",
            Self::EmergencyPause => "emergency_pause",
            Self::ReserveAttested => "reserve_attested",
            Self::DevnetGenesis => "devnet_genesis",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryConfig {
    pub protocol_version: String,
    pub metadata_schema: String,
    pub registry_schema: String,
    pub pq_scheme: String,
    pub default_transfer_engine_root: String,
    pub default_memo_policy_root: String,
    pub default_low_fee_lane: String,
    pub max_hook_gas_units: u64,
    pub max_sponsor_rebate_bps: u64,
    pub min_upgrade_timelock_blocks: u64,
}

impl Default for TokenFactoryConfig {
    fn default() -> Self {
        Self {
            protocol_version: TOKEN_FACTORY_PROTOCOL_VERSION.to_string(),
            metadata_schema: TOKEN_FACTORY_METADATA_SCHEMA.to_string(),
            registry_schema: TOKEN_FACTORY_REGISTRY_SCHEMA.to_string(),
            pq_scheme: TOKEN_FACTORY_DEFAULT_PQ_SCHEME.to_string(),
            default_transfer_engine_root: token_factory_string_root(
                "TOKEN-FACTORY-TRANSFER-ENGINE",
                TOKEN_FACTORY_DEFAULT_TRANSFER_ENGINE,
            ),
            default_memo_policy_root: token_factory_string_root(
                "TOKEN-FACTORY-MEMO-POLICY",
                TOKEN_FACTORY_DEFAULT_MEMO_POLICY,
            ),
            default_low_fee_lane: TOKEN_FACTORY_DEFAULT_LOW_FEE_LANE.to_string(),
            max_hook_gas_units: TOKEN_FACTORY_MAX_HOOK_GAS_UNITS,
            max_sponsor_rebate_bps: TOKEN_FACTORY_MAX_BPS,
            min_upgrade_timelock_blocks: TOKEN_FACTORY_MIN_TIMELOCK_BLOCKS,
        }
    }
}

impl TokenFactoryConfig {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_config",
            "chain_id": CHAIN_ID,
            "protocol_version": self.protocol_version,
            "metadata_schema": self.metadata_schema,
            "registry_schema": self.registry_schema,
            "pq_scheme": self.pq_scheme,
            "default_transfer_engine_root": self.default_transfer_engine_root,
            "default_memo_policy_root": self.default_memo_policy_root,
            "default_low_fee_lane": self.default_low_fee_lane,
            "max_hook_gas_units": self.max_hook_gas_units,
            "max_sponsor_rebate_bps": self.max_sponsor_rebate_bps,
            "min_upgrade_timelock_blocks": self.min_upgrade_timelock_blocks,
        })
    }

    pub fn config_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_not_empty(&self.protocol_version, "token factory protocol version")?;
        validate_not_empty(&self.metadata_schema, "token factory metadata schema")?;
        validate_not_empty(&self.registry_schema, "token factory registry schema")?;
        validate_not_empty(&self.pq_scheme, "token factory PQ scheme")?;
        validate_root_like(
            &self.default_transfer_engine_root,
            "token factory transfer engine root",
        )?;
        validate_root_like(
            &self.default_memo_policy_root,
            "token factory memo policy root",
        )?;
        validate_bps(
            self.max_sponsor_rebate_bps,
            "token factory max sponsor rebate",
        )?;
        if self.max_hook_gas_units == 0 {
            return Err("token factory max hook gas must be positive".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryMetadataCommitment {
    pub schema_version: String,
    pub disclosed_symbol: String,
    pub disclosed_name: String,
    pub decimals: u8,
    pub metadata_root: String,
    pub symbol_commitment: String,
    pub name_commitment: String,
    pub uri_commitment: String,
    pub icon_commitment: String,
    pub audit_uri_commitment: String,
    pub proof_system_root: String,
    pub confidentiality_level: String,
    pub created_at_height: u64,
}

impl TokenFactoryMetadataCommitment {
    pub fn confidential(
        symbol: &str,
        display_name: &str,
        decimals: u8,
        metadata: &Value,
        blinding: &str,
        created_at_height: u64,
    ) -> Self {
        let normalized_symbol = normalize_symbol(symbol);
        let uri = metadata
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let icon = metadata
            .get("icon")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let audit_uri = metadata
            .get("audit_uri")
            .or_else(|| metadata.get("audit"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        Self {
            schema_version: TOKEN_FACTORY_METADATA_SCHEMA.to_string(),
            disclosed_symbol: normalized_symbol.clone(),
            disclosed_name: display_name.to_string(),
            decimals,
            metadata_root: token_factory_payload_root("TOKEN-FACTORY-METADATA", metadata),
            symbol_commitment: token_factory_field_commitment(
                "symbol",
                &normalized_symbol,
                blinding,
            ),
            name_commitment: token_factory_field_commitment("display_name", display_name, blinding),
            uri_commitment: token_factory_field_commitment("uri", uri, blinding),
            icon_commitment: token_factory_field_commitment("icon", icon, blinding),
            audit_uri_commitment: token_factory_field_commitment("audit_uri", audit_uri, blinding),
            proof_system_root: token_factory_string_root(
                "TOKEN-FACTORY-METADATA-PROOF-SYSTEM",
                "pq-private-metadata-openings-v1",
            ),
            confidentiality_level: TOKEN_FACTORY_DEFAULT_CONFIDENTIALITY.to_string(),
            created_at_height,
        }
    }

    pub fn wrapped_monero(created_at_height: u64) -> Self {
        Self::confidential(
            TOKEN_FACTORY_WXMR_SYMBOL,
            TOKEN_FACTORY_WXMR_DISPLAY_NAME,
            TOKEN_FACTORY_WXMR_DECIMALS,
            &json!({
                "display_name": TOKEN_FACTORY_WXMR_DISPLAY_NAME,
                "symbol": TOKEN_FACTORY_WXMR_SYMBOL,
                "decimals": TOKEN_FACTORY_WXMR_DECIMALS,
                "network": TOKEN_FACTORY_WXMR_RESERVE_NETWORK,
                "reserve_policy": TOKEN_FACTORY_WXMR_RESERVE_POLICY,
                "uri": "nebula://assets/wxmr",
                "audit_uri": "nebula://audits/wxmr-reserve-devnet",
            }),
            "devnet-wxmr-metadata",
            created_at_height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_metadata_commitment",
            "chain_id": CHAIN_ID,
            "schema_version": self.schema_version,
            "disclosed_symbol": self.disclosed_symbol,
            "disclosed_name": self.disclosed_name,
            "decimals": self.decimals,
            "metadata_root": self.metadata_root,
            "symbol_commitment": self.symbol_commitment,
            "name_commitment": self.name_commitment,
            "uri_commitment": self.uri_commitment,
            "icon_commitment": self.icon_commitment,
            "audit_uri_commitment": self.audit_uri_commitment,
            "proof_system_root": self.proof_system_root,
            "confidentiality_level": self.confidentiality_level,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn commitment_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-METADATA-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_symbol(&self.disclosed_symbol)?;
        validate_not_empty(&self.disclosed_name, "token factory metadata display name")?;
        validate_root_like(&self.metadata_root, "token factory metadata root")?;
        validate_root_like(&self.symbol_commitment, "token factory symbol commitment")?;
        validate_root_like(&self.name_commitment, "token factory name commitment")?;
        validate_root_like(&self.uri_commitment, "token factory URI commitment")?;
        validate_root_like(&self.icon_commitment, "token factory icon commitment")?;
        validate_root_like(
            &self.audit_uri_commitment,
            "token factory audit URI commitment",
        )?;
        validate_root_like(
            &self.proof_system_root,
            "token factory metadata proof system root",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryRegistryCommitment {
    pub registry_id: String,
    pub class_id: String,
    pub registry_schema: String,
    pub metadata_commitment_root: String,
    pub issuer_commitment: String,
    pub issuance_commitment: String,
    pub transfer_policy_commitment: String,
    pub privacy_salt_commitment: String,
    pub disclosed_fields_root: String,
    pub registry_leaf: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFactoryRegistryCommitment {
    pub fn new(
        class_id: &str,
        metadata_commitment_root: &str,
        issuer_root: &str,
        supply_root: &str,
        transfer_policy_root: &str,
        disclosed_fields: &[String],
        blinding: &str,
        height: u64,
    ) -> Self {
        let disclosed_fields_root =
            token_factory_string_set_root("TOKEN-FACTORY-DISCLOSED-FIELD", disclosed_fields);
        let issuer_commitment =
            token_factory_field_commitment("issuer_root", issuer_root, blinding);
        let issuance_commitment =
            token_factory_field_commitment("supply_root", supply_root, blinding);
        let transfer_policy_commitment =
            token_factory_field_commitment("transfer_policy_root", transfer_policy_root, blinding);
        let privacy_salt_commitment =
            token_factory_field_commitment("privacy_salt", blinding, class_id);
        let registry_leaf = token_factory_registry_leaf(
            class_id,
            metadata_commitment_root,
            &issuer_commitment,
            &issuance_commitment,
            &transfer_policy_commitment,
            &privacy_salt_commitment,
            &disclosed_fields_root,
        );
        let registry_id = token_factory_registry_id(class_id, &registry_leaf, height);
        Self {
            registry_id,
            class_id: class_id.to_string(),
            registry_schema: TOKEN_FACTORY_REGISTRY_SCHEMA.to_string(),
            metadata_commitment_root: metadata_commitment_root.to_string(),
            issuer_commitment,
            issuance_commitment,
            transfer_policy_commitment,
            privacy_salt_commitment,
            disclosed_fields_root,
            registry_leaf,
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_registry_commitment",
            "chain_id": CHAIN_ID,
            "registry_id": self.registry_id,
            "class_id": self.class_id,
            "registry_schema": self.registry_schema,
            "metadata_commitment_root": self.metadata_commitment_root,
            "issuer_commitment": self.issuer_commitment,
            "issuance_commitment": self.issuance_commitment,
            "transfer_policy_commitment": self.transfer_policy_commitment,
            "privacy_salt_commitment": self.privacy_salt_commitment,
            "disclosed_fields_root": self.disclosed_fields_root,
            "registry_leaf": self.registry_leaf,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn commitment_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-REGISTRY-COMMITMENT", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.registry_id, "token factory registry id")?;
        validate_root_like(&self.class_id, "token factory registry class id")?;
        validate_root_like(
            &self.metadata_commitment_root,
            "token factory registry metadata root",
        )?;
        validate_root_like(&self.issuer_commitment, "token factory issuer commitment")?;
        validate_root_like(
            &self.issuance_commitment,
            "token factory issuance commitment",
        )?;
        validate_root_like(
            &self.transfer_policy_commitment,
            "token factory transfer policy commitment",
        )?;
        validate_root_like(
            &self.privacy_salt_commitment,
            "token factory privacy salt commitment",
        )?;
        validate_root_like(
            &self.disclosed_fields_root,
            "token factory disclosed fields root",
        )?;
        validate_root_like(&self.registry_leaf, "token factory registry leaf")?;
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_RETIRED,
                TOKEN_FACTORY_STATUS_REVOKED,
            ],
            "token factory registry status",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactorySupplyPolicy {
    pub class_id: String,
    pub supply_mode: TokenFactorySupplyMode,
    pub max_supply_units: u64,
    pub lifetime_mint_cap_units: u64,
    pub lifetime_burn_cap_units: u64,
    pub epoch: u64,
    pub epoch_mint_cap_units: u64,
    pub epoch_burn_cap_units: u64,
    pub issued_units: u64,
    pub burned_units: u64,
    pub epoch_issued_units: u64,
    pub epoch_burned_units: u64,
    pub mint_authority_root: String,
    pub burn_authority_root: String,
    pub reserve_commitment_root: String,
    pub reserve_asset_id: String,
    pub supply_nonce: u64,
    pub last_updated_height: u64,
}

impl TokenFactorySupplyPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        supply_mode: TokenFactorySupplyMode,
        max_supply_units: u64,
        lifetime_mint_cap_units: u64,
        lifetime_burn_cap_units: u64,
        epoch: u64,
        epoch_mint_cap_units: u64,
        epoch_burn_cap_units: u64,
        initial_supply_units: u64,
        mint_authorities: &[String],
        burn_authorities: &[String],
        reserve_asset_id: &str,
        reserve_commitment_root: &str,
        height: u64,
    ) -> Self {
        Self {
            class_id: class_id.to_string(),
            supply_mode,
            max_supply_units,
            lifetime_mint_cap_units,
            lifetime_burn_cap_units,
            epoch,
            epoch_mint_cap_units,
            epoch_burn_cap_units,
            issued_units: initial_supply_units,
            burned_units: 0,
            epoch_issued_units: initial_supply_units,
            epoch_burned_units: 0,
            mint_authority_root: token_factory_string_set_root(
                "TOKEN-FACTORY-MINT-AUTHORITY",
                mint_authorities,
            ),
            burn_authority_root: token_factory_string_set_root(
                "TOKEN-FACTORY-BURN-AUTHORITY",
                burn_authorities,
            ),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            supply_nonce: 0,
            last_updated_height: height,
        }
    }

    pub fn fixed(
        class_id: &str,
        initial_supply_units: u64,
        authorities: &[String],
        height: u64,
    ) -> Self {
        Self::new(
            class_id,
            TokenFactorySupplyMode::Fixed,
            initial_supply_units,
            0,
            initial_supply_units,
            TOKEN_FACTORY_DEVNET_EPOCH,
            0,
            initial_supply_units,
            initial_supply_units,
            authorities,
            authorities,
            "",
            &token_factory_empty_root("TOKEN-FACTORY-RESERVE"),
            height,
        )
    }

    pub fn capped_mint_burn(
        class_id: &str,
        max_supply_units: u64,
        initial_supply_units: u64,
        authorities: &[String],
        height: u64,
    ) -> Self {
        Self::new(
            class_id,
            TokenFactorySupplyMode::CappedMintBurn,
            max_supply_units,
            max_supply_units,
            max_supply_units,
            TOKEN_FACTORY_DEVNET_EPOCH,
            max_supply_units,
            max_supply_units,
            initial_supply_units,
            authorities,
            authorities,
            "",
            &token_factory_empty_root("TOKEN-FACTORY-RESERVE"),
            height,
        )
    }

    pub fn wrapped_monero(
        class_id: &str,
        initial_supply_units: u64,
        authorities: &[String],
        reserve_root: &str,
        height: u64,
    ) -> Self {
        Self::new(
            class_id,
            TokenFactorySupplyMode::WrappedReserve,
            18_400_000_000_000_000_000,
            18_400_000_000_000_000_000,
            18_400_000_000_000_000_000,
            TOKEN_FACTORY_DEVNET_EPOCH,
            1_000_000_000_000_000,
            1_000_000_000_000_000,
            initial_supply_units,
            authorities,
            authorities,
            "monero:xmr",
            reserve_root,
            height,
        )
    }

    pub fn lp_share(
        class_id: &str,
        initial_supply_units: u64,
        contract_authorities: &[String],
        height: u64,
    ) -> Self {
        Self::new(
            class_id,
            TokenFactorySupplyMode::PoolShare,
            0,
            0,
            0,
            TOKEN_FACTORY_DEVNET_EPOCH,
            0,
            0,
            initial_supply_units,
            contract_authorities,
            contract_authorities,
            "",
            &token_factory_empty_root("TOKEN-FACTORY-RESERVE"),
            height,
        )
    }

    pub fn circulating_units(&self) -> u64 {
        self.issued_units.saturating_sub(self.burned_units)
    }

    pub fn remaining_supply_units(&self) -> u64 {
        cap_remaining(self.max_supply_units, self.circulating_units())
    }

    pub fn remaining_lifetime_mint_units(&self) -> u64 {
        cap_remaining(self.lifetime_mint_cap_units, self.issued_units)
    }

    pub fn remaining_epoch_mint_units(&self) -> u64 {
        cap_remaining(self.epoch_mint_cap_units, self.epoch_issued_units)
    }

    pub fn remaining_mint_units(&self) -> u64 {
        let mut remaining = self.remaining_supply_units();
        remaining = remaining.min(self.remaining_lifetime_mint_units());
        remaining.min(self.remaining_epoch_mint_units())
    }

    pub fn remaining_burn_units(&self) -> u64 {
        let lifetime = cap_remaining(self.lifetime_burn_cap_units, self.burned_units);
        let epoch = cap_remaining(self.epoch_burn_cap_units, self.epoch_burned_units);
        self.circulating_units().min(lifetime).min(epoch)
    }

    pub fn can_mint(&self, amount: u64) -> bool {
        if amount == 0 || !self.supply_mode.allows_mint() {
            return false;
        }
        if amount > self.remaining_mint_units() {
            return false;
        }
        self.issued_units.checked_add(amount).is_some()
            && self.epoch_issued_units.checked_add(amount).is_some()
            && self.circulating_units().checked_add(amount).is_some()
    }

    pub fn can_burn(&self, amount: u64) -> bool {
        if amount == 0 || !self.supply_mode.allows_burn() {
            return false;
        }
        if amount > self.remaining_burn_units() {
            return false;
        }
        self.burned_units.checked_add(amount).is_some()
            && self.epoch_burned_units.checked_add(amount).is_some()
    }

    pub fn apply_mint(&mut self, amount: u64, height: u64) -> TokenFactoryResult<String> {
        if !self.can_mint(amount) {
            return Err("token factory mint exceeds supply policy".to_string());
        }
        self.issued_units = self
            .issued_units
            .checked_add(amount)
            .ok_or_else(|| "token factory issued supply overflow".to_string())?;
        self.epoch_issued_units = self
            .epoch_issued_units
            .checked_add(amount)
            .ok_or_else(|| "token factory epoch issued overflow".to_string())?;
        self.supply_nonce = self.supply_nonce.saturating_add(1);
        self.last_updated_height = height;
        Ok(self.supply_root())
    }

    pub fn apply_burn(&mut self, amount: u64, height: u64) -> TokenFactoryResult<String> {
        if !self.can_burn(amount) {
            return Err("token factory burn exceeds supply policy".to_string());
        }
        self.burned_units = self
            .burned_units
            .checked_add(amount)
            .ok_or_else(|| "token factory burned supply overflow".to_string())?;
        self.epoch_burned_units = self
            .epoch_burned_units
            .checked_add(amount)
            .ok_or_else(|| "token factory epoch burned overflow".to_string())?;
        self.supply_nonce = self.supply_nonce.saturating_add(1);
        self.last_updated_height = height;
        Ok(self.supply_root())
    }

    pub fn roll_epoch(&mut self, epoch: u64, height: u64) -> TokenFactoryResult<String> {
        if epoch < self.epoch {
            return Err("token factory supply epoch cannot move backward".to_string());
        }
        if epoch > self.epoch {
            self.epoch = epoch;
            self.epoch_issued_units = 0;
            self.epoch_burned_units = 0;
            self.last_updated_height = height;
        }
        Ok(self.supply_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_supply_policy",
            "chain_id": CHAIN_ID,
            "class_id": self.class_id,
            "supply_mode": self.supply_mode.as_str(),
            "max_supply_units": self.max_supply_units,
            "lifetime_mint_cap_units": self.lifetime_mint_cap_units,
            "lifetime_burn_cap_units": self.lifetime_burn_cap_units,
            "epoch": self.epoch,
            "epoch_mint_cap_units": self.epoch_mint_cap_units,
            "epoch_burn_cap_units": self.epoch_burn_cap_units,
            "issued_units": self.issued_units,
            "burned_units": self.burned_units,
            "circulating_units": self.circulating_units(),
            "epoch_issued_units": self.epoch_issued_units,
            "epoch_burned_units": self.epoch_burned_units,
            "remaining_supply_units": self.remaining_supply_units(),
            "remaining_mint_units": self.remaining_mint_units(),
            "remaining_burn_units": self.remaining_burn_units(),
            "mint_authority_root": self.mint_authority_root,
            "burn_authority_root": self.burn_authority_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "reserve_asset_id": self.reserve_asset_id,
            "supply_nonce": self.supply_nonce,
            "last_updated_height": self.last_updated_height,
        })
    }

    pub fn supply_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-SUPPLY-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.class_id, "token factory supply class id")?;
        validate_root_like(
            &self.mint_authority_root,
            "token factory supply mint authority root",
        )?;
        validate_root_like(
            &self.burn_authority_root,
            "token factory supply burn authority root",
        )?;
        validate_root_like(
            &self.reserve_commitment_root,
            "token factory reserve commitment root",
        )?;
        if self.burned_units > self.issued_units {
            return Err("token factory burned supply exceeds issued supply".to_string());
        }
        if self.max_supply_units != 0 && self.circulating_units() > self.max_supply_units {
            return Err("token factory circulating supply exceeds cap".to_string());
        }
        if self.lifetime_mint_cap_units != 0 && self.issued_units > self.lifetime_mint_cap_units {
            return Err("token factory issued units exceed lifetime mint cap".to_string());
        }
        if self.lifetime_burn_cap_units != 0 && self.burned_units > self.lifetime_burn_cap_units {
            return Err("token factory burned units exceed lifetime burn cap".to_string());
        }
        if self.epoch_mint_cap_units != 0 && self.epoch_issued_units > self.epoch_mint_cap_units {
            return Err("token factory issued units exceed epoch mint cap".to_string());
        }
        if self.epoch_burn_cap_units != 0 && self.epoch_burned_units > self.epoch_burn_cap_units {
            return Err("token factory burned units exceed epoch burn cap".to_string());
        }
        if self.supply_mode.requires_cap() && self.max_supply_units == 0 {
            return Err("token factory capped supply mode requires max supply".to_string());
        }
        if self.supply_mode == TokenFactorySupplyMode::WrappedReserve
            && self.reserve_asset_id.trim().is_empty()
        {
            return Err("token factory wrapped reserve supply requires reserve asset".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryIssuerAuthorization {
    pub issuer_id: String,
    pub issuer_label: String,
    pub pq_scheme: String,
    pub pq_public_key_root: String,
    pub pq_multisig_root: String,
    pub mint_authority_root: String,
    pub burn_authority_root: String,
    pub upgrade_authority_root: String,
    pub freeze_authority_root: String,
    pub governance_controller_root: String,
    pub quorum: u64,
    pub threshold: u64,
    pub activated_at_height: u64,
    pub rotated_at_height: u64,
    pub retired_at_height: u64,
    pub status: String,
}

impl TokenFactoryIssuerAuthorization {
    pub fn governance_controlled(
        issuer_label: &str,
        governance_label: &str,
        authority_labels: &[String],
        threshold: u64,
        activated_at_height: u64,
    ) -> Self {
        let normalized_authorities = normalized_strings(authority_labels);
        let pq_public_key_root =
            token_factory_string_set_root("TOKEN-FACTORY-PQ-PUBLIC-KEY", &normalized_authorities);
        let pq_multisig_root =
            token_factory_string_set_root("TOKEN-FACTORY-PQ-MULTISIG", &normalized_authorities);
        let mint_authority_root = token_factory_string_set_root(
            "TOKEN-FACTORY-ISSUER-MINT-AUTHORITY",
            &normalized_authorities,
        );
        let burn_authority_root = token_factory_string_set_root(
            "TOKEN-FACTORY-ISSUER-BURN-AUTHORITY",
            &normalized_authorities,
        );
        let upgrade_authority_root = token_factory_string_set_root(
            "TOKEN-FACTORY-ISSUER-UPGRADE-AUTHORITY",
            &normalized_authorities,
        );
        let freeze_authority_root = token_factory_string_set_root(
            "TOKEN-FACTORY-ISSUER-FREEZE-AUTHORITY",
            &normalized_authorities,
        );
        let governance_controller_root =
            token_factory_string_root("TOKEN-FACTORY-GOVERNANCE-CONTROLLER", governance_label);
        let quorum = normalized_authorities.len() as u64;
        let issuer_id = token_factory_issuer_id(
            issuer_label,
            TOKEN_FACTORY_DEFAULT_PQ_SCHEME,
            &pq_public_key_root,
            &pq_multisig_root,
            &governance_controller_root,
            activated_at_height,
        );
        Self {
            issuer_id,
            issuer_label: issuer_label.to_string(),
            pq_scheme: TOKEN_FACTORY_DEFAULT_PQ_SCHEME.to_string(),
            pq_public_key_root,
            pq_multisig_root,
            mint_authority_root,
            burn_authority_root,
            upgrade_authority_root,
            freeze_authority_root,
            governance_controller_root,
            quorum,
            threshold: threshold.max(1).min(quorum.max(1)),
            activated_at_height,
            rotated_at_height: 0,
            retired_at_height: 0,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn devnet_governance(height: u64) -> Self {
        let authorities = vec![
            "devnet-token-council-ml-dsa-key-0".to_string(),
            "devnet-token-council-ml-dsa-key-1".to_string(),
            "devnet-token-council-ml-dsa-key-2".to_string(),
        ];
        Self::governance_controlled(
            TOKEN_FACTORY_DEVNET_GOVERNANCE_LABEL,
            TOKEN_FACTORY_DEFAULT_UPGRADE_SCOPE,
            &authorities,
            2,
            height,
        )
    }

    pub fn devnet_bridge(height: u64) -> Self {
        let authorities = vec![
            "devnet-monero-bridge-ml-dsa-key-0".to_string(),
            "devnet-monero-bridge-ml-dsa-key-1".to_string(),
            "devnet-monero-watchtower-ml-dsa-key-0".to_string(),
        ];
        Self::governance_controlled(
            TOKEN_FACTORY_DEVNET_BRIDGE_LABEL,
            "monero_bridge_governance",
            &authorities,
            2,
            height,
        )
    }

    pub fn devnet_defi(height: u64) -> Self {
        let authorities = vec![
            "devnet-defi-treasury-ml-dsa-key-0".to_string(),
            "devnet-defi-guardian-ml-dsa-key-0".to_string(),
            "devnet-defi-guardian-ml-dsa-key-1".to_string(),
        ];
        Self::governance_controlled(
            TOKEN_FACTORY_DEVNET_DEFI_LABEL,
            "defi_token_governance",
            &authorities,
            2,
            height,
        )
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == TOKEN_FACTORY_STATUS_ACTIVE
            && height >= self.activated_at_height
            && (self.retired_at_height == 0 || height < self.retired_at_height)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_issuer_authorization",
            "chain_id": CHAIN_ID,
            "issuer_id": self.issuer_id,
            "issuer_label": self.issuer_label,
            "pq_scheme": self.pq_scheme,
            "pq_public_key_root": self.pq_public_key_root,
            "pq_multisig_root": self.pq_multisig_root,
            "mint_authority_root": self.mint_authority_root,
            "burn_authority_root": self.burn_authority_root,
            "upgrade_authority_root": self.upgrade_authority_root,
            "freeze_authority_root": self.freeze_authority_root,
            "governance_controller_root": self.governance_controller_root,
            "quorum": self.quorum,
            "threshold": self.threshold,
            "activated_at_height": self.activated_at_height,
            "rotated_at_height": self.rotated_at_height,
            "retired_at_height": self.retired_at_height,
            "status": self.status,
        })
    }

    pub fn issuer_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-ISSUER-AUTHORIZATION", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_not_empty(&self.issuer_label, "token factory issuer label")?;
        validate_not_empty(&self.pq_scheme, "token factory issuer PQ scheme")?;
        validate_root_like(&self.issuer_id, "token factory issuer id")?;
        validate_root_like(&self.pq_public_key_root, "token factory issuer PQ key root")?;
        validate_root_like(
            &self.pq_multisig_root,
            "token factory issuer PQ multisig root",
        )?;
        validate_root_like(
            &self.mint_authority_root,
            "token factory issuer mint authority root",
        )?;
        validate_root_like(
            &self.burn_authority_root,
            "token factory issuer burn authority root",
        )?;
        validate_root_like(
            &self.upgrade_authority_root,
            "token factory issuer upgrade authority root",
        )?;
        validate_root_like(
            &self.freeze_authority_root,
            "token factory issuer freeze authority root",
        )?;
        validate_root_like(
            &self.governance_controller_root,
            "token factory issuer governance root",
        )?;
        if self.quorum == 0 {
            return Err("token factory issuer quorum must be positive".to_string());
        }
        if self.threshold == 0 || self.threshold > self.quorum {
            return Err("token factory issuer threshold is invalid".to_string());
        }
        if self.retired_at_height != 0 && self.retired_at_height < self.activated_at_height {
            return Err("token factory issuer retirement precedes activation".to_string());
        }
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_RETIRED,
                TOKEN_FACTORY_STATUS_REVOKED,
            ],
            "token factory issuer status",
        )?;
        let expected = token_factory_issuer_id(
            &self.issuer_label,
            &self.pq_scheme,
            &self.pq_public_key_root,
            &self.pq_multisig_root,
            &self.governance_controller_root,
            self.activated_at_height,
        );
        if self.issuer_id != expected {
            return Err("token factory issuer id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryTransferPolicy {
    pub policy_id: String,
    pub class_id: String,
    pub policy_label: String,
    pub version: u64,
    pub transfer_mode: TokenFactoryTransferMode,
    pub list_mode: TokenFactoryListMode,
    pub sender_allowlist_root: String,
    pub receiver_allowlist_root: String,
    pub sender_denylist_root: String,
    pub receiver_denylist_root: String,
    pub allowed_contract_root: String,
    pub denied_contract_root: String,
    pub require_sender_proof: bool,
    pub require_receiver_proof: bool,
    pub require_view_tag: bool,
    pub allow_bridge_deposits: bool,
    pub allow_bridge_withdrawals: bool,
    pub allow_private_contract_calls: bool,
    pub max_transfer_units: u64,
    pub daily_transfer_cap_units: u64,
    pub cooldown_blocks: u64,
    pub hook_root: String,
    pub policy_engine_root: String,
    pub memo_policy_root: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFactoryTransferPolicy {
    pub fn default_confidential(class_id: &str, height: u64) -> Self {
        Self::new(
            class_id,
            TOKEN_FACTORY_DEFAULT_POLICY_LABEL,
            1,
            TokenFactoryTransferMode::PrivateOnly,
            TokenFactoryListMode::Open,
            height,
        )
    }

    pub fn new(
        class_id: &str,
        policy_label: &str,
        version: u64,
        transfer_mode: TokenFactoryTransferMode,
        list_mode: TokenFactoryListMode,
        height: u64,
    ) -> Self {
        let policy_id = token_factory_transfer_policy_id(class_id, policy_label, version, height);
        Self {
            policy_id,
            class_id: class_id.to_string(),
            policy_label: policy_label.to_string(),
            version,
            transfer_mode,
            list_mode,
            sender_allowlist_root: token_factory_empty_root("TOKEN-FACTORY-SENDER-ALLOWLIST"),
            receiver_allowlist_root: token_factory_empty_root("TOKEN-FACTORY-RECEIVER-ALLOWLIST"),
            sender_denylist_root: token_factory_empty_root("TOKEN-FACTORY-SENDER-DENYLIST"),
            receiver_denylist_root: token_factory_empty_root("TOKEN-FACTORY-RECEIVER-DENYLIST"),
            allowed_contract_root: token_factory_empty_root("TOKEN-FACTORY-ALLOWED-CONTRACT"),
            denied_contract_root: token_factory_empty_root("TOKEN-FACTORY-DENIED-CONTRACT"),
            require_sender_proof: true,
            require_receiver_proof: true,
            require_view_tag: true,
            allow_bridge_deposits: true,
            allow_bridge_withdrawals: true,
            allow_private_contract_calls: true,
            max_transfer_units: 0,
            daily_transfer_cap_units: 0,
            cooldown_blocks: 0,
            hook_root: token_factory_empty_root("TOKEN-FACTORY-HOOK"),
            policy_engine_root: token_factory_string_root(
                "TOKEN-FACTORY-TRANSFER-ENGINE",
                TOKEN_FACTORY_DEFAULT_TRANSFER_ENGINE,
            ),
            memo_policy_root: token_factory_string_root(
                "TOKEN-FACTORY-MEMO-POLICY",
                TOKEN_FACTORY_DEFAULT_MEMO_POLICY,
            ),
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn with_lists(mut self, allowlist_members: &[String], denylist_members: &[String]) -> Self {
        if !allowlist_members.is_empty() {
            self.sender_allowlist_root =
                token_factory_string_set_root("TOKEN-FACTORY-SENDER-ALLOWLIST", allowlist_members);
            self.receiver_allowlist_root = token_factory_string_set_root(
                "TOKEN-FACTORY-RECEIVER-ALLOWLIST",
                allowlist_members,
            );
        }
        if !denylist_members.is_empty() {
            self.sender_denylist_root =
                token_factory_string_set_root("TOKEN-FACTORY-SENDER-DENYLIST", denylist_members);
            self.receiver_denylist_root =
                token_factory_string_set_root("TOKEN-FACTORY-RECEIVER-DENYLIST", denylist_members);
        }
        self
    }

    pub fn set_hook_root(&mut self, hook_root: &str, height: u64) {
        self.hook_root = hook_root.to_string();
        self.updated_at_height = height;
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_transfer_policy",
            "chain_id": CHAIN_ID,
            "policy_id": self.policy_id,
            "class_id": self.class_id,
            "policy_label": self.policy_label,
            "version": self.version,
            "transfer_mode": self.transfer_mode.as_str(),
            "list_mode": self.list_mode.as_str(),
            "sender_allowlist_root": self.sender_allowlist_root,
            "receiver_allowlist_root": self.receiver_allowlist_root,
            "sender_denylist_root": self.sender_denylist_root,
            "receiver_denylist_root": self.receiver_denylist_root,
            "allowed_contract_root": self.allowed_contract_root,
            "denied_contract_root": self.denied_contract_root,
            "require_sender_proof": self.require_sender_proof,
            "require_receiver_proof": self.require_receiver_proof,
            "require_view_tag": self.require_view_tag,
            "allow_bridge_deposits": self.allow_bridge_deposits,
            "allow_bridge_withdrawals": self.allow_bridge_withdrawals,
            "allow_private_contract_calls": self.allow_private_contract_calls,
            "max_transfer_units": self.max_transfer_units,
            "daily_transfer_cap_units": self.daily_transfer_cap_units,
            "cooldown_blocks": self.cooldown_blocks,
            "hook_root": self.hook_root,
            "policy_engine_root": self.policy_engine_root,
            "memo_policy_root": self.memo_policy_root,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn policy_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-TRANSFER-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.policy_id, "token factory transfer policy id")?;
        validate_root_like(&self.class_id, "token factory transfer policy class id")?;
        validate_not_empty(&self.policy_label, "token factory transfer policy label")?;
        if self.version == 0 {
            return Err("token factory transfer policy version cannot be zero".to_string());
        }
        if self.transfer_mode.blocks_transfer() && self.status == TOKEN_FACTORY_STATUS_ACTIVE {
            return Err("token factory active policy cannot use frozen transfer mode".to_string());
        }
        if self.transfer_mode.requires_contract()
            && self.allowed_contract_root
                == token_factory_empty_root("TOKEN-FACTORY-ALLOWED-CONTRACT")
        {
            return Err(
                "token factory contract-only policy requires allowed contracts".to_string(),
            );
        }
        validate_root_like(
            &self.sender_allowlist_root,
            "token factory sender allowlist root",
        )?;
        validate_root_like(
            &self.receiver_allowlist_root,
            "token factory receiver allowlist root",
        )?;
        validate_root_like(
            &self.sender_denylist_root,
            "token factory sender denylist root",
        )?;
        validate_root_like(
            &self.receiver_denylist_root,
            "token factory receiver denylist root",
        )?;
        validate_root_like(
            &self.allowed_contract_root,
            "token factory allowed contract root",
        )?;
        validate_root_like(
            &self.denied_contract_root,
            "token factory denied contract root",
        )?;
        validate_root_like(&self.hook_root, "token factory transfer hook root")?;
        validate_root_like(
            &self.policy_engine_root,
            "token factory transfer policy engine root",
        )?;
        validate_root_like(&self.memo_policy_root, "token factory memo policy root")?;
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_FROZEN,
                TOKEN_FACTORY_STATUS_RETIRED,
            ],
            "token factory transfer policy status",
        )?;
        let expected = token_factory_transfer_policy_id(
            &self.class_id,
            &self.policy_label,
            self.version,
            self.created_at_height,
        );
        if self.policy_id != expected {
            return Err("token factory transfer policy id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryContractHook {
    pub hook_id: String,
    pub class_id: String,
    pub contract_id: String,
    pub contract_root: String,
    pub entrypoint: String,
    pub before_transfer: bool,
    pub after_transfer: bool,
    pub before_mint: bool,
    pub after_mint: bool,
    pub before_burn: bool,
    pub after_burn: bool,
    pub max_gas_units: u64,
    pub failure_mode: TokenHookFailureMode,
    pub privacy_budget_root: String,
    pub callback_commitment_root: String,
    pub version: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFactoryContractHook {
    pub fn new(
        class_id: &str,
        contract_id: &str,
        entrypoint: &str,
        phases: TokenFactoryHookPhases,
        height: u64,
    ) -> Self {
        let contract_root = token_factory_string_root("TOKEN-FACTORY-HOOK-CONTRACT", contract_id);
        let privacy_budget_root =
            token_factory_string_root("TOKEN-FACTORY-HOOK-PRIVACY-BUDGET", "default");
        let callback_commitment_root =
            token_factory_string_root("TOKEN-FACTORY-HOOK-CALLBACK", entrypoint);
        let hook_id =
            token_factory_hook_id(class_id, contract_id, entrypoint, &contract_root, 1, height);
        Self {
            hook_id,
            class_id: class_id.to_string(),
            contract_id: contract_id.to_string(),
            contract_root,
            entrypoint: entrypoint.to_string(),
            before_transfer: phases.before_transfer,
            after_transfer: phases.after_transfer,
            before_mint: phases.before_mint,
            after_mint: phases.after_mint,
            before_burn: phases.before_burn,
            after_burn: phases.after_burn,
            max_gas_units: 250_000,
            failure_mode: TokenHookFailureMode::Revert,
            privacy_budget_root,
            callback_commitment_root,
            version: 1,
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_contract_hook",
            "chain_id": CHAIN_ID,
            "hook_id": self.hook_id,
            "class_id": self.class_id,
            "contract_id": self.contract_id,
            "contract_root": self.contract_root,
            "entrypoint": self.entrypoint,
            "before_transfer": self.before_transfer,
            "after_transfer": self.after_transfer,
            "before_mint": self.before_mint,
            "after_mint": self.after_mint,
            "before_burn": self.before_burn,
            "after_burn": self.after_burn,
            "max_gas_units": self.max_gas_units,
            "failure_mode": self.failure_mode.as_str(),
            "privacy_budget_root": self.privacy_budget_root,
            "callback_commitment_root": self.callback_commitment_root,
            "version": self.version,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn hook_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-CONTRACT-HOOK", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.hook_id, "token factory hook id")?;
        validate_root_like(&self.class_id, "token factory hook class id")?;
        validate_not_empty(&self.contract_id, "token factory hook contract id")?;
        validate_root_like(&self.contract_root, "token factory hook contract root")?;
        validate_not_empty(&self.entrypoint, "token factory hook entrypoint")?;
        if !self.before_transfer
            && !self.after_transfer
            && !self.before_mint
            && !self.after_mint
            && !self.before_burn
            && !self.after_burn
        {
            return Err("token factory hook must subscribe to at least one phase".to_string());
        }
        if self.max_gas_units == 0 || self.max_gas_units > TOKEN_FACTORY_MAX_HOOK_GAS_UNITS {
            return Err("token factory hook gas limit is invalid".to_string());
        }
        validate_root_like(
            &self.privacy_budget_root,
            "token factory hook privacy budget root",
        )?;
        validate_root_like(
            &self.callback_commitment_root,
            "token factory hook callback commitment root",
        )?;
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_RETIRED,
            ],
            "token factory hook status",
        )?;
        let expected = token_factory_hook_id(
            &self.class_id,
            &self.contract_id,
            &self.entrypoint,
            &self.contract_root,
            self.version,
            self.created_at_height,
        );
        if self.hook_id != expected {
            return Err("token factory hook id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryHookPhases {
    pub before_transfer: bool,
    pub after_transfer: bool,
    pub before_mint: bool,
    pub after_mint: bool,
    pub before_burn: bool,
    pub after_burn: bool,
}

impl TokenFactoryHookPhases {
    pub fn all_supply_and_transfer() -> Self {
        Self {
            before_transfer: true,
            after_transfer: true,
            before_mint: true,
            after_mint: true,
            before_burn: true,
            after_burn: true,
        }
    }

    pub fn transfer_only() -> Self {
        Self {
            before_transfer: true,
            after_transfer: true,
            ..Self::default()
        }
    }

    pub fn supply_only() -> Self {
        Self {
            before_mint: true,
            after_mint: true,
            before_burn: true,
            after_burn: true,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryLpBinding {
    pub binding_id: String,
    pub share_class_id: String,
    pub pool_id: String,
    pub pool_root: String,
    pub pool_kind: String,
    pub base_asset_id: String,
    pub quote_asset_id: String,
    pub base_weight_bps: u64,
    pub quote_weight_bps: u64,
    pub invariant_root: String,
    pub fee_bps: u64,
    pub redeem_policy_root: String,
    pub oracle_guard_root: String,
    pub created_at_height: u64,
    pub status: String,
}

impl TokenFactoryLpBinding {
    pub fn constant_product(
        share_class_id: &str,
        pool_id: &str,
        base_asset_id: &str,
        quote_asset_id: &str,
        fee_bps: u64,
        height: u64,
    ) -> Self {
        let pool_root = token_factory_string_root("TOKEN-FACTORY-LP-POOL", pool_id);
        let invariant_root = token_factory_payload_root(
            "TOKEN-FACTORY-LP-INVARIANT",
            &json!({
                "kind": "constant_product",
                "base_asset_id": base_asset_id,
                "quote_asset_id": quote_asset_id,
            }),
        );
        let redeem_policy_root =
            token_factory_string_root("TOKEN-FACTORY-LP-REDEEM-POLICY", "burn-for-pro-rata");
        let oracle_guard_root =
            token_factory_string_root("TOKEN-FACTORY-LP-ORACLE-GUARD", "twap-bounded-devnet");
        let binding_id = token_factory_lp_binding_id(
            share_class_id,
            pool_id,
            base_asset_id,
            quote_asset_id,
            &invariant_root,
            height,
        );
        Self {
            binding_id,
            share_class_id: share_class_id.to_string(),
            pool_id: pool_id.to_string(),
            pool_root,
            pool_kind: "constant_product".to_string(),
            base_asset_id: base_asset_id.to_string(),
            quote_asset_id: quote_asset_id.to_string(),
            base_weight_bps: 5_000,
            quote_weight_bps: 5_000,
            invariant_root,
            fee_bps,
            redeem_policy_root,
            oracle_guard_root,
            created_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_lp_binding",
            "chain_id": CHAIN_ID,
            "binding_id": self.binding_id,
            "share_class_id": self.share_class_id,
            "pool_id": self.pool_id,
            "pool_root": self.pool_root,
            "pool_kind": self.pool_kind,
            "base_asset_id": self.base_asset_id,
            "quote_asset_id": self.quote_asset_id,
            "base_weight_bps": self.base_weight_bps,
            "quote_weight_bps": self.quote_weight_bps,
            "invariant_root": self.invariant_root,
            "fee_bps": self.fee_bps,
            "redeem_policy_root": self.redeem_policy_root,
            "oracle_guard_root": self.oracle_guard_root,
            "created_at_height": self.created_at_height,
            "status": self.status,
        })
    }

    pub fn binding_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-LP-BINDING", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.binding_id, "token factory LP binding id")?;
        validate_root_like(&self.share_class_id, "token factory LP share class id")?;
        validate_not_empty(&self.pool_id, "token factory LP pool id")?;
        validate_root_like(&self.pool_root, "token factory LP pool root")?;
        validate_root_like(&self.base_asset_id, "token factory LP base asset id")?;
        validate_root_like(&self.quote_asset_id, "token factory LP quote asset id")?;
        if self.base_asset_id == self.quote_asset_id {
            return Err("token factory LP binding requires two distinct assets".to_string());
        }
        validate_bps(self.base_weight_bps, "token factory LP base weight")?;
        validate_bps(self.quote_weight_bps, "token factory LP quote weight")?;
        if self.base_weight_bps.saturating_add(self.quote_weight_bps) != TOKEN_FACTORY_MAX_BPS {
            return Err("token factory LP weights must sum to 100 percent".to_string());
        }
        validate_bps(self.fee_bps, "token factory LP fee")?;
        validate_root_like(&self.invariant_root, "token factory LP invariant root")?;
        validate_root_like(
            &self.redeem_policy_root,
            "token factory LP redeem policy root",
        )?;
        validate_root_like(
            &self.oracle_guard_root,
            "token factory LP oracle guard root",
        )?;
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_RETIRED,
            ],
            "token factory LP binding status",
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryUpgradePolicy {
    pub upgrade_policy_id: String,
    pub class_id: String,
    pub governance_scope: String,
    pub governance_controller_root: String,
    pub proposal_threshold_units: u64,
    pub timelock_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub allowed_scope_root: String,
    pub metadata_upgradeable: bool,
    pub supply_policy_upgradeable: bool,
    pub transfer_policy_upgradeable: bool,
    pub hook_upgradeable: bool,
    pub issuer_rotation_allowed: bool,
    pub latest_proposal_id: String,
    pub latest_proposal_root: String,
    pub executed_upgrade_root: String,
    pub version: u64,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFactoryUpgradePolicy {
    pub fn governance_controlled(
        class_id: &str,
        governance_controller_root: &str,
        height: u64,
    ) -> Self {
        let scopes = vec![
            TokenFactoryUpgradeScope::Metadata.as_str().to_string(),
            TokenFactoryUpgradeScope::SupplyPolicy.as_str().to_string(),
            TokenFactoryUpgradeScope::TransferPolicy
                .as_str()
                .to_string(),
            TokenFactoryUpgradeScope::HookSet.as_str().to_string(),
            TokenFactoryUpgradeScope::IssuerAuthorization
                .as_str()
                .to_string(),
            TokenFactoryUpgradeScope::Sponsor.as_str().to_string(),
            TokenFactoryUpgradeScope::EmergencyPause
                .as_str()
                .to_string(),
        ];
        let allowed_scope_root =
            token_factory_string_set_root("TOKEN-FACTORY-UPGRADE-SCOPE", &scopes);
        let latest_proposal_root = token_factory_empty_root("TOKEN-FACTORY-UPGRADE-PROPOSAL");
        let executed_upgrade_root = token_factory_empty_root("TOKEN-FACTORY-EXECUTED-UPGRADE");
        let upgrade_policy_id = token_factory_upgrade_policy_id(
            class_id,
            TOKEN_FACTORY_DEFAULT_UPGRADE_SCOPE,
            governance_controller_root,
            1,
            height,
        );
        Self {
            upgrade_policy_id,
            class_id: class_id.to_string(),
            governance_scope: TOKEN_FACTORY_DEFAULT_UPGRADE_SCOPE.to_string(),
            governance_controller_root: governance_controller_root.to_string(),
            proposal_threshold_units: 1,
            timelock_blocks: 20,
            emergency_delay_blocks: 2,
            allowed_scope_root,
            metadata_upgradeable: true,
            supply_policy_upgradeable: true,
            transfer_policy_upgradeable: true,
            hook_upgradeable: true,
            issuer_rotation_allowed: true,
            latest_proposal_id: String::new(),
            latest_proposal_root,
            executed_upgrade_root,
            version: 1,
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_upgrade_policy",
            "chain_id": CHAIN_ID,
            "upgrade_policy_id": self.upgrade_policy_id,
            "class_id": self.class_id,
            "governance_scope": self.governance_scope,
            "governance_controller_root": self.governance_controller_root,
            "proposal_threshold_units": self.proposal_threshold_units,
            "timelock_blocks": self.timelock_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "allowed_scope_root": self.allowed_scope_root,
            "metadata_upgradeable": self.metadata_upgradeable,
            "supply_policy_upgradeable": self.supply_policy_upgradeable,
            "transfer_policy_upgradeable": self.transfer_policy_upgradeable,
            "hook_upgradeable": self.hook_upgradeable,
            "issuer_rotation_allowed": self.issuer_rotation_allowed,
            "latest_proposal_id": self.latest_proposal_id,
            "latest_proposal_root": self.latest_proposal_root,
            "executed_upgrade_root": self.executed_upgrade_root,
            "version": self.version,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn policy_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-UPGRADE-POLICY", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.upgrade_policy_id, "token factory upgrade policy id")?;
        validate_root_like(&self.class_id, "token factory upgrade class id")?;
        validate_not_empty(
            &self.governance_scope,
            "token factory upgrade governance scope",
        )?;
        validate_root_like(
            &self.governance_controller_root,
            "token factory upgrade governance controller root",
        )?;
        validate_root_like(&self.allowed_scope_root, "token factory upgrade scope root")?;
        validate_root_like(
            &self.latest_proposal_root,
            "token factory latest proposal root",
        )?;
        validate_root_like(
            &self.executed_upgrade_root,
            "token factory executed upgrade root",
        )?;
        if self.timelock_blocks < TOKEN_FACTORY_MIN_TIMELOCK_BLOCKS {
            return Err("token factory upgrade timelock is too short".to_string());
        }
        if self.emergency_delay_blocks > self.timelock_blocks {
            return Err("token factory emergency delay exceeds timelock".to_string());
        }
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_EXECUTED,
                TOKEN_FACTORY_STATUS_RETIRED,
            ],
            "token factory upgrade policy status",
        )?;
        let expected = token_factory_upgrade_policy_id(
            &self.class_id,
            &self.governance_scope,
            &self.governance_controller_root,
            self.version,
            self.created_at_height,
        );
        if self.upgrade_policy_id != expected {
            return Err("token factory upgrade policy id mismatch".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryMintSponsor {
    pub sponsorship_id: String,
    pub class_id: String,
    pub sponsor_commitment: String,
    pub paymaster_root: String,
    pub fee_asset_id: String,
    pub lane_id: String,
    pub budget_units: u64,
    pub reserved_units: u64,
    pub spent_units: u64,
    pub max_units_per_mint: u64,
    pub min_mint_units: u64,
    pub rebate_bps: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub nonce: u64,
    pub status: String,
}

impl TokenFactoryMintSponsor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class_id: &str,
        sponsor_label: &str,
        fee_asset_id: &str,
        lane_id: &str,
        budget_units: u64,
        max_units_per_mint: u64,
        rebate_bps: u64,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> Self {
        let sponsor_commitment =
            token_factory_string_root("TOKEN-FACTORY-MINT-SPONSOR", sponsor_label);
        let paymaster_root = token_factory_string_root(
            "TOKEN-FACTORY-PAYMASTER",
            TOKEN_FACTORY_DEFAULT_PAYMASTER_LABEL,
        );
        let sponsorship_id = token_factory_mint_sponsorship_id(
            class_id,
            &sponsor_commitment,
            fee_asset_id,
            lane_id,
            starts_at_height,
        );
        Self {
            sponsorship_id,
            class_id: class_id.to_string(),
            sponsor_commitment,
            paymaster_root,
            fee_asset_id: fee_asset_id.to_string(),
            lane_id: lane_id.to_string(),
            budget_units,
            reserved_units: 0,
            spent_units: 0,
            max_units_per_mint,
            min_mint_units: 1,
            rebate_bps,
            starts_at_height,
            expires_at_height,
            nonce: 0,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        }
    }

    pub fn available_units(&self) -> u64 {
        self.budget_units
            .saturating_sub(self.reserved_units)
            .saturating_sub(self.spent_units)
    }

    pub fn is_active_at(&self, height: u64) -> bool {
        self.status == TOKEN_FACTORY_STATUS_ACTIVE
            && height >= self.starts_at_height
            && (self.expires_at_height == 0 || height <= self.expires_at_height)
            && self.available_units() > 0
    }

    pub fn can_cover(&self, mint_units: u64, fee_units: u64, height: u64) -> bool {
        if !self.is_active_at(height) || mint_units < self.min_mint_units {
            return false;
        }
        if self.max_units_per_mint != 0 && mint_units > self.max_units_per_mint {
            return false;
        }
        fee_units <= self.available_units()
    }

    pub fn reserve(&mut self, fee_units: u64, height: u64) -> TokenFactoryResult<String> {
        if !self.is_active_at(height) {
            return Err("token factory mint sponsorship is not active".to_string());
        }
        if fee_units > self.available_units() {
            return Err("token factory mint sponsorship budget exhausted".to_string());
        }
        self.reserved_units = self
            .reserved_units
            .checked_add(fee_units)
            .ok_or_else(|| "token factory mint sponsorship reserve overflow".to_string())?;
        self.nonce = self.nonce.saturating_add(1);
        Ok(self.sponsorship_root())
    }

    pub fn spend(&mut self, fee_units: u64, height: u64) -> TokenFactoryResult<String> {
        if !self.is_active_at(height) {
            return Err("token factory mint sponsorship is not active".to_string());
        }
        if fee_units > self.reserved_units && fee_units > self.available_units() {
            return Err("token factory mint sponsorship spend exceeds budget".to_string());
        }
        if self.reserved_units >= fee_units {
            self.reserved_units = self.reserved_units.saturating_sub(fee_units);
        }
        self.spent_units = self
            .spent_units
            .checked_add(fee_units)
            .ok_or_else(|| "token factory mint sponsorship spend overflow".to_string())?;
        self.nonce = self.nonce.saturating_add(1);
        if self.available_units() == 0 {
            self.status = TOKEN_FACTORY_STATUS_EXHAUSTED.to_string();
        }
        Ok(self.sponsorship_root())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_mint_sponsor",
            "chain_id": CHAIN_ID,
            "sponsorship_id": self.sponsorship_id,
            "class_id": self.class_id,
            "sponsor_commitment": self.sponsor_commitment,
            "paymaster_root": self.paymaster_root,
            "fee_asset_id": self.fee_asset_id,
            "lane_id": self.lane_id,
            "budget_units": self.budget_units,
            "reserved_units": self.reserved_units,
            "spent_units": self.spent_units,
            "available_units": self.available_units(),
            "max_units_per_mint": self.max_units_per_mint,
            "min_mint_units": self.min_mint_units,
            "rebate_bps": self.rebate_bps,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "nonce": self.nonce,
            "status": self.status,
        })
    }

    pub fn sponsorship_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-MINT-SPONSOR", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.sponsorship_id, "token factory mint sponsorship id")?;
        validate_root_like(&self.class_id, "token factory mint sponsorship class id")?;
        validate_root_like(
            &self.sponsor_commitment,
            "token factory mint sponsor commitment",
        )?;
        validate_root_like(
            &self.paymaster_root,
            "token factory mint sponsor paymaster root",
        )?;
        validate_root_like(&self.fee_asset_id, "token factory mint sponsor fee asset")?;
        validate_not_empty(&self.lane_id, "token factory mint sponsor lane")?;
        validate_bps(self.rebate_bps, "token factory mint sponsor rebate")?;
        if self.spent_units > self.budget_units {
            return Err("token factory mint sponsorship spent units exceed budget".to_string());
        }
        if self.reserved_units > self.budget_units.saturating_sub(self.spent_units) {
            return Err("token factory mint sponsorship reserved units exceed budget".to_string());
        }
        if self.expires_at_height != 0 && self.expires_at_height < self.starts_at_height {
            return Err("token factory mint sponsorship expires before start".to_string());
        }
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_EXHAUSTED,
                TOKEN_FACTORY_STATUS_REVOKED,
            ],
            "token factory mint sponsorship status",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryAuditEvent {
    pub event_id: String,
    pub event_kind: TokenFactoryAuditEventKind,
    pub class_id: String,
    pub actor_commitment: String,
    pub subject_id: String,
    pub amount_units: u64,
    pub root_before: String,
    pub root_after: String,
    pub memo_commitment: String,
    pub evidence_root: String,
    pub height: u64,
    pub index: u64,
}

impl TokenFactoryAuditEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        event_kind: TokenFactoryAuditEventKind,
        class_id: &str,
        actor_label: &str,
        subject_id: &str,
        amount_units: u64,
        root_before: &str,
        root_after: &str,
        memo: &str,
        evidence: &Value,
        height: u64,
        index: u64,
    ) -> Self {
        let actor_commitment = token_factory_string_root("TOKEN-FACTORY-AUDIT-ACTOR", actor_label);
        let memo_commitment = token_factory_string_root("TOKEN-FACTORY-AUDIT-MEMO", memo);
        let evidence_root = token_factory_payload_root("TOKEN-FACTORY-AUDIT-EVIDENCE", evidence);
        let event_id = token_factory_audit_event_id(
            event_kind.as_str(),
            class_id,
            &actor_commitment,
            subject_id,
            amount_units,
            root_before,
            root_after,
            height,
            index,
        );
        Self {
            event_id,
            event_kind,
            class_id: class_id.to_string(),
            actor_commitment,
            subject_id: subject_id.to_string(),
            amount_units,
            root_before: root_before.to_string(),
            root_after: root_after.to_string(),
            memo_commitment,
            evidence_root,
            height,
            index,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_audit_event",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "class_id": self.class_id,
            "actor_commitment": self.actor_commitment,
            "subject_id": self.subject_id,
            "amount_units": self.amount_units,
            "root_before": self.root_before,
            "root_after": self.root_after,
            "memo_commitment": self.memo_commitment,
            "evidence_root": self.evidence_root,
            "height": self.height,
            "index": self.index,
        })
    }

    pub fn event_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-AUDIT-EVENT", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.event_id, "token factory audit event id")?;
        validate_root_like(
            &self.actor_commitment,
            "token factory audit actor commitment",
        )?;
        validate_not_empty(&self.subject_id, "token factory audit subject id")?;
        validate_root_like(&self.root_before, "token factory audit root before")?;
        validate_root_like(&self.root_after, "token factory audit root after")?;
        validate_root_like(&self.memo_commitment, "token factory audit memo commitment")?;
        validate_root_like(&self.evidence_root, "token factory audit evidence root")?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryIssueRequest {
    pub request_id: String,
    pub symbol: String,
    pub display_name: String,
    pub decimals: u8,
    pub asset_kind: TokenFactoryAssetKind,
    pub supply_mode: TokenFactorySupplyMode,
    pub issuer_id: String,
    pub initial_supply_units: u64,
    pub max_supply_units: u64,
    pub metadata: Value,
    pub metadata_blinding: String,
    pub governance_proposal_id: String,
    pub reserve_commitment_root: String,
    pub reserve_asset_id: String,
    pub created_at_height: u64,
}

impl TokenFactoryIssueRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        symbol: &str,
        display_name: &str,
        decimals: u8,
        asset_kind: TokenFactoryAssetKind,
        supply_mode: TokenFactorySupplyMode,
        issuer_id: &str,
        initial_supply_units: u64,
        max_supply_units: u64,
        metadata: Value,
        metadata_blinding: &str,
        governance_proposal_id: &str,
        reserve_commitment_root: &str,
        reserve_asset_id: &str,
        created_at_height: u64,
    ) -> Self {
        let normalized_symbol = normalize_symbol(symbol);
        let request_id = token_factory_issue_request_id(
            &normalized_symbol,
            decimals,
            &asset_kind.as_str(),
            supply_mode.as_str(),
            issuer_id,
            governance_proposal_id,
            created_at_height,
        );
        Self {
            request_id,
            symbol: normalized_symbol,
            display_name: display_name.to_string(),
            decimals,
            asset_kind,
            supply_mode,
            issuer_id: issuer_id.to_string(),
            initial_supply_units,
            max_supply_units,
            metadata,
            metadata_blinding: metadata_blinding.to_string(),
            governance_proposal_id: governance_proposal_id.to_string(),
            reserve_commitment_root: reserve_commitment_root.to_string(),
            reserve_asset_id: reserve_asset_id.to_string(),
            created_at_height,
        }
    }

    pub fn wrapped_monero(issuer_id: &str, height: u64) -> Self {
        Self::new(
            TOKEN_FACTORY_WXMR_SYMBOL,
            TOKEN_FACTORY_WXMR_DISPLAY_NAME,
            TOKEN_FACTORY_WXMR_DECIMALS,
            TokenFactoryAssetKind::WrappedMonero,
            TokenFactorySupplyMode::WrappedReserve,
            issuer_id,
            5_000_000_000_000,
            18_400_000_000_000_000_000,
            json!({
                "display_name": TOKEN_FACTORY_WXMR_DISPLAY_NAME,
                "symbol": TOKEN_FACTORY_WXMR_SYMBOL,
                "decimals": TOKEN_FACTORY_WXMR_DECIMALS,
                "network": TOKEN_FACTORY_WXMR_RESERVE_NETWORK,
                "reserve_policy": TOKEN_FACTORY_WXMR_RESERVE_POLICY,
                "uri": "nebula://assets/wxmr",
                "audit_uri": "nebula://audits/wxmr-reserve-devnet",
            }),
            "devnet-wxmr-metadata",
            "genesis-wxmr",
            &token_factory_string_root("TOKEN-FACTORY-WXMR-RESERVE", "monero-reserve-devnet"),
            "monero:xmr",
            height,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_issue_request",
            "chain_id": CHAIN_ID,
            "request_id": self.request_id,
            "symbol": self.symbol,
            "display_name": self.display_name,
            "decimals": self.decimals,
            "asset_kind": self.asset_kind.as_str(),
            "supply_mode": self.supply_mode.as_str(),
            "issuer_id": self.issuer_id,
            "initial_supply_units": self.initial_supply_units,
            "max_supply_units": self.max_supply_units,
            "metadata_root": token_factory_payload_root("TOKEN-FACTORY-ISSUE-METADATA", &self.metadata),
            "metadata_blinding_root": token_factory_string_root("TOKEN-FACTORY-ISSUE-BLINDING", &self.metadata_blinding),
            "governance_proposal_id": self.governance_proposal_id,
            "reserve_commitment_root": self.reserve_commitment_root,
            "reserve_asset_id": self.reserve_asset_id,
            "created_at_height": self.created_at_height,
        })
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.request_id, "token factory issue request id")?;
        validate_symbol(&self.symbol)?;
        validate_not_empty(&self.display_name, "token factory issue display name")?;
        validate_root_like(&self.issuer_id, "token factory issue issuer id")?;
        validate_not_empty(
            &self.governance_proposal_id,
            "token factory issue governance proposal id",
        )?;
        validate_not_empty(
            &self.metadata_blinding,
            "token factory issue metadata blinding",
        )?;
        if self.asset_kind.requires_reserve()
            || self.supply_mode == TokenFactorySupplyMode::WrappedReserve
        {
            validate_root_like(
                &self.reserve_commitment_root,
                "token factory issue reserve commitment root",
            )?;
            validate_not_empty(
                &self.reserve_asset_id,
                "token factory issue reserve asset id",
            )?;
        }
        if self.supply_mode.requires_cap() && self.max_supply_units == 0 {
            return Err("token factory capped issue requires max supply".to_string());
        }
        if self.max_supply_units != 0 && self.initial_supply_units > self.max_supply_units {
            return Err("token factory initial supply exceeds max supply".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryClassRecord {
    pub class_id: String,
    pub asset_kind: TokenFactoryAssetKind,
    pub symbol: String,
    pub decimals: u8,
    pub metadata: TokenFactoryMetadataCommitment,
    pub registry_commitment: TokenFactoryRegistryCommitment,
    pub issuer_id: String,
    pub issuer_root: String,
    pub supply: TokenFactorySupplyPolicy,
    pub transfer_policy_id: String,
    pub transfer_policy_root: String,
    pub hook_root: String,
    pub upgrade_policy_id: String,
    pub upgrade_policy_root: String,
    pub lp_binding_id: String,
    pub lp_binding_root: String,
    pub sponsorship_id: String,
    pub sponsorship_root: String,
    pub creation_governance_id: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub status: String,
}

impl TokenFactoryClassRecord {
    pub fn from_issue_request(
        request: &TokenFactoryIssueRequest,
        issuer: &TokenFactoryIssuerAuthorization,
        height: u64,
    ) -> TokenFactoryResult<(Self, TokenFactoryTransferPolicy, TokenFactoryUpgradePolicy)> {
        request.validate()?;
        issuer.validate()?;
        if !issuer.is_active_at(height) {
            return Err("token factory issuer is not active".to_string());
        }
        if request.issuer_id != issuer.issuer_id {
            return Err("token factory issue request issuer mismatch".to_string());
        }
        let metadata = TokenFactoryMetadataCommitment::confidential(
            &request.symbol,
            &request.display_name,
            request.decimals,
            &request.metadata,
            &request.metadata_blinding,
            height,
        );
        metadata.validate()?;
        let metadata_root = metadata.commitment_root();
        let issuer_root = issuer.issuer_root();
        let class_id = token_factory_class_id(
            &request.symbol,
            request.decimals,
            &request.asset_kind.as_str(),
            request.supply_mode.as_str(),
            &issuer_root,
            &metadata_root,
            height,
            &request.governance_proposal_id,
        );
        let authorities = vec![issuer.issuer_id.clone()];
        let reserve_commitment_root = if request.reserve_commitment_root.trim().is_empty() {
            token_factory_empty_root("TOKEN-FACTORY-RESERVE")
        } else {
            request.reserve_commitment_root.clone()
        };
        let supply = match request.supply_mode {
            TokenFactorySupplyMode::Fixed => TokenFactorySupplyPolicy::fixed(
                &class_id,
                request.initial_supply_units,
                &authorities,
                height,
            ),
            TokenFactorySupplyMode::WrappedReserve => TokenFactorySupplyPolicy::wrapped_monero(
                &class_id,
                request.initial_supply_units,
                &authorities,
                &reserve_commitment_root,
                height,
            ),
            TokenFactorySupplyMode::PoolShare => TokenFactorySupplyPolicy::lp_share(
                &class_id,
                request.initial_supply_units,
                &authorities,
                height,
            ),
            TokenFactorySupplyMode::CappedMintBurn | TokenFactorySupplyMode::GovernanceMint => {
                TokenFactorySupplyPolicy::capped_mint_burn(
                    &class_id,
                    request.max_supply_units,
                    request.initial_supply_units,
                    &authorities,
                    height,
                )
            }
            TokenFactorySupplyMode::MintBurn
            | TokenFactorySupplyMode::ContractControlled
            | TokenFactorySupplyMode::BurnOnly => TokenFactorySupplyPolicy::new(
                &class_id,
                request.supply_mode.clone(),
                request.max_supply_units,
                request.max_supply_units,
                request.max_supply_units,
                TOKEN_FACTORY_DEVNET_EPOCH,
                request.max_supply_units,
                request.max_supply_units,
                request.initial_supply_units,
                &authorities,
                &authorities,
                &request.reserve_asset_id,
                &reserve_commitment_root,
                height,
            ),
        };
        supply.validate()?;
        let transfer_policy = TokenFactoryTransferPolicy::default_confidential(&class_id, height);
        let transfer_policy_root = transfer_policy.policy_root();
        let registry_commitment = TokenFactoryRegistryCommitment::new(
            &class_id,
            &metadata_root,
            &issuer_root,
            &supply.supply_root(),
            &transfer_policy_root,
            &[
                "symbol".to_string(),
                "decimals".to_string(),
                "asset_kind".to_string(),
            ],
            &request.metadata_blinding,
            height,
        );
        registry_commitment.validate()?;
        let upgrade_policy = TokenFactoryUpgradePolicy::governance_controlled(
            &class_id,
            &issuer.governance_controller_root,
            height,
        );
        let record = Self {
            class_id,
            asset_kind: request.asset_kind.clone(),
            symbol: request.symbol.clone(),
            decimals: request.decimals,
            metadata,
            registry_commitment,
            issuer_id: issuer.issuer_id.clone(),
            issuer_root,
            supply,
            transfer_policy_id: transfer_policy.policy_id.clone(),
            transfer_policy_root,
            hook_root: token_factory_empty_root("TOKEN-FACTORY-HOOK"),
            upgrade_policy_id: upgrade_policy.upgrade_policy_id.clone(),
            upgrade_policy_root: upgrade_policy.policy_root(),
            lp_binding_id: String::new(),
            lp_binding_root: token_factory_empty_root("TOKEN-FACTORY-LP-BINDING"),
            sponsorship_id: String::new(),
            sponsorship_root: token_factory_empty_root("TOKEN-FACTORY-MINT-SPONSOR"),
            creation_governance_id: request.governance_proposal_id.clone(),
            created_at_height: height,
            updated_at_height: height,
            status: TOKEN_FACTORY_STATUS_ACTIVE.to_string(),
        };
        record.validate()?;
        Ok((record, transfer_policy, upgrade_policy))
    }

    pub fn circulating_units(&self) -> u64 {
        self.supply.circulating_units()
    }

    pub fn can_use_low_fee_mint_lane(&self) -> bool {
        self.status == TOKEN_FACTORY_STATUS_ACTIVE && !self.sponsorship_id.is_empty()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_class_record",
            "chain_id": CHAIN_ID,
            "class_id": self.class_id,
            "asset_kind": self.asset_kind.as_str(),
            "symbol": self.symbol,
            "decimals": self.decimals,
            "metadata": self.metadata.public_record(),
            "metadata_root": self.metadata.commitment_root(),
            "registry_commitment": self.registry_commitment.public_record(),
            "registry_commitment_root": self.registry_commitment.commitment_root(),
            "issuer_id": self.issuer_id,
            "issuer_root": self.issuer_root,
            "supply": self.supply.public_record(),
            "supply_root": self.supply.supply_root(),
            "circulating_units": self.circulating_units(),
            "transfer_policy_id": self.transfer_policy_id,
            "transfer_policy_root": self.transfer_policy_root,
            "hook_root": self.hook_root,
            "upgrade_policy_id": self.upgrade_policy_id,
            "upgrade_policy_root": self.upgrade_policy_root,
            "lp_binding_id": self.lp_binding_id,
            "lp_binding_root": self.lp_binding_root,
            "sponsorship_id": self.sponsorship_id,
            "sponsorship_root": self.sponsorship_root,
            "low_fee_mint_lane_enabled": self.can_use_low_fee_mint_lane(),
            "creation_governance_id": self.creation_governance_id,
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "status": self.status,
        })
    }

    pub fn class_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-CLASS-RECORD", &self.public_record())
    }

    pub fn validate(&self) -> TokenFactoryResult<()> {
        validate_root_like(&self.class_id, "token factory class id")?;
        validate_symbol(&self.symbol)?;
        self.metadata.validate()?;
        self.registry_commitment.validate()?;
        validate_root_like(&self.issuer_id, "token factory class issuer id")?;
        validate_root_like(&self.issuer_root, "token factory class issuer root")?;
        self.supply.validate()?;
        validate_root_like(
            &self.transfer_policy_id,
            "token factory class transfer policy id",
        )?;
        validate_root_like(
            &self.transfer_policy_root,
            "token factory class transfer policy root",
        )?;
        validate_root_like(&self.hook_root, "token factory class hook root")?;
        validate_root_like(
            &self.upgrade_policy_id,
            "token factory class upgrade policy id",
        )?;
        validate_root_like(
            &self.upgrade_policy_root,
            "token factory class upgrade policy root",
        )?;
        validate_root_like(&self.lp_binding_root, "token factory class LP binding root")?;
        validate_root_like(
            &self.sponsorship_root,
            "token factory class sponsorship root",
        )?;
        validate_not_empty(
            &self.creation_governance_id,
            "token factory class creation governance id",
        )?;
        if self.supply.class_id != self.class_id {
            return Err("token factory class supply id mismatch".to_string());
        }
        if self.registry_commitment.class_id != self.class_id {
            return Err("token factory class registry id mismatch".to_string());
        }
        if self.asset_kind == TokenFactoryAssetKind::WrappedMonero
            && self.supply.supply_mode != TokenFactorySupplyMode::WrappedReserve
        {
            return Err("token factory wXMR must use wrapped reserve supply".to_string());
        }
        validate_status(
            &self.status,
            &[
                TOKEN_FACTORY_STATUS_ACTIVE,
                TOKEN_FACTORY_STATUS_PENDING,
                TOKEN_FACTORY_STATUS_PAUSED,
                TOKEN_FACTORY_STATUS_FROZEN,
                TOKEN_FACTORY_STATUS_RETIRED,
            ],
            "token factory class status",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryRoots {
    pub config_root: String,
    pub issuer_root: String,
    pub class_root: String,
    pub transfer_policy_root: String,
    pub registry_root: String,
    pub hook_root: String,
    pub lp_binding_root: String,
    pub upgrade_policy_root: String,
    pub mint_sponsor_root: String,
    pub audit_event_root: String,
}

impl TokenFactoryRoots {
    pub fn state_root(&self) -> String {
        token_factory_payload_root("TOKEN-FACTORY-ROOTS", &self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "token_factory_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "issuer_root": self.issuer_root,
            "class_root": self.class_root,
            "transfer_policy_root": self.transfer_policy_root,
            "registry_root": self.registry_root,
            "hook_root": self.hook_root,
            "lp_binding_root": self.lp_binding_root,
            "upgrade_policy_root": self.upgrade_policy_root,
            "mint_sponsor_root": self.mint_sponsor_root,
            "audit_event_root": self.audit_event_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryState {
    pub config: TokenFactoryConfig,
    pub issuers: BTreeMap<String, TokenFactoryIssuerAuthorization>,
    pub classes: BTreeMap<String, TokenFactoryClassRecord>,
    pub transfer_policies: BTreeMap<String, TokenFactoryTransferPolicy>,
    pub registry_commitments: BTreeMap<String, TokenFactoryRegistryCommitment>,
    pub hooks: BTreeMap<String, TokenFactoryContractHook>,
    pub lp_bindings: BTreeMap<String, TokenFactoryLpBinding>,
    pub upgrade_policies: BTreeMap<String, TokenFactoryUpgradePolicy>,
    pub mint_sponsors: BTreeMap<String, TokenFactoryMintSponsor>,
    pub audit_events: BTreeMap<String, TokenFactoryAuditEvent>,
    pub height: u64,
    pub next_audit_index: u64,
}

impl Default for TokenFactoryState {
    fn default() -> Self {
        Self {
            config: TokenFactoryConfig::default(),
            issuers: BTreeMap::new(),
            classes: BTreeMap::new(),
            transfer_policies: BTreeMap::new(),
            registry_commitments: BTreeMap::new(),
            hooks: BTreeMap::new(),
            lp_bindings: BTreeMap::new(),
            upgrade_policies: BTreeMap::new(),
            mint_sponsors: BTreeMap::new(),
            audit_events: BTreeMap::new(),
            height: 0,
            next_audit_index: 0,
        }
    }
}

impl TokenFactoryState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devnet() -> TokenFactoryResult<Self> {
        let mut state = Self {
            height: TOKEN_FACTORY_DEVNET_HEIGHT,
            ..Self::default()
        };
        let governance = TokenFactoryIssuerAuthorization::devnet_governance(state.height);
        let bridge = TokenFactoryIssuerAuthorization::devnet_bridge(state.height);
        let defi = TokenFactoryIssuerAuthorization::devnet_defi(state.height);
        let governance_id = state.register_issuer(governance)?;
        let bridge_id = state.register_issuer(bridge)?;
        let defi_id = state.register_issuer(defi)?;

        let wxmr_id = state.issue_class(TokenFactoryIssueRequest::wrapped_monero(
            &bridge_id,
            state.height,
        ))?;
        let dnr_id = state.issue_class(TokenFactoryIssueRequest::new(
            TOKEN_FACTORY_DEVNET_DNR_SYMBOL,
            TOKEN_FACTORY_DEVNET_DNR_NAME,
            12,
            TokenFactoryAssetKind::Governance,
            TokenFactorySupplyMode::GovernanceMint,
            &governance_id,
            100_000_000_000_000,
            1_000_000_000_000_000,
            json!({
                "display_name": TOKEN_FACTORY_DEVNET_DNR_NAME,
                "symbol": TOKEN_FACTORY_DEVNET_DNR_SYMBOL,
                "uri": "nebula://assets/dnr",
                "audit_uri": "nebula://audits/dnr-genesis",
            }),
            "devnet-dnr-metadata",
            "genesis-dnr",
            &token_factory_empty_root("TOKEN-FACTORY-RESERVE"),
            "",
            state.height,
        ))?;
        let usdd_id = state.issue_class(TokenFactoryIssueRequest::new(
            TOKEN_FACTORY_DEVNET_USDD_SYMBOL,
            TOKEN_FACTORY_DEVNET_USDD_NAME,
            6,
            TokenFactoryAssetKind::Stable,
            TokenFactorySupplyMode::CappedMintBurn,
            &defi_id,
            2_500_000_000_000,
            1_000_000_000_000_000,
            json!({
                "display_name": TOKEN_FACTORY_DEVNET_USDD_NAME,
                "symbol": TOKEN_FACTORY_DEVNET_USDD_SYMBOL,
                "uri": "nebula://assets/usdd",
                "audit_uri": "nebula://audits/usdd-risk-devnet",
            }),
            "devnet-usdd-metadata",
            "genesis-usdd",
            &token_factory_string_root(
                "TOKEN-FACTORY-USDD-RESERVE",
                "devnet-private-dollar-reserve",
            ),
            "nebula:reserve:usdd",
            state.height,
        ))?;
        let lp_id = state.issue_class(TokenFactoryIssueRequest::new(
            TOKEN_FACTORY_DEVNET_LP_SYMBOL,
            "wXMR/USDD LP Share",
            18,
            TokenFactoryAssetKind::LiquidityShare,
            TokenFactorySupplyMode::PoolShare,
            &defi_id,
            1_000_000_000_000_000_000,
            0,
            json!({
                "display_name": "wXMR/USDD LP Share",
                "symbol": TOKEN_FACTORY_DEVNET_LP_SYMBOL,
                "uri": "nebula://assets/wxmr-usdd-lp",
                "pool": "wxmr-usdd-devnet",
            }),
            "devnet-wxmr-usdd-lp-metadata",
            "genesis-wxmr-usdd-lp",
            &token_factory_empty_root("TOKEN-FACTORY-RESERVE"),
            "",
            state.height,
        ))?;
        let lp_binding = TokenFactoryLpBinding::constant_product(
            &lp_id,
            "wxmr-usdd-devnet-pool",
            &wxmr_id,
            &usdd_id,
            18,
            state.height,
        );
        state.attach_lp_binding(lp_binding)?;

        let wxmr_hook = TokenFactoryContractHook::new(
            &wxmr_id,
            "monero-bridge-hook-devnet",
            "on_wrapped_monero_flow",
            TokenFactoryHookPhases::all_supply_and_transfer(),
            state.height,
        );
        state.attach_hook(wxmr_hook)?;
        let lp_hook = TokenFactoryContractHook::new(
            &lp_id,
            "amm-share-accounting-hook-devnet",
            "on_lp_share_flow",
            TokenFactoryHookPhases::all_supply_and_transfer(),
            state.height,
        );
        state.attach_hook(lp_hook)?;

        let wxmr_sponsor = TokenFactoryMintSponsor::new(
            &wxmr_id,
            "devnet-wxmr-low-fee-mint-sponsor",
            &wxmr_id,
            TOKEN_FACTORY_DEFAULT_LOW_FEE_LANE,
            250_000_000_000,
            100_000_000_000,
            10_000,
            state.height,
            state.height.saturating_add(10_000),
        );
        state.register_mint_sponsor(wxmr_sponsor)?;
        let usdd_sponsor = TokenFactoryMintSponsor::new(
            &usdd_id,
            "devnet-usdd-low-fee-mint-sponsor",
            &wxmr_id,
            "stable_asset_issuance",
            500_000_000,
            250_000_000_000,
            7_500,
            state.height,
            state.height.saturating_add(10_000),
        );
        state.register_mint_sponsor(usdd_sponsor)?;

        state.append_audit_event(
            TokenFactoryAuditEventKind::DevnetGenesis,
            "",
            TOKEN_FACTORY_DEVNET_GOVERNANCE_LABEL,
            "token-factory-devnet",
            0,
            &token_factory_empty_root("TOKEN-FACTORY-DEVNET-BEFORE"),
            &state.roots().state_root(),
            "deterministic token factory devnet",
            &json!({
                "wxmr_id": wxmr_id,
                "dnr_id": dnr_id,
                "usdd_id": usdd_id,
                "lp_id": lp_id,
            }),
        )?;
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> TokenFactoryResult<String> {
        if height < self.height {
            return Err("token factory height cannot move backward".to_string());
        }
        self.height = height;
        Ok(self.state_root())
    }

    pub fn register_issuer(
        &mut self,
        issuer: TokenFactoryIssuerAuthorization,
    ) -> TokenFactoryResult<String> {
        issuer.validate()?;
        if self.issuers.contains_key(&issuer.issuer_id) {
            return Err("token factory issuer already exists".to_string());
        }
        let issuer_id = issuer.issuer_id.clone();
        let root_before = self.issuer_root();
        let root_after = issuer.issuer_root();
        self.issuers.insert(issuer_id.clone(), issuer);
        self.append_audit_event(
            TokenFactoryAuditEventKind::IssuerRegistered,
            "",
            "issuer-registry",
            &issuer_id,
            0,
            &root_before,
            &root_after,
            "issuer registered",
            &json!({ "issuer_id": issuer_id }),
        )?;
        Ok(issuer_id)
    }

    pub fn issue_class(&mut self, request: TokenFactoryIssueRequest) -> TokenFactoryResult<String> {
        request.validate()?;
        let issuer = self
            .issuers
            .get(&request.issuer_id)
            .cloned()
            .ok_or_else(|| "token factory unknown issuer".to_string())?;
        let (class, transfer_policy, upgrade_policy) =
            TokenFactoryClassRecord::from_issue_request(&request, &issuer, self.height)?;
        if self.classes.contains_key(&class.class_id) {
            return Err("token factory class already exists".to_string());
        }
        let class_id = class.class_id.clone();
        let class_root = class.class_root();
        let transfer_policy_id = transfer_policy.policy_id.clone();
        let registry_id = class.registry_commitment.registry_id.clone();
        let upgrade_policy_id = upgrade_policy.upgrade_policy_id.clone();
        self.transfer_policies
            .insert(transfer_policy_id, transfer_policy);
        self.registry_commitments
            .insert(registry_id, class.registry_commitment.clone());
        self.upgrade_policies
            .insert(upgrade_policy_id, upgrade_policy);
        self.classes.insert(class_id.clone(), class);
        self.append_audit_event(
            TokenFactoryAuditEventKind::AssetIssued,
            &class_id,
            &issuer.issuer_label,
            &class_id,
            request.initial_supply_units,
            &token_factory_empty_root("TOKEN-FACTORY-CLASS-BEFORE"),
            &class_root,
            "asset class issued",
            &request.public_record(),
        )?;
        Ok(class_id)
    }

    pub fn apply_transfer_policy(
        &mut self,
        mut policy: TokenFactoryTransferPolicy,
        governance_proposal_id: &str,
    ) -> TokenFactoryResult<String> {
        validate_not_empty(
            governance_proposal_id,
            "token factory transfer policy governance proposal",
        )?;
        policy.updated_at_height = self.height;
        policy.validate()?;
        let mut class =
            self.classes.get(&policy.class_id).cloned().ok_or_else(|| {
                "token factory transfer policy references unknown class".to_string()
            })?;
        let root_before = class.class_root();
        let policy_root = policy.policy_root();
        class.transfer_policy_id = policy.policy_id.clone();
        class.transfer_policy_root = policy_root.clone();
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        self.transfer_policies
            .insert(policy.policy_id.clone(), policy);
        self.classes.insert(class.class_id.clone(), class.clone());
        self.append_audit_event(
            TokenFactoryAuditEventKind::TransferPolicyUpdated,
            &class.class_id,
            governance_proposal_id,
            &class.transfer_policy_id,
            0,
            &root_before,
            &root_after,
            "transfer policy updated",
            &json!({ "policy_root": policy_root }),
        )?;
        Ok(policy_root)
    }

    pub fn attach_hook(&mut self, hook: TokenFactoryContractHook) -> TokenFactoryResult<String> {
        hook.validate()?;
        let mut class = self
            .classes
            .get(&hook.class_id)
            .cloned()
            .ok_or_else(|| "token factory hook references unknown class".to_string())?;
        if !class.asset_kind.supports_hooks() {
            return Err("token factory class does not support hooks".to_string());
        }
        let root_before = class.class_root();
        let hook_root = hook.hook_root();
        class.hook_root = hook_root.clone();
        class.updated_at_height = self.height;
        if let Some(policy) = self.transfer_policies.get_mut(&class.transfer_policy_id) {
            policy.set_hook_root(&hook_root, self.height);
            class.transfer_policy_root = policy.policy_root();
        }
        let root_after = class.class_root();
        let hook_id = hook.hook_id.clone();
        self.hooks.insert(hook_id.clone(), hook);
        self.classes.insert(class.class_id.clone(), class.clone());
        self.append_audit_event(
            TokenFactoryAuditEventKind::HookAttached,
            &class.class_id,
            "hook-registry",
            &hook_id,
            0,
            &root_before,
            &root_after,
            "contract-bound token hook attached",
            &json!({ "hook_id": hook_id, "hook_root": hook_root }),
        )?;
        Ok(hook_id)
    }

    pub fn attach_lp_binding(
        &mut self,
        binding: TokenFactoryLpBinding,
    ) -> TokenFactoryResult<String> {
        binding.validate()?;
        let mut class = self
            .classes
            .get(&binding.share_class_id)
            .cloned()
            .ok_or_else(|| "token factory LP binding references unknown share class".to_string())?;
        if !class.asset_kind.is_lp_share() {
            return Err("token factory LP binding requires a liquidity share class".to_string());
        }
        if !self.classes.contains_key(&binding.base_asset_id) {
            return Err("token factory LP base asset is unknown".to_string());
        }
        if !self.classes.contains_key(&binding.quote_asset_id) {
            return Err("token factory LP quote asset is unknown".to_string());
        }
        let root_before = class.class_root();
        let binding_root = binding.binding_root();
        class.lp_binding_id = binding.binding_id.clone();
        class.lp_binding_root = binding_root.clone();
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        let binding_id = binding.binding_id.clone();
        self.lp_bindings.insert(binding_id.clone(), binding);
        self.classes.insert(class.class_id.clone(), class.clone());
        self.append_audit_event(
            TokenFactoryAuditEventKind::LpShareBound,
            &class.class_id,
            "lp-binding-registry",
            &binding_id,
            0,
            &root_before,
            &root_after,
            "LP share token bound to AMM pool",
            &json!({ "binding_id": binding_id, "binding_root": binding_root }),
        )?;
        Ok(binding_id)
    }

    pub fn apply_upgrade_policy(
        &mut self,
        mut policy: TokenFactoryUpgradePolicy,
        governance_proposal_id: &str,
    ) -> TokenFactoryResult<String> {
        validate_not_empty(
            governance_proposal_id,
            "token factory upgrade governance proposal",
        )?;
        policy.updated_at_height = self.height;
        policy.latest_proposal_id = governance_proposal_id.to_string();
        policy.latest_proposal_root =
            token_factory_string_root("TOKEN-FACTORY-UPGRADE-PROPOSAL", governance_proposal_id);
        policy.validate()?;
        let mut class =
            self.classes.get(&policy.class_id).cloned().ok_or_else(|| {
                "token factory upgrade policy references unknown class".to_string()
            })?;
        let root_before = class.class_root();
        let policy_root = policy.policy_root();
        class.upgrade_policy_id = policy.upgrade_policy_id.clone();
        class.upgrade_policy_root = policy_root.clone();
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        self.upgrade_policies
            .insert(policy.upgrade_policy_id.clone(), policy);
        self.classes.insert(class.class_id.clone(), class.clone());
        self.append_audit_event(
            TokenFactoryAuditEventKind::UpgradePolicyUpdated,
            &class.class_id,
            governance_proposal_id,
            &class.upgrade_policy_id,
            0,
            &root_before,
            &root_after,
            "governance upgrade policy updated",
            &json!({ "upgrade_policy_root": policy_root }),
        )?;
        Ok(policy_root)
    }

    pub fn register_mint_sponsor(
        &mut self,
        sponsor: TokenFactoryMintSponsor,
    ) -> TokenFactoryResult<String> {
        sponsor.validate()?;
        let mut class = self
            .classes
            .get(&sponsor.class_id)
            .cloned()
            .ok_or_else(|| "token factory sponsor references unknown class".to_string())?;
        let root_before = class.class_root();
        let sponsor_root = sponsor.sponsorship_root();
        class.sponsorship_id = sponsor.sponsorship_id.clone();
        class.sponsorship_root = sponsor_root.clone();
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        let sponsorship_id = sponsor.sponsorship_id.clone();
        self.mint_sponsors.insert(sponsorship_id.clone(), sponsor);
        self.classes.insert(class.class_id.clone(), class.clone());
        self.append_audit_event(
            TokenFactoryAuditEventKind::SponsorCreated,
            &class.class_id,
            "mint-sponsor-registry",
            &sponsorship_id,
            0,
            &root_before,
            &root_after,
            "low-fee mint sponsor created",
            &json!({ "sponsorship_id": sponsorship_id, "sponsorship_root": sponsor_root }),
        )?;
        Ok(sponsorship_id)
    }

    pub fn apply_mint(
        &mut self,
        class_id: &str,
        issuer_id: &str,
        amount_units: u64,
        sponsorship_id: Option<&str>,
        fee_units: u64,
        memo: &str,
    ) -> TokenFactoryResult<String> {
        let issuer = self
            .issuers
            .get(issuer_id)
            .cloned()
            .ok_or_else(|| "token factory mint issuer is unknown".to_string())?;
        if !issuer.is_active_at(self.height) {
            return Err("token factory mint issuer is not active".to_string());
        }
        let mut class = self
            .classes
            .get(class_id)
            .cloned()
            .ok_or_else(|| "token factory mint class is unknown".to_string())?;
        if class.issuer_id != issuer_id {
            return Err("token factory mint issuer mismatch".to_string());
        }
        let root_before = class.class_root();
        class.supply.apply_mint(amount_units, self.height)?;
        let mut sponsor_audit = None;
        if let Some(sponsor_id) = sponsorship_id {
            let sponsor_root = {
                let sponsor = self
                    .mint_sponsors
                    .get_mut(sponsor_id)
                    .ok_or_else(|| "token factory mint sponsor is unknown".to_string())?;
                if sponsor.class_id != class_id {
                    return Err("token factory mint sponsor class mismatch".to_string());
                }
                if !sponsor.can_cover(amount_units, fee_units, self.height) {
                    return Err("token factory mint sponsor cannot cover fee".to_string());
                }
                sponsor.spend(fee_units, self.height)?;
                sponsor.sponsorship_root()
            };
            class.sponsorship_root = sponsor_root.clone();
            sponsor_audit = Some((sponsor_id.to_string(), sponsor_root));
        }
        if let Some((sponsor_id, sponsor_root)) = sponsor_audit {
            self.append_audit_event(
                TokenFactoryAuditEventKind::SponsorSpent,
                class_id,
                &issuer.issuer_label,
                &sponsor_id,
                fee_units,
                &root_before,
                &sponsor_root,
                "mint sponsor spent",
                &json!({ "fee_units": fee_units, "mint_units": amount_units }),
            )?;
        }
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        self.classes.insert(class_id.to_string(), class);
        self.append_audit_event(
            TokenFactoryAuditEventKind::MintApplied,
            class_id,
            &issuer.issuer_label,
            class_id,
            amount_units,
            &root_before,
            &root_after,
            memo,
            &json!({
                "issuer_id": issuer_id,
                "sponsorship_id": sponsorship_id.unwrap_or_default(),
                "fee_units": fee_units,
            }),
        )
    }

    pub fn apply_burn(
        &mut self,
        class_id: &str,
        issuer_id: &str,
        amount_units: u64,
        memo: &str,
    ) -> TokenFactoryResult<String> {
        let issuer = self
            .issuers
            .get(issuer_id)
            .cloned()
            .ok_or_else(|| "token factory burn issuer is unknown".to_string())?;
        if !issuer.is_active_at(self.height) {
            return Err("token factory burn issuer is not active".to_string());
        }
        let mut class = self
            .classes
            .get(class_id)
            .cloned()
            .ok_or_else(|| "token factory burn class is unknown".to_string())?;
        if class.issuer_id != issuer_id {
            return Err("token factory burn issuer mismatch".to_string());
        }
        let root_before = class.class_root();
        class.supply.apply_burn(amount_units, self.height)?;
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        self.classes.insert(class_id.to_string(), class);
        self.append_audit_event(
            TokenFactoryAuditEventKind::BurnApplied,
            class_id,
            &issuer.issuer_label,
            class_id,
            amount_units,
            &root_before,
            &root_after,
            memo,
            &json!({ "issuer_id": issuer_id }),
        )
    }

    pub fn retire_class(
        &mut self,
        class_id: &str,
        governance_proposal_id: &str,
    ) -> TokenFactoryResult<String> {
        validate_not_empty(
            governance_proposal_id,
            "token factory retire governance proposal id",
        )?;
        let mut class = self
            .classes
            .get(class_id)
            .cloned()
            .ok_or_else(|| "token factory retire class is unknown".to_string())?;
        let root_before = class.class_root();
        class.status = TOKEN_FACTORY_STATUS_RETIRED.to_string();
        class.updated_at_height = self.height;
        let root_after = class.class_root();
        self.classes.insert(class_id.to_string(), class);
        self.append_audit_event(
            TokenFactoryAuditEventKind::AssetRetired,
            class_id,
            governance_proposal_id,
            class_id,
            0,
            &root_before,
            &root_after,
            "asset class retired",
            &json!({ "governance_proposal_id": governance_proposal_id }),
        )
    }

    pub fn append_audit_event(
        &mut self,
        event_kind: TokenFactoryAuditEventKind,
        class_id: &str,
        actor_label: &str,
        subject_id: &str,
        amount_units: u64,
        root_before: &str,
        root_after: &str,
        memo: &str,
        evidence: &Value,
    ) -> TokenFactoryResult<String> {
        let event = TokenFactoryAuditEvent::new(
            event_kind,
            class_id,
            actor_label,
            subject_id,
            amount_units,
            root_before,
            root_after,
            memo,
            evidence,
            self.height,
            self.next_audit_index,
        );
        event.validate()?;
        self.next_audit_index = self.next_audit_index.saturating_add(1);
        let event_id = event.event_id.clone();
        self.audit_events.insert(event_id.clone(), event);
        Ok(event_id)
    }

    pub fn roots(&self) -> TokenFactoryRoots {
        TokenFactoryRoots {
            config_root: self.config.config_root(),
            issuer_root: self.issuer_root(),
            class_root: self.class_root(),
            transfer_policy_root: self.transfer_policy_root(),
            registry_root: self.registry_root(),
            hook_root: self.hook_root(),
            lp_binding_root: self.lp_binding_root(),
            upgrade_policy_root: self.upgrade_policy_root(),
            mint_sponsor_root: self.mint_sponsor_root(),
            audit_event_root: self.audit_event_root(),
        }
    }

    pub fn issuer_root(&self) -> String {
        token_factory_issuer_set_root(&self.issuers.values().cloned().collect::<Vec<_>>())
    }

    pub fn class_root(&self) -> String {
        token_factory_class_set_root(&self.classes.values().cloned().collect::<Vec<_>>())
    }

    pub fn transfer_policy_root(&self) -> String {
        token_factory_transfer_policy_set_root(
            &self.transfer_policies.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn registry_root(&self) -> String {
        token_factory_registry_set_root(
            &self
                .registry_commitments
                .values()
                .cloned()
                .collect::<Vec<_>>(),
        )
    }

    pub fn hook_root(&self) -> String {
        token_factory_hook_set_root(&self.hooks.values().cloned().collect::<Vec<_>>())
    }

    pub fn lp_binding_root(&self) -> String {
        token_factory_lp_binding_set_root(&self.lp_bindings.values().cloned().collect::<Vec<_>>())
    }

    pub fn upgrade_policy_root(&self) -> String {
        token_factory_upgrade_policy_set_root(
            &self.upgrade_policies.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn mint_sponsor_root(&self) -> String {
        token_factory_mint_sponsor_set_root(
            &self.mint_sponsors.values().cloned().collect::<Vec<_>>(),
        )
    }

    pub fn audit_event_root(&self) -> String {
        token_factory_audit_event_set_root(&self.audit_events.values().cloned().collect::<Vec<_>>())
    }

    pub fn low_fee_mint_class_ids(&self) -> Vec<String> {
        self.classes
            .values()
            .filter(|class| {
                class.status == TOKEN_FACTORY_STATUS_ACTIVE
                    && !class.sponsorship_id.is_empty()
                    && self
                        .mint_sponsors
                        .get(&class.sponsorship_id)
                        .map_or(false, |sponsor| sponsor.is_active_at(self.height))
            })
            .map(|class| class.class_id.clone())
            .collect()
    }

    pub fn wrapped_monero_class_id(&self) -> Option<String> {
        self.classes
            .values()
            .find(|class| class.asset_kind == TokenFactoryAssetKind::WrappedMonero)
            .map(|class| class.class_id.clone())
    }

    pub fn state_root(&self) -> String {
        token_factory_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        record
            .as_object_mut()
            .expect("token factory state record object")
            .insert("state_root".to_string(), Value::String(self.state_root()));
        record
    }

    fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        json!({
            "kind": "token_factory_state",
            "chain_id": CHAIN_ID,
            "protocol_version": TOKEN_FACTORY_PROTOCOL_VERSION,
            "height": self.height,
            "next_audit_index": self.next_audit_index,
            "issuer_count": self.issuers.len() as u64,
            "class_count": self.classes.len() as u64,
            "transfer_policy_count": self.transfer_policies.len() as u64,
            "registry_commitment_count": self.registry_commitments.len() as u64,
            "hook_count": self.hooks.len() as u64,
            "lp_binding_count": self.lp_bindings.len() as u64,
            "upgrade_policy_count": self.upgrade_policies.len() as u64,
            "mint_sponsor_count": self.mint_sponsors.len() as u64,
            "audit_event_count": self.audit_events.len() as u64,
            "roots": roots.public_record(),
            "low_fee_mint_class_ids": self.low_fee_mint_class_ids(),
            "wrapped_monero_class_id": self.wrapped_monero_class_id(),
        })
    }

    pub fn validate(&self) -> TokenFactoryResult<String> {
        self.config.validate()?;
        for issuer in self.issuers.values() {
            issuer.validate()?;
        }
        for policy in self.transfer_policies.values() {
            policy.validate()?;
            if !self.classes.contains_key(&policy.class_id) {
                return Err("token factory transfer policy references unknown class".to_string());
            }
        }
        for commitment in self.registry_commitments.values() {
            commitment.validate()?;
            if !self.classes.contains_key(&commitment.class_id) {
                return Err(
                    "token factory registry commitment references unknown class".to_string()
                );
            }
        }
        for hook in self.hooks.values() {
            hook.validate()?;
            if !self.classes.contains_key(&hook.class_id) {
                return Err("token factory hook references unknown class".to_string());
            }
        }
        for binding in self.lp_bindings.values() {
            binding.validate()?;
            if !self.classes.contains_key(&binding.share_class_id) {
                return Err("token factory LP binding references unknown share class".to_string());
            }
            if !self.classes.contains_key(&binding.base_asset_id) {
                return Err("token factory LP binding references unknown base asset".to_string());
            }
            if !self.classes.contains_key(&binding.quote_asset_id) {
                return Err("token factory LP binding references unknown quote asset".to_string());
            }
        }
        for policy in self.upgrade_policies.values() {
            policy.validate()?;
            if !self.classes.contains_key(&policy.class_id) {
                return Err("token factory upgrade policy references unknown class".to_string());
            }
        }
        for sponsor in self.mint_sponsors.values() {
            sponsor.validate()?;
            if !self.classes.contains_key(&sponsor.class_id) {
                return Err("token factory mint sponsor references unknown class".to_string());
            }
        }
        for event in self.audit_events.values() {
            event.validate()?;
        }
        for class in self.classes.values() {
            class.validate()?;
            let issuer = self
                .issuers
                .get(&class.issuer_id)
                .ok_or_else(|| "token factory class references unknown issuer".to_string())?;
            if issuer.issuer_root() != class.issuer_root {
                return Err("token factory class issuer root is stale".to_string());
            }
            let transfer_policy = self
                .transfer_policies
                .get(&class.transfer_policy_id)
                .ok_or_else(|| {
                    "token factory class references unknown transfer policy".to_string()
                })?;
            if transfer_policy.policy_root() != class.transfer_policy_root {
                return Err("token factory class transfer policy root is stale".to_string());
            }
            let registry = self
                .registry_commitments
                .get(&class.registry_commitment.registry_id)
                .ok_or_else(|| "token factory class registry commitment is missing".to_string())?;
            if registry.commitment_root() != class.registry_commitment.commitment_root() {
                return Err("token factory class registry commitment root is stale".to_string());
            }
            let upgrade_policy = self
                .upgrade_policies
                .get(&class.upgrade_policy_id)
                .ok_or_else(|| "token factory class upgrade policy is missing".to_string())?;
            if upgrade_policy.policy_root() != class.upgrade_policy_root {
                return Err("token factory class upgrade policy root is stale".to_string());
            }
            if !class.lp_binding_id.is_empty() {
                let binding = self
                    .lp_bindings
                    .get(&class.lp_binding_id)
                    .ok_or_else(|| "token factory class LP binding is missing".to_string())?;
                if binding.binding_root() != class.lp_binding_root {
                    return Err("token factory class LP binding root is stale".to_string());
                }
            }
            if !class.sponsorship_id.is_empty() {
                let sponsor = self
                    .mint_sponsors
                    .get(&class.sponsorship_id)
                    .ok_or_else(|| "token factory class sponsor is missing".to_string())?;
                if sponsor.sponsorship_root() != class.sponsorship_root {
                    return Err("token factory class sponsor root is stale".to_string());
                }
            }
        }
        Ok(self.state_root())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn token_factory_class_id(
    symbol: &str,
    decimals: u8,
    asset_kind: &str,
    supply_mode: &str,
    issuer_root: &str,
    metadata_root: &str,
    created_at_height: u64,
    governance_proposal_id: &str,
) -> String {
    let normalized_symbol = normalize_symbol(symbol);
    domain_hash(
        "TOKEN-FACTORY-CLASS-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&normalized_symbol),
            HashPart::Int(decimals as i128),
            HashPart::Str(asset_kind),
            HashPart::Str(supply_mode),
            HashPart::Str(issuer_root),
            HashPart::Str(metadata_root),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(governance_proposal_id),
        ],
        32,
    )
}

pub fn token_factory_issue_request_id(
    symbol: &str,
    decimals: u8,
    asset_kind: &str,
    supply_mode: &str,
    issuer_id: &str,
    governance_proposal_id: &str,
    created_at_height: u64,
) -> String {
    let normalized_symbol = normalize_symbol(symbol);
    domain_hash(
        "TOKEN-FACTORY-ISSUE-REQUEST-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&normalized_symbol),
            HashPart::Int(decimals as i128),
            HashPart::Str(asset_kind),
            HashPart::Str(supply_mode),
            HashPart::Str(issuer_id),
            HashPart::Str(governance_proposal_id),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_issuer_id(
    issuer_label: &str,
    pq_scheme: &str,
    pq_public_key_root: &str,
    pq_multisig_root: &str,
    governance_controller_root: &str,
    activated_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-ISSUER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(issuer_label),
            HashPart::Str(pq_scheme),
            HashPart::Str(pq_public_key_root),
            HashPart::Str(pq_multisig_root),
            HashPart::Str(governance_controller_root),
            HashPart::Int(activated_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_transfer_policy_id(
    class_id: &str,
    policy_label: &str,
    version: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-TRANSFER-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(policy_label),
            HashPart::Int(version as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_registry_id(class_id: &str, registry_leaf: &str, height: u64) -> String {
    domain_hash(
        "TOKEN-FACTORY-REGISTRY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(registry_leaf),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn token_factory_registry_leaf(
    class_id: &str,
    metadata_commitment_root: &str,
    issuer_commitment: &str,
    issuance_commitment: &str,
    transfer_policy_commitment: &str,
    privacy_salt_commitment: &str,
    disclosed_fields_root: &str,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-REGISTRY-LEAF",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(metadata_commitment_root),
            HashPart::Str(issuer_commitment),
            HashPart::Str(issuance_commitment),
            HashPart::Str(transfer_policy_commitment),
            HashPart::Str(privacy_salt_commitment),
            HashPart::Str(disclosed_fields_root),
        ],
        32,
    )
}

pub fn token_factory_hook_id(
    class_id: &str,
    contract_id: &str,
    entrypoint: &str,
    contract_root: &str,
    version: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(contract_id),
            HashPart::Str(entrypoint),
            HashPart::Str(contract_root),
            HashPart::Int(version as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_lp_binding_id(
    share_class_id: &str,
    pool_id: &str,
    base_asset_id: &str,
    quote_asset_id: &str,
    invariant_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-LP-BINDING-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(share_class_id),
            HashPart::Str(pool_id),
            HashPart::Str(base_asset_id),
            HashPart::Str(quote_asset_id),
            HashPart::Str(invariant_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_upgrade_policy_id(
    class_id: &str,
    governance_scope: &str,
    governance_controller_root: &str,
    version: u64,
    created_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-UPGRADE-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(governance_scope),
            HashPart::Str(governance_controller_root),
            HashPart::Int(version as i128),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn token_factory_mint_sponsorship_id(
    class_id: &str,
    sponsor_commitment: &str,
    fee_asset_id: &str,
    lane_id: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-MINT-SPONSORSHIP-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(class_id),
            HashPart::Str(sponsor_commitment),
            HashPart::Str(fee_asset_id),
            HashPart::Str(lane_id),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn token_factory_audit_event_id(
    event_kind: &str,
    class_id: &str,
    actor_commitment: &str,
    subject_id: &str,
    amount_units: u64,
    root_before: &str,
    root_after: &str,
    height: u64,
    index: u64,
) -> String {
    domain_hash(
        "TOKEN-FACTORY-AUDIT-EVENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind),
            HashPart::Str(class_id),
            HashPart::Str(actor_commitment),
            HashPart::Str(subject_id),
            HashPart::Int(amount_units as i128),
            HashPart::Str(root_before),
            HashPart::Str(root_after),
            HashPart::Int(height as i128),
            HashPart::Int(index as i128),
        ],
        32,
    )
}

pub fn token_factory_field_commitment(label: &str, value: &str, blinding: &str) -> String {
    domain_hash(
        "TOKEN-FACTORY-FIELD-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(value),
            HashPart::Str(blinding),
        ],
        32,
    )
}

pub fn token_factory_state_root_from_record(record: &Value) -> String {
    token_factory_payload_root("TOKEN-FACTORY-STATE", record)
}

pub fn token_factory_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn token_factory_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn token_factory_string_set_root(domain: &str, values: &[String]) -> String {
    let records = normalized_strings(values)
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &records)
}

pub fn token_factory_empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

pub fn token_factory_issuer_set_root(values: &[TokenFactoryIssuerAuthorization]) -> String {
    let records = values
        .iter()
        .map(|item| (item.issuer_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-ISSUER-SET", records)
}

pub fn token_factory_class_set_root(values: &[TokenFactoryClassRecord]) -> String {
    let records = values
        .iter()
        .map(|item| (item.class_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-CLASS-SET", records)
}

pub fn token_factory_transfer_policy_set_root(values: &[TokenFactoryTransferPolicy]) -> String {
    let records = values
        .iter()
        .map(|item| (item.policy_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-TRANSFER-POLICY-SET", records)
}

pub fn token_factory_registry_set_root(values: &[TokenFactoryRegistryCommitment]) -> String {
    let records = values
        .iter()
        .map(|item| (item.registry_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-REGISTRY-SET", records)
}

pub fn token_factory_hook_set_root(values: &[TokenFactoryContractHook]) -> String {
    let records = values
        .iter()
        .map(|item| (item.hook_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-HOOK-SET", records)
}

pub fn token_factory_lp_binding_set_root(values: &[TokenFactoryLpBinding]) -> String {
    let records = values
        .iter()
        .map(|item| (item.binding_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-LP-BINDING-SET", records)
}

pub fn token_factory_upgrade_policy_set_root(values: &[TokenFactoryUpgradePolicy]) -> String {
    let records = values
        .iter()
        .map(|item| (item.upgrade_policy_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-UPGRADE-POLICY-SET", records)
}

pub fn token_factory_mint_sponsor_set_root(values: &[TokenFactoryMintSponsor]) -> String {
    let records = values
        .iter()
        .map(|item| (item.sponsorship_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-MINT-SPONSOR-SET", records)
}

pub fn token_factory_audit_event_set_root(values: &[TokenFactoryAuditEvent]) -> String {
    let records = values
        .iter()
        .map(|item| (item.event_id.clone(), item.public_record()))
        .collect::<Vec<_>>();
    token_factory_sorted_record_root("TOKEN-FACTORY-AUDIT-EVENT-SET", records)
}

fn token_factory_sorted_record_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    merkle_root(
        domain,
        &records
            .into_iter()
            .map(|(_, record)| record)
            .collect::<Vec<_>>(),
    )
}

fn cap_remaining(cap: u64, used: u64) -> u64 {
    if cap == 0 {
        u64::MAX
    } else {
        cap.saturating_sub(used)
    }
}

fn normalize_symbol(symbol: &str) -> String {
    symbol.trim().to_ascii_uppercase()
}

fn normalized_strings(values: &[String]) -> Vec<String> {
    let set = values
        .iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    set.into_iter().collect()
}

fn validate_symbol(symbol: &str) -> TokenFactoryResult<()> {
    if symbol.trim().is_empty() {
        return Err("token factory symbol cannot be empty".to_string());
    }
    if symbol.len() > TOKEN_FACTORY_MAX_SYMBOL_LEN {
        return Err("token factory symbol is too long".to_string());
    }
    if symbol != normalize_symbol(symbol) {
        return Err("token factory symbol must be normalized uppercase ASCII".to_string());
    }
    if !symbol
        .chars()
        .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == '-')
    {
        return Err("token factory symbol contains unsupported characters".to_string());
    }
    Ok(())
}

fn validate_root_like(value: &str, label: &str) -> TokenFactoryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_not_empty(value: &str, label: &str) -> TokenFactoryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn validate_bps(value: u64, label: &str) -> TokenFactoryResult<()> {
    if value > TOKEN_FACTORY_MAX_BPS {
        Err(format!("{label} exceeds 100 percent"))
    } else {
        Ok(())
    }
}

fn validate_status(value: &str, allowed: &[&str], label: &str) -> TokenFactoryResult<()> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{label} is unsupported"))
    }
}
