use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateTokenContractAbiRegistryResult<T> = Result<T, String>;

pub const PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_PROTOCOL_VERSION: &str =
    "nebula-private-token-contract-abi-registry-v1";
pub const PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_SCHEMA_VERSION: u64 = 1;
pub const PRIVATE_TOKEN_INTERFACE_COMMITMENT_SCHEME: &str =
    "shake256-private-token-interface-canonical-abi-v1";
pub const PRIVATE_CONTRACT_SELECTOR_SCHEME: &str = "shake256-private-contract-selector-v1";
pub const PRIVATE_CONTRACT_ABI_COMMITMENT_SCHEME: &str =
    "shake256-private-contract-abi-canonical-json-v1";
pub const PRIVATE_COMPLIANCE_CIRCUIT_ROOT_SCHEME: &str =
    "zk-private-token-compliance-circuit-root-v1";
pub const PRIVATE_PQ_UPGRADE_AUTHORITY_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-256f-pq-upgrade-authority-root-v1";
pub const PRIVATE_FEE_SPONSOR_CAPABILITY_SCHEME: &str = "shielded-fee-sponsor-capability-root-v1";
pub const PRIVATE_DEFI_HOOK_COMMITMENT_SCHEME: &str = "private-defi-hook-selector-root-v1";
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_LOW_FEE_LANE: &str = "private-contract-calls";
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_FEE_ASSET: &str = "pXMR";
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_UPGRADE_TIMELOCK_BLOCKS: u64 = 144;
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_UPGRADE_EXPIRY_BLOCKS: u64 = 7_200;
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_SPONSOR_EPOCH_BLOCKS: u64 = 2_880;
pub const PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_SELECTOR_NAMESPACE: &str = "nebula.private";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    ConfidentialFungibleToken,
    ConfidentialNonFungibleToken,
    ConfidentialVaultShare,
    WrappedMonero,
    StableAsset,
    GovernanceToken,
    LiquidityShare,
    DerivativeReceipt,
    Custom,
}

impl InterfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfidentialFungibleToken => "confidential_fungible_token",
            Self::ConfidentialNonFungibleToken => "confidential_non_fungible_token",
            Self::ConfidentialVaultShare => "confidential_vault_share",
            Self::WrappedMonero => "wrapped_monero",
            Self::StableAsset => "stable_asset",
            Self::GovernanceToken => "governance_token",
            Self::LiquidityShare => "liquidity_share",
            Self::DerivativeReceipt => "derivative_receipt",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractAbiKind {
    Token,
    Amm,
    Lending,
    Vault,
    Perps,
    Options,
    Oracle,
    Paymaster,
    BridgeAdapter,
    Governance,
    Custom,
}

impl ContractAbiKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Amm => "amm",
            Self::Lending => "lending",
            Self::Vault => "vault",
            Self::Perps => "perps",
            Self::Options => "options",
            Self::Oracle => "oracle",
            Self::Paymaster => "paymaster",
            Self::BridgeAdapter => "bridge_adapter",
            Self::Governance => "governance",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryStatus {
    Draft,
    Active,
    Suspended,
    Deprecated,
    Revoked,
}

impl RegistryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deprecated => "deprecated",
            Self::Revoked => "revoked",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(self, Self::Active)
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectorVisibility {
    Public,
    Shielded,
    NullifierGated,
    ComplianceGated,
    GovernanceOnly,
}

impl SelectorVisibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Shielded => "shielded",
            Self::NullifierGated => "nullifier_gated",
            Self::ComplianceGated => "compliance_gated",
            Self::GovernanceOnly => "governance_only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCircuitKind {
    TransferPolicy,
    MintPolicy,
    BurnPolicy,
    FreezePolicy,
    SelectiveDisclosure,
    SanctionsNullifier,
    JurisdictionRoot,
    ReserveProof,
    DefiRisk,
    Custom,
}

impl ComplianceCircuitKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TransferPolicy => "transfer_policy",
            Self::MintPolicy => "mint_policy",
            Self::BurnPolicy => "burn_policy",
            Self::FreezePolicy => "freeze_policy",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::SanctionsNullifier => "sanctions_nullifier",
            Self::JurisdictionRoot => "jurisdiction_root",
            Self::ReserveProof => "reserve_proof",
            Self::DefiRisk => "defi_risk",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiHookKind {
    BeforeTransfer,
    AfterTransfer,
    BeforeSwap,
    AfterSwap,
    BeforeDeposit,
    AfterWithdraw,
    LiquidationCheck,
    OracleRefresh,
    Rebalance,
    Custom,
}

impl DefiHookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeTransfer => "before_transfer",
            Self::AfterTransfer => "after_transfer",
            Self::BeforeSwap => "before_swap",
            Self::AfterSwap => "after_swap",
            Self::BeforeDeposit => "before_deposit",
            Self::AfterWithdraw => "after_withdraw",
            Self::LiquidationCheck => "liquidation_check",
            Self::OracleRefresh => "oracle_refresh",
            Self::Rebalance => "rebalance",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSponsorCapabilityKind {
    ContractCallGas,
    ProofGeneration,
    BatchInclusion,
    BridgeExit,
    SwapRouting,
    VaultRebalance,
    LiquidationProtection,
    Custom,
}

impl FeeSponsorCapabilityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContractCallGas => "contract_call_gas",
            Self::ProofGeneration => "proof_generation",
            Self::BatchInclusion => "batch_inclusion",
            Self::BridgeExit => "bridge_exit",
            Self::SwapRouting => "swap_routing",
            Self::VaultRebalance => "vault_rebalance",
            Self::LiquidationProtection => "liquidation_protection",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeAuthorizationStatus {
    Proposed,
    Timelocked,
    Authorized,
    Executed,
    Rejected,
    Expired,
}

impl UpgradeAuthorizationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Timelocked => "timelocked",
            Self::Authorized => "authorized",
            Self::Executed => "executed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub selector_namespace: String,
    pub default_low_fee_lane: String,
    pub default_fee_asset: String,
    pub default_upgrade_timelock_blocks: u64,
    pub default_upgrade_expiry_blocks: u64,
    pub sponsor_epoch_blocks: u64,
    pub require_pq_upgrade_authority: bool,
    pub require_compliance_circuit_root: bool,
    pub allow_experimental_defi_hooks: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_PROTOCOL_VERSION.to_string(),
            schema_version: PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_SCHEMA_VERSION,
            selector_namespace: PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_SELECTOR_NAMESPACE.to_string(),
            default_low_fee_lane: PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_LOW_FEE_LANE.to_string(),
            default_fee_asset: PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_FEE_ASSET.to_string(),
            default_upgrade_timelock_blocks:
                PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_UPGRADE_TIMELOCK_BLOCKS,
            default_upgrade_expiry_blocks: PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_UPGRADE_EXPIRY_BLOCKS,
            sponsor_epoch_blocks: PRIVATE_TOKEN_CONTRACT_ABI_DEFAULT_SPONSOR_EPOCH_BLOCKS,
            require_pq_upgrade_authority: true,
            require_compliance_circuit_root: true,
            allow_experimental_defi_hooks: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "selector_namespace": self.selector_namespace,
            "default_low_fee_lane": self.default_low_fee_lane,
            "default_fee_asset": self.default_fee_asset,
            "default_upgrade_timelock_blocks": self.default_upgrade_timelock_blocks,
            "default_upgrade_expiry_blocks": self.default_upgrade_expiry_blocks,
            "sponsor_epoch_blocks": self.sponsor_epoch_blocks,
            "require_pq_upgrade_authority": self.require_pq_upgrade_authority,
            "require_compliance_circuit_root": self.require_compliance_circuit_root,
            "allow_experimental_defi_hooks": self.allow_experimental_defi_hooks,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub token_interfaces_registered: u64,
    pub contract_abis_registered: u64,
    pub selectors_registered: u64,
    pub compliance_circuits_registered: u64,
    pub pq_upgrade_authorities_registered: u64,
    pub fee_sponsor_capabilities_registered: u64,
    pub defi_hooks_registered: u64,
    pub upgrades_authorized: u64,
    pub rejected_operations: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "token_interfaces_registered": self.token_interfaces_registered,
            "contract_abis_registered": self.contract_abis_registered,
            "selectors_registered": self.selectors_registered,
            "compliance_circuits_registered": self.compliance_circuits_registered,
            "pq_upgrade_authorities_registered": self.pq_upgrade_authorities_registered,
            "fee_sponsor_capabilities_registered": self.fee_sponsor_capabilities_registered,
            "defi_hooks_registered": self.defi_hooks_registered,
            "upgrades_authorized": self.upgrades_authorized,
            "rejected_operations": self.rejected_operations,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenInterfaceSpec {
    pub label: String,
    pub kind: InterfaceKind,
    pub version: String,
    pub method_commitment_root: String,
    pub event_commitment_root: String,
    pub metadata_commitment_root: String,
    pub compliance_circuit_ids: BTreeSet<String>,
    pub fee_sponsor_capability_ids: BTreeSet<String>,
    pub defi_hook_ids: BTreeSet<String>,
    pub pq_upgrade_authority_id: String,
    pub status: RegistryStatus,
}

impl TokenInterfaceSpec {
    pub fn public_record(&self) -> Value {
        json!({
            "interface_id": token_interface_id(self),
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_PROTOCOL_VERSION,
            "label": self.label,
            "kind": self.kind.as_str(),
            "version": self.version,
            "method_commitment_root": self.method_commitment_root,
            "event_commitment_root": self.event_commitment_root,
            "metadata_commitment_root": self.metadata_commitment_root,
            "compliance_circuit_ids": self.compliance_circuit_ids,
            "fee_sponsor_capability_ids": self.fee_sponsor_capability_ids,
            "defi_hook_ids": self.defi_hook_ids,
            "pq_upgrade_authority_id": self.pq_upgrade_authority_id,
            "status": self.status.as_str(),
            "commitment_scheme": PRIVATE_TOKEN_INTERFACE_COMMITMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSelector {
    pub name: String,
    pub selector: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub visibility: SelectorVisibility,
    pub required_circuit_ids: BTreeSet<String>,
    pub fee_sponsor_capability_ids: BTreeSet<String>,
}

impl ContractSelector {
    pub fn public_record(&self) -> Value {
        json!({
            "selector_id": selector_id(self),
            "chain_id": CHAIN_ID,
            "name": self.name,
            "selector": self.selector,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "visibility": self.visibility.as_str(),
            "required_circuit_ids": self.required_circuit_ids,
            "fee_sponsor_capability_ids": self.fee_sponsor_capability_ids,
            "selector_scheme": PRIVATE_CONTRACT_SELECTOR_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCircuit {
    pub label: String,
    pub kind: ComplianceCircuitKind,
    pub verifier_key_root: String,
    pub policy_commitment_root: String,
    pub audit_committee_root: String,
    pub min_proof_security_bits: u16,
    pub status: RegistryStatus,
}

impl ComplianceCircuit {
    pub fn public_record(&self) -> Value {
        json!({
            "circuit_id": compliance_circuit_id(self),
            "chain_id": CHAIN_ID,
            "label": self.label,
            "kind": self.kind.as_str(),
            "verifier_key_root": self.verifier_key_root,
            "policy_commitment_root": self.policy_commitment_root,
            "audit_committee_root": self.audit_committee_root,
            "min_proof_security_bits": self.min_proof_security_bits,
            "status": self.status.as_str(),
            "circuit_root_scheme": PRIVATE_COMPLIANCE_CIRCUIT_ROOT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqUpgradeAuthority {
    pub label: String,
    pub authority_root: String,
    pub veto_root: String,
    pub rotation_policy_root: String,
    pub threshold: u16,
    pub timelock_blocks: u64,
    pub status: RegistryStatus,
}

impl PqUpgradeAuthority {
    pub fn public_record(&self) -> Value {
        json!({
            "authority_id": pq_upgrade_authority_id(self),
            "chain_id": CHAIN_ID,
            "label": self.label,
            "authority_root": self.authority_root,
            "veto_root": self.veto_root,
            "rotation_policy_root": self.rotation_policy_root,
            "threshold": self.threshold,
            "timelock_blocks": self.timelock_blocks,
            "status": self.status.as_str(),
            "authority_scheme": PRIVATE_PQ_UPGRADE_AUTHORITY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSponsorCapability {
    pub label: String,
    pub kind: FeeSponsorCapabilityKind,
    pub sponsor_commitment_root: String,
    pub fee_asset: String,
    pub low_fee_lane: String,
    pub max_fee_per_call_micro: u64,
    pub epoch_limit_micro: u64,
    pub expires_at_height: u64,
    pub status: RegistryStatus,
}

impl FeeSponsorCapability {
    pub fn public_record(&self) -> Value {
        json!({
            "capability_id": fee_sponsor_capability_id(self),
            "chain_id": CHAIN_ID,
            "label": self.label,
            "kind": self.kind.as_str(),
            "sponsor_commitment_root": self.sponsor_commitment_root,
            "fee_asset": self.fee_asset,
            "low_fee_lane": self.low_fee_lane,
            "max_fee_per_call_micro": self.max_fee_per_call_micro,
            "epoch_limit_micro": self.epoch_limit_micro,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "capability_scheme": PRIVATE_FEE_SPONSOR_CAPABILITY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefiHook {
    pub label: String,
    pub kind: DefiHookKind,
    pub hook_commitment_root: String,
    pub risk_policy_root: String,
    pub supported_venue_root: String,
    pub requires_compliance_circuit: bool,
    pub status: RegistryStatus,
}

impl DefiHook {
    pub fn public_record(&self) -> Value {
        json!({
            "hook_id": defi_hook_id(self),
            "chain_id": CHAIN_ID,
            "label": self.label,
            "kind": self.kind.as_str(),
            "hook_commitment_root": self.hook_commitment_root,
            "risk_policy_root": self.risk_policy_root,
            "supported_venue_root": self.supported_venue_root,
            "requires_compliance_circuit": self.requires_compliance_circuit,
            "status": self.status.as_str(),
            "hook_scheme": PRIVATE_DEFI_HOOK_COMMITMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractAbiSpec {
    pub label: String,
    pub kind: ContractAbiKind,
    pub version: String,
    pub abi_commitment_root: String,
    pub bytecode_commitment_root: String,
    pub storage_layout_root: String,
    pub token_interface_ids: BTreeSet<String>,
    pub selectors: BTreeMap<String, ContractSelector>,
    pub compliance_circuit_ids: BTreeSet<String>,
    pub pq_upgrade_authority_id: String,
    pub fee_sponsor_capability_ids: BTreeSet<String>,
    pub defi_hook_ids: BTreeSet<String>,
    pub status: RegistryStatus,
}

impl ContractAbiSpec {
    pub fn public_record(&self) -> Value {
        let selector_records =
            sorted_values(self.selectors.values().map(ContractSelector::public_record));
        json!({
            "contract_abi_id": contract_abi_id(self),
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_PROTOCOL_VERSION,
            "label": self.label,
            "kind": self.kind.as_str(),
            "version": self.version,
            "abi_commitment_root": self.abi_commitment_root,
            "bytecode_commitment_root": self.bytecode_commitment_root,
            "storage_layout_root": self.storage_layout_root,
            "token_interface_ids": self.token_interface_ids,
            "selector_root": merkle_root("PRIVATE-CONTRACT-ABI-SELECTOR", &selector_records),
            "selector_count": self.selectors.len() as u64,
            "compliance_circuit_ids": self.compliance_circuit_ids,
            "pq_upgrade_authority_id": self.pq_upgrade_authority_id,
            "fee_sponsor_capability_ids": self.fee_sponsor_capability_ids,
            "defi_hook_ids": self.defi_hook_ids,
            "status": self.status.as_str(),
            "abi_commitment_scheme": PRIVATE_CONTRACT_ABI_COMMITMENT_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeAuthorization {
    pub authorization_id: String,
    pub target_contract_abi_id: String,
    pub current_abi_commitment_root: String,
    pub next_abi_commitment_root: String,
    pub migration_witness_root: String,
    pub compatibility_proof_root: String,
    pub authority_id: String,
    pub sponsor_capability_id: Option<String>,
    pub authorized_at_height: u64,
    pub executable_at_height: u64,
    pub expires_at_height: u64,
    pub status: UpgradeAuthorizationStatus,
}

impl UpgradeAuthorization {
    pub fn public_record(&self) -> Value {
        json!({
            "authorization_id": self.authorization_id,
            "chain_id": CHAIN_ID,
            "target_contract_abi_id": self.target_contract_abi_id,
            "current_abi_commitment_root": self.current_abi_commitment_root,
            "next_abi_commitment_root": self.next_abi_commitment_root,
            "migration_witness_root": self.migration_witness_root,
            "compatibility_proof_root": self.compatibility_proof_root,
            "authority_id": self.authority_id,
            "sponsor_capability_id": self.sponsor_capability_id,
            "authorized_at_height": self.authorized_at_height,
            "executable_at_height": self.executable_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
            "authorization_scheme": PRIVATE_PQ_UPGRADE_AUTHORITY_SCHEME,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub token_interface_root: String,
    pub contract_abi_root: String,
    pub compliance_circuit_root: String,
    pub pq_upgrade_authority_root: String,
    pub fee_sponsor_capability_root: String,
    pub defi_hook_root: String,
    pub upgrade_authorization_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "token_interface_root": self.token_interface_root,
            "contract_abi_root": self.contract_abi_root,
            "compliance_circuit_root": self.compliance_circuit_root,
            "pq_upgrade_authority_root": self.pq_upgrade_authority_root,
            "fee_sponsor_capability_root": self.fee_sponsor_capability_root,
            "defi_hook_root": self.defi_hook_root,
            "upgrade_authorization_root": self.upgrade_authorization_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub token_interfaces: BTreeMap<String, TokenInterfaceSpec>,
    pub contract_abis: BTreeMap<String, ContractAbiSpec>,
    pub compliance_circuits: BTreeMap<String, ComplianceCircuit>,
    pub pq_upgrade_authorities: BTreeMap<String, PqUpgradeAuthority>,
    pub fee_sponsor_capabilities: BTreeMap<String, FeeSponsorCapability>,
    pub defi_hooks: BTreeMap<String, DefiHook>,
    pub upgrade_authorizations: BTreeMap<String, UpgradeAuthorization>,
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            counters: Counters::default(),
            token_interfaces: BTreeMap::new(),
            contract_abis: BTreeMap::new(),
            compliance_circuits: BTreeMap::new(),
            pq_upgrade_authorities: BTreeMap::new(),
            fee_sponsor_capabilities: BTreeMap::new(),
            defi_hooks: BTreeMap::new(),
            upgrade_authorizations: BTreeMap::new(),
        };

        let compliance = ComplianceCircuit {
            label: "devnet-private-token-transfer-policy".to_string(),
            kind: ComplianceCircuitKind::TransferPolicy,
            verifier_key_root: sample_root("devnet-transfer-vk"),
            policy_commitment_root: sample_root("devnet-transfer-policy"),
            audit_committee_root: sample_root("devnet-auditor-committee"),
            min_proof_security_bits: 128,
            status: RegistryStatus::Active,
        };
        let compliance_id = state.insert_compliance_circuit(compliance);

        let authority = PqUpgradeAuthority {
            label: "devnet-pq-upgrade-council".to_string(),
            authority_root: sample_root("devnet-pq-authority"),
            veto_root: sample_root("devnet-pq-veto"),
            rotation_policy_root: sample_root("devnet-pq-rotation"),
            threshold: 2,
            timelock_blocks: state.config.default_upgrade_timelock_blocks,
            status: RegistryStatus::Active,
        };
        let authority_id = state.insert_pq_upgrade_authority(authority);

        let sponsor = FeeSponsorCapability {
            label: "devnet-private-call-sponsor".to_string(),
            kind: FeeSponsorCapabilityKind::ContractCallGas,
            sponsor_commitment_root: sample_root("devnet-call-sponsor"),
            fee_asset: state.config.default_fee_asset.clone(),
            low_fee_lane: state.config.default_low_fee_lane.clone(),
            max_fee_per_call_micro: 25_000,
            epoch_limit_micro: 5_000_000,
            expires_at_height: state.config.sponsor_epoch_blocks,
            status: RegistryStatus::Active,
        };
        let sponsor_id = state.insert_fee_sponsor_capability(sponsor);

        let hook = DefiHook {
            label: "devnet-confidential-amm-before-swap".to_string(),
            kind: DefiHookKind::BeforeSwap,
            hook_commitment_root: sample_root("devnet-before-swap-hook"),
            risk_policy_root: sample_root("devnet-amm-risk-policy"),
            supported_venue_root: sample_root("devnet-private-amm-venues"),
            requires_compliance_circuit: true,
            status: RegistryStatus::Active,
        };
        let hook_id = state.insert_defi_hook(hook);

        let mut circuit_ids = BTreeSet::new();
        circuit_ids.insert(compliance_id.clone());
        let mut sponsor_ids = BTreeSet::new();
        sponsor_ids.insert(sponsor_id.clone());
        let mut hook_ids = BTreeSet::new();
        hook_ids.insert(hook_id.clone());

        let token = TokenInterfaceSpec {
            label: "pXMR-confidential-fungible-v1".to_string(),
            kind: InterfaceKind::WrappedMonero,
            version: "1.0.0".to_string(),
            method_commitment_root: sample_root("pxmr-token-methods"),
            event_commitment_root: sample_root("pxmr-token-events"),
            metadata_commitment_root: sample_root("pxmr-token-metadata"),
            compliance_circuit_ids: circuit_ids.clone(),
            fee_sponsor_capability_ids: sponsor_ids.clone(),
            defi_hook_ids: hook_ids.clone(),
            pq_upgrade_authority_id: authority_id.clone(),
            status: RegistryStatus::Active,
        };
        let token_interface_id = state.register_token_interface(token).expect("devnet token");

        let mut selector_circuits = BTreeSet::new();
        selector_circuits.insert(compliance_id);
        let mut selector_sponsors = BTreeSet::new();
        selector_sponsors.insert(sponsor_id);
        let transfer_selector = ContractSelector {
            name: "confidential_transfer".to_string(),
            selector: derive_selector(&state.config.selector_namespace, "confidential_transfer"),
            input_commitment_root: sample_root("pxmr-transfer-inputs"),
            output_commitment_root: sample_root("pxmr-transfer-outputs"),
            visibility: SelectorVisibility::NullifierGated,
            required_circuit_ids: selector_circuits,
            fee_sponsor_capability_ids: selector_sponsors,
        };
        let mut selectors = BTreeMap::new();
        selectors.insert(transfer_selector.selector.clone(), transfer_selector);
        let mut token_ids = BTreeSet::new();
        token_ids.insert(token_interface_id);
        let contract = ContractAbiSpec {
            label: "pxmr-private-token-contract-v1".to_string(),
            kind: ContractAbiKind::Token,
            version: "1.0.0".to_string(),
            abi_commitment_root: sample_root("pxmr-contract-abi"),
            bytecode_commitment_root: sample_root("pxmr-contract-bytecode"),
            storage_layout_root: sample_root("pxmr-contract-storage-layout"),
            token_interface_ids: token_ids,
            selectors,
            compliance_circuit_ids: circuit_ids,
            pq_upgrade_authority_id: authority_id,
            fee_sponsor_capability_ids: sponsor_ids,
            defi_hook_ids: hook_ids,
            status: RegistryStatus::Active,
        };
        state
            .register_contract_abi(contract)
            .expect("devnet contract");
        state
    }

    pub fn register_token_interface(
        &mut self,
        spec: TokenInterfaceSpec,
    ) -> PrivateTokenContractAbiRegistryResult<String> {
        self.validate_token_interface(&spec)?;
        let interface_id = token_interface_id(&spec);
        if self.token_interfaces.contains_key(&interface_id) {
            self.counters.rejected_operations += 1;
            return Err(format!(
                "token interface already registered: {interface_id}"
            ));
        }
        self.token_interfaces.insert(interface_id.clone(), spec);
        self.counters.token_interfaces_registered += 1;
        Ok(interface_id)
    }

    pub fn register_contract_abi(
        &mut self,
        spec: ContractAbiSpec,
    ) -> PrivateTokenContractAbiRegistryResult<String> {
        self.validate_contract_abi(&spec)?;
        let contract_abi_id = contract_abi_id(&spec);
        if self.contract_abis.contains_key(&contract_abi_id) {
            self.counters.rejected_operations += 1;
            return Err(format!(
                "contract ABI already registered: {contract_abi_id}"
            ));
        }
        self.counters.selectors_registered += spec.selectors.len() as u64;
        self.contract_abis.insert(contract_abi_id.clone(), spec);
        self.counters.contract_abis_registered += 1;
        Ok(contract_abi_id)
    }

    pub fn authorize_upgrade(
        &mut self,
        target_contract_abi_id: &str,
        next_abi_commitment_root: String,
        migration_witness_root: String,
        compatibility_proof_root: String,
        sponsor_capability_id: Option<String>,
        authorized_at_height: u64,
    ) -> PrivateTokenContractAbiRegistryResult<String> {
        let contract = self
            .contract_abis
            .get(target_contract_abi_id)
            .ok_or_else(|| format!("unknown contract ABI: {target_contract_abi_id}"))?;
        if !contract.status.is_live() {
            self.counters.rejected_operations += 1;
            return Err(format!(
                "contract ABI is not active: {target_contract_abi_id}"
            ));
        }
        let current_abi_commitment_root = contract.abi_commitment_root.clone();
        let authority_id = contract.pq_upgrade_authority_id.clone();
        self.ensure_authority(&authority_id)?;
        if let Some(capability_id) = &sponsor_capability_id {
            self.ensure_sponsor_capability(capability_id)?;
        }
        ensure_root("next_abi_commitment_root", &next_abi_commitment_root)?;
        ensure_root("migration_witness_root", &migration_witness_root)?;
        ensure_root("compatibility_proof_root", &compatibility_proof_root)?;

        let authority = self
            .pq_upgrade_authorities
            .get(&authority_id)
            .expect("authority checked");
        let executable_at_height = authorized_at_height.saturating_add(authority.timelock_blocks);
        let expires_at_height =
            executable_at_height.saturating_add(self.config.default_upgrade_expiry_blocks);
        let authorization_id = domain_hash(
            "PRIVATE-TOKEN-CONTRACT-ABI-UPGRADE-AUTHORIZATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(target_contract_abi_id),
                HashPart::Str(&current_abi_commitment_root),
                HashPart::Str(&next_abi_commitment_root),
                HashPart::Str(&migration_witness_root),
                HashPart::Str(&compatibility_proof_root),
                HashPart::Str(&authority_id),
                HashPart::Int(authorized_at_height as i128),
            ],
            32,
        );
        if self.upgrade_authorizations.contains_key(&authorization_id) {
            self.counters.rejected_operations += 1;
            return Err(format!("upgrade already authorized: {authorization_id}"));
        }
        let authorization = UpgradeAuthorization {
            authorization_id: authorization_id.clone(),
            target_contract_abi_id: target_contract_abi_id.to_string(),
            current_abi_commitment_root,
            next_abi_commitment_root,
            migration_witness_root,
            compatibility_proof_root,
            authority_id,
            sponsor_capability_id,
            authorized_at_height,
            executable_at_height,
            expires_at_height,
            status: UpgradeAuthorizationStatus::Timelocked,
        };
        self.upgrade_authorizations
            .insert(authorization_id.clone(), authorization);
        self.counters.upgrades_authorized += 1;
        Ok(authorization_id)
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_PROTOCOL_VERSION,
            "schema_version": PRIVATE_TOKEN_CONTRACT_ABI_REGISTRY_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": roots.public_record(),
            "state_root": self.state_root_without_self_reference(&roots),
        })
    }

    pub fn state_root(&self) -> String {
        let roots = self.roots();
        self.state_root_without_self_reference(&roots)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            token_interface_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-TOKEN-INTERFACE",
                &sorted_values(
                    self.token_interfaces
                        .values()
                        .map(TokenInterfaceSpec::public_record),
                ),
            ),
            contract_abi_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-CONTRACT",
                &sorted_values(
                    self.contract_abis
                        .values()
                        .map(ContractAbiSpec::public_record),
                ),
            ),
            compliance_circuit_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-COMPLIANCE-CIRCUIT",
                &sorted_values(
                    self.compliance_circuits
                        .values()
                        .map(ComplianceCircuit::public_record),
                ),
            ),
            pq_upgrade_authority_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-PQ-AUTHORITY",
                &sorted_values(
                    self.pq_upgrade_authorities
                        .values()
                        .map(PqUpgradeAuthority::public_record),
                ),
            ),
            fee_sponsor_capability_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-FEE-SPONSOR",
                &sorted_values(
                    self.fee_sponsor_capabilities
                        .values()
                        .map(FeeSponsorCapability::public_record),
                ),
            ),
            defi_hook_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-DEFI-HOOK",
                &sorted_values(self.defi_hooks.values().map(DefiHook::public_record)),
            ),
            upgrade_authorization_root: merkle_root(
                "PRIVATE-TOKEN-CONTRACT-ABI-UPGRADE-AUTHORIZATION",
                &sorted_values(
                    self.upgrade_authorizations
                        .values()
                        .map(UpgradeAuthorization::public_record),
                ),
            ),
        }
    }

    fn insert_compliance_circuit(&mut self, circuit: ComplianceCircuit) -> String {
        let circuit_id = compliance_circuit_id(&circuit);
        self.compliance_circuits.insert(circuit_id.clone(), circuit);
        self.counters.compliance_circuits_registered += 1;
        circuit_id
    }

    fn insert_pq_upgrade_authority(&mut self, authority: PqUpgradeAuthority) -> String {
        let authority_id = pq_upgrade_authority_id(&authority);
        self.pq_upgrade_authorities
            .insert(authority_id.clone(), authority);
        self.counters.pq_upgrade_authorities_registered += 1;
        authority_id
    }

    fn insert_fee_sponsor_capability(&mut self, capability: FeeSponsorCapability) -> String {
        let capability_id = fee_sponsor_capability_id(&capability);
        self.fee_sponsor_capabilities
            .insert(capability_id.clone(), capability);
        self.counters.fee_sponsor_capabilities_registered += 1;
        capability_id
    }

    fn insert_defi_hook(&mut self, hook: DefiHook) -> String {
        let hook_id = defi_hook_id(&hook);
        self.defi_hooks.insert(hook_id.clone(), hook);
        self.counters.defi_hooks_registered += 1;
        hook_id
    }

    fn validate_token_interface(
        &mut self,
        spec: &TokenInterfaceSpec,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        ensure_label("token interface label", &spec.label)?;
        ensure_label("token interface version", &spec.version)?;
        ensure_root("method_commitment_root", &spec.method_commitment_root)?;
        ensure_root("event_commitment_root", &spec.event_commitment_root)?;
        ensure_root("metadata_commitment_root", &spec.metadata_commitment_root)?;
        self.ensure_authority(&spec.pq_upgrade_authority_id)?;
        for circuit_id in &spec.compliance_circuit_ids {
            self.ensure_compliance_circuit(circuit_id)?;
        }
        for capability_id in &spec.fee_sponsor_capability_ids {
            self.ensure_sponsor_capability(capability_id)?;
        }
        for hook_id in &spec.defi_hook_ids {
            self.ensure_defi_hook(hook_id)?;
        }
        Ok(())
    }

    fn validate_contract_abi(
        &mut self,
        spec: &ContractAbiSpec,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        ensure_label("contract ABI label", &spec.label)?;
        ensure_label("contract ABI version", &spec.version)?;
        ensure_root("abi_commitment_root", &spec.abi_commitment_root)?;
        ensure_root("bytecode_commitment_root", &spec.bytecode_commitment_root)?;
        ensure_root("storage_layout_root", &spec.storage_layout_root)?;
        self.ensure_authority(&spec.pq_upgrade_authority_id)?;
        for interface_id in &spec.token_interface_ids {
            self.ensure_token_interface(interface_id)?;
        }
        for circuit_id in &spec.compliance_circuit_ids {
            self.ensure_compliance_circuit(circuit_id)?;
        }
        for capability_id in &spec.fee_sponsor_capability_ids {
            self.ensure_sponsor_capability(capability_id)?;
        }
        for hook_id in &spec.defi_hook_ids {
            self.ensure_defi_hook(hook_id)?;
        }
        if spec.selectors.is_empty() {
            self.counters.rejected_operations += 1;
            return Err("contract ABI must expose at least one selector commitment".to_string());
        }
        for (selector_key, selector) in &spec.selectors {
            ensure_label("selector name", &selector.name)?;
            ensure_root(
                "selector input_commitment_root",
                &selector.input_commitment_root,
            )?;
            ensure_root(
                "selector output_commitment_root",
                &selector.output_commitment_root,
            )?;
            if selector.selector != *selector_key {
                self.counters.rejected_operations += 1;
                return Err(format!("selector key mismatch for {}", selector.name));
            }
            for circuit_id in &selector.required_circuit_ids {
                self.ensure_compliance_circuit(circuit_id)?;
            }
            for capability_id in &selector.fee_sponsor_capability_ids {
                self.ensure_sponsor_capability(capability_id)?;
            }
        }
        Ok(())
    }

    fn ensure_token_interface(
        &mut self,
        interface_id: &str,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        match self.token_interfaces.get(interface_id) {
            Some(spec) if spec.status.is_live() => Ok(()),
            Some(_) => {
                self.counters.rejected_operations += 1;
                Err(format!("token interface is not active: {interface_id}"))
            }
            None => {
                self.counters.rejected_operations += 1;
                Err(format!("unknown token interface: {interface_id}"))
            }
        }
    }

    fn ensure_compliance_circuit(
        &mut self,
        circuit_id: &str,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        match self.compliance_circuits.get(circuit_id) {
            Some(circuit) if circuit.status.is_live() => Ok(()),
            Some(_) => {
                self.counters.rejected_operations += 1;
                Err(format!("compliance circuit is not active: {circuit_id}"))
            }
            None => {
                self.counters.rejected_operations += 1;
                Err(format!("unknown compliance circuit: {circuit_id}"))
            }
        }
    }

    fn ensure_authority(
        &mut self,
        authority_id: &str,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        match self.pq_upgrade_authorities.get(authority_id) {
            Some(authority) if authority.status.is_live() => Ok(()),
            Some(_) => {
                self.counters.rejected_operations += 1;
                Err(format!(
                    "PQ upgrade authority is not active: {authority_id}"
                ))
            }
            None => {
                self.counters.rejected_operations += 1;
                Err(format!("unknown PQ upgrade authority: {authority_id}"))
            }
        }
    }

    fn ensure_sponsor_capability(
        &mut self,
        capability_id: &str,
    ) -> PrivateTokenContractAbiRegistryResult<()> {
        match self.fee_sponsor_capabilities.get(capability_id) {
            Some(capability) if capability.status.is_live() => Ok(()),
            Some(_) => {
                self.counters.rejected_operations += 1;
                Err(format!(
                    "fee sponsor capability is not active: {capability_id}"
                ))
            }
            None => {
                self.counters.rejected_operations += 1;
                Err(format!("unknown fee sponsor capability: {capability_id}"))
            }
        }
    }

    fn ensure_defi_hook(&mut self, hook_id: &str) -> PrivateTokenContractAbiRegistryResult<()> {
        match self.defi_hooks.get(hook_id) {
            Some(hook) if hook.status.is_live() => Ok(()),
            Some(_) => {
                self.counters.rejected_operations += 1;
                Err(format!("DeFi hook is not active: {hook_id}"))
            }
            None => {
                self.counters.rejected_operations += 1;
                Err(format!("unknown DeFi hook: {hook_id}"))
            }
        }
    }

    fn state_root_without_self_reference(&self, roots: &Roots) -> String {
        domain_hash(
            "PRIVATE-TOKEN-CONTRACT-ABI-REGISTRY-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&roots.public_record()),
            ],
            32,
        )
    }
}

pub fn derive_selector(namespace: &str, method_name: &str) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-SELECTOR-DERIVE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(namespace),
            HashPart::Str(method_name),
        ],
        4,
    )
}

pub fn token_interface_id(spec: &TokenInterfaceSpec) -> String {
    domain_hash(
        "PRIVATE-TOKEN-INTERFACE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(spec.kind.as_str()),
            HashPart::Str(&spec.label),
            HashPart::Str(&spec.version),
            HashPart::Str(&spec.method_commitment_root),
            HashPart::Str(&spec.event_commitment_root),
            HashPart::Str(&spec.metadata_commitment_root),
        ],
        32,
    )
}

pub fn contract_abi_id(spec: &ContractAbiSpec) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-ABI-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(spec.kind.as_str()),
            HashPart::Str(&spec.label),
            HashPart::Str(&spec.version),
            HashPart::Str(&spec.abi_commitment_root),
            HashPart::Str(&spec.bytecode_commitment_root),
            HashPart::Str(&spec.storage_layout_root),
        ],
        32,
    )
}

pub fn selector_id(selector: &ContractSelector) -> String {
    domain_hash(
        "PRIVATE-CONTRACT-SELECTOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&selector.name),
            HashPart::Str(&selector.selector),
            HashPart::Str(&selector.input_commitment_root),
            HashPart::Str(&selector.output_commitment_root),
            HashPart::Str(selector.visibility.as_str()),
        ],
        32,
    )
}

pub fn compliance_circuit_id(circuit: &ComplianceCircuit) -> String {
    domain_hash(
        "PRIVATE-COMPLIANCE-CIRCUIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(circuit.kind.as_str()),
            HashPart::Str(&circuit.label),
            HashPart::Str(&circuit.verifier_key_root),
            HashPart::Str(&circuit.policy_commitment_root),
            HashPart::Str(&circuit.audit_committee_root),
        ],
        32,
    )
}

pub fn pq_upgrade_authority_id(authority: &PqUpgradeAuthority) -> String {
    domain_hash(
        "PRIVATE-PQ-UPGRADE-AUTHORITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&authority.label),
            HashPart::Str(&authority.authority_root),
            HashPart::Str(&authority.veto_root),
            HashPart::Str(&authority.rotation_policy_root),
            HashPart::Int(authority.threshold as i128),
            HashPart::Int(authority.timelock_blocks as i128),
        ],
        32,
    )
}

pub fn fee_sponsor_capability_id(capability: &FeeSponsorCapability) -> String {
    domain_hash(
        "PRIVATE-FEE-SPONSOR-CAPABILITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(capability.kind.as_str()),
            HashPart::Str(&capability.label),
            HashPart::Str(&capability.sponsor_commitment_root),
            HashPart::Str(&capability.fee_asset),
            HashPart::Str(&capability.low_fee_lane),
            HashPart::Int(capability.expires_at_height as i128),
        ],
        32,
    )
}

pub fn defi_hook_id(hook: &DefiHook) -> String {
    domain_hash(
        "PRIVATE-DEFI-HOOK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(hook.kind.as_str()),
            HashPart::Str(&hook.label),
            HashPart::Str(&hook.hook_commitment_root),
            HashPart::Str(&hook.risk_policy_root),
            HashPart::Str(&hook.supported_venue_root),
        ],
        32,
    )
}

fn ensure_label(field: &str, value: &str) -> PrivateTokenContractAbiRegistryResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{field} is too long"));
    }
    Ok(())
}

fn ensure_root(field: &str, value: &str) -> PrivateTokenContractAbiRegistryResult<()> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a 32-byte hex commitment root"));
    }
    Ok(())
}

fn sample_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-TOKEN-CONTRACT-ABI-DEVNET-SAMPLE-ROOT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn sorted_values<I>(records: I) -> Vec<Value>
where
    I: IntoIterator<Item = Value>,
{
    let mut records = records.into_iter().collect::<Vec<_>>();
    records.sort_by_key(|record| record.to_string());
    records
}
