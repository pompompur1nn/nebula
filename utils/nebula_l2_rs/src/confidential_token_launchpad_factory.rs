use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub type ConfidentialTokenLaunchpadFactoryResult<T> = Result<T, String>;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_PROTOCOL_VERSION: &str =
    "nebula-confidential-token-launchpad-factory-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_SCHEMA_VERSION: &str =
    "nebula-confidential-token-launchpad-factory-state-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEVNET_HEIGHT: u64 = 256;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PQ_AUTH_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-launchpad-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PQ_KEM_SUITE: &str = "ML-KEM-1024";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_COMMITMENT_SCHEME: &str =
    "shake256-domain-separated-shielded-allocation-commitment-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_NULLIFIER_SCHEME: &str =
    "shake256-sale-round-nullifier-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_VESTING_SCHEME: &str =
    "confidential-linear-cliff-vesting-commitment-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_RECEIPT_SCHEME: &str =
    "private-contract-init-receipt-v1";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_LOW_FEE_LANE: &str =
    "confidential-token-launchpad";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_FEE_ASSET_ID: &str = "piconero";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_ASSET_ID: &str = "wxmr-devnet";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_TREASURY_ID: &str =
    "nebula-devnet-launchpad-treasury";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_AUDITOR_SET_ID: &str =
    "nebula-devnet-launchpad-auditors";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_DEPLOYER_SET_ID: &str =
    "nebula-devnet-contract-deployer-set";
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PRIVACY_SET_SIZE: u64 = 512;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_ANONYMITY_SET: u64 = 256;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_ROUND_TTL_BLOCKS: u64 = 720;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_RECEIPT_TTL_BLOCKS: u64 = 96;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_CREDENTIAL_TTL_BLOCKS: u64 = 7_200;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_WINDOW_BLOCKS: u64 = 1_440;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_ROUNDS_PER_LAUNCH: usize = 12;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_HOOKS: usize = 16;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_DEPLOYMENT_GAS_UNITS: u64 = 12_500_000;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_ALLOCATION_UNITS: u64 =
    1_000_000_000_000_000;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_ALLOCATION_UNITS: u64 = 1;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_FEE_UNITS: u64 = 25;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_BUDGET_UNITS: u64 = 250_000;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_SYBIL_SCORE_BPS: u64 = 2_500;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_CREDENTIAL_WEIGHT: u64 = 1;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_BPS: u64 = 10_000;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_FACTORIES: usize = 65_536;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_LAUNCHES: usize = 262_144;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_ROUNDS: usize = 1_048_576;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_ALLOCATIONS: usize = 4_194_304;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_CREDENTIALS: usize = 1_048_576;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_VESTING_COMMITMENTS: usize = 1_048_576;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_SUBSIDIES: usize = 524_288;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_RECEIPTS: usize = 524_288;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_NULLIFIERS: usize = 4_194_304;
pub const CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_EVENTS: usize = 1_048_576;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchpadFactoryStatus {
    Draft,
    Active,
    RateLimited,
    Paused,
    Frozen,
    Retired,
}
impl LaunchpadFactoryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Paused => "paused",
            Self::Frozen => "frozen",
            Self::Retired => "retired",
        }
    }
    pub fn accepts_launches(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenLaunchStatus {
    Draft,
    Scheduled,
    CredentialGateOpen,
    Live,
    Sealed,
    Initialized,
    Settled,
    Cancelled,
    Failed,
}
impl TokenLaunchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::CredentialGateOpen => "credential_gate_open",
            Self::Live => "live",
            Self::Sealed => "sealed",
            Self::Initialized => "initialized",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
    pub fn accepts_rounds(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Scheduled | Self::CredentialGateOpen
        )
    }
    pub fn accepts_allocations(self) -> bool {
        matches!(self, Self::CredentialGateOpen | Self::Live)
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Failed)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaleRoundKind {
    Founder,
    Strategic,
    PrivateSale,
    Community,
    LiquidityBootstrap,
    DeveloperGrant,
    Airdrop,
    ContractBound,
}
impl SaleRoundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Founder => "founder",
            Self::Strategic => "strategic",
            Self::PrivateSale => "private_sale",
            Self::Community => "community",
            Self::LiquidityBootstrap => "liquidity_bootstrap",
            Self::DeveloperGrant => "developer_grant",
            Self::Airdrop => "airdrop",
            Self::ContractBound => "contract_bound",
        }
    }
    pub fn requires_credential(self) -> bool {
        matches!(
            self,
            Self::PrivateSale | Self::Community | Self::Airdrop | Self::ContractBound
        )
    }
    pub fn permits_subsidy(self) -> bool {
        matches!(
            self,
            Self::Community
                | Self::LiquidityBootstrap
                | Self::DeveloperGrant
                | Self::Airdrop
                | Self::ContractBound
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaleRoundStatus {
    Planned,
    CredentialGated,
    Open,
    Sealed,
    Settled,
    Cancelled,
    Expired,
}
impl SaleRoundStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::CredentialGated => "credential_gated",
            Self::Open => "open",
            Self::Sealed => "sealed",
            Self::Settled => "settled",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
    pub fn accepts_allocations(self) -> bool {
        matches!(self, Self::CredentialGated | Self::Open)
    }
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Cancelled | Self::Expired)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    HumanUniqueness,
    AccreditedInvestor,
    JurisdictionEligibility,
    SanctionsClear,
    DeveloperReputation,
    CommunityReputation,
    LiquidityProvider,
    GovernanceDelegate,
    ContractDeveloper,
    CustomPredicate,
}
impl CredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HumanUniqueness => "human_uniqueness",
            Self::AccreditedInvestor => "accredited_investor",
            Self::JurisdictionEligibility => "jurisdiction_eligibility",
            Self::SanctionsClear => "sanctions_clear",
            Self::DeveloperReputation => "developer_reputation",
            Self::CommunityReputation => "community_reputation",
            Self::LiquidityProvider => "liquidity_provider",
            Self::GovernanceDelegate => "governance_delegate",
            Self::ContractDeveloper => "contract_developer",
            Self::CustomPredicate => "custom_predicate",
        }
    }
    pub fn default_weight(self) -> u64 {
        match self {
            Self::AccreditedInvestor | Self::SanctionsClear => 4,
            Self::HumanUniqueness
            | Self::JurisdictionEligibility
            | Self::DeveloperReputation
            | Self::ContractDeveloper => 3,
            Self::CommunityReputation | Self::LiquidityProvider | Self::GovernanceDelegate => 2,
            Self::CustomPredicate => 1,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Committed,
    Attested,
    Active,
    RateLimited,
    Revoked,
    Expired,
}
impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Attested => "attested",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
    pub fn usable(self) -> bool {
        matches!(self, Self::Attested | Self::Active | Self::RateLimited)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStatus {
    Committed,
    CredentialChecked,
    Accepted,
    Subsidized,
    Vested,
    Claimed,
    Rejected,
    Cancelled,
}
impl AllocationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::CredentialChecked => "credential_checked",
            Self::Accepted => "accepted",
            Self::Subsidized => "subsidized",
            Self::Vested => "vested",
            Self::Claimed => "claimed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }
    pub fn counts_toward_cap(self) -> bool {
        matches!(
            self,
            Self::Committed
                | Self::CredentialChecked
                | Self::Accepted
                | Self::Subsidized
                | Self::Vested
                | Self::Claimed
        )
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VestingKind {
    Immediate,
    Cliff,
    Linear,
    CliffLinear,
    Milestone,
    GovernanceControlled,
    ContractControlled,
}
impl VestingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Cliff => "cliff",
            Self::Linear => "linear",
            Self::CliffLinear => "cliff_linear",
            Self::Milestone => "milestone",
            Self::GovernanceControlled => "governance_controlled",
            Self::ContractControlled => "contract_controlled",
        }
    }
    pub fn requires_schedule(self) -> bool {
        !matches!(self, Self::Immediate)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsidyStatus {
    Reserved,
    Applied,
    Exhausted,
    Revoked,
    Expired,
}
impl SubsidyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Applied => "applied",
            Self::Exhausted => "exhausted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
    pub fn usable(self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitializationReceiptStatus {
    Prepared,
    Submitted,
    Verified,
    Applied,
    Rejected,
    Expired,
}
impl InitializationReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Verified => "verified",
            Self::Applied => "applied",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        }
    }
    pub fn is_final(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected | Self::Expired)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchpadEventKind {
    FactoryRegistered,
    LaunchCreated,
    RoundOpened,
    CredentialCommitted,
    AllocationCommitted,
    VestingCommitted,
    SubsidyReserved,
    ContractInitialized,
    ReceiptVerified,
    LaunchSettled,
    RiskFlagRaised,
}
impl LaunchpadEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FactoryRegistered => "factory_registered",
            Self::LaunchCreated => "launch_created",
            Self::RoundOpened => "round_opened",
            Self::CredentialCommitted => "credential_committed",
            Self::AllocationCommitted => "allocation_committed",
            Self::VestingCommitted => "vesting_committed",
            Self::SubsidyReserved => "subsidy_reserved",
            Self::ContractInitialized => "contract_initialized",
            Self::ReceiptVerified => "receipt_verified",
            Self::LaunchSettled => "launch_settled",
            Self::RiskFlagRaised => "risk_flag_raised",
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: String,
    pub pq_auth_suite: String,
    pub pq_kem_suite: String,
    pub commitment_scheme: String,
    pub nullifier_scheme: String,
    pub vesting_scheme: String,
    pub receipt_scheme: String,
    pub low_fee_lane: String,
    pub fee_asset_id: String,
    pub subsidy_asset_id: String,
    pub treasury_id: String,
    pub auditor_set_id: String,
    pub deployer_set_id: String,
    pub min_pq_security_bits: u16,
    pub min_anonymity_set: u64,
    pub default_privacy_set_size: u64,
    pub round_ttl_blocks: u64,
    pub receipt_ttl_blocks: u64,
    pub credential_ttl_blocks: u64,
    pub subsidy_window_blocks: u64,
    pub max_rounds_per_launch: usize,
    pub max_hooks: usize,
    pub max_deployment_gas_units: u64,
    pub min_allocation_units: u64,
    pub max_allocation_units: u64,
    pub max_fee_units: u64,
    pub subsidy_budget_units: u64,
    pub max_sybil_score_bps: u64,
    pub min_credential_weight: u64,
    pub require_pq_credentials: bool,
    pub require_vesting_commitments: bool,
    pub allow_low_fee_subsidies: bool,
    pub allow_contract_initializers: bool,
    pub allow_public_receipt_metadata: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_PROTOCOL_VERSION.to_string(),
            schema_version: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_SCHEMA_VERSION.to_string(),
            pq_auth_suite: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PQ_AUTH_SUITE.to_string(),
            pq_kem_suite: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PQ_KEM_SUITE.to_string(),
            commitment_scheme: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_COMMITMENT_SCHEME
                .to_string(),
            nullifier_scheme: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_NULLIFIER_SCHEME
                .to_string(),
            vesting_scheme: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_VESTING_SCHEME.to_string(),
            receipt_scheme: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_RECEIPT_SCHEME.to_string(),
            low_fee_lane: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_LOW_FEE_LANE.to_string(),
            fee_asset_id: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_FEE_ASSET_ID.to_string(),
            subsidy_asset_id: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_ASSET_ID
                .to_string(),
            treasury_id: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_TREASURY_ID.to_string(),
            auditor_set_id: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_AUDITOR_SET_ID.to_string(),
            deployer_set_id: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_DEPLOYER_SET_ID
                .to_string(),
            min_pq_security_bits: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_PQ_SECURITY_BITS,
            min_anonymity_set: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_ANONYMITY_SET,
            default_privacy_set_size: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_PRIVACY_SET_SIZE,
            round_ttl_blocks: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_ROUND_TTL_BLOCKS,
            receipt_ttl_blocks: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_RECEIPT_TTL_BLOCKS,
            credential_ttl_blocks:
                CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_CREDENTIAL_TTL_BLOCKS,
            subsidy_window_blocks:
                CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_WINDOW_BLOCKS,
            max_rounds_per_launch:
                CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_ROUNDS_PER_LAUNCH,
            max_hooks: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_HOOKS,
            max_deployment_gas_units:
                CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_DEPLOYMENT_GAS_UNITS,
            min_allocation_units: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_ALLOCATION_UNITS,
            max_allocation_units: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_ALLOCATION_UNITS,
            max_fee_units: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_FEE_UNITS,
            subsidy_budget_units: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_SUBSIDY_BUDGET_UNITS,
            max_sybil_score_bps: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_SYBIL_SCORE_BPS,
            min_credential_weight:
                CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MIN_CREDENTIAL_WEIGHT,
            require_pq_credentials: true,
            require_vesting_commitments: true,
            allow_low_fee_subsidies: true,
            allow_contract_initializers: true,
            allow_public_receipt_metadata: false,
        }
    }
}
impl Config {
    pub fn validate(&self) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("chain_id", &self.chain_id)?;
        ensure_non_empty("protocol_version", &self.protocol_version)?;
        ensure_non_empty("schema_version", &self.schema_version)?;
        ensure_non_empty("pq_auth_suite", &self.pq_auth_suite)?;
        ensure_non_empty("pq_kem_suite", &self.pq_kem_suite)?;
        ensure_non_empty("commitment_scheme", &self.commitment_scheme)?;
        ensure_non_empty("nullifier_scheme", &self.nullifier_scheme)?;
        ensure_non_empty("vesting_scheme", &self.vesting_scheme)?;
        ensure_non_empty("receipt_scheme", &self.receipt_scheme)?;
        ensure_non_empty("low_fee_lane", &self.low_fee_lane)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("subsidy_asset_id", &self.subsidy_asset_id)?;
        ensure_non_empty("treasury_id", &self.treasury_id)?;
        ensure_non_empty("auditor_set_id", &self.auditor_set_id)?;
        ensure_non_empty("deployer_set_id", &self.deployer_set_id)?;
        ensure_positive("min_anonymity_set", self.min_anonymity_set)?;
        ensure_positive("default_privacy_set_size", self.default_privacy_set_size)?;
        ensure_positive("round_ttl_blocks", self.round_ttl_blocks)?;
        ensure_positive("receipt_ttl_blocks", self.receipt_ttl_blocks)?;
        ensure_positive("credential_ttl_blocks", self.credential_ttl_blocks)?;
        ensure_positive("subsidy_window_blocks", self.subsidy_window_blocks)?;
        ensure_positive("max_deployment_gas_units", self.max_deployment_gas_units)?;
        ensure_positive("min_allocation_units", self.min_allocation_units)?;
        ensure_positive("max_allocation_units", self.max_allocation_units)?;
        ensure_positive("min_credential_weight", self.min_credential_weight)?;
        if self.min_anonymity_set > self.default_privacy_set_size {
            return Err("min_anonymity_set exceeds default_privacy_set_size".to_string());
        }
        if self.min_allocation_units > self.max_allocation_units {
            return Err("min_allocation_units exceeds max_allocation_units".to_string());
        }
        if self.max_sybil_score_bps > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_BPS {
            return Err("max_sybil_score_bps exceeds max bps".to_string());
        }
        if self.max_rounds_per_launch == 0 {
            return Err("max_rounds_per_launch must be positive".to_string());
        }
        if self.max_rounds_per_launch
            > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_MAX_ROUNDS_PER_LAUNCH * 8
        {
            return Err("max_rounds_per_launch exceeds protocol safety bound".to_string());
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_launchpad_factory_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "pq_auth_suite": self.pq_auth_suite,
            "pq_kem_suite": self.pq_kem_suite,
            "commitment_scheme": self.commitment_scheme,
            "nullifier_scheme": self.nullifier_scheme,
            "vesting_scheme": self.vesting_scheme,
            "receipt_scheme": self.receipt_scheme,
            "low_fee_lane": self.low_fee_lane,
            "fee_asset_id": self.fee_asset_id,
            "subsidy_asset_id": self.subsidy_asset_id,
            "treasury_id": self.treasury_id,
            "auditor_set_id": self.auditor_set_id,
            "deployer_set_id": self.deployer_set_id,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_anonymity_set": self.min_anonymity_set,
            "default_privacy_set_size": self.default_privacy_set_size,
            "round_ttl_blocks": self.round_ttl_blocks,
            "receipt_ttl_blocks": self.receipt_ttl_blocks,
            "credential_ttl_blocks": self.credential_ttl_blocks,
            "subsidy_window_blocks": self.subsidy_window_blocks,
            "max_rounds_per_launch": self.max_rounds_per_launch,
            "max_hooks": self.max_hooks,
            "max_deployment_gas_units": self.max_deployment_gas_units,
            "min_allocation_units": self.min_allocation_units,
            "max_allocation_units": self.max_allocation_units,
            "max_fee_units": self.max_fee_units,
            "subsidy_budget_units": self.subsidy_budget_units,
            "max_sybil_score_bps": self.max_sybil_score_bps,
            "min_credential_weight": self.min_credential_weight,
            "require_pq_credentials": self.require_pq_credentials,
            "require_vesting_commitments": self.require_vesting_commitments,
            "allow_low_fee_subsidies": self.allow_low_fee_subsidies,
            "allow_contract_initializers": self.allow_contract_initializers,
            "allow_public_receipt_metadata": self.allow_public_receipt_metadata,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub factories: u64,
    pub launches: u64,
    pub rounds: u64,
    pub allocation_commitments: u64,
    pub credential_commitments: u64,
    pub vesting_commitments: u64,
    pub subsidies: u64,
    pub initialization_receipts: u64,
    pub nullifiers: u64,
    pub events: u64,
    pub accepted_allocation_units: u64,
    pub subsidized_fee_units: u64,
    pub deployed_contracts: u64,
    pub rejected_allocations: u64,
    pub active_credentials: u64,
}
impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_launchpad_factory_counters",
            "chain_id": CHAIN_ID,
            "factories": self.factories,
            "launches": self.launches,
            "rounds": self.rounds,
            "allocation_commitments": self.allocation_commitments,
            "credential_commitments": self.credential_commitments,
            "vesting_commitments": self.vesting_commitments,
            "subsidies": self.subsidies,
            "initialization_receipts": self.initialization_receipts,
            "nullifiers": self.nullifiers,
            "events": self.events,
            "accepted_allocation_units": self.accepted_allocation_units,
            "subsidized_fee_units": self.subsidized_fee_units,
            "deployed_contracts": self.deployed_contracts,
            "rejected_allocations": self.rejected_allocations,
            "active_credentials": self.active_credentials,
        })
    }
    pub fn validate_against(&self, state: &State) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        compare_counter("factories", self.factories, state.factories.len())?;
        compare_counter("launches", self.launches, state.launches.len())?;
        compare_counter("rounds", self.rounds, state.rounds.len())?;
        compare_counter(
            "allocation_commitments",
            self.allocation_commitments,
            state.allocations.len(),
        )?;
        compare_counter(
            "credential_commitments",
            self.credential_commitments,
            state.credentials.len(),
        )?;
        compare_counter(
            "vesting_commitments",
            self.vesting_commitments,
            state.vesting_commitments.len(),
        )?;
        compare_counter("subsidies", self.subsidies, state.subsidies.len())?;
        compare_counter(
            "initialization_receipts",
            self.initialization_receipts,
            state.initialization_receipts.len(),
        )?;
        compare_counter("nullifiers", self.nullifiers, state.nullifiers.len())?;
        compare_counter("events", self.events, state.events.len())?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub factories_root: String,
    pub launches_root: String,
    pub rounds_root: String,
    pub allocation_commitments_root: String,
    pub credential_commitments_root: String,
    pub vesting_commitments_root: String,
    pub subsidy_root: String,
    pub initialization_receipts_root: String,
    pub nullifier_root: String,
    pub event_root: String,
    pub counters_root: String,
    pub policy_root: String,
    pub state_root: String,
}
impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_launchpad_factory_roots",
            "chain_id": CHAIN_ID,
            "config_root": self.config_root,
            "factories_root": self.factories_root,
            "launches_root": self.launches_root,
            "rounds_root": self.rounds_root,
            "allocation_commitments_root": self.allocation_commitments_root,
            "credential_commitments_root": self.credential_commitments_root,
            "vesting_commitments_root": self.vesting_commitments_root,
            "subsidy_root": self.subsidy_root,
            "initialization_receipts_root": self.initialization_receipts_root,
            "nullifier_root": self.nullifier_root,
            "event_root": self.event_root,
            "counters_root": self.counters_root,
            "policy_root": self.policy_root,
            "state_root": self.state_root,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenFactoryRecord {
    pub factory_id: String,
    pub label: String,
    pub owner_commitment: String,
    pub deployer_set_id: String,
    pub governance_scope: String,
    pub status: LaunchpadFactoryStatus,
    pub pq_auth_root: String,
    pub factory_template_root: String,
    pub allowed_asset_kinds_root: String,
    pub hook_policy_root: String,
    pub low_fee_lane: String,
    pub max_launches: u64,
    pub max_rounds_per_launch: usize,
    pub max_deployment_gas_units: u64,
    pub created_height: u64,
    pub updated_height: u64,
}
impl TokenFactoryRecord {
    pub fn new(
        label: &str,
        owner_commitment: &str,
        deployer_set_id: &str,
        governance_scope: &str,
        created_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("label", label)?;
        ensure_non_empty("owner_commitment", owner_commitment)?;
        ensure_non_empty("deployer_set_id", deployer_set_id)?;
        ensure_non_empty("governance_scope", governance_scope)?;
        let factory_id = token_factory_id(label, owner_commitment, created_height);
        let allowed_asset_kinds_root = string_set_root(
            "launchpad_allowed_asset_kinds",
            &[
                "confidential_fungible".to_string(),
                "governance".to_string(),
                "stable".to_string(),
                "receipt".to_string(),
                "contract_bound".to_string(),
            ],
        );
        Ok(Self {
            factory_id,
            label: label.to_string(),
            owner_commitment: owner_commitment.to_string(),
            deployer_set_id: deployer_set_id.to_string(),
            governance_scope: governance_scope.to_string(),
            status: LaunchpadFactoryStatus::Active,
            pq_auth_root: string_root("launchpad_factory_pq_auth", &config.pq_auth_suite),
            factory_template_root: template_root(label, governance_scope, config),
            allowed_asset_kinds_root,
            hook_policy_root: hook_policy_root(&[], config.max_hooks),
            low_fee_lane: config.low_fee_lane.clone(),
            max_launches: 512,
            max_rounds_per_launch: config.max_rounds_per_launch,
            max_deployment_gas_units: config.max_deployment_gas_units,
            created_height,
            updated_height: created_height,
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("factory_id", &self.factory_id)?;
        ensure_non_empty("factory label", &self.label)?;
        ensure_non_empty("owner_commitment", &self.owner_commitment)?;
        ensure_non_empty("deployer_set_id", &self.deployer_set_id)?;
        ensure_non_empty("governance_scope", &self.governance_scope)?;
        ensure_non_empty("pq_auth_root", &self.pq_auth_root)?;
        ensure_non_empty("factory_template_root", &self.factory_template_root)?;
        ensure_non_empty("allowed_asset_kinds_root", &self.allowed_asset_kinds_root)?;
        ensure_non_empty("hook_policy_root", &self.hook_policy_root)?;
        ensure_non_empty("low_fee_lane", &self.low_fee_lane)?;
        ensure_positive("factory max_launches", self.max_launches)?;
        if self.max_rounds_per_launch == 0 {
            return Err(format!("factory {} has no round capacity", self.factory_id));
        }
        if self.max_rounds_per_launch > config.max_rounds_per_launch {
            return Err(format!(
                "factory {} exceeds configured round limit",
                self.factory_id
            ));
        }
        if self.max_deployment_gas_units > config.max_deployment_gas_units {
            return Err(format!(
                "factory {} exceeds configured deployment gas limit",
                self.factory_id
            ));
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "factory {} updated before creation",
                self.factory_id
            ));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_launchpad_factory_record",
            "chain_id": CHAIN_ID,
            "factory_id": self.factory_id,
            "label": self.label,
            "owner_commitment": self.owner_commitment,
            "deployer_set_id": self.deployer_set_id,
            "governance_scope": self.governance_scope,
            "status": self.status.as_str(),
            "pq_auth_root": self.pq_auth_root,
            "factory_template_root": self.factory_template_root,
            "allowed_asset_kinds_root": self.allowed_asset_kinds_root,
            "hook_policy_root": self.hook_policy_root,
            "low_fee_lane": self.low_fee_lane,
            "max_launches": self.max_launches,
            "max_rounds_per_launch": self.max_rounds_per_launch,
            "max_deployment_gas_units": self.max_deployment_gas_units,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenLaunchRecord {
    pub launch_id: String,
    pub factory_id: String,
    pub issuer_commitment: String,
    pub asset_symbol_commitment: String,
    pub asset_metadata_root: String,
    pub asset_kind: String,
    pub supply_commitment: String,
    pub transfer_policy_root: String,
    pub contract_init_root: String,
    pub status: TokenLaunchStatus,
    pub credential_policy_root: String,
    pub sale_rounds_root: String,
    pub vesting_policy_root: String,
    pub subsidy_policy_root: String,
    pub privacy_set_size: u64,
    pub min_raise_commitment: String,
    pub max_raise_commitment: String,
    pub created_height: u64,
    pub opens_at_height: u64,
    pub closes_at_height: u64,
    pub updated_height: u64,
}
impl TokenLaunchRecord {
    pub fn new(
        factory_id: &str,
        issuer_commitment: &str,
        asset_symbol_commitment: &str,
        asset_metadata_root: &str,
        asset_kind: &str,
        created_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("factory_id", factory_id)?;
        ensure_non_empty("issuer_commitment", issuer_commitment)?;
        ensure_non_empty("asset_symbol_commitment", asset_symbol_commitment)?;
        ensure_non_empty("asset_metadata_root", asset_metadata_root)?;
        ensure_non_empty("asset_kind", asset_kind)?;
        let launch_id = token_launch_id(factory_id, issuer_commitment, asset_symbol_commitment);
        let opens_at_height = created_height.saturating_add(4);
        let closes_at_height = opens_at_height.saturating_add(config.round_ttl_blocks);
        Ok(Self {
            launch_id,
            factory_id: factory_id.to_string(),
            issuer_commitment: issuer_commitment.to_string(),
            asset_symbol_commitment: asset_symbol_commitment.to_string(),
            asset_metadata_root: asset_metadata_root.to_string(),
            asset_kind: asset_kind.to_string(),
            supply_commitment: supply_commitment_root(factory_id, issuer_commitment, asset_kind),
            transfer_policy_root: transfer_policy_root(asset_kind, config),
            contract_init_root: contract_initializer_root(factory_id, asset_metadata_root, config),
            status: TokenLaunchStatus::Scheduled,
            credential_policy_root: credential_policy_root(&[CredentialKind::HumanUniqueness]),
            sale_rounds_root: merkle_root("launchpad_empty_sale_rounds", &[]),
            vesting_policy_root: vesting_policy_root(VestingKind::CliffLinear, 180, 1_080),
            subsidy_policy_root: subsidy_policy_root(config),
            privacy_set_size: config.default_privacy_set_size,
            min_raise_commitment: amount_commitment("min_raise", 1_000),
            max_raise_commitment: amount_commitment("max_raise", 1_000_000),
            created_height,
            opens_at_height,
            closes_at_height,
            updated_height: created_height,
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("factory_id", &self.factory_id)?;
        ensure_non_empty("issuer_commitment", &self.issuer_commitment)?;
        ensure_non_empty("asset_symbol_commitment", &self.asset_symbol_commitment)?;
        ensure_non_empty("asset_metadata_root", &self.asset_metadata_root)?;
        ensure_non_empty("asset_kind", &self.asset_kind)?;
        ensure_non_empty("supply_commitment", &self.supply_commitment)?;
        ensure_non_empty("transfer_policy_root", &self.transfer_policy_root)?;
        ensure_non_empty("contract_init_root", &self.contract_init_root)?;
        ensure_non_empty("credential_policy_root", &self.credential_policy_root)?;
        ensure_non_empty("sale_rounds_root", &self.sale_rounds_root)?;
        ensure_non_empty("vesting_policy_root", &self.vesting_policy_root)?;
        ensure_non_empty("subsidy_policy_root", &self.subsidy_policy_root)?;
        ensure_positive("privacy_set_size", self.privacy_set_size)?;
        if self.privacy_set_size < config.min_anonymity_set {
            return Err(format!(
                "launch {} privacy set below configured anonymity floor",
                self.launch_id
            ));
        }
        if self.opens_at_height < self.created_height {
            return Err(format!("launch {} opens before creation", self.launch_id));
        }
        if self.closes_at_height <= self.opens_at_height {
            return Err(format!("launch {} closes before opening", self.launch_id));
        }
        if self.updated_height < self.created_height {
            return Err(format!("launch {} updated before creation", self.launch_id));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_launch_record",
            "chain_id": CHAIN_ID,
            "launch_id": self.launch_id,
            "factory_id": self.factory_id,
            "issuer_commitment": self.issuer_commitment,
            "asset_symbol_commitment": self.asset_symbol_commitment,
            "asset_metadata_root": self.asset_metadata_root,
            "asset_kind": self.asset_kind,
            "supply_commitment": self.supply_commitment,
            "transfer_policy_root": self.transfer_policy_root,
            "contract_init_root": self.contract_init_root,
            "status": self.status.as_str(),
            "credential_policy_root": self.credential_policy_root,
            "sale_rounds_root": self.sale_rounds_root,
            "vesting_policy_root": self.vesting_policy_root,
            "subsidy_policy_root": self.subsidy_policy_root,
            "privacy_set_size": self.privacy_set_size,
            "min_raise_commitment": self.min_raise_commitment,
            "max_raise_commitment": self.max_raise_commitment,
            "created_height": self.created_height,
            "opens_at_height": self.opens_at_height,
            "closes_at_height": self.closes_at_height,
            "updated_height": self.updated_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaleRoundRecord {
    pub round_id: String,
    pub launch_id: String,
    pub round_index: u32,
    pub kind: SaleRoundKind,
    pub status: SaleRoundStatus,
    pub price_commitment: String,
    pub supply_cap_commitment: String,
    pub min_ticket_commitment: String,
    pub max_ticket_commitment: String,
    pub credential_policy_root: String,
    pub anti_sybil_policy_root: String,
    pub vesting_policy_root: String,
    pub subsidy_policy_root: String,
    pub start_height: u64,
    pub end_height: u64,
    pub sealed_allocation_root: String,
    pub accepted_allocation_units: u64,
    pub created_height: u64,
    pub updated_height: u64,
}
impl SaleRoundRecord {
    pub fn new(
        launch_id: &str,
        round_index: u32,
        kind: SaleRoundKind,
        start_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("launch_id", launch_id)?;
        let end_height = start_height.saturating_add(config.round_ttl_blocks);
        let round_id = sale_round_id(launch_id, round_index, kind);
        Ok(Self {
            round_id,
            launch_id: launch_id.to_string(),
            round_index,
            kind,
            status: if kind.requires_credential() {
                SaleRoundStatus::CredentialGated
            } else {
                SaleRoundStatus::Open
            },
            price_commitment: amount_commitment("round_price", 1_000 + u64::from(round_index)),
            supply_cap_commitment: amount_commitment(
                "round_supply_cap",
                100_000 + u64::from(round_index) * 10_000,
            ),
            min_ticket_commitment: amount_commitment("round_min_ticket", 1),
            max_ticket_commitment: amount_commitment("round_max_ticket", 10_000),
            credential_policy_root: credential_policy_root(&round_credentials(kind)),
            anti_sybil_policy_root: anti_sybil_policy_root(kind, config),
            vesting_policy_root: round_vesting_policy_root(kind),
            subsidy_policy_root: if kind.permits_subsidy() {
                subsidy_policy_root(config)
            } else {
                merkle_root("launchpad_no_subsidy_policy", &[])
            },
            start_height,
            end_height,
            sealed_allocation_root: merkle_root("launchpad_round_empty_allocations", &[]),
            accepted_allocation_units: 0,
            created_height: start_height,
            updated_height: start_height,
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("round_id", &self.round_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("price_commitment", &self.price_commitment)?;
        ensure_non_empty("supply_cap_commitment", &self.supply_cap_commitment)?;
        ensure_non_empty("min_ticket_commitment", &self.min_ticket_commitment)?;
        ensure_non_empty("max_ticket_commitment", &self.max_ticket_commitment)?;
        ensure_non_empty("credential_policy_root", &self.credential_policy_root)?;
        ensure_non_empty("anti_sybil_policy_root", &self.anti_sybil_policy_root)?;
        ensure_non_empty("vesting_policy_root", &self.vesting_policy_root)?;
        ensure_non_empty("subsidy_policy_root", &self.subsidy_policy_root)?;
        ensure_non_empty("sealed_allocation_root", &self.sealed_allocation_root)?;
        if self.end_height <= self.start_height {
            return Err(format!("round {} ends before it starts", self.round_id));
        }
        if self.end_height.saturating_sub(self.start_height) > config.round_ttl_blocks * 4 {
            return Err(format!("round {} exceeds extended ttl", self.round_id));
        }
        if self.updated_height < self.created_height {
            return Err(format!("round {} updated before creation", self.round_id));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_token_sale_round",
            "chain_id": CHAIN_ID,
            "round_id": self.round_id,
            "launch_id": self.launch_id,
            "round_index": self.round_index,
            "round_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "price_commitment": self.price_commitment,
            "supply_cap_commitment": self.supply_cap_commitment,
            "min_ticket_commitment": self.min_ticket_commitment,
            "max_ticket_commitment": self.max_ticket_commitment,
            "credential_policy_root": self.credential_policy_root,
            "anti_sybil_policy_root": self.anti_sybil_policy_root,
            "vesting_policy_root": self.vesting_policy_root,
            "subsidy_policy_root": self.subsidy_policy_root,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "sealed_allocation_root": self.sealed_allocation_root,
            "accepted_allocation_units": self.accepted_allocation_units,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqCredentialCommitment {
    pub credential_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub issuer_commitment: String,
    pub holder_commitment: String,
    pub credential_kind: CredentialKind,
    pub status: CredentialStatus,
    pub credential_commitment: String,
    pub nullifier_root: String,
    pub anti_sybil_tag: String,
    pub disclosure_policy_root: String,
    pub pq_signature_root: String,
    pub pq_security_bits: u16,
    pub weight: u64,
    pub sybil_score_bps: u64,
    pub issued_height: u64,
    pub expires_at_height: u64,
}
impl PqCredentialCommitment {
    pub fn new(
        launch_id: &str,
        round_id: &str,
        issuer_commitment: &str,
        holder_commitment: &str,
        credential_kind: CredentialKind,
        issued_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("launch_id", launch_id)?;
        ensure_non_empty("round_id", round_id)?;
        ensure_non_empty("issuer_commitment", issuer_commitment)?;
        ensure_non_empty("holder_commitment", holder_commitment)?;
        let credential_id = pq_credential_id(
            launch_id,
            round_id,
            issuer_commitment,
            holder_commitment,
            credential_kind,
        );
        let credential_commitment = credential_commitment_root(
            launch_id,
            holder_commitment,
            credential_kind,
            issued_height,
            config,
        );
        Ok(Self {
            credential_id,
            launch_id: launch_id.to_string(),
            round_id: round_id.to_string(),
            issuer_commitment: issuer_commitment.to_string(),
            holder_commitment: holder_commitment.to_string(),
            credential_kind,
            status: CredentialStatus::Active,
            credential_commitment,
            nullifier_root: credential_nullifier_root(round_id, holder_commitment, config),
            anti_sybil_tag: anti_sybil_tag(launch_id, holder_commitment),
            disclosure_policy_root: credential_policy_root(&[credential_kind]),
            pq_signature_root: pq_signature_root(
                "credential_attestation",
                issuer_commitment,
                holder_commitment,
                config,
            ),
            pq_security_bits: config.min_pq_security_bits,
            weight: credential_kind
                .default_weight()
                .max(config.min_credential_weight),
            sybil_score_bps: config.max_sybil_score_bps / 4,
            issued_height,
            expires_at_height: issued_height.saturating_add(config.credential_ttl_blocks),
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("credential_id", &self.credential_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("round_id", &self.round_id)?;
        ensure_non_empty("issuer_commitment", &self.issuer_commitment)?;
        ensure_non_empty("holder_commitment", &self.holder_commitment)?;
        ensure_non_empty("credential_commitment", &self.credential_commitment)?;
        ensure_non_empty("nullifier_root", &self.nullifier_root)?;
        ensure_non_empty("anti_sybil_tag", &self.anti_sybil_tag)?;
        ensure_non_empty("disclosure_policy_root", &self.disclosure_policy_root)?;
        ensure_non_empty("pq_signature_root", &self.pq_signature_root)?;
        if self.pq_security_bits < config.min_pq_security_bits {
            return Err(format!(
                "credential {} below pq security floor",
                self.credential_id
            ));
        }
        if self.weight < config.min_credential_weight {
            return Err(format!(
                "credential {} weight below floor",
                self.credential_id
            ));
        }
        if self.sybil_score_bps > config.max_sybil_score_bps {
            return Err(format!(
                "credential {} sybil score exceeds policy",
                self.credential_id
            ));
        }
        if self.expires_at_height <= self.issued_height {
            return Err(format!(
                "credential {} expires immediately",
                self.credential_id
            ));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "launchpad_pq_credential_commitment",
            "chain_id": CHAIN_ID,
            "credential_id": self.credential_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "issuer_commitment": self.issuer_commitment,
            "holder_commitment": self.holder_commitment,
            "credential_kind": self.credential_kind.as_str(),
            "status": self.status.as_str(),
            "credential_commitment": self.credential_commitment,
            "nullifier_root": self.nullifier_root,
            "anti_sybil_tag": self.anti_sybil_tag,
            "disclosure_policy_root": self.disclosure_policy_root,
            "pq_signature_root": self.pq_signature_root,
            "pq_security_bits": self.pq_security_bits,
            "weight": self.weight,
            "sybil_score_bps": self.sybil_score_bps,
            "issued_height": self.issued_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedAllocationCommitment {
    pub allocation_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub credential_id: String,
    pub participant_commitment: String,
    pub allocation_commitment: String,
    pub payment_commitment: String,
    pub refund_commitment: String,
    pub nullifier: String,
    pub status: AllocationStatus,
    pub allocation_units: u64,
    pub fee_units: u64,
    pub privacy_set_size: u64,
    pub range_proof_root: String,
    pub credential_proof_root: String,
    pub subsidy_id: Option<String>,
    pub vesting_id: Option<String>,
    pub committed_height: u64,
    pub updated_height: u64,
}
impl ShieldedAllocationCommitment {
    pub fn new(
        launch_id: &str,
        round_id: &str,
        credential_id: &str,
        participant_commitment: &str,
        allocation_units: u64,
        committed_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("launch_id", launch_id)?;
        ensure_non_empty("round_id", round_id)?;
        ensure_non_empty("credential_id", credential_id)?;
        ensure_non_empty("participant_commitment", participant_commitment)?;
        if allocation_units < config.min_allocation_units {
            return Err("allocation_units below configured minimum".to_string());
        }
        if allocation_units > config.max_allocation_units {
            return Err("allocation_units above configured maximum".to_string());
        }
        let allocation_id = shielded_allocation_id(
            launch_id,
            round_id,
            credential_id,
            participant_commitment,
            committed_height,
        );
        let nullifier = allocation_nullifier(round_id, participant_commitment, committed_height);
        Ok(Self {
            allocation_id,
            launch_id: launch_id.to_string(),
            round_id: round_id.to_string(),
            credential_id: credential_id.to_string(),
            participant_commitment: participant_commitment.to_string(),
            allocation_commitment: allocation_commitment_root(
                round_id,
                participant_commitment,
                allocation_units,
                config,
            ),
            payment_commitment: payment_commitment_root(round_id, participant_commitment),
            refund_commitment: refund_commitment_root(round_id, participant_commitment),
            nullifier,
            status: AllocationStatus::Committed,
            allocation_units,
            fee_units: config.max_fee_units.min(5),
            privacy_set_size: config.default_privacy_set_size,
            range_proof_root: range_proof_root(allocation_units, config),
            credential_proof_root: credential_use_proof_root(credential_id, round_id, config),
            subsidy_id: None,
            vesting_id: None,
            committed_height,
            updated_height: committed_height,
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("allocation_id", &self.allocation_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("round_id", &self.round_id)?;
        ensure_non_empty("credential_id", &self.credential_id)?;
        ensure_non_empty("participant_commitment", &self.participant_commitment)?;
        ensure_non_empty("allocation_commitment", &self.allocation_commitment)?;
        ensure_non_empty("payment_commitment", &self.payment_commitment)?;
        ensure_non_empty("refund_commitment", &self.refund_commitment)?;
        ensure_non_empty("nullifier", &self.nullifier)?;
        ensure_non_empty("range_proof_root", &self.range_proof_root)?;
        ensure_non_empty("credential_proof_root", &self.credential_proof_root)?;
        if self.allocation_units < config.min_allocation_units {
            return Err(format!("allocation {} below minimum", self.allocation_id));
        }
        if self.allocation_units > config.max_allocation_units {
            return Err(format!("allocation {} above maximum", self.allocation_id));
        }
        if self.fee_units > config.max_fee_units {
            return Err(format!("allocation {} fee too high", self.allocation_id));
        }
        if self.privacy_set_size < config.min_anonymity_set {
            return Err(format!(
                "allocation {} privacy set below floor",
                self.allocation_id
            ));
        }
        if self.updated_height < self.committed_height {
            return Err(format!(
                "allocation {} updated before commitment",
                self.allocation_id
            ));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "shielded_launchpad_allocation_commitment",
            "chain_id": CHAIN_ID,
            "allocation_id": self.allocation_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "credential_id": self.credential_id,
            "participant_commitment": self.participant_commitment,
            "allocation_commitment": self.allocation_commitment,
            "payment_commitment": self.payment_commitment,
            "refund_commitment": self.refund_commitment,
            "nullifier": self.nullifier,
            "status": self.status.as_str(),
            "allocation_units": self.allocation_units,
            "fee_units": self.fee_units,
            "privacy_set_size": self.privacy_set_size,
            "range_proof_root": self.range_proof_root,
            "credential_proof_root": self.credential_proof_root,
            "subsidy_id": self.subsidy_id,
            "vesting_id": self.vesting_id,
            "committed_height": self.committed_height,
            "updated_height": self.updated_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingCommitment {
    pub vesting_id: String,
    pub allocation_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub beneficiary_commitment: String,
    pub vesting_kind: VestingKind,
    pub schedule_commitment: String,
    pub cliff_height: u64,
    pub start_height: u64,
    pub end_height: u64,
    pub release_frequency_blocks: u64,
    pub amount_commitment: String,
    pub revocation_policy_root: String,
    pub proof_root: String,
    pub created_height: u64,
}
impl VestingCommitment {
    pub fn new(
        allocation: &ShieldedAllocationCommitment,
        vesting_kind: VestingKind,
        start_height: u64,
        duration_blocks: u64,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_positive("duration_blocks", duration_blocks)?;
        let cliff_height = if vesting_kind.requires_schedule() {
            start_height.saturating_add(duration_blocks / 4)
        } else {
            start_height
        };
        let end_height = start_height.saturating_add(duration_blocks);
        let vesting_id = vesting_commitment_id(&allocation.allocation_id, vesting_kind);
        Ok(Self {
            vesting_id,
            allocation_id: allocation.allocation_id.clone(),
            launch_id: allocation.launch_id.clone(),
            round_id: allocation.round_id.clone(),
            beneficiary_commitment: allocation.participant_commitment.clone(),
            vesting_kind,
            schedule_commitment: vesting_schedule_commitment(
                &allocation.allocation_id,
                vesting_kind,
                start_height,
                end_height,
            ),
            cliff_height,
            start_height,
            end_height,
            release_frequency_blocks: duration_blocks.max(1) / 12 + 1,
            amount_commitment: allocation.allocation_commitment.clone(),
            revocation_policy_root: revocation_policy_root(vesting_kind),
            proof_root: vesting_proof_root(&allocation.allocation_id, vesting_kind),
            created_height: allocation.updated_height,
        })
    }
    pub fn validate(&self) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("vesting_id", &self.vesting_id)?;
        ensure_non_empty("allocation_id", &self.allocation_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("round_id", &self.round_id)?;
        ensure_non_empty("beneficiary_commitment", &self.beneficiary_commitment)?;
        ensure_non_empty("schedule_commitment", &self.schedule_commitment)?;
        ensure_non_empty("amount_commitment", &self.amount_commitment)?;
        ensure_non_empty("revocation_policy_root", &self.revocation_policy_root)?;
        ensure_non_empty("proof_root", &self.proof_root)?;
        if self.end_height < self.start_height {
            return Err(format!("vesting {} ends before start", self.vesting_id));
        }
        if self.cliff_height < self.start_height {
            return Err(format!("vesting {} cliff before start", self.vesting_id));
        }
        if self.cliff_height > self.end_height {
            return Err(format!("vesting {} cliff after end", self.vesting_id));
        }
        ensure_positive("release_frequency_blocks", self.release_frequency_blocks)?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "confidential_launchpad_vesting_commitment",
            "chain_id": CHAIN_ID,
            "vesting_id": self.vesting_id,
            "allocation_id": self.allocation_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "vesting_kind": self.vesting_kind.as_str(),
            "schedule_commitment": self.schedule_commitment,
            "cliff_height": self.cliff_height,
            "start_height": self.start_height,
            "end_height": self.end_height,
            "release_frequency_blocks": self.release_frequency_blocks,
            "amount_commitment": self.amount_commitment,
            "revocation_policy_root": self.revocation_policy_root,
            "proof_root": self.proof_root,
            "created_height": self.created_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentSubsidy {
    pub subsidy_id: String,
    pub launch_id: String,
    pub round_id: String,
    pub allocation_id: String,
    pub sponsor_commitment: String,
    pub recipient_commitment: String,
    pub status: SubsidyStatus,
    pub fee_asset_id: String,
    pub subsidy_asset_id: String,
    pub reserved_fee_units: u64,
    pub applied_fee_units: u64,
    pub budget_commitment: String,
    pub low_fee_lane: String,
    pub eligibility_root: String,
    pub expires_at_height: u64,
    pub created_height: u64,
    pub updated_height: u64,
}
impl DeploymentSubsidy {
    pub fn new(
        allocation: &ShieldedAllocationCommitment,
        sponsor_commitment: &str,
        created_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("sponsor_commitment", sponsor_commitment)?;
        if !config.allow_low_fee_subsidies {
            return Err("low-fee subsidies disabled by config".to_string());
        }
        let subsidy_id = deployment_subsidy_id(&allocation.allocation_id, sponsor_commitment);
        let reserved_fee_units = allocation.fee_units.min(config.max_fee_units);
        Ok(Self {
            subsidy_id,
            launch_id: allocation.launch_id.clone(),
            round_id: allocation.round_id.clone(),
            allocation_id: allocation.allocation_id.clone(),
            sponsor_commitment: sponsor_commitment.to_string(),
            recipient_commitment: allocation.participant_commitment.clone(),
            status: SubsidyStatus::Reserved,
            fee_asset_id: config.fee_asset_id.clone(),
            subsidy_asset_id: config.subsidy_asset_id.clone(),
            reserved_fee_units,
            applied_fee_units: 0,
            budget_commitment: amount_commitment("subsidy_budget", config.subsidy_budget_units),
            low_fee_lane: config.low_fee_lane.clone(),
            eligibility_root: subsidy_eligibility_root(&allocation.round_id, sponsor_commitment),
            expires_at_height: created_height.saturating_add(config.subsidy_window_blocks),
            created_height,
            updated_height: created_height,
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("subsidy_id", &self.subsidy_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("round_id", &self.round_id)?;
        ensure_non_empty("allocation_id", &self.allocation_id)?;
        ensure_non_empty("sponsor_commitment", &self.sponsor_commitment)?;
        ensure_non_empty("recipient_commitment", &self.recipient_commitment)?;
        ensure_non_empty("fee_asset_id", &self.fee_asset_id)?;
        ensure_non_empty("subsidy_asset_id", &self.subsidy_asset_id)?;
        ensure_non_empty("budget_commitment", &self.budget_commitment)?;
        ensure_non_empty("low_fee_lane", &self.low_fee_lane)?;
        ensure_non_empty("eligibility_root", &self.eligibility_root)?;
        if self.reserved_fee_units > config.max_fee_units {
            return Err(format!(
                "subsidy {} reserves too many fees",
                self.subsidy_id
            ));
        }
        if self.applied_fee_units > self.reserved_fee_units {
            return Err(format!("subsidy {} over-applied", self.subsidy_id));
        }
        if self.expires_at_height <= self.created_height {
            return Err(format!("subsidy {} expires immediately", self.subsidy_id));
        }
        if self.updated_height < self.created_height {
            return Err(format!(
                "subsidy {} updated before creation",
                self.subsidy_id
            ));
        }
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "launchpad_low_fee_deployment_subsidy",
            "chain_id": CHAIN_ID,
            "subsidy_id": self.subsidy_id,
            "launch_id": self.launch_id,
            "round_id": self.round_id,
            "allocation_id": self.allocation_id,
            "sponsor_commitment": self.sponsor_commitment,
            "recipient_commitment": self.recipient_commitment,
            "status": self.status.as_str(),
            "fee_asset_id": self.fee_asset_id,
            "subsidy_asset_id": self.subsidy_asset_id,
            "reserved_fee_units": self.reserved_fee_units,
            "applied_fee_units": self.applied_fee_units,
            "budget_commitment": self.budget_commitment,
            "low_fee_lane": self.low_fee_lane,
            "eligibility_root": self.eligibility_root,
            "expires_at_height": self.expires_at_height,
            "created_height": self.created_height,
            "updated_height": self.updated_height,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmartContractInitializationReceipt {
    pub receipt_id: String,
    pub launch_id: String,
    pub factory_id: String,
    pub contract_address_commitment: String,
    pub initializer_commitment: String,
    pub init_calldata_root: String,
    pub init_state_root: String,
    pub deployed_code_root: String,
    pub constructor_args_root: String,
    pub post_init_policy_root: String,
    pub receipt_proof_root: String,
    pub pq_attestation_root: String,
    pub status: InitializationReceiptStatus,
    pub gas_units: u64,
    pub fee_units: u64,
    pub submitted_height: u64,
    pub expires_at_height: u64,
}
impl SmartContractInitializationReceipt {
    pub fn new(
        launch: &TokenLaunchRecord,
        initializer_commitment: &str,
        contract_address_commitment: &str,
        gas_units: u64,
        submitted_height: u64,
        config: &Config,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("initializer_commitment", initializer_commitment)?;
        ensure_non_empty("contract_address_commitment", contract_address_commitment)?;
        if !config.allow_contract_initializers {
            return Err("contract initializers disabled by config".to_string());
        }
        if gas_units > config.max_deployment_gas_units {
            return Err("contract initialization gas exceeds configured maximum".to_string());
        }
        let receipt_id = initialization_receipt_id(
            &launch.launch_id,
            initializer_commitment,
            contract_address_commitment,
        );
        Ok(Self {
            receipt_id,
            launch_id: launch.launch_id.clone(),
            factory_id: launch.factory_id.clone(),
            contract_address_commitment: contract_address_commitment.to_string(),
            initializer_commitment: initializer_commitment.to_string(),
            init_calldata_root: init_calldata_root(&launch.launch_id, initializer_commitment),
            init_state_root: launch.contract_init_root.clone(),
            deployed_code_root: deployed_code_root(&launch.asset_kind, &launch.asset_metadata_root),
            constructor_args_root: constructor_args_root(&launch.launch_id, config),
            post_init_policy_root: post_init_policy_root(&launch.launch_id, config),
            receipt_proof_root: receipt_proof_root(&launch.launch_id, contract_address_commitment),
            pq_attestation_root: pq_signature_root(
                "contract_initialization",
                initializer_commitment,
                contract_address_commitment,
                config,
            ),
            status: InitializationReceiptStatus::Submitted,
            gas_units,
            fee_units: gas_units_to_fee_units(gas_units, config),
            submitted_height,
            expires_at_height: submitted_height.saturating_add(config.receipt_ttl_blocks),
        })
    }
    pub fn validate(&self, config: &Config) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("receipt_id", &self.receipt_id)?;
        ensure_non_empty("launch_id", &self.launch_id)?;
        ensure_non_empty("factory_id", &self.factory_id)?;
        ensure_non_empty(
            "contract_address_commitment",
            &self.contract_address_commitment,
        )?;
        ensure_non_empty("initializer_commitment", &self.initializer_commitment)?;
        ensure_non_empty("init_calldata_root", &self.init_calldata_root)?;
        ensure_non_empty("init_state_root", &self.init_state_root)?;
        ensure_non_empty("deployed_code_root", &self.deployed_code_root)?;
        ensure_non_empty("constructor_args_root", &self.constructor_args_root)?;
        ensure_non_empty("post_init_policy_root", &self.post_init_policy_root)?;
        ensure_non_empty("receipt_proof_root", &self.receipt_proof_root)?;
        ensure_non_empty("pq_attestation_root", &self.pq_attestation_root)?;
        ensure_positive("gas_units", self.gas_units)?;
        if self.gas_units > config.max_deployment_gas_units {
            return Err(format!("receipt {} gas exceeds limit", self.receipt_id));
        }
        if self.fee_units > config.max_fee_units {
            return Err(format!("receipt {} fee exceeds limit", self.receipt_id));
        }
        if self.expires_at_height <= self.submitted_height {
            return Err(format!("receipt {} expires immediately", self.receipt_id));
        }
        Ok(())
    }
    pub fn public_record(&self, reveal_metadata: bool) -> Value {
        let metadata_root = if reveal_metadata {
            self.constructor_args_root.clone()
        } else {
            string_root("launchpad_private_constructor_args", &self.receipt_id)
        };
        json!({
            "kind": "launchpad_smart_contract_initialization_receipt",
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "launch_id": self.launch_id,
            "factory_id": self.factory_id,
            "contract_address_commitment": self.contract_address_commitment,
            "initializer_commitment": self.initializer_commitment,
            "init_calldata_root": self.init_calldata_root,
            "init_state_root": self.init_state_root,
            "deployed_code_root": self.deployed_code_root,
            "constructor_args_root": metadata_root,
            "post_init_policy_root": self.post_init_policy_root,
            "receipt_proof_root": self.receipt_proof_root,
            "pq_attestation_root": self.pq_attestation_root,
            "status": self.status.as_str(),
            "gas_units": self.gas_units,
            "fee_units": self.fee_units,
            "submitted_height": self.submitted_height,
            "expires_at_height": self.expires_at_height,
        })
    }
    pub fn root(&self, reveal_metadata: bool) -> String {
        root_from_record(&self.public_record(reveal_metadata))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchpadEvent {
    pub event_id: String,
    pub event_kind: LaunchpadEventKind,
    pub subject_id: String,
    pub related_id: Option<String>,
    pub event_root: String,
    pub height: u64,
    pub sequence: u64,
}
impl LaunchpadEvent {
    pub fn new(
        event_kind: LaunchpadEventKind,
        subject_id: &str,
        related_id: Option<String>,
        event_root: &str,
        height: u64,
        sequence: u64,
    ) -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        ensure_non_empty("subject_id", subject_id)?;
        ensure_non_empty("event_root", event_root)?;
        let event_id = launchpad_event_id(event_kind, subject_id, height, sequence);
        Ok(Self {
            event_id,
            event_kind,
            subject_id: subject_id.to_string(),
            related_id,
            event_root: event_root.to_string(),
            height,
            sequence,
        })
    }
    pub fn validate(&self) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        ensure_non_empty("event_id", &self.event_id)?;
        ensure_non_empty("subject_id", &self.subject_id)?;
        ensure_non_empty("event_root", &self.event_root)?;
        Ok(())
    }
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "launchpad_event",
            "chain_id": CHAIN_ID,
            "event_id": self.event_id,
            "event_kind": self.event_kind.as_str(),
            "subject_id": self.subject_id,
            "related_id": self.related_id,
            "event_root": self.event_root,
            "height": self.height,
            "sequence": self.sequence,
        })
    }
    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub epoch: u64,
    pub factories: BTreeMap<String, TokenFactoryRecord>,
    pub launches: BTreeMap<String, TokenLaunchRecord>,
    pub rounds: BTreeMap<String, SaleRoundRecord>,
    pub credentials: BTreeMap<String, PqCredentialCommitment>,
    pub allocations: BTreeMap<String, ShieldedAllocationCommitment>,
    pub vesting_commitments: BTreeMap<String, VestingCommitment>,
    pub subsidies: BTreeMap<String, DeploymentSubsidy>,
    pub initialization_receipts: BTreeMap<String, SmartContractInitializationReceipt>,
    pub nullifiers: BTreeSet<String>,
    pub events: Vec<LaunchpadEvent>,
}
impl State {
    pub fn devnet() -> ConfidentialTokenLaunchpadFactoryResult<Self> {
        let config = Config::default();
        config.validate()?;
        let mut state = Self {
            config,
            height: CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEVNET_HEIGHT,
            epoch: 1,
            factories: BTreeMap::new(),
            launches: BTreeMap::new(),
            rounds: BTreeMap::new(),
            credentials: BTreeMap::new(),
            allocations: BTreeMap::new(),
            vesting_commitments: BTreeMap::new(),
            subsidies: BTreeMap::new(),
            initialization_receipts: BTreeMap::new(),
            nullifiers: BTreeSet::new(),
            events: Vec::new(),
        };
        let factory = TokenFactoryRecord::new(
            "devnet-confidential-launchpad-factory",
            &string_root("devnet_launchpad_owner", "treasury"),
            &state.config.deployer_set_id,
            "nebula-devnet-token-governance",
            state.height,
            &state.config,
        )?;
        let factory_id = factory.factory_id.clone();
        let factory_root = factory.root();
        state.factories.insert(factory_id.clone(), factory);
        let launch = TokenLaunchRecord::new(
            &factory_id,
            &string_root("devnet_issuer", "private-nebula-labs"),
            &string_root("devnet_symbol", "pDNR"),
            &metadata_root(
                "Private Nebula",
                "pDNR",
                12,
                "confidential_governance_utility",
            ),
            "confidential_fungible",
            state.height.saturating_add(1),
            &state.config,
        )?;
        let launch_id = launch.launch_id.clone();
        let launch_root = launch.root();
        state.launches.insert(launch_id.clone(), launch);
        let strategic_round = SaleRoundRecord::new(
            &launch_id,
            0,
            SaleRoundKind::Strategic,
            state.height.saturating_add(8),
            &state.config,
        )?;
        let strategic_round_id = strategic_round.round_id.clone();
        let strategic_round_root = strategic_round.root();
        state
            .rounds
            .insert(strategic_round_id.clone(), strategic_round);
        let community_round = SaleRoundRecord::new(
            &launch_id,
            1,
            SaleRoundKind::Community,
            state.height.saturating_add(24),
            &state.config,
        )?;
        let round_id = community_round.round_id.clone();
        let round_root = community_round.root();
        state.rounds.insert(round_id.clone(), community_round);
        let credential = PqCredentialCommitment::new(
            &launch_id,
            &round_id,
            &string_root("devnet_credential_issuer", "anti-sybil-council"),
            &string_root("devnet_holder", "participant-0001"),
            CredentialKind::HumanUniqueness,
            state.height.saturating_add(32),
            &state.config,
        )?;
        let credential_id = credential.credential_id.clone();
        let credential_root = credential.root();
        state.nullifiers.insert(credential.nullifier_root.clone());
        state.credentials.insert(credential_id.clone(), credential);
        let mut allocation = ShieldedAllocationCommitment::new(
            &launch_id,
            &round_id,
            &credential_id,
            &string_root("devnet_participant", "participant-0001"),
            10_000,
            state.height.saturating_add(36),
            &state.config,
        )?;
        let allocation_id = allocation.allocation_id.clone();
        let vesting = VestingCommitment::new(&allocation, VestingKind::CliffLinear, 320, 1_440)?;
        let vesting_id = vesting.vesting_id.clone();
        let subsidy = DeploymentSubsidy::new(
            &allocation,
            &string_root("devnet_sponsor", "fee-sponsor-0001"),
            state.height.saturating_add(40),
            &state.config,
        )?;
        let subsidy_id = subsidy.subsidy_id.clone();
        allocation.vesting_id = Some(vesting_id.clone());
        allocation.subsidy_id = Some(subsidy_id.clone());
        allocation.status = AllocationStatus::Subsidized;
        let allocation_root = allocation.root();
        state.nullifiers.insert(allocation.nullifier.clone());
        state
            .allocations
            .insert(allocation_id.clone(), allocation.clone());
        state
            .vesting_commitments
            .insert(vesting_id.clone(), vesting);
        state.subsidies.insert(subsidy_id.clone(), subsidy);
        let launch = state
            .launches
            .get(&launch_id)
            .cloned()
            .ok_or_else(|| "missing devnet launch".to_string())?;
        let receipt = SmartContractInitializationReceipt::new(
            &launch,
            &string_root("devnet_initializer", "contract-deployer-0001"),
            &string_root("devnet_contract", "private-token-contract-0001"),
            250_000,
            state.height.saturating_add(48),
            &state.config,
        )?;
        let receipt_id = receipt.receipt_id.clone();
        let receipt_root = receipt.root(state.config.allow_public_receipt_metadata);
        state
            .initialization_receipts
            .insert(receipt_id.clone(), receipt);
        let launch_rounds_root = record_map_root(
            "launchpad_launch_rounds",
            state
                .rounds
                .values()
                .filter(|round| round.launch_id == launch_id)
                .map(SaleRoundRecord::public_record),
        );
        let round_allocations_root = record_map_root(
            "launchpad_round_allocation_set",
            state
                .allocations
                .values()
                .filter(|item| item.round_id == round_id)
                .map(ShieldedAllocationCommitment::public_record),
        );
        if let Some(launch) = state.launches.get_mut(&launch_id) {
            launch.sale_rounds_root = launch_rounds_root;
            launch.status = TokenLaunchStatus::Initialized;
            launch.updated_height = state.height;
        }
        if let Some(round) = state.rounds.get_mut(&round_id) {
            round.accepted_allocation_units = 10_000;
            round.sealed_allocation_root = round_allocations_root;
            round.updated_height = state.height;
        }
        let event_specs = [
            (
                LaunchpadEventKind::FactoryRegistered,
                factory_id.as_str(),
                None,
                factory_root,
            ),
            (
                LaunchpadEventKind::LaunchCreated,
                launch_id.as_str(),
                Some(factory_id.clone()),
                launch_root,
            ),
            (
                LaunchpadEventKind::RoundOpened,
                strategic_round_id.as_str(),
                Some(launch_id.clone()),
                strategic_round_root,
            ),
            (
                LaunchpadEventKind::RoundOpened,
                round_id.as_str(),
                Some(launch_id.clone()),
                round_root,
            ),
            (
                LaunchpadEventKind::CredentialCommitted,
                credential_id.as_str(),
                Some(round_id.clone()),
                credential_root,
            ),
            (
                LaunchpadEventKind::AllocationCommitted,
                allocation_id.as_str(),
                Some(round_id.clone()),
                allocation_root,
            ),
            (
                LaunchpadEventKind::VestingCommitted,
                vesting_id.as_str(),
                Some(allocation_id.clone()),
                string_root("devnet_vesting_event", &vesting_id),
            ),
            (
                LaunchpadEventKind::SubsidyReserved,
                subsidy_id.as_str(),
                Some(allocation_id.clone()),
                string_root("devnet_subsidy_event", &subsidy_id),
            ),
            (
                LaunchpadEventKind::ContractInitialized,
                receipt_id.as_str(),
                Some(launch_id.clone()),
                receipt_root,
            ),
        ];
        for (sequence, (kind, subject, related, event_root)) in event_specs.into_iter().enumerate()
        {
            state.events.push(LaunchpadEvent::new(
                kind,
                subject,
                related,
                &event_root,
                state.height,
                sequence as u64,
            )?);
        }
        state.validate()?;
        Ok(state)
    }
    pub fn validate(&self) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        self.config.validate()?;
        ensure_positive("state height", self.height)?;
        if self.factories.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_FACTORIES {
            return Err("factory count exceeds protocol maximum".to_string());
        }
        if self.launches.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_LAUNCHES {
            return Err("launch count exceeds protocol maximum".to_string());
        }
        if self.rounds.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_ROUNDS {
            return Err("round count exceeds protocol maximum".to_string());
        }
        if self.allocations.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_ALLOCATIONS {
            return Err("allocation count exceeds protocol maximum".to_string());
        }
        if self.credentials.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_CREDENTIALS {
            return Err("credential count exceeds protocol maximum".to_string());
        }
        if self.vesting_commitments.len()
            > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_VESTING_COMMITMENTS
        {
            return Err("vesting commitment count exceeds protocol maximum".to_string());
        }
        if self.subsidies.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_SUBSIDIES {
            return Err("subsidy count exceeds protocol maximum".to_string());
        }
        if self.initialization_receipts.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_RECEIPTS {
            return Err("receipt count exceeds protocol maximum".to_string());
        }
        if self.nullifiers.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_NULLIFIERS {
            return Err("nullifier count exceeds protocol maximum".to_string());
        }
        if self.events.len() > CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_MAX_EVENTS {
            return Err("event count exceeds protocol maximum".to_string());
        }
        for factory in self.factories.values() {
            factory.validate(&self.config)?;
        }
        for launch in self.launches.values() {
            launch.validate(&self.config)?;
            if !self.factories.contains_key(&launch.factory_id) {
                return Err(format!(
                    "launch {} references missing factory",
                    launch.launch_id
                ));
            }
        }
        for round in self.rounds.values() {
            round.validate(&self.config)?;
            if !self.launches.contains_key(&round.launch_id) {
                return Err(format!(
                    "round {} references missing launch",
                    round.round_id
                ));
            }
        }
        for credential in self.credentials.values() {
            credential.validate(&self.config)?;
            if !self.launches.contains_key(&credential.launch_id) {
                return Err(format!(
                    "credential {} references missing launch",
                    credential.credential_id
                ));
            }
            if !self.rounds.contains_key(&credential.round_id) {
                return Err(format!(
                    "credential {} references missing round",
                    credential.credential_id
                ));
            }
        }
        for allocation in self.allocations.values() {
            allocation.validate(&self.config)?;
            if !self.launches.contains_key(&allocation.launch_id) {
                return Err(format!(
                    "allocation {} references missing launch",
                    allocation.allocation_id
                ));
            }
            if !self.rounds.contains_key(&allocation.round_id) {
                return Err(format!(
                    "allocation {} references missing round",
                    allocation.allocation_id
                ));
            }
            if self.config.require_pq_credentials
                && !self.credentials.contains_key(&allocation.credential_id)
            {
                return Err(format!(
                    "allocation {} references missing credential",
                    allocation.allocation_id
                ));
            }
            if !self.nullifiers.contains(&allocation.nullifier) {
                return Err(format!(
                    "allocation {} nullifier missing from set",
                    allocation.allocation_id
                ));
            }
        }
        for vesting in self.vesting_commitments.values() {
            vesting.validate()?;
            if !self.allocations.contains_key(&vesting.allocation_id) {
                return Err(format!(
                    "vesting {} references missing allocation",
                    vesting.vesting_id
                ));
            }
        }
        if self.config.require_vesting_commitments {
            for allocation in self.allocations.values() {
                let has_vesting = match allocation.vesting_id.as_ref() {
                    Some(vesting_id) => self.vesting_commitments.contains_key(vesting_id),
                    None => false,
                };
                if allocation.status.counts_toward_cap() && !has_vesting {
                    return Err(format!(
                        "allocation {} missing vesting commitment",
                        allocation.allocation_id
                    ));
                }
            }
        }
        for subsidy in self.subsidies.values() {
            subsidy.validate(&self.config)?;
            if !self.allocations.contains_key(&subsidy.allocation_id) {
                return Err(format!(
                    "subsidy {} references missing allocation",
                    subsidy.subsidy_id
                ));
            }
        }
        for receipt in self.initialization_receipts.values() {
            receipt.validate(&self.config)?;
            if !self.launches.contains_key(&receipt.launch_id) {
                return Err(format!(
                    "receipt {} references missing launch",
                    receipt.receipt_id
                ));
            }
            if !self.factories.contains_key(&receipt.factory_id) {
                return Err(format!(
                    "receipt {} references missing factory",
                    receipt.receipt_id
                ));
            }
        }
        for event in &self.events {
            event.validate()?;
        }
        self.counters().validate_against(self)?;
        Ok(())
    }
    pub fn set_height(&mut self, height: u64) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        if height == 0 {
            return Err("height must be positive".to_string());
        }
        self.height = height;
        self.expire_records();
        Ok(())
    }
    pub fn update_height(&mut self, height: u64) -> ConfidentialTokenLaunchpadFactoryResult<()> {
        if height < self.height {
            return Err("cannot move launchpad factory height backwards".to_string());
        }
        self.height = height;
        self.epoch = self.height / 720 + 1;
        self.expire_records();
        Ok(())
    }
    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        let config_root = self.config.root();
        let factories_root = record_map_root(
            "launchpad_factories",
            self.factories
                .values()
                .map(TokenFactoryRecord::public_record),
        );
        let launches_root = record_map_root(
            "launchpad_launches",
            self.launches.values().map(TokenLaunchRecord::public_record),
        );
        let rounds_root = record_map_root(
            "launchpad_rounds",
            self.rounds.values().map(SaleRoundRecord::public_record),
        );
        let allocation_commitments_root = record_map_root(
            "launchpad_allocations",
            self.allocations
                .values()
                .map(ShieldedAllocationCommitment::public_record),
        );
        let credential_commitments_root = record_map_root(
            "launchpad_credentials",
            self.credentials
                .values()
                .map(PqCredentialCommitment::public_record),
        );
        let vesting_commitments_root = record_map_root(
            "launchpad_vesting",
            self.vesting_commitments
                .values()
                .map(VestingCommitment::public_record),
        );
        let subsidy_root = record_map_root(
            "launchpad_subsidies",
            self.subsidies
                .values()
                .map(DeploymentSubsidy::public_record),
        );
        let initialization_receipts_root = record_map_root(
            "launchpad_receipts",
            self.initialization_receipts
                .values()
                .map(|receipt| receipt.public_record(self.config.allow_public_receipt_metadata)),
        );
        let nullifier_root = string_set_root(
            "launchpad_nullifiers",
            &self.nullifiers.iter().cloned().collect::<Vec<_>>(),
        );
        let event_root = record_map_root(
            "launchpad_events",
            self.events.iter().map(LaunchpadEvent::public_record),
        );
        let counters_root = root_from_record(&counters.public_record());
        let policy_root = policy_root(&self.config);
        let state_root = domain_hash(
            "confidential_token_launchpad_factory_state_root",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&factories_root),
                HashPart::Str(&launches_root),
                HashPart::Str(&rounds_root),
                HashPart::Str(&allocation_commitments_root),
                HashPart::Str(&credential_commitments_root),
                HashPart::Str(&vesting_commitments_root),
                HashPart::Str(&subsidy_root),
                HashPart::Str(&initialization_receipts_root),
                HashPart::Str(&nullifier_root),
                HashPart::Str(&event_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&policy_root),
                HashPart::Int(i128::from(self.height)),
                HashPart::Int(i128::from(self.epoch)),
            ],
            32,
        );
        Roots {
            config_root,
            factories_root,
            launches_root,
            rounds_root,
            allocation_commitments_root,
            credential_commitments_root,
            vesting_commitments_root,
            subsidy_root,
            initialization_receipts_root,
            nullifier_root,
            event_root,
            counters_root,
            policy_root,
            state_root,
        }
    }
    pub fn counters(&self) -> Counters {
        Counters {
            factories: self.factories.len() as u64,
            launches: self.launches.len() as u64,
            rounds: self.rounds.len() as u64,
            allocation_commitments: self.allocations.len() as u64,
            credential_commitments: self.credentials.len() as u64,
            vesting_commitments: self.vesting_commitments.len() as u64,
            subsidies: self.subsidies.len() as u64,
            initialization_receipts: self.initialization_receipts.len() as u64,
            nullifiers: self.nullifiers.len() as u64,
            events: self.events.len() as u64,
            accepted_allocation_units: self
                .allocations
                .values()
                .filter(|allocation| allocation.status.counts_toward_cap())
                .map(|allocation| allocation.allocation_units)
                .sum(),
            subsidized_fee_units: self
                .subsidies
                .values()
                .filter(|subsidy| subsidy.status.usable())
                .map(|subsidy| subsidy.reserved_fee_units)
                .sum(),
            deployed_contracts: self
                .initialization_receipts
                .values()
                .filter(|receipt| {
                    matches!(
                        receipt.status,
                        InitializationReceiptStatus::Verified
                            | InitializationReceiptStatus::Applied
                    )
                })
                .count() as u64,
            rejected_allocations: self
                .allocations
                .values()
                .filter(|allocation| {
                    matches!(
                        allocation.status,
                        AllocationStatus::Rejected | AllocationStatus::Cancelled
                    )
                })
                .count() as u64,
            active_credentials: self
                .credentials
                .values()
                .filter(|credential| credential.status.usable())
                .count() as u64,
        }
    }
    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "confidential_token_launchpad_factory_state",
            "chain_id": CHAIN_ID,
            "protocol_version": CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_PROTOCOL_VERSION,
            "height": self.height,
            "epoch": self.epoch,
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "state_root": roots.state_root,
        })
    }
    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
    fn expire_records(&mut self) {
        for round in self.rounds.values_mut() {
            if self.height > round.end_height && !round.status.is_terminal() {
                round.status = SaleRoundStatus::Expired;
                round.updated_height = self.height;
            }
        }
        for credential in self.credentials.values_mut() {
            if self.height > credential.expires_at_height && credential.status.usable() {
                credential.status = CredentialStatus::Expired;
            }
        }
        for subsidy in self.subsidies.values_mut() {
            if self.height > subsidy.expires_at_height && subsidy.status.usable() {
                subsidy.status = SubsidyStatus::Expired;
                subsidy.updated_height = self.height;
            }
        }
        for receipt in self.initialization_receipts.values_mut() {
            if self.height > receipt.expires_at_height && !receipt.status.is_final() {
                receipt.status = InitializationReceiptStatus::Expired;
            }
        }
    }
}
pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "confidential_token_launchpad_factory_record",
        &[HashPart::Json(record)],
        32,
    )
}
pub fn devnet() -> ConfidentialTokenLaunchpadFactoryResult<State> {
    State::devnet()
}
pub fn token_factory_id(label: &str, owner_commitment: &str, created_height: u64) -> String {
    domain_hash(
        "launchpad_token_factory_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(owner_commitment),
            HashPart::Int(i128::from(created_height)),
        ],
        32,
    )
}
pub fn token_launch_id(
    factory_id: &str,
    issuer_commitment: &str,
    asset_symbol_commitment: &str,
) -> String {
    domain_hash(
        "launchpad_token_launch_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(factory_id),
            HashPart::Str(issuer_commitment),
            HashPart::Str(asset_symbol_commitment),
        ],
        32,
    )
}
pub fn sale_round_id(launch_id: &str, round_index: u32, kind: SaleRoundKind) -> String {
    domain_hash(
        "launchpad_sale_round_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Int(i128::from(round_index)),
            HashPart::Str(kind.as_str()),
        ],
        32,
    )
}
pub fn pq_credential_id(
    launch_id: &str,
    round_id: &str,
    issuer_commitment: &str,
    holder_commitment: &str,
    credential_kind: CredentialKind,
) -> String {
    domain_hash(
        "launchpad_pq_credential_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(round_id),
            HashPart::Str(issuer_commitment),
            HashPart::Str(holder_commitment),
            HashPart::Str(credential_kind.as_str()),
        ],
        32,
    )
}
pub fn shielded_allocation_id(
    launch_id: &str,
    round_id: &str,
    credential_id: &str,
    participant_commitment: &str,
    committed_height: u64,
) -> String {
    domain_hash(
        "launchpad_shielded_allocation_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(round_id),
            HashPart::Str(credential_id),
            HashPart::Str(participant_commitment),
            HashPart::Int(i128::from(committed_height)),
        ],
        32,
    )
}
pub fn vesting_commitment_id(allocation_id: &str, vesting_kind: VestingKind) -> String {
    domain_hash(
        "launchpad_vesting_commitment_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(allocation_id),
            HashPart::Str(vesting_kind.as_str()),
        ],
        32,
    )
}
pub fn deployment_subsidy_id(allocation_id: &str, sponsor_commitment: &str) -> String {
    domain_hash(
        "launchpad_deployment_subsidy_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(allocation_id),
            HashPart::Str(sponsor_commitment),
        ],
        32,
    )
}
pub fn initialization_receipt_id(
    launch_id: &str,
    initializer_commitment: &str,
    contract_address_commitment: &str,
) -> String {
    domain_hash(
        "launchpad_initialization_receipt_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(initializer_commitment),
            HashPart::Str(contract_address_commitment),
        ],
        32,
    )
}
pub fn launchpad_event_id(
    event_kind: LaunchpadEventKind,
    subject_id: &str,
    height: u64,
    sequence: u64,
) -> String {
    domain_hash(
        "launchpad_event_id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(event_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Int(i128::from(height)),
            HashPart::Int(i128::from(sequence)),
        ],
        32,
    )
}
fn record_map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let mut records = records.into_iter().collect::<Vec<_>>();
    records.sort_by_key(root_from_record);
    merkle_root(domain, &records)
}
fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}
fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .map(|value| {
            json!({
                "kind": "launchpad_string_leaf",
                "chain_id": CHAIN_ID,
                "value": value,
                "leaf_root": string_root(domain, value),
            })
        })
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}
fn metadata_root(name: &str, symbol: &str, decimals: u8, description: &str) -> String {
    let record = json!({
        "kind": "launchpad_asset_metadata",
        "chain_id": CHAIN_ID,
        "name_commitment": string_root("launchpad_asset_name", name),
        "symbol_commitment": string_root("launchpad_asset_symbol", symbol),
        "decimals": decimals,
        "description_commitment": string_root("launchpad_asset_description", description),
    });
    root_from_record(&record)
}
fn template_root(label: &str, governance_scope: &str, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_factory_template",
        "chain_id": CHAIN_ID,
        "label": label,
        "governance_scope": governance_scope,
        "pq_auth_suite": config.pq_auth_suite,
        "pq_kem_suite": config.pq_kem_suite,
        "commitment_scheme": config.commitment_scheme,
        "vesting_scheme": config.vesting_scheme,
        "receipt_scheme": config.receipt_scheme,
    });
    root_from_record(&record)
}
fn hook_policy_root(hooks: &[String], max_hooks: usize) -> String {
    let record = json!({
        "kind": "launchpad_hook_policy",
        "chain_id": CHAIN_ID,
        "max_hooks": max_hooks,
        "hooks_root": string_set_root("launchpad_hook_set", hooks),
    });
    root_from_record(&record)
}
fn supply_commitment_root(factory_id: &str, issuer_commitment: &str, asset_kind: &str) -> String {
    domain_hash(
        "launchpad_supply_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(factory_id),
            HashPart::Str(issuer_commitment),
            HashPart::Str(asset_kind),
        ],
        32,
    )
}
fn transfer_policy_root(asset_kind: &str, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_transfer_policy",
        "chain_id": CHAIN_ID,
        "asset_kind": asset_kind,
        "confidential_default": true,
        "memo_policy": "commitment_only",
        "pq_auth_suite": config.pq_auth_suite,
        "low_fee_lane": config.low_fee_lane,
    });
    root_from_record(&record)
}
fn contract_initializer_root(
    factory_id: &str,
    asset_metadata_root: &str,
    config: &Config,
) -> String {
    let record = json!({
        "kind": "launchpad_contract_initializer",
        "chain_id": CHAIN_ID,
        "factory_id": factory_id,
        "asset_metadata_root": asset_metadata_root,
        "receipt_scheme": config.receipt_scheme,
        "max_deployment_gas_units": config.max_deployment_gas_units,
    });
    root_from_record(&record)
}
fn credential_policy_root(credentials: &[CredentialKind]) -> String {
    let leaves = credentials
        .iter()
        .map(|credential| {
            json!({
                "kind": "launchpad_credential_policy_leaf",
                "chain_id": CHAIN_ID,
                "credential_kind": credential.as_str(),
                "default_weight": credential.default_weight(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("launchpad_credential_policy", &leaves)
}
fn vesting_policy_root(
    vesting_kind: VestingKind,
    cliff_blocks: u64,
    duration_blocks: u64,
) -> String {
    let record = json!({
        "kind": "launchpad_vesting_policy",
        "chain_id": CHAIN_ID,
        "vesting_kind": vesting_kind.as_str(),
        "cliff_blocks": cliff_blocks,
        "duration_blocks": duration_blocks,
    });
    root_from_record(&record)
}
fn subsidy_policy_root(config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_subsidy_policy",
        "chain_id": CHAIN_ID,
        "enabled": config.allow_low_fee_subsidies,
        "fee_asset_id": config.fee_asset_id,
        "subsidy_asset_id": config.subsidy_asset_id,
        "budget_units": config.subsidy_budget_units,
        "window_blocks": config.subsidy_window_blocks,
        "low_fee_lane": config.low_fee_lane,
    });
    root_from_record(&record)
}
fn amount_commitment(domain: &str, amount_units: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(i128::from(amount_units)),
        ],
        32,
    )
}
fn round_credentials(kind: SaleRoundKind) -> Vec<CredentialKind> {
    match kind {
        SaleRoundKind::Founder => vec![CredentialKind::GovernanceDelegate],
        SaleRoundKind::Strategic => vec![
            CredentialKind::AccreditedInvestor,
            CredentialKind::SanctionsClear,
        ],
        SaleRoundKind::PrivateSale => vec![
            CredentialKind::HumanUniqueness,
            CredentialKind::AccreditedInvestor,
            CredentialKind::JurisdictionEligibility,
        ],
        SaleRoundKind::Community => vec![
            CredentialKind::HumanUniqueness,
            CredentialKind::CommunityReputation,
        ],
        SaleRoundKind::LiquidityBootstrap => vec![CredentialKind::LiquidityProvider],
        SaleRoundKind::DeveloperGrant => vec![CredentialKind::DeveloperReputation],
        SaleRoundKind::Airdrop => vec![CredentialKind::HumanUniqueness],
        SaleRoundKind::ContractBound => vec![CredentialKind::ContractDeveloper],
    }
}
fn anti_sybil_policy_root(kind: SaleRoundKind, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_anti_sybil_policy",
        "chain_id": CHAIN_ID,
        "round_kind": kind.as_str(),
        "requires_credential": kind.requires_credential(),
        "min_credential_weight": config.min_credential_weight,
        "max_sybil_score_bps": config.max_sybil_score_bps,
        "nullifier_scheme": config.nullifier_scheme,
        "min_anonymity_set": config.min_anonymity_set,
    });
    root_from_record(&record)
}
fn round_vesting_policy_root(kind: SaleRoundKind) -> String {
    match kind {
        SaleRoundKind::Founder => {
            vesting_policy_root(VestingKind::GovernanceControlled, 720, 8_640)
        }
        SaleRoundKind::Strategic => vesting_policy_root(VestingKind::CliffLinear, 720, 4_320),
        SaleRoundKind::PrivateSale => vesting_policy_root(VestingKind::CliffLinear, 360, 2_160),
        SaleRoundKind::Community => vesting_policy_root(VestingKind::Linear, 0, 1_080),
        SaleRoundKind::LiquidityBootstrap => vesting_policy_root(VestingKind::Immediate, 0, 1),
        SaleRoundKind::DeveloperGrant => vesting_policy_root(VestingKind::Milestone, 720, 8_640),
        SaleRoundKind::Airdrop => vesting_policy_root(VestingKind::Cliff, 180, 180),
        SaleRoundKind::ContractBound => {
            vesting_policy_root(VestingKind::ContractControlled, 120, 1_440)
        }
    }
}
fn credential_commitment_root(
    launch_id: &str,
    holder_commitment: &str,
    credential_kind: CredentialKind,
    issued_height: u64,
    config: &Config,
) -> String {
    domain_hash(
        "launchpad_credential_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(holder_commitment),
            HashPart::Str(credential_kind.as_str()),
            HashPart::Str(&config.commitment_scheme),
            HashPart::Int(i128::from(issued_height)),
        ],
        32,
    )
}
fn credential_nullifier_root(round_id: &str, holder_commitment: &str, config: &Config) -> String {
    domain_hash(
        "launchpad_credential_nullifier",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(round_id),
            HashPart::Str(holder_commitment),
            HashPart::Str(&config.nullifier_scheme),
        ],
        32,
    )
}
fn anti_sybil_tag(launch_id: &str, holder_commitment: &str) -> String {
    domain_hash(
        "launchpad_anti_sybil_tag",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(holder_commitment),
        ],
        32,
    )
}
fn pq_signature_root(
    domain: &str,
    signer_commitment: &str,
    payload_commitment: &str,
    config: &Config,
) -> String {
    let record = json!({
        "kind": "launchpad_pq_signature_root",
        "chain_id": CHAIN_ID,
        "domain": domain,
        "signer_commitment": signer_commitment,
        "payload_commitment": payload_commitment,
        "pq_auth_suite": config.pq_auth_suite,
        "pq_security_bits": config.min_pq_security_bits,
    });
    root_from_record(&record)
}
fn allocation_commitment_root(
    round_id: &str,
    participant_commitment: &str,
    allocation_units: u64,
    config: &Config,
) -> String {
    domain_hash(
        "launchpad_allocation_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(round_id),
            HashPart::Str(participant_commitment),
            HashPart::Int(i128::from(allocation_units)),
            HashPart::Str(&config.commitment_scheme),
        ],
        32,
    )
}
fn payment_commitment_root(round_id: &str, participant_commitment: &str) -> String {
    domain_hash(
        "launchpad_payment_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(round_id),
            HashPart::Str(participant_commitment),
        ],
        32,
    )
}
fn refund_commitment_root(round_id: &str, participant_commitment: &str) -> String {
    domain_hash(
        "launchpad_refund_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(round_id),
            HashPart::Str(participant_commitment),
        ],
        32,
    )
}
fn allocation_nullifier(
    round_id: &str,
    participant_commitment: &str,
    committed_height: u64,
) -> String {
    domain_hash(
        "launchpad_allocation_nullifier",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(round_id),
            HashPart::Str(participant_commitment),
            HashPart::Int(i128::from(committed_height)),
        ],
        32,
    )
}
fn range_proof_root(allocation_units: u64, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_range_proof",
        "chain_id": CHAIN_ID,
        "allocation_commitment_domain": config.commitment_scheme,
        "min_allocation_units": config.min_allocation_units,
        "max_allocation_units": config.max_allocation_units,
        "allocation_bucket_root": amount_commitment("allocation_bucket", allocation_units),
    });
    root_from_record(&record)
}
fn credential_use_proof_root(credential_id: &str, round_id: &str, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_credential_use_proof",
        "chain_id": CHAIN_ID,
        "credential_id": credential_id,
        "round_id": round_id,
        "pq_auth_suite": config.pq_auth_suite,
        "nullifier_scheme": config.nullifier_scheme,
    });
    root_from_record(&record)
}
fn vesting_schedule_commitment(
    allocation_id: &str,
    vesting_kind: VestingKind,
    start_height: u64,
    end_height: u64,
) -> String {
    domain_hash(
        "launchpad_vesting_schedule_commitment",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(allocation_id),
            HashPart::Str(vesting_kind.as_str()),
            HashPart::Int(i128::from(start_height)),
            HashPart::Int(i128::from(end_height)),
        ],
        32,
    )
}
fn revocation_policy_root(vesting_kind: VestingKind) -> String {
    let record = json!({
        "kind": "launchpad_vesting_revocation_policy",
        "chain_id": CHAIN_ID,
        "vesting_kind": vesting_kind.as_str(),
        "governance_review_required": matches!(
            vesting_kind,
            VestingKind::GovernanceControlled | VestingKind::Milestone
        ),
        "beneficiary_proof_required": true,
    });
    root_from_record(&record)
}
fn vesting_proof_root(allocation_id: &str, vesting_kind: VestingKind) -> String {
    let record = json!({
        "kind": "launchpad_vesting_proof",
        "chain_id": CHAIN_ID,
        "allocation_id": allocation_id,
        "vesting_kind": vesting_kind.as_str(),
        "proof_system": CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_VESTING_SCHEME,
    });
    root_from_record(&record)
}
fn subsidy_eligibility_root(round_id: &str, sponsor_commitment: &str) -> String {
    let record = json!({
        "kind": "launchpad_subsidy_eligibility",
        "chain_id": CHAIN_ID,
        "round_id": round_id,
        "sponsor_commitment": sponsor_commitment,
        "low_fee": true,
    });
    root_from_record(&record)
}
fn init_calldata_root(launch_id: &str, initializer_commitment: &str) -> String {
    domain_hash(
        "launchpad_init_calldata",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(initializer_commitment),
        ],
        32,
    )
}
fn deployed_code_root(asset_kind: &str, asset_metadata_root: &str) -> String {
    let record = json!({
        "kind": "launchpad_deployed_code",
        "chain_id": CHAIN_ID,
        "asset_kind": asset_kind,
        "asset_metadata_root": asset_metadata_root,
        "runtime": "confidential-token-runtime-v1",
    });
    root_from_record(&record)
}
fn constructor_args_root(launch_id: &str, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_constructor_args",
        "chain_id": CHAIN_ID,
        "launch_id": launch_id,
        "commitment_scheme": config.commitment_scheme,
        "vesting_scheme": config.vesting_scheme,
        "low_fee_lane": config.low_fee_lane,
    });
    root_from_record(&record)
}
fn post_init_policy_root(launch_id: &str, config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_post_init_policy",
        "chain_id": CHAIN_ID,
        "launch_id": launch_id,
        "auditor_set_id": config.auditor_set_id,
        "deployer_set_id": config.deployer_set_id,
        "receipt_ttl_blocks": config.receipt_ttl_blocks,
    });
    root_from_record(&record)
}
fn receipt_proof_root(launch_id: &str, contract_address_commitment: &str) -> String {
    domain_hash(
        "launchpad_receipt_proof",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(launch_id),
            HashPart::Str(contract_address_commitment),
            HashPart::Str(CONFIDENTIAL_TOKEN_LAUNCHPAD_FACTORY_DEFAULT_RECEIPT_SCHEME),
        ],
        32,
    )
}
fn gas_units_to_fee_units(gas_units: u64, config: &Config) -> u64 {
    let divisor = 50_000_u64.max(config.max_deployment_gas_units / config.max_fee_units.max(1));
    let fee_units = gas_units / divisor + u64::from(gas_units % divisor != 0);
    fee_units.min(config.max_fee_units)
}
fn policy_root(config: &Config) -> String {
    let record = json!({
        "kind": "launchpad_policy_root",
        "chain_id": CHAIN_ID,
        "config_root": config.root(),
        "anti_sybil_root": anti_sybil_policy_root(SaleRoundKind::Community, config),
        "subsidy_policy_root": subsidy_policy_root(config),
        "credential_policy_root": credential_policy_root(&[
            CredentialKind::HumanUniqueness,
            CredentialKind::SanctionsClear,
            CredentialKind::JurisdictionEligibility,
        ]),
        "contract_initializer_policy_root": contract_initializer_root(
            "policy",
            &string_root("policy_metadata", "launchpad"),
            config
        ),
    });
    root_from_record(&record)
}
fn ensure_non_empty(name: &str, value: &str) -> ConfidentialTokenLaunchpadFactoryResult<()> {
    if value.trim().is_empty() {
        Err(format!("{name} must not be empty"))
    } else {
        Ok(())
    }
}
fn ensure_positive(name: &str, value: u64) -> ConfidentialTokenLaunchpadFactoryResult<()> {
    if value == 0 {
        Err(format!("{name} must be positive"))
    } else {
        Ok(())
    }
}
fn compare_counter(
    name: &str,
    counter: u64,
    actual: usize,
) -> ConfidentialTokenLaunchpadFactoryResult<()> {
    if counter != actual as u64 {
        Err(format!(
            "counter {name} mismatch: counter={counter} actual={actual}"
        ))
    } else {
        Ok(())
    }
}
