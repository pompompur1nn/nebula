use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenContractGovernanceAuditRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-token-contract-governance-audit-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_PROTOCOL_VERSION;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_SCHEMA_VERSION: u64 =
    1;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_HEIGHT: u64 =
    842_400;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_NETWORK: &str =
    "nebula-private-l2-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_FEE_ASSET_ID:
    &str = "piconero-devnet";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_PQ_SIGNER_SCHEME:
    &str = "ml-dsa-87+slh-dsa-shake-192f-governance-quorum-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DISCLOSURE_SCHEME:
    &str = "roots-only-private-vote-disclosure-budget-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_TOKEN_FACTORY_SCHEME: &str =
    "confidential-token-factory-policy-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_UPGRADE_SCHEME: &str =
    "contract-upgrade-timelock-covenant-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_TREASURY_SCHEME: &str =
    "private-treasury-permission-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFI_RISK_SCHEME:
    &str = "private-defi-protocol-risk-flag-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_BRIDGE_ASSET_SCHEME:
    &str = "bridge-asset-registry-governance-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_BATCHING_SCHEME: &str =
    "low-fee-governance-proposal-batching-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_RELEASE_SCHEME: &str =
    "private-l2-release-readiness-finding-root-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BPS: u64 = 10_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS: u16 =
    192;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS: u16 =
    256;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_SIGNER_QUORUM: u16 =
    4;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_SIGNER_WEIGHT: u64 =
    67;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_UPGRADE_DELAY_BLOCKS: u64 =
    7_200;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_EMERGENCY_DELAY_BLOCKS: u64 =
    120;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_PRIVATE_VOTE_BUDGET: u64 =
    128;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_BATCH_WEIGHT: u64 =
    5_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_LOW_FEE_BPS: u64 =
    12;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_TREASURY_DAILY_LIMIT: u64 =
    50_000_000_000;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_COVENANT_DRIFT_BPS: u64 =
    75;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_DEFI_RISK_SCORE: u64 =
    72;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE: u64 =
    65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_BRIDGE_CONFIRMATIONS: u64 =
    10;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_TOKEN_POLICIES:
    usize = 131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_UPGRADE_PLANS:
    usize = 131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_TREASURY_PERMISSIONS: usize =
    65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_COVENANT_SNAPSHOTS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_DISCLOSURE_BUDGETS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_SIGNER_QUORUMS:
    usize = 65_536;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BATCHES: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_DEFI_FLAGS: usize =
    262_144;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BRIDGE_ASSETS:
    usize = 131_072;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_FINDINGS: usize =
    524_288;
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_PUBLIC_EVENTS:
    usize = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDomain {
    TokenFactory,
    ContractUpgrade,
    Treasury,
    Covenant,
    PrivateVoting,
    PqSignerQuorum,
    ProposalBatching,
    DefiRisk,
    BridgeAssetRegistry,
    ReleaseReadiness,
}

impl GovernanceDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TokenFactory => "token_factory",
            Self::ContractUpgrade => "contract_upgrade",
            Self::Treasury => "treasury",
            Self::Covenant => "covenant",
            Self::PrivateVoting => "private_voting",
            Self::PqSignerQuorum => "pq_signer_quorum",
            Self::ProposalBatching => "proposal_batching",
            Self::DefiRisk => "defi_risk",
            Self::BridgeAssetRegistry => "bridge_asset_registry",
            Self::ReleaseReadiness => "release_readiness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Info => 0,
            Self::Low => 20,
            Self::Medium => 45,
            Self::High => 75,
            Self::Critical => 100,
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    AcceptedRisk,
    Mitigated,
    WaivedByCouncil,
    Superseded,
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::AcceptedRisk => "accepted_risk",
            Self::Mitigated => "mitigated",
            Self::WaivedByCouncil => "waived_by_council",
            Self::Superseded => "superseded",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::AcceptedRisk)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenPolicyStatus {
    Draft,
    PendingVote,
    Active,
    Paused,
    Deprecated,
    Rejected,
}

impl TokenPolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PendingVote => "pending_vote",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deprecated => "deprecated",
            Self::Rejected => "rejected",
        }
    }

    pub fn live(self) -> bool {
        matches!(self, Self::PendingVote | Self::Active | Self::Paused)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialTokenCapability {
    Mint,
    Burn,
    Freeze,
    ConfidentialTransfer,
    SelectiveDisclosure,
    DefiCollateral,
    BridgeWrapped,
    GovernanceReceipt,
}

impl ConfidentialTokenCapability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Burn => "burn",
            Self::Freeze => "freeze",
            Self::ConfidentialTransfer => "confidential_transfer",
            Self::SelectiveDisclosure => "selective_disclosure",
            Self::DefiCollateral => "defi_collateral",
            Self::BridgeWrapped => "bridge_wrapped",
            Self::GovernanceReceipt => "governance_receipt",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeStatus {
    Draft,
    Scheduled,
    Timelocked,
    Executable,
    Executed,
    Cancelled,
    EmergencyPaused,
}

impl UpgradeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::Timelocked => "timelocked",
            Self::Executable => "executable",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
            Self::EmergencyPaused => "emergency_paused",
        }
    }

    pub fn pending(self) -> bool {
        matches!(self, Self::Scheduled | Self::Timelocked | Self::Executable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryPermissionKind {
    Spend,
    Rebalance,
    SponsorFees,
    EmergencyPause,
    BridgeReserveMove,
    DefiInsurancePayout,
}

impl TreasuryPermissionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spend => "spend",
            Self::Rebalance => "rebalance",
            Self::SponsorFees => "sponsor_fees",
            Self::EmergencyPause => "emergency_pause",
            Self::BridgeReserveMove => "bridge_reserve_move",
            Self::DefiInsurancePayout => "defi_insurance_payout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TreasuryPermissionStatus {
    Requested,
    Active,
    RateLimited,
    Suspended,
    Revoked,
    Expired,
}

impl TreasuryPermissionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::RateLimited => "rate_limited",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, Self::Active | Self::RateLimited)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CovenantStatus {
    Baseline,
    WithinTolerance,
    DriftWarning,
    DriftExceeded,
    Frozen,
}

impl CovenantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::WithinTolerance => "within_tolerance",
            Self::DriftWarning => "drift_warning",
            Self::DriftExceeded => "drift_exceeded",
            Self::Frozen => "frozen",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureBudgetStatus {
    Open,
    NearLimit,
    Exhausted,
    Frozen,
    Rotated,
}

impl DisclosureBudgetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::NearLimit => "near_limit",
            Self::Exhausted => "exhausted",
            Self::Frozen => "frozen",
            Self::Rotated => "rotated",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignerStatus {
    Candidate,
    Active,
    Degraded,
    Rotating,
    Revoked,
}

impl PqSignerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Active | Self::Degraded | Self::Rotating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStatus {
    Assembling,
    Sealed,
    Accepted,
    Rejected,
    Executed,
}

impl BatchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assembling => "assembling",
            Self::Sealed => "sealed",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Executed => "executed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefiRiskFlagKind {
    OracleDrift,
    LiquidityConcentration,
    LiquidationCongestion,
    ReentrancySurface,
    AdminKeyExposure,
    BridgeDependency,
    PrivacySetErosion,
    FeeVolatility,
}

impl DefiRiskFlagKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OracleDrift => "oracle_drift",
            Self::LiquidityConcentration => "liquidity_concentration",
            Self::LiquidationCongestion => "liquidation_congestion",
            Self::ReentrancySurface => "reentrancy_surface",
            Self::AdminKeyExposure => "admin_key_exposure",
            Self::BridgeDependency => "bridge_dependency",
            Self::PrivacySetErosion => "privacy_set_erosion",
            Self::FeeVolatility => "fee_volatility",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeAssetStatus {
    Proposed,
    Listed,
    Watchlisted,
    DepositPaused,
    WithdrawalPaused,
    Delisted,
}

impl BridgeAssetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Listed => "listed",
            Self::Watchlisted => "watchlisted",
            Self::DepositPaused => "deposit_paused",
            Self::WithdrawalPaused => "withdrawal_paused",
            Self::Delisted => "delisted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateStatus {
    Pending,
    Passing,
    Warning,
    Blocking,
    Waived,
}

impl ReleaseGateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passing => "passing",
            Self::Warning => "warning",
            Self::Blocking => "blocking",
            Self::Waived => "waived",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub network: String,
    pub audit_epoch: u64,
    pub fee_asset_id: String,
    pub min_pq_security_bits: u16,
    pub target_pq_security_bits: u16,
    pub min_signer_quorum: u16,
    pub min_signer_weight: u64,
    pub min_upgrade_delay_blocks: u64,
    pub emergency_delay_blocks: u64,
    pub private_vote_disclosure_budget: u64,
    pub max_batch_weight: u64,
    pub max_low_fee_bps: u64,
    pub treasury_daily_limit: u64,
    pub max_covenant_drift_bps: u64,
    pub max_defi_risk_score: u64,
    pub min_privacy_set_size: u64,
    pub min_bridge_confirmations: u64,
    pub token_factory_requires_quorum: bool,
    pub upgrades_require_timelock: bool,
    pub treasury_requires_dual_control: bool,
    pub bridge_registry_requires_risk_review: bool,
    pub release_blocks_on_high: bool,
    pub max_token_policies: usize,
    pub max_upgrade_plans: usize,
    pub max_treasury_permissions: usize,
    pub max_covenant_snapshots: usize,
    pub max_disclosure_budgets: usize,
    pub max_signer_quorums: usize,
    pub max_batches: usize,
    pub max_defi_flags: usize,
    pub max_bridge_assets: usize,
    pub max_findings: usize,
    pub max_public_events: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            network: PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_NETWORK
                .to_string(),
            audit_epoch:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_HEIGHT,
            fee_asset_id:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEVNET_FEE_ASSET_ID
                    .to_string(),
            min_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_PQ_SECURITY_BITS,
            target_pq_security_bits:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_TARGET_PQ_SECURITY_BITS,
            min_signer_quorum:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_SIGNER_QUORUM,
            min_signer_weight:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_SIGNER_WEIGHT,
            min_upgrade_delay_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_UPGRADE_DELAY_BLOCKS,
            emergency_delay_blocks:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_EMERGENCY_DELAY_BLOCKS,
            private_vote_disclosure_budget:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_PRIVATE_VOTE_BUDGET,
            max_batch_weight:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_BATCH_WEIGHT,
            max_low_fee_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_LOW_FEE_BPS,
            treasury_daily_limit:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_TREASURY_DAILY_LIMIT,
            max_covenant_drift_bps:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_COVENANT_DRIFT_BPS,
            max_defi_risk_score:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MAX_DEFI_RISK_SCORE,
            min_privacy_set_size:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_bridge_confirmations:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFAULT_MIN_BRIDGE_CONFIRMATIONS,
            token_factory_requires_quorum: true,
            upgrades_require_timelock: true,
            treasury_requires_dual_control: true,
            bridge_registry_requires_risk_review: true,
            release_blocks_on_high: true,
            max_token_policies:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_TOKEN_POLICIES,
            max_upgrade_plans:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_UPGRADE_PLANS,
            max_treasury_permissions:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_TREASURY_PERMISSIONS,
            max_covenant_snapshots:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_COVENANT_SNAPSHOTS,
            max_disclosure_budgets:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_DISCLOSURE_BUDGETS,
            max_signer_quorums:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_SIGNER_QUORUMS,
            max_batches:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BATCHES,
            max_defi_flags:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_DEFI_FLAGS,
            max_bridge_assets:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BRIDGE_ASSETS,
            max_findings:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_FINDINGS,
            max_public_events:
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_PUBLIC_EVENTS,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_contract_governance_audit_config",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "network": self.network,
            "audit_epoch": self.audit_epoch,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_HASH_SUITE,
            "pq_signer_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_PQ_SIGNER_SCHEME,
            "disclosure_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DISCLOSURE_SCHEME,
            "token_factory_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_TOKEN_FACTORY_SCHEME,
            "upgrade_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_UPGRADE_SCHEME,
            "treasury_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_TREASURY_SCHEME,
            "defi_risk_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_DEFI_RISK_SCHEME,
            "bridge_asset_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_BRIDGE_ASSET_SCHEME,
            "batching_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_BATCHING_SCHEME,
            "release_scheme": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_RELEASE_SCHEME,
            "min_pq_security_bits": self.min_pq_security_bits,
            "target_pq_security_bits": self.target_pq_security_bits,
            "min_signer_quorum": self.min_signer_quorum,
            "min_signer_weight": self.min_signer_weight,
            "min_upgrade_delay_blocks": self.min_upgrade_delay_blocks,
            "emergency_delay_blocks": self.emergency_delay_blocks,
            "private_vote_disclosure_budget": self.private_vote_disclosure_budget,
            "max_batch_weight": self.max_batch_weight,
            "max_low_fee_bps": self.max_low_fee_bps,
            "treasury_daily_limit": self.treasury_daily_limit,
            "max_covenant_drift_bps": self.max_covenant_drift_bps,
            "max_defi_risk_score": self.max_defi_risk_score,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_bridge_confirmations": self.min_bridge_confirmations,
            "token_factory_requires_quorum": self.token_factory_requires_quorum,
            "upgrades_require_timelock": self.upgrades_require_timelock,
            "treasury_requires_dual_control": self.treasury_requires_dual_control,
            "bridge_registry_requires_risk_review": self.bridge_registry_requires_risk_review,
            "release_blocks_on_high": self.release_blocks_on_high,
            "max_token_policies": self.max_token_policies,
            "max_upgrade_plans": self.max_upgrade_plans,
            "max_treasury_permissions": self.max_treasury_permissions,
            "max_covenant_snapshots": self.max_covenant_snapshots,
            "max_disclosure_budgets": self.max_disclosure_budgets,
            "max_signer_quorums": self.max_signer_quorums,
            "max_batches": self.max_batches,
            "max_defi_flags": self.max_defi_flags,
            "max_bridge_assets": self.max_bridge_assets,
            "max_findings": self.max_findings,
            "max_public_events": self.max_public_events,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PRIVATE-L2-GOVERNANCE-AUDIT-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("chain_id", &self.chain_id)?;
        require_non_empty("network", &self.network)?;
        require_non_empty("fee_asset_id", &self.fee_asset_id)?;
        require_positive("audit_epoch", self.audit_epoch)?;
        require_positive("min_pq_security_bits", self.min_pq_security_bits as u64)?;
        require_positive(
            "target_pq_security_bits",
            self.target_pq_security_bits as u64,
        )?;
        require(
            self.target_pq_security_bits >= self.min_pq_security_bits,
            "target pq security bits below minimum",
        )?;
        require_positive("min_signer_quorum", self.min_signer_quorum as u64)?;
        require_positive("min_signer_weight", self.min_signer_weight)?;
        require_bps("min_signer_weight", self.min_signer_weight)?;
        require_positive("min_upgrade_delay_blocks", self.min_upgrade_delay_blocks)?;
        require_positive("emergency_delay_blocks", self.emergency_delay_blocks)?;
        require(
            self.min_upgrade_delay_blocks >= self.emergency_delay_blocks,
            "normal upgrade delay below emergency delay",
        )?;
        require_positive(
            "private_vote_disclosure_budget",
            self.private_vote_disclosure_budget,
        )?;
        require_positive("max_batch_weight", self.max_batch_weight)?;
        require_bps("max_low_fee_bps", self.max_low_fee_bps)?;
        require_positive("treasury_daily_limit", self.treasury_daily_limit)?;
        require_bps("max_covenant_drift_bps", self.max_covenant_drift_bps)?;
        require_bps("max_defi_risk_score", self.max_defi_risk_score)?;
        require_positive("min_privacy_set_size", self.min_privacy_set_size)?;
        require_positive("min_bridge_confirmations", self.min_bridge_confirmations)?;
        require_positive("max_token_policies", self.max_token_policies as u64)?;
        require_positive("max_upgrade_plans", self.max_upgrade_plans as u64)?;
        require_positive(
            "max_treasury_permissions",
            self.max_treasury_permissions as u64,
        )?;
        require_positive("max_covenant_snapshots", self.max_covenant_snapshots as u64)?;
        require_positive("max_disclosure_budgets", self.max_disclosure_budgets as u64)?;
        require_positive("max_signer_quorums", self.max_signer_quorums as u64)?;
        require_positive("max_batches", self.max_batches as u64)?;
        require_positive("max_defi_flags", self.max_defi_flags as u64)?;
        require_positive("max_bridge_assets", self.max_bridge_assets as u64)?;
        require_positive("max_findings", self.max_findings as u64)?;
        require_positive("max_public_events", self.max_public_events as u64)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub token_policies: u64,
    pub active_token_policies: u64,
    pub upgrade_plans: u64,
    pub pending_upgrades: u64,
    pub treasury_permissions: u64,
    pub usable_treasury_permissions: u64,
    pub covenant_snapshots: u64,
    pub disclosure_budgets: u64,
    pub exhausted_disclosure_budgets: u64,
    pub signer_quorums: u64,
    pub signer_quorums_below_threshold: u64,
    pub proposal_batches: u64,
    pub low_fee_batches: u64,
    pub defi_flags: u64,
    pub active_defi_flags: u64,
    pub bridge_assets: u64,
    pub listed_bridge_assets: u64,
    pub findings: u64,
    pub active_findings: u64,
    pub release_blocking_findings: u64,
    pub public_events: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_contract_governance_audit_counters",
            "token_policies": self.token_policies,
            "active_token_policies": self.active_token_policies,
            "upgrade_plans": self.upgrade_plans,
            "pending_upgrades": self.pending_upgrades,
            "treasury_permissions": self.treasury_permissions,
            "usable_treasury_permissions": self.usable_treasury_permissions,
            "covenant_snapshots": self.covenant_snapshots,
            "disclosure_budgets": self.disclosure_budgets,
            "exhausted_disclosure_budgets": self.exhausted_disclosure_budgets,
            "signer_quorums": self.signer_quorums,
            "signer_quorums_below_threshold": self.signer_quorums_below_threshold,
            "proposal_batches": self.proposal_batches,
            "low_fee_batches": self.low_fee_batches,
            "defi_flags": self.defi_flags,
            "active_defi_flags": self.active_defi_flags,
            "bridge_assets": self.bridge_assets,
            "listed_bridge_assets": self.listed_bridge_assets,
            "findings": self.findings,
            "active_findings": self.active_findings,
            "release_blocking_findings": self.release_blocking_findings,
            "public_events": self.public_events,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root(
            "PRIVATE-L2-GOVERNANCE-AUDIT-COUNTERS",
            &self.public_record(),
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub token_policy_root: String,
    pub upgrade_plan_root: String,
    pub treasury_permission_root: String,
    pub covenant_snapshot_root: String,
    pub disclosure_budget_root: String,
    pub signer_quorum_root: String,
    pub proposal_batch_root: String,
    pub defi_risk_flag_root: String,
    pub bridge_asset_root: String,
    pub release_finding_root: String,
    pub public_event_root: String,
    pub counters_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_l2_pq_confidential_token_contract_governance_audit_roots",
            "config_root": self.config_root,
            "token_policy_root": self.token_policy_root,
            "upgrade_plan_root": self.upgrade_plan_root,
            "treasury_permission_root": self.treasury_permission_root,
            "covenant_snapshot_root": self.covenant_snapshot_root,
            "disclosure_budget_root": self.disclosure_budget_root,
            "signer_quorum_root": self.signer_quorum_root,
            "proposal_batch_root": self.proposal_batch_root,
            "defi_risk_flag_root": self.defi_risk_flag_root,
            "bridge_asset_root": self.bridge_asset_root,
            "release_finding_root": self.release_finding_root,
            "public_event_root": self.public_event_root,
            "counters_root": self.counters_root,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PRIVATE-L2-GOVERNANCE-AUDIT-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenFactoryPolicyRequest {
    pub policy_id: String,
    pub issuer_commitment: String,
    pub metadata_commitment: String,
    pub supply_cap_commitment: String,
    pub capabilities: BTreeSet<ConfidentialTokenCapability>,
    pub status: TokenPolicyStatus,
    pub pq_quorum_id: String,
    pub privacy_set_size: u64,
    pub mint_limit_per_epoch: u64,
    pub max_admin_fee_bps: u64,
    pub requires_council_vote: bool,
    pub allows_unbounded_mint: bool,
    pub notes_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenFactoryPolicyRecord {
    pub policy_id: String,
    pub issuer_commitment: String,
    pub metadata_commitment: String,
    pub supply_cap_commitment: String,
    pub capabilities: BTreeSet<ConfidentialTokenCapability>,
    pub status: TokenPolicyStatus,
    pub pq_quorum_id: String,
    pub privacy_set_size: u64,
    pub mint_limit_per_epoch: u64,
    pub max_admin_fee_bps: u64,
    pub requires_council_vote: bool,
    pub allows_unbounded_mint: bool,
    pub notes_commitment: String,
    pub audit_score: u64,
    pub release_ready: bool,
}

impl TokenFactoryPolicyRecord {
    pub fn from_request(request: TokenFactoryPolicyRequest, config: &Config) -> Result<Self> {
        require_non_empty("policy_id", &request.policy_id)?;
        require_non_empty("issuer_commitment", &request.issuer_commitment)?;
        require_non_empty("metadata_commitment", &request.metadata_commitment)?;
        require_non_empty("supply_cap_commitment", &request.supply_cap_commitment)?;
        require_non_empty("pq_quorum_id", &request.pq_quorum_id)?;
        require_non_empty("notes_commitment", &request.notes_commitment)?;
        require_positive("privacy_set_size", request.privacy_set_size)?;
        require_positive("mint_limit_per_epoch", request.mint_limit_per_epoch)?;
        require_bps("max_admin_fee_bps", request.max_admin_fee_bps)?;

        let mut score = 100_u64;
        if request.privacy_set_size < config.min_privacy_set_size {
            score = score.saturating_sub(25);
        }
        if request.max_admin_fee_bps > config.max_low_fee_bps.saturating_mul(10) {
            score = score.saturating_sub(15);
        }
        if request.allows_unbounded_mint {
            score = score.saturating_sub(35);
        }
        if config.token_factory_requires_quorum && !request.requires_council_vote {
            score = score.saturating_sub(20);
        }
        if !request
            .capabilities
            .contains(&ConfidentialTokenCapability::ConfidentialTransfer)
        {
            score = score.saturating_sub(15);
        }
        let release_ready = score >= 75 && request.status.live();

        Ok(Self {
            policy_id: request.policy_id,
            issuer_commitment: request.issuer_commitment,
            metadata_commitment: request.metadata_commitment,
            supply_cap_commitment: request.supply_cap_commitment,
            capabilities: request.capabilities,
            status: request.status,
            pq_quorum_id: request.pq_quorum_id,
            privacy_set_size: request.privacy_set_size,
            mint_limit_per_epoch: request.mint_limit_per_epoch,
            max_admin_fee_bps: request.max_admin_fee_bps,
            requires_council_vote: request.requires_council_vote,
            allows_unbounded_mint: request.allows_unbounded_mint,
            notes_commitment: request.notes_commitment,
            audit_score: score,
            release_ready,
        })
    }

    pub fn public_record(&self) -> Value {
        let capabilities = self
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>();
        json!({
            "kind": "token_factory_policy_record",
            "policy_id": self.policy_id,
            "issuer_commitment": self.issuer_commitment,
            "metadata_commitment": self.metadata_commitment,
            "supply_cap_commitment": self.supply_cap_commitment,
            "capabilities": capabilities,
            "status": self.status.as_str(),
            "pq_quorum_id": self.pq_quorum_id,
            "privacy_set_size": self.privacy_set_size,
            "mint_limit_per_epoch": self.mint_limit_per_epoch,
            "max_admin_fee_bps": self.max_admin_fee_bps,
            "requires_council_vote": self.requires_council_vote,
            "allows_unbounded_mint": self.allows_unbounded_mint,
            "notes_commitment": self.notes_commitment,
            "audit_score": self.audit_score,
            "release_ready": self.release_ready,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("TOKEN-FACTORY-POLICY", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractUpgradeRequest {
    pub upgrade_id: String,
    pub contract_id: String,
    pub current_code_root: String,
    pub proposed_code_root: String,
    pub migration_root: String,
    pub covenant_root_before: String,
    pub covenant_root_after: String,
    pub scheduled_height: u64,
    pub executable_height: u64,
    pub emergency: bool,
    pub pq_quorum_id: String,
    pub status: UpgradeStatus,
    pub rollback_code_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractUpgradeRecord {
    pub upgrade_id: String,
    pub contract_id: String,
    pub current_code_root: String,
    pub proposed_code_root: String,
    pub migration_root: String,
    pub covenant_root_before: String,
    pub covenant_root_after: String,
    pub scheduled_height: u64,
    pub executable_height: u64,
    pub delay_blocks: u64,
    pub emergency: bool,
    pub pq_quorum_id: String,
    pub status: UpgradeStatus,
    pub rollback_code_root: String,
    pub timelock_satisfied: bool,
    pub covenant_changed: bool,
}

impl ContractUpgradeRecord {
    pub fn from_request(request: ContractUpgradeRequest, config: &Config) -> Result<Self> {
        require_non_empty("upgrade_id", &request.upgrade_id)?;
        require_non_empty("contract_id", &request.contract_id)?;
        require_non_empty("current_code_root", &request.current_code_root)?;
        require_non_empty("proposed_code_root", &request.proposed_code_root)?;
        require_non_empty("migration_root", &request.migration_root)?;
        require_non_empty("covenant_root_before", &request.covenant_root_before)?;
        require_non_empty("covenant_root_after", &request.covenant_root_after)?;
        require_non_empty("pq_quorum_id", &request.pq_quorum_id)?;
        require_non_empty("rollback_code_root", &request.rollback_code_root)?;
        require_positive("scheduled_height", request.scheduled_height)?;
        require_positive("executable_height", request.executable_height)?;
        require(
            request.executable_height >= request.scheduled_height,
            "upgrade executable height before scheduled height",
        )?;
        let delay_blocks = request
            .executable_height
            .saturating_sub(request.scheduled_height);
        let required_delay = if request.emergency {
            config.emergency_delay_blocks
        } else {
            config.min_upgrade_delay_blocks
        };
        let timelock_satisfied =
            !config.upgrades_require_timelock || delay_blocks >= required_delay;
        Ok(Self {
            upgrade_id: request.upgrade_id,
            contract_id: request.contract_id,
            current_code_root: request.current_code_root,
            proposed_code_root: request.proposed_code_root,
            migration_root: request.migration_root,
            covenant_root_before: request.covenant_root_before.clone(),
            covenant_root_after: request.covenant_root_after.clone(),
            scheduled_height: request.scheduled_height,
            executable_height: request.executable_height,
            delay_blocks,
            emergency: request.emergency,
            pq_quorum_id: request.pq_quorum_id,
            status: request.status,
            rollback_code_root: request.rollback_code_root,
            timelock_satisfied,
            covenant_changed: request.covenant_root_before != request.covenant_root_after,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "contract_upgrade_record",
            "upgrade_id": self.upgrade_id,
            "contract_id": self.contract_id,
            "current_code_root": self.current_code_root,
            "proposed_code_root": self.proposed_code_root,
            "migration_root": self.migration_root,
            "covenant_root_before": self.covenant_root_before,
            "covenant_root_after": self.covenant_root_after,
            "scheduled_height": self.scheduled_height,
            "executable_height": self.executable_height,
            "delay_blocks": self.delay_blocks,
            "emergency": self.emergency,
            "pq_quorum_id": self.pq_quorum_id,
            "status": self.status.as_str(),
            "rollback_code_root": self.rollback_code_root,
            "timelock_satisfied": self.timelock_satisfied,
            "covenant_changed": self.covenant_changed,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("CONTRACT-UPGRADE", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryPermissionRequest {
    pub permission_id: String,
    pub vault_id: String,
    pub controller_commitment: String,
    pub asset_id: String,
    pub kind: TreasuryPermissionKind,
    pub status: TreasuryPermissionStatus,
    pub daily_limit: u64,
    pub per_action_limit: u64,
    pub spent_in_epoch: u64,
    pub pq_quorum_id: String,
    pub dual_control: bool,
    pub purpose_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreasuryPermissionRecord {
    pub permission_id: String,
    pub vault_id: String,
    pub controller_commitment: String,
    pub asset_id: String,
    pub kind: TreasuryPermissionKind,
    pub status: TreasuryPermissionStatus,
    pub daily_limit: u64,
    pub per_action_limit: u64,
    pub spent_in_epoch: u64,
    pub pq_quorum_id: String,
    pub dual_control: bool,
    pub purpose_commitment: String,
    pub limit_remaining: u64,
    pub over_policy_limit: bool,
}

impl TreasuryPermissionRecord {
    pub fn from_request(request: TreasuryPermissionRequest, config: &Config) -> Result<Self> {
        require_non_empty("permission_id", &request.permission_id)?;
        require_non_empty("vault_id", &request.vault_id)?;
        require_non_empty("controller_commitment", &request.controller_commitment)?;
        require_non_empty("asset_id", &request.asset_id)?;
        require_non_empty("pq_quorum_id", &request.pq_quorum_id)?;
        require_non_empty("purpose_commitment", &request.purpose_commitment)?;
        require_positive("daily_limit", request.daily_limit)?;
        require_positive("per_action_limit", request.per_action_limit)?;
        require(
            request.per_action_limit <= request.daily_limit,
            "treasury per-action limit above daily limit",
        )?;
        let limit_remaining = request.daily_limit.saturating_sub(request.spent_in_epoch);
        let over_policy_limit = request.daily_limit > config.treasury_daily_limit
            || (config.treasury_requires_dual_control && !request.dual_control);
        Ok(Self {
            permission_id: request.permission_id,
            vault_id: request.vault_id,
            controller_commitment: request.controller_commitment,
            asset_id: request.asset_id,
            kind: request.kind,
            status: request.status,
            daily_limit: request.daily_limit,
            per_action_limit: request.per_action_limit,
            spent_in_epoch: request.spent_in_epoch,
            pq_quorum_id: request.pq_quorum_id,
            dual_control: request.dual_control,
            purpose_commitment: request.purpose_commitment,
            limit_remaining,
            over_policy_limit,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "treasury_permission_record",
            "permission_id": self.permission_id,
            "vault_id": self.vault_id,
            "controller_commitment": self.controller_commitment,
            "asset_id": self.asset_id,
            "permission_kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "daily_limit": self.daily_limit,
            "per_action_limit": self.per_action_limit,
            "spent_in_epoch": self.spent_in_epoch,
            "pq_quorum_id": self.pq_quorum_id,
            "dual_control": self.dual_control,
            "purpose_commitment": self.purpose_commitment,
            "limit_remaining": self.limit_remaining,
            "over_policy_limit": self.over_policy_limit,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("TREASURY-PERMISSION", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CovenantDriftRequest {
    pub snapshot_id: String,
    pub subject_id: String,
    pub baseline_root: String,
    pub current_root: String,
    pub changed_key_root: String,
    pub drift_bps: u64,
    pub affected_contracts: u64,
    pub status: CovenantStatus,
    pub reviewer_quorum_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CovenantDriftRecord {
    pub snapshot_id: String,
    pub subject_id: String,
    pub baseline_root: String,
    pub current_root: String,
    pub changed_key_root: String,
    pub drift_bps: u64,
    pub affected_contracts: u64,
    pub status: CovenantStatus,
    pub reviewer_quorum_id: String,
    pub exceeds_policy: bool,
}

impl CovenantDriftRecord {
    pub fn from_request(request: CovenantDriftRequest, config: &Config) -> Result<Self> {
        require_non_empty("snapshot_id", &request.snapshot_id)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_non_empty("baseline_root", &request.baseline_root)?;
        require_non_empty("current_root", &request.current_root)?;
        require_non_empty("changed_key_root", &request.changed_key_root)?;
        require_non_empty("reviewer_quorum_id", &request.reviewer_quorum_id)?;
        require_bps("drift_bps", request.drift_bps)?;
        let exceeds_policy = request.drift_bps > config.max_covenant_drift_bps
            || matches!(
                request.status,
                CovenantStatus::DriftExceeded | CovenantStatus::Frozen
            );
        Ok(Self {
            snapshot_id: request.snapshot_id,
            subject_id: request.subject_id,
            baseline_root: request.baseline_root,
            current_root: request.current_root,
            changed_key_root: request.changed_key_root,
            drift_bps: request.drift_bps,
            affected_contracts: request.affected_contracts,
            status: request.status,
            reviewer_quorum_id: request.reviewer_quorum_id,
            exceeds_policy,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "covenant_drift_record",
            "snapshot_id": self.snapshot_id,
            "subject_id": self.subject_id,
            "baseline_root": self.baseline_root,
            "current_root": self.current_root,
            "changed_key_root": self.changed_key_root,
            "drift_bps": self.drift_bps,
            "affected_contracts": self.affected_contracts,
            "status": self.status.as_str(),
            "reviewer_quorum_id": self.reviewer_quorum_id,
            "exceeds_policy": self.exceeds_policy,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("COVENANT-DRIFT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateVotingDisclosureBudgetRequest {
    pub budget_id: String,
    pub proposal_id: String,
    pub vote_root: String,
    pub nullifier_root: String,
    pub eligible_voter_root: String,
    pub disclosure_budget: u64,
    pub disclosures_used: u64,
    pub selective_disclosure_root: String,
    pub status: DisclosureBudgetStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateVotingDisclosureBudgetRecord {
    pub budget_id: String,
    pub proposal_id: String,
    pub vote_root: String,
    pub nullifier_root: String,
    pub eligible_voter_root: String,
    pub disclosure_budget: u64,
    pub disclosures_used: u64,
    pub selective_disclosure_root: String,
    pub status: DisclosureBudgetStatus,
    pub remaining_budget: u64,
    pub usage_bps: u64,
}

impl PrivateVotingDisclosureBudgetRecord {
    pub fn from_request(
        request: PrivateVotingDisclosureBudgetRequest,
        config: &Config,
    ) -> Result<Self> {
        require_non_empty("budget_id", &request.budget_id)?;
        require_non_empty("proposal_id", &request.proposal_id)?;
        require_non_empty("vote_root", &request.vote_root)?;
        require_non_empty("nullifier_root", &request.nullifier_root)?;
        require_non_empty("eligible_voter_root", &request.eligible_voter_root)?;
        require_non_empty(
            "selective_disclosure_root",
            &request.selective_disclosure_root,
        )?;
        require_positive("disclosure_budget", request.disclosure_budget)?;
        require(
            request.disclosure_budget <= config.private_vote_disclosure_budget,
            "private voting disclosure budget above configured cap",
        )?;
        let remaining_budget = request
            .disclosure_budget
            .saturating_sub(request.disclosures_used);
        let usage_bps = bps(request.disclosures_used, request.disclosure_budget);
        Ok(Self {
            budget_id: request.budget_id,
            proposal_id: request.proposal_id,
            vote_root: request.vote_root,
            nullifier_root: request.nullifier_root,
            eligible_voter_root: request.eligible_voter_root,
            disclosure_budget: request.disclosure_budget,
            disclosures_used: request.disclosures_used,
            selective_disclosure_root: request.selective_disclosure_root,
            status: request.status,
            remaining_budget,
            usage_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "private_voting_disclosure_budget_record",
            "budget_id": self.budget_id,
            "proposal_id": self.proposal_id,
            "vote_root": self.vote_root,
            "nullifier_root": self.nullifier_root,
            "eligible_voter_root": self.eligible_voter_root,
            "disclosure_budget": self.disclosure_budget,
            "disclosures_used": self.disclosures_used,
            "selective_disclosure_root": self.selective_disclosure_root,
            "status": self.status.as_str(),
            "remaining_budget": self.remaining_budget,
            "usage_bps": self.usage_bps,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PRIVATE-VOTING-DISCLOSURE-BUDGET", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSignerQuorumRequest {
    pub quorum_id: String,
    pub signer_set_root: String,
    pub active_signers: u16,
    pub threshold_signers: u16,
    pub aggregate_weight: u64,
    pub threshold_weight: u64,
    pub min_security_bits: u16,
    pub status: PqSignerStatus,
    pub rotation_height: u64,
    pub compromised_signer_count: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqSignerQuorumRecord {
    pub quorum_id: String,
    pub signer_set_root: String,
    pub active_signers: u16,
    pub threshold_signers: u16,
    pub aggregate_weight: u64,
    pub threshold_weight: u64,
    pub min_security_bits: u16,
    pub status: PqSignerStatus,
    pub rotation_height: u64,
    pub compromised_signer_count: u16,
    pub quorum_satisfied: bool,
    pub pq_satisfied: bool,
    pub risk_score: u64,
}

impl PqSignerQuorumRecord {
    pub fn from_request(request: PqSignerQuorumRequest, config: &Config) -> Result<Self> {
        require_non_empty("quorum_id", &request.quorum_id)?;
        require_non_empty("signer_set_root", &request.signer_set_root)?;
        require_positive("active_signers", request.active_signers as u64)?;
        require_positive("threshold_signers", request.threshold_signers as u64)?;
        require_positive("aggregate_weight", request.aggregate_weight)?;
        require_positive("threshold_weight", request.threshold_weight)?;
        require(
            request.threshold_signers <= request.active_signers,
            "threshold signers above active signers",
        )?;
        require(
            request.threshold_weight <= request.aggregate_weight,
            "threshold weight above aggregate weight",
        )?;
        require_positive("min_security_bits", request.min_security_bits as u64)?;
        let quorum_satisfied = request.status.counts_for_quorum()
            && request.threshold_signers >= config.min_signer_quorum
            && request.threshold_weight >= config.min_signer_weight;
        let pq_satisfied = request.min_security_bits >= config.min_pq_security_bits;
        let mut risk_score = 0_u64;
        if !quorum_satisfied {
            risk_score = risk_score.saturating_add(45);
        }
        if !pq_satisfied {
            risk_score = risk_score.saturating_add(35);
        }
        risk_score = risk_score.saturating_add((request.compromised_signer_count as u64) * 20);
        if matches!(
            request.status,
            PqSignerStatus::Degraded | PqSignerStatus::Rotating
        ) {
            risk_score = risk_score.saturating_add(10);
        }
        Ok(Self {
            quorum_id: request.quorum_id,
            signer_set_root: request.signer_set_root,
            active_signers: request.active_signers,
            threshold_signers: request.threshold_signers,
            aggregate_weight: request.aggregate_weight,
            threshold_weight: request.threshold_weight,
            min_security_bits: request.min_security_bits,
            status: request.status,
            rotation_height: request.rotation_height,
            compromised_signer_count: request.compromised_signer_count,
            quorum_satisfied,
            pq_satisfied,
            risk_score: risk_score.min(100),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "pq_signer_quorum_record",
            "quorum_id": self.quorum_id,
            "signer_set_root": self.signer_set_root,
            "active_signers": self.active_signers,
            "threshold_signers": self.threshold_signers,
            "aggregate_weight": self.aggregate_weight,
            "threshold_weight": self.threshold_weight,
            "min_security_bits": self.min_security_bits,
            "status": self.status.as_str(),
            "rotation_height": self.rotation_height,
            "compromised_signer_count": self.compromised_signer_count,
            "quorum_satisfied": self.quorum_satisfied,
            "pq_satisfied": self.pq_satisfied,
            "risk_score": self.risk_score,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("PQ-SIGNER-QUORUM", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeProposalBatchRequest {
    pub batch_id: String,
    pub proposal_root: String,
    pub proposer_set_root: String,
    pub proposal_count: u64,
    pub aggregate_weight: u64,
    pub fee_bps: u64,
    pub fee_asset_id: String,
    pub status: BatchStatus,
    pub contains_upgrade: bool,
    pub contains_treasury_spend: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LowFeeProposalBatchRecord {
    pub batch_id: String,
    pub proposal_root: String,
    pub proposer_set_root: String,
    pub proposal_count: u64,
    pub aggregate_weight: u64,
    pub fee_bps: u64,
    pub fee_asset_id: String,
    pub status: BatchStatus,
    pub contains_upgrade: bool,
    pub contains_treasury_spend: bool,
    pub low_fee_eligible: bool,
    pub policy_weight_remaining: u64,
}

impl LowFeeProposalBatchRecord {
    pub fn from_request(request: LowFeeProposalBatchRequest, config: &Config) -> Result<Self> {
        require_non_empty("batch_id", &request.batch_id)?;
        require_non_empty("proposal_root", &request.proposal_root)?;
        require_non_empty("proposer_set_root", &request.proposer_set_root)?;
        require_non_empty("fee_asset_id", &request.fee_asset_id)?;
        require_positive("proposal_count", request.proposal_count)?;
        require_positive("aggregate_weight", request.aggregate_weight)?;
        require_bps("fee_bps", request.fee_bps)?;
        let low_fee_eligible = request.fee_bps <= config.max_low_fee_bps
            && request.aggregate_weight <= config.max_batch_weight
            && request.fee_asset_id == config.fee_asset_id
            && !request.contains_treasury_spend;
        let policy_weight_remaining = config
            .max_batch_weight
            .saturating_sub(request.aggregate_weight);
        Ok(Self {
            batch_id: request.batch_id,
            proposal_root: request.proposal_root,
            proposer_set_root: request.proposer_set_root,
            proposal_count: request.proposal_count,
            aggregate_weight: request.aggregate_weight,
            fee_bps: request.fee_bps,
            fee_asset_id: request.fee_asset_id,
            status: request.status,
            contains_upgrade: request.contains_upgrade,
            contains_treasury_spend: request.contains_treasury_spend,
            low_fee_eligible,
            policy_weight_remaining,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "low_fee_proposal_batch_record",
            "batch_id": self.batch_id,
            "proposal_root": self.proposal_root,
            "proposer_set_root": self.proposer_set_root,
            "proposal_count": self.proposal_count,
            "aggregate_weight": self.aggregate_weight,
            "fee_bps": self.fee_bps,
            "fee_asset_id": self.fee_asset_id,
            "status": self.status.as_str(),
            "contains_upgrade": self.contains_upgrade,
            "contains_treasury_spend": self.contains_treasury_spend,
            "low_fee_eligible": self.low_fee_eligible,
            "policy_weight_remaining": self.policy_weight_remaining,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("LOW-FEE-PROPOSAL-BATCH", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefiProtocolRiskFlagRequest {
    pub flag_id: String,
    pub protocol_id: String,
    pub kind: DefiRiskFlagKind,
    pub severity: FindingSeverity,
    pub metric_root: String,
    pub exposure_value: u64,
    pub risk_score: u64,
    pub privacy_set_size: u64,
    pub bridge_dependency_asset: String,
    pub active: bool,
    pub mitigation_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DefiProtocolRiskFlagRecord {
    pub flag_id: String,
    pub protocol_id: String,
    pub kind: DefiRiskFlagKind,
    pub severity: FindingSeverity,
    pub metric_root: String,
    pub exposure_value: u64,
    pub risk_score: u64,
    pub privacy_set_size: u64,
    pub bridge_dependency_asset: String,
    pub active: bool,
    pub mitigation_root: String,
    pub exceeds_policy: bool,
}

impl DefiProtocolRiskFlagRecord {
    pub fn from_request(request: DefiProtocolRiskFlagRequest, config: &Config) -> Result<Self> {
        require_non_empty("flag_id", &request.flag_id)?;
        require_non_empty("protocol_id", &request.protocol_id)?;
        require_non_empty("metric_root", &request.metric_root)?;
        require_non_empty("bridge_dependency_asset", &request.bridge_dependency_asset)?;
        require_non_empty("mitigation_root", &request.mitigation_root)?;
        require_bps("risk_score", request.risk_score)?;
        require_positive("privacy_set_size", request.privacy_set_size)?;
        let exceeds_policy = request.risk_score > config.max_defi_risk_score
            || request.privacy_set_size < config.min_privacy_set_size
            || request.severity.blocks_release();
        Ok(Self {
            flag_id: request.flag_id,
            protocol_id: request.protocol_id,
            kind: request.kind,
            severity: request.severity,
            metric_root: request.metric_root,
            exposure_value: request.exposure_value,
            risk_score: request.risk_score,
            privacy_set_size: request.privacy_set_size,
            bridge_dependency_asset: request.bridge_dependency_asset,
            active: request.active,
            mitigation_root: request.mitigation_root,
            exceeds_policy,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "defi_protocol_risk_flag_record",
            "flag_id": self.flag_id,
            "protocol_id": self.protocol_id,
            "risk_kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "metric_root": self.metric_root,
            "exposure_value": self.exposure_value,
            "risk_score": self.risk_score,
            "privacy_set_size": self.privacy_set_size,
            "bridge_dependency_asset": self.bridge_dependency_asset,
            "active": self.active,
            "mitigation_root": self.mitigation_root,
            "exceeds_policy": self.exceeds_policy,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("DEFI-PROTOCOL-RISK-FLAG", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeAssetRegistryRequest {
    pub asset_id: String,
    pub origin_chain: String,
    pub origin_asset_commitment: String,
    pub reserve_proof_root: String,
    pub risk_review_root: String,
    pub status: BridgeAssetStatus,
    pub confirmations_required: u64,
    pub wrapped_token_policy_id: String,
    pub guardian_quorum_id: String,
    pub deposits_enabled: bool,
    pub withdrawals_enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeAssetRegistryRecord {
    pub asset_id: String,
    pub origin_chain: String,
    pub origin_asset_commitment: String,
    pub reserve_proof_root: String,
    pub risk_review_root: String,
    pub status: BridgeAssetStatus,
    pub confirmations_required: u64,
    pub wrapped_token_policy_id: String,
    pub guardian_quorum_id: String,
    pub deposits_enabled: bool,
    pub withdrawals_enabled: bool,
    pub registry_ready: bool,
}

impl BridgeAssetRegistryRecord {
    pub fn from_request(request: BridgeAssetRegistryRequest, config: &Config) -> Result<Self> {
        require_non_empty("asset_id", &request.asset_id)?;
        require_non_empty("origin_chain", &request.origin_chain)?;
        require_non_empty("origin_asset_commitment", &request.origin_asset_commitment)?;
        require_non_empty("reserve_proof_root", &request.reserve_proof_root)?;
        require_non_empty("risk_review_root", &request.risk_review_root)?;
        require_non_empty("wrapped_token_policy_id", &request.wrapped_token_policy_id)?;
        require_non_empty("guardian_quorum_id", &request.guardian_quorum_id)?;
        require_positive("confirmations_required", request.confirmations_required)?;
        let registry_ready = matches!(
            request.status,
            BridgeAssetStatus::Listed | BridgeAssetStatus::Watchlisted
        ) && request.confirmations_required >= config.min_bridge_confirmations
            && (!config.bridge_registry_requires_risk_review || request.risk_review_root != "none")
            && request.deposits_enabled
            && request.withdrawals_enabled;
        Ok(Self {
            asset_id: request.asset_id,
            origin_chain: request.origin_chain,
            origin_asset_commitment: request.origin_asset_commitment,
            reserve_proof_root: request.reserve_proof_root,
            risk_review_root: request.risk_review_root,
            status: request.status,
            confirmations_required: request.confirmations_required,
            wrapped_token_policy_id: request.wrapped_token_policy_id,
            guardian_quorum_id: request.guardian_quorum_id,
            deposits_enabled: request.deposits_enabled,
            withdrawals_enabled: request.withdrawals_enabled,
            registry_ready,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "bridge_asset_registry_record",
            "asset_id": self.asset_id,
            "origin_chain": self.origin_chain,
            "origin_asset_commitment": self.origin_asset_commitment,
            "reserve_proof_root": self.reserve_proof_root,
            "risk_review_root": self.risk_review_root,
            "status": self.status.as_str(),
            "confirmations_required": self.confirmations_required,
            "wrapped_token_policy_id": self.wrapped_token_policy_id,
            "guardian_quorum_id": self.guardian_quorum_id,
            "deposits_enabled": self.deposits_enabled,
            "withdrawals_enabled": self.withdrawals_enabled,
            "registry_ready": self.registry_ready,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("BRIDGE-ASSET-REGISTRY", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReadinessFindingRequest {
    pub finding_id: String,
    pub domain: GovernanceDomain,
    pub subject_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub summary: String,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub owner_commitment: String,
    pub release_gate: ReleaseGateStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseReadinessFindingRecord {
    pub finding_id: String,
    pub domain: GovernanceDomain,
    pub subject_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub summary: String,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub owner_commitment: String,
    pub release_gate: ReleaseGateStatus,
    pub blocks_release: bool,
}

impl ReleaseReadinessFindingRecord {
    pub fn from_request(request: ReleaseReadinessFindingRequest, config: &Config) -> Result<Self> {
        require_non_empty("finding_id", &request.finding_id)?;
        require_non_empty("subject_id", &request.subject_id)?;
        require_non_empty("summary", &request.summary)?;
        require_non_empty("evidence_root", &request.evidence_root)?;
        require_non_empty("mitigation_root", &request.mitigation_root)?;
        require_non_empty("owner_commitment", &request.owner_commitment)?;
        let blocks_release = config.release_blocks_on_high
            && request.status.active()
            && (request.severity.blocks_release()
                || matches!(request.release_gate, ReleaseGateStatus::Blocking));
        Ok(Self {
            finding_id: request.finding_id,
            domain: request.domain,
            subject_id: request.subject_id,
            severity: request.severity,
            status: request.status,
            summary: request.summary,
            evidence_root: request.evidence_root,
            mitigation_root: request.mitigation_root,
            owner_commitment: request.owner_commitment,
            release_gate: request.release_gate,
            blocks_release,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "release_readiness_finding_record",
            "finding_id": self.finding_id,
            "domain": self.domain.as_str(),
            "subject_id": self.subject_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "summary": self.summary,
            "evidence_root": self.evidence_root,
            "mitigation_root": self.mitigation_root,
            "owner_commitment": self.owner_commitment,
            "release_gate": self.release_gate.as_str(),
            "blocks_release": self.blocks_release,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("RELEASE-READINESS-FINDING", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceAuditPublicEvent {
    pub event_id: String,
    pub domain: GovernanceDomain,
    pub subject_id: String,
    pub record_root: String,
    pub severity: FindingSeverity,
    pub message: String,
}

impl GovernanceAuditPublicEvent {
    pub fn new(
        domain: GovernanceDomain,
        subject_id: &str,
        record_root: &str,
        severity: FindingSeverity,
        message: &str,
    ) -> Self {
        let record = json!({
            "domain": domain.as_str(),
            "subject_id": subject_id,
            "record_root": record_root,
            "severity": severity.as_str(),
            "message": message,
        });
        Self {
            event_id: id_from_record("GOVERNANCE-AUDIT-PUBLIC-EVENT-ID", &record),
            domain,
            subject_id: subject_id.to_string(),
            record_root: record_root.to_string(),
            severity,
            message: message.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "governance_audit_public_event",
            "event_id": self.event_id,
            "domain": self.domain.as_str(),
            "subject_id": self.subject_id,
            "record_root": self.record_root,
            "severity": self.severity.as_str(),
            "message": self.message,
        })
    }

    pub fn state_root(&self) -> String {
        payload_root("GOVERNANCE-AUDIT-PUBLIC-EVENT", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub token_policies: BTreeMap<String, TokenFactoryPolicyRecord>,
    pub upgrade_plans: BTreeMap<String, ContractUpgradeRecord>,
    pub treasury_permissions: BTreeMap<String, TreasuryPermissionRecord>,
    pub covenant_snapshots: BTreeMap<String, CovenantDriftRecord>,
    pub disclosure_budgets: BTreeMap<String, PrivateVotingDisclosureBudgetRecord>,
    pub signer_quorums: BTreeMap<String, PqSignerQuorumRecord>,
    pub proposal_batches: BTreeMap<String, LowFeeProposalBatchRecord>,
    pub defi_flags: BTreeMap<String, DefiProtocolRiskFlagRecord>,
    pub bridge_assets: BTreeMap<String, BridgeAssetRegistryRecord>,
    pub findings: BTreeMap<String, ReleaseReadinessFindingRecord>,
    pub public_events: BTreeMap<String, GovernanceAuditPublicEvent>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            token_policies: BTreeMap::new(),
            upgrade_plans: BTreeMap::new(),
            treasury_permissions: BTreeMap::new(),
            covenant_snapshots: BTreeMap::new(),
            disclosure_budgets: BTreeMap::new(),
            signer_quorums: BTreeMap::new(),
            proposal_batches: BTreeMap::new(),
            defi_flags: BTreeMap::new(),
            bridge_assets: BTreeMap::new(),
            findings: BTreeMap::new(),
            public_events: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::devnet()) {
            Ok(state) => state,
            Err(_) => Self {
                config: Config::default(),
                token_policies: BTreeMap::new(),
                upgrade_plans: BTreeMap::new(),
                treasury_permissions: BTreeMap::new(),
                covenant_snapshots: BTreeMap::new(),
                disclosure_budgets: BTreeMap::new(),
                signer_quorums: BTreeMap::new(),
                proposal_batches: BTreeMap::new(),
                defi_flags: BTreeMap::new(),
                bridge_assets: BTreeMap::new(),
                findings: BTreeMap::new(),
                public_events: BTreeMap::new(),
            },
        }
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();

        let mut capabilities = BTreeSet::new();
        capabilities.insert(ConfidentialTokenCapability::Mint);
        capabilities.insert(ConfidentialTokenCapability::Burn);
        capabilities.insert(ConfidentialTokenCapability::ConfidentialTransfer);
        capabilities.insert(ConfidentialTokenCapability::SelectiveDisclosure);
        capabilities.insert(ConfidentialTokenCapability::DefiCollateral);
        let _ = state.register_token_policy(TokenFactoryPolicyRequest {
            policy_id: "ctoken-dusd-governance-v1".to_string(),
            issuer_commitment: demo_root("issuer-dusd"),
            metadata_commitment: demo_root("metadata-dusd"),
            supply_cap_commitment: demo_root("supply-cap-dusd"),
            capabilities,
            status: TokenPolicyStatus::Active,
            pq_quorum_id: "pq-quorum-core".to_string(),
            privacy_set_size: 131_072,
            mint_limit_per_epoch: 10_000_000_000,
            max_admin_fee_bps: 20,
            requires_council_vote: true,
            allows_unbounded_mint: false,
            notes_commitment: demo_root("token-policy-notes"),
        });

        let _ = state.register_signer_quorum(PqSignerQuorumRequest {
            quorum_id: "pq-quorum-core".to_string(),
            signer_set_root: demo_root("signer-set-core"),
            active_signers: 7,
            threshold_signers: 5,
            aggregate_weight: 100,
            threshold_weight: 72,
            min_security_bits: 256,
            status: PqSignerStatus::Active,
            rotation_height: state.config.audit_epoch.saturating_add(50_400),
            compromised_signer_count: 0,
        });

        let _ = state.register_upgrade_plan(ContractUpgradeRequest {
            upgrade_id: "upgrade-private-amm-v2".to_string(),
            contract_id: "private-amm-core".to_string(),
            current_code_root: demo_root("amm-v1-code"),
            proposed_code_root: demo_root("amm-v2-code"),
            migration_root: demo_root("amm-v2-migration"),
            covenant_root_before: demo_root("amm-covenant-v1"),
            covenant_root_after: demo_root("amm-covenant-v2"),
            scheduled_height: state.config.audit_epoch,
            executable_height: state
                .config
                .audit_epoch
                .saturating_add(state.config.min_upgrade_delay_blocks),
            emergency: false,
            pq_quorum_id: "pq-quorum-core".to_string(),
            status: UpgradeStatus::Timelocked,
            rollback_code_root: demo_root("amm-v1-rollback"),
        });

        let _ = state.register_treasury_permission(TreasuryPermissionRequest {
            permission_id: "treasury-fee-sponsor-dusd".to_string(),
            vault_id: "private-treasury-main".to_string(),
            controller_commitment: demo_root("treasury-controller"),
            asset_id: state.config.fee_asset_id.clone(),
            kind: TreasuryPermissionKind::SponsorFees,
            status: TreasuryPermissionStatus::Active,
            daily_limit: 12_000_000_000,
            per_action_limit: 300_000_000,
            spent_in_epoch: 1_000_000_000,
            pq_quorum_id: "pq-quorum-core".to_string(),
            dual_control: true,
            purpose_commitment: demo_root("sponsor-low-fee-governance"),
        });

        let _ = state.register_covenant_snapshot(CovenantDriftRequest {
            snapshot_id: "covenant-private-amm-v2".to_string(),
            subject_id: "private-amm-core".to_string(),
            baseline_root: demo_root("amm-covenant-v1"),
            current_root: demo_root("amm-covenant-v2"),
            changed_key_root: demo_root("amm-covenant-diff"),
            drift_bps: 41,
            affected_contracts: 2,
            status: CovenantStatus::WithinTolerance,
            reviewer_quorum_id: "pq-quorum-core".to_string(),
        });

        let _ = state.register_disclosure_budget(PrivateVotingDisclosureBudgetRequest {
            budget_id: "vote-budget-amm-v2".to_string(),
            proposal_id: "upgrade-private-amm-v2".to_string(),
            vote_root: demo_root("private-vote-root"),
            nullifier_root: demo_root("vote-nullifier-root"),
            eligible_voter_root: demo_root("eligible-voter-root"),
            disclosure_budget: 64,
            disclosures_used: 9,
            selective_disclosure_root: demo_root("selective-disclosure-root"),
            status: DisclosureBudgetStatus::Open,
        });

        let _ = state.register_proposal_batch(LowFeeProposalBatchRequest {
            batch_id: "low-fee-governance-batch-001".to_string(),
            proposal_root: demo_root("batch-proposal-root"),
            proposer_set_root: demo_root("batch-proposer-set"),
            proposal_count: 12,
            aggregate_weight: 2_700,
            fee_bps: 7,
            fee_asset_id: state.config.fee_asset_id.clone(),
            status: BatchStatus::Accepted,
            contains_upgrade: true,
            contains_treasury_spend: false,
        });

        let _ = state.register_defi_flag(DefiProtocolRiskFlagRequest {
            flag_id: "risk-private-lending-oracle".to_string(),
            protocol_id: "private-lending-core".to_string(),
            kind: DefiRiskFlagKind::OracleDrift,
            severity: FindingSeverity::Medium,
            metric_root: demo_root("oracle-drift-metrics"),
            exposure_value: 8_000_000_000,
            risk_score: 58,
            privacy_set_size: 98_304,
            bridge_dependency_asset: "wxmr-devnet".to_string(),
            active: true,
            mitigation_root: demo_root("oracle-mitigation-plan"),
        });

        let _ = state.register_bridge_asset(BridgeAssetRegistryRequest {
            asset_id: "wxmr-devnet".to_string(),
            origin_chain: "monero-devnet".to_string(),
            origin_asset_commitment: demo_root("xmr-origin-asset"),
            reserve_proof_root: demo_root("xmr-reserve-proof"),
            risk_review_root: demo_root("xmr-risk-review"),
            status: BridgeAssetStatus::Listed,
            confirmations_required: 12,
            wrapped_token_policy_id: "ctoken-dusd-governance-v1".to_string(),
            guardian_quorum_id: "pq-quorum-core".to_string(),
            deposits_enabled: true,
            withdrawals_enabled: true,
        });

        state.audit_release_readiness();
        state
    }

    pub fn register_token_policy(&mut self, request: TokenFactoryPolicyRequest) -> Result<String> {
        require_capacity(
            "token_policies",
            self.token_policies.len(),
            self.config.max_token_policies,
        )?;
        let record = TokenFactoryPolicyRecord::from_request(request, &self.config)?;
        let id = record.policy_id.clone();
        let root = record.state_root();
        self.token_policies.insert(id.clone(), record.clone());
        if !record.release_ready {
            self.add_finding(
                GovernanceDomain::TokenFactory,
                &id,
                FindingSeverity::High,
                "token factory policy is not release-ready",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::TokenFactory,
            &id,
            &root,
            if record.release_ready {
                FindingSeverity::Info
            } else {
                FindingSeverity::High
            },
            "token factory policy audited",
        )?;
        Ok(id)
    }

    pub fn register_upgrade_plan(&mut self, request: ContractUpgradeRequest) -> Result<String> {
        require_capacity(
            "upgrade_plans",
            self.upgrade_plans.len(),
            self.config.max_upgrade_plans,
        )?;
        let record = ContractUpgradeRecord::from_request(request, &self.config)?;
        let id = record.upgrade_id.clone();
        let root = record.state_root();
        self.upgrade_plans.insert(id.clone(), record.clone());
        if !record.timelock_satisfied {
            self.add_finding(
                GovernanceDomain::ContractUpgrade,
                &id,
                FindingSeverity::Critical,
                "contract upgrade timelock does not satisfy policy",
                &root,
            )?;
        } else if record.covenant_changed {
            self.add_finding(
                GovernanceDomain::Covenant,
                &id,
                FindingSeverity::Low,
                "contract upgrade changes covenant root and needs drift review",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::ContractUpgrade,
            &id,
            &root,
            if record.timelock_satisfied {
                FindingSeverity::Info
            } else {
                FindingSeverity::Critical
            },
            "contract upgrade timelock audited",
        )?;
        Ok(id)
    }

    pub fn register_treasury_permission(
        &mut self,
        request: TreasuryPermissionRequest,
    ) -> Result<String> {
        require_capacity(
            "treasury_permissions",
            self.treasury_permissions.len(),
            self.config.max_treasury_permissions,
        )?;
        let record = TreasuryPermissionRecord::from_request(request, &self.config)?;
        let id = record.permission_id.clone();
        let root = record.state_root();
        self.treasury_permissions.insert(id.clone(), record.clone());
        if record.over_policy_limit {
            self.add_finding(
                GovernanceDomain::Treasury,
                &id,
                FindingSeverity::High,
                "treasury permission exceeds configured spend or dual-control policy",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::Treasury,
            &id,
            &root,
            if record.over_policy_limit {
                FindingSeverity::High
            } else {
                FindingSeverity::Info
            },
            "treasury permission audited",
        )?;
        Ok(id)
    }

    pub fn register_covenant_snapshot(&mut self, request: CovenantDriftRequest) -> Result<String> {
        require_capacity(
            "covenant_snapshots",
            self.covenant_snapshots.len(),
            self.config.max_covenant_snapshots,
        )?;
        let record = CovenantDriftRecord::from_request(request, &self.config)?;
        let id = record.snapshot_id.clone();
        let root = record.state_root();
        self.covenant_snapshots.insert(id.clone(), record.clone());
        if record.exceeds_policy {
            self.add_finding(
                GovernanceDomain::Covenant,
                &id,
                FindingSeverity::High,
                "covenant drift exceeds policy tolerance",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::Covenant,
            &id,
            &root,
            if record.exceeds_policy {
                FindingSeverity::High
            } else {
                FindingSeverity::Info
            },
            "covenant drift audited",
        )?;
        Ok(id)
    }

    pub fn register_disclosure_budget(
        &mut self,
        request: PrivateVotingDisclosureBudgetRequest,
    ) -> Result<String> {
        require_capacity(
            "disclosure_budgets",
            self.disclosure_budgets.len(),
            self.config.max_disclosure_budgets,
        )?;
        let record = PrivateVotingDisclosureBudgetRecord::from_request(request, &self.config)?;
        let id = record.budget_id.clone();
        let root = record.state_root();
        self.disclosure_budgets.insert(id.clone(), record.clone());
        if record.remaining_budget == 0
            || matches!(record.status, DisclosureBudgetStatus::Exhausted)
        {
            self.add_finding(
                GovernanceDomain::PrivateVoting,
                &id,
                FindingSeverity::Medium,
                "private voting disclosure budget is exhausted",
                &root,
            )?;
        } else if record.usage_bps >= 8_000 {
            self.add_finding(
                GovernanceDomain::PrivateVoting,
                &id,
                FindingSeverity::Low,
                "private voting disclosure budget is near limit",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::PrivateVoting,
            &id,
            &root,
            if record.usage_bps >= 8_000 {
                FindingSeverity::Low
            } else {
                FindingSeverity::Info
            },
            "private voting disclosure budget audited",
        )?;
        Ok(id)
    }

    pub fn register_signer_quorum(&mut self, request: PqSignerQuorumRequest) -> Result<String> {
        require_capacity(
            "signer_quorums",
            self.signer_quorums.len(),
            self.config.max_signer_quorums,
        )?;
        let record = PqSignerQuorumRecord::from_request(request, &self.config)?;
        let id = record.quorum_id.clone();
        let root = record.state_root();
        self.signer_quorums.insert(id.clone(), record.clone());
        if !record.quorum_satisfied || !record.pq_satisfied {
            self.add_finding(
                GovernanceDomain::PqSignerQuorum,
                &id,
                FindingSeverity::Critical,
                "pq signer quorum fails threshold or security-bit policy",
                &root,
            )?;
        } else if record.risk_score >= 50 {
            self.add_finding(
                GovernanceDomain::PqSignerQuorum,
                &id,
                FindingSeverity::Medium,
                "pq signer quorum risk score is elevated",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::PqSignerQuorum,
            &id,
            &root,
            if record.quorum_satisfied && record.pq_satisfied {
                FindingSeverity::Info
            } else {
                FindingSeverity::Critical
            },
            "pq signer quorum audited",
        )?;
        Ok(id)
    }

    pub fn register_proposal_batch(
        &mut self,
        request: LowFeeProposalBatchRequest,
    ) -> Result<String> {
        require_capacity(
            "proposal_batches",
            self.proposal_batches.len(),
            self.config.max_batches,
        )?;
        let record = LowFeeProposalBatchRecord::from_request(request, &self.config)?;
        let id = record.batch_id.clone();
        let root = record.state_root();
        self.proposal_batches.insert(id.clone(), record.clone());
        if !record.low_fee_eligible {
            self.add_finding(
                GovernanceDomain::ProposalBatching,
                &id,
                FindingSeverity::Medium,
                "proposal batch is not eligible for low-fee lane",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::ProposalBatching,
            &id,
            &root,
            if record.low_fee_eligible {
                FindingSeverity::Info
            } else {
                FindingSeverity::Medium
            },
            "low-fee proposal batch audited",
        )?;
        Ok(id)
    }

    pub fn register_defi_flag(&mut self, request: DefiProtocolRiskFlagRequest) -> Result<String> {
        require_capacity(
            "defi_flags",
            self.defi_flags.len(),
            self.config.max_defi_flags,
        )?;
        let record = DefiProtocolRiskFlagRecord::from_request(request, &self.config)?;
        let id = record.flag_id.clone();
        let root = record.state_root();
        self.defi_flags.insert(id.clone(), record.clone());
        if record.exceeds_policy && record.active {
            self.add_finding(
                GovernanceDomain::DefiRisk,
                &id,
                record.severity,
                "active defi protocol risk flag exceeds release policy",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::DefiRisk,
            &id,
            &root,
            record.severity,
            "defi protocol risk flag audited",
        )?;
        Ok(id)
    }

    pub fn register_bridge_asset(&mut self, request: BridgeAssetRegistryRequest) -> Result<String> {
        require_capacity(
            "bridge_assets",
            self.bridge_assets.len(),
            self.config.max_bridge_assets,
        )?;
        let record = BridgeAssetRegistryRecord::from_request(request, &self.config)?;
        let id = record.asset_id.clone();
        let root = record.state_root();
        self.bridge_assets.insert(id.clone(), record.clone());
        if !record.registry_ready {
            self.add_finding(
                GovernanceDomain::BridgeAssetRegistry,
                &id,
                FindingSeverity::High,
                "bridge asset registry entry is not governance-ready",
                &root,
            )?;
        }
        self.add_event(
            GovernanceDomain::BridgeAssetRegistry,
            &id,
            &root,
            if record.registry_ready {
                FindingSeverity::Info
            } else {
                FindingSeverity::High
            },
            "bridge asset registry governance audited",
        )?;
        Ok(id)
    }

    pub fn register_release_finding(
        &mut self,
        request: ReleaseReadinessFindingRequest,
    ) -> Result<String> {
        require_capacity("findings", self.findings.len(), self.config.max_findings)?;
        let record = ReleaseReadinessFindingRecord::from_request(request, &self.config)?;
        let id = record.finding_id.clone();
        let root = record.state_root();
        self.findings.insert(id.clone(), record.clone());
        self.add_event(
            GovernanceDomain::ReleaseReadiness,
            &id,
            &root,
            record.severity,
            "release readiness finding recorded",
        )?;
        Ok(id)
    }

    pub fn audit_release_readiness(&mut self) {
        let roots = self.roots();
        let summary_root = roots.state_root();
        if self
            .signer_quorums
            .values()
            .all(|quorum| quorum.quorum_satisfied && quorum.pq_satisfied)
        {
            let _ = self.register_release_finding(ReleaseReadinessFindingRequest {
                finding_id: "release-pq-quorum-pass".to_string(),
                domain: GovernanceDomain::PqSignerQuorum,
                subject_id: "all-pq-quorums".to_string(),
                severity: FindingSeverity::Info,
                status: FindingStatus::Mitigated,
                summary: "all registered pq signer quorums satisfy configured thresholds"
                    .to_string(),
                evidence_root: summary_root.clone(),
                mitigation_root: demo_root("no-mitigation-required"),
                owner_commitment: demo_root("release-council"),
                release_gate: ReleaseGateStatus::Passing,
            });
        }
        if self
            .upgrade_plans
            .values()
            .any(|upgrade| upgrade.status.pending() && !upgrade.timelock_satisfied)
        {
            let _ = self.register_release_finding(ReleaseReadinessFindingRequest {
                finding_id: "release-upgrade-timelock-blocker".to_string(),
                domain: GovernanceDomain::ContractUpgrade,
                subject_id: "pending-upgrades".to_string(),
                severity: FindingSeverity::Critical,
                status: FindingStatus::Open,
                summary: "one or more pending upgrades fail timelock policy".to_string(),
                evidence_root: summary_root.clone(),
                mitigation_root: demo_root("extend-upgrade-delay"),
                owner_commitment: demo_root("upgrade-council"),
                release_gate: ReleaseGateStatus::Blocking,
            });
        }
        if self
            .defi_flags
            .values()
            .any(|flag| flag.active && flag.exceeds_policy)
        {
            let _ = self.register_release_finding(ReleaseReadinessFindingRequest {
                finding_id: "release-defi-risk-review-required".to_string(),
                domain: GovernanceDomain::DefiRisk,
                subject_id: "active-defi-flags".to_string(),
                severity: FindingSeverity::High,
                status: FindingStatus::Open,
                summary: "active defi flags exceed configured risk policy".to_string(),
                evidence_root: summary_root,
                mitigation_root: demo_root("defi-risk-mitigation"),
                owner_commitment: demo_root("risk-council"),
                release_gate: ReleaseGateStatus::Warning,
            });
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            token_policies: self.token_policies.len() as u64,
            active_token_policies: self
                .token_policies
                .values()
                .filter(|record| record.status.live())
                .count() as u64,
            upgrade_plans: self.upgrade_plans.len() as u64,
            pending_upgrades: self
                .upgrade_plans
                .values()
                .filter(|record| record.status.pending())
                .count() as u64,
            treasury_permissions: self.treasury_permissions.len() as u64,
            usable_treasury_permissions: self
                .treasury_permissions
                .values()
                .filter(|record| record.status.usable())
                .count() as u64,
            covenant_snapshots: self.covenant_snapshots.len() as u64,
            disclosure_budgets: self.disclosure_budgets.len() as u64,
            exhausted_disclosure_budgets: self
                .disclosure_budgets
                .values()
                .filter(|record| record.remaining_budget == 0)
                .count() as u64,
            signer_quorums: self.signer_quorums.len() as u64,
            signer_quorums_below_threshold: self
                .signer_quorums
                .values()
                .filter(|record| !record.quorum_satisfied || !record.pq_satisfied)
                .count() as u64,
            proposal_batches: self.proposal_batches.len() as u64,
            low_fee_batches: self
                .proposal_batches
                .values()
                .filter(|record| record.low_fee_eligible)
                .count() as u64,
            defi_flags: self.defi_flags.len() as u64,
            active_defi_flags: self
                .defi_flags
                .values()
                .filter(|record| record.active)
                .count() as u64,
            bridge_assets: self.bridge_assets.len() as u64,
            listed_bridge_assets: self
                .bridge_assets
                .values()
                .filter(|record| matches!(record.status, BridgeAssetStatus::Listed))
                .count() as u64,
            findings: self.findings.len() as u64,
            active_findings: self
                .findings
                .values()
                .filter(|record| record.status.active())
                .count() as u64,
            release_blocking_findings: self
                .findings
                .values()
                .filter(|record| record.blocks_release)
                .count() as u64,
            public_events: self.public_events.len() as u64,
        }
    }

    pub fn roots(&self) -> Roots {
        let counters = self.counters();
        Roots {
            config_root: self.config.state_root(),
            token_policy_root: map_root(
                "TOKEN-FACTORY-POLICIES",
                &self.token_policies,
                TokenFactoryPolicyRecord::public_record,
            ),
            upgrade_plan_root: map_root(
                "CONTRACT-UPGRADE-PLANS",
                &self.upgrade_plans,
                ContractUpgradeRecord::public_record,
            ),
            treasury_permission_root: map_root(
                "TREASURY-PERMISSIONS",
                &self.treasury_permissions,
                TreasuryPermissionRecord::public_record,
            ),
            covenant_snapshot_root: map_root(
                "COVENANT-SNAPSHOTS",
                &self.covenant_snapshots,
                CovenantDriftRecord::public_record,
            ),
            disclosure_budget_root: map_root(
                "PRIVATE-VOTING-DISCLOSURE-BUDGETS",
                &self.disclosure_budgets,
                PrivateVotingDisclosureBudgetRecord::public_record,
            ),
            signer_quorum_root: map_root(
                "PQ-SIGNER-QUORUMS",
                &self.signer_quorums,
                PqSignerQuorumRecord::public_record,
            ),
            proposal_batch_root: map_root(
                "LOW-FEE-PROPOSAL-BATCHES",
                &self.proposal_batches,
                LowFeeProposalBatchRecord::public_record,
            ),
            defi_risk_flag_root: map_root(
                "DEFI-RISK-FLAGS",
                &self.defi_flags,
                DefiProtocolRiskFlagRecord::public_record,
            ),
            bridge_asset_root: map_root(
                "BRIDGE-ASSET-REGISTRY",
                &self.bridge_assets,
                BridgeAssetRegistryRecord::public_record,
            ),
            release_finding_root: map_root(
                "RELEASE-READINESS-FINDINGS",
                &self.findings,
                ReleaseReadinessFindingRecord::public_record,
            ),
            public_event_root: map_root(
                "GOVERNANCE-AUDIT-PUBLIC-EVENTS",
                &self.public_events,
                GovernanceAuditPublicEvent::public_record,
            ),
            counters_root: counters.state_root(),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        let record = json!({
            "kind": "private_l2_pq_confidential_token_contract_governance_audit_state",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "token_policies": map_records(&self.token_policies, TokenFactoryPolicyRecord::public_record),
            "upgrade_plans": map_records(&self.upgrade_plans, ContractUpgradeRecord::public_record),
            "treasury_permissions": map_records(&self.treasury_permissions, TreasuryPermissionRecord::public_record),
            "covenant_snapshots": map_records(&self.covenant_snapshots, CovenantDriftRecord::public_record),
            "disclosure_budgets": map_records(&self.disclosure_budgets, PrivateVotingDisclosureBudgetRecord::public_record),
            "signer_quorums": map_records(&self.signer_quorums, PqSignerQuorumRecord::public_record),
            "proposal_batches": map_records(&self.proposal_batches, LowFeeProposalBatchRecord::public_record),
            "defi_flags": map_records(&self.defi_flags, DefiProtocolRiskFlagRecord::public_record),
            "bridge_assets": map_records(&self.bridge_assets, BridgeAssetRegistryRecord::public_record),
            "findings": map_records(&self.findings, ReleaseReadinessFindingRecord::public_record),
            "public_events": map_records(&self.public_events, GovernanceAuditPublicEvent::public_record),
        });
        let state_root = state_root_from_record(&record);
        json!({
            "state_root": state_root,
            "record": record,
        })
    }

    pub fn state_root(&self) -> String {
        let record = json!({
            "kind": "private_l2_pq_confidential_token_contract_governance_audit_state_root_record",
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_SCHEMA_VERSION,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
        });
        state_root_from_record(&record)
    }

    fn add_event(
        &mut self,
        domain: GovernanceDomain,
        subject_id: &str,
        record_root: &str,
        severity: FindingSeverity,
        message: &str,
    ) -> Result<()> {
        require_capacity(
            "public_events",
            self.public_events.len(),
            self.config.max_public_events,
        )?;
        let event =
            GovernanceAuditPublicEvent::new(domain, subject_id, record_root, severity, message);
        self.public_events.insert(event.event_id.clone(), event);
        Ok(())
    }

    fn add_finding(
        &mut self,
        domain: GovernanceDomain,
        subject_id: &str,
        severity: FindingSeverity,
        summary: &str,
        evidence_root: &str,
    ) -> Result<()> {
        require_capacity("findings", self.findings.len(), self.config.max_findings)?;
        let seed = json!({
            "domain": domain.as_str(),
            "subject_id": subject_id,
            "severity": severity.as_str(),
            "summary": summary,
            "evidence_root": evidence_root,
        });
        let finding_id = id_from_record("AUTO-RELEASE-FINDING-ID", &seed);
        if self.findings.contains_key(&finding_id) {
            return Ok(());
        }
        let finding = ReleaseReadinessFindingRecord::from_request(
            ReleaseReadinessFindingRequest {
                finding_id,
                domain,
                subject_id: subject_id.to_string(),
                severity,
                status: FindingStatus::Open,
                summary: summary.to_string(),
                evidence_root: evidence_root.to_string(),
                mitigation_root: demo_root("mitigation-required"),
                owner_commitment: demo_root("governance-audit-owner"),
                release_gate: if severity.blocks_release() {
                    ReleaseGateStatus::Blocking
                } else if matches!(severity, FindingSeverity::Medium) {
                    ReleaseGateStatus::Warning
                } else {
                    ReleaseGateStatus::Pending
                },
            },
            &self.config,
        )?;
        self.findings.insert(finding.finding_id.clone(), finding);
        Ok(())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record() -> Value {
    demo().public_record()
}

pub fn state_root() -> String {
    demo().state_root()
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("PRIVATE-L2-GOVERNANCE-AUDIT-STATE", record)
}

pub fn public_record_root(record: &Value) -> String {
    payload_root("PRIVATE-L2-GOVERNANCE-AUDIT-PUBLIC-RECORD", record)
}

pub fn payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(
                PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_HASH_SUITE,
            ),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn id_from_record(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        16,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public_record: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn map_records<T, F>(map: &BTreeMap<String, T>, public_record: F) -> Value
where
    F: Fn(&T) -> Value,
{
    let records = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "record": public_record(value) }))
        .collect::<Vec<_>>();
    Value::Array(records)
}

fn demo_root(label: &str) -> String {
    domain_hash(
        "PRIVATE-L2-GOVERNANCE-AUDIT-DEMO-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(label)],
        32,
    )
}

fn bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(
            PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BPS,
        ) / denominator
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    require(!value.trim().is_empty(), &format!("{label} is empty"))
}

fn require_positive(label: &str, value: u64) -> Result<()> {
    require(value > 0, &format!("{label} must be positive"))
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    require(
        value <= PRIVATE_L2_PQ_CONFIDENTIAL_TOKEN_CONTRACT_GOVERNANCE_AUDIT_RUNTIME_MAX_BPS,
        &format!("{label} exceeds bps scale"),
    )
}

fn require_capacity(label: &str, len: usize, max: usize) -> Result<()> {
    require(len < max, &format!("{label} capacity exceeded"))
}
