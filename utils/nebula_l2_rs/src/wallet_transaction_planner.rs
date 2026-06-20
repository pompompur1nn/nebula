use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type WalletTransactionPlannerResult<T> = Result<T, String>;

pub const WALLET_TRANSACTION_PLANNER_PROTOCOL_VERSION: &str =
    "nebula-wallet-transaction-planner-v1";
pub const WALLET_TRANSACTION_PLANNER_SECURITY_MODEL: &str =
    "deterministic-devnet-wallet-planning-not-real-crypto";
pub const WALLET_TRANSACTION_PLANNER_PQ_SUITE: &str = "ML-KEM-768+ML-DSA-65+SLH-DSA-SHAKE-128s";
pub const WALLET_TRANSACTION_PLANNER_PROOF_SCHEME: &str =
    "zk-wallet-plan-proof-requirements-shake256-v1";
pub const WALLET_TRANSACTION_PLANNER_OFFLINE_ENVELOPE_SCHEME: &str =
    "airgapped-wallet-signing-envelope-v1";
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_HEIGHT: u64 = 192;
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_PLAN_TTL_BLOCKS: u64 = 72;
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_QUOTE_TTL_BLOCKS: u64 = 24;
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_OFFLINE_TTL_BLOCKS: u64 = 288;
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_RISK_WINDOW_BLOCKS: u64 = 720;
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_FEE_ASSET_ID: &str = "wxmr-devnet";
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_MONERO_NETWORK: &str = "stagenet";
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_PRIVACY_POOL_ID: &str = "wallet-default-privacy-pool";
pub const WALLET_TRANSACTION_PLANNER_DEFAULT_SPONSOR_LANE: &str = "wallet-low-fee-lane";
pub const WALLET_TRANSACTION_PLANNER_MAX_BPS: u64 = 10_000;
pub const WALLET_TRANSACTION_PLANNER_MIN_PQ_SECURITY_BITS: u16 = 192;
pub const WALLET_TRANSACTION_PLANNER_MAX_ACCOUNTS: usize = 64;
pub const WALLET_TRANSACTION_PLANNER_MAX_PRIVACY_BUDGETS: usize = 128;
pub const WALLET_TRANSACTION_PLANNER_MAX_PLANS: usize = 192;
pub const WALLET_TRANSACTION_PLANNER_MAX_SPONSORS: usize = 128;
pub const WALLET_TRANSACTION_PLANNER_MAX_COMMITMENTS: usize = 256;
pub const WALLET_TRANSACTION_PLANNER_MAX_PROOFS: usize = 256;
pub const WALLET_TRANSACTION_PLANNER_MAX_FEE_QUOTES: usize = 256;
pub const WALLET_TRANSACTION_PLANNER_MAX_RISK_CHECKS: usize = 256;
pub const WALLET_TRANSACTION_PLANNER_MAX_OFFLINE_ENVELOPES: usize = 128;
pub const WALLET_TRANSACTION_PLANNER_MAX_LIFECYCLE_HINTS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPlanKind {
    PrivateTransfer,
    PrivateDefi,
    PrivateContract,
    BridgeDeposit,
    BridgeWithdrawal,
}

impl WalletPlanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "private_defi",
            Self::PrivateContract => "private_contract",
            Self::BridgeDeposit => "bridge_deposit",
            Self::BridgeWithdrawal => "bridge_withdrawal",
        }
    }

    pub fn default_lane(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateDefi => "small_private_defi",
            Self::PrivateContract => "private_contract_call",
            Self::BridgeDeposit => "monero_bridge_deposit",
            Self::BridgeWithdrawal => "monero_bridge_withdrawal",
        }
    }

    pub fn requires_bridge_commitment(self) -> bool {
        matches!(self, Self::BridgeDeposit | Self::BridgeWithdrawal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletPlanStatus {
    Draft,
    Planned,
    Quoted,
    RiskChecked,
    ReadyForSigning,
    OfflineExported,
    Signed,
    Submitted,
    Included,
    Finalized,
    Expired,
    Cancelled,
    Quarantined,
}

impl WalletPlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Planned => "planned",
            Self::Quoted => "quoted",
            Self::RiskChecked => "risk_checked",
            Self::ReadyForSigning => "ready_for_signing",
            Self::OfflineExported => "offline_exported",
            Self::Signed => "signed",
            Self::Submitted => "submitted",
            Self::Included => "included",
            Self::Finalized => "finalized",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn is_live(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::Planned
                | Self::Quoted
                | Self::RiskChecked
                | Self::ReadyForSigning
                | Self::OfflineExported
                | Self::Signed
                | Self::Submitted
                | Self::Included
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Finalized | Self::Expired | Self::Cancelled | Self::Quarantined
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletAccountKind {
    Spending,
    WatchOnly,
    Hardware,
    Session,
    Recovery,
}

impl WalletAccountKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spending => "spending",
            Self::WatchOnly => "watch_only",
            Self::Hardware => "hardware",
            Self::Session => "session",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqRequirementLevel {
    Optional,
    Required,
    HardwareRequired,
    RecoveryRequired,
}

impl PqRequirementLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Optional => "optional",
            Self::Required => "required",
            Self::HardwareRequired => "hardware_required",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    pub fn needs_attestation(self) -> bool {
        !matches!(self, Self::Optional)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyBudgetMode {
    Minimum,
    Balanced,
    Strong,
    Maximum,
    Custom,
}

impl PrivacyBudgetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Minimum => "minimum",
            Self::Balanced => "balanced",
            Self::Strong => "strong",
            Self::Maximum => "maximum",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SponsorSelectionMode {
    Disabled,
    PreferLowestFee,
    PreferPrivateSponsor,
    RequireSponsor,
    SelfPayFallback,
}

impl SponsorSelectionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::PreferLowestFee => "prefer_lowest_fee",
            Self::PreferPrivateSponsor => "prefer_private_sponsor",
            Self::RequireSponsor => "require_sponsor",
            Self::SelfPayFallback => "self_pay_fallback",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentKind {
    Route,
    Deposit,
    Withdrawal,
    ContractCall,
    DefiLeg,
}

impl CommitmentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Deposit => "deposit",
            Self::Withdrawal => "withdrawal",
            Self::ContractCall => "contract_call",
            Self::DefiLeg => "defi_leg",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRequirementKind {
    Balance,
    Membership,
    Range,
    Nullifier,
    Route,
    ContractAuthorization,
    BridgeReserve,
    FeeSponsorship,
    PqSignature,
}

impl ProofRequirementKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Balance => "balance",
            Self::Membership => "membership",
            Self::Range => "range",
            Self::Nullifier => "nullifier",
            Self::Route => "route",
            Self::ContractAuthorization => "contract_authorization",
            Self::BridgeReserve => "bridge_reserve",
            Self::FeeSponsorship => "fee_sponsorship",
            Self::PqSignature => "pq_signature",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskSeverity {
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
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCheckStatus {
    Passed,
    Warning,
    Blocked,
    NeedsUserReview,
}

impl RiskCheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Warning => "warning",
            Self::Blocked => "blocked",
            Self::NeedsUserReview => "needs_user_review",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineEnvelopeStatus {
    Prepared,
    Exported,
    Signed,
    Imported,
    Expired,
    Revoked,
}

impl OfflineEnvelopeStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Exported => "exported",
            Self::Signed => "signed",
            Self::Imported => "imported",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransactionPlannerConfig {
    pub chain_id: String,
    pub protocol_version: String,
    pub security_model: String,
    pub pq_suite: String,
    pub proof_scheme: String,
    pub offline_envelope_scheme: String,
    pub monero_network: String,
    pub default_fee_asset_id: String,
    pub default_privacy_pool_id: String,
    pub default_sponsor_lane: String,
    pub min_pq_security_bits: u16,
    pub default_plan_ttl_blocks: u64,
    pub default_quote_ttl_blocks: u64,
    pub default_offline_ttl_blocks: u64,
    pub default_risk_window_blocks: u64,
    pub max_accounts: usize,
    pub max_privacy_budgets: usize,
    pub max_plans: usize,
    pub max_sponsors: usize,
    pub max_commitments: usize,
    pub max_proofs: usize,
    pub max_fee_quotes: usize,
    pub max_risk_checks: usize,
    pub max_offline_envelopes: usize,
    pub max_lifecycle_hints: usize,
    pub metadata: BTreeMap<String, String>,
}

impl WalletTransactionPlannerConfig {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: WALLET_TRANSACTION_PLANNER_PROTOCOL_VERSION.to_string(),
            security_model: WALLET_TRANSACTION_PLANNER_SECURITY_MODEL.to_string(),
            pq_suite: WALLET_TRANSACTION_PLANNER_PQ_SUITE.to_string(),
            proof_scheme: WALLET_TRANSACTION_PLANNER_PROOF_SCHEME.to_string(),
            offline_envelope_scheme: WALLET_TRANSACTION_PLANNER_OFFLINE_ENVELOPE_SCHEME.to_string(),
            monero_network: WALLET_TRANSACTION_PLANNER_DEFAULT_MONERO_NETWORK.to_string(),
            default_fee_asset_id: WALLET_TRANSACTION_PLANNER_DEFAULT_FEE_ASSET_ID.to_string(),
            default_privacy_pool_id: WALLET_TRANSACTION_PLANNER_DEFAULT_PRIVACY_POOL_ID.to_string(),
            default_sponsor_lane: WALLET_TRANSACTION_PLANNER_DEFAULT_SPONSOR_LANE.to_string(),
            min_pq_security_bits: WALLET_TRANSACTION_PLANNER_MIN_PQ_SECURITY_BITS,
            default_plan_ttl_blocks: WALLET_TRANSACTION_PLANNER_DEFAULT_PLAN_TTL_BLOCKS,
            default_quote_ttl_blocks: WALLET_TRANSACTION_PLANNER_DEFAULT_QUOTE_TTL_BLOCKS,
            default_offline_ttl_blocks: WALLET_TRANSACTION_PLANNER_DEFAULT_OFFLINE_TTL_BLOCKS,
            default_risk_window_blocks: WALLET_TRANSACTION_PLANNER_DEFAULT_RISK_WINDOW_BLOCKS,
            max_accounts: WALLET_TRANSACTION_PLANNER_MAX_ACCOUNTS,
            max_privacy_budgets: WALLET_TRANSACTION_PLANNER_MAX_PRIVACY_BUDGETS,
            max_plans: WALLET_TRANSACTION_PLANNER_MAX_PLANS,
            max_sponsors: WALLET_TRANSACTION_PLANNER_MAX_SPONSORS,
            max_commitments: WALLET_TRANSACTION_PLANNER_MAX_COMMITMENTS,
            max_proofs: WALLET_TRANSACTION_PLANNER_MAX_PROOFS,
            max_fee_quotes: WALLET_TRANSACTION_PLANNER_MAX_FEE_QUOTES,
            max_risk_checks: WALLET_TRANSACTION_PLANNER_MAX_RISK_CHECKS,
            max_offline_envelopes: WALLET_TRANSACTION_PLANNER_MAX_OFFLINE_ENVELOPES,
            max_lifecycle_hints: WALLET_TRANSACTION_PLANNER_MAX_LIFECYCLE_HINTS,
            metadata: BTreeMap::from([(
                "fixture".to_string(),
                "wallet_transaction_planner_devnet".to_string(),
            )]),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "security_model": self.security_model,
            "pq_suite": self.pq_suite,
            "proof_scheme": self.proof_scheme,
            "offline_envelope_scheme": self.offline_envelope_scheme,
            "monero_network": self.monero_network,
            "default_fee_asset_id": self.default_fee_asset_id,
            "default_privacy_pool_id": self.default_privacy_pool_id,
            "default_sponsor_lane": self.default_sponsor_lane,
            "min_pq_security_bits": self.min_pq_security_bits,
            "default_plan_ttl_blocks": self.default_plan_ttl_blocks,
            "default_quote_ttl_blocks": self.default_quote_ttl_blocks,
            "default_offline_ttl_blocks": self.default_offline_ttl_blocks,
            "default_risk_window_blocks": self.default_risk_window_blocks,
            "max_accounts": self.max_accounts,
            "max_privacy_budgets": self.max_privacy_budgets,
            "max_plans": self.max_plans,
            "max_sponsors": self.max_sponsors,
            "max_commitments": self.max_commitments,
            "max_proofs": self.max_proofs,
            "max_fee_quotes": self.max_fee_quotes,
            "max_risk_checks": self.max_risk_checks,
            "max_offline_envelopes": self.max_offline_envelopes,
            "max_lifecycle_hints": self.max_lifecycle_hints,
            "metadata": self.metadata,
        })
    }

    pub fn config_root(&self) -> String {
        wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-CONFIG", &self.public_record())
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_eq(&self.chain_id, CHAIN_ID, "config chain id")?;
        ensure_non_empty(&self.protocol_version, "protocol version")?;
        ensure_non_empty(&self.security_model, "security model")?;
        ensure_non_empty(&self.pq_suite, "pq suite")?;
        ensure_non_empty(&self.proof_scheme, "proof scheme")?;
        ensure_non_empty(&self.offline_envelope_scheme, "offline envelope scheme")?;
        ensure_non_empty(&self.monero_network, "monero network")?;
        ensure_non_empty(&self.default_fee_asset_id, "default fee asset id")?;
        ensure_non_empty(&self.default_privacy_pool_id, "default privacy pool id")?;
        ensure_positive(self.default_plan_ttl_blocks, "default plan ttl blocks")?;
        ensure_positive(self.default_quote_ttl_blocks, "default quote ttl blocks")?;
        ensure_positive(
            self.default_offline_ttl_blocks,
            "default offline ttl blocks",
        )?;
        ensure_positive(
            self.default_risk_window_blocks,
            "default risk window blocks",
        )?;
        ensure_usize_positive(self.max_accounts, "max accounts")?;
        ensure_usize_positive(self.max_privacy_budgets, "max privacy budgets")?;
        ensure_usize_positive(self.max_plans, "max plans")?;
        ensure_usize_positive(self.max_sponsors, "max sponsors")?;
        ensure_usize_positive(self.max_commitments, "max commitments")?;
        ensure_usize_positive(self.max_proofs, "max proofs")?;
        ensure_usize_positive(self.max_fee_quotes, "max fee quotes")?;
        ensure_usize_positive(self.max_risk_checks, "max risk checks")?;
        ensure_usize_positive(self.max_offline_envelopes, "max offline envelopes")?;
        ensure_usize_positive(self.max_lifecycle_hints, "max lifecycle hints")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuantumAccountRequirement {
    pub account_id: String,
    pub account_kind: WalletAccountKind,
    pub required_level: PqRequirementLevel,
    pub public_view_tag: String,
    pub pq_key_commitment: String,
    pub hardware_attestation_root: String,
    pub recovery_authority_root: String,
    pub min_security_bits: u16,
    pub rotation_height: u64,
    pub expires_at_height: u64,
    pub allowed_plan_kinds: BTreeSet<WalletPlanKind>,
    pub metadata: BTreeMap<String, String>,
}

impl QuantumAccountRequirement {
    pub fn public_record(&self) -> Value {
        json!({
            "account_id": self.account_id,
            "account_kind": self.account_kind.as_str(),
            "required_level": self.required_level.as_str(),
            "public_view_tag": self.public_view_tag,
            "pq_key_commitment": self.pq_key_commitment,
            "hardware_attestation_root": self.hardware_attestation_root,
            "recovery_authority_root": self.recovery_authority_root,
            "min_security_bits": self.min_security_bits,
            "rotation_height": self.rotation_height,
            "expires_at_height": self.expires_at_height,
            "allowed_plan_kinds": self.allowed_plan_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "metadata": self.metadata,
        })
    }

    pub fn account_root(&self) -> String {
        wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-ACCOUNT", &self.public_record())
    }

    pub fn validate(
        &self,
        config: &WalletTransactionPlannerConfig,
    ) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.account_id, "account id")?;
        ensure_non_empty(&self.public_view_tag, "account public view tag")?;
        ensure_non_empty(&self.pq_key_commitment, "account pq key commitment")?;
        if self.min_security_bits < config.min_pq_security_bits {
            return Err("account pq security bits below configured minimum".to_string());
        }
        if self.expires_at_height <= self.rotation_height {
            return Err("account expiry must be after rotation height".to_string());
        }
        if self.required_level.needs_attestation() {
            ensure_non_empty(
                &self.hardware_attestation_root,
                "account hardware attestation root",
            )?;
        }
        ensure_non_empty_set(&self.allowed_plan_kinds, "account allowed plan kinds")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyBudgetSelection {
    pub budget_id: String,
    pub account_id: String,
    pub mode: PrivacyBudgetMode,
    pub pool_id: String,
    pub anonymity_set_target: u64,
    pub decoy_count: u16,
    pub linkability_budget_bps: u64,
    pub amount_bucket_size: u64,
    pub max_reuse_count: u32,
    pub selected_route_hints: Vec<String>,
    pub disclosure_policy_root: String,
    pub expires_at_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl PrivacyBudgetSelection {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "account_id": self.account_id,
            "mode": self.mode.as_str(),
            "pool_id": self.pool_id,
            "anonymity_set_target": self.anonymity_set_target,
            "decoy_count": self.decoy_count,
            "linkability_budget_bps": self.linkability_budget_bps,
            "amount_bucket_size": self.amount_bucket_size,
            "max_reuse_count": self.max_reuse_count,
            "selected_route_hints": self.selected_route_hints,
            "disclosure_policy_root": self.disclosure_policy_root,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn budget_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-PRIVACY-BUDGET",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.budget_id, "privacy budget id")?;
        ensure_non_empty(&self.account_id, "privacy budget account id")?;
        ensure_non_empty(&self.pool_id, "privacy budget pool id")?;
        ensure_positive(self.anonymity_set_target, "anonymity set target")?;
        ensure_positive(self.decoy_count as u64, "privacy decoy count")?;
        ensure_bps(self.linkability_budget_bps, "linkability budget bps")?;
        ensure_positive(self.amount_bucket_size, "amount bucket size")?;
        ensure_positive(self.max_reuse_count as u64, "max reuse count")?;
        ensure_non_empty(&self.disclosure_policy_root, "disclosure policy root")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransactionPlan {
    pub plan_id: String,
    pub plan_kind: WalletPlanKind,
    pub status: WalletPlanStatus,
    pub account_id: String,
    pub privacy_budget_id: String,
    pub fee_quote_id: String,
    pub sponsor_selection_id: String,
    pub route_commitment_id: String,
    pub bridge_commitment_id: String,
    pub offline_envelope_id: String,
    pub asset_id: String,
    pub amount_bucket: u64,
    pub destination_commitment: String,
    pub call_target: String,
    pub intent_payload_root: String,
    pub user_memo_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub dependency_roots: BTreeMap<String, String>,
    pub metadata: BTreeMap<String, String>,
}

impl WalletTransactionPlan {
    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "plan_kind": self.plan_kind.as_str(),
            "status": self.status.as_str(),
            "account_id": self.account_id,
            "privacy_budget_id": self.privacy_budget_id,
            "fee_quote_id": self.fee_quote_id,
            "sponsor_selection_id": self.sponsor_selection_id,
            "route_commitment_id": self.route_commitment_id,
            "bridge_commitment_id": self.bridge_commitment_id,
            "offline_envelope_id": self.offline_envelope_id,
            "asset_id": self.asset_id,
            "amount_bucket": self.amount_bucket,
            "destination_commitment": self.destination_commitment,
            "call_target": self.call_target,
            "intent_payload_root": self.intent_payload_root,
            "user_memo_commitment": self.user_memo_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "dependency_roots": self.dependency_roots,
            "metadata": self.metadata,
        })
    }

    pub fn plan_root(&self) -> String {
        wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-PLAN", &self.public_record())
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.plan_id, "plan id")?;
        ensure_non_empty(&self.account_id, "plan account id")?;
        ensure_non_empty(&self.privacy_budget_id, "plan privacy budget id")?;
        ensure_non_empty(&self.asset_id, "plan asset id")?;
        ensure_positive(self.amount_bucket, "plan amount bucket")?;
        ensure_non_empty(&self.intent_payload_root, "plan intent payload root")?;
        if self.expires_at_height <= self.created_at_height {
            return Err("plan expiry must be after created height".to_string());
        }
        if self.plan_kind.requires_bridge_commitment() {
            ensure_non_empty(&self.bridge_commitment_id, "bridge plan commitment id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorCandidate {
    pub sponsor_id: String,
    pub sponsor_account: String,
    pub lane_id: String,
    pub supported_plan_kinds: BTreeSet<WalletPlanKind>,
    pub fee_asset_id: String,
    pub max_fee_micro_units: u64,
    pub available_budget_micro_units: u64,
    pub privacy_score_bps: u64,
    pub reliability_score_bps: u64,
    pub pq_authorization_root: String,
    pub terms_root: String,
    pub valid_until_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl LowFeeSponsorCandidate {
    pub fn public_record(&self) -> Value {
        json!({
            "sponsor_id": self.sponsor_id,
            "sponsor_account": self.sponsor_account,
            "lane_id": self.lane_id,
            "supported_plan_kinds": self.supported_plan_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "fee_asset_id": self.fee_asset_id,
            "max_fee_micro_units": self.max_fee_micro_units,
            "available_budget_micro_units": self.available_budget_micro_units,
            "privacy_score_bps": self.privacy_score_bps,
            "reliability_score_bps": self.reliability_score_bps,
            "pq_authorization_root": self.pq_authorization_root,
            "terms_root": self.terms_root,
            "valid_until_height": self.valid_until_height,
            "metadata": self.metadata,
        })
    }

    pub fn sponsor_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-SPONSOR-CANDIDATE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.sponsor_id, "sponsor id")?;
        ensure_non_empty(&self.sponsor_account, "sponsor account")?;
        ensure_non_empty(&self.lane_id, "sponsor lane id")?;
        ensure_non_empty_set(&self.supported_plan_kinds, "sponsor supported plan kinds")?;
        ensure_non_empty(&self.fee_asset_id, "sponsor fee asset id")?;
        ensure_positive(self.max_fee_micro_units, "sponsor max fee")?;
        ensure_positive(
            self.available_budget_micro_units,
            "sponsor available budget",
        )?;
        ensure_bps(self.privacy_score_bps, "sponsor privacy score bps")?;
        ensure_bps(self.reliability_score_bps, "sponsor reliability score bps")?;
        ensure_non_empty(&self.pq_authorization_root, "sponsor pq authorization root")?;
        ensure_non_empty(&self.terms_root, "sponsor terms root")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSponsorshipSelection {
    pub selection_id: String,
    pub plan_id: String,
    pub mode: SponsorSelectionMode,
    pub sponsor_id: String,
    pub reservation_nullifier: String,
    pub sponsored_fee_micro_units: u64,
    pub self_pay_fee_micro_units: u64,
    pub rebate_commitment: String,
    pub selection_reason_root: String,
    pub selected_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl LowFeeSponsorshipSelection {
    pub fn public_record(&self) -> Value {
        json!({
            "selection_id": self.selection_id,
            "plan_id": self.plan_id,
            "mode": self.mode.as_str(),
            "sponsor_id": self.sponsor_id,
            "reservation_nullifier": self.reservation_nullifier,
            "sponsored_fee_micro_units": self.sponsored_fee_micro_units,
            "self_pay_fee_micro_units": self.self_pay_fee_micro_units,
            "rebate_commitment": self.rebate_commitment,
            "selection_reason_root": self.selection_reason_root,
            "selected_at_height": self.selected_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn selection_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-SPONSOR-SELECTION",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.selection_id, "sponsorship selection id")?;
        ensure_non_empty(&self.plan_id, "sponsorship plan id")?;
        if !matches!(self.mode, SponsorSelectionMode::Disabled) {
            ensure_non_empty(&self.sponsor_id, "selected sponsor id")?;
            ensure_positive(self.sponsored_fee_micro_units, "sponsored fee")?;
            ensure_non_empty(&self.reservation_nullifier, "reservation nullifier")?;
        }
        if self.expires_at_height <= self.selected_at_height {
            return Err("sponsorship selection expiry must be after selected height".to_string());
        }
        ensure_non_empty(&self.selection_reason_root, "selection reason root")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDepositWithdrawalCommitment {
    pub commitment_id: String,
    pub plan_id: String,
    pub commitment_kind: CommitmentKind,
    pub route_id: String,
    pub source_domain: String,
    pub destination_domain: String,
    pub input_commitment_root: String,
    pub output_commitment_root: String,
    pub deposit_address_commitment: String,
    pub withdrawal_address_commitment: String,
    pub path_commitments: Vec<String>,
    pub slippage_bps: u64,
    pub min_output_bucket: u64,
    pub timeout_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl RouteDepositWithdrawalCommitment {
    pub fn public_record(&self) -> Value {
        json!({
            "commitment_id": self.commitment_id,
            "plan_id": self.plan_id,
            "commitment_kind": self.commitment_kind.as_str(),
            "route_id": self.route_id,
            "source_domain": self.source_domain,
            "destination_domain": self.destination_domain,
            "input_commitment_root": self.input_commitment_root,
            "output_commitment_root": self.output_commitment_root,
            "deposit_address_commitment": self.deposit_address_commitment,
            "withdrawal_address_commitment": self.withdrawal_address_commitment,
            "path_commitments": self.path_commitments,
            "slippage_bps": self.slippage_bps,
            "min_output_bucket": self.min_output_bucket,
            "timeout_height": self.timeout_height,
            "metadata": self.metadata,
        })
    }

    pub fn commitment_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-COMMITMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.commitment_id, "commitment id")?;
        ensure_non_empty(&self.plan_id, "commitment plan id")?;
        ensure_non_empty(&self.route_id, "commitment route id")?;
        ensure_non_empty(&self.source_domain, "commitment source domain")?;
        ensure_non_empty(&self.destination_domain, "commitment destination domain")?;
        ensure_non_empty(&self.input_commitment_root, "input commitment root")?;
        ensure_non_empty(&self.output_commitment_root, "output commitment root")?;
        ensure_bps(self.slippage_bps, "commitment slippage bps")?;
        ensure_positive(self.min_output_bucket, "commitment min output bucket")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequirement {
    pub requirement_id: String,
    pub plan_id: String,
    pub proof_kind: ProofRequirementKind,
    pub circuit_id: String,
    pub witness_root: String,
    pub public_inputs_root: String,
    pub recursive_parent_root: String,
    pub proving_market_hint: String,
    pub required_before_height: u64,
    pub estimated_constraints: u64,
    pub metadata: BTreeMap<String, String>,
}

impl ProofRequirement {
    pub fn public_record(&self) -> Value {
        json!({
            "requirement_id": self.requirement_id,
            "plan_id": self.plan_id,
            "proof_kind": self.proof_kind.as_str(),
            "circuit_id": self.circuit_id,
            "witness_root": self.witness_root,
            "public_inputs_root": self.public_inputs_root,
            "recursive_parent_root": self.recursive_parent_root,
            "proving_market_hint": self.proving_market_hint,
            "required_before_height": self.required_before_height,
            "estimated_constraints": self.estimated_constraints,
            "metadata": self.metadata,
        })
    }

    pub fn requirement_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-PROOF-REQUIREMENT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.requirement_id, "proof requirement id")?;
        ensure_non_empty(&self.plan_id, "proof requirement plan id")?;
        ensure_non_empty(&self.circuit_id, "proof requirement circuit id")?;
        ensure_non_empty(&self.witness_root, "proof witness root")?;
        ensure_non_empty(&self.public_inputs_root, "proof public inputs root")?;
        ensure_positive(self.required_before_height, "proof required height")?;
        ensure_positive(self.estimated_constraints, "estimated constraints")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeQuote {
    pub quote_id: String,
    pub plan_id: String,
    pub fee_asset_id: String,
    pub base_fee_micro_units: u64,
    pub proof_fee_micro_units: u64,
    pub da_fee_micro_units: u64,
    pub sponsor_discount_micro_units: u64,
    pub total_fee_micro_units: u64,
    pub max_fee_micro_units: u64,
    pub quote_source: String,
    pub quote_commitment: String,
    pub quoted_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl FeeQuote {
    pub fn public_record(&self) -> Value {
        json!({
            "quote_id": self.quote_id,
            "plan_id": self.plan_id,
            "fee_asset_id": self.fee_asset_id,
            "base_fee_micro_units": self.base_fee_micro_units,
            "proof_fee_micro_units": self.proof_fee_micro_units,
            "da_fee_micro_units": self.da_fee_micro_units,
            "sponsor_discount_micro_units": self.sponsor_discount_micro_units,
            "total_fee_micro_units": self.total_fee_micro_units,
            "max_fee_micro_units": self.max_fee_micro_units,
            "quote_source": self.quote_source,
            "quote_commitment": self.quote_commitment,
            "quoted_at_height": self.quoted_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn quote_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-FEE-QUOTE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.quote_id, "fee quote id")?;
        ensure_non_empty(&self.plan_id, "fee quote plan id")?;
        ensure_non_empty(&self.fee_asset_id, "fee quote asset id")?;
        ensure_non_empty(&self.quote_source, "fee quote source")?;
        ensure_non_empty(&self.quote_commitment, "fee quote commitment")?;
        let subtotal = self
            .base_fee_micro_units
            .saturating_add(self.proof_fee_micro_units)
            .saturating_add(self.da_fee_micro_units);
        let discounted = subtotal.saturating_sub(self.sponsor_discount_micro_units);
        if discounted != self.total_fee_micro_units {
            return Err("fee quote total does not match components".to_string());
        }
        if self.total_fee_micro_units > self.max_fee_micro_units {
            return Err("fee quote total exceeds max fee".to_string());
        }
        if self.expires_at_height <= self.quoted_at_height {
            return Err("fee quote expiry must be after quoted height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletRiskCheck {
    pub check_id: String,
    pub plan_id: String,
    pub status: RiskCheckStatus,
    pub severity: RiskSeverity,
    pub policy_id: String,
    pub reason_code: String,
    pub observed_value_root: String,
    pub threshold_root: String,
    pub mitigation_hint: String,
    pub requires_user_ack: bool,
    pub checked_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl WalletRiskCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "plan_id": self.plan_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "policy_id": self.policy_id,
            "reason_code": self.reason_code,
            "observed_value_root": self.observed_value_root,
            "threshold_root": self.threshold_root,
            "mitigation_hint": self.mitigation_hint,
            "requires_user_ack": self.requires_user_ack,
            "checked_at_height": self.checked_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn check_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-RISK-CHECK",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.check_id, "risk check id")?;
        ensure_non_empty(&self.plan_id, "risk check plan id")?;
        ensure_non_empty(&self.policy_id, "risk policy id")?;
        ensure_non_empty(&self.reason_code, "risk reason code")?;
        ensure_non_empty(&self.observed_value_root, "risk observed value root")?;
        ensure_non_empty(&self.threshold_root, "risk threshold root")?;
        if matches!(self.status, RiskCheckStatus::Blocked) && self.severity.score() < 3 {
            return Err("blocked risk check must be high or critical severity".to_string());
        }
        if self.expires_at_height <= self.checked_at_height {
            return Err("risk check expiry must be after checked height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSigningEnvelope {
    pub envelope_id: String,
    pub plan_id: String,
    pub status: OfflineEnvelopeStatus,
    pub account_id: String,
    pub signing_device_hint: String,
    pub unsigned_payload_root: String,
    pub signer_policy_root: String,
    pub pq_transcript_root: String,
    pub export_commitment: String,
    pub import_commitment: String,
    pub signature_commitment: String,
    pub created_at_height: u64,
    pub expires_at_height: u64,
    pub metadata: BTreeMap<String, String>,
}

impl OfflineSigningEnvelope {
    pub fn public_record(&self) -> Value {
        json!({
            "envelope_id": self.envelope_id,
            "plan_id": self.plan_id,
            "status": self.status.as_str(),
            "account_id": self.account_id,
            "signing_device_hint": self.signing_device_hint,
            "unsigned_payload_root": self.unsigned_payload_root,
            "signer_policy_root": self.signer_policy_root,
            "pq_transcript_root": self.pq_transcript_root,
            "export_commitment": self.export_commitment,
            "import_commitment": self.import_commitment,
            "signature_commitment": self.signature_commitment,
            "created_at_height": self.created_at_height,
            "expires_at_height": self.expires_at_height,
            "metadata": self.metadata,
        })
    }

    pub fn envelope_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-OFFLINE-ENVELOPE",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.envelope_id, "offline envelope id")?;
        ensure_non_empty(&self.plan_id, "offline envelope plan id")?;
        ensure_non_empty(&self.account_id, "offline envelope account id")?;
        ensure_non_empty(&self.unsigned_payload_root, "unsigned payload root")?;
        ensure_non_empty(&self.signer_policy_root, "signer policy root")?;
        ensure_non_empty(&self.pq_transcript_root, "pq transcript root")?;
        ensure_non_empty(&self.export_commitment, "offline export commitment")?;
        if matches!(
            self.status,
            OfflineEnvelopeStatus::Signed | OfflineEnvelopeStatus::Imported
        ) {
            ensure_non_empty(&self.signature_commitment, "offline signature commitment")?;
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("offline envelope expiry must be after created height".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLifecycleHint {
    pub hint_id: String,
    pub plan_id: String,
    pub status_hint: WalletPlanStatus,
    pub expected_next_status: WalletPlanStatus,
    pub earliest_submit_height: u64,
    pub latest_submit_height: u64,
    pub expected_inclusion_blocks: u64,
    pub finality_target_blocks: u64,
    pub replacement_allowed: bool,
    pub cancel_commitment: String,
    pub watchtower_hint_root: String,
    pub metadata: BTreeMap<String, String>,
}

impl TransactionLifecycleHint {
    pub fn public_record(&self) -> Value {
        json!({
            "hint_id": self.hint_id,
            "plan_id": self.plan_id,
            "status_hint": self.status_hint.as_str(),
            "expected_next_status": self.expected_next_status.as_str(),
            "earliest_submit_height": self.earliest_submit_height,
            "latest_submit_height": self.latest_submit_height,
            "expected_inclusion_blocks": self.expected_inclusion_blocks,
            "finality_target_blocks": self.finality_target_blocks,
            "replacement_allowed": self.replacement_allowed,
            "cancel_commitment": self.cancel_commitment,
            "watchtower_hint_root": self.watchtower_hint_root,
            "metadata": self.metadata,
        })
    }

    pub fn hint_root(&self) -> String {
        wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-LIFECYCLE-HINT",
            &self.public_record(),
        )
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<()> {
        ensure_non_empty(&self.hint_id, "lifecycle hint id")?;
        ensure_non_empty(&self.plan_id, "lifecycle hint plan id")?;
        if self.latest_submit_height < self.earliest_submit_height {
            return Err("latest submit height cannot precede earliest submit height".to_string());
        }
        ensure_positive(self.expected_inclusion_blocks, "expected inclusion blocks")?;
        ensure_positive(self.finality_target_blocks, "finality target blocks")?;
        ensure_non_empty(&self.watchtower_hint_root, "watchtower hint root")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransactionPlannerRoots {
    pub config_root: String,
    pub accounts_root: String,
    pub privacy_budgets_root: String,
    pub plans_root: String,
    pub sponsor_candidates_root: String,
    pub sponsorship_selections_root: String,
    pub commitments_root: String,
    pub proof_requirements_root: String,
    pub fee_quotes_root: String,
    pub risk_checks_root: String,
    pub offline_envelopes_root: String,
    pub lifecycle_hints_root: String,
}

impl WalletTransactionPlannerRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "accounts_root": self.accounts_root,
            "privacy_budgets_root": self.privacy_budgets_root,
            "plans_root": self.plans_root,
            "sponsor_candidates_root": self.sponsor_candidates_root,
            "sponsorship_selections_root": self.sponsorship_selections_root,
            "commitments_root": self.commitments_root,
            "proof_requirements_root": self.proof_requirements_root,
            "fee_quotes_root": self.fee_quotes_root,
            "risk_checks_root": self.risk_checks_root,
            "offline_envelopes_root": self.offline_envelopes_root,
            "lifecycle_hints_root": self.lifecycle_hints_root,
        })
    }

    pub fn roots_root(&self) -> String {
        wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-ROOTS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransactionPlannerCounters {
    pub accounts: usize,
    pub privacy_budgets: usize,
    pub plans: usize,
    pub live_plans: usize,
    pub terminal_plans: usize,
    pub sponsor_candidates: usize,
    pub sponsorship_selections: usize,
    pub commitments: usize,
    pub proof_requirements: usize,
    pub fee_quotes: usize,
    pub risk_checks: usize,
    pub blocking_risk_checks: usize,
    pub offline_envelopes: usize,
    pub lifecycle_hints: usize,
}

impl WalletTransactionPlannerCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "accounts": self.accounts,
            "privacy_budgets": self.privacy_budgets,
            "plans": self.plans,
            "live_plans": self.live_plans,
            "terminal_plans": self.terminal_plans,
            "sponsor_candidates": self.sponsor_candidates,
            "sponsorship_selections": self.sponsorship_selections,
            "commitments": self.commitments,
            "proof_requirements": self.proof_requirements,
            "fee_quotes": self.fee_quotes,
            "risk_checks": self.risk_checks,
            "blocking_risk_checks": self.blocking_risk_checks,
            "offline_envelopes": self.offline_envelopes,
            "lifecycle_hints": self.lifecycle_hints,
        })
    }

    pub fn counters_root(&self) -> String {
        wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-COUNTERS", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransactionPlannerState {
    pub config: WalletTransactionPlannerConfig,
    pub height: u64,
    pub accounts: BTreeMap<String, QuantumAccountRequirement>,
    pub privacy_budgets: BTreeMap<String, PrivacyBudgetSelection>,
    pub plans: BTreeMap<String, WalletTransactionPlan>,
    pub sponsor_candidates: BTreeMap<String, LowFeeSponsorCandidate>,
    pub sponsorship_selections: BTreeMap<String, LowFeeSponsorshipSelection>,
    pub commitments: BTreeMap<String, RouteDepositWithdrawalCommitment>,
    pub proof_requirements: BTreeMap<String, ProofRequirement>,
    pub fee_quotes: BTreeMap<String, FeeQuote>,
    pub risk_checks: BTreeMap<String, WalletRiskCheck>,
    pub offline_envelopes: BTreeMap<String, OfflineSigningEnvelope>,
    pub lifecycle_hints: BTreeMap<String, TransactionLifecycleHint>,
}

impl WalletTransactionPlannerState {
    pub fn devnet() -> WalletTransactionPlannerResult<Self> {
        let config = WalletTransactionPlannerConfig::devnet();
        let height = WALLET_TRANSACTION_PLANNER_DEFAULT_HEIGHT;

        let account_id = wallet_transaction_planner_account_id(
            "devnet-wallet",
            WalletAccountKind::Hardware,
            "primary",
        );
        let allowed_plan_kinds = BTreeSet::from([
            WalletPlanKind::PrivateTransfer,
            WalletPlanKind::PrivateDefi,
            WalletPlanKind::PrivateContract,
            WalletPlanKind::BridgeDeposit,
            WalletPlanKind::BridgeWithdrawal,
        ]);
        let account = QuantumAccountRequirement {
            account_id: account_id.clone(),
            account_kind: WalletAccountKind::Hardware,
            required_level: PqRequirementLevel::HardwareRequired,
            public_view_tag: "devnet-view-tag-primary".to_string(),
            pq_key_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-PQ-KEY",
                "primary-pq-key",
            ),
            hardware_attestation_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-HARDWARE-ATTESTATION",
                "hardware-attestation",
            ),
            recovery_authority_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-RECOVERY-AUTHORITY",
                "recovery-authority",
            ),
            min_security_bits: config.min_pq_security_bits,
            rotation_height: height.saturating_sub(12),
            expires_at_height: height + 2_880,
            allowed_plan_kinds,
            metadata: BTreeMap::from([("profile".to_string(), "primary".to_string())]),
        };

        let privacy_budget_id = wallet_transaction_planner_privacy_budget_id(
            &account_id,
            PrivacyBudgetMode::Strong,
            &config.default_privacy_pool_id,
            height,
        );
        let privacy_budget = PrivacyBudgetSelection {
            budget_id: privacy_budget_id.clone(),
            account_id: account_id.clone(),
            mode: PrivacyBudgetMode::Strong,
            pool_id: config.default_privacy_pool_id.clone(),
            anonymity_set_target: 4_096,
            decoy_count: 24,
            linkability_budget_bps: 350,
            amount_bucket_size: 10_000,
            max_reuse_count: 2,
            selected_route_hints: vec![
                "private-fast-lane".to_string(),
                "small-private-defi".to_string(),
            ],
            disclosure_policy_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-DISCLOSURE-POLICY",
                "no-disclosure",
            ),
            expires_at_height: height + 720,
            metadata: BTreeMap::from([("selector".to_string(), "strong-default".to_string())]),
        };

        let intent_payload = json!({
            "kind": WalletPlanKind::PrivateTransfer.as_str(),
            "asset_id": config.default_fee_asset_id,
            "amount_bucket": 50_000_u64,
            "destination": "recipient-output-commitment",
        });
        let intent_payload_root = wallet_transaction_planner_payload_root(
            "WALLET-TX-PLANNER-DEVNET-INTENT",
            &intent_payload,
        );
        let plan_id = wallet_transaction_planner_plan_id(
            &account_id,
            WalletPlanKind::PrivateTransfer,
            &intent_payload_root,
            height,
        );
        let route_commitment_id = wallet_transaction_planner_commitment_id(
            &plan_id,
            CommitmentKind::Route,
            "private-fast-lane",
        );
        let fee_quote_id =
            wallet_transaction_planner_fee_quote_id(&plan_id, &config.default_fee_asset_id, height);
        let sponsor_id = wallet_transaction_planner_sponsor_id(
            &config.default_sponsor_lane,
            "devnet-sponsor",
            &config.default_fee_asset_id,
        );
        let selection_id = wallet_transaction_planner_sponsorship_selection_id(
            &plan_id,
            &sponsor_id,
            SponsorSelectionMode::PreferPrivateSponsor,
        );
        let envelope_id = wallet_transaction_planner_offline_envelope_id(
            &plan_id,
            &account_id,
            "hardware-signer-1",
            height,
        );
        let plan = WalletTransactionPlan {
            plan_id: plan_id.clone(),
            plan_kind: WalletPlanKind::PrivateTransfer,
            status: WalletPlanStatus::ReadyForSigning,
            account_id: account_id.clone(),
            privacy_budget_id: privacy_budget_id.clone(),
            fee_quote_id: fee_quote_id.clone(),
            sponsor_selection_id: selection_id.clone(),
            route_commitment_id: route_commitment_id.clone(),
            bridge_commitment_id: String::new(),
            offline_envelope_id: envelope_id.clone(),
            asset_id: config.default_fee_asset_id.clone(),
            amount_bucket: 50_000,
            destination_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-DESTINATION",
                "recipient-output-commitment",
            ),
            call_target: String::new(),
            intent_payload_root: intent_payload_root.clone(),
            user_memo_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-MEMO",
                "private memo",
            ),
            created_at_height: height,
            expires_at_height: height + config.default_plan_ttl_blocks,
            dependency_roots: BTreeMap::from([(
                "privacy_budget".to_string(),
                privacy_budget.budget_root(),
            )]),
            metadata: BTreeMap::from([(
                "purpose".to_string(),
                "devnet private transfer".to_string(),
            )]),
        };

        let sponsor = LowFeeSponsorCandidate {
            sponsor_id: sponsor_id.clone(),
            sponsor_account: "sponsor-pq-account-devnet".to_string(),
            lane_id: config.default_sponsor_lane.clone(),
            supported_plan_kinds: BTreeSet::from([
                WalletPlanKind::PrivateTransfer,
                WalletPlanKind::PrivateDefi,
                WalletPlanKind::PrivateContract,
            ]),
            fee_asset_id: config.default_fee_asset_id.clone(),
            max_fee_micro_units: 900,
            available_budget_micro_units: 500_000,
            privacy_score_bps: 9_100,
            reliability_score_bps: 9_500,
            pq_authorization_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-SPONSOR-PQ",
                "sponsor-pq-auth",
            ),
            terms_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-SPONSOR-TERMS",
                "low-fee-private-transfer",
            ),
            valid_until_height: height + 144,
            metadata: BTreeMap::from([("rebate".to_string(), "devnet".to_string())]),
        };

        let selection = LowFeeSponsorshipSelection {
            selection_id: selection_id.clone(),
            plan_id: plan_id.clone(),
            mode: SponsorSelectionMode::PreferPrivateSponsor,
            sponsor_id: sponsor_id.clone(),
            reservation_nullifier: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-RESERVATION",
                &plan_id,
            ),
            sponsored_fee_micro_units: 475,
            self_pay_fee_micro_units: 900,
            rebate_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-REBATE",
                &selection_id,
            ),
            selection_reason_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-SELECTION-REASON",
                "private sponsor better fee",
            ),
            selected_at_height: height,
            expires_at_height: height + config.default_quote_ttl_blocks,
            metadata: BTreeMap::new(),
        };

        let commitment = RouteDepositWithdrawalCommitment {
            commitment_id: route_commitment_id.clone(),
            plan_id: plan_id.clone(),
            commitment_kind: CommitmentKind::Route,
            route_id: "private-fast-lane".to_string(),
            source_domain: "nebula-l2-private".to_string(),
            destination_domain: "nebula-l2-private".to_string(),
            input_commitment_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-INPUT-COMMITMENT",
                &plan_id,
            ),
            output_commitment_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-OUTPUT-COMMITMENT",
                &plan_id,
            ),
            deposit_address_commitment: String::new(),
            withdrawal_address_commitment: String::new(),
            path_commitments: vec![wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-PATH",
                "wallet-private-transfer-route",
            )],
            slippage_bps: 0,
            min_output_bucket: 49_000,
            timeout_height: height + config.default_plan_ttl_blocks,
            metadata: BTreeMap::new(),
        };

        let proof = ProofRequirement {
            requirement_id: wallet_transaction_planner_proof_requirement_id(
                &plan_id,
                ProofRequirementKind::PqSignature,
                "wallet-transfer-v1",
            ),
            plan_id: plan_id.clone(),
            proof_kind: ProofRequirementKind::PqSignature,
            circuit_id: "wallet-transfer-v1".to_string(),
            witness_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-WITNESS",
                &plan_id,
            ),
            public_inputs_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-PUBLIC-INPUTS",
                &plan_id,
            ),
            recursive_parent_root: String::new(),
            proving_market_hint: "local-wallet-prover".to_string(),
            required_before_height: height + 48,
            estimated_constraints: 880_000,
            metadata: BTreeMap::new(),
        };

        let quote = FeeQuote {
            quote_id: fee_quote_id.clone(),
            plan_id: plan_id.clone(),
            fee_asset_id: config.default_fee_asset_id.clone(),
            base_fee_micro_units: 300,
            proof_fee_micro_units: 150,
            da_fee_micro_units: 75,
            sponsor_discount_micro_units: 50,
            total_fee_micro_units: 475,
            max_fee_micro_units: 900,
            quote_source: "devnet-low-fee-market".to_string(),
            quote_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-QUOTE",
                &fee_quote_id,
            ),
            quoted_at_height: height,
            expires_at_height: height + config.default_quote_ttl_blocks,
            metadata: BTreeMap::new(),
        };

        let risk_check = WalletRiskCheck {
            check_id: wallet_transaction_planner_risk_check_id(
                &plan_id,
                "spend-limit",
                RiskCheckStatus::Passed,
            ),
            plan_id: plan_id.clone(),
            status: RiskCheckStatus::Passed,
            severity: RiskSeverity::Low,
            policy_id: "wallet-default-spend-limit".to_string(),
            reason_code: "amount_bucket_within_limit".to_string(),
            observed_value_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-RISK-OBSERVED",
                "50000",
            ),
            threshold_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-RISK-THRESHOLD",
                "100000",
            ),
            mitigation_hint: "none".to_string(),
            requires_user_ack: false,
            checked_at_height: height,
            expires_at_height: height + config.default_risk_window_blocks,
            metadata: BTreeMap::new(),
        };

        let envelope = OfflineSigningEnvelope {
            envelope_id: envelope_id.clone(),
            plan_id: plan_id.clone(),
            status: OfflineEnvelopeStatus::Prepared,
            account_id: account_id.clone(),
            signing_device_hint: "hardware-signer-1".to_string(),
            unsigned_payload_root: plan.plan_root(),
            signer_policy_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-SIGNER-POLICY",
                "require-hardware-pq",
            ),
            pq_transcript_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-PQ-TRANSCRIPT",
                &envelope_id,
            ),
            export_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-EXPORT",
                &envelope_id,
            ),
            import_commitment: String::new(),
            signature_commitment: String::new(),
            created_at_height: height,
            expires_at_height: height + config.default_offline_ttl_blocks,
            metadata: BTreeMap::new(),
        };

        let lifecycle_hint = TransactionLifecycleHint {
            hint_id: wallet_transaction_planner_lifecycle_hint_id(
                &plan_id,
                WalletPlanStatus::ReadyForSigning,
                height,
            ),
            plan_id: plan_id.clone(),
            status_hint: WalletPlanStatus::ReadyForSigning,
            expected_next_status: WalletPlanStatus::OfflineExported,
            earliest_submit_height: height,
            latest_submit_height: height + config.default_plan_ttl_blocks,
            expected_inclusion_blocks: 3,
            finality_target_blocks: 20,
            replacement_allowed: true,
            cancel_commitment: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-CANCEL",
                &plan_id,
            ),
            watchtower_hint_root: wallet_transaction_planner_string_root(
                "WALLET-TX-PLANNER-DEVNET-WATCHTOWER-HINT",
                &plan_id,
            ),
            metadata: BTreeMap::new(),
        };

        let state = Self {
            config,
            height,
            accounts: BTreeMap::from([(account_id, account)]),
            privacy_budgets: BTreeMap::from([(privacy_budget_id, privacy_budget)]),
            plans: BTreeMap::from([(plan_id, plan)]),
            sponsor_candidates: BTreeMap::from([(sponsor_id, sponsor)]),
            sponsorship_selections: BTreeMap::from([(selection_id, selection)]),
            commitments: BTreeMap::from([(route_commitment_id, commitment)]),
            proof_requirements: BTreeMap::from([(proof.requirement_id.clone(), proof)]),
            fee_quotes: BTreeMap::from([(fee_quote_id, quote)]),
            risk_checks: BTreeMap::from([(risk_check.check_id.clone(), risk_check)]),
            offline_envelopes: BTreeMap::from([(envelope_id, envelope)]),
            lifecycle_hints: BTreeMap::from([(lifecycle_hint.hint_id.clone(), lifecycle_hint)]),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn roots(&self) -> WalletTransactionPlannerRoots {
        WalletTransactionPlannerRoots {
            config_root: self.config.config_root(),
            accounts_root: quantum_account_requirement_collection_root(&self.accounts),
            privacy_budgets_root: privacy_budget_selection_collection_root(&self.privacy_budgets),
            plans_root: wallet_transaction_plan_collection_root(&self.plans),
            sponsor_candidates_root: low_fee_sponsor_candidate_collection_root(
                &self.sponsor_candidates,
            ),
            sponsorship_selections_root: low_fee_sponsorship_selection_collection_root(
                &self.sponsorship_selections,
            ),
            commitments_root: route_deposit_withdrawal_commitment_collection_root(
                &self.commitments,
            ),
            proof_requirements_root: proof_requirement_collection_root(&self.proof_requirements),
            fee_quotes_root: fee_quote_collection_root(&self.fee_quotes),
            risk_checks_root: wallet_risk_check_collection_root(&self.risk_checks),
            offline_envelopes_root: offline_signing_envelope_collection_root(
                &self.offline_envelopes,
            ),
            lifecycle_hints_root: transaction_lifecycle_hint_collection_root(&self.lifecycle_hints),
        }
    }

    pub fn counters(&self) -> WalletTransactionPlannerCounters {
        WalletTransactionPlannerCounters {
            accounts: self.accounts.len(),
            privacy_budgets: self.privacy_budgets.len(),
            plans: self.plans.len(),
            live_plans: self
                .plans
                .values()
                .filter(|plan| plan.status.is_live())
                .count(),
            terminal_plans: self
                .plans
                .values()
                .filter(|plan| plan.status.is_terminal())
                .count(),
            sponsor_candidates: self.sponsor_candidates.len(),
            sponsorship_selections: self.sponsorship_selections.len(),
            commitments: self.commitments.len(),
            proof_requirements: self.proof_requirements.len(),
            fee_quotes: self.fee_quotes.len(),
            risk_checks: self.risk_checks.len(),
            blocking_risk_checks: self
                .risk_checks
                .values()
                .filter(|check| matches!(check.status, RiskCheckStatus::Blocked))
                .count(),
            offline_envelopes: self.offline_envelopes.len(),
            lifecycle_hints: self.lifecycle_hints.len(),
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        wallet_transaction_planner_state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn validate(&self) -> WalletTransactionPlannerResult<String> {
        self.config.validate()?;
        ensure_eq(&self.config.chain_id, CHAIN_ID, "state chain id")?;
        ensure_len_at_most(self.accounts.len(), self.config.max_accounts, "accounts")?;
        ensure_len_at_most(
            self.privacy_budgets.len(),
            self.config.max_privacy_budgets,
            "privacy budgets",
        )?;
        ensure_len_at_most(self.plans.len(), self.config.max_plans, "plans")?;
        ensure_len_at_most(
            self.sponsor_candidates.len(),
            self.config.max_sponsors,
            "sponsor candidates",
        )?;
        ensure_len_at_most(
            self.commitments.len(),
            self.config.max_commitments,
            "commitments",
        )?;
        ensure_len_at_most(
            self.proof_requirements.len(),
            self.config.max_proofs,
            "proof requirements",
        )?;
        ensure_len_at_most(
            self.fee_quotes.len(),
            self.config.max_fee_quotes,
            "fee quotes",
        )?;
        ensure_len_at_most(
            self.risk_checks.len(),
            self.config.max_risk_checks,
            "risk checks",
        )?;
        ensure_len_at_most(
            self.offline_envelopes.len(),
            self.config.max_offline_envelopes,
            "offline envelopes",
        )?;
        ensure_len_at_most(
            self.lifecycle_hints.len(),
            self.config.max_lifecycle_hints,
            "lifecycle hints",
        )?;

        for (id, account) in &self.accounts {
            ensure_eq(id, &account.account_id, "account map id")?;
            account.validate(&self.config)?;
        }
        for (id, budget) in &self.privacy_budgets {
            ensure_eq(id, &budget.budget_id, "privacy budget map id")?;
            budget.validate()?;
            self.ensure_account_exists(&budget.account_id, "privacy budget")?;
            if budget.expires_at_height < self.height {
                return Err("privacy budget expired before planner height".to_string());
            }
        }
        for (id, sponsor) in &self.sponsor_candidates {
            ensure_eq(id, &sponsor.sponsor_id, "sponsor map id")?;
            sponsor.validate()?;
        }
        for (id, selection) in &self.sponsorship_selections {
            ensure_eq(id, &selection.selection_id, "sponsorship selection map id")?;
            selection.validate()?;
            self.ensure_plan_exists(&selection.plan_id, "sponsorship selection")?;
            if !matches!(selection.mode, SponsorSelectionMode::Disabled) {
                self.ensure_sponsor_exists(&selection.sponsor_id, "sponsorship selection")?;
            }
        }
        for (id, commitment) in &self.commitments {
            ensure_eq(id, &commitment.commitment_id, "commitment map id")?;
            commitment.validate()?;
            self.ensure_plan_exists(&commitment.plan_id, "commitment")?;
        }
        for (id, proof) in &self.proof_requirements {
            ensure_eq(id, &proof.requirement_id, "proof requirement map id")?;
            proof.validate()?;
            self.ensure_plan_exists(&proof.plan_id, "proof requirement")?;
        }
        for (id, quote) in &self.fee_quotes {
            ensure_eq(id, &quote.quote_id, "fee quote map id")?;
            quote.validate()?;
            self.ensure_plan_exists(&quote.plan_id, "fee quote")?;
        }
        for (id, check) in &self.risk_checks {
            ensure_eq(id, &check.check_id, "risk check map id")?;
            check.validate()?;
            self.ensure_plan_exists(&check.plan_id, "risk check")?;
        }
        for (id, envelope) in &self.offline_envelopes {
            ensure_eq(id, &envelope.envelope_id, "offline envelope map id")?;
            envelope.validate()?;
            self.ensure_plan_exists(&envelope.plan_id, "offline envelope")?;
            self.ensure_account_exists(&envelope.account_id, "offline envelope")?;
        }
        for (id, hint) in &self.lifecycle_hints {
            ensure_eq(id, &hint.hint_id, "lifecycle hint map id")?;
            hint.validate()?;
            self.ensure_plan_exists(&hint.plan_id, "lifecycle hint")?;
        }
        for (id, plan) in &self.plans {
            ensure_eq(id, &plan.plan_id, "plan map id")?;
            plan.validate()?;
            self.ensure_account_exists(&plan.account_id, "plan")?;
            self.ensure_privacy_budget_exists(&plan.privacy_budget_id, "plan")?;
            if !plan.fee_quote_id.is_empty() {
                self.ensure_fee_quote_exists(&plan.fee_quote_id, "plan")?;
            }
            if !plan.sponsor_selection_id.is_empty() {
                self.ensure_sponsorship_selection_exists(&plan.sponsor_selection_id, "plan")?;
            }
            if !plan.route_commitment_id.is_empty() {
                self.ensure_commitment_exists(&plan.route_commitment_id, "plan")?;
            }
            if !plan.bridge_commitment_id.is_empty() {
                self.ensure_commitment_exists(&plan.bridge_commitment_id, "plan")?;
            }
            if !plan.offline_envelope_id.is_empty() {
                self.ensure_offline_envelope_exists(&plan.offline_envelope_id, "plan")?;
            }
            self.ensure_account_allows_plan(&plan.account_id, plan.plan_kind)?;
            if plan.expires_at_height < self.height && plan.status.is_live() {
                return Err("live plan expired before planner height".to_string());
            }
        }

        Ok(self.state_root())
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "chain_id": self.config.chain_id,
            "height": self.height,
            "protocol_version": self.config.protocol_version,
            "roots": self.roots().public_record(),
            "roots_root": self.roots().roots_root(),
            "counters": self.counters().public_record(),
            "counters_root": self.counters().counters_root(),
        })
    }

    fn ensure_account_exists(
        &self,
        account_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.accounts.contains_key(account_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown account"))
        }
    }

    fn ensure_account_allows_plan(
        &self,
        account_id: &str,
        plan_kind: WalletPlanKind,
    ) -> WalletTransactionPlannerResult<()> {
        match self.accounts.get(account_id) {
            Some(account) if account.allowed_plan_kinds.contains(&plan_kind) => Ok(()),
            Some(_) => Err("account does not allow plan kind".to_string()),
            None => Err("plan references unknown account".to_string()),
        }
    }

    fn ensure_privacy_budget_exists(
        &self,
        budget_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.privacy_budgets.contains_key(budget_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown privacy budget"))
        }
    }

    fn ensure_plan_exists(
        &self,
        plan_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.plans.contains_key(plan_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown plan"))
        }
    }

    fn ensure_sponsor_exists(
        &self,
        sponsor_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.sponsor_candidates.contains_key(sponsor_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown sponsor"))
        }
    }

    fn ensure_sponsorship_selection_exists(
        &self,
        selection_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.sponsorship_selections.contains_key(selection_id) {
            Ok(())
        } else {
            Err(format!(
                "{context} references unknown sponsorship selection"
            ))
        }
    }

    fn ensure_commitment_exists(
        &self,
        commitment_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.commitments.contains_key(commitment_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown commitment"))
        }
    }

    fn ensure_fee_quote_exists(
        &self,
        quote_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.fee_quotes.contains_key(quote_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown fee quote"))
        }
    }

    fn ensure_offline_envelope_exists(
        &self,
        envelope_id: &str,
        context: &str,
    ) -> WalletTransactionPlannerResult<()> {
        if self.offline_envelopes.contains_key(envelope_id) {
            Ok(())
        } else {
            Err(format!("{context} references unknown offline envelope"))
        }
    }
}

pub type Config = WalletTransactionPlannerConfig;
pub type State = WalletTransactionPlannerState;
pub type Roots = WalletTransactionPlannerRoots;
pub type Counters = WalletTransactionPlannerCounters;

pub fn wallet_transaction_planner_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(CHAIN_ID), HashPart::Json(payload)],
        32,
    )
}

pub fn wallet_transaction_planner_state_root_from_record(record: &Value) -> String {
    wallet_transaction_planner_payload_root("WALLET-TX-PLANNER-STATE", record)
}

pub fn wallet_transaction_planner_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(CHAIN_ID), HashPart::Str(value)], 32)
}

pub fn wallet_transaction_planner_value_collection_root(
    domain: &str,
    records: Vec<Value>,
) -> String {
    merkle_root(domain, &records)
}

pub fn wallet_transaction_planner_public_record_id(label: &str, record: &Value) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_account_id(
    wallet_label: &str,
    account_kind: WalletAccountKind,
    account_hint: &str,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-ACCOUNT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(wallet_label),
            HashPart::Str(account_kind.as_str()),
            HashPart::Str(account_hint),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_privacy_budget_id(
    account_id: &str,
    mode: PrivacyBudgetMode,
    pool_id: &str,
    height: u64,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-PRIVACY-BUDGET-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(pool_id),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_plan_id(
    account_id: &str,
    plan_kind: WalletPlanKind,
    intent_payload_root: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-PLAN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(account_id),
            HashPart::Str(plan_kind.as_str()),
            HashPart::Str(intent_payload_root),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_sponsor_id(
    lane_id: &str,
    sponsor_account: &str,
    fee_asset_id: &str,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-SPONSOR-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane_id),
            HashPart::Str(sponsor_account),
            HashPart::Str(fee_asset_id),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_sponsorship_selection_id(
    plan_id: &str,
    sponsor_id: &str,
    mode: SponsorSelectionMode,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-SPONSORSHIP-SELECTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(sponsor_id),
            HashPart::Str(mode.as_str()),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_commitment_id(
    plan_id: &str,
    commitment_kind: CommitmentKind,
    route_id: &str,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-COMMITMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(commitment_kind.as_str()),
            HashPart::Str(route_id),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_proof_requirement_id(
    plan_id: &str,
    proof_kind: ProofRequirementKind,
    circuit_id: &str,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-PROOF-REQUIREMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(proof_kind.as_str()),
            HashPart::Str(circuit_id),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_fee_quote_id(
    plan_id: &str,
    fee_asset_id: &str,
    quoted_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-FEE-QUOTE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(fee_asset_id),
            HashPart::Int(quoted_at_height as i128),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_risk_check_id(
    plan_id: &str,
    policy_id: &str,
    status: RiskCheckStatus,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-RISK-CHECK-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(policy_id),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_offline_envelope_id(
    plan_id: &str,
    account_id: &str,
    signer_hint: &str,
    created_at_height: u64,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-OFFLINE-ENVELOPE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(account_id),
            HashPart::Str(signer_hint),
            HashPart::Int(created_at_height as i128),
        ],
        32,
    )
}

pub fn wallet_transaction_planner_lifecycle_hint_id(
    plan_id: &str,
    status_hint: WalletPlanStatus,
    height: u64,
) -> String {
    domain_hash(
        "WALLET-TX-PLANNER-LIFECYCLE-HINT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(plan_id),
            HashPart::Str(status_hint.as_str()),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn quantum_account_requirement_collection_root(
    accounts: &BTreeMap<String, QuantumAccountRequirement>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-ACCOUNT-COLLECTION",
        &accounts
            .values()
            .map(QuantumAccountRequirement::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn privacy_budget_selection_collection_root(
    budgets: &BTreeMap<String, PrivacyBudgetSelection>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-PRIVACY-BUDGET-COLLECTION",
        &budgets
            .values()
            .map(PrivacyBudgetSelection::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_transaction_plan_collection_root(
    plans: &BTreeMap<String, WalletTransactionPlan>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-PLAN-COLLECTION",
        &plans
            .values()
            .map(WalletTransactionPlan::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsor_candidate_collection_root(
    sponsors: &BTreeMap<String, LowFeeSponsorCandidate>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-SPONSOR-CANDIDATE-COLLECTION",
        &sponsors
            .values()
            .map(LowFeeSponsorCandidate::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn low_fee_sponsorship_selection_collection_root(
    selections: &BTreeMap<String, LowFeeSponsorshipSelection>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-SPONSORSHIP-SELECTION-COLLECTION",
        &selections
            .values()
            .map(LowFeeSponsorshipSelection::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn route_deposit_withdrawal_commitment_collection_root(
    commitments: &BTreeMap<String, RouteDepositWithdrawalCommitment>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-COMMITMENT-COLLECTION",
        &commitments
            .values()
            .map(RouteDepositWithdrawalCommitment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn proof_requirement_collection_root(
    requirements: &BTreeMap<String, ProofRequirement>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-PROOF-REQUIREMENT-COLLECTION",
        &requirements
            .values()
            .map(ProofRequirement::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn fee_quote_collection_root(quotes: &BTreeMap<String, FeeQuote>) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-FEE-QUOTE-COLLECTION",
        &quotes
            .values()
            .map(FeeQuote::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn wallet_risk_check_collection_root(checks: &BTreeMap<String, WalletRiskCheck>) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-RISK-CHECK-COLLECTION",
        &checks
            .values()
            .map(WalletRiskCheck::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn offline_signing_envelope_collection_root(
    envelopes: &BTreeMap<String, OfflineSigningEnvelope>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-OFFLINE-ENVELOPE-COLLECTION",
        &envelopes
            .values()
            .map(OfflineSigningEnvelope::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn transaction_lifecycle_hint_collection_root(
    hints: &BTreeMap<String, TransactionLifecycleHint>,
) -> String {
    merkle_root(
        "WALLET-TX-PLANNER-LIFECYCLE-HINT-COLLECTION",
        &hints
            .values()
            .map(TransactionLifecycleHint::public_record)
            .collect::<Vec<_>>(),
    )
}

fn ensure_non_empty(value: &str, label: &str) -> WalletTransactionPlannerResult<()> {
    if value.trim().is_empty() {
        Err(format!("{label} is required"))
    } else {
        Ok(())
    }
}

fn ensure_positive(value: u64, label: &str) -> WalletTransactionPlannerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_usize_positive(value: usize, label: &str) -> WalletTransactionPlannerResult<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, label: &str) -> WalletTransactionPlannerResult<()> {
    if value > WALLET_TRANSACTION_PLANNER_MAX_BPS {
        Err(format!("{label} exceeds basis point maximum"))
    } else {
        Ok(())
    }
}

fn ensure_eq(left: &str, right: &str, label: &str) -> WalletTransactionPlannerResult<()> {
    if left == right {
        Ok(())
    } else {
        Err(format!("{label} mismatch"))
    }
}

fn ensure_len_at_most(value: usize, max: usize, label: &str) -> WalletTransactionPlannerResult<()> {
    if value > max {
        Err(format!("{label} exceeds configured maximum"))
    } else {
        Ok(())
    }
}

fn ensure_non_empty_set<T>(
    values: &BTreeSet<T>,
    label: &str,
) -> WalletTransactionPlannerResult<()> {
    if values.is_empty() {
        Err(format!("{label} must not be empty"))
    } else {
        Ok(())
    }
}
