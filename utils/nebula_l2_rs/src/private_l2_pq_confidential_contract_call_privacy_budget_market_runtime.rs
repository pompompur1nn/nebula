use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<T> = Result<T>;
pub type Runtime = State;

macro_rules! ensure {
    ($condition:expr, $($arg:tt)+) => {
        if !$condition {
            return Err(format!($($arg)+));
        }
    };
}

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_CALL_PRIVACY_BUDGET_MARKET_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-call-privacy-budget-market-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_CALL_PRIVACY_BUDGET_MARKET_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str =
    "ML-DSA-87+SLH-DSA-SHAKE-256f-contract-call-budget-attestation-v1";
pub const SEALED_BUDGET_SUITE: &str =
    "ML-KEM-1024+XChaCha20Poly1305+sealed-call-budget-envelope-v1";
pub const NAMESPACE_COMMITMENT_SUITE: &str = "monero-l2-contract-namespace-commitment-root-v1";
pub const PRIVACY_CREDIT_SCHEME: &str = "fee-priced-confidential-privacy-credit-v1";
pub const PRIVACY_FENCE_SCHEME: &str = "monero-l2-call-budget-nullifier-fence-v1";
pub const ABUSE_QUARANTINE_SCHEME: &str = "pq-confidential-call-budget-abuse-quarantine-v1";
pub const DEVNET_HEIGHT: u64 = 1_386_000;
pub const DEVNET_EPOCH: u64 = 1_927;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_BUDGET_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_ATTESTATION_TTL_BLOCKS: u64 = 1_440;
pub const DEFAULT_CREDIT_TTL_BLOCKS: u64 = 7_200;
pub const DEFAULT_REBATE_TTL_BLOCKS: u64 = 2_160;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 10_080;
pub const DEFAULT_ABUSE_WINDOW_BLOCKS: u64 = 7_200;
pub const DEFAULT_MIN_PRIVACY_SET: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET: u64 = 524_288;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_BASE_CREDIT_PRICE: u128 = 25_000;
pub const DEFAULT_MIN_CREDIT_PRICE: u128 = 5_000;
pub const DEFAULT_MAX_CREDIT_PRICE: u128 = 250_000;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 1_200;
pub const DEFAULT_ABUSE_SLASH_BPS: u64 = 2_500;
pub const DEFAULT_QUARANTINE_RESERVE_BPS: u64 = 1_000;
pub const DEFAULT_MAX_NAMESPACES: usize = 1_048_576;
pub const DEFAULT_MAX_BUDGETS: usize = 16_777_216;
pub const DEFAULT_MAX_ATTESTATIONS: usize = 33_554_432;
pub const DEFAULT_MAX_CREDITS: usize = 67_108_864;
pub const DEFAULT_MAX_REBATES: usize = 16_777_216;
pub const DEFAULT_MAX_ABUSE_REPORTS: usize = 8_388_608;
pub const DEFAULT_MAX_QUARANTINES: usize = 8_388_608;
pub const DEFAULT_MAX_SETTLEMENTS: usize = 33_554_432;
pub const DEFAULT_MAX_PRIVACY_FENCES: usize = 67_108_864;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceKind {
    DefiRouter,
    LendingPool,
    Perpetuals,
    Options,
    BridgeAdapter,
    OracleAdapter,
    AccountAbstraction,
    Governance,
    NftRoyalty,
    CustomContract,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceStatus {
    Proposed,
    Active,
    Congested,
    Throttled,
    Quarantined,
    Draining,
    Retired,
}

impl NamespaceStatus {
    pub fn can_accept_budget(self) -> bool {
        matches!(
            self,
            Self::Proposed | Self::Active | Self::Congested | Self::Throttled
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetClass {
    ReadOnlyCall,
    StateChangingCall,
    CrossContractCall,
    BatchCall,
    LiquidationCall,
    BridgeCall,
    OracleCall,
    GovernanceCall,
    EmergencyCall,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetStatus {
    Sealed,
    Attested,
    Funded,
    Reserved,
    PartiallySpent,
    Exhausted,
    RebateQueued,
    Settled,
    Expired,
    Quarantined,
    Slashed,
    Cancelled,
}

impl BudgetStatus {
    pub fn spendable(self) -> bool {
        matches!(
            self,
            Self::Attested | Self::Funded | Self::Reserved | Self::PartiallySpent
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    PqSignerSet,
    BudgetOpening,
    NamespaceBinding,
    CreditPrice,
    CallTrace,
    PrivacySet,
    RebateEligibility,
    AbuseReview,
    EmergencyFreeze,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    Accepted,
    Superseded,
    Disputed,
    Revoked,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Minted,
    Reserved,
    BoundToBudget,
    Spent,
    RebateQueued,
    Rebated,
    Expired,
    Slashed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Pending,
    Claimable,
    Claimed,
    DonatedToNamespace,
    Expired,
    Denied,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseKind {
    NamespaceSpray,
    BudgetReplay,
    NullifierReuse,
    CreditWash,
    FeeEvasion,
    AttestationForgery,
    PrivacySetCollapse,
    ContractSpam,
    QuarantineBypass,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseStatus {
    Reported,
    EvidenceCommitted,
    UnderReview,
    Accepted,
    Rejected,
    Quarantined,
    Settled,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineScope {
    Budget,
    Namespace,
    Attestor,
    CreditIssuer,
    Nullifier,
    ContractCluster,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Open,
    EvidenceLocked,
    Active,
    CoolingOff,
    Released,
    Slashed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Proposed,
    CreditsPriced,
    BudgetDebited,
    RebateComputed,
    Finalized,
    Disputed,
    Reverted,
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub sealed_budget_suite: String,
    pub namespace_commitment_suite: String,
    pub privacy_credit_scheme: String,
    pub privacy_fence_scheme: String,
    pub abuse_quarantine_scheme: String,
    pub min_privacy_set: u64,
    pub target_privacy_set: u64,
    pub min_pq_security_bits: u16,
    pub epoch_blocks: u64,
    pub budget_ttl_blocks: u64,
    pub attestation_ttl_blocks: u64,
    pub credit_ttl_blocks: u64,
    pub rebate_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub abuse_window_blocks: u64,
    pub base_credit_price: u128,
    pub min_credit_price: u128,
    pub max_credit_price: u128,
    pub low_fee_rebate_bps: u64,
    pub abuse_slash_bps: u64,
    pub quarantine_reserve_bps: u64,
    pub max_namespaces: usize,
    pub max_budgets: usize,
    pub max_attestations: usize,
    pub max_credits: usize,
    pub max_rebates: usize,
    pub max_abuse_reports: usize,
    pub max_quarantines: usize,
    pub max_settlements: usize,
    pub max_privacy_fences: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            sealed_budget_suite: SEALED_BUDGET_SUITE.to_string(),
            namespace_commitment_suite: NAMESPACE_COMMITMENT_SUITE.to_string(),
            privacy_credit_scheme: PRIVACY_CREDIT_SCHEME.to_string(),
            privacy_fence_scheme: PRIVACY_FENCE_SCHEME.to_string(),
            abuse_quarantine_scheme: ABUSE_QUARANTINE_SCHEME.to_string(),
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            target_privacy_set: DEFAULT_TARGET_PRIVACY_SET,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            epoch_blocks: DEFAULT_EPOCH_BLOCKS,
            budget_ttl_blocks: DEFAULT_BUDGET_TTL_BLOCKS,
            attestation_ttl_blocks: DEFAULT_ATTESTATION_TTL_BLOCKS,
            credit_ttl_blocks: DEFAULT_CREDIT_TTL_BLOCKS,
            rebate_ttl_blocks: DEFAULT_REBATE_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            abuse_window_blocks: DEFAULT_ABUSE_WINDOW_BLOCKS,
            base_credit_price: DEFAULT_BASE_CREDIT_PRICE,
            min_credit_price: DEFAULT_MIN_CREDIT_PRICE,
            max_credit_price: DEFAULT_MAX_CREDIT_PRICE,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            abuse_slash_bps: DEFAULT_ABUSE_SLASH_BPS,
            quarantine_reserve_bps: DEFAULT_QUARANTINE_RESERVE_BPS,
            max_namespaces: DEFAULT_MAX_NAMESPACES,
            max_budgets: DEFAULT_MAX_BUDGETS,
            max_attestations: DEFAULT_MAX_ATTESTATIONS,
            max_credits: DEFAULT_MAX_CREDITS,
            max_rebates: DEFAULT_MAX_REBATES,
            max_abuse_reports: DEFAULT_MAX_ABUSE_REPORTS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_settlements: DEFAULT_MAX_SETTLEMENTS,
            max_privacy_fences: DEFAULT_MAX_PRIVACY_FENCES,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "sealed_budget_suite": self.sealed_budget_suite,
            "namespace_commitment_suite": self.namespace_commitment_suite,
            "privacy_credit_scheme": self.privacy_credit_scheme,
            "privacy_fence_scheme": self.privacy_fence_scheme,
            "abuse_quarantine_scheme": self.abuse_quarantine_scheme,
            "min_privacy_set": self.min_privacy_set,
            "target_privacy_set": self.target_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "epoch_blocks": self.epoch_blocks,
            "budget_ttl_blocks": self.budget_ttl_blocks,
            "attestation_ttl_blocks": self.attestation_ttl_blocks,
            "credit_ttl_blocks": self.credit_ttl_blocks,
            "rebate_ttl_blocks": self.rebate_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "abuse_window_blocks": self.abuse_window_blocks,
            "base_credit_price": self.base_credit_price.to_string(),
            "min_credit_price": self.min_credit_price.to_string(),
            "max_credit_price": self.max_credit_price.to_string(),
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "abuse_slash_bps": self.abuse_slash_bps,
            "quarantine_reserve_bps": self.quarantine_reserve_bps,
            "max_namespaces": self.max_namespaces,
            "max_budgets": self.max_budgets,
            "max_attestations": self.max_attestations,
            "max_credits": self.max_credits,
            "max_rebates": self.max_rebates,
            "max_abuse_reports": self.max_abuse_reports,
            "max_quarantines": self.max_quarantines,
            "max_settlements": self.max_settlements,
            "max_privacy_fences": self.max_privacy_fences
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Counters {
    pub next_namespace: u64,
    pub next_budget: u64,
    pub next_attestation: u64,
    pub next_credit: u64,
    pub next_rebate: u64,
    pub next_abuse_report: u64,
    pub next_quarantine: u64,
    pub next_settlement: u64,
    pub next_privacy_fence: u64,
    pub namespaces_registered: u64,
    pub sealed_budgets_submitted: u64,
    pub budget_attestations_accepted: u64,
    pub credits_minted: u64,
    pub credits_spent: u64,
    pub rebates_queued: u64,
    pub rebates_claimed: u64,
    pub abuse_reports_accepted: u64,
    pub quarantines_opened: u64,
    pub quarantines_released: u64,
    pub settlements_finalized: u64,
    pub fences_registered: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "next_namespace": self.next_namespace,
            "next_budget": self.next_budget,
            "next_attestation": self.next_attestation,
            "next_credit": self.next_credit,
            "next_rebate": self.next_rebate,
            "next_abuse_report": self.next_abuse_report,
            "next_quarantine": self.next_quarantine,
            "next_settlement": self.next_settlement,
            "next_privacy_fence": self.next_privacy_fence,
            "namespaces_registered": self.namespaces_registered,
            "sealed_budgets_submitted": self.sealed_budgets_submitted,
            "budget_attestations_accepted": self.budget_attestations_accepted,
            "credits_minted": self.credits_minted,
            "credits_spent": self.credits_spent,
            "rebates_queued": self.rebates_queued,
            "rebates_claimed": self.rebates_claimed,
            "abuse_reports_accepted": self.abuse_reports_accepted,
            "quarantines_opened": self.quarantines_opened,
            "quarantines_released": self.quarantines_released,
            "settlements_finalized": self.settlements_finalized,
            "fences_registered": self.fences_registered
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub namespace_root: String,
    pub budget_root: String,
    pub attestation_root: String,
    pub credit_root: String,
    pub rebate_root: String,
    pub abuse_report_root: String,
    pub quarantine_root: String,
    pub settlement_root: String,
    pub privacy_fence_root: String,
    pub accounting_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            config_root: empty_root("CONFIG"),
            namespace_root: empty_root("NAMESPACE"),
            budget_root: empty_root("BUDGET"),
            attestation_root: empty_root("ATTESTATION"),
            credit_root: empty_root("CREDIT"),
            rebate_root: empty_root("REBATE"),
            abuse_report_root: empty_root("ABUSE-REPORT"),
            quarantine_root: empty_root("QUARANTINE"),
            settlement_root: empty_root("SETTLEMENT"),
            privacy_fence_root: empty_root("PRIVACY-FENCE"),
            accounting_root: empty_root("ACCOUNTING"),
            counters_root: empty_root("COUNTERS"),
            state_root: empty_root("STATE"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "namespace_root": self.namespace_root,
            "budget_root": self.budget_root,
            "attestation_root": self.attestation_root,
            "credit_root": self.credit_root,
            "rebate_root": self.rebate_root,
            "abuse_report_root": self.abuse_report_root,
            "quarantine_root": self.quarantine_root,
            "settlement_root": self.settlement_root,
            "privacy_fence_root": self.privacy_fence_root,
            "accounting_root": self.accounting_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct NamespaceCommitmentRecord {
    pub namespace_id: String,
    pub kind: NamespaceKind,
    pub status: NamespaceStatus,
    pub owner_commitment: String,
    pub contract_namespace_commitment: String,
    pub policy_root: String,
    pub allowed_call_root: String,
    pub credit_asset_id: String,
    pub base_credit_price: u128,
    pub surge_price_bps: u64,
    pub low_fee_threshold: u128,
    pub low_fee_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub pending_budget_count: u64,
    pub spent_credit_count: u64,
    pub quarantine_count: u64,
    pub opened_at_height: u64,
    pub last_updated_height: u64,
    pub metadata_root: String,
}

impl NamespaceCommitmentRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "kind": self.kind,
            "status": self.status,
            "owner_commitment": self.owner_commitment,
            "contract_namespace_commitment": self.contract_namespace_commitment,
            "policy_root": self.policy_root,
            "allowed_call_root": self.allowed_call_root,
            "credit_asset_id": self.credit_asset_id,
            "base_credit_price": self.base_credit_price.to_string(),
            "surge_price_bps": self.surge_price_bps,
            "low_fee_threshold": self.low_fee_threshold.to_string(),
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "pending_budget_count": self.pending_budget_count,
            "spent_credit_count": self.spent_credit_count,
            "quarantine_count": self.quarantine_count,
            "opened_at_height": self.opened_at_height,
            "last_updated_height": self.last_updated_height,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SealedCallBudgetRecord {
    pub budget_id: String,
    pub namespace_id: String,
    pub budget_class: BudgetClass,
    pub status: BudgetStatus,
    pub caller_commitment: String,
    pub sealed_budget_commitment: String,
    pub call_bundle_root: String,
    pub call_nullifier: String,
    pub max_call_units: u64,
    pub remaining_call_units: u64,
    pub reserved_credits: u128,
    pub spent_credits: u128,
    pub max_credit_price: u128,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub attestation_ids: BTreeSet<String>,
    pub credit_ids: BTreeSet<String>,
    pub settlement_ids: BTreeSet<String>,
    pub rebate_ids: BTreeSet<String>,
}

impl SealedCallBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "namespace_id": self.namespace_id,
            "budget_class": self.budget_class,
            "status": self.status,
            "caller_commitment": self.caller_commitment,
            "sealed_budget_commitment": self.sealed_budget_commitment,
            "call_bundle_root": self.call_bundle_root,
            "call_nullifier": self.call_nullifier,
            "max_call_units": self.max_call_units,
            "remaining_call_units": self.remaining_call_units,
            "reserved_credits": self.reserved_credits.to_string(),
            "spent_credits": self.spent_credits.to_string(),
            "max_credit_price": self.max_credit_price.to_string(),
            "min_privacy_set": self.min_privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "attestation_ids": sorted_strings(&self.attestation_ids),
            "credit_ids": sorted_strings(&self.credit_ids),
            "settlement_ids": sorted_strings(&self.settlement_ids),
            "rebate_ids": sorted_strings(&self.rebate_ids)
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PqBudgetAttestationRecord {
    pub attestation_id: String,
    pub budget_id: String,
    pub namespace_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
    pub accepted_at_height: u64,
    pub expires_at_height: u64,
}

impl PqBudgetAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "budget_id": self.budget_id,
            "namespace_id": self.namespace_id,
            "kind": self.kind,
            "status": self.status,
            "attestor_commitment": self.attestor_commitment,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "signer_set_root": self.signer_set_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size,
            "accepted_at_height": self.accepted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyCreditRecord {
    pub credit_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub status: CreditStatus,
    pub credit_owner_commitment: String,
    pub credit_asset_id: String,
    pub units: u64,
    pub unit_price: u128,
    pub gross_fee: u128,
    pub reserve_fee: u128,
    pub rebate_bps: u64,
    pub price_attestation_root: String,
    pub minted_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyCreditRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "credit_id": self.credit_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "status": self.status,
            "credit_owner_commitment": self.credit_owner_commitment,
            "credit_asset_id": self.credit_asset_id,
            "units": self.units,
            "unit_price": self.unit_price.to_string(),
            "gross_fee": self.gross_fee.to_string(),
            "reserve_fee": self.reserve_fee.to_string(),
            "rebate_bps": self.rebate_bps,
            "price_attestation_root": self.price_attestation_root,
            "minted_at_height": self.minted_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct LowFeeRebateRecord {
    pub rebate_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub credit_id: String,
    pub status: RebateStatus,
    pub recipient_commitment: String,
    pub rebate_amount: u128,
    pub rebate_bps: u64,
    pub eligibility_root: String,
    pub queued_at_height: u64,
    pub expires_at_height: u64,
}

impl LowFeeRebateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "rebate_id": self.rebate_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "credit_id": self.credit_id,
            "status": self.status,
            "recipient_commitment": self.recipient_commitment,
            "rebate_amount": self.rebate_amount.to_string(),
            "rebate_bps": self.rebate_bps,
            "eligibility_root": self.eligibility_root,
            "queued_at_height": self.queued_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AbuseReportRecord {
    pub report_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub kind: AbuseKind,
    pub status: AbuseStatus,
    pub reporter_commitment: String,
    pub subject_commitment: String,
    pub evidence_root: String,
    pub slash_amount: u128,
    pub reported_at_height: u64,
    pub review_deadline_height: u64,
}

impl AbuseReportRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "kind": self.kind,
            "status": self.status,
            "reporter_commitment": self.reporter_commitment,
            "subject_commitment": self.subject_commitment,
            "evidence_root": self.evidence_root,
            "slash_amount": self.slash_amount.to_string(),
            "reported_at_height": self.reported_at_height,
            "review_deadline_height": self.review_deadline_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub report_id: String,
    pub scope: QuarantineScope,
    pub status: QuarantineStatus,
    pub subject_commitment: String,
    pub quarantine_root: String,
    pub reserved_amount: u128,
    pub opened_at_height: u64,
    pub releases_at_height: u64,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "report_id": self.report_id,
            "scope": self.scope,
            "status": self.status,
            "subject_commitment": self.subject_commitment,
            "quarantine_root": self.quarantine_root,
            "reserved_amount": self.reserved_amount.to_string(),
            "opened_at_height": self.opened_at_height,
            "releases_at_height": self.releases_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct CallSettlementRecord {
    pub settlement_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub credit_id: String,
    pub status: SettlementStatus,
    pub call_receipt_root: String,
    pub spent_units: u64,
    pub charged_fee: u128,
    pub rebate_amount: u128,
    pub post_budget_root: String,
    pub settled_at_height: u64,
}

impl CallSettlementRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "credit_id": self.credit_id,
            "status": self.status,
            "call_receipt_root": self.call_receipt_root,
            "spent_units": self.spent_units,
            "charged_fee": self.charged_fee.to_string(),
            "rebate_amount": self.rebate_amount.to_string(),
            "post_budget_root": self.post_budget_root,
            "settled_at_height": self.settled_at_height
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivacyFenceRecord {
    pub fence_id: String,
    pub namespace_id: String,
    pub budget_id: String,
    pub call_nullifier: String,
    pub anonymity_set_root: String,
    pub view_tag_root: String,
    pub status: BudgetStatus,
    pub registered_at_height: u64,
    pub expires_at_height: u64,
}

impl PrivacyFenceRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "fence_id": self.fence_id,
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "call_nullifier": self.call_nullifier,
            "anonymity_set_root": self.anonymity_set_root,
            "view_tag_root": self.view_tag_root,
            "status": self.status,
            "registered_at_height": self.registered_at_height,
            "expires_at_height": self.expires_at_height
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct Accounting {
    pub total_reserved_credits: u128,
    pub total_spent_credits: u128,
    pub total_rebate_amount: u128,
    pub total_quarantine_reserved: u128,
    pub total_slashed_amount: u128,
    pub total_call_units_reserved: u64,
    pub total_call_units_spent: u64,
}

impl Accounting {
    pub fn public_record(&self) -> Value {
        json!({
            "total_reserved_credits": self.total_reserved_credits.to_string(),
            "total_spent_credits": self.total_spent_credits.to_string(),
            "total_rebate_amount": self.total_rebate_amount.to_string(),
            "total_quarantine_reserved": self.total_quarantine_reserved.to_string(),
            "total_slashed_amount": self.total_slashed_amount.to_string(),
            "total_call_units_reserved": self.total_call_units_reserved,
            "total_call_units_spent": self.total_call_units_spent
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct RegisterNamespaceRequest {
    pub kind: NamespaceKind,
    pub owner_commitment: String,
    pub contract_namespace_commitment: String,
    pub policy_root: String,
    pub allowed_call_root: String,
    pub credit_asset_id: String,
    pub base_credit_price: u128,
    pub surge_price_bps: u64,
    pub low_fee_threshold: u128,
    pub low_fee_rebate_bps: u64,
    pub privacy_set_size: u64,
    pub metadata_root: String,
}

impl RegisterNamespaceRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind,
            "owner_commitment": self.owner_commitment,
            "contract_namespace_commitment": self.contract_namespace_commitment,
            "policy_root": self.policy_root,
            "allowed_call_root": self.allowed_call_root,
            "credit_asset_id": self.credit_asset_id,
            "base_credit_price": self.base_credit_price.to_string(),
            "surge_price_bps": self.surge_price_bps,
            "low_fee_threshold": self.low_fee_threshold.to_string(),
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "privacy_set_size": self.privacy_set_size,
            "metadata_root": self.metadata_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SubmitSealedBudgetRequest {
    pub namespace_id: String,
    pub budget_class: BudgetClass,
    pub caller_commitment: String,
    pub sealed_budget_commitment: String,
    pub call_bundle_root: String,
    pub call_nullifier: String,
    pub max_call_units: u64,
    pub max_credit_price: u128,
    pub min_privacy_set: u64,
    pub pq_security_bits: u16,
    pub anonymity_set_root: String,
    pub view_tag_root: String,
}

impl SubmitSealedBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "budget_class": self.budget_class,
            "caller_commitment": self.caller_commitment,
            "sealed_budget_commitment": self.sealed_budget_commitment,
            "call_bundle_root": self.call_bundle_root,
            "call_nullifier": self.call_nullifier,
            "max_call_units": self.max_call_units,
            "max_credit_price": self.max_credit_price.to_string(),
            "min_privacy_set": self.min_privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "anonymity_set_root": self.anonymity_set_root,
            "view_tag_root": self.view_tag_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct AttestBudgetRequest {
    pub budget_id: String,
    pub kind: AttestationKind,
    pub attestor_commitment: String,
    pub attestation_root: String,
    pub signature_root: String,
    pub signer_set_root: String,
    pub pq_security_bits: u16,
    pub privacy_set_size: u64,
}

impl AttestBudgetRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "kind": self.kind,
            "attestor_commitment": self.attestor_commitment,
            "attestation_root": self.attestation_root,
            "signature_root": self.signature_root,
            "signer_set_root": self.signer_set_root,
            "pq_security_bits": self.pq_security_bits,
            "privacy_set_size": self.privacy_set_size
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct MintPrivacyCreditRequest {
    pub budget_id: String,
    pub credit_owner_commitment: String,
    pub units: u64,
    pub unit_price: u128,
    pub price_attestation_root: String,
}

impl MintPrivacyCreditRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "credit_owner_commitment": self.credit_owner_commitment,
            "units": self.units,
            "unit_price": self.unit_price.to_string(),
            "price_attestation_root": self.price_attestation_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SettleCallRequest {
    pub budget_id: String,
    pub credit_id: String,
    pub call_receipt_root: String,
    pub spent_units: u64,
    pub post_budget_root: String,
}

impl SettleCallRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "credit_id": self.credit_id,
            "call_receipt_root": self.call_receipt_root,
            "spent_units": self.spent_units,
            "post_budget_root": self.post_budget_root
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ReportAbuseRequest {
    pub namespace_id: String,
    pub budget_id: String,
    pub kind: AbuseKind,
    pub reporter_commitment: String,
    pub subject_commitment: String,
    pub evidence_root: String,
    pub requested_scope: QuarantineScope,
}

impl ReportAbuseRequest {
    pub fn public_record(&self) -> Value {
        json!({
            "namespace_id": self.namespace_id,
            "budget_id": self.budget_id,
            "kind": self.kind,
            "reporter_commitment": self.reporter_commitment,
            "subject_commitment": self.subject_commitment,
            "evidence_root": self.evidence_root,
            "requested_scope": self.requested_scope
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub current_epoch: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub namespaces: BTreeMap<String, NamespaceCommitmentRecord>,
    pub budgets: BTreeMap<String, SealedCallBudgetRecord>,
    pub attestations: BTreeMap<String, PqBudgetAttestationRecord>,
    pub credits: BTreeMap<String, PrivacyCreditRecord>,
    pub rebates: BTreeMap<String, LowFeeRebateRecord>,
    pub abuse_reports: BTreeMap<String, AbuseReportRecord>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub settlements: BTreeMap<String, CallSettlementRecord>,
    pub privacy_fences: BTreeMap<String, PrivacyFenceRecord>,
    pub accounting: Accounting,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default(), DEVNET_HEIGHT, DEVNET_EPOCH)
    }
}

impl State {
    pub fn new(config: Config, current_height: u64, current_epoch: u64) -> Self {
        let mut state = Self {
            config,
            current_height,
            current_epoch,
            counters: Counters::default(),
            roots: Roots::default(),
            namespaces: BTreeMap::new(),
            budgets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            credits: BTreeMap::new(),
            rebates: BTreeMap::new(),
            abuse_reports: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            settlements: BTreeMap::new(),
            privacy_fences: BTreeMap::new(),
            accounting: Accounting::default(),
        };
        state.refresh_roots();
        state
    }

    pub fn register_namespace(
        &mut self,
        request: RegisterNamespaceRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(
            self.namespaces.len(),
            self.config.max_namespaces,
            "namespace",
        )?;
        required("owner_commitment", &request.owner_commitment)?;
        required(
            "contract_namespace_commitment",
            &request.contract_namespace_commitment,
        )?;
        required("policy_root", &request.policy_root)?;
        required("allowed_call_root", &request.allowed_call_root)?;
        required("credit_asset_id", &request.credit_asset_id)?;
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set,
            "privacy set below configured minimum"
        );
        ensure!(
            request.low_fee_rebate_bps <= MAX_BPS && request.surge_price_bps <= MAX_BPS,
            "basis points out of range"
        );
        ensure!(
            request.base_credit_price >= self.config.min_credit_price
                && request.base_credit_price <= self.config.max_credit_price,
            "base credit price out of range"
        );

        let sequence = self.counters.next_namespace;
        let namespace_id = namespace_id(&request, sequence);
        ensure!(
            !self.namespaces.contains_key(&namespace_id),
            "namespace id collision"
        );
        let record = NamespaceCommitmentRecord {
            namespace_id: namespace_id.clone(),
            kind: request.kind,
            status: NamespaceStatus::Active,
            owner_commitment: request.owner_commitment,
            contract_namespace_commitment: request.contract_namespace_commitment,
            policy_root: request.policy_root,
            allowed_call_root: request.allowed_call_root,
            credit_asset_id: request.credit_asset_id,
            base_credit_price: request.base_credit_price,
            surge_price_bps: request.surge_price_bps,
            low_fee_threshold: request.low_fee_threshold,
            low_fee_rebate_bps: request.low_fee_rebate_bps,
            privacy_set_size: request.privacy_set_size,
            pending_budget_count: 0,
            spent_credit_count: 0,
            quarantine_count: 0,
            opened_at_height: self.current_height,
            last_updated_height: self.current_height,
            metadata_root: request.metadata_root,
        };
        self.namespaces.insert(namespace_id.clone(), record);
        self.counters.next_namespace += 1;
        self.counters.namespaces_registered += 1;
        self.refresh_roots();
        Ok(namespace_id)
    }

    pub fn submit_sealed_budget(
        &mut self,
        request: SubmitSealedBudgetRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(self.budgets.len(), self.config.max_budgets, "budget")?;
        self.ensure_capacity(
            self.privacy_fences.len(),
            self.config.max_privacy_fences,
            "privacy fence",
        )?;
        required("caller_commitment", &request.caller_commitment)?;
        required(
            "sealed_budget_commitment",
            &request.sealed_budget_commitment,
        )?;
        required("call_bundle_root", &request.call_bundle_root)?;
        required("call_nullifier", &request.call_nullifier)?;
        required("anonymity_set_root", &request.anonymity_set_root)?;
        required("view_tag_root", &request.view_tag_root)?;
        ensure!(
            request.max_call_units > 0,
            "max call units must be non-zero"
        );
        ensure!(
            request.min_privacy_set >= self.config.min_privacy_set,
            "budget privacy set below configured minimum"
        );
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "budget pq security below configured minimum"
        );
        ensure!(
            request.max_credit_price >= self.config.min_credit_price,
            "budget max credit price below minimum"
        );
        let namespace = self
            .namespaces
            .get_mut(&request.namespace_id)
            .ok_or_else(|| "unknown namespace".to_string())?;
        ensure!(
            namespace.status.can_accept_budget(),
            "namespace cannot accept budgets"
        );
        ensure!(
            namespace.privacy_set_size >= request.min_privacy_set,
            "namespace privacy set below budget requirement"
        );

        let sequence = self.counters.next_budget;
        let budget_id = sealed_budget_id(&request, sequence);
        let fence_id = privacy_fence_id(&request, self.counters.next_privacy_fence);
        ensure!(
            !self.budgets.contains_key(&budget_id),
            "budget id collision"
        );
        ensure!(
            !self
                .privacy_fences
                .values()
                .any(|fence| fence.call_nullifier == request.call_nullifier),
            "call nullifier already registered"
        );
        let expires_at_height = self
            .current_height
            .saturating_add(self.config.budget_ttl_blocks);
        let record = SealedCallBudgetRecord {
            budget_id: budget_id.clone(),
            namespace_id: request.namespace_id.clone(),
            budget_class: request.budget_class,
            status: BudgetStatus::Sealed,
            caller_commitment: request.caller_commitment,
            sealed_budget_commitment: request.sealed_budget_commitment,
            call_bundle_root: request.call_bundle_root,
            call_nullifier: request.call_nullifier.clone(),
            max_call_units: request.max_call_units,
            remaining_call_units: request.max_call_units,
            reserved_credits: 0,
            spent_credits: 0,
            max_credit_price: request.max_credit_price,
            min_privacy_set: request.min_privacy_set,
            pq_security_bits: request.pq_security_bits,
            submitted_at_height: self.current_height,
            expires_at_height,
            attestation_ids: BTreeSet::new(),
            credit_ids: BTreeSet::new(),
            settlement_ids: BTreeSet::new(),
            rebate_ids: BTreeSet::new(),
        };
        let fence = PrivacyFenceRecord {
            fence_id: fence_id.clone(),
            namespace_id: request.namespace_id.clone(),
            budget_id: budget_id.clone(),
            call_nullifier: request.call_nullifier,
            anonymity_set_root: request.anonymity_set_root,
            view_tag_root: request.view_tag_root,
            status: BudgetStatus::Sealed,
            registered_at_height: self.current_height,
            expires_at_height,
        };
        namespace.pending_budget_count += 1;
        namespace.last_updated_height = self.current_height;
        self.budgets.insert(budget_id.clone(), record);
        self.privacy_fences.insert(fence_id, fence);
        self.counters.next_budget += 1;
        self.counters.next_privacy_fence += 1;
        self.counters.sealed_budgets_submitted += 1;
        self.counters.fences_registered += 1;
        self.accounting.total_call_units_reserved = self
            .accounting
            .total_call_units_reserved
            .saturating_add(request.max_call_units);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn attest_budget(
        &mut self,
        request: AttestBudgetRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(
            self.attestations.len(),
            self.config.max_attestations,
            "attestation",
        )?;
        required("attestor_commitment", &request.attestor_commitment)?;
        required("attestation_root", &request.attestation_root)?;
        required("signature_root", &request.signature_root)?;
        required("signer_set_root", &request.signer_set_root)?;
        ensure!(
            request.pq_security_bits >= self.config.min_pq_security_bits,
            "attestation pq security below configured minimum"
        );
        ensure!(
            request.privacy_set_size >= self.config.min_privacy_set,
            "attestation privacy set below configured minimum"
        );
        let budget = self
            .budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| "unknown budget".to_string())?;
        ensure!(
            self.current_height <= budget.expires_at_height,
            "budget expired"
        );
        ensure!(
            request.pq_security_bits >= budget.pq_security_bits,
            "attestation pq security below budget requirement"
        );
        ensure!(
            request.privacy_set_size >= budget.min_privacy_set,
            "attestation privacy set below budget requirement"
        );
        let sequence = self.counters.next_attestation;
        let attestation_id = budget_attestation_id(&request, sequence);
        let record = PqBudgetAttestationRecord {
            attestation_id: attestation_id.clone(),
            budget_id: request.budget_id.clone(),
            namespace_id: budget.namespace_id.clone(),
            kind: request.kind,
            status: AttestationStatus::Accepted,
            attestor_commitment: request.attestor_commitment,
            attestation_root: request.attestation_root,
            signature_root: request.signature_root,
            signer_set_root: request.signer_set_root,
            pq_security_bits: request.pq_security_bits,
            privacy_set_size: request.privacy_set_size,
            accepted_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.attestation_ttl_blocks),
        };
        budget.attestation_ids.insert(attestation_id.clone());
        if matches!(budget.status, BudgetStatus::Sealed) {
            budget.status = BudgetStatus::Attested;
        }
        self.attestations.insert(attestation_id.clone(), record);
        self.counters.next_attestation += 1;
        self.counters.budget_attestations_accepted += 1;
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn mint_privacy_credit(
        &mut self,
        request: MintPrivacyCreditRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(self.credits.len(), self.config.max_credits, "credit")?;
        required("credit_owner_commitment", &request.credit_owner_commitment)?;
        required("price_attestation_root", &request.price_attestation_root)?;
        ensure!(request.units > 0, "credit units must be non-zero");
        ensure!(
            request.unit_price >= self.config.min_credit_price
                && request.unit_price <= self.config.max_credit_price,
            "credit price out of configured range"
        );
        let budget = self
            .budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| "unknown budget".to_string())?;
        ensure!(
            budget.status.spendable() || matches!(budget.status, BudgetStatus::Sealed),
            "budget is not creditable"
        );
        ensure!(
            request.unit_price <= budget.max_credit_price,
            "credit price above sealed budget maximum"
        );
        ensure!(
            request.units <= budget.remaining_call_units,
            "credit units exceed remaining call budget"
        );
        ensure!(
            !budget.attestation_ids.is_empty(),
            "budget requires at least one accepted pq attestation"
        );
        let namespace = self
            .namespaces
            .get(&budget.namespace_id)
            .ok_or_else(|| "unknown namespace".to_string())?;
        let sequence = self.counters.next_credit;
        let credit_id = privacy_credit_id(&request, sequence);
        let gross_fee = request.unit_price.saturating_mul(request.units as u128);
        let reserve_fee = bps_amount(gross_fee, self.config.quarantine_reserve_bps);
        let record = PrivacyCreditRecord {
            credit_id: credit_id.clone(),
            namespace_id: budget.namespace_id.clone(),
            budget_id: request.budget_id.clone(),
            status: CreditStatus::BoundToBudget,
            credit_owner_commitment: request.credit_owner_commitment,
            credit_asset_id: namespace.credit_asset_id.clone(),
            units: request.units,
            unit_price: request.unit_price,
            gross_fee,
            reserve_fee,
            rebate_bps: namespace.low_fee_rebate_bps,
            price_attestation_root: request.price_attestation_root,
            minted_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.credit_ttl_blocks),
        };
        budget.status = BudgetStatus::Funded;
        budget.reserved_credits = budget.reserved_credits.saturating_add(gross_fee);
        budget.credit_ids.insert(credit_id.clone());
        self.accounting.total_reserved_credits = self
            .accounting
            .total_reserved_credits
            .saturating_add(gross_fee);
        self.credits.insert(credit_id.clone(), record);
        self.counters.next_credit += 1;
        self.counters.credits_minted += 1;
        self.refresh_roots();
        Ok(credit_id)
    }

    pub fn settle_call(
        &mut self,
        request: SettleCallRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(
            self.settlements.len(),
            self.config.max_settlements,
            "settlement",
        )?;
        required("call_receipt_root", &request.call_receipt_root)?;
        required("post_budget_root", &request.post_budget_root)?;
        ensure!(request.spent_units > 0, "spent units must be non-zero");
        let namespace_id_for_threshold = self
            .budgets
            .get(&request.budget_id)
            .ok_or_else(|| "unknown budget".to_string())?
            .namespace_id
            .clone();
        let low_fee_threshold = self.namespace_low_fee_threshold(&namespace_id_for_threshold)?;
        let budget = self
            .budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| "unknown budget".to_string())?;
        ensure!(budget.status.spendable(), "budget is not spendable");
        ensure!(
            budget.credit_ids.contains(&request.credit_id),
            "credit is not bound to budget"
        );
        ensure!(
            request.spent_units <= budget.remaining_call_units,
            "spent units exceed remaining call budget"
        );
        let credit = self
            .credits
            .get_mut(&request.credit_id)
            .ok_or_else(|| "unknown credit".to_string())?;
        ensure!(
            matches!(
                credit.status,
                CreditStatus::BoundToBudget | CreditStatus::Reserved | CreditStatus::Minted
            ),
            "credit is not spendable"
        );
        ensure!(
            request.spent_units <= credit.units,
            "spent units exceed credit units"
        );
        let sequence = self.counters.next_settlement;
        let settlement_id = call_settlement_id(&request, sequence);
        let charged_fee = credit
            .unit_price
            .saturating_mul(request.spent_units as u128);
        let rebate_amount = if credit.unit_price <= low_fee_threshold {
            bps_amount(charged_fee, credit.rebate_bps)
        } else {
            0
        };
        let record = CallSettlementRecord {
            settlement_id: settlement_id.clone(),
            namespace_id: budget.namespace_id.clone(),
            budget_id: request.budget_id.clone(),
            credit_id: request.credit_id.clone(),
            status: SettlementStatus::Finalized,
            call_receipt_root: request.call_receipt_root,
            spent_units: request.spent_units,
            charged_fee,
            rebate_amount,
            post_budget_root: request.post_budget_root,
            settled_at_height: self.current_height,
        };
        budget.remaining_call_units -= request.spent_units;
        budget.spent_credits = budget.spent_credits.saturating_add(charged_fee);
        budget.settlement_ids.insert(settlement_id.clone());
        budget.status = if budget.remaining_call_units == 0 {
            BudgetStatus::Exhausted
        } else {
            BudgetStatus::PartiallySpent
        };
        credit.status = if rebate_amount > 0 {
            CreditStatus::RebateQueued
        } else {
            CreditStatus::Spent
        };
        self.accounting.total_spent_credits = self
            .accounting
            .total_spent_credits
            .saturating_add(charged_fee);
        self.accounting.total_call_units_spent = self
            .accounting
            .total_call_units_spent
            .saturating_add(request.spent_units);
        if let Some(namespace) = self.namespaces.get_mut(&budget.namespace_id) {
            namespace.spent_credit_count = namespace.spent_credit_count.saturating_add(1);
            namespace.last_updated_height = self.current_height;
        }
        self.settlements.insert(settlement_id.clone(), record);
        self.counters.next_settlement += 1;
        self.counters.credits_spent += 1;
        self.counters.settlements_finalized += 1;
        if rebate_amount > 0 {
            self.queue_low_fee_rebate(&request.budget_id, &request.credit_id, rebate_amount)?;
        } else {
            self.refresh_roots();
        }
        Ok(settlement_id)
    }

    pub fn report_abuse(
        &mut self,
        request: ReportAbuseRequest,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(
            self.abuse_reports.len(),
            self.config.max_abuse_reports,
            "abuse report",
        )?;
        self.ensure_capacity(
            self.quarantines.len(),
            self.config.max_quarantines,
            "quarantine",
        )?;
        required("reporter_commitment", &request.reporter_commitment)?;
        required("subject_commitment", &request.subject_commitment)?;
        required("evidence_root", &request.evidence_root)?;
        ensure!(
            self.namespaces.contains_key(&request.namespace_id),
            "unknown namespace"
        );
        let budget = self
            .budgets
            .get_mut(&request.budget_id)
            .ok_or_else(|| "unknown budget".to_string())?;
        ensure!(
            budget.namespace_id == request.namespace_id,
            "budget namespace mismatch"
        );
        let sequence = self.counters.next_abuse_report;
        let report_id = abuse_report_id(&request, sequence);
        let slash_amount = bps_amount(budget.reserved_credits, self.config.abuse_slash_bps);
        let report = AbuseReportRecord {
            report_id: report_id.clone(),
            namespace_id: request.namespace_id.clone(),
            budget_id: request.budget_id.clone(),
            kind: request.kind,
            status: AbuseStatus::Accepted,
            reporter_commitment: request.reporter_commitment,
            subject_commitment: request.subject_commitment.clone(),
            evidence_root: request.evidence_root,
            slash_amount,
            reported_at_height: self.current_height,
            review_deadline_height: self
                .current_height
                .saturating_add(self.config.abuse_window_blocks),
        };
        let quarantine_id = quarantine_id(&request, self.counters.next_quarantine);
        let quarantine = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            namespace_id: request.namespace_id.clone(),
            budget_id: request.budget_id.clone(),
            report_id: report_id.clone(),
            scope: request.requested_scope,
            status: QuarantineStatus::Active,
            subject_commitment: request.subject_commitment,
            quarantine_root: deterministic_record_root(
                "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:QUARANTINE-COMMITMENT",
                &json!({"report_id": report_id, "budget_id": request.budget_id}),
            ),
            reserved_amount: slash_amount,
            opened_at_height: self.current_height,
            releases_at_height: self
                .current_height
                .saturating_add(self.config.quarantine_ttl_blocks),
        };
        budget.status = BudgetStatus::Quarantined;
        self.abuse_reports.insert(report_id.clone(), report);
        self.quarantines.insert(quarantine_id, quarantine);
        if let Some(namespace) = self.namespaces.get_mut(&request.namespace_id) {
            namespace.quarantine_count = namespace.quarantine_count.saturating_add(1);
            namespace.status = NamespaceStatus::Throttled;
            namespace.last_updated_height = self.current_height;
        }
        self.accounting.total_quarantine_reserved = self
            .accounting
            .total_quarantine_reserved
            .saturating_add(slash_amount);
        self.accounting.total_slashed_amount = self
            .accounting
            .total_slashed_amount
            .saturating_add(slash_amount);
        self.counters.next_abuse_report += 1;
        self.counters.next_quarantine += 1;
        self.counters.abuse_reports_accepted += 1;
        self.counters.quarantines_opened += 1;
        self.refresh_roots();
        Ok(report_id)
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "current_height": self.current_height,
            "current_epoch": self.current_epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": {
                "config_root": self.roots.config_root,
                "namespace_root": self.roots.namespace_root,
                "budget_root": self.roots.budget_root,
                "attestation_root": self.roots.attestation_root,
                "credit_root": self.roots.credit_root,
                "rebate_root": self.roots.rebate_root,
                "abuse_report_root": self.roots.abuse_report_root,
                "quarantine_root": self.roots.quarantine_root,
                "settlement_root": self.roots.settlement_root,
                "privacy_fence_root": self.roots.privacy_fence_root,
                "accounting_root": self.roots.accounting_root,
                "counters_root": self.roots.counters_root
            },
            "accounting": self.accounting.public_record(),
            "namespaces": values_record(&self.namespaces),
            "budgets": values_record(&self.budgets),
            "attestations": values_record(&self.attestations),
            "credits": values_record(&self.credits),
            "rebates": values_record(&self.rebates),
            "abuse_reports": values_record(&self.abuse_reports),
            "quarantines": values_record(&self.quarantines),
            "settlements": values_record(&self.settlements),
            "privacy_fences": values_record(&self.privacy_fences)
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["roots"]["state_root"] = Value::String(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.roots.config_root = deterministic_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:CONFIG-ROOT",
            &self.config.public_record(),
        );
        self.roots.namespace_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:NAMESPACE-ROOT",
            &values_record(&self.namespaces),
        );
        self.roots.budget_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:BUDGET-ROOT",
            &values_record(&self.budgets),
        );
        self.roots.attestation_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:ATTESTATION-ROOT",
            &values_record(&self.attestations),
        );
        self.roots.credit_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:CREDIT-ROOT",
            &values_record(&self.credits),
        );
        self.roots.rebate_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:REBATE-ROOT",
            &values_record(&self.rebates),
        );
        self.roots.abuse_report_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:ABUSE-REPORT-ROOT",
            &values_record(&self.abuse_reports),
        );
        self.roots.quarantine_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:QUARANTINE-ROOT",
            &values_record(&self.quarantines),
        );
        self.roots.settlement_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:SETTLEMENT-ROOT",
            &values_record(&self.settlements),
        );
        self.roots.privacy_fence_root = public_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:PRIVACY-FENCE-ROOT",
            &values_record(&self.privacy_fences),
        );
        self.roots.accounting_root = deterministic_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:ACCOUNTING-ROOT",
            &self.accounting.public_record(),
        );
        self.roots.counters_root = deterministic_record_root(
            "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:COUNTERS-ROOT",
            &self.counters.public_record(),
        );
        self.roots.state_root = self.state_root();
    }

    pub fn namespace_low_fee_threshold(
        &self,
        namespace_id: &str,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<u128> {
        Ok(self
            .namespaces
            .get(namespace_id)
            .ok_or_else(|| "unknown namespace".to_string())?
            .low_fee_threshold)
    }

    pub fn quote_privacy_credits(
        &self,
        namespace_id: &str,
        units: u64,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<Value> {
        ensure!(units > 0, "units must be non-zero");
        let namespace = self
            .namespaces
            .get(namespace_id)
            .ok_or_else(|| "unknown namespace".to_string())?;
        let unit_price = namespace.base_credit_price.saturating_add(bps_amount(
            namespace.base_credit_price,
            namespace.surge_price_bps,
        ));
        let gross_fee = unit_price.saturating_mul(units as u128);
        let reserve_fee = bps_amount(gross_fee, self.config.quarantine_reserve_bps);
        let rebate_amount = if unit_price <= namespace.low_fee_threshold {
            bps_amount(gross_fee, namespace.low_fee_rebate_bps)
        } else {
            0
        };
        Ok(json!({
            "namespace_id": namespace_id,
            "credit_asset_id": namespace.credit_asset_id,
            "units": units,
            "unit_price": unit_price.to_string(),
            "gross_fee": gross_fee.to_string(),
            "reserve_fee": reserve_fee.to_string(),
            "low_fee_rebate_bps": namespace.low_fee_rebate_bps,
            "expected_rebate": rebate_amount.to_string(),
            "net_fee_after_rebate": gross_fee.saturating_sub(rebate_amount).to_string()
        }))
    }

    pub fn active_budget_ids(&self, namespace_id: &str) -> Vec<String> {
        self.budgets
            .iter()
            .filter(|(_, budget)| {
                budget.namespace_id == namespace_id
                    && budget.status.spendable()
                    && self.current_height <= budget.expires_at_height
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn claimable_rebate_ids(&self, recipient_commitment: &str) -> Vec<String> {
        self.rebates
            .iter()
            .filter(|(_, rebate)| {
                rebate.recipient_commitment == recipient_commitment
                    && matches!(rebate.status, RebateStatus::Claimable)
                    && self.current_height <= rebate.expires_at_height
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn queue_low_fee_rebate(
        &mut self,
        budget_id: &str,
        credit_id: &str,
        rebate_amount: u128,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<String> {
        self.ensure_capacity(self.rebates.len(), self.config.max_rebates, "rebate")?;
        let budget = self
            .budgets
            .get_mut(budget_id)
            .ok_or_else(|| "unknown budget".to_string())?;
        let credit = self
            .credits
            .get(credit_id)
            .ok_or_else(|| "unknown credit".to_string())?;
        let sequence = self.counters.next_rebate;
        let rebate_id = deterministic_id(
            "REBATE-ID",
            sequence,
            &json!({"budget_id": budget_id, "credit_id": credit_id, "rebate_amount": rebate_amount.to_string()}),
        );
        let record = LowFeeRebateRecord {
            rebate_id: rebate_id.clone(),
            namespace_id: budget.namespace_id.clone(),
            budget_id: budget_id.to_string(),
            credit_id: credit_id.to_string(),
            status: RebateStatus::Claimable,
            recipient_commitment: budget.caller_commitment.clone(),
            rebate_amount,
            rebate_bps: credit.rebate_bps,
            eligibility_root: deterministic_record_root(
                "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:REBATE-ELIGIBILITY",
                &json!({"budget_id": budget_id, "credit_id": credit_id, "height": self.current_height}),
            ),
            queued_at_height: self.current_height,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.rebate_ttl_blocks),
        };
        budget.status = BudgetStatus::RebateQueued;
        budget.rebate_ids.insert(rebate_id.clone());
        self.rebates.insert(rebate_id.clone(), record);
        self.accounting.total_rebate_amount = self
            .accounting
            .total_rebate_amount
            .saturating_add(rebate_amount);
        self.counters.next_rebate += 1;
        self.counters.rebates_queued += 1;
        self.refresh_roots();
        Ok(rebate_id)
    }

    fn ensure_capacity(
        &self,
        current_len: usize,
        max_len: usize,
        name: &str,
    ) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<()> {
        if current_len >= max_len {
            return Err(format!("{name} capacity exhausted"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let namespace_id = state
        .register_namespace(RegisterNamespaceRequest {
            kind: NamespaceKind::DefiRouter,
            owner_commitment: "owner:devnet:confidential-router".to_string(),
            contract_namespace_commitment: "namespace:commitment:defi-router:v1".to_string(),
            policy_root: "policy:root:defi-router:low-fee".to_string(),
            allowed_call_root: "allowed-calls:root:defi-router:swap-lend-bridge".to_string(),
            credit_asset_id: "privacy-credit-devnet".to_string(),
            base_credit_price: DEFAULT_BASE_CREDIT_PRICE,
            surge_price_bps: 350,
            low_fee_threshold: DEFAULT_BASE_CREDIT_PRICE.saturating_add(2_500),
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
            metadata_root: "metadata:root:devnet-call-budget-market".to_string(),
        })
        .expect("devnet namespace registration must succeed");
    let budget_id = state
        .submit_sealed_budget(SubmitSealedBudgetRequest {
            namespace_id,
            budget_class: BudgetClass::CrossContractCall,
            caller_commitment: "caller:commitment:devnet-wallet-01".to_string(),
            sealed_budget_commitment: "sealed-budget:commitment:devnet-001".to_string(),
            call_bundle_root: "call-bundle:root:swap-lend-route".to_string(),
            call_nullifier: "call-nullifier:devnet-001".to_string(),
            max_call_units: 64,
            max_credit_price: DEFAULT_BASE_CREDIT_PRICE.saturating_add(10_000),
            min_privacy_set: DEFAULT_MIN_PRIVACY_SET,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            anonymity_set_root: "anonymity-set:root:devnet-001".to_string(),
            view_tag_root: "view-tag:root:devnet-001".to_string(),
        })
        .expect("devnet budget submission must succeed");
    state
        .attest_budget(AttestBudgetRequest {
            budget_id,
            kind: AttestationKind::BudgetOpening,
            attestor_commitment: "attestor:commitment:ml-dsa-committee-a".to_string(),
            attestation_root: "attestation:root:budget-opening-devnet-001".to_string(),
            signature_root: "signature:root:ml-dsa-slh-dsa-devnet-001".to_string(),
            signer_set_root: "signer-set:root:pq-budget-committee-devnet".to_string(),
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET,
        })
        .expect("devnet budget attestation must succeed");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let budget_id = state
        .budgets
        .keys()
        .next()
        .expect("demo budget exists")
        .clone();
    let credit_id = state
        .mint_privacy_credit(MintPrivacyCreditRequest {
            budget_id: budget_id.clone(),
            credit_owner_commitment: "credit-owner:commitment:demo-wallet-01".to_string(),
            units: 16,
            unit_price: DEFAULT_BASE_CREDIT_PRICE,
            price_attestation_root: "price-attestation:root:demo-low-fee".to_string(),
        })
        .expect("demo credit mint must succeed");
    state
        .settle_call(SettleCallRequest {
            budget_id,
            credit_id,
            call_receipt_root: "call-receipt:root:demo-cross-contract-call".to_string(),
            spent_units: 8,
            post_budget_root: "post-budget:root:demo-remaining-56".to_string(),
        })
        .expect("demo call settlement must succeed");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn namespace_id(request: &RegisterNamespaceRequest, sequence: u64) -> String {
    deterministic_id("NAMESPACE-ID", sequence, &request.public_record())
}

pub fn sealed_budget_id(request: &SubmitSealedBudgetRequest, sequence: u64) -> String {
    deterministic_id("BUDGET-ID", sequence, &request.public_record())
}

pub fn budget_attestation_id(request: &AttestBudgetRequest, sequence: u64) -> String {
    deterministic_id("ATTESTATION-ID", sequence, &request.public_record())
}

pub fn privacy_credit_id(request: &MintPrivacyCreditRequest, sequence: u64) -> String {
    deterministic_id("CREDIT-ID", sequence, &request.public_record())
}

pub fn call_settlement_id(request: &SettleCallRequest, sequence: u64) -> String {
    deterministic_id("SETTLEMENT-ID", sequence, &request.public_record())
}

pub fn abuse_report_id(request: &ReportAbuseRequest, sequence: u64) -> String {
    deterministic_id("ABUSE-REPORT-ID", sequence, &request.public_record())
}

pub fn quarantine_id(request: &ReportAbuseRequest, sequence: u64) -> String {
    deterministic_id("QUARANTINE-ID", sequence, &request.public_record())
}

pub fn privacy_fence_id(request: &SubmitSealedBudgetRequest, sequence: u64) -> String {
    deterministic_id(
        "PRIVACY-FENCE-ID",
        sequence,
        &json!({
            "namespace_id": request.namespace_id,
            "call_nullifier": request.call_nullifier,
            "anonymity_set_root": request.anonymity_set_root,
            "view_tag_root": request.view_tag_root
        }),
    )
}

pub fn deterministic_id(kind: &str, sequence: u64, record: &Value) -> String {
    domain_hash(
        &format!("PRIVATE-L2-PQ-CALL-BUDGET-MARKET:{kind}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn public_record_root(domain: &str, records: &[Value]) -> String {
    merkle_root(domain, records)
}

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:STATE-ROOT",
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn deterministic_record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        domain,
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Json(record)],
        32,
    )
}

pub fn namespace_record_root(record: &NamespaceCommitmentRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:NAMESPACE-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn budget_record_root(record: &SealedCallBudgetRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:BUDGET-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn attestation_record_root(record: &PqBudgetAttestationRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:ATTESTATION-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn credit_record_root(record: &PrivacyCreditRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:CREDIT-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn rebate_record_root(record: &LowFeeRebateRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:REBATE-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn abuse_report_record_root(record: &AbuseReportRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:ABUSE-REPORT-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn quarantine_record_root(record: &QuarantineRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:QUARANTINE-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn settlement_record_root(record: &CallSettlementRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:SETTLEMENT-RECORD-ROOT",
        &record.public_record(),
    )
}

pub fn privacy_fence_record_root(record: &PrivacyFenceRecord) -> String {
    deterministic_record_root(
        "PRIVATE-L2-PQ-CALL-BUDGET-MARKET:PRIVACY-FENCE-RECORD-ROOT",
        &record.public_record(),
    )
}

fn values_record<T>(records: &BTreeMap<String, T>) -> Vec<Value>
where
    T: PublicRecord,
{
    records
        .values()
        .map(PublicRecord::public_record_value)
        .collect()
}

trait PublicRecord {
    fn public_record_value(&self) -> Value;
}

impl PublicRecord for NamespaceCommitmentRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for SealedCallBudgetRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PqBudgetAttestationRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyCreditRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for LowFeeRebateRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for AbuseReportRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for QuarantineRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for CallSettlementRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

impl PublicRecord for PrivacyFenceRecord {
    fn public_record_value(&self) -> Value {
        self.public_record()
    }
}

fn sorted_strings(values: &BTreeSet<String>) -> Vec<String> {
    values.iter().cloned().collect()
}

fn required(
    name: &str,
    value: &str,
) -> PrivateL2PqConfidentialContractCallPrivacyBudgetMarketRuntimeResult<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} is required"));
    }
    Ok(())
}

fn bps_amount(amount: u128, bps: u64) -> u128 {
    amount.saturating_mul(bps as u128) / MAX_BPS as u128
}

fn empty_root(domain: &str) -> String {
    merkle_root(
        &format!("PRIVATE-L2-PQ-CALL-BUDGET-MARKET:{domain}-EMPTY"),
        &[],
    )
}
