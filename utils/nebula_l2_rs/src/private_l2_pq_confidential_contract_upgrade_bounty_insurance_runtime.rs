use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type PrivateL2PqConfidentialContractUpgradeBountyInsuranceRuntimeResult<T> =
    std::result::Result<T, String>;
pub type Result<T> = PrivateL2PqConfidentialContractUpgradeBountyInsuranceRuntimeResult<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_UPGRADE_BOUNTY_INSURANCE_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-private-l2-pq-confidential-contract-upgrade-bounty-insurance-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_CONTRACT_UPGRADE_BOUNTY_INSURANCE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_HEIGHT: u64 = 1_382_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUDIT_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-upgrade-bounty-insurance-v1";
pub const CONFIDENTIALITY_SUITE: &str =
    "Monero-viewtag-nullifier-fence+Poseidon2-redaction-budget-v1";
pub const POLICY_SCHEME: &str = "sealed-contract-upgrade-bounty-policy-root-v1";
pub const RISK_CLASS_SCHEME: &str = "confidential-contract-upgrade-risk-class-root-v1";
pub const AUDITOR_ATTESTATION_SCHEME: &str = "pq-auditor-upgrade-attestation-root-v1";
pub const INSURED_RECEIPT_SCHEME: &str = "insured-contract-upgrade-receipt-root-v1";
pub const PREMIUM_CREDIT_SCHEME: &str = "low-fee-upgrade-premium-credit-root-v1";
pub const CLAIM_QUARANTINE_SCHEME: &str = "claim-quarantine-and-evidence-lock-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "upgrade-bounty-redaction-budget-root-v1";
pub const PUBLIC_RECORD_SCHEME: &str = "upgrade-bounty-insurance-public-record-root-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_BATCH_PRIVACY_SET_SIZE: u64 = 1_048_576;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MAX_PREMIUM_BPS: u64 = 220;
pub const DEFAULT_MIN_RESERVE_RATIO_BPS: u64 = 18_000;
pub const DEFAULT_LOW_FEE_CREDIT_BPS: u64 = 11;
pub const DEFAULT_AUDITOR_QUORUM: u16 = 5;
pub const DEFAULT_AUDITOR_SET_SIZE: u16 = 9;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 5_760;
pub const DEFAULT_POLICY_TTL_BLOCKS: u64 = 43_200;
pub const DEFAULT_RECEIPT_FINALITY_BLOCKS: u64 = 24;
pub const DEFAULT_REDACTION_BUDGET_FIELDS: u16 = 8;
pub const DEFAULT_MAX_POLICIES: usize = 1_048_576;
pub const DEFAULT_MAX_RISK_CLASSES: usize = 4_096;
pub const DEFAULT_MAX_AUDITOR_ATTESTATIONS: usize = 8_388_608;
pub const DEFAULT_MAX_RECEIPTS: usize = 8_388_608;
pub const DEFAULT_MAX_PREMIUM_CREDITS: usize = 8_388_608;
pub const DEFAULT_MAX_QUARANTINES: usize = 2_097_152;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 2_097_152;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeRiskKind {
    ParameterOnly,
    StorageLayout,
    VerifierKeyRotation,
    PrecompileBinding,
    GovernanceAdmin,
    CrossContractCallGraph,
    BridgeAdapter,
    EmergencyPatch,
}

impl UpgradeRiskKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ParameterOnly => "parameter_only",
            Self::StorageLayout => "storage_layout",
            Self::VerifierKeyRotation => "verifier_key_rotation",
            Self::PrecompileBinding => "precompile_binding",
            Self::GovernanceAdmin => "governance_admin",
            Self::CrossContractCallGraph => "cross_contract_call_graph",
            Self::BridgeAdapter => "bridge_adapter",
            Self::EmergencyPatch => "emergency_patch",
        }
    }

    pub fn risk_weight(self) -> u64 {
        match self {
            Self::EmergencyPatch => 1_000,
            Self::BridgeAdapter => 940,
            Self::CrossContractCallGraph => 900,
            Self::PrecompileBinding => 840,
            Self::VerifierKeyRotation => 790,
            Self::StorageLayout => 740,
            Self::GovernanceAdmin => 690,
            Self::ParameterOnly => 420,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Draft,
    Sealed,
    Bound,
    ClaimOnly,
    Expired,
    Cancelled,
    Quarantined,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Sealed => "sealed",
            Self::Bound => "bound",
            Self::ClaimOnly => "claim_only",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn accepts_receipts(self) -> bool {
        matches!(self, Self::Sealed | Self::Bound)
    }

    pub fn accepts_claims(self) -> bool {
        matches!(self, Self::Bound | Self::ClaimOnly | Self::Quarantined)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditorVerdict {
    Pending,
    Passed,
    Conditional,
    Failed,
    Quarantined,
}

impl AuditorVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Passed => "passed",
            Self::Conditional => "conditional",
            Self::Failed => "failed",
            Self::Quarantined => "quarantined",
        }
    }

    pub fn approves(self) -> bool {
        matches!(self, Self::Passed | Self::Conditional)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptStatus {
    Submitted,
    Insured,
    Finalized,
    Challenged,
    Reversed,
    Quarantined,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::Insured => "insured",
            Self::Finalized => "finalized",
            Self::Challenged => "challenged",
            Self::Reversed => "reversed",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Submitted,
    EvidenceLocked,
    Quarantined,
    Approved,
    Rejected,
    Settled,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "submitted",
            Self::EvidenceLocked => "evidence_locked",
            Self::Quarantined => "quarantined",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Settled => "settled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CreditStatus {
    Pending,
    Available,
    Applied,
    Expired,
    Revoked,
}

impl CreditStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Available => "available",
            Self::Applied => "applied",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub l2_network: String,
    pub monero_network: String,
    pub activation_height: u64,
    pub min_privacy_set_size: u64,
    pub batch_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub max_premium_bps: u64,
    pub min_reserve_ratio_bps: u64,
    pub low_fee_credit_bps: u64,
    pub auditor_quorum: u16,
    pub auditor_set_size: u16,
    pub quarantine_blocks: u64,
    pub policy_ttl_blocks: u64,
    pub receipt_finality_blocks: u64,
    pub redaction_budget_fields: u16,
    pub max_policies: usize,
    pub max_risk_classes: usize,
    pub max_auditor_attestations: usize,
    pub max_receipts: usize,
    pub max_premium_credits: usize,
    pub max_quarantines: usize,
    pub max_redaction_budgets: usize,
    pub allowed_risk_kinds: BTreeSet<UpgradeRiskKind>,
    pub require_sealed_policies: bool,
    pub require_pq_auditors: bool,
    pub require_low_fee_credits: bool,
    pub require_operator_safe_public_records: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            l2_network: "nebula-private-l2-devnet".to_string(),
            monero_network: "monero-devnet".to_string(),
            activation_height: DEVNET_HEIGHT,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            batch_privacy_set_size: DEFAULT_BATCH_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            max_premium_bps: DEFAULT_MAX_PREMIUM_BPS,
            min_reserve_ratio_bps: DEFAULT_MIN_RESERVE_RATIO_BPS,
            low_fee_credit_bps: DEFAULT_LOW_FEE_CREDIT_BPS,
            auditor_quorum: DEFAULT_AUDITOR_QUORUM,
            auditor_set_size: DEFAULT_AUDITOR_SET_SIZE,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            policy_ttl_blocks: DEFAULT_POLICY_TTL_BLOCKS,
            receipt_finality_blocks: DEFAULT_RECEIPT_FINALITY_BLOCKS,
            redaction_budget_fields: DEFAULT_REDACTION_BUDGET_FIELDS,
            max_policies: DEFAULT_MAX_POLICIES,
            max_risk_classes: DEFAULT_MAX_RISK_CLASSES,
            max_auditor_attestations: DEFAULT_MAX_AUDITOR_ATTESTATIONS,
            max_receipts: DEFAULT_MAX_RECEIPTS,
            max_premium_credits: DEFAULT_MAX_PREMIUM_CREDITS,
            max_quarantines: DEFAULT_MAX_QUARANTINES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
            allowed_risk_kinds: BTreeSet::from([
                UpgradeRiskKind::ParameterOnly,
                UpgradeRiskKind::StorageLayout,
                UpgradeRiskKind::VerifierKeyRotation,
                UpgradeRiskKind::PrecompileBinding,
                UpgradeRiskKind::GovernanceAdmin,
                UpgradeRiskKind::CrossContractCallGraph,
                UpgradeRiskKind::BridgeAdapter,
                UpgradeRiskKind::EmergencyPatch,
            ]),
            require_sealed_policies: true,
            require_pq_auditors: true,
            require_low_fee_credits: true,
            require_operator_safe_public_records: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "chain_id": self.chain_id,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "activation_height": self.activation_height,
            "hash_suite": HASH_SUITE,
            "pq_audit_suite": PQ_AUDIT_SUITE,
            "confidentiality_suite": CONFIDENTIALITY_SUITE,
            "min_privacy_set_size": self.min_privacy_set_size,
            "batch_privacy_set_size": self.batch_privacy_set_size,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_premium_bps": self.max_premium_bps,
            "min_reserve_ratio_bps": self.min_reserve_ratio_bps,
            "low_fee_credit_bps": self.low_fee_credit_bps,
            "auditor_quorum": self.auditor_quorum,
            "auditor_set_size": self.auditor_set_size,
            "quarantine_blocks": self.quarantine_blocks,
            "policy_ttl_blocks": self.policy_ttl_blocks,
            "receipt_finality_blocks": self.receipt_finality_blocks,
            "redaction_budget_fields": self.redaction_budget_fields,
            "allowed_risk_kinds": self.allowed_risk_kinds.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "sealed_policies": self.require_sealed_policies,
            "pq_auditors": self.require_pq_auditors,
            "low_fee_credits": self.require_low_fee_credits,
            "operator_safe_public_records": self.require_operator_safe_public_records,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub policies: u64,
    pub risk_classes: u64,
    pub auditor_attestations: u64,
    pub insured_receipts: u64,
    pub premium_credits: u64,
    pub claim_quarantines: u64,
    pub redaction_budgets: u64,
    pub public_records: u64,
    pub accepted_attestations: u64,
    pub rejected_attestations: u64,
    pub quarantined_claims: u64,
    pub applied_credits: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "policies": self.policies,
            "risk_classes": self.risk_classes,
            "auditor_attestations": self.auditor_attestations,
            "insured_receipts": self.insured_receipts,
            "premium_credits": self.premium_credits,
            "claim_quarantines": self.claim_quarantines,
            "redaction_budgets": self.redaction_budgets,
            "public_records": self.public_records,
            "accepted_attestations": self.accepted_attestations,
            "rejected_attestations": self.rejected_attestations,
            "quarantined_claims": self.quarantined_claims,
            "applied_credits": self.applied_credits,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub policies_root: String,
    pub risk_classes_root: String,
    pub auditor_attestations_root: String,
    pub insured_receipts_root: String,
    pub premium_credits_root: String,
    pub claim_quarantines_root: String,
    pub redaction_budgets_root: String,
    pub public_records_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            policies_root: merkle_root(POLICY_SCHEME, &[]),
            risk_classes_root: merkle_root(RISK_CLASS_SCHEME, &[]),
            auditor_attestations_root: merkle_root(AUDITOR_ATTESTATION_SCHEME, &[]),
            insured_receipts_root: merkle_root(INSURED_RECEIPT_SCHEME, &[]),
            premium_credits_root: merkle_root(PREMIUM_CREDIT_SCHEME, &[]),
            claim_quarantines_root: merkle_root(CLAIM_QUARANTINE_SCHEME, &[]),
            redaction_budgets_root: merkle_root(REDACTION_BUDGET_SCHEME, &[]),
            public_records_root: merkle_root(PUBLIC_RECORD_SCHEME, &[]),
            state_root: domain_hash(PROTOCOL_VERSION, &[HashPart::Str("empty")], 32),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "policies_root": self.policies_root,
            "risk_classes_root": self.risk_classes_root,
            "auditor_attestations_root": self.auditor_attestations_root,
            "insured_receipts_root": self.insured_receipts_root,
            "premium_credits_root": self.premium_credits_root,
            "claim_quarantines_root": self.claim_quarantines_root,
            "redaction_budgets_root": self.redaction_budgets_root,
            "public_records_root": self.public_records_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedBountyPolicyRequest {
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub contract_id: String,
    pub upgrade_id: String,
    pub risk_class_id: String,
    pub bounty_commitment: String,
    pub insured_limit_micronero: u64,
    pub premium_commitment: String,
    pub reserve_commitment: String,
    pub privacy_set_size: u64,
    pub opens_height: u64,
    pub expires_height: u64,
    pub status: PolicyStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SealedBountyPolicy {
    pub sequence: u64,
    pub policy_id: String,
    pub sponsor_commitment: String,
    pub contract_id: String,
    pub upgrade_id: String,
    pub risk_class_id: String,
    pub bounty_commitment: String,
    pub insured_limit_micronero: u64,
    pub premium_commitment: String,
    pub reserve_commitment: String,
    pub privacy_set_size: u64,
    pub opens_height: u64,
    pub expires_height: u64,
    pub status: PolicyStatus,
    pub policy_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeRiskClassRequest {
    pub risk_class_id: String,
    pub kind: UpgradeRiskKind,
    pub contract_family: String,
    pub invariant_root: String,
    pub storage_layout_root: String,
    pub call_graph_root: String,
    pub verifier_key_root: String,
    pub risk_score: u16,
    pub base_premium_bps: u64,
    pub reserve_ratio_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradeRiskClass {
    pub sequence: u64,
    pub risk_class_id: String,
    pub kind: UpgradeRiskKind,
    pub contract_family: String,
    pub invariant_root: String,
    pub storage_layout_root: String,
    pub call_graph_root: String,
    pub verifier_key_root: String,
    pub risk_score: u16,
    pub base_premium_bps: u64,
    pub reserve_ratio_bps: u64,
    pub accepted: bool,
    pub class_root: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuditorAttestationRequest {
    pub attestation_id: String,
    pub auditor_id: String,
    pub policy_id: String,
    pub upgrade_id: String,
    pub pq_key_commitment: String,
    pub proof_manifest_root: String,
    pub diff_witness_root: String,
    pub vulnerability_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub coverage_bps: u16,
    pub verdict: AuditorVerdict,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqAuditorAttestation {
    pub sequence: u64,
    pub attestation_id: String,
    pub auditor_id: String,
    pub policy_id: String,
    pub upgrade_id: String,
    pub pq_key_commitment: String,
    pub proof_manifest_root: String,
    pub diff_witness_root: String,
    pub vulnerability_root: String,
    pub signature_root: String,
    pub security_bits: u16,
    pub coverage_bps: u16,
    pub verdict: AuditorVerdict,
    pub accepted: bool,
    pub attestation_root: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InsuredUpgradeReceiptRequest {
    pub receipt_id: String,
    pub policy_id: String,
    pub upgrade_id: String,
    pub contract_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub execution_trace_root: String,
    pub auditor_quorum_root: String,
    pub receipt_commitment: String,
    pub finality_height: u64,
    pub status: ReceiptStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InsuredUpgradeReceipt {
    pub sequence: u64,
    pub receipt_id: String,
    pub policy_id: String,
    pub upgrade_id: String,
    pub contract_id: String,
    pub pre_state_root: String,
    pub post_state_root: String,
    pub execution_trace_root: String,
    pub auditor_quorum_root: String,
    pub receipt_commitment: String,
    pub finality_height: u64,
    pub status: ReceiptStatus,
    pub receipt_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeePremiumCreditRequest {
    pub credit_id: String,
    pub policy_id: String,
    pub owner_nullifier: String,
    pub sponsor_commitment: String,
    pub credit_commitment: String,
    pub fee_lane_root: String,
    pub amount_micronero: u64,
    pub discount_bps: u64,
    pub expires_height: u64,
    pub status: CreditStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeePremiumCredit {
    pub sequence: u64,
    pub credit_id: String,
    pub policy_id: String,
    pub owner_nullifier: String,
    pub sponsor_commitment: String,
    pub credit_commitment: String,
    pub fee_lane_root: String,
    pub amount_micronero: u64,
    pub discount_bps: u64,
    pub expires_height: u64,
    pub status: CreditStatus,
    pub credit_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimQuarantineRequest {
    pub quarantine_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub receipt_id: String,
    pub claimant_nullifier: String,
    pub evidence_root: String,
    pub suspected_fault_root: String,
    pub locked_amount_micronero: u64,
    pub opened_height: u64,
    pub release_height: u64,
    pub status: ClaimStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClaimQuarantine {
    pub sequence: u64,
    pub quarantine_id: String,
    pub claim_id: String,
    pub policy_id: String,
    pub receipt_id: String,
    pub claimant_nullifier: String,
    pub evidence_root: String,
    pub suspected_fault_root: String,
    pub locked_amount_micronero: u64,
    pub opened_height: u64,
    pub release_height: u64,
    pub status: ClaimStatus,
    pub quarantine_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudgetRequest {
    pub budget_id: String,
    pub policy_id: String,
    pub steward_id: String,
    pub allowed_fields: u16,
    pub consumed_fields: u16,
    pub redaction_root: String,
    pub disclosure_log_root: String,
    pub public_summary_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedactionBudget {
    pub sequence: u64,
    pub budget_id: String,
    pub policy_id: String,
    pub steward_id: String,
    pub allowed_fields: u16,
    pub consumed_fields: u16,
    pub redaction_root: String,
    pub disclosure_log_root: String,
    pub public_summary_root: String,
    pub exhausted: bool,
    pub budget_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub height: u64,
    pub policies: BTreeMap<String, SealedBountyPolicy>,
    pub risk_classes: BTreeMap<String, UpgradeRiskClass>,
    pub auditor_attestations: BTreeMap<String, PqAuditorAttestation>,
    pub insured_receipts: BTreeMap<String, InsuredUpgradeReceipt>,
    pub premium_credits: BTreeMap<String, LowFeePremiumCredit>,
    pub claim_quarantines: BTreeMap<String, ClaimQuarantine>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub policy_claim_index: BTreeMap<String, BTreeSet<String>>,
    pub public_records: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config) -> Self {
        let mut state = Self {
            height: config.activation_height,
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            policies: BTreeMap::new(),
            risk_classes: BTreeMap::new(),
            auditor_attestations: BTreeMap::new(),
            insured_receipts: BTreeMap::new(),
            premium_credits: BTreeMap::new(),
            claim_quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            policy_claim_index: BTreeMap::new(),
            public_records: BTreeMap::new(),
        };
        state.refresh_roots();
        state
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet());
        state
            .register_risk_class(UpgradeRiskClassRequest {
                risk_class_id: "risk-devnet-storage-layout-001".to_string(),
                kind: UpgradeRiskKind::StorageLayout,
                contract_family: "confidential-vault".to_string(),
                invariant_root: commitment("invariant", "vault-upgrade", 1),
                storage_layout_root: commitment("storage-layout", "vault-v2", 2),
                call_graph_root: commitment("call-graph", "vault-safe", 3),
                verifier_key_root: commitment("vk", "vault-upgrade", 4),
                risk_score: 742,
                base_premium_bps: 74,
                reserve_ratio_bps: 19_500,
            })
            .expect("devnet risk class");
        state
            .seal_policy(SealedBountyPolicyRequest {
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                sponsor_commitment: commitment("sponsor", "vault-dao", 11),
                contract_id: "contract-confidential-vault-001".to_string(),
                upgrade_id: "upgrade-vault-layout-v2".to_string(),
                risk_class_id: "risk-devnet-storage-layout-001".to_string(),
                bounty_commitment: commitment("bounty", "vault-upgrade", 25_000_000_000),
                insured_limit_micronero: 80_000_000_000,
                premium_commitment: commitment("premium", "vault-upgrade", 640_000_000),
                reserve_commitment: commitment("reserve", "vault-upgrade", 16_000_000_000),
                privacy_set_size: 524_288,
                opens_height: DEVNET_HEIGHT + 12,
                expires_height: DEVNET_HEIGHT + 43_200,
                status: PolicyStatus::Sealed,
            })
            .expect("devnet policy");
        state
            .attest_upgrade(PqAuditorAttestationRequest {
                attestation_id: "attestation-devnet-auditor-001".to_string(),
                auditor_id: "auditor-ml-dsa-001".to_string(),
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                upgrade_id: "upgrade-vault-layout-v2".to_string(),
                pq_key_commitment: commitment("pq-key", "auditor-001", 1),
                proof_manifest_root: commitment("proof-manifest", "vault-v2", 2),
                diff_witness_root: commitment("diff-witness", "vault-v2", 3),
                vulnerability_root: commitment("vuln-root", "none-critical", 4),
                signature_root: commitment("sig", "auditor-001", 5),
                security_bits: 256,
                coverage_bps: 9_450,
                verdict: AuditorVerdict::Passed,
            })
            .expect("devnet attestation");
        state
            .record_insured_receipt(InsuredUpgradeReceiptRequest {
                receipt_id: "receipt-devnet-vault-upgrade-001".to_string(),
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                upgrade_id: "upgrade-vault-layout-v2".to_string(),
                contract_id: "contract-confidential-vault-001".to_string(),
                pre_state_root: commitment("state", "vault-pre", 10),
                post_state_root: commitment("state", "vault-post", 11),
                execution_trace_root: commitment("trace", "vault-upgrade", 12),
                auditor_quorum_root: commitment("auditor-quorum", "vault-upgrade", 13),
                receipt_commitment: commitment("receipt", "vault-upgrade", 14),
                finality_height: DEVNET_HEIGHT + 48,
                status: ReceiptStatus::Insured,
            })
            .expect("devnet receipt");
        state
            .issue_premium_credit(LowFeePremiumCreditRequest {
                credit_id: "credit-devnet-vault-upgrade-001".to_string(),
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                owner_nullifier: commitment("nullifier", "vault-sponsor", 1),
                sponsor_commitment: commitment("sponsor", "vault-dao", 11),
                credit_commitment: commitment("credit", "vault-upgrade", 70_400_000),
                fee_lane_root: commitment("fee-lane", "low-fee", 2),
                amount_micronero: 70_400_000,
                discount_bps: 11,
                expires_height: DEVNET_HEIGHT + 12_000,
                status: CreditStatus::Available,
            })
            .expect("devnet credit");
        state
            .open_claim_quarantine(ClaimQuarantineRequest {
                quarantine_id: "quarantine-devnet-vault-claim-001".to_string(),
                claim_id: "claim-devnet-vault-001".to_string(),
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                receipt_id: "receipt-devnet-vault-upgrade-001".to_string(),
                claimant_nullifier: commitment("claimant", "vault-user", 1),
                evidence_root: commitment("claim-evidence", "vault-v2", 2),
                suspected_fault_root: commitment("fault", "storage-shadow", 3),
                locked_amount_micronero: 8_000_000_000,
                opened_height: DEVNET_HEIGHT + 96,
                release_height: DEVNET_HEIGHT + 96 + DEFAULT_QUARANTINE_BLOCKS,
                status: ClaimStatus::Quarantined,
            })
            .expect("devnet quarantine");
        state
            .allocate_redaction_budget(RedactionBudgetRequest {
                budget_id: "redaction-devnet-vault-001".to_string(),
                policy_id: "policy-devnet-vault-upgrade-001".to_string(),
                steward_id: "operator-safe-steward-001".to_string(),
                allowed_fields: DEFAULT_REDACTION_BUDGET_FIELDS,
                consumed_fields: 3,
                redaction_root: commitment("redaction", "vault-fields", 1),
                disclosure_log_root: commitment("disclosure", "vault-log", 2),
                public_summary_root: commitment("summary", "vault-public", 3),
            })
            .expect("devnet redaction");
        state.publish_public_record("public-devnet-vault-001");
        state
    }

    pub fn demo() -> Self {
        let mut state = Self::devnet();
        state.height += 128;
        state
            .register_risk_class(UpgradeRiskClassRequest {
                risk_class_id: "risk-demo-bridge-adapter-001".to_string(),
                kind: UpgradeRiskKind::BridgeAdapter,
                contract_family: "confidential-bridge-adapter".to_string(),
                invariant_root: commitment("invariant", "bridge-adapter", 1),
                storage_layout_root: commitment("storage-layout", "bridge-adapter", 2),
                call_graph_root: commitment("call-graph", "bridge-adapter", 3),
                verifier_key_root: commitment("vk", "bridge-adapter", 4),
                risk_score: 912,
                base_premium_bps: 138,
                reserve_ratio_bps: 24_000,
            })
            .expect("demo risk class");
        state
    }

    pub fn register_risk_class(
        &mut self,
        request: UpgradeRiskClassRequest,
    ) -> Result<UpgradeRiskClass> {
        if self.risk_classes.len() >= self.config.max_risk_classes {
            return Err("risk class capacity exhausted".to_string());
        }
        if self.risk_classes.contains_key(&request.risk_class_id) {
            return Err("risk class already exists".to_string());
        }
        if !self.config.allowed_risk_kinds.contains(&request.kind) {
            return Err("risk kind not enabled".to_string());
        }
        let accepted = request.base_premium_bps <= self.config.max_premium_bps
            && request.reserve_ratio_bps >= self.config.min_reserve_ratio_bps
            && request.risk_score <= 1_000;
        let reason = if accepted {
            "risk class accepted"
        } else {
            "risk class outside premium or reserve guardrails"
        };
        let sequence = self.counters.risk_classes + 1;
        let class_root = domain_hash(
            RISK_CLASS_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.risk_class_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.contract_family),
                HashPart::Str(&request.invariant_root),
                HashPart::Str(&request.storage_layout_root),
                HashPart::Str(&request.call_graph_root),
                HashPart::Str(&request.verifier_key_root),
                HashPart::U64(request.risk_score as u64),
                HashPart::U64(request.base_premium_bps),
                HashPart::U64(request.reserve_ratio_bps),
            ],
            32,
        );
        let record = UpgradeRiskClass {
            sequence,
            risk_class_id: request.risk_class_id,
            kind: request.kind,
            contract_family: request.contract_family,
            invariant_root: request.invariant_root,
            storage_layout_root: request.storage_layout_root,
            call_graph_root: request.call_graph_root,
            verifier_key_root: request.verifier_key_root,
            risk_score: request.risk_score,
            base_premium_bps: request.base_premium_bps,
            reserve_ratio_bps: request.reserve_ratio_bps,
            accepted,
            class_root,
            reason: reason.to_string(),
        };
        self.counters.risk_classes = sequence;
        self.risk_classes
            .insert(record.risk_class_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn seal_policy(
        &mut self,
        request: SealedBountyPolicyRequest,
    ) -> Result<SealedBountyPolicy> {
        if self.policies.len() >= self.config.max_policies {
            return Err("policy capacity exhausted".to_string());
        }
        if self.policies.contains_key(&request.policy_id) {
            return Err("policy already exists".to_string());
        }
        if !self.risk_classes.contains_key(&request.risk_class_id) {
            return Err("risk class missing".to_string());
        }
        if self.config.require_sealed_policies && request.status == PolicyStatus::Draft {
            return Err("sealed policy required".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("privacy set below configured floor".to_string());
        }
        if request.expires_height <= request.opens_height {
            return Err("policy expiry must be after open height".to_string());
        }
        let sequence = self.counters.policies + 1;
        let policy_root = domain_hash(
            POLICY_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.sponsor_commitment),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.upgrade_id),
                HashPart::Str(&request.risk_class_id),
                HashPart::Str(&request.bounty_commitment),
                HashPart::U64(request.insured_limit_micronero),
                HashPart::Str(&request.premium_commitment),
                HashPart::Str(&request.reserve_commitment),
                HashPart::U64(request.privacy_set_size),
                HashPart::U64(request.opens_height),
                HashPart::U64(request.expires_height),
                HashPart::Str(request.status.as_str()),
            ],
            32,
        );
        let policy = SealedBountyPolicy {
            sequence,
            policy_id: request.policy_id,
            sponsor_commitment: request.sponsor_commitment,
            contract_id: request.contract_id,
            upgrade_id: request.upgrade_id,
            risk_class_id: request.risk_class_id,
            bounty_commitment: request.bounty_commitment,
            insured_limit_micronero: request.insured_limit_micronero,
            premium_commitment: request.premium_commitment,
            reserve_commitment: request.reserve_commitment,
            privacy_set_size: request.privacy_set_size,
            opens_height: request.opens_height,
            expires_height: request.expires_height,
            status: request.status,
            policy_root,
        };
        self.counters.policies = sequence;
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        self.refresh_roots();
        Ok(policy)
    }

    pub fn attest_upgrade(
        &mut self,
        request: PqAuditorAttestationRequest,
    ) -> Result<PqAuditorAttestation> {
        if self.auditor_attestations.len() >= self.config.max_auditor_attestations {
            return Err("auditor attestation capacity exhausted".to_string());
        }
        if self
            .auditor_attestations
            .contains_key(&request.attestation_id)
        {
            return Err("auditor attestation already exists".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "policy missing".to_string())?;
        if policy.upgrade_id != request.upgrade_id {
            return Err("attestation upgrade id mismatch".to_string());
        }
        let accepted = request.verdict.approves()
            && request.security_bits >= self.config.min_pq_security_bits
            && request.coverage_bps >= 8_000;
        let reason = if accepted {
            "pq auditor attestation accepted"
        } else {
            "pq auditor attestation did not meet security or coverage floor"
        };
        let sequence = self.counters.auditor_attestations + 1;
        let attestation_root = domain_hash(
            AUDITOR_ATTESTATION_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.attestation_id),
                HashPart::Str(&request.auditor_id),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.upgrade_id),
                HashPart::Str(&request.pq_key_commitment),
                HashPart::Str(&request.proof_manifest_root),
                HashPart::Str(&request.diff_witness_root),
                HashPart::Str(&request.vulnerability_root),
                HashPart::Str(&request.signature_root),
                HashPart::U64(request.security_bits as u64),
                HashPart::U64(request.coverage_bps as u64),
                HashPart::Str(request.verdict.as_str()),
            ],
            32,
        );
        let record = PqAuditorAttestation {
            sequence,
            attestation_id: request.attestation_id,
            auditor_id: request.auditor_id,
            policy_id: request.policy_id,
            upgrade_id: request.upgrade_id,
            pq_key_commitment: request.pq_key_commitment,
            proof_manifest_root: request.proof_manifest_root,
            diff_witness_root: request.diff_witness_root,
            vulnerability_root: request.vulnerability_root,
            signature_root: request.signature_root,
            security_bits: request.security_bits,
            coverage_bps: request.coverage_bps,
            verdict: request.verdict,
            accepted,
            attestation_root,
            reason: reason.to_string(),
        };
        self.counters.auditor_attestations = sequence;
        if accepted {
            self.counters.accepted_attestations += 1;
        } else {
            self.counters.rejected_attestations += 1;
        }
        self.auditor_attestations
            .insert(record.attestation_id.clone(), record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn record_insured_receipt(
        &mut self,
        request: InsuredUpgradeReceiptRequest,
    ) -> Result<InsuredUpgradeReceipt> {
        if self.insured_receipts.len() >= self.config.max_receipts {
            return Err("insured receipt capacity exhausted".to_string());
        }
        if self.insured_receipts.contains_key(&request.receipt_id) {
            return Err("insured receipt already exists".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "policy missing".to_string())?;
        if !policy.status.accepts_receipts() {
            return Err("policy does not accept insured receipts".to_string());
        }
        if policy.contract_id != request.contract_id || policy.upgrade_id != request.upgrade_id {
            return Err("receipt does not match policy contract or upgrade".to_string());
        }
        let accepted_attestations = self
            .auditor_attestations
            .values()
            .filter(|attestation| {
                attestation.policy_id == request.policy_id
                    && attestation.upgrade_id == request.upgrade_id
                    && attestation.accepted
            })
            .count() as u16;
        if self.config.require_pq_auditors && accepted_attestations == 0 {
            return Err("at least one accepted pq auditor attestation required".to_string());
        }
        let sequence = self.counters.insured_receipts + 1;
        let receipt_root = domain_hash(
            INSURED_RECEIPT_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.receipt_id),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.upgrade_id),
                HashPart::Str(&request.contract_id),
                HashPart::Str(&request.pre_state_root),
                HashPart::Str(&request.post_state_root),
                HashPart::Str(&request.execution_trace_root),
                HashPart::Str(&request.auditor_quorum_root),
                HashPart::Str(&request.receipt_commitment),
                HashPart::U64(request.finality_height),
                HashPart::Str(request.status.as_str()),
            ],
            32,
        );
        let receipt = InsuredUpgradeReceipt {
            sequence,
            receipt_id: request.receipt_id,
            policy_id: request.policy_id,
            upgrade_id: request.upgrade_id,
            contract_id: request.contract_id,
            pre_state_root: request.pre_state_root,
            post_state_root: request.post_state_root,
            execution_trace_root: request.execution_trace_root,
            auditor_quorum_root: request.auditor_quorum_root,
            receipt_commitment: request.receipt_commitment,
            finality_height: request.finality_height,
            status: request.status,
            receipt_root,
        };
        self.counters.insured_receipts = sequence;
        self.insured_receipts
            .insert(receipt.receipt_id.clone(), receipt.clone());
        self.refresh_roots();
        Ok(receipt)
    }

    pub fn issue_premium_credit(
        &mut self,
        request: LowFeePremiumCreditRequest,
    ) -> Result<LowFeePremiumCredit> {
        if self.premium_credits.len() >= self.config.max_premium_credits {
            return Err("premium credit capacity exhausted".to_string());
        }
        if self.premium_credits.contains_key(&request.credit_id) {
            return Err("premium credit already exists".to_string());
        }
        if !self.policies.contains_key(&request.policy_id) {
            return Err("policy missing".to_string());
        }
        if request.discount_bps > self.config.low_fee_credit_bps {
            return Err("premium credit discount exceeds low fee budget".to_string());
        }
        let sequence = self.counters.premium_credits + 1;
        let credit_root = domain_hash(
            PREMIUM_CREDIT_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.credit_id),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.owner_nullifier),
                HashPart::Str(&request.sponsor_commitment),
                HashPart::Str(&request.credit_commitment),
                HashPart::Str(&request.fee_lane_root),
                HashPart::U64(request.amount_micronero),
                HashPart::U64(request.discount_bps),
                HashPart::U64(request.expires_height),
                HashPart::Str(request.status.as_str()),
            ],
            32,
        );
        let credit = LowFeePremiumCredit {
            sequence,
            credit_id: request.credit_id,
            policy_id: request.policy_id,
            owner_nullifier: request.owner_nullifier,
            sponsor_commitment: request.sponsor_commitment,
            credit_commitment: request.credit_commitment,
            fee_lane_root: request.fee_lane_root,
            amount_micronero: request.amount_micronero,
            discount_bps: request.discount_bps,
            expires_height: request.expires_height,
            status: request.status,
            credit_root,
        };
        self.counters.premium_credits = sequence;
        if credit.status == CreditStatus::Applied {
            self.counters.applied_credits += 1;
        }
        self.premium_credits
            .insert(credit.credit_id.clone(), credit.clone());
        self.refresh_roots();
        Ok(credit)
    }

    pub fn open_claim_quarantine(
        &mut self,
        request: ClaimQuarantineRequest,
    ) -> Result<ClaimQuarantine> {
        if self.claim_quarantines.len() >= self.config.max_quarantines {
            return Err("claim quarantine capacity exhausted".to_string());
        }
        if self.claim_quarantines.contains_key(&request.quarantine_id) {
            return Err("claim quarantine already exists".to_string());
        }
        let policy = self
            .policies
            .get(&request.policy_id)
            .ok_or_else(|| "policy missing".to_string())?;
        if !policy.status.accepts_claims() && request.status != ClaimStatus::Quarantined {
            return Err("policy does not accept claims".to_string());
        }
        if !self.insured_receipts.contains_key(&request.receipt_id) {
            return Err("insured receipt missing".to_string());
        }
        if request.release_height < request.opened_height + self.config.quarantine_blocks {
            return Err("quarantine release height is below configured hold".to_string());
        }
        let sequence = self.counters.claim_quarantines + 1;
        let quarantine_root = domain_hash(
            CLAIM_QUARANTINE_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.quarantine_id),
                HashPart::Str(&request.claim_id),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.receipt_id),
                HashPart::Str(&request.claimant_nullifier),
                HashPart::Str(&request.evidence_root),
                HashPart::Str(&request.suspected_fault_root),
                HashPart::U64(request.locked_amount_micronero),
                HashPart::U64(request.opened_height),
                HashPart::U64(request.release_height),
                HashPart::Str(request.status.as_str()),
            ],
            32,
        );
        let quarantine = ClaimQuarantine {
            sequence,
            quarantine_id: request.quarantine_id,
            claim_id: request.claim_id,
            policy_id: request.policy_id,
            receipt_id: request.receipt_id,
            claimant_nullifier: request.claimant_nullifier,
            evidence_root: request.evidence_root,
            suspected_fault_root: request.suspected_fault_root,
            locked_amount_micronero: request.locked_amount_micronero,
            opened_height: request.opened_height,
            release_height: request.release_height,
            status: request.status,
            quarantine_root,
        };
        self.counters.claim_quarantines = sequence;
        if quarantine.status == ClaimStatus::Quarantined {
            self.counters.quarantined_claims += 1;
        }
        self.policy_claim_index
            .entry(quarantine.policy_id.clone())
            .or_default()
            .insert(quarantine.claim_id.clone());
        self.claim_quarantines
            .insert(quarantine.quarantine_id.clone(), quarantine.clone());
        self.refresh_roots();
        Ok(quarantine)
    }

    pub fn allocate_redaction_budget(
        &mut self,
        request: RedactionBudgetRequest,
    ) -> Result<RedactionBudget> {
        if self.redaction_budgets.len() >= self.config.max_redaction_budgets {
            return Err("redaction budget capacity exhausted".to_string());
        }
        if self.redaction_budgets.contains_key(&request.budget_id) {
            return Err("redaction budget already exists".to_string());
        }
        if !self.policies.contains_key(&request.policy_id) {
            return Err("policy missing".to_string());
        }
        if request.allowed_fields > self.config.redaction_budget_fields {
            return Err("redaction budget exceeds configured field cap".to_string());
        }
        if request.consumed_fields > request.allowed_fields {
            return Err("redaction budget consumed fields exceed allowance".to_string());
        }
        let sequence = self.counters.redaction_budgets + 1;
        let exhausted = request.consumed_fields == request.allowed_fields;
        let budget_root = domain_hash(
            REDACTION_BUDGET_SCHEME,
            &[
                HashPart::U64(sequence),
                HashPart::Str(&request.budget_id),
                HashPart::Str(&request.policy_id),
                HashPart::Str(&request.steward_id),
                HashPart::U64(request.allowed_fields as u64),
                HashPart::U64(request.consumed_fields as u64),
                HashPart::Str(&request.redaction_root),
                HashPart::Str(&request.disclosure_log_root),
                HashPart::Str(&request.public_summary_root),
            ],
            32,
        );
        let budget = RedactionBudget {
            sequence,
            budget_id: request.budget_id,
            policy_id: request.policy_id,
            steward_id: request.steward_id,
            allowed_fields: request.allowed_fields,
            consumed_fields: request.consumed_fields,
            redaction_root: request.redaction_root,
            disclosure_log_root: request.disclosure_log_root,
            public_summary_root: request.public_summary_root,
            exhausted,
            budget_root,
        };
        self.counters.redaction_budgets = sequence;
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget.clone());
        self.refresh_roots();
        Ok(budget)
    }

    pub fn publish_public_record(&mut self, record_id: &str) -> Value {
        let record = self.public_record();
        self.public_records
            .insert(record_id.to_string(), redact_public_record(&record));
        self.counters.public_records = self.public_records.len() as u64;
        self.refresh_roots();
        record
    }

    pub fn refresh_roots(&mut self) {
        self.roots.policies_root = merkle_root(
            POLICY_SCHEME,
            &self
                .policies
                .values()
                .map(redact_policy)
                .collect::<Vec<_>>(),
        );
        self.roots.risk_classes_root = merkle_root(
            RISK_CLASS_SCHEME,
            &self
                .risk_classes
                .values()
                .map(redact_risk_class)
                .collect::<Vec<_>>(),
        );
        self.roots.auditor_attestations_root = merkle_root(
            AUDITOR_ATTESTATION_SCHEME,
            &self
                .auditor_attestations
                .values()
                .map(redact_attestation)
                .collect::<Vec<_>>(),
        );
        self.roots.insured_receipts_root = merkle_root(
            INSURED_RECEIPT_SCHEME,
            &self
                .insured_receipts
                .values()
                .map(redact_receipt)
                .collect::<Vec<_>>(),
        );
        self.roots.premium_credits_root = merkle_root(
            PREMIUM_CREDIT_SCHEME,
            &self
                .premium_credits
                .values()
                .map(redact_credit)
                .collect::<Vec<_>>(),
        );
        self.roots.claim_quarantines_root = merkle_root(
            CLAIM_QUARANTINE_SCHEME,
            &self
                .claim_quarantines
                .values()
                .map(redact_quarantine)
                .collect::<Vec<_>>(),
        );
        self.roots.redaction_budgets_root = merkle_root(
            REDACTION_BUDGET_SCHEME,
            &self
                .redaction_budgets
                .values()
                .map(redact_budget)
                .collect::<Vec<_>>(),
        );
        self.roots.public_records_root = merkle_root(
            PUBLIC_RECORD_SCHEME,
            &self.public_records.values().cloned().collect::<Vec<_>>(),
        );
        self.roots.state_root = self.state_root();
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            PROTOCOL_VERSION,
            &[
                HashPart::Str(&self.config.chain_id),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Str(&self.roots.policies_root),
                HashPart::Str(&self.roots.risk_classes_root),
                HashPart::Str(&self.roots.auditor_attestations_root),
                HashPart::Str(&self.roots.insured_receipts_root),
                HashPart::Str(&self.roots.premium_credits_root),
                HashPart::Str(&self.roots.claim_quarantines_root),
                HashPart::Str(&self.roots.redaction_budgets_root),
                HashPart::Str(&self.roots.public_records_root),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "operator_safe_summary": {
                "sealed_policies": self.policies.values().filter(|policy| policy.status == PolicyStatus::Sealed).count(),
                "bound_policies": self.policies.values().filter(|policy| policy.status == PolicyStatus::Bound).count(),
                "risk_classes": self.risk_classes.len(),
                "accepted_attestations": self.counters.accepted_attestations,
                "insured_receipts": self.insured_receipts.len(),
                "available_low_fee_credits": self.premium_credits.values().filter(|credit| credit.status == CreditStatus::Available).count(),
                "quarantined_claims": self.counters.quarantined_claims,
                "redaction_budgets": self.redaction_budgets.len(),
                "operator_safe_public_records": self.config.require_operator_safe_public_records,
            }
        })
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn commitment(domain: &str, label: &str, value: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(label),
            HashPart::U64(value),
            HashPart::Str(PROTOCOL_VERSION),
        ],
        32,
    )
}

fn redact_policy(policy: &SealedBountyPolicy) -> Value {
    json!({
        "kind": "sealed_bounty_policy",
        "sequence": policy.sequence,
        "policy_id": policy.policy_id,
        "contract_id": policy.contract_id,
        "upgrade_id": policy.upgrade_id,
        "risk_class_id": policy.risk_class_id,
        "sponsor_commitment": policy.sponsor_commitment,
        "bounty_commitment": policy.bounty_commitment,
        "insured_limit_micronero": policy.insured_limit_micronero,
        "premium_commitment": policy.premium_commitment,
        "reserve_commitment": policy.reserve_commitment,
        "privacy_set_size": policy.privacy_set_size,
        "opens_height": policy.opens_height,
        "expires_height": policy.expires_height,
        "status": policy.status.as_str(),
        "policy_root": policy.policy_root,
        "redacted_fields": ["sponsor_identity", "bounty_plaintext", "premium_plaintext"],
    })
}

fn redact_risk_class(class: &UpgradeRiskClass) -> Value {
    json!({
        "kind": "upgrade_risk_class",
        "sequence": class.sequence,
        "risk_class_id": class.risk_class_id,
        "risk_kind": class.kind.as_str(),
        "contract_family": class.contract_family,
        "invariant_root": class.invariant_root,
        "storage_layout_root": class.storage_layout_root,
        "call_graph_root": class.call_graph_root,
        "verifier_key_root": class.verifier_key_root,
        "risk_score": class.risk_score,
        "base_premium_bps": class.base_premium_bps,
        "reserve_ratio_bps": class.reserve_ratio_bps,
        "accepted": class.accepted,
        "class_root": class.class_root,
        "reason": class.reason,
    })
}

fn redact_attestation(attestation: &PqAuditorAttestation) -> Value {
    json!({
        "kind": "pq_auditor_attestation",
        "sequence": attestation.sequence,
        "attestation_id": attestation.attestation_id,
        "auditor_id": attestation.auditor_id,
        "policy_id": attestation.policy_id,
        "upgrade_id": attestation.upgrade_id,
        "pq_key_commitment": attestation.pq_key_commitment,
        "proof_manifest_root": attestation.proof_manifest_root,
        "diff_witness_root": attestation.diff_witness_root,
        "vulnerability_root": attestation.vulnerability_root,
        "signature_root": attestation.signature_root,
        "security_bits": attestation.security_bits,
        "coverage_bps": attestation.coverage_bps,
        "verdict": attestation.verdict.as_str(),
        "accepted": attestation.accepted,
        "attestation_root": attestation.attestation_root,
        "reason": attestation.reason,
    })
}

fn redact_receipt(receipt: &InsuredUpgradeReceipt) -> Value {
    json!({
        "kind": "insured_upgrade_receipt",
        "sequence": receipt.sequence,
        "receipt_id": receipt.receipt_id,
        "policy_id": receipt.policy_id,
        "upgrade_id": receipt.upgrade_id,
        "contract_id": receipt.contract_id,
        "pre_state_root": receipt.pre_state_root,
        "post_state_root": receipt.post_state_root,
        "execution_trace_root": receipt.execution_trace_root,
        "auditor_quorum_root": receipt.auditor_quorum_root,
        "receipt_commitment": receipt.receipt_commitment,
        "finality_height": receipt.finality_height,
        "status": receipt.status.as_str(),
        "receipt_root": receipt.receipt_root,
    })
}

fn redact_credit(credit: &LowFeePremiumCredit) -> Value {
    json!({
        "kind": "low_fee_premium_credit",
        "sequence": credit.sequence,
        "credit_id": credit.credit_id,
        "policy_id": credit.policy_id,
        "owner_nullifier": credit.owner_nullifier,
        "sponsor_commitment": credit.sponsor_commitment,
        "credit_commitment": credit.credit_commitment,
        "fee_lane_root": credit.fee_lane_root,
        "amount_micronero": credit.amount_micronero,
        "discount_bps": credit.discount_bps,
        "expires_height": credit.expires_height,
        "status": credit.status.as_str(),
        "credit_root": credit.credit_root,
        "redacted_fields": ["owner_address", "premium_plaintext"],
    })
}

fn redact_quarantine(quarantine: &ClaimQuarantine) -> Value {
    json!({
        "kind": "claim_quarantine",
        "sequence": quarantine.sequence,
        "quarantine_id": quarantine.quarantine_id,
        "claim_id": quarantine.claim_id,
        "policy_id": quarantine.policy_id,
        "receipt_id": quarantine.receipt_id,
        "claimant_nullifier": quarantine.claimant_nullifier,
        "evidence_root": quarantine.evidence_root,
        "suspected_fault_root": quarantine.suspected_fault_root,
        "locked_amount_micronero": quarantine.locked_amount_micronero,
        "opened_height": quarantine.opened_height,
        "release_height": quarantine.release_height,
        "status": quarantine.status.as_str(),
        "quarantine_root": quarantine.quarantine_root,
        "redacted_fields": ["claimant_identity", "private_evidence_blob"],
    })
}

fn redact_budget(budget: &RedactionBudget) -> Value {
    json!({
        "kind": "redaction_budget",
        "sequence": budget.sequence,
        "budget_id": budget.budget_id,
        "policy_id": budget.policy_id,
        "steward_id": budget.steward_id,
        "allowed_fields": budget.allowed_fields,
        "consumed_fields": budget.consumed_fields,
        "redaction_root": budget.redaction_root,
        "disclosure_log_root": budget.disclosure_log_root,
        "public_summary_root": budget.public_summary_root,
        "exhausted": budget.exhausted,
        "budget_root": budget.budget_root,
    })
}

fn redact_public_record(record: &Value) -> Value {
    json!({
        "kind": "deterministic_public_record",
        "protocol_version": PROTOCOL_VERSION,
        "record_root": domain_hash(PUBLIC_RECORD_SCHEME, &[HashPart::Json(record)], 32),
        "record": record,
    })
}
