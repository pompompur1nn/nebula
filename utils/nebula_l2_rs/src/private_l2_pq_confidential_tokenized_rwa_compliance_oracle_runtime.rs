use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedRwaComplianceOracleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-rwa-compliance-oracle-runtime-v1";
pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_RWA_COMPLIANCE_ORACLE_RUNTIME_PROTOCOL_VERSION:
    &str = PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ATTESTATION_SUITE: &str = "ML-DSA-87+ML-KEM-1024+SLH-DSA-SHAKE-256f-rwa-compliance";
pub const PRIVACY_PROOF_SUITE: &str =
    "redacted-jurisdiction-nullifier-set-membership-confidential-rwa-v1";
pub const ORACLE_COMMITTEE_SUITE: &str = "threshold-pq-issuer-oracle-committee-root-v1";
pub const TOKEN_GATE_SUITE: &str = "confidential-token-transfer-gate-policy-root-v1";
pub const LOW_FEE_BATCH_SUITE: &str = "recursive-low-fee-rwa-compliance-settlement-batch-v1";
pub const DEFAULT_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEFAULT_SETTLEMENT_ASSET_ID: &str = "asset:confidential-rwa-usdc-note";
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_PRIVACY_SET_SIZE: u64 = 262_144;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_STRONG_ORACLE_QUORUM_BPS: u64 = 8_400;
pub const DEFAULT_MAX_TRANSFER_FEE_BPS: u64 = 20;
pub const DEFAULT_TARGET_REBATE_BPS: u64 = 7;
pub const DEFAULT_MAX_PUBLIC_REDACTION_BYTES: u64 = 2_048;
pub const DEFAULT_ATTESTATION_TTL_SLOTS: u64 = 720;
pub const DEFAULT_BATCH_WINDOW_SLOTS: u64 = 32;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 512;
pub const DEFAULT_MIN_ISSUER_BOND_MICRO_UNITS: u64 = 50_000_000;
pub const DEFAULT_MIN_ASSET_NAV_MICRO_UNITS: u64 = 1_000_000;
pub const MAX_BPS: u64 = 10_000;
pub const MAX_ASSETS: usize = 1_048_576;
pub const MAX_ATTESTATIONS: usize = 4_194_304;
pub const MAX_JURISDICTION_PROOFS: usize = 4_194_304;
pub const MAX_COMMITTEES: usize = 524_288;
pub const MAX_TRANSFER_GATES: usize = 4_194_304;
pub const MAX_BATCHES: usize = 2_097_152;
pub const MAX_REBATES: usize = 2_097_152;
pub const MAX_OPERATOR_SUMMARIES: usize = 524_288;
pub const DEVNET_EPOCH: u64 = 8_144;
pub const DEVNET_SLOT: u64 = 91;
pub const DEVNET_L2_HEIGHT: u64 = 3_184_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RwaAssetClass {
    TreasuryBill,
    MoneyMarketFund,
    PrivateCredit,
    RealEstateDebt,
    CommodityReceipt,
    CarbonCredit,
    InvoiceReceivable,
    FundShare,
}

impl RwaAssetClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TreasuryBill => "treasury_bill",
            Self::MoneyMarketFund => "money_market_fund",
            Self::PrivateCredit => "private_credit",
            Self::RealEstateDebt => "real_estate_debt",
            Self::CommodityReceipt => "commodity_receipt",
            Self::CarbonCredit => "carbon_credit",
            Self::InvoiceReceivable => "invoice_receivable",
            Self::FundShare => "fund_share",
        }
    }

    pub fn baseline_risk_weight_bps(self) -> u64 {
        match self {
            Self::TreasuryBill => 500,
            Self::MoneyMarketFund => 800,
            Self::CommodityReceipt => 1_100,
            Self::InvoiceReceivable => 1_600,
            Self::FundShare => 2_000,
            Self::RealEstateDebt => 2_400,
            Self::PrivateCredit => 3_200,
            Self::CarbonCredit => 4_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStatus {
    Draft,
    Active,
    TransferOnly,
    RedemptionOnly,
    AttestationRefresh,
    Paused,
    Frozen,
    Retired,
}

impl AssetStatus {
    pub fn accepts_transfers(self) -> bool {
        matches!(self, Self::Active | Self::TransferOnly)
    }

    pub fn accepts_settlement(self) -> bool {
        matches!(
            self,
            Self::Active | Self::TransferOnly | Self::RedemptionOnly
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceProgram {
    AccreditedInvestor,
    QualifiedPurchaser,
    KycAmlScreened,
    SanctionsClean,
    TravelRuleExempt,
    MiCaEligible,
    RegS,
    RegD,
}

impl ComplianceProgram {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccreditedInvestor => "accredited_investor",
            Self::QualifiedPurchaser => "qualified_purchaser",
            Self::KycAmlScreened => "kyc_aml_screened",
            Self::SanctionsClean => "sanctions_clean",
            Self::TravelRuleExempt => "travel_rule_exempt",
            Self::MiCaEligible => "mica_eligible",
            Self::RegS => "reg_s",
            Self::RegD => "reg_d",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    IssuerStanding,
    AssetReserve,
    NavUpdate,
    CompliancePolicy,
    SanctionsScreen,
    InvestorEligibility,
    JurisdictionAllowList,
    TransferAuthorization,
    SettlementFinality,
}

impl AttestationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerStanding => "issuer_standing",
            Self::AssetReserve => "asset_reserve",
            Self::NavUpdate => "nav_update",
            Self::CompliancePolicy => "compliance_policy",
            Self::SanctionsScreen => "sanctions_screen",
            Self::InvestorEligibility => "investor_eligibility",
            Self::JurisdictionAllowList => "jurisdiction_allow_list",
            Self::TransferAuthorization => "transfer_authorization",
            Self::SettlementFinality => "settlement_finality",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Submitted,
    QuorumReached,
    Accepted,
    Expired,
    Challenged,
    Revoked,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JurisdictionProofStatus {
    Submitted,
    Verified,
    Expired,
    Rejected,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitteeStatus {
    Candidate,
    Active,
    Rotating,
    Degraded,
    Slashed,
    Retired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferGateDecision {
    Allow,
    AllowWithRebate,
    QueueForBatch,
    RequireFreshProof,
    Deny,
    Quarantine,
}

impl TransferGateDecision {
    pub fn is_positive(self) -> bool {
        matches!(
            self,
            Self::Allow | Self::AllowWithRebate | Self::QueueForBatch
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementBatchStatus {
    Open,
    Sealed,
    OracleAttested,
    Settled,
    Rebated,
    Disputed,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateReason {
    BatchCompression,
    ProofReuse,
    OracleNetting,
    PrivacySetContribution,
    FeeSponsorCredit,
    SettlementSurplus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub privacy_proof_suite: String,
    pub oracle_committee_suite: String,
    pub token_gate_suite: String,
    pub low_fee_batch_suite: String,
    pub fee_asset_id: String,
    pub settlement_asset_id: String,
    pub min_privacy_set_size: u64,
    pub target_privacy_set_size: u64,
    pub min_pq_security_bits: u16,
    pub oracle_quorum_bps: u64,
    pub strong_oracle_quorum_bps: u64,
    pub max_transfer_fee_bps: u64,
    pub target_rebate_bps: u64,
    pub max_public_redaction_bytes: u64,
    pub attestation_ttl_slots: u64,
    pub batch_window_slots: u64,
    pub max_batch_items: usize,
    pub min_issuer_bond_micro_units: u64,
    pub min_asset_nav_micro_units: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_ATTESTATION_SUITE.to_string(),
            privacy_proof_suite: PRIVACY_PROOF_SUITE.to_string(),
            oracle_committee_suite: ORACLE_COMMITTEE_SUITE.to_string(),
            token_gate_suite: TOKEN_GATE_SUITE.to_string(),
            low_fee_batch_suite: LOW_FEE_BATCH_SUITE.to_string(),
            fee_asset_id: DEFAULT_FEE_ASSET_ID.to_string(),
            settlement_asset_id: DEFAULT_SETTLEMENT_ASSET_ID.to_string(),
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            max_transfer_fee_bps: DEFAULT_MAX_TRANSFER_FEE_BPS,
            target_rebate_bps: DEFAULT_TARGET_REBATE_BPS,
            max_public_redaction_bytes: DEFAULT_MAX_PUBLIC_REDACTION_BYTES,
            attestation_ttl_slots: DEFAULT_ATTESTATION_TTL_SLOTS,
            batch_window_slots: DEFAULT_BATCH_WINDOW_SLOTS,
            max_batch_items: DEFAULT_MAX_BATCH_ITEMS,
            min_issuer_bond_micro_units: DEFAULT_MIN_ISSUER_BOND_MICRO_UNITS,
            min_asset_nav_micro_units: DEFAULT_MIN_ASSET_NAV_MICRO_UNITS,
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure_non_empty(&self.protocol_version, "protocol_version")?;
        ensure_non_empty(&self.chain_id, "chain_id")?;
        ensure_non_empty(&self.hash_suite, "hash_suite")?;
        ensure_non_empty(&self.pq_attestation_suite, "pq_attestation_suite")?;
        ensure_non_empty(&self.privacy_proof_suite, "privacy_proof_suite")?;
        ensure_bps(self.oracle_quorum_bps, "oracle_quorum_bps")?;
        ensure_bps(self.strong_oracle_quorum_bps, "strong_oracle_quorum_bps")?;
        ensure_bps(self.max_transfer_fee_bps, "max_transfer_fee_bps")?;
        ensure_bps(self.target_rebate_bps, "target_rebate_bps")?;
        if self.strong_oracle_quorum_bps < self.oracle_quorum_bps {
            return Err("strong oracle quorum must be >= regular quorum".to_string());
        }
        if self.target_privacy_set_size < self.min_privacy_set_size {
            return Err("target privacy set must be >= minimum privacy set".to_string());
        }
        if self.min_pq_security_bits < 192 {
            return Err("minimum pq security bits below runtime floor".to_string());
        }
        if self.max_batch_items == 0 {
            return Err("max_batch_items must be non-zero".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub assets: u64,
    pub attestations: u64,
    pub jurisdiction_proofs: u64,
    pub committees: u64,
    pub transfer_gates: u64,
    pub settlement_batches: u64,
    pub fee_rebates: u64,
    pub operator_summaries: u64,
    pub active_assets: u64,
    pub accepted_attestations: u64,
    pub verified_jurisdiction_proofs: u64,
    pub allowed_transfers: u64,
    pub denied_transfers: u64,
    pub quarantined_transfers: u64,
    pub settled_batches: u64,
    pub rebated_batches: u64,
    pub total_nav_micro_units: u64,
    pub gated_notional_micro_units: u64,
    pub settled_notional_micro_units: u64,
    pub rebated_fee_micro_units: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub asset_root: String,
    pub attestation_root: String,
    pub jurisdiction_proof_root: String,
    pub committee_root: String,
    pub transfer_gate_root: String,
    pub settlement_batch_root: String,
    pub fee_rebate_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        Self {
            asset_root: empty_root("assets"),
            attestation_root: empty_root("attestations"),
            jurisdiction_proof_root: empty_root("jurisdiction-proofs"),
            committee_root: empty_root("committees"),
            transfer_gate_root: empty_root("transfer-gates"),
            settlement_batch_root: empty_root("settlement-batches"),
            fee_rebate_root: empty_root("fee-rebates"),
            operator_summary_root: empty_root("operator-summaries"),
            state_root: empty_root("state"),
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RwaAssetEnvelope {
    pub asset_id: String,
    pub issuer_id: String,
    pub asset_class: RwaAssetClass,
    pub status: AssetStatus,
    pub sealed_terms_root: String,
    pub public_metadata_root: String,
    pub reserve_commitment_root: String,
    pub nav_micro_units: u64,
    pub outstanding_token_units: u64,
    pub maturity_slot: u64,
    pub compliance_programs: BTreeSet<ComplianceProgram>,
    pub allowed_jurisdiction_root: String,
    pub denied_jurisdiction_root: String,
    pub privacy_set_size: u64,
    pub created_slot: u64,
    pub updated_slot: u64,
}

impl RwaAssetEnvelope {
    pub fn is_live(&self) -> bool {
        matches!(
            self.status,
            AssetStatus::Active | AssetStatus::TransferOnly | AssetStatus::RedemptionOnly
        )
    }

    pub fn nav_per_token_micro_units(&self) -> u64 {
        if self.outstanding_token_units == 0 {
            0
        } else {
            self.nav_micro_units / self.outstanding_token_units
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "asset_id": self.asset_id,
            "issuer_id": self.issuer_id,
            "asset_class": self.asset_class,
            "status": self.status,
            "public_metadata_root": self.public_metadata_root,
            "reserve_commitment_root": self.reserve_commitment_root,
            "nav_micro_units": self.nav_micro_units,
            "outstanding_token_units": self.outstanding_token_units,
            "maturity_slot": self.maturity_slot,
            "compliance_programs": self.compliance_programs,
            "allowed_jurisdiction_root": self.allowed_jurisdiction_root,
            "denied_jurisdiction_root": self.denied_jurisdiction_root,
            "privacy_set_size": self.privacy_set_size,
            "created_slot": self.created_slot,
            "updated_slot": self.updated_slot,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ComplianceAttestation {
    pub attestation_id: String,
    pub asset_id: String,
    pub committee_id: String,
    pub kind: AttestationKind,
    pub status: AttestationStatus,
    pub statement_root: String,
    pub redacted_statement_root: String,
    pub pq_signature_root: String,
    pub oracle_bitmap_root: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_slot: u64,
    pub expires_slot: u64,
}

impl ComplianceAttestation {
    pub fn is_usable_at(&self, slot: u64) -> bool {
        matches!(
            self.status,
            AttestationStatus::QuorumReached | AttestationStatus::Accepted
        ) && slot <= self.expires_slot
    }

    pub fn is_strong(&self, config: &Config) -> bool {
        self.quorum_weight_bps >= config.strong_oracle_quorum_bps
            && self.pq_security_bits >= config.min_pq_security_bits
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactedJurisdictionProof {
    pub proof_id: String,
    pub asset_id: String,
    pub account_commitment: String,
    pub jurisdiction_set_root: String,
    pub redacted_region_root: String,
    pub nullifier_root: String,
    pub selective_disclosure_root: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub status: JurisdictionProofStatus,
    pub verified_slot: u64,
    pub expires_slot: u64,
}

impl RedactedJurisdictionProof {
    pub fn preserves_privacy(&self, config: &Config) -> bool {
        self.privacy_set_size >= config.min_privacy_set_size
            && self.actual_public_bytes <= self.max_public_bytes
            && self.max_public_bytes <= config.max_public_redaction_bytes
            && !self.redacted_fields.is_empty()
    }

    pub fn is_valid_at(&self, slot: u64) -> bool {
        self.status == JurisdictionProofStatus::Verified && slot <= self.expires_slot
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssuerOracleCommittee {
    pub committee_id: String,
    pub issuer_id: String,
    pub status: CommitteeStatus,
    pub member_set_root: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_root: String,
    pub min_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub active_members: u64,
    pub slashed_members: u64,
    pub bond_micro_units: u64,
    pub rotation_slot: u64,
}

impl IssuerOracleCommittee {
    pub fn has_quorum_for(&self, weight_bps: u64) -> bool {
        self.status == CommitteeStatus::Active && weight_bps >= self.min_quorum_bps
    }

    pub fn has_strong_quorum_for(&self, weight_bps: u64) -> bool {
        self.status == CommitteeStatus::Active && weight_bps >= self.strong_quorum_bps
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TokenTransferGate {
    pub gate_id: String,
    pub asset_id: String,
    pub from_account_commitment: String,
    pub to_account_commitment: String,
    pub jurisdiction_proof_id: String,
    pub attestation_id: String,
    pub amount_token_units: u64,
    pub notional_micro_units: u64,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub decision: TransferGateDecision,
    pub reason_root: String,
    pub opened_slot: u64,
    pub expires_slot: u64,
}

impl TokenTransferGate {
    pub fn is_allowed(&self) -> bool {
        self.decision.is_positive()
    }

    pub fn fee_micro_units(&self) -> u64 {
        mul_bps(self.notional_micro_units, self.fee_bps)
    }

    pub fn rebate_micro_units(&self) -> u64 {
        mul_bps(self.fee_micro_units(), self.rebate_bps)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementBatch {
    pub batch_id: String,
    pub asset_id: String,
    pub gate_ids: Vec<String>,
    pub status: SettlementBatchStatus,
    pub sealed_batch_root: String,
    pub recursive_proof_root: String,
    pub oracle_attestation_root: String,
    pub aggregate_notional_micro_units: u64,
    pub aggregate_fee_micro_units: u64,
    pub aggregate_rebate_micro_units: u64,
    pub opened_slot: u64,
    pub sealed_slot: u64,
    pub settled_slot: u64,
}

impl SettlementBatch {
    pub fn item_count(&self) -> usize {
        self.gate_ids.len()
    }

    pub fn compression_ratio_bps(&self) -> u64 {
        if self.gate_ids.is_empty() {
            0
        } else {
            (MAX_BPS / self.gate_ids.len() as u64).max(1)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeRebate {
    pub rebate_id: String,
    pub batch_id: String,
    pub gate_id: String,
    pub reason: RebateReason,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub assets: u64,
    pub active_assets: u64,
    pub committees: u64,
    pub accepted_attestations: u64,
    pub verified_jurisdiction_proofs: u64,
    pub allowed_transfers: u64,
    pub denied_transfers: u64,
    pub settled_batches: u64,
    pub total_nav_micro_units: u64,
    pub gated_notional_micro_units: u64,
    pub settled_notional_micro_units: u64,
    pub rebated_fee_micro_units: u64,
    pub median_fee_bps: u64,
    pub oracle_quorum_bps: u64,
    pub state_root: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterAssetRequest {
    pub issuer_id: String,
    pub asset_class: RwaAssetClass,
    pub sealed_terms_root: String,
    pub public_metadata_root: String,
    pub reserve_commitment_root: String,
    pub nav_micro_units: u64,
    pub outstanding_token_units: u64,
    pub maturity_slot: u64,
    pub compliance_programs: BTreeSet<ComplianceProgram>,
    pub allowed_jurisdiction_root: String,
    pub denied_jurisdiction_root: String,
    pub privacy_set_size: u64,
    pub created_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RegisterCommitteeRequest {
    pub issuer_id: String,
    pub member_set_root: String,
    pub pq_verifying_key_root: String,
    pub stake_bond_root: String,
    pub min_quorum_bps: u64,
    pub strong_quorum_bps: u64,
    pub active_members: u64,
    pub bond_micro_units: u64,
    pub rotation_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RecordAttestationRequest {
    pub asset_id: String,
    pub committee_id: String,
    pub kind: AttestationKind,
    pub statement_root: String,
    pub redacted_statement_root: String,
    pub pq_signature_root: String,
    pub oracle_bitmap_root: String,
    pub quorum_weight_bps: u64,
    pub pq_security_bits: u16,
    pub observed_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubmitJurisdictionProofRequest {
    pub asset_id: String,
    pub account_commitment: String,
    pub jurisdiction_set_root: String,
    pub redacted_region_root: String,
    pub nullifier_root: String,
    pub selective_disclosure_root: String,
    pub public_fields: BTreeSet<String>,
    pub redacted_fields: BTreeSet<String>,
    pub max_public_bytes: u64,
    pub actual_public_bytes: u64,
    pub privacy_set_size: u64,
    pub verified_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenTransferGateRequest {
    pub asset_id: String,
    pub from_account_commitment: String,
    pub to_account_commitment: String,
    pub jurisdiction_proof_id: String,
    pub attestation_id: String,
    pub amount_token_units: u64,
    pub notional_micro_units: u64,
    pub fee_bps: u64,
    pub rebate_bps: u64,
    pub reason_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OpenSettlementBatchRequest {
    pub asset_id: String,
    pub gate_ids: Vec<String>,
    pub sealed_batch_root: String,
    pub recursive_proof_root: String,
    pub oracle_attestation_root: String,
    pub opened_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettleBatchRequest {
    pub batch_id: String,
    pub settled_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IssueRebateRequest {
    pub batch_id: String,
    pub gate_id: String,
    pub reason: RebateReason,
    pub beneficiary_commitment: String,
    pub asset_id: String,
    pub amount_micro_units: u64,
    pub rebate_bps: u64,
    pub issued_slot: u64,
    pub expires_slot: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummaryRequest {
    pub median_fee_bps: u64,
    pub oracle_quorum_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub assets: BTreeMap<String, RwaAssetEnvelope>,
    pub attestations: BTreeMap<String, ComplianceAttestation>,
    pub jurisdiction_proofs: BTreeMap<String, RedactedJurisdictionProof>,
    pub committees: BTreeMap<String, IssuerOracleCommittee>,
    pub transfer_gates: BTreeMap<String, TokenTransferGate>,
    pub settlement_batches: BTreeMap<String, SettlementBatch>,
    pub fee_rebates: BTreeMap<String, FeeRebate>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::default()).expect("default tokenized rwa compliance oracle config")
    }
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            counters: Counters::default(),
            roots: Roots::default(),
            assets: BTreeMap::new(),
            attestations: BTreeMap::new(),
            jurisdiction_proofs: BTreeMap::new(),
            committees: BTreeMap::new(),
            transfer_gates: BTreeMap::new(),
            settlement_batches: BTreeMap::new(),
            fee_rebates: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
        })
    }

    pub fn register_asset(&mut self, request: RegisterAssetRequest) -> Result<RwaAssetEnvelope> {
        ensure_capacity(self.assets.len(), MAX_ASSETS, "assets")?;
        ensure_non_empty(&request.issuer_id, "issuer_id")?;
        ensure_non_empty(&request.sealed_terms_root, "sealed_terms_root")?;
        ensure_non_empty(&request.public_metadata_root, "public_metadata_root")?;
        ensure_non_empty(&request.reserve_commitment_root, "reserve_commitment_root")?;
        ensure_non_empty(
            &request.allowed_jurisdiction_root,
            "allowed_jurisdiction_root",
        )?;
        ensure_non_empty(
            &request.denied_jurisdiction_root,
            "denied_jurisdiction_root",
        )?;
        if request.nav_micro_units < self.config.min_asset_nav_micro_units {
            return Err("asset nav below configured minimum".to_string());
        }
        if request.outstanding_token_units == 0 {
            return Err("asset outstanding token units must be non-zero".to_string());
        }
        if request.compliance_programs.is_empty() {
            return Err("asset requires at least one compliance program".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("asset privacy set below configured minimum".to_string());
        }
        let asset_id = stable_id(
            "asset",
            &[
                HashPart::Str(&request.issuer_id),
                HashPart::Str(request.asset_class.as_str()),
                HashPart::Str(&request.public_metadata_root),
                HashPart::U64(request.created_slot),
            ],
        );
        let asset = RwaAssetEnvelope {
            asset_id: asset_id.clone(),
            issuer_id: request.issuer_id,
            asset_class: request.asset_class,
            status: AssetStatus::Active,
            sealed_terms_root: request.sealed_terms_root,
            public_metadata_root: request.public_metadata_root,
            reserve_commitment_root: request.reserve_commitment_root,
            nav_micro_units: request.nav_micro_units,
            outstanding_token_units: request.outstanding_token_units,
            maturity_slot: request.maturity_slot,
            compliance_programs: request.compliance_programs,
            allowed_jurisdiction_root: request.allowed_jurisdiction_root,
            denied_jurisdiction_root: request.denied_jurisdiction_root,
            privacy_set_size: request.privacy_set_size,
            created_slot: request.created_slot,
            updated_slot: request.created_slot,
        };
        self.assets.insert(asset_id, asset.clone());
        self.refresh_roots();
        Ok(asset)
    }

    pub fn register_committee(
        &mut self,
        request: RegisterCommitteeRequest,
    ) -> Result<IssuerOracleCommittee> {
        ensure_capacity(self.committees.len(), MAX_COMMITTEES, "committees")?;
        ensure_non_empty(&request.issuer_id, "issuer_id")?;
        ensure_non_empty(&request.member_set_root, "member_set_root")?;
        ensure_non_empty(&request.pq_verifying_key_root, "pq_verifying_key_root")?;
        ensure_non_empty(&request.stake_bond_root, "stake_bond_root")?;
        ensure_bps(request.min_quorum_bps, "min_quorum_bps")?;
        ensure_bps(request.strong_quorum_bps, "strong_quorum_bps")?;
        if request.strong_quorum_bps < request.min_quorum_bps {
            return Err("committee strong quorum below regular quorum".to_string());
        }
        if request.min_quorum_bps < self.config.oracle_quorum_bps {
            return Err("committee quorum below runtime minimum".to_string());
        }
        if request.active_members == 0 {
            return Err("committee requires active members".to_string());
        }
        if request.bond_micro_units < self.config.min_issuer_bond_micro_units {
            return Err("committee bond below runtime minimum".to_string());
        }
        let committee_id = stable_id(
            "committee",
            &[
                HashPart::Str(&request.issuer_id),
                HashPart::Str(&request.member_set_root),
                HashPart::Str(&request.pq_verifying_key_root),
                HashPart::U64(request.rotation_slot),
            ],
        );
        let committee = IssuerOracleCommittee {
            committee_id: committee_id.clone(),
            issuer_id: request.issuer_id,
            status: CommitteeStatus::Active,
            member_set_root: request.member_set_root,
            pq_verifying_key_root: request.pq_verifying_key_root,
            stake_bond_root: request.stake_bond_root,
            min_quorum_bps: request.min_quorum_bps,
            strong_quorum_bps: request.strong_quorum_bps,
            active_members: request.active_members,
            slashed_members: 0,
            bond_micro_units: request.bond_micro_units,
            rotation_slot: request.rotation_slot,
        };
        self.committees.insert(committee_id, committee.clone());
        self.refresh_roots();
        Ok(committee)
    }

    pub fn record_attestation(
        &mut self,
        request: RecordAttestationRequest,
    ) -> Result<ComplianceAttestation> {
        ensure_capacity(self.attestations.len(), MAX_ATTESTATIONS, "attestations")?;
        ensure_non_empty(&request.statement_root, "statement_root")?;
        ensure_non_empty(&request.redacted_statement_root, "redacted_statement_root")?;
        ensure_non_empty(&request.pq_signature_root, "pq_signature_root")?;
        ensure_non_empty(&request.oracle_bitmap_root, "oracle_bitmap_root")?;
        ensure_bps(request.quorum_weight_bps, "quorum_weight_bps")?;
        let asset = self
            .assets
            .get(&request.asset_id)
            .ok_or_else(|| "asset not found".to_string())?;
        if !asset.is_live() {
            return Err("asset is not live for attestations".to_string());
        }
        let committee = self
            .committees
            .get(&request.committee_id)
            .ok_or_else(|| "committee not found".to_string())?;
        if committee.issuer_id != asset.issuer_id {
            return Err("committee issuer does not match asset issuer".to_string());
        }
        if !committee.has_quorum_for(request.quorum_weight_bps) {
            return Err("attestation quorum below committee threshold".to_string());
        }
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("attestation pq security below runtime minimum".to_string());
        }
        let attestation_id = stable_id(
            "attestation",
            &[
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.committee_id),
                HashPart::Str(request.kind.as_str()),
                HashPart::Str(&request.redacted_statement_root),
                HashPart::U64(request.observed_slot),
            ],
        );
        let status = if committee.has_strong_quorum_for(request.quorum_weight_bps) {
            AttestationStatus::Accepted
        } else {
            AttestationStatus::QuorumReached
        };
        let attestation = ComplianceAttestation {
            attestation_id: attestation_id.clone(),
            asset_id: request.asset_id,
            committee_id: request.committee_id,
            kind: request.kind,
            status,
            statement_root: request.statement_root,
            redacted_statement_root: request.redacted_statement_root,
            pq_signature_root: request.pq_signature_root,
            oracle_bitmap_root: request.oracle_bitmap_root,
            quorum_weight_bps: request.quorum_weight_bps,
            pq_security_bits: request.pq_security_bits,
            observed_slot: request.observed_slot,
            expires_slot: request.observed_slot + self.config.attestation_ttl_slots,
        };
        self.attestations
            .insert(attestation_id, attestation.clone());
        self.refresh_roots();
        Ok(attestation)
    }

    pub fn submit_jurisdiction_proof(
        &mut self,
        request: SubmitJurisdictionProofRequest,
    ) -> Result<RedactedJurisdictionProof> {
        ensure_capacity(
            self.jurisdiction_proofs.len(),
            MAX_JURISDICTION_PROOFS,
            "jurisdiction_proofs",
        )?;
        self.ensure_asset_exists(&request.asset_id)?;
        ensure_non_empty(&request.account_commitment, "account_commitment")?;
        ensure_non_empty(&request.jurisdiction_set_root, "jurisdiction_set_root")?;
        ensure_non_empty(&request.redacted_region_root, "redacted_region_root")?;
        ensure_non_empty(&request.nullifier_root, "nullifier_root")?;
        ensure_non_empty(
            &request.selective_disclosure_root,
            "selective_disclosure_root",
        )?;
        if request.public_fields.is_empty() {
            return Err("jurisdiction proof requires public fields".to_string());
        }
        if request.redacted_fields.is_empty() {
            return Err("jurisdiction proof requires redacted fields".to_string());
        }
        if request.actual_public_bytes > request.max_public_bytes {
            return Err("actual public bytes exceed max public bytes".to_string());
        }
        if request.max_public_bytes > self.config.max_public_redaction_bytes {
            return Err("jurisdiction proof exceeds public redaction byte cap".to_string());
        }
        if request.privacy_set_size < self.config.min_privacy_set_size {
            return Err("jurisdiction proof privacy set below runtime minimum".to_string());
        }
        let proof_id = stable_id(
            "jurisdiction-proof",
            &[
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.account_commitment),
                HashPart::Str(&request.nullifier_root),
                HashPart::U64(request.verified_slot),
            ],
        );
        let proof = RedactedJurisdictionProof {
            proof_id: proof_id.clone(),
            asset_id: request.asset_id,
            account_commitment: request.account_commitment,
            jurisdiction_set_root: request.jurisdiction_set_root,
            redacted_region_root: request.redacted_region_root,
            nullifier_root: request.nullifier_root,
            selective_disclosure_root: request.selective_disclosure_root,
            public_fields: request.public_fields,
            redacted_fields: request.redacted_fields,
            max_public_bytes: request.max_public_bytes,
            actual_public_bytes: request.actual_public_bytes,
            privacy_set_size: request.privacy_set_size,
            status: JurisdictionProofStatus::Verified,
            verified_slot: request.verified_slot,
            expires_slot: request.verified_slot + self.config.attestation_ttl_slots,
        };
        self.jurisdiction_proofs.insert(proof_id, proof.clone());
        self.refresh_roots();
        Ok(proof)
    }

    pub fn open_transfer_gate(
        &mut self,
        request: OpenTransferGateRequest,
    ) -> Result<TokenTransferGate> {
        ensure_capacity(
            self.transfer_gates.len(),
            MAX_TRANSFER_GATES,
            "transfer_gates",
        )?;
        ensure_non_empty(&request.from_account_commitment, "from_account_commitment")?;
        ensure_non_empty(&request.to_account_commitment, "to_account_commitment")?;
        ensure_non_empty(&request.reason_root, "reason_root")?;
        ensure_bps(request.fee_bps, "fee_bps")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.fee_bps > self.config.max_transfer_fee_bps {
            return Err("transfer fee exceeds runtime cap".to_string());
        }
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("transfer rebate exceeds runtime target".to_string());
        }
        let asset = self
            .assets
            .get(&request.asset_id)
            .ok_or_else(|| "asset not found".to_string())?;
        if !asset.status.accepts_transfers() {
            return Err("asset does not accept transfers".to_string());
        }
        if request.amount_token_units == 0 || request.notional_micro_units == 0 {
            return Err("transfer amount and notional must be non-zero".to_string());
        }
        let proof = self
            .jurisdiction_proofs
            .get(&request.jurisdiction_proof_id)
            .ok_or_else(|| "jurisdiction proof not found".to_string())?;
        if proof.asset_id != request.asset_id {
            return Err("jurisdiction proof asset mismatch".to_string());
        }
        let attestation = self
            .attestations
            .get(&request.attestation_id)
            .ok_or_else(|| "attestation not found".to_string())?;
        if attestation.asset_id != request.asset_id {
            return Err("attestation asset mismatch".to_string());
        }
        let decision = if !proof.is_valid_at(request.opened_slot) {
            TransferGateDecision::RequireFreshProof
        } else if !attestation.is_usable_at(request.opened_slot) {
            TransferGateDecision::RequireFreshProof
        } else if request.fee_bps == 0 || request.rebate_bps > 0 {
            TransferGateDecision::AllowWithRebate
        } else {
            TransferGateDecision::QueueForBatch
        };
        let gate_id = stable_id(
            "transfer-gate",
            &[
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.from_account_commitment),
                HashPart::Str(&request.to_account_commitment),
                HashPart::Str(&request.jurisdiction_proof_id),
                HashPart::U64(request.opened_slot),
            ],
        );
        let gate = TokenTransferGate {
            gate_id: gate_id.clone(),
            asset_id: request.asset_id,
            from_account_commitment: request.from_account_commitment,
            to_account_commitment: request.to_account_commitment,
            jurisdiction_proof_id: request.jurisdiction_proof_id,
            attestation_id: request.attestation_id,
            amount_token_units: request.amount_token_units,
            notional_micro_units: request.notional_micro_units,
            fee_bps: request.fee_bps,
            rebate_bps: request.rebate_bps,
            decision,
            reason_root: request.reason_root,
            opened_slot: request.opened_slot,
            expires_slot: request.opened_slot + self.config.batch_window_slots,
        };
        if gate.is_allowed() {
            self.counters.allowed_transfers = self.counters.allowed_transfers.saturating_add(1);
            self.counters.gated_notional_micro_units = self
                .counters
                .gated_notional_micro_units
                .saturating_add(gate.notional_micro_units);
        } else if gate.decision == TransferGateDecision::Quarantine {
            self.counters.quarantined_transfers =
                self.counters.quarantined_transfers.saturating_add(1);
        } else {
            self.counters.denied_transfers = self.counters.denied_transfers.saturating_add(1);
        }
        self.transfer_gates.insert(gate_id, gate.clone());
        self.refresh_roots();
        Ok(gate)
    }

    pub fn open_settlement_batch(
        &mut self,
        request: OpenSettlementBatchRequest,
    ) -> Result<SettlementBatch> {
        ensure_capacity(
            self.settlement_batches.len(),
            MAX_BATCHES,
            "settlement_batches",
        )?;
        self.ensure_asset_exists(&request.asset_id)?;
        ensure_non_empty(&request.sealed_batch_root, "sealed_batch_root")?;
        ensure_non_empty(&request.recursive_proof_root, "recursive_proof_root")?;
        ensure_non_empty(&request.oracle_attestation_root, "oracle_attestation_root")?;
        if request.gate_ids.is_empty() {
            return Err("settlement batch requires at least one transfer gate".to_string());
        }
        if request.gate_ids.len() > self.config.max_batch_items {
            return Err("settlement batch exceeds configured item cap".to_string());
        }
        let mut aggregate_notional_micro_units = 0_u64;
        let mut aggregate_fee_micro_units = 0_u64;
        let mut aggregate_rebate_micro_units = 0_u64;
        let mut unique_gate_ids = BTreeSet::new();
        for gate_id in &request.gate_ids {
            if !unique_gate_ids.insert(gate_id.clone()) {
                return Err("settlement batch contains duplicate gate".to_string());
            }
            let gate = self
                .transfer_gates
                .get(gate_id)
                .ok_or_else(|| format!("transfer gate not found: {gate_id}"))?;
            if gate.asset_id != request.asset_id {
                return Err("settlement batch gate asset mismatch".to_string());
            }
            if !gate.is_allowed() {
                return Err("settlement batch includes non-allowed gate".to_string());
            }
            aggregate_notional_micro_units =
                aggregate_notional_micro_units.saturating_add(gate.notional_micro_units);
            aggregate_fee_micro_units =
                aggregate_fee_micro_units.saturating_add(gate.fee_micro_units());
            aggregate_rebate_micro_units =
                aggregate_rebate_micro_units.saturating_add(gate.rebate_micro_units());
        }
        let batch_id = stable_id(
            "settlement-batch",
            &[
                HashPart::Str(&request.asset_id),
                HashPart::Str(&request.sealed_batch_root),
                HashPart::U64(request.opened_slot),
                HashPart::U64(request.gate_ids.len() as u64),
            ],
        );
        let batch = SettlementBatch {
            batch_id: batch_id.clone(),
            asset_id: request.asset_id,
            gate_ids: request.gate_ids,
            status: SettlementBatchStatus::OracleAttested,
            sealed_batch_root: request.sealed_batch_root,
            recursive_proof_root: request.recursive_proof_root,
            oracle_attestation_root: request.oracle_attestation_root,
            aggregate_notional_micro_units,
            aggregate_fee_micro_units,
            aggregate_rebate_micro_units,
            opened_slot: request.opened_slot,
            sealed_slot: request.opened_slot,
            settled_slot: 0,
        };
        self.settlement_batches.insert(batch_id, batch.clone());
        self.refresh_roots();
        Ok(batch)
    }

    pub fn settle_batch(&mut self, request: SettleBatchRequest) -> Result<SettlementBatch> {
        let batch = self
            .settlement_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "settlement batch not found".to_string())?;
        if batch.status != SettlementBatchStatus::OracleAttested {
            return Err("settlement batch is not oracle attested".to_string());
        }
        batch.status = SettlementBatchStatus::Settled;
        batch.settled_slot = request.settled_slot;
        let settled = batch.clone();
        self.counters.settled_batches = self.counters.settled_batches.saturating_add(1);
        self.counters.settled_notional_micro_units = self
            .counters
            .settled_notional_micro_units
            .saturating_add(settled.aggregate_notional_micro_units);
        self.refresh_roots();
        Ok(settled)
    }

    pub fn issue_rebate(&mut self, request: IssueRebateRequest) -> Result<FeeRebate> {
        ensure_capacity(self.fee_rebates.len(), MAX_REBATES, "fee_rebates")?;
        ensure_non_empty(&request.beneficiary_commitment, "beneficiary_commitment")?;
        ensure_bps(request.rebate_bps, "rebate_bps")?;
        if request.rebate_bps > self.config.target_rebate_bps {
            return Err("rebate exceeds runtime target".to_string());
        }
        let batch = self
            .settlement_batches
            .get_mut(&request.batch_id)
            .ok_or_else(|| "settlement batch not found".to_string())?;
        if batch.status != SettlementBatchStatus::Settled
            && batch.status != SettlementBatchStatus::Rebated
        {
            return Err("rebate requires a settled batch".to_string());
        }
        if !batch.gate_ids.contains(&request.gate_id) {
            return Err("rebate gate is not part of batch".to_string());
        }
        if request.asset_id != batch.asset_id {
            return Err("rebate asset mismatch".to_string());
        }
        let gate = self
            .transfer_gates
            .get(&request.gate_id)
            .ok_or_else(|| "transfer gate not found".to_string())?;
        let max_rebate = gate
            .rebate_micro_units()
            .max(mul_bps(gate.fee_micro_units(), request.rebate_bps));
        if request.amount_micro_units > max_rebate {
            return Err("rebate amount exceeds gate rebate allowance".to_string());
        }
        batch.status = SettlementBatchStatus::Rebated;
        let rebate_id = stable_id(
            "fee-rebate",
            &[
                HashPart::Str(&request.batch_id),
                HashPart::Str(&request.gate_id),
                HashPart::Str(&request.beneficiary_commitment),
                HashPart::U64(request.issued_slot),
            ],
        );
        let rebate = FeeRebate {
            rebate_id: rebate_id.clone(),
            batch_id: request.batch_id,
            gate_id: request.gate_id,
            reason: request.reason,
            beneficiary_commitment: request.beneficiary_commitment,
            asset_id: request.asset_id,
            amount_micro_units: request.amount_micro_units,
            rebate_bps: request.rebate_bps,
            issued_slot: request.issued_slot,
            expires_slot: request.expires_slot,
        };
        self.counters.rebated_batches = self.counters.rebated_batches.saturating_add(1);
        self.counters.rebated_fee_micro_units = self
            .counters
            .rebated_fee_micro_units
            .saturating_add(rebate.amount_micro_units);
        self.fee_rebates.insert(rebate_id, rebate.clone());
        self.refresh_roots();
        Ok(rebate)
    }

    pub fn publish_operator_summary(
        &mut self,
        request: OperatorSummaryRequest,
    ) -> Result<OperatorSummary> {
        ensure_capacity(
            self.operator_summaries.len(),
            MAX_OPERATOR_SUMMARIES,
            "operator_summaries",
        )?;
        ensure_bps(request.median_fee_bps, "median_fee_bps")?;
        ensure_bps(request.oracle_quorum_bps, "oracle_quorum_bps")?;
        let summary_id = stable_id(
            "operator-summary",
            &[HashPart::U64(self.operator_summaries.len() as u64)],
        );
        let summary = OperatorSummary {
            summary_id: summary_id.clone(),
            assets: self.counters.assets,
            active_assets: self.counters.active_assets,
            committees: self.counters.committees,
            accepted_attestations: self.counters.accepted_attestations,
            verified_jurisdiction_proofs: self.counters.verified_jurisdiction_proofs,
            allowed_transfers: self.counters.allowed_transfers,
            denied_transfers: self.counters.denied_transfers,
            settled_batches: self.counters.settled_batches,
            total_nav_micro_units: self.counters.total_nav_micro_units,
            gated_notional_micro_units: self.counters.gated_notional_micro_units,
            settled_notional_micro_units: self.counters.settled_notional_micro_units,
            rebated_fee_micro_units: self.counters.rebated_fee_micro_units,
            median_fee_bps: request.median_fee_bps,
            oracle_quorum_bps: request.oracle_quorum_bps,
            state_root: self.state_root(),
        };
        self.operator_summaries.insert(summary_id, summary.clone());
        self.refresh_roots();
        Ok(summary)
    }

    pub fn refresh_roots(&mut self) {
        self.counters.assets = self.assets.len() as u64;
        self.counters.attestations = self.attestations.len() as u64;
        self.counters.jurisdiction_proofs = self.jurisdiction_proofs.len() as u64;
        self.counters.committees = self.committees.len() as u64;
        self.counters.transfer_gates = self.transfer_gates.len() as u64;
        self.counters.settlement_batches = self.settlement_batches.len() as u64;
        self.counters.fee_rebates = self.fee_rebates.len() as u64;
        self.counters.operator_summaries = self.operator_summaries.len() as u64;
        self.counters.active_assets =
            self.assets.values().filter(|asset| asset.is_live()).count() as u64;
        self.counters.accepted_attestations = self
            .attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Accepted)
            .count() as u64;
        self.counters.verified_jurisdiction_proofs = self
            .jurisdiction_proofs
            .values()
            .filter(|proof| proof.status == JurisdictionProofStatus::Verified)
            .count() as u64;
        self.counters.total_nav_micro_units = self
            .assets
            .values()
            .map(|asset| asset.nav_micro_units)
            .sum();
        self.roots.asset_root = map_root("tokenized-rwa-compliance-oracle:assets", &self.assets);
        self.roots.attestation_root = map_root(
            "tokenized-rwa-compliance-oracle:attestations",
            &self.attestations,
        );
        self.roots.jurisdiction_proof_root = map_root(
            "tokenized-rwa-compliance-oracle:jurisdiction-proofs",
            &self.jurisdiction_proofs,
        );
        self.roots.committee_root = map_root(
            "tokenized-rwa-compliance-oracle:committees",
            &self.committees,
        );
        self.roots.transfer_gate_root = map_root(
            "tokenized-rwa-compliance-oracle:transfer-gates",
            &self.transfer_gates,
        );
        self.roots.settlement_batch_root = map_root(
            "tokenized-rwa-compliance-oracle:settlement-batches",
            &self.settlement_batches,
        );
        self.roots.fee_rebate_root = map_root(
            "tokenized-rwa-compliance-oracle:fee-rebates",
            &self.fee_rebates,
        );
        self.roots.operator_summary_root = map_root(
            "tokenized-rwa-compliance-oracle:operator-summaries",
            &self.operator_summaries,
        );
        self.roots.state_root = self.compute_state_root();
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "chain_id": self.config.chain_id,
            "hash_suite": self.config.hash_suite,
            "pq_attestation_suite": self.config.pq_attestation_suite,
            "privacy_proof_suite": self.config.privacy_proof_suite,
            "oracle_committee_suite": self.config.oracle_committee_suite,
            "token_gate_suite": self.config.token_gate_suite,
            "low_fee_batch_suite": self.config.low_fee_batch_suite,
            "epoch": DEVNET_EPOCH,
            "slot": DEVNET_SLOT,
            "l2_height": DEVNET_L2_HEIGHT,
            "config": self.config,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "assets": self.assets,
            "attestations": self.attestations,
            "jurisdiction_proofs": self.jurisdiction_proofs,
            "committees": self.committees,
            "transfer_gates": self.transfer_gates,
            "settlement_batches": self.settlement_batches,
            "fee_rebates": self.fee_rebates,
            "operator_summaries": self.operator_summaries,
        })
    }

    pub fn devnet() -> State {
        devnet()
    }

    fn compute_state_root(&self) -> String {
        let record = json!({
            "schema_version": SCHEMA_VERSION,
            "protocol_version": self.config.protocol_version,
            "asset_root": self.roots.asset_root,
            "attestation_root": self.roots.attestation_root,
            "jurisdiction_proof_root": self.roots.jurisdiction_proof_root,
            "committee_root": self.roots.committee_root,
            "transfer_gate_root": self.roots.transfer_gate_root,
            "settlement_batch_root": self.roots.settlement_batch_root,
            "fee_rebate_root": self.roots.fee_rebate_root,
            "operator_summary_root": self.roots.operator_summary_root,
            "counters": self.counters.public_record(),
        });
        domain_hash(
            "tokenized-rwa-compliance-oracle:state-root",
            &[HashPart::Json(&record)],
            32,
        )
    }

    fn ensure_asset_exists(&self, asset_id: &str) -> Result<()> {
        ensure_non_empty(asset_id, "asset_id")?;
        if !self.assets.contains_key(asset_id) {
            return Err(format!("asset not found: {asset_id}"));
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    let mut state = State::default();
    let mut programs = BTreeSet::new();
    programs.insert(ComplianceProgram::KycAmlScreened);
    programs.insert(ComplianceProgram::SanctionsClean);
    programs.insert(ComplianceProgram::RegD);
    let asset = state
        .register_asset(RegisterAssetRequest {
            issuer_id: "issuer:devnet-rwa-foundation".to_string(),
            asset_class: RwaAssetClass::TreasuryBill,
            sealed_terms_root: sample_hash("sealed-terms", 1),
            public_metadata_root: sample_hash("public-metadata", 1),
            reserve_commitment_root: sample_hash("reserve", 1),
            nav_micro_units: 500_000_000,
            outstanding_token_units: 500_000,
            maturity_slot: DEVNET_SLOT + 16_000,
            compliance_programs: programs,
            allowed_jurisdiction_root: sample_hash("allowed-jurisdictions", 1),
            denied_jurisdiction_root: sample_hash("denied-jurisdictions", 1),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            created_slot: DEVNET_SLOT,
        })
        .expect("devnet asset registered");
    let committee = state
        .register_committee(RegisterCommitteeRequest {
            issuer_id: asset.issuer_id.clone(),
            member_set_root: sample_hash("committee-members", 1),
            pq_verifying_key_root: sample_hash("committee-pq-key", 1),
            stake_bond_root: sample_hash("committee-bond", 1),
            min_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            active_members: 9,
            bond_micro_units: DEFAULT_MIN_ISSUER_BOND_MICRO_UNITS * 3,
            rotation_slot: DEVNET_SLOT,
        })
        .expect("devnet committee registered");
    let attestation = state
        .record_attestation(RecordAttestationRequest {
            asset_id: asset.asset_id.clone(),
            committee_id: committee.committee_id.clone(),
            kind: AttestationKind::TransferAuthorization,
            statement_root: sample_hash("attestation-statement", 1),
            redacted_statement_root: sample_hash("attestation-redacted", 1),
            pq_signature_root: sample_hash("attestation-pq-signature", 1),
            oracle_bitmap_root: sample_hash("attestation-bitmap", 1),
            quorum_weight_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_slot: DEVNET_SLOT + 1,
        })
        .expect("devnet attestation recorded");
    let proof = state
        .submit_jurisdiction_proof(SubmitJurisdictionProofRequest {
            asset_id: asset.asset_id.clone(),
            account_commitment: sample_hash("account", 1),
            jurisdiction_set_root: sample_hash("jurisdiction-set", 1),
            redacted_region_root: sample_hash("redacted-region", 1),
            nullifier_root: sample_hash("nullifier", 1),
            selective_disclosure_root: sample_hash("selective-disclosure", 1),
            public_fields: set(["program", "proof_age_slot"]),
            redacted_fields: set(["country", "state", "identity_hash", "screening_vendor"]),
            max_public_bytes: 512,
            actual_public_bytes: 168,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE,
            verified_slot: DEVNET_SLOT + 2,
        })
        .expect("devnet jurisdiction proof submitted");
    let gate = state
        .open_transfer_gate(OpenTransferGateRequest {
            asset_id: asset.asset_id.clone(),
            from_account_commitment: sample_hash("from-account", 1),
            to_account_commitment: sample_hash("to-account", 1),
            jurisdiction_proof_id: proof.proof_id.clone(),
            attestation_id: attestation.attestation_id.clone(),
            amount_token_units: 25_000,
            notional_micro_units: 25_000_000,
            fee_bps: 5,
            rebate_bps: 3,
            reason_root: sample_hash("transfer-reason", 1),
            opened_slot: DEVNET_SLOT + 3,
        })
        .expect("devnet transfer gate opened");
    let batch = state
        .open_settlement_batch(OpenSettlementBatchRequest {
            asset_id: asset.asset_id.clone(),
            gate_ids: vec![gate.gate_id.clone()],
            sealed_batch_root: sample_hash("batch-sealed", 1),
            recursive_proof_root: sample_hash("batch-recursive-proof", 1),
            oracle_attestation_root: sample_hash("batch-oracle", 1),
            opened_slot: DEVNET_SLOT + 4,
        })
        .expect("devnet settlement batch opened");
    let settled = state
        .settle_batch(SettleBatchRequest {
            batch_id: batch.batch_id.clone(),
            settled_slot: DEVNET_SLOT + 5,
        })
        .expect("devnet batch settled");
    state
        .issue_rebate(IssueRebateRequest {
            batch_id: settled.batch_id,
            gate_id: gate.gate_id,
            reason: RebateReason::BatchCompression,
            beneficiary_commitment: sample_hash("rebate-beneficiary", 1),
            asset_id: asset.asset_id,
            amount_micro_units: 37,
            rebate_bps: 3,
            issued_slot: DEVNET_SLOT + 6,
            expires_slot: DEVNET_SLOT + 720,
        })
        .expect("devnet rebate issued");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 5,
            oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
        })
        .expect("devnet operator summary published");
    state.refresh_roots();
    state
}

pub fn demo() -> State {
    let mut state = devnet();
    let mut programs = BTreeSet::new();
    programs.insert(ComplianceProgram::KycAmlScreened);
    programs.insert(ComplianceProgram::QualifiedPurchaser);
    let asset = state
        .register_asset(RegisterAssetRequest {
            issuer_id: "issuer:demo-private-credit-desk".to_string(),
            asset_class: RwaAssetClass::PrivateCredit,
            sealed_terms_root: sample_hash("demo-sealed-terms", 2),
            public_metadata_root: sample_hash("demo-public-metadata", 2),
            reserve_commitment_root: sample_hash("demo-reserve", 2),
            nav_micro_units: 900_000_000,
            outstanding_token_units: 750_000,
            maturity_slot: DEVNET_SLOT + 32_000,
            compliance_programs: programs,
            allowed_jurisdiction_root: sample_hash("demo-allowed-jurisdictions", 2),
            denied_jurisdiction_root: sample_hash("demo-denied-jurisdictions", 2),
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE * 2,
            created_slot: DEVNET_SLOT + 10,
        })
        .expect("demo asset registered");
    let committee = state
        .register_committee(RegisterCommitteeRequest {
            issuer_id: asset.issuer_id.clone(),
            member_set_root: sample_hash("demo-committee-members", 2),
            pq_verifying_key_root: sample_hash("demo-committee-pq-key", 2),
            stake_bond_root: sample_hash("demo-committee-bond", 2),
            min_quorum_bps: DEFAULT_ORACLE_QUORUM_BPS,
            strong_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            active_members: 11,
            bond_micro_units: DEFAULT_MIN_ISSUER_BOND_MICRO_UNITS * 4,
            rotation_slot: DEVNET_SLOT + 10,
        })
        .expect("demo committee registered");
    let attestation = state
        .record_attestation(RecordAttestationRequest {
            asset_id: asset.asset_id.clone(),
            committee_id: committee.committee_id,
            kind: AttestationKind::AssetReserve,
            statement_root: sample_hash("demo-attestation-statement", 2),
            redacted_statement_root: sample_hash("demo-attestation-redacted", 2),
            pq_signature_root: sample_hash("demo-attestation-pq-signature", 2),
            oracle_bitmap_root: sample_hash("demo-attestation-bitmap", 2),
            quorum_weight_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
            pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            observed_slot: DEVNET_SLOT + 11,
        })
        .expect("demo attestation recorded");
    let proof = state
        .submit_jurisdiction_proof(SubmitJurisdictionProofRequest {
            asset_id: asset.asset_id.clone(),
            account_commitment: sample_hash("demo-account", 2),
            jurisdiction_set_root: sample_hash("demo-jurisdiction-set", 2),
            redacted_region_root: sample_hash("demo-redacted-region", 2),
            nullifier_root: sample_hash("demo-nullifier", 2),
            selective_disclosure_root: sample_hash("demo-selective-disclosure", 2),
            public_fields: set(["program", "risk_band"]),
            redacted_fields: set(["country", "tax_residency", "identity_hash"]),
            max_public_bytes: 640,
            actual_public_bytes: 192,
            privacy_set_size: DEFAULT_TARGET_PRIVACY_SET_SIZE * 2,
            verified_slot: DEVNET_SLOT + 12,
        })
        .expect("demo jurisdiction proof submitted");
    let mut gate_ids = Vec::new();
    for index in 0..4 {
        let gate = state
            .open_transfer_gate(OpenTransferGateRequest {
                asset_id: asset.asset_id.clone(),
                from_account_commitment: sample_hash("demo-from-account", index),
                to_account_commitment: sample_hash("demo-to-account", index),
                jurisdiction_proof_id: proof.proof_id.clone(),
                attestation_id: attestation.attestation_id.clone(),
                amount_token_units: 10_000 + index,
                notional_micro_units: 12_000_000 + (index * 100_000),
                fee_bps: 4,
                rebate_bps: 2,
                reason_root: sample_hash("demo-transfer-reason", index),
                opened_slot: DEVNET_SLOT + 13 + index,
            })
            .expect("demo transfer gate opened");
        gate_ids.push(gate.gate_id);
    }
    let batch = state
        .open_settlement_batch(OpenSettlementBatchRequest {
            asset_id: asset.asset_id.clone(),
            gate_ids,
            sealed_batch_root: sample_hash("demo-batch-sealed", 2),
            recursive_proof_root: sample_hash("demo-batch-recursive-proof", 2),
            oracle_attestation_root: sample_hash("demo-batch-oracle", 2),
            opened_slot: DEVNET_SLOT + 20,
        })
        .expect("demo settlement batch opened");
    state
        .settle_batch(SettleBatchRequest {
            batch_id: batch.batch_id,
            settled_slot: DEVNET_SLOT + 21,
        })
        .expect("demo batch settled");
    state
        .publish_operator_summary(OperatorSummaryRequest {
            median_fee_bps: 4,
            oracle_quorum_bps: DEFAULT_STRONG_ORACLE_QUORUM_BPS,
        })
        .expect("demo operator summary published");
    state.refresh_roots();
    state
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn ensure_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{field} must be non-empty"))
    } else {
        Ok(())
    }
}

fn ensure_bps(value: u64, field: &str) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{field} exceeds {MAX_BPS} bps"))
    } else {
        Ok(())
    }
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn mul_bps(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}

fn empty_root(label: &str) -> String {
    domain_hash(
        "tokenized-rwa-compliance-oracle:empty-root",
        &[HashPart::Str(label)],
        32,
    )
}

fn stable_id(label: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(
        &format!("tokenized-rwa-compliance-oracle:{label}:id"),
        parts,
        20,
    )
}

fn map_root<T: Serialize>(domain: &str, map: &BTreeMap<String, T>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_hash(label: &str, index: u64) -> String {
    domain_hash(
        "tokenized-rwa-compliance-oracle:sample",
        &[HashPart::Str(label), HashPart::U64(index)],
        32,
    )
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(str::to_string).collect()
}
