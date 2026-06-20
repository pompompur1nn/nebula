use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type RuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-treasury-bill-vault-runtime-v1";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_AUTH_SUITE: &str = "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-tbill-vault-v1";
pub const PRIVACY_SCHEME: &str = "confidential-note-nullifier-redaction-root-viewkey-disclosure-v1";
pub const CONTRACT_SCHEME: &str =
    "pq-private-smart-contract-tokenized-treasury-bill-vault-covenant-v1";
pub const ORACLE_SCHEME: &str = "threshold-nav-root-oracle-proof-of-reserve-v1";
pub const LOW_FEE_SCHEME: &str = "recursive-proof-batch-netting-low-fee-tbill-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_HEIGHT: u64 = 3_100_000;
pub const DEVNET_FEE_ASSET_ID: &str = "asset:piconero";
pub const DEVNET_SETTLEMENT_ASSET_ID: &str = "asset:usdc-devnet";
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_ORACLE_QUORUM: u16 = 5;
pub const DEFAULT_CUSTODIAN_QUORUM: u16 = 4;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 65_536;
pub const DEFAULT_TARGET_BATCH_SIZE: u64 = 512;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 8;
pub const DEFAULT_PROTOCOL_FEE_BPS: u64 = 3;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_100;
pub const DEFAULT_MAX_NAV_STALENESS_BLOCKS: u64 = 180;
pub const DEFAULT_MAX_MATURITY_DAYS: u64 = 397;
pub const DEFAULT_MAX_SINGLE_INVESTOR_BPS: u64 = 2_500;
pub const DEFAULT_MIN_COMPLIANCE_EPOCH: u64 = 1;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheSeniority {
    TreasuryOnly,
    Senior,
    LiquidityBuffer,
    SponsorFirstLoss,
}

impl TrancheSeniority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TreasuryOnly => "treasury_only",
            Self::Senior => "senior",
            Self::LiquidityBuffer => "liquidity_buffer",
            Self::SponsorFirstLoss => "sponsor_first_loss",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrancheStatus {
    Draft,
    Open,
    SubscriptionOnly,
    RedemptionOnly,
    CouponOnly,
    Paused,
    Matured,
    Retired,
}

impl TrancheStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Open => "open",
            Self::SubscriptionOnly => "subscription_only",
            Self::RedemptionOnly => "redemption_only",
            Self::CouponOnly => "coupon_only",
            Self::Paused => "paused",
            Self::Matured => "matured",
            Self::Retired => "retired",
        }
    }

    pub fn accepts_subscriptions(self) -> bool {
        matches!(self, Self::Open | Self::SubscriptionOnly)
    }

    pub fn accepts_redemptions(self) -> bool {
        matches!(self, Self::Open | Self::RedemptionOnly)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteKind {
    Subscription,
    Redemption,
}

impl NoteKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::Redemption => "redemption",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Pending,
    RiskAccepted,
    Netted,
    Settled,
    Rejected,
    Cancelled,
}

impl NoteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::RiskAccepted => "risk_accepted",
            Self::Netted => "netted",
            Self::Settled => "settled",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleStatus {
    Proposed,
    QuorumAccepted,
    Stale,
    Challenged,
}

impl OracleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::QuorumAccepted => "quorum_accepted",
            Self::Stale => "stale",
            Self::Challenged => "challenged",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDecision {
    Accept,
    HoldForOracle,
    HoldForCompliance,
    HoldForCustodian,
    RejectLimit,
    PauseTranche,
}

impl RiskDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::HoldForOracle => "hold_for_oracle",
            Self::HoldForCompliance => "hold_for_compliance",
            Self::HoldForCustodian => "hold_for_custodian",
            Self::RejectLimit => "reject_limit",
            Self::PauseTranche => "pause_tranche",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub l2_network: String,
    pub settlement_asset_id: String,
    pub fee_asset_id: String,
    pub pq_auth_suite: String,
    pub privacy_scheme: String,
    pub contract_scheme: String,
    pub oracle_scheme: String,
    pub low_fee_scheme: String,
    pub min_pq_security_bits: u16,
    pub oracle_quorum: u16,
    pub custodian_quorum: u16,
    pub min_privacy_set_size: u64,
    pub target_batch_size: u64,
    pub max_user_fee_bps: u64,
    pub protocol_fee_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_nav_staleness_blocks: u64,
    pub max_maturity_days: u64,
    pub max_single_investor_bps: u64,
    pub min_compliance_epoch: u64,
    pub operator_view_redaction: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            settlement_asset_id: DEVNET_SETTLEMENT_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            pq_auth_suite: PQ_AUTH_SUITE.to_string(),
            privacy_scheme: PRIVACY_SCHEME.to_string(),
            contract_scheme: CONTRACT_SCHEME.to_string(),
            oracle_scheme: ORACLE_SCHEME.to_string(),
            low_fee_scheme: LOW_FEE_SCHEME.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            oracle_quorum: DEFAULT_ORACLE_QUORUM,
            custodian_quorum: DEFAULT_CUSTODIAN_QUORUM,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            target_batch_size: DEFAULT_TARGET_BATCH_SIZE,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            max_nav_staleness_blocks: DEFAULT_MAX_NAV_STALENESS_BLOCKS,
            max_maturity_days: DEFAULT_MAX_MATURITY_DAYS,
            max_single_investor_bps: DEFAULT_MAX_SINGLE_INVESTOR_BPS,
            min_compliance_epoch: DEFAULT_MIN_COMPLIANCE_EPOCH,
            operator_view_redaction: "operator-safe-no-investor-pii".to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "l2_network": self.l2_network,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_asset_id": self.fee_asset_id,
            "pq_auth_suite": self.pq_auth_suite,
            "privacy_scheme": self.privacy_scheme,
            "contract_scheme": self.contract_scheme,
            "oracle_scheme": self.oracle_scheme,
            "low_fee_scheme": self.low_fee_scheme,
            "min_pq_security_bits": self.min_pq_security_bits,
            "oracle_quorum": self.oracle_quorum,
            "custodian_quorum": self.custodian_quorum,
            "min_privacy_set_size": self.min_privacy_set_size,
            "target_batch_size": self.target_batch_size,
            "max_user_fee_bps": self.max_user_fee_bps,
            "protocol_fee_bps": self.protocol_fee_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_nav_staleness_blocks": self.max_nav_staleness_blocks,
            "max_maturity_days": self.max_maturity_days,
            "max_single_investor_bps": self.max_single_investor_bps,
            "min_compliance_epoch": self.min_compliance_epoch,
            "operator_view_redaction": self.operator_view_redaction,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub vaults: u64,
    pub tranches: u64,
    pub confidential_notes: u64,
    pub oracle_nav_roots: u64,
    pub pq_custodian_attestations: u64,
    pub coupon_distributions: u64,
    pub low_fee_batches: u64,
    pub compliance_redactions: u64,
    pub risk_gates: u64,
    pub smart_contract_receipts: u64,
    pub accepted_flows: u64,
    pub rejected_flows: u64,
    pub total_subscription_amount: u64,
    pub total_redemption_amount: u64,
    pub total_coupon_amount: u64,
    pub total_fee_charged: u64,
    pub total_fee_saved: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub vault_root: String,
    pub tranche_root: String,
    pub confidential_note_root: String,
    pub oracle_nav_root: String,
    pub pq_custodian_attestation_root: String,
    pub coupon_distribution_root: String,
    pub low_fee_batch_root: String,
    pub compliance_redaction_root: String,
    pub risk_gate_root: String,
    pub smart_contract_receipt_root: String,
    pub operator_summary_root: String,
    pub state_root: String,
}

impl Default for Roots {
    fn default() -> Self {
        let empty = merkle_root("TBILL-VAULT-EMPTY", &[]);
        Self {
            config_root: empty.clone(),
            vault_root: empty.clone(),
            tranche_root: empty.clone(),
            confidential_note_root: empty.clone(),
            oracle_nav_root: empty.clone(),
            pq_custodian_attestation_root: empty.clone(),
            coupon_distribution_root: empty.clone(),
            low_fee_batch_root: empty.clone(),
            compliance_redaction_root: empty.clone(),
            risk_gate_root: empty.clone(),
            smart_contract_receipt_root: empty.clone(),
            operator_summary_root: empty.clone(),
            state_root: empty,
        }
    }
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultCreateRequest {
    pub issuer_commitment: String,
    pub custodian_committee_root: String,
    pub trustee_contract_id: String,
    pub cash_account_commitment: String,
    pub treasury_inventory_root: String,
    pub compliance_policy_root: String,
    pub operator_policy_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VaultRecord {
    pub vault_id: String,
    pub chain_id: String,
    pub issuer_commitment: String,
    pub custodian_committee_root: String,
    pub trustee_contract_id: String,
    pub cash_account_commitment: String,
    pub treasury_inventory_root: String,
    pub compliance_policy_root: String,
    pub operator_policy_root: String,
    pub created_at_height: u64,
    pub latest_nav_root: String,
    pub latest_custodian_attestation_root: String,
    pub total_assets_face_value: u64,
    pub total_liabilities_units: u64,
    pub reserve_coverage_bps: u64,
    pub paused: bool,
}

impl VaultRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheCreateRequest {
    pub vault_id: String,
    pub label: String,
    pub seniority: TrancheSeniority,
    pub isin_hash: String,
    pub cusip_hash: String,
    pub maturity_days: u64,
    pub target_duration_days: u64,
    pub min_ticket_amount: u64,
    pub max_supply_units: u64,
    pub coupon_rate_bps: u64,
    pub contract_address_commitment: String,
    pub subscription_covenant_root: String,
    pub redemption_covenant_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrancheRecord {
    pub tranche_id: String,
    pub vault_id: String,
    pub label: String,
    pub seniority: TrancheSeniority,
    pub status: TrancheStatus,
    pub isin_hash: String,
    pub cusip_hash: String,
    pub maturity_days: u64,
    pub target_duration_days: u64,
    pub min_ticket_amount: u64,
    pub max_supply_units: u64,
    pub outstanding_units: u64,
    pub coupon_rate_bps: u64,
    pub last_coupon_height: u64,
    pub contract_address_commitment: String,
    pub subscription_covenant_root: String,
    pub redemption_covenant_root: String,
    pub created_at_height: u64,
}

impl TrancheRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "tranche_id": self.tranche_id,
            "vault_id": self.vault_id,
            "label": self.label,
            "seniority": self.seniority.as_str(),
            "status": self.status.as_str(),
            "isin_hash": self.isin_hash,
            "cusip_hash": self.cusip_hash,
            "maturity_days": self.maturity_days,
            "target_duration_days": self.target_duration_days,
            "min_ticket_amount": self.min_ticket_amount,
            "max_supply_units": self.max_supply_units,
            "outstanding_units": self.outstanding_units,
            "coupon_rate_bps": self.coupon_rate_bps,
            "last_coupon_height": self.last_coupon_height,
            "contract_address_commitment": self.contract_address_commitment,
            "subscription_covenant_root": self.subscription_covenant_root,
            "redemption_covenant_root": self.redemption_covenant_root,
            "created_at_height": self.created_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialNoteRequest {
    pub tranche_id: String,
    pub investor_commitment: String,
    pub amount: u64,
    pub encrypted_note_root: String,
    pub nullifier_commitment: String,
    pub view_tag: String,
    pub compliance_proof_root: String,
    pub pq_authorization_root: String,
    pub max_fee_bps: u64,
    pub submitted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConfidentialNoteRecord {
    pub note_id: String,
    pub kind: NoteKind,
    pub tranche_id: String,
    pub investor_commitment: String,
    pub amount: u64,
    pub encrypted_note_root: String,
    pub nullifier_commitment: String,
    pub view_tag: String,
    pub compliance_proof_root: String,
    pub pq_authorization_root: String,
    pub risk_gate_id: String,
    pub status: NoteStatus,
    pub charged_fee_bps: u64,
    pub charged_fee_amount: u64,
    pub submitted_at_height: u64,
    pub settled_at_height: u64,
}

impl ConfidentialNoteRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "note_id": self.note_id,
            "kind": self.kind.as_str(),
            "tranche_id": self.tranche_id,
            "investor_commitment": self.investor_commitment,
            "amount": self.amount,
            "encrypted_note_root": self.encrypted_note_root,
            "nullifier_commitment": self.nullifier_commitment,
            "view_tag": self.view_tag,
            "compliance_proof_root": self.compliance_proof_root,
            "pq_authorization_root": self.pq_authorization_root,
            "risk_gate_id": self.risk_gate_id,
            "status": self.status.as_str(),
            "charged_fee_bps": self.charged_fee_bps,
            "charged_fee_amount": self.charged_fee_amount,
            "submitted_at_height": self.submitted_at_height,
            "settled_at_height": self.settled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleNavRequest {
    pub vault_id: String,
    pub valuation_epoch: u64,
    pub nav_per_unit_micros: u64,
    pub treasury_inventory_root: String,
    pub pricing_source_root: String,
    pub reserve_coverage_bps: u64,
    pub attestor_set_root: String,
    pub pq_signature_root: String,
    pub posted_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OracleNavRecord {
    pub nav_id: String,
    pub vault_id: String,
    pub valuation_epoch: u64,
    pub nav_per_unit_micros: u64,
    pub treasury_inventory_root: String,
    pub pricing_source_root: String,
    pub reserve_coverage_bps: u64,
    pub attestor_set_root: String,
    pub pq_signature_root: String,
    pub status: OracleStatus,
    pub posted_at_height: u64,
}

impl OracleNavRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "nav_id": self.nav_id,
            "vault_id": self.vault_id,
            "valuation_epoch": self.valuation_epoch,
            "nav_per_unit_micros": self.nav_per_unit_micros,
            "treasury_inventory_root": self.treasury_inventory_root,
            "pricing_source_root": self.pricing_source_root,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "attestor_set_root": self.attestor_set_root,
            "pq_signature_root": self.pq_signature_root,
            "status": self.status.as_str(),
            "posted_at_height": self.posted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCustodianAttestationRequest {
    pub vault_id: String,
    pub custodian_id: String,
    pub custody_epoch: u64,
    pub inventory_root: String,
    pub cash_sweep_root: String,
    pub segregation_root: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub attested_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqCustodianAttestationRecord {
    pub attestation_id: String,
    pub vault_id: String,
    pub custodian_id: String,
    pub custody_epoch: u64,
    pub inventory_root: String,
    pub cash_sweep_root: String,
    pub segregation_root: String,
    pub pq_public_key_commitment: String,
    pub pq_signature_root: String,
    pub accepted: bool,
    pub attested_at_height: u64,
}

impl PqCustodianAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CouponDistributionRequest {
    pub tranche_id: String,
    pub coupon_epoch: u64,
    pub distribution_amount: u64,
    pub holder_commitment_root: String,
    pub encrypted_allocation_root: String,
    pub tax_redaction_root: String,
    pub pq_operator_authorization_root: String,
    pub distributed_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CouponDistributionRecord {
    pub distribution_id: String,
    pub tranche_id: String,
    pub coupon_epoch: u64,
    pub distribution_amount: u64,
    pub holder_commitment_root: String,
    pub encrypted_allocation_root: String,
    pub tax_redaction_root: String,
    pub pq_operator_authorization_root: String,
    pub fee_amount: u64,
    pub distributed_at_height: u64,
}

impl CouponDistributionRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchNettingRequest {
    pub tranche_id: String,
    pub subscription_note_ids: Vec<String>,
    pub redemption_note_ids: Vec<String>,
    pub batcher_commitment: String,
    pub recursive_proof_root: String,
    pub net_settlement_root: String,
    pub max_fee_bps: u64,
    pub settled_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeBatchNettingRecord {
    pub batch_id: String,
    pub tranche_id: String,
    pub note_root: String,
    pub subscription_count: u64,
    pub redemption_count: u64,
    pub gross_subscription_amount: u64,
    pub gross_redemption_amount: u64,
    pub net_subscription_amount: u64,
    pub net_redemption_amount: u64,
    pub batcher_commitment: String,
    pub recursive_proof_root: String,
    pub net_settlement_root: String,
    pub fee_bps: u64,
    pub fee_amount: u64,
    pub estimated_fee_saved: u64,
    pub settled_at_height: u64,
}

impl LowFeeBatchNettingRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceRedactionRequest {
    pub subject_commitment: String,
    pub jurisdiction_root: String,
    pub allowlist_epoch: u64,
    pub redaction_reason_root: String,
    pub disclosure_committee_root: String,
    pub encrypted_disclosure_root: String,
    pub pq_compliance_authorization_root: String,
    pub created_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ComplianceRedactionRecord {
    pub redaction_id: String,
    pub subject_commitment: String,
    pub jurisdiction_root: String,
    pub allowlist_epoch: u64,
    pub redaction_reason_root: String,
    pub disclosure_committee_root: String,
    pub encrypted_disclosure_root: String,
    pub pq_compliance_authorization_root: String,
    pub redaction_root: String,
    pub created_at_height: u64,
}

impl ComplianceRedactionRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskGateRequest {
    pub tranche_id: String,
    pub investor_commitment: String,
    pub amount: u64,
    pub note_kind: NoteKind,
    pub oracle_nav_id: String,
    pub custodian_attestation_id: String,
    pub compliance_redaction_id: String,
    pub exposure_after_amount: u64,
    pub evaluated_at_height: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskGateRecord {
    pub risk_gate_id: String,
    pub tranche_id: String,
    pub investor_commitment: String,
    pub amount: u64,
    pub note_kind: NoteKind,
    pub oracle_nav_id: String,
    pub custodian_attestation_id: String,
    pub compliance_redaction_id: String,
    pub exposure_after_amount: u64,
    pub exposure_bps: u64,
    pub decision: RiskDecision,
    pub reason_root: String,
    pub evaluated_at_height: u64,
}

impl RiskGateRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "risk_gate_id": self.risk_gate_id,
            "tranche_id": self.tranche_id,
            "investor_commitment": self.investor_commitment,
            "amount": self.amount,
            "note_kind": self.note_kind.as_str(),
            "oracle_nav_id": self.oracle_nav_id,
            "custodian_attestation_id": self.custodian_attestation_id,
            "compliance_redaction_id": self.compliance_redaction_id,
            "exposure_after_amount": self.exposure_after_amount,
            "exposure_bps": self.exposure_bps,
            "decision": self.decision.as_str(),
            "reason_root": self.reason_root,
            "evaluated_at_height": self.evaluated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SmartContractReceiptRecord {
    pub receipt_id: String,
    pub contract_id: String,
    pub call_kind: String,
    pub input_root: String,
    pub output_root: String,
    pub pq_authorization_root: String,
    pub gas_fee_amount: u64,
    pub success: bool,
    pub emitted_at_height: u64,
}

impl SmartContractReceiptRecord {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperatorSummary {
    pub summary_id: String,
    pub height: u64,
    pub vault_count: u64,
    pub tranche_count: u64,
    pub note_count: u64,
    pub pending_note_count: u64,
    pub accepted_note_count: u64,
    pub rejected_note_count: u64,
    pub total_subscription_amount: u64,
    pub total_redemption_amount: u64,
    pub total_coupon_amount: u64,
    pub total_fee_charged: u64,
    pub total_fee_saved: u64,
    pub latest_state_root: String,
    pub redaction_policy: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub vaults: BTreeMap<String, VaultRecord>,
    pub tranches: BTreeMap<String, TrancheRecord>,
    pub confidential_notes: BTreeMap<String, ConfidentialNoteRecord>,
    pub oracle_nav_roots: BTreeMap<String, OracleNavRecord>,
    pub pq_custodian_attestations: BTreeMap<String, PqCustodianAttestationRecord>,
    pub coupon_distributions: BTreeMap<String, CouponDistributionRecord>,
    pub low_fee_batches: BTreeMap<String, LowFeeBatchNettingRecord>,
    pub compliance_redactions: BTreeMap<String, ComplianceRedactionRecord>,
    pub risk_gates: BTreeMap<String, RiskGateRecord>,
    pub smart_contract_receipts: BTreeMap<String, SmartContractReceiptRecord>,
    pub spent_nullifiers: BTreeSet<String>,
    pub operator_summaries: Vec<OperatorSummary>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            height: DEVNET_HEIGHT,
            counters: Counters::default(),
            roots: Roots::default(),
            vaults: BTreeMap::new(),
            tranches: BTreeMap::new(),
            confidential_notes: BTreeMap::new(),
            oracle_nav_roots: BTreeMap::new(),
            pq_custodian_attestations: BTreeMap::new(),
            coupon_distributions: BTreeMap::new(),
            low_fee_batches: BTreeMap::new(),
            compliance_redactions: BTreeMap::new(),
            risk_gates: BTreeMap::new(),
            smart_contract_receipts: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
            operator_summaries: Vec::new(),
        };
        state.refresh_roots();
        state
    }
}

impl State {
    pub fn new(config: Config, height: u64) -> Self {
        let mut state = Self {
            config,
            height,
            ..Self::default()
        };
        state.refresh_roots();
        state
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "height": self.height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "TBILL-VAULT-STATE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(self.height),
                HashPart::Json(&self.config.public_record()),
                HashPart::Json(&self.counters.public_record()),
                HashPart::Json(&self.roots_without_state_root()),
            ],
            32,
        )
    }

    pub fn refresh_roots(&mut self) {
        let vault_records = values(&self.vaults, VaultRecord::public_record);
        let tranche_records = values(&self.tranches, TrancheRecord::public_record);
        let note_records = values(
            &self.confidential_notes,
            ConfidentialNoteRecord::public_record,
        );
        let nav_records = values(&self.oracle_nav_roots, OracleNavRecord::public_record);
        let custodian_records = values(
            &self.pq_custodian_attestations,
            PqCustodianAttestationRecord::public_record,
        );
        let coupon_records = values(
            &self.coupon_distributions,
            CouponDistributionRecord::public_record,
        );
        let batch_records = values(
            &self.low_fee_batches,
            LowFeeBatchNettingRecord::public_record,
        );
        let redaction_records = values(
            &self.compliance_redactions,
            ComplianceRedactionRecord::public_record,
        );
        let risk_records = values(&self.risk_gates, RiskGateRecord::public_record);
        let receipt_records = values(
            &self.smart_contract_receipts,
            SmartContractReceiptRecord::public_record,
        );
        let summary_records = self
            .operator_summaries
            .iter()
            .map(OperatorSummary::public_record)
            .collect::<Vec<_>>();

        self.roots.config_root = domain_hash(
            "TBILL-VAULT-CONFIG",
            &[HashPart::Json(&self.config.public_record())],
            32,
        );
        self.roots.vault_root = merkle_root("TBILL-VAULT-VAULT", &vault_records);
        self.roots.tranche_root = merkle_root("TBILL-VAULT-TRANCHE", &tranche_records);
        self.roots.confidential_note_root =
            merkle_root("TBILL-VAULT-CONFIDENTIAL-NOTE", &note_records);
        self.roots.oracle_nav_root = merkle_root("TBILL-VAULT-ORACLE-NAV", &nav_records);
        self.roots.pq_custodian_attestation_root =
            merkle_root("TBILL-VAULT-PQ-CUSTODIAN-ATTESTATION", &custodian_records);
        self.roots.coupon_distribution_root =
            merkle_root("TBILL-VAULT-COUPON-DISTRIBUTION", &coupon_records);
        self.roots.low_fee_batch_root = merkle_root("TBILL-VAULT-LOW-FEE-BATCH", &batch_records);
        self.roots.compliance_redaction_root =
            merkle_root("TBILL-VAULT-COMPLIANCE-REDACTION", &redaction_records);
        self.roots.risk_gate_root = merkle_root("TBILL-VAULT-RISK-GATE", &risk_records);
        self.roots.smart_contract_receipt_root =
            merkle_root("TBILL-VAULT-SMART-CONTRACT-RECEIPT", &receipt_records);
        self.roots.operator_summary_root =
            merkle_root("TBILL-VAULT-OPERATOR-SUMMARY", &summary_records);
        self.roots.state_root = self.state_root();
    }

    pub fn create_vault(&mut self, request: VaultCreateRequest) -> RuntimeResult<VaultRecord> {
        let vault_id = id(
            "TBILL-VAULT-ID",
            &[
                HashPart::Str(&request.issuer_commitment),
                HashPart::Str(&request.custodian_committee_root),
                HashPart::Str(&request.trustee_contract_id),
                HashPart::U64(request.created_at_height),
            ],
        );
        if self.vaults.contains_key(&vault_id) {
            return Err(format!("vault already exists: {vault_id}"));
        }

        let record = VaultRecord {
            vault_id: vault_id.clone(),
            chain_id: CHAIN_ID.to_string(),
            issuer_commitment: request.issuer_commitment,
            custodian_committee_root: request.custodian_committee_root,
            trustee_contract_id: request.trustee_contract_id,
            cash_account_commitment: request.cash_account_commitment,
            treasury_inventory_root: request.treasury_inventory_root,
            compliance_policy_root: request.compliance_policy_root,
            operator_policy_root: request.operator_policy_root,
            created_at_height: request.created_at_height,
            latest_nav_root: empty_root("TBILL-VAULT-NAV"),
            latest_custodian_attestation_root: empty_root("TBILL-VAULT-CUSTODY"),
            total_assets_face_value: 0,
            total_liabilities_units: 0,
            reserve_coverage_bps: MAX_BPS,
            paused: false,
        };
        self.counters.vaults += 1;
        self.height = self.height.max(record.created_at_height);
        self.vaults.insert(vault_id, record.clone());
        self.emit_contract_receipt(
            &record.trustee_contract_id,
            "create_vault",
            &record.public_record(),
            true,
            record.created_at_height,
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn create_tranche(
        &mut self,
        request: TrancheCreateRequest,
    ) -> RuntimeResult<TrancheRecord> {
        if !self.vaults.contains_key(&request.vault_id) {
            return Err(format!("unknown vault: {}", request.vault_id));
        }
        if request.maturity_days > self.config.max_maturity_days {
            return Err(format!(
                "maturity exceeds policy: {}",
                request.maturity_days
            ));
        }
        if request.coupon_rate_bps > MAX_BPS {
            return Err(format!(
                "coupon bps exceeds max: {}",
                request.coupon_rate_bps
            ));
        }

        let tranche_id = id(
            "TBILL-VAULT-TRANCHE-ID",
            &[
                HashPart::Str(&request.vault_id),
                HashPart::Str(&request.label),
                HashPart::Str(request.seniority.as_str()),
                HashPart::Str(&request.isin_hash),
                HashPart::U64(request.created_at_height),
            ],
        );
        let record = TrancheRecord {
            tranche_id: tranche_id.clone(),
            vault_id: request.vault_id,
            label: request.label,
            seniority: request.seniority,
            status: TrancheStatus::Open,
            isin_hash: request.isin_hash,
            cusip_hash: request.cusip_hash,
            maturity_days: request.maturity_days,
            target_duration_days: request.target_duration_days,
            min_ticket_amount: request.min_ticket_amount,
            max_supply_units: request.max_supply_units,
            outstanding_units: 0,
            coupon_rate_bps: request.coupon_rate_bps,
            last_coupon_height: request.created_at_height,
            contract_address_commitment: request.contract_address_commitment,
            subscription_covenant_root: request.subscription_covenant_root,
            redemption_covenant_root: request.redemption_covenant_root,
            created_at_height: request.created_at_height,
        };
        self.counters.tranches += 1;
        self.height = self.height.max(record.created_at_height);
        self.tranches.insert(tranche_id, record.clone());
        self.emit_contract_receipt(
            &record.contract_address_commitment,
            "create_tranche",
            &record.public_record(),
            true,
            record.created_at_height,
        );
        self.refresh_roots();
        Ok(record)
    }

    pub fn submit_oracle_nav(
        &mut self,
        request: OracleNavRequest,
    ) -> RuntimeResult<OracleNavRecord> {
        let vault = self
            .vaults
            .get_mut(&request.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", request.vault_id))?;
        let status = if request.reserve_coverage_bps >= self.config.min_reserve_coverage_bps {
            OracleStatus::QuorumAccepted
        } else {
            OracleStatus::Challenged
        };
        let nav_id = id(
            "TBILL-VAULT-NAV-ID",
            &[
                HashPart::Str(&request.vault_id),
                HashPart::U64(request.valuation_epoch),
                HashPart::U64(request.nav_per_unit_micros),
                HashPart::Str(&request.treasury_inventory_root),
                HashPart::Str(&request.pq_signature_root),
            ],
        );
        let record = OracleNavRecord {
            nav_id: nav_id.clone(),
            vault_id: request.vault_id,
            valuation_epoch: request.valuation_epoch,
            nav_per_unit_micros: request.nav_per_unit_micros,
            treasury_inventory_root: request.treasury_inventory_root,
            pricing_source_root: request.pricing_source_root,
            reserve_coverage_bps: request.reserve_coverage_bps,
            attestor_set_root: request.attestor_set_root,
            pq_signature_root: request.pq_signature_root,
            status,
            posted_at_height: request.posted_at_height,
        };
        vault.latest_nav_root = record.nav_id.clone();
        vault.treasury_inventory_root = record.treasury_inventory_root.clone();
        vault.reserve_coverage_bps = record.reserve_coverage_bps;
        vault.paused = matches!(record.status, OracleStatus::Challenged);
        self.counters.oracle_nav_roots += 1;
        self.height = self.height.max(record.posted_at_height);
        self.oracle_nav_roots.insert(nav_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn attest_custodian(
        &mut self,
        request: PqCustodianAttestationRequest,
    ) -> RuntimeResult<PqCustodianAttestationRecord> {
        let vault = self
            .vaults
            .get_mut(&request.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", request.vault_id))?;
        let attestation_id = id(
            "TBILL-VAULT-CUSTODIAN-ATTESTATION-ID",
            &[
                HashPart::Str(&request.vault_id),
                HashPart::Str(&request.custodian_id),
                HashPart::U64(request.custody_epoch),
                HashPart::Str(&request.inventory_root),
                HashPart::Str(&request.pq_signature_root),
            ],
        );
        let accepted = request.attested_at_height >= vault.created_at_height;
        let record = PqCustodianAttestationRecord {
            attestation_id: attestation_id.clone(),
            vault_id: request.vault_id,
            custodian_id: request.custodian_id,
            custody_epoch: request.custody_epoch,
            inventory_root: request.inventory_root,
            cash_sweep_root: request.cash_sweep_root,
            segregation_root: request.segregation_root,
            pq_public_key_commitment: request.pq_public_key_commitment,
            pq_signature_root: request.pq_signature_root,
            accepted,
            attested_at_height: request.attested_at_height,
        };
        vault.latest_custodian_attestation_root = record.attestation_id.clone();
        self.counters.pq_custodian_attestations += 1;
        self.height = self.height.max(record.attested_at_height);
        self.pq_custodian_attestations
            .insert(attestation_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn redact_compliance(
        &mut self,
        request: ComplianceRedactionRequest,
    ) -> RuntimeResult<ComplianceRedactionRecord> {
        if request.allowlist_epoch < self.config.min_compliance_epoch {
            return Err(format!(
                "allowlist epoch below configured minimum: {}",
                request.allowlist_epoch
            ));
        }
        let redaction_root = domain_hash(
            "TBILL-VAULT-COMPLIANCE-REDACTION-ROOT",
            &[
                HashPart::Str(&request.subject_commitment),
                HashPart::Str(&request.jurisdiction_root),
                HashPart::U64(request.allowlist_epoch),
                HashPart::Str(&request.redaction_reason_root),
                HashPart::Str(&request.encrypted_disclosure_root),
                HashPart::Str(&request.pq_compliance_authorization_root),
            ],
            32,
        );
        let redaction_id = id(
            "TBILL-VAULT-COMPLIANCE-REDACTION-ID",
            &[
                HashPart::Str(&request.subject_commitment),
                HashPart::Str(&redaction_root),
                HashPart::U64(request.created_at_height),
            ],
        );
        let record = ComplianceRedactionRecord {
            redaction_id: redaction_id.clone(),
            subject_commitment: request.subject_commitment,
            jurisdiction_root: request.jurisdiction_root,
            allowlist_epoch: request.allowlist_epoch,
            redaction_reason_root: request.redaction_reason_root,
            disclosure_committee_root: request.disclosure_committee_root,
            encrypted_disclosure_root: request.encrypted_disclosure_root,
            pq_compliance_authorization_root: request.pq_compliance_authorization_root,
            redaction_root,
            created_at_height: request.created_at_height,
        };
        self.counters.compliance_redactions += 1;
        self.height = self.height.max(record.created_at_height);
        self.compliance_redactions
            .insert(redaction_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn evaluate_risk_gate(
        &mut self,
        request: RiskGateRequest,
    ) -> RuntimeResult<RiskGateRecord> {
        let tranche = self
            .tranches
            .get(&request.tranche_id)
            .ok_or_else(|| format!("unknown tranche: {}", request.tranche_id))?;
        let vault = self
            .vaults
            .get(&tranche.vault_id)
            .ok_or_else(|| format!("unknown vault: {}", tranche.vault_id))?;
        let nav = self
            .oracle_nav_roots
            .get(&request.oracle_nav_id)
            .ok_or_else(|| format!("unknown nav root: {}", request.oracle_nav_id))?;
        let custodian = self
            .pq_custodian_attestations
            .get(&request.custodian_attestation_id)
            .ok_or_else(|| {
                format!(
                    "unknown custodian attestation: {}",
                    request.custodian_attestation_id
                )
            })?;
        if !self
            .compliance_redactions
            .contains_key(&request.compliance_redaction_id)
        {
            return Err(format!(
                "unknown compliance redaction: {}",
                request.compliance_redaction_id
            ));
        }
        let future_supply = tranche
            .outstanding_units
            .saturating_add(request.amount)
            .max(1);
        let exposure_bps = request.exposure_after_amount.saturating_mul(MAX_BPS) / future_supply;
        let decision = if vault.paused || matches!(tranche.status, TrancheStatus::Paused) {
            RiskDecision::PauseTranche
        } else if request
            .evaluated_at_height
            .saturating_sub(nav.posted_at_height)
            > self.config.max_nav_staleness_blocks
        {
            RiskDecision::HoldForOracle
        } else if !custodian.accepted {
            RiskDecision::HoldForCustodian
        } else if exposure_bps > self.config.max_single_investor_bps {
            RiskDecision::RejectLimit
        } else if nav.reserve_coverage_bps < self.config.min_reserve_coverage_bps {
            RiskDecision::HoldForOracle
        } else {
            RiskDecision::Accept
        };
        let reason_root = domain_hash(
            "TBILL-VAULT-RISK-REASON",
            &[
                HashPart::Str(decision.as_str()),
                HashPart::Str(&request.tranche_id),
                HashPart::Str(&request.investor_commitment),
                HashPart::U64(request.amount),
                HashPart::U64(exposure_bps),
            ],
            32,
        );
        let risk_gate_id = id(
            "TBILL-VAULT-RISK-GATE-ID",
            &[
                HashPart::Str(&request.tranche_id),
                HashPart::Str(&request.investor_commitment),
                HashPart::Str(request.note_kind.as_str()),
                HashPart::U64(request.amount),
                HashPart::Str(&reason_root),
            ],
        );
        let record = RiskGateRecord {
            risk_gate_id: risk_gate_id.clone(),
            tranche_id: request.tranche_id,
            investor_commitment: request.investor_commitment,
            amount: request.amount,
            note_kind: request.note_kind,
            oracle_nav_id: request.oracle_nav_id,
            custodian_attestation_id: request.custodian_attestation_id,
            compliance_redaction_id: request.compliance_redaction_id,
            exposure_after_amount: request.exposure_after_amount,
            exposure_bps,
            decision,
            reason_root,
            evaluated_at_height: request.evaluated_at_height,
        };
        self.counters.risk_gates += 1;
        self.height = self.height.max(record.evaluated_at_height);
        self.risk_gates.insert(risk_gate_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn confidential_subscribe(
        &mut self,
        request: ConfidentialNoteRequest,
    ) -> RuntimeResult<ConfidentialNoteRecord> {
        self.confidential_note(NoteKind::Subscription, request)
    }

    pub fn confidential_redeem(
        &mut self,
        request: ConfidentialNoteRequest,
    ) -> RuntimeResult<ConfidentialNoteRecord> {
        self.confidential_note(NoteKind::Redemption, request)
    }

    pub fn distribute_coupon(
        &mut self,
        request: CouponDistributionRequest,
    ) -> RuntimeResult<CouponDistributionRecord> {
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| format!("unknown tranche: {}", request.tranche_id))?;
        if matches!(
            tranche.status,
            TrancheStatus::Paused | TrancheStatus::Retired
        ) {
            return Err(format!(
                "tranche is not coupon eligible: {}",
                tranche.tranche_id
            ));
        }
        let fee_amount = bps_amount(request.distribution_amount, self.config.protocol_fee_bps);
        let distribution_id = id(
            "TBILL-VAULT-COUPON-DISTRIBUTION-ID",
            &[
                HashPart::Str(&request.tranche_id),
                HashPart::U64(request.coupon_epoch),
                HashPart::U64(request.distribution_amount),
                HashPart::Str(&request.holder_commitment_root),
                HashPart::Str(&request.pq_operator_authorization_root),
            ],
        );
        let record = CouponDistributionRecord {
            distribution_id: distribution_id.clone(),
            tranche_id: request.tranche_id,
            coupon_epoch: request.coupon_epoch,
            distribution_amount: request.distribution_amount,
            holder_commitment_root: request.holder_commitment_root,
            encrypted_allocation_root: request.encrypted_allocation_root,
            tax_redaction_root: request.tax_redaction_root,
            pq_operator_authorization_root: request.pq_operator_authorization_root,
            fee_amount,
            distributed_at_height: request.distributed_at_height,
        };
        tranche.last_coupon_height = record.distributed_at_height;
        self.counters.coupon_distributions += 1;
        self.counters.total_coupon_amount = self
            .counters
            .total_coupon_amount
            .saturating_add(record.distribution_amount);
        self.counters.total_fee_charged = self
            .counters
            .total_fee_charged
            .saturating_add(record.fee_amount);
        self.height = self.height.max(record.distributed_at_height);
        self.coupon_distributions
            .insert(distribution_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn net_low_fee_batch(
        &mut self,
        request: LowFeeBatchNettingRequest,
    ) -> RuntimeResult<LowFeeBatchNettingRecord> {
        let tranche = self
            .tranches
            .get_mut(&request.tranche_id)
            .ok_or_else(|| format!("unknown tranche: {}", request.tranche_id))?;
        let mut gross_subscription_amount = 0_u64;
        let mut gross_redemption_amount = 0_u64;
        let mut note_leaves = Vec::new();
        for note_id in &request.subscription_note_ids {
            let note = self
                .confidential_notes
                .get(note_id)
                .ok_or_else(|| format!("unknown subscription note: {note_id}"))?;
            if note.kind != NoteKind::Subscription || note.status != NoteStatus::RiskAccepted {
                return Err(format!("subscription note is not nettable: {note_id}"));
            }
            gross_subscription_amount = gross_subscription_amount.saturating_add(note.amount);
            note_leaves.push(json!(note_id));
        }
        for note_id in &request.redemption_note_ids {
            let note = self
                .confidential_notes
                .get(note_id)
                .ok_or_else(|| format!("unknown redemption note: {note_id}"))?;
            if note.kind != NoteKind::Redemption || note.status != NoteStatus::RiskAccepted {
                return Err(format!("redemption note is not nettable: {note_id}"));
            }
            gross_redemption_amount = gross_redemption_amount.saturating_add(note.amount);
            note_leaves.push(json!(note_id));
        }
        let fee_bps = request.max_fee_bps.min(self.config.max_user_fee_bps);
        let net_subscription_amount =
            gross_subscription_amount.saturating_sub(gross_redemption_amount);
        let net_redemption_amount =
            gross_redemption_amount.saturating_sub(gross_subscription_amount);
        let fee_amount = bps_amount(
            gross_subscription_amount.saturating_add(gross_redemption_amount),
            fee_bps,
        );
        let estimated_fee_saved = bps_amount(
            gross_subscription_amount.saturating_add(gross_redemption_amount),
            self.config.max_user_fee_bps.saturating_sub(fee_bps / 2),
        );
        let note_root = merkle_root("TBILL-VAULT-LOW-FEE-BATCH-NOTE", &note_leaves);
        let batch_id = id(
            "TBILL-VAULT-LOW-FEE-BATCH-ID",
            &[
                HashPart::Str(&request.tranche_id),
                HashPart::Str(&note_root),
                HashPart::Str(&request.recursive_proof_root),
                HashPart::U64(request.settled_at_height),
            ],
        );
        let subscription_ids = request.subscription_note_ids.clone();
        let redemption_ids = request.redemption_note_ids.clone();
        let record = LowFeeBatchNettingRecord {
            batch_id: batch_id.clone(),
            tranche_id: request.tranche_id,
            note_root,
            subscription_count: subscription_ids.len() as u64,
            redemption_count: redemption_ids.len() as u64,
            gross_subscription_amount,
            gross_redemption_amount,
            net_subscription_amount,
            net_redemption_amount,
            batcher_commitment: request.batcher_commitment,
            recursive_proof_root: request.recursive_proof_root,
            net_settlement_root: request.net_settlement_root,
            fee_bps,
            fee_amount,
            estimated_fee_saved,
            settled_at_height: request.settled_at_height,
        };
        for note_id in subscription_ids.iter().chain(redemption_ids.iter()) {
            if let Some(note) = self.confidential_notes.get_mut(note_id) {
                note.status = NoteStatus::Settled;
                note.settled_at_height = record.settled_at_height;
            }
        }
        tranche.outstanding_units = tranche
            .outstanding_units
            .saturating_add(record.net_subscription_amount)
            .saturating_sub(record.net_redemption_amount);
        if let Some(vault) = self.vaults.get_mut(&tranche.vault_id) {
            vault.total_liabilities_units = vault
                .total_liabilities_units
                .saturating_add(record.net_subscription_amount)
                .saturating_sub(record.net_redemption_amount);
            vault.total_assets_face_value = vault
                .total_assets_face_value
                .saturating_add(record.net_subscription_amount)
                .saturating_sub(record.net_redemption_amount);
        }
        self.counters.low_fee_batches += 1;
        self.counters.total_fee_charged = self
            .counters
            .total_fee_charged
            .saturating_add(record.fee_amount);
        self.counters.total_fee_saved = self
            .counters
            .total_fee_saved
            .saturating_add(record.estimated_fee_saved);
        self.height = self.height.max(record.settled_at_height);
        self.low_fee_batches.insert(batch_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    pub fn operator_safe_summary(&mut self) -> OperatorSummary {
        let pending_note_count = self
            .confidential_notes
            .values()
            .filter(|note| matches!(note.status, NoteStatus::Pending | NoteStatus::RiskAccepted))
            .count() as u64;
        let summary_id = id(
            "TBILL-VAULT-OPERATOR-SUMMARY-ID",
            &[
                HashPart::U64(self.height),
                HashPart::Str(&self.roots.state_root),
                HashPart::U64(self.counters.confidential_notes),
                HashPart::U64(self.counters.low_fee_batches),
            ],
        );
        let summary = OperatorSummary {
            summary_id,
            height: self.height,
            vault_count: self.counters.vaults,
            tranche_count: self.counters.tranches,
            note_count: self.counters.confidential_notes,
            pending_note_count,
            accepted_note_count: self.counters.accepted_flows,
            rejected_note_count: self.counters.rejected_flows,
            total_subscription_amount: self.counters.total_subscription_amount,
            total_redemption_amount: self.counters.total_redemption_amount,
            total_coupon_amount: self.counters.total_coupon_amount,
            total_fee_charged: self.counters.total_fee_charged,
            total_fee_saved: self.counters.total_fee_saved,
            latest_state_root: self.roots.state_root.clone(),
            redaction_policy: self.config.operator_view_redaction.clone(),
        };
        self.operator_summaries.push(summary.clone());
        self.refresh_roots();
        summary
    }

    fn confidential_note(
        &mut self,
        kind: NoteKind,
        request: ConfidentialNoteRequest,
    ) -> RuntimeResult<ConfidentialNoteRecord> {
        if self
            .spent_nullifiers
            .contains(&request.nullifier_commitment)
        {
            return Err(format!(
                "nullifier already spent: {}",
                request.nullifier_commitment
            ));
        }
        let tranche = self
            .tranches
            .get(&request.tranche_id)
            .ok_or_else(|| format!("unknown tranche: {}", request.tranche_id))?;
        let allowed = match kind {
            NoteKind::Subscription => tranche.status.accepts_subscriptions(),
            NoteKind::Redemption => tranche.status.accepts_redemptions(),
        };
        if !allowed {
            return Err(format!(
                "tranche {} does not accept {} notes",
                tranche.tranche_id,
                kind.as_str()
            ));
        }
        if request.amount < tranche.min_ticket_amount {
            return Err(format!("amount below tranche minimum: {}", request.amount));
        }
        if request.max_fee_bps > self.config.max_user_fee_bps {
            return Err(format!("fee cap exceeds policy: {}", request.max_fee_bps));
        }
        let latest_nav_id = self
            .oracle_nav_roots
            .values()
            .rev()
            .find(|nav| nav.vault_id == tranche.vault_id)
            .map(|nav| nav.nav_id.clone())
            .unwrap_or_else(|| empty_root("TBILL-VAULT-NAV-ID"));
        let latest_custodian_id = self
            .pq_custodian_attestations
            .values()
            .rev()
            .find(|attestation| attestation.vault_id == tranche.vault_id)
            .map(|attestation| attestation.attestation_id.clone())
            .unwrap_or_else(|| empty_root("TBILL-VAULT-CUSTODIAN-ID"));
        let latest_redaction_id = self
            .compliance_redactions
            .values()
            .rev()
            .find(|redaction| redaction.subject_commitment == request.investor_commitment)
            .map(|redaction| redaction.redaction_id.clone())
            .ok_or_else(|| {
                format!(
                    "no compliance redaction root for investor commitment: {}",
                    request.investor_commitment
                )
            })?;
        let exposure_after_amount = request.amount.saturating_add(
            self.confidential_notes
                .values()
                .filter(|note| {
                    note.investor_commitment == request.investor_commitment
                        && note.tranche_id == request.tranche_id
                        && note.status != NoteStatus::Rejected
                })
                .map(|note| note.amount)
                .sum::<u64>(),
        );
        let risk = self.evaluate_risk_gate(RiskGateRequest {
            tranche_id: request.tranche_id.clone(),
            investor_commitment: request.investor_commitment.clone(),
            amount: request.amount,
            note_kind: kind,
            oracle_nav_id: latest_nav_id,
            custodian_attestation_id: latest_custodian_id,
            compliance_redaction_id: latest_redaction_id,
            exposure_after_amount,
            evaluated_at_height: request.submitted_at_height,
        })?;
        let status = if risk.decision == RiskDecision::Accept {
            NoteStatus::RiskAccepted
        } else {
            NoteStatus::Rejected
        };
        let charged_fee_bps = request.max_fee_bps.min(self.config.max_user_fee_bps);
        let charged_fee_amount = bps_amount(request.amount, charged_fee_bps);
        let note_id = id(
            "TBILL-VAULT-CONFIDENTIAL-NOTE-ID",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(&request.tranche_id),
                HashPart::Str(&request.investor_commitment),
                HashPart::U64(request.amount),
                HashPart::Str(&request.encrypted_note_root),
                HashPart::Str(&request.nullifier_commitment),
                HashPart::Str(&request.pq_authorization_root),
            ],
        );
        let record = ConfidentialNoteRecord {
            note_id: note_id.clone(),
            kind,
            tranche_id: request.tranche_id,
            investor_commitment: request.investor_commitment,
            amount: request.amount,
            encrypted_note_root: request.encrypted_note_root,
            nullifier_commitment: request.nullifier_commitment,
            view_tag: request.view_tag,
            compliance_proof_root: request.compliance_proof_root,
            pq_authorization_root: request.pq_authorization_root,
            risk_gate_id: risk.risk_gate_id,
            status,
            charged_fee_bps,
            charged_fee_amount,
            submitted_at_height: request.submitted_at_height,
            settled_at_height: 0,
        };
        self.spent_nullifiers
            .insert(record.nullifier_commitment.clone());
        self.counters.confidential_notes += 1;
        self.counters.total_fee_charged = self
            .counters
            .total_fee_charged
            .saturating_add(record.charged_fee_amount);
        if record.status == NoteStatus::RiskAccepted {
            self.counters.accepted_flows += 1;
            match kind {
                NoteKind::Subscription => {
                    self.counters.total_subscription_amount = self
                        .counters
                        .total_subscription_amount
                        .saturating_add(record.amount);
                }
                NoteKind::Redemption => {
                    self.counters.total_redemption_amount = self
                        .counters
                        .total_redemption_amount
                        .saturating_add(record.amount);
                }
            }
        } else {
            self.counters.rejected_flows += 1;
        }
        self.height = self.height.max(record.submitted_at_height);
        self.confidential_notes.insert(note_id, record.clone());
        self.refresh_roots();
        Ok(record)
    }

    fn emit_contract_receipt(
        &mut self,
        contract_id: &str,
        call_kind: &str,
        input: &Value,
        success: bool,
        emitted_at_height: u64,
    ) {
        let input_root = domain_hash("TBILL-VAULT-CONTRACT-INPUT", &[HashPart::Json(input)], 32);
        let output_root = domain_hash(
            "TBILL-VAULT-CONTRACT-OUTPUT",
            &[
                HashPart::Str(contract_id),
                HashPart::Str(call_kind),
                HashPart::Str(if success { "success" } else { "failure" }),
                HashPart::U64(emitted_at_height),
            ],
            32,
        );
        let receipt_id = id(
            "TBILL-VAULT-CONTRACT-RECEIPT-ID",
            &[
                HashPart::Str(contract_id),
                HashPart::Str(call_kind),
                HashPart::Str(&input_root),
                HashPart::Str(&output_root),
            ],
        );
        let record = SmartContractReceiptRecord {
            receipt_id: receipt_id.clone(),
            contract_id: contract_id.to_string(),
            call_kind: call_kind.to_string(),
            input_root,
            output_root,
            pq_authorization_root: domain_hash(
                "TBILL-VAULT-CONTRACT-PQ-AUTH",
                &[HashPart::Str(contract_id), HashPart::Str(call_kind)],
                32,
            ),
            gas_fee_amount: 1,
            success,
            emitted_at_height,
        };
        self.counters.smart_contract_receipts += 1;
        self.smart_contract_receipts.insert(receipt_id, record);
    }

    fn roots_without_state_root(&self) -> Value {
        json!({
            "config_root": self.roots.config_root,
            "vault_root": self.roots.vault_root,
            "tranche_root": self.roots.tranche_root,
            "confidential_note_root": self.roots.confidential_note_root,
            "oracle_nav_root": self.roots.oracle_nav_root,
            "pq_custodian_attestation_root": self.roots.pq_custodian_attestation_root,
            "coupon_distribution_root": self.roots.coupon_distribution_root,
            "low_fee_batch_root": self.roots.low_fee_batch_root,
            "compliance_redaction_root": self.roots.compliance_redaction_root,
            "risk_gate_root": self.roots.risk_gate_root,
            "smart_contract_receipt_root": self.roots.smart_contract_receipt_root,
            "operator_summary_root": self.roots.operator_summary_root,
        })
    }
}

pub fn devnet() -> State {
    State::default()
}

pub fn demo() -> State {
    let mut state = devnet();
    let vault = state
        .create_vault(VaultCreateRequest {
            issuer_commitment: sample_hash("issuer-us-tbill-fund"),
            custodian_committee_root: sample_hash("custodian-committee"),
            trustee_contract_id: sample_hash("trustee-contract"),
            cash_account_commitment: sample_hash("cash-account"),
            treasury_inventory_root: sample_hash("treasury-inventory-open"),
            compliance_policy_root: sample_hash("compliance-policy"),
            operator_policy_root: sample_hash("operator-policy"),
            created_at_height: DEVNET_HEIGHT + 1,
        })
        .expect("demo vault");
    let tranche = state
        .create_tranche(TrancheCreateRequest {
            vault_id: vault.vault_id.clone(),
            label: "13-week tokenized treasury bill senior notes".to_string(),
            seniority: TrancheSeniority::TreasuryOnly,
            isin_hash: sample_hash("isin-us-devnet-13w"),
            cusip_hash: sample_hash("cusip-devnet-13w"),
            maturity_days: 91,
            target_duration_days: 45,
            min_ticket_amount: 1_000_000,
            max_supply_units: 5_000_000_000,
            coupon_rate_bps: 470,
            contract_address_commitment: sample_hash("tranche-contract"),
            subscription_covenant_root: sample_hash("subscription-covenant"),
            redemption_covenant_root: sample_hash("redemption-covenant"),
            created_at_height: DEVNET_HEIGHT + 2,
        })
        .expect("demo tranche");
    let nav = state
        .submit_oracle_nav(OracleNavRequest {
            vault_id: vault.vault_id.clone(),
            valuation_epoch: 1,
            nav_per_unit_micros: 1_000_023,
            treasury_inventory_root: sample_hash("treasury-inventory-epoch-1"),
            pricing_source_root: sample_hash("pricing-sources"),
            reserve_coverage_bps: 10_250,
            attestor_set_root: sample_hash("oracle-attestors"),
            pq_signature_root: sample_hash("oracle-pq-signatures"),
            posted_at_height: DEVNET_HEIGHT + 3,
        })
        .expect("demo nav");
    let custody = state
        .attest_custodian(PqCustodianAttestationRequest {
            vault_id: vault.vault_id.clone(),
            custodian_id: "custodian:demo-bank-pq".to_string(),
            custody_epoch: 1,
            inventory_root: nav.treasury_inventory_root.clone(),
            cash_sweep_root: sample_hash("cash-sweep"),
            segregation_root: sample_hash("segregation"),
            pq_public_key_commitment: sample_hash("custodian-pq-key"),
            pq_signature_root: sample_hash("custodian-pq-signature"),
            attested_at_height: DEVNET_HEIGHT + 4,
        })
        .expect("demo custody");
    let investor = sample_hash("investor-alice");
    let redaction = state
        .redact_compliance(ComplianceRedactionRequest {
            subject_commitment: investor.clone(),
            jurisdiction_root: sample_hash("jurisdiction-us-accredited"),
            allowlist_epoch: 1,
            redaction_reason_root: sample_hash("kyc-ok-aml-ok"),
            disclosure_committee_root: sample_hash("disclosure-committee"),
            encrypted_disclosure_root: sample_hash("encrypted-disclosure"),
            pq_compliance_authorization_root: sample_hash("compliance-pq-auth"),
            created_at_height: DEVNET_HEIGHT + 5,
        })
        .expect("demo compliance");
    let subscription = state
        .confidential_subscribe(ConfidentialNoteRequest {
            tranche_id: tranche.tranche_id.clone(),
            investor_commitment: investor.clone(),
            amount: 2_500_000,
            encrypted_note_root: sample_hash("subscription-note"),
            nullifier_commitment: sample_hash("subscription-nullifier"),
            view_tag: "7f".to_string(),
            compliance_proof_root: redaction.redaction_root.clone(),
            pq_authorization_root: sample_hash("subscription-pq-auth"),
            max_fee_bps: 5,
            submitted_at_height: DEVNET_HEIGHT + 6,
        })
        .expect("demo subscription");
    let redemption = state
        .confidential_redeem(ConfidentialNoteRequest {
            tranche_id: tranche.tranche_id.clone(),
            investor_commitment: investor,
            amount: 1_000_000,
            encrypted_note_root: sample_hash("redemption-note"),
            nullifier_commitment: sample_hash("redemption-nullifier"),
            view_tag: "82".to_string(),
            compliance_proof_root: redaction.redaction_root,
            pq_authorization_root: sample_hash("redemption-pq-auth"),
            max_fee_bps: 5,
            submitted_at_height: DEVNET_HEIGHT + 7,
        })
        .expect("demo redemption");
    state
        .net_low_fee_batch(LowFeeBatchNettingRequest {
            tranche_id: tranche.tranche_id.clone(),
            subscription_note_ids: vec![subscription.note_id],
            redemption_note_ids: vec![redemption.note_id],
            batcher_commitment: sample_hash("batcher"),
            recursive_proof_root: sample_hash("recursive-proof"),
            net_settlement_root: sample_hash("net-settlement"),
            max_fee_bps: 4,
            settled_at_height: DEVNET_HEIGHT + 8,
        })
        .expect("demo batch");
    state
        .distribute_coupon(CouponDistributionRequest {
            tranche_id: tranche.tranche_id,
            coupon_epoch: 1,
            distribution_amount: 12_500,
            holder_commitment_root: sample_hash("holders"),
            encrypted_allocation_root: sample_hash("encrypted-coupon-allocations"),
            tax_redaction_root: sample_hash("tax-redaction"),
            pq_operator_authorization_root: custody.pq_signature_root,
            distributed_at_height: DEVNET_HEIGHT + 9,
        })
        .expect("demo coupon");
    state.operator_safe_summary();
    state.refresh_roots();
    state
}

fn values<T>(map: &BTreeMap<String, T>, record: fn(&T) -> Value) -> Vec<Value> {
    map.values().map(record).collect()
}

fn id(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

fn empty_root(domain: &str) -> String {
    merkle_root(domain, &[])
}

fn sample_hash(label: &str) -> String {
    domain_hash(
        "TBILL-VAULT-DEMO-SAMPLE",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}

fn bps_amount(amount: u64, bps: u64) -> u64 {
    amount.saturating_mul(bps) / MAX_BPS
}
