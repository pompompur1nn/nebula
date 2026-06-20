use crate::hash::{domain_hash, merkle_root, HashPart};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub type Result<T> = std::result::Result<T, String>;
pub type PrivateL2PqConfidentialTokenizedPowerHashrateForwardSettlementRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_POWER_HASHRATE_FORWARD_SETTLEMENT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-tokenized-power-hashrate-forward-settlement-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    PRIVATE_L2_PQ_CONFIDENTIAL_TOKENIZED_POWER_HASHRATE_FORWARD_SETTLEMENT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_CHAIN_ID: &str = "nebula-l2-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_ORACLE_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-forward-delivery-oracle-report-v1";
pub const CONFIDENTIAL_COMMITMENT_SUITE: &str =
    "Pedersen+RingCT-tokenized-power-hashrate-forward-commitment-v1";
pub const ESCROW_SUITE: &str = "confidential-collateral-escrow-netting-root-v1";
pub const INSURANCE_SUITE: &str = "default-insurance-mutualized-loss-bucket-root-v1";
pub const REDACTION_SUITE: &str = "selective-disclosure-redaction-budget-root-v1";
pub const LOW_FEE_REBATE_SUITE: &str = "low-fee-forward-settlement-rebate-root-v1";
pub const PUBLIC_RECORD_SUITE: &str =
    "roots-only-confidential-tokenized-power-hashrate-forward-public-record-v1";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_SETTLEMENT_EPOCH_BLOCKS: u64 = 720;
pub const DEFAULT_DISPUTE_WINDOW_BLOCKS: u64 = 360;
pub const DEFAULT_ORACLE_REPORT_TTL_BLOCKS: u64 = 180;
pub const DEFAULT_REDACTION_BUDGET_PER_EPOCH: u64 = 48;
pub const DEFAULT_LOW_FEE_REBATE_BPS: u64 = 22;
pub const DEFAULT_INSURANCE_PREMIUM_BPS: u64 = 65;
pub const DEFAULT_INITIAL_MARGIN_BPS: u64 = 1_800;
pub const DEFAULT_MAINTENANCE_MARGIN_BPS: u64 = 1_250;
pub const DEFAULT_DELIVERY_TOLERANCE_BPS: u64 = 250;
pub const DEFAULT_MAX_FORWARD_CONTRACTS: usize = 262_144;
pub const DEFAULT_MAX_DELIVERY_COHORTS: usize = 262_144;
pub const DEFAULT_MAX_ORACLE_REPORTS: usize = 524_288;
pub const DEFAULT_MAX_COLLATERAL_ESCROWS: usize = 262_144;
pub const DEFAULT_MAX_SETTLEMENT_EVENTS: usize = 1_048_576;
pub const DEFAULT_MAX_INSURANCE_CLAIMS: usize = 262_144;
pub const DEFAULT_MAX_LOW_FEE_REBATES: usize = 524_288;
pub const DEFAULT_MAX_REDACTION_BUDGETS: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Devnet,
    Canary,
    MainnetCandidate,
}

impl RuntimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::Canary => "canary",
            Self::MainnetCandidate => "mainnet_candidate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MarketKind {
    PowerMwh,
    HashratePhs,
    HybridPowerHashrate,
    CurtailmentCredit,
    RenewableCertificate,
}

impl MarketKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PowerMwh => "power_mwh",
            Self::HashratePhs => "hashrate_phs",
            Self::HybridPowerHashrate => "hybrid_power_hashrate",
            Self::CurtailmentCredit => "curtailment_credit",
            Self::RenewableCertificate => "renewable_certificate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSide {
    Buyer,
    Seller,
    MarketMaker,
    InsuranceFund,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardStatus {
    Quoted,
    Open,
    Delivering,
    Settled,
    Defaulted,
    Cancelled,
    Disputed,
}

impl ForwardStatus {
    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Delivering | Self::Disputed)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Scheduled,
    Metered,
    PartiallyDelivered,
    Delivered,
    Shortfall,
    Excused,
    Rejected,
}

impl DeliveryStatus {
    pub fn counts_as_delivery(self) -> bool {
        matches!(
            self,
            Self::Metered | Self::PartiallyDelivered | Self::Delivered | Self::Excused
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleReportKind {
    MeterReading,
    PoolHashrate,
    GridCurtailment,
    RenewableProof,
    SpotIndex,
    WeatherDerate,
    ForceMajeure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OracleVerdict {
    Accepted,
    Quarantined,
    Replayed,
    SignatureInvalid,
    Stale,
    Disputed,
}

impl OracleVerdict {
    pub fn accepted(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EscrowStatus {
    Reserved,
    MarginHealthy,
    MarginCall,
    Liquidating,
    Released,
    Slashed,
}

impl EscrowStatus {
    pub fn locked(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::MarginHealthy | Self::MarginCall | Self::Liquidating
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEventKind {
    ContractOpened,
    MarginPosted,
    OracleReportAccepted,
    DeliveryCredited,
    ShortfallDebited,
    RebateReserved,
    InsuranceClaimOpened,
    InsuranceClaimPaid,
    FinalSettlement,
    DefaultDeclared,
    RedactionSpent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Pending,
    Applied,
    Reversed,
    Disputed,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultReason {
    DeliveryShortfall,
    MarginBreach,
    OracleFraud,
    LateSettlement,
    UnauthorizedRedaction,
    OperatorPause,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InsuranceClaimStatus {
    Open,
    EvidenceComplete,
    Approved,
    Paid,
    Denied,
    Subrogated,
}

impl InsuranceClaimStatus {
    pub fn payable(self) -> bool {
        matches!(self, Self::Approved | Self::Paid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateStatus {
    Reserved,
    Applied,
    Paid,
    Expired,
    Revoked,
}

impl RebateStatus {
    pub fn live(self) -> bool {
        matches!(self, Self::Reserved | Self::Applied)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionBudgetStatus {
    Available,
    Exhausted,
    Quarantined,
    Revoked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub mode: RuntimeMode,
    pub protocol_version: String,
    pub schema_version: u64,
    pub settlement_epoch_blocks: u64,
    pub dispute_window_blocks: u64,
    pub oracle_report_ttl_blocks: u64,
    pub min_pq_security_bits: u16,
    pub initial_margin_bps: u64,
    pub maintenance_margin_bps: u64,
    pub delivery_tolerance_bps: u64,
    pub insurance_premium_bps: u64,
    pub low_fee_rebate_bps: u64,
    pub redaction_budget_per_epoch: u64,
    pub max_forward_contracts: usize,
    pub max_delivery_cohorts: usize,
    pub max_oracle_reports: usize,
    pub max_collateral_escrows: usize,
    pub max_settlement_events: usize,
    pub max_insurance_claims: usize,
    pub max_low_fee_rebates: usize,
    pub max_redaction_budgets: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: DEVNET_CHAIN_ID.to_string(),
            mode: RuntimeMode::Devnet,
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            settlement_epoch_blocks: DEFAULT_SETTLEMENT_EPOCH_BLOCKS,
            dispute_window_blocks: DEFAULT_DISPUTE_WINDOW_BLOCKS,
            oracle_report_ttl_blocks: DEFAULT_ORACLE_REPORT_TTL_BLOCKS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            initial_margin_bps: DEFAULT_INITIAL_MARGIN_BPS,
            maintenance_margin_bps: DEFAULT_MAINTENANCE_MARGIN_BPS,
            delivery_tolerance_bps: DEFAULT_DELIVERY_TOLERANCE_BPS,
            insurance_premium_bps: DEFAULT_INSURANCE_PREMIUM_BPS,
            low_fee_rebate_bps: DEFAULT_LOW_FEE_REBATE_BPS,
            redaction_budget_per_epoch: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
            max_forward_contracts: DEFAULT_MAX_FORWARD_CONTRACTS,
            max_delivery_cohorts: DEFAULT_MAX_DELIVERY_COHORTS,
            max_oracle_reports: DEFAULT_MAX_ORACLE_REPORTS,
            max_collateral_escrows: DEFAULT_MAX_COLLATERAL_ESCROWS,
            max_settlement_events: DEFAULT_MAX_SETTLEMENT_EVENTS,
            max_insurance_claims: DEFAULT_MAX_INSURANCE_CLAIMS,
            max_low_fee_rebates: DEFAULT_MAX_LOW_FEE_REBATES,
            max_redaction_budgets: DEFAULT_MAX_REDACTION_BUDGETS,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "mode": self.mode.as_str(),
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "settlement_epoch_blocks": self.settlement_epoch_blocks,
            "dispute_window_blocks": self.dispute_window_blocks,
            "oracle_report_ttl_blocks": self.oracle_report_ttl_blocks,
            "min_pq_security_bits": self.min_pq_security_bits,
            "initial_margin_bps": self.initial_margin_bps,
            "maintenance_margin_bps": self.maintenance_margin_bps,
            "delivery_tolerance_bps": self.delivery_tolerance_bps,
            "insurance_premium_bps": self.insurance_premium_bps,
            "low_fee_rebate_bps": self.low_fee_rebate_bps,
            "redaction_budget_per_epoch": self.redaction_budget_per_epoch,
            "max_forward_contracts": self.max_forward_contracts,
            "max_delivery_cohorts": self.max_delivery_cohorts,
            "max_oracle_reports": self.max_oracle_reports,
            "max_collateral_escrows": self.max_collateral_escrows,
            "max_settlement_events": self.max_settlement_events,
            "max_insurance_claims": self.max_insurance_claims,
            "max_low_fee_rebates": self.max_low_fee_rebates,
            "max_redaction_budgets": self.max_redaction_budgets
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub forward_contracts: u64,
    pub active_forwards: u64,
    pub delivery_cohorts: u64,
    pub metered_cohorts: u64,
    pub oracle_reports: u64,
    pub accepted_oracle_reports: u64,
    pub collateral_escrows: u64,
    pub locked_escrows: u64,
    pub settlement_events: u64,
    pub finalized_settlements: u64,
    pub defaults: u64,
    pub insurance_claims: u64,
    pub paid_insurance_claims: u64,
    pub low_fee_rebates: u64,
    pub paid_low_fee_rebates: u64,
    pub redaction_budgets: u64,
    pub exhausted_redaction_budgets: u64,
    pub operator_summaries: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "forward_contracts": self.forward_contracts,
            "active_forwards": self.active_forwards,
            "delivery_cohorts": self.delivery_cohorts,
            "metered_cohorts": self.metered_cohorts,
            "oracle_reports": self.oracle_reports,
            "accepted_oracle_reports": self.accepted_oracle_reports,
            "collateral_escrows": self.collateral_escrows,
            "locked_escrows": self.locked_escrows,
            "settlement_events": self.settlement_events,
            "finalized_settlements": self.finalized_settlements,
            "defaults": self.defaults,
            "insurance_claims": self.insurance_claims,
            "paid_insurance_claims": self.paid_insurance_claims,
            "low_fee_rebates": self.low_fee_rebates,
            "paid_low_fee_rebates": self.paid_low_fee_rebates,
            "redaction_budgets": self.redaction_budgets,
            "exhausted_redaction_budgets": self.exhausted_redaction_budgets,
            "operator_summaries": self.operator_summaries
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub forward_contract_root: String,
    pub delivery_cohort_root: String,
    pub pq_oracle_report_root: String,
    pub collateral_escrow_root: String,
    pub settlement_event_root: String,
    pub default_insurance_root: String,
    pub low_fee_rebate_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub nullifier_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "forward_contract_root": self.forward_contract_root,
            "delivery_cohort_root": self.delivery_cohort_root,
            "pq_oracle_report_root": self.pq_oracle_report_root,
            "collateral_escrow_root": self.collateral_escrow_root,
            "settlement_event_root": self.settlement_event_root,
            "default_insurance_root": self.default_insurance_root,
            "low_fee_rebate_root": self.low_fee_rebate_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "nullifier_root": self.nullifier_root
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root);
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ForwardContract {
    pub id: String,
    pub market: MarketKind,
    pub buyer_commitment: String,
    pub seller_commitment: String,
    pub notional_commitment: String,
    pub delivery_commitment: String,
    pub price_index_commitment: String,
    pub collateral_policy_id: String,
    pub insurance_policy_id: String,
    pub start_l2_height: u64,
    pub maturity_l2_height: u64,
    pub settlement_asset_id: String,
    pub fee_bps: u64,
    pub status: ForwardStatus,
    pub privacy_set_size: u64,
    pub pq_authorization_root: String,
    pub nullifier: String,
}

impl ForwardContract {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "market": self.market.as_str(),
            "buyer_commitment": self.buyer_commitment,
            "seller_commitment": self.seller_commitment,
            "notional_commitment": self.notional_commitment,
            "delivery_commitment": self.delivery_commitment,
            "price_index_commitment": self.price_index_commitment,
            "collateral_policy_id": self.collateral_policy_id,
            "insurance_policy_id": self.insurance_policy_id,
            "start_l2_height": self.start_l2_height,
            "maturity_l2_height": self.maturity_l2_height,
            "settlement_asset_id": self.settlement_asset_id,
            "fee_bps": self.fee_bps,
            "status": self.status,
            "privacy_set_size": self.privacy_set_size,
            "pq_authorization_root": self.pq_authorization_root,
            "nullifier": self.nullifier
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "tokenized-power-hashrate-forward-contract",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeliveryCohort {
    pub id: String,
    pub contract_id: String,
    pub market: MarketKind,
    pub cohort_start_height: u64,
    pub cohort_end_height: u64,
    pub grid_region_commitment: String,
    pub miner_pool_commitment: String,
    pub expected_quantity_commitment: String,
    pub delivered_quantity_commitment: String,
    pub renewable_fraction_bps: u64,
    pub curtailment_bps: u64,
    pub status: DeliveryStatus,
    pub oracle_report_ids: Vec<String>,
    pub redaction_budget_id: String,
}

impl DeliveryCohort {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id": self.contract_id,
            "market": self.market.as_str(),
            "cohort_start_height": self.cohort_start_height,
            "cohort_end_height": self.cohort_end_height,
            "grid_region_commitment": self.grid_region_commitment,
            "miner_pool_commitment": self.miner_pool_commitment,
            "expected_quantity_commitment": self.expected_quantity_commitment,
            "delivered_quantity_commitment": self.delivered_quantity_commitment,
            "renewable_fraction_bps": self.renewable_fraction_bps,
            "curtailment_bps": self.curtailment_bps,
            "status": self.status,
            "oracle_report_ids": self.oracle_report_ids,
            "redaction_budget_id": self.redaction_budget_id
        })
    }

    pub fn delivery_gap_commitment(&self) -> String {
        domain_hash(
            "delivery-cohort-gap-commitment",
            &[
                HashPart::Str(&self.expected_quantity_commitment),
                HashPart::Str(&self.delivered_quantity_commitment),
                HashPart::U64(self.curtailment_bps),
            ],
            32,
        )
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "tokenized-power-hashrate-delivery-cohort",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqOracleReport {
    pub id: String,
    pub cohort_id: String,
    pub reporter_commitment: String,
    pub report_kind: OracleReportKind,
    pub l2_height: u64,
    pub source_height: u64,
    pub measurement_commitment: String,
    pub confidence_bps: u64,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub verdict: OracleVerdict,
    pub expires_at_l2_height: u64,
    pub nullifier: String,
}

impl PqOracleReport {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "cohort_id": self.cohort_id,
            "reporter_commitment": self.reporter_commitment,
            "report_kind": self.report_kind,
            "l2_height": self.l2_height,
            "source_height": self.source_height,
            "measurement_commitment": self.measurement_commitment,
            "confidence_bps": self.confidence_bps,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "verdict": self.verdict,
            "expires_at_l2_height": self.expires_at_l2_height,
            "nullifier": self.nullifier
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "pq-forward-delivery-oracle-report",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CollateralEscrow {
    pub id: String,
    pub contract_id: String,
    pub side: ContractSide,
    pub owner_commitment: String,
    pub collateral_asset_id: String,
    pub posted_commitment: String,
    pub required_initial_margin_commitment: String,
    pub required_maintenance_margin_commitment: String,
    pub locked_until_l2_height: u64,
    pub status: EscrowStatus,
    pub last_margin_call_height: Option<u64>,
    pub nullifier: String,
}

impl CollateralEscrow {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id": self.contract_id,
            "side": self.side,
            "owner_commitment": self.owner_commitment,
            "collateral_asset_id": self.collateral_asset_id,
            "posted_commitment": self.posted_commitment,
            "required_initial_margin_commitment": self.required_initial_margin_commitment,
            "required_maintenance_margin_commitment": self.required_maintenance_margin_commitment,
            "locked_until_l2_height": self.locked_until_l2_height,
            "status": self.status,
            "last_margin_call_height": self.last_margin_call_height,
            "nullifier": self.nullifier
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "confidential-forward-collateral-escrow",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SettlementEvent {
    pub id: String,
    pub contract_id: String,
    pub cohort_id: Option<String>,
    pub event_kind: SettlementEventKind,
    pub status: SettlementStatus,
    pub l2_height: u64,
    pub amount_commitment: String,
    pub fee_commitment: String,
    pub settlement_root_before: String,
    pub settlement_root_after: String,
    pub operator_commitment: String,
    pub note: String,
}

impl SettlementEvent {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id": self.contract_id,
            "cohort_id": self.cohort_id,
            "event_kind": self.event_kind,
            "status": self.status,
            "l2_height": self.l2_height,
            "amount_commitment": self.amount_commitment,
            "fee_commitment": self.fee_commitment,
            "settlement_root_before": self.settlement_root_before,
            "settlement_root_after": self.settlement_root_after,
            "operator_commitment": self.operator_commitment,
            "note": self.note
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "confidential-forward-settlement-event",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DefaultInsuranceClaim {
    pub id: String,
    pub contract_id: String,
    pub claimant_commitment: String,
    pub default_reason: DefaultReason,
    pub loss_commitment: String,
    pub insured_payout_commitment: String,
    pub premium_commitment: String,
    pub evidence_root: String,
    pub status: InsuranceClaimStatus,
    pub opened_l2_height: u64,
    pub paid_l2_height: Option<u64>,
}

impl DefaultInsuranceClaim {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id": self.contract_id,
            "claimant_commitment": self.claimant_commitment,
            "default_reason": self.default_reason,
            "loss_commitment": self.loss_commitment,
            "insured_payout_commitment": self.insured_payout_commitment,
            "premium_commitment": self.premium_commitment,
            "evidence_root": self.evidence_root,
            "status": self.status,
            "opened_l2_height": self.opened_l2_height,
            "paid_l2_height": self.paid_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "default-insurance-claim",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LowFeeRebate {
    pub id: String,
    pub contract_id: String,
    pub beneficiary_commitment: String,
    pub fee_asset_id: String,
    pub gross_fee_commitment: String,
    pub rebate_commitment: String,
    pub rebate_bps: u64,
    pub status: RebateStatus,
    pub reserved_l2_height: u64,
    pub paid_l2_height: Option<u64>,
}

impl LowFeeRebate {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "contract_id": self.contract_id,
            "beneficiary_commitment": self.beneficiary_commitment,
            "fee_asset_id": self.fee_asset_id,
            "gross_fee_commitment": self.gross_fee_commitment,
            "rebate_commitment": self.rebate_commitment,
            "rebate_bps": self.rebate_bps,
            "status": self.status,
            "reserved_l2_height": self.reserved_l2_height,
            "paid_l2_height": self.paid_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "low-fee-forward-settlement-rebate",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudget {
    pub id: String,
    pub subject_commitment: String,
    pub epoch: u64,
    pub allowance: u64,
    pub spent: u64,
    pub purpose_root: String,
    pub status: RedactionBudgetStatus,
    pub last_spent_l2_height: Option<u64>,
}

impl RedactionBudget {
    pub fn remaining(&self) -> u64 {
        self.allowance.saturating_sub(self.spent)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "subject_commitment": self.subject_commitment,
            "epoch": self.epoch,
            "allowance": self.allowance,
            "spent": self.spent,
            "remaining": self.remaining(),
            "purpose_root": self.purpose_root,
            "status": self.status,
            "last_spent_l2_height": self.last_spent_l2_height
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "forward-redaction-budget",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub id: String,
    pub operator_commitment: String,
    pub epoch: u64,
    pub active_contracts: u64,
    pub delivery_cohorts: u64,
    pub accepted_oracle_reports: u64,
    pub disputed_oracle_reports: u64,
    pub settled_contracts: u64,
    pub defaulted_contracts: u64,
    pub escrow_health_bps: u64,
    pub rebate_liability_commitment: String,
    pub insurance_liability_commitment: String,
    pub redaction_spend: u64,
    pub summary_root: String,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "id": self.id,
            "operator_commitment": self.operator_commitment,
            "epoch": self.epoch,
            "active_contracts": self.active_contracts,
            "delivery_cohorts": self.delivery_cohorts,
            "accepted_oracle_reports": self.accepted_oracle_reports,
            "disputed_oracle_reports": self.disputed_oracle_reports,
            "settled_contracts": self.settled_contracts,
            "defaulted_contracts": self.defaulted_contracts,
            "escrow_health_bps": self.escrow_health_bps,
            "rebate_liability_commitment": self.rebate_liability_commitment,
            "insurance_liability_commitment": self.insurance_liability_commitment,
            "redaction_spend": self.redaction_spend,
            "summary_root": self.summary_root
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "forward-operator-summary",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub l2_height: u64,
    pub monero_height: u64,
    pub epoch: u64,
    pub forward_contracts: BTreeMap<String, ForwardContract>,
    pub delivery_cohorts: BTreeMap<String, DeliveryCohort>,
    pub pq_oracle_reports: BTreeMap<String, PqOracleReport>,
    pub collateral_escrows: BTreeMap<String, CollateralEscrow>,
    pub settlement_events: BTreeMap<String, SettlementEvent>,
    pub default_insurance_claims: BTreeMap<String, DefaultInsuranceClaim>,
    pub low_fee_rebates: BTreeMap<String, LowFeeRebate>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSummary>,
    pub spent_nullifiers: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            l2_height: 2_028_720,
            monero_height: 3_642_420,
            epoch: 2_818,
            forward_contracts: BTreeMap::new(),
            delivery_cohorts: BTreeMap::new(),
            pq_oracle_reports: BTreeMap::new(),
            collateral_escrows: BTreeMap::new(),
            settlement_events: BTreeMap::new(),
            default_insurance_claims: BTreeMap::new(),
            low_fee_rebates: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            spent_nullifiers: BTreeSet::new(),
        };
        state.recompute();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let mut state = Self::default();
        state.install_devnet_fixture();
        state.recompute();
        state
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_public_record(&self.public_record_without_state_root())
    }

    pub fn roots(&self) -> Roots {
        self.compute_roots()
    }

    pub fn recompute(&mut self) {
        self.counters = self.compute_counters();
        self.roots = self.compute_roots();
        self.roots.state_root = self.state_root();
    }

    pub fn add_forward_contract(&mut self, contract: ForwardContract) -> Result<()> {
        if self.forward_contracts.len() >= self.config.max_forward_contracts {
            return Err("forward contract capacity exceeded".to_string());
        }
        if !self.spent_nullifiers.insert(contract.nullifier.clone()) {
            return Err(format!(
                "duplicate forward nullifier {}",
                contract.nullifier
            ));
        }
        if self.forward_contracts.contains_key(&contract.id) {
            return Err(format!("duplicate forward contract {}", contract.id));
        }
        self.forward_contracts.insert(contract.id.clone(), contract);
        self.recompute();
        Ok(())
    }

    pub fn add_delivery_cohort(&mut self, cohort: DeliveryCohort) -> Result<()> {
        if self.delivery_cohorts.len() >= self.config.max_delivery_cohorts {
            return Err("delivery cohort capacity exceeded".to_string());
        }
        if !self.forward_contracts.contains_key(&cohort.contract_id) {
            return Err(format!("unknown contract {}", cohort.contract_id));
        }
        if self.delivery_cohorts.contains_key(&cohort.id) {
            return Err(format!("duplicate delivery cohort {}", cohort.id));
        }
        self.delivery_cohorts.insert(cohort.id.clone(), cohort);
        self.recompute();
        Ok(())
    }

    pub fn add_pq_oracle_report(&mut self, report: PqOracleReport) -> Result<()> {
        if self.pq_oracle_reports.len() >= self.config.max_oracle_reports {
            return Err("oracle report capacity exceeded".to_string());
        }
        if !self.delivery_cohorts.contains_key(&report.cohort_id) {
            return Err(format!("unknown delivery cohort {}", report.cohort_id));
        }
        if !self.spent_nullifiers.insert(report.nullifier.clone()) {
            return Err(format!("duplicate oracle nullifier {}", report.nullifier));
        }
        if self.pq_oracle_reports.contains_key(&report.id) {
            return Err(format!("duplicate oracle report {}", report.id));
        }
        self.pq_oracle_reports.insert(report.id.clone(), report);
        self.recompute();
        Ok(())
    }

    pub fn add_collateral_escrow(&mut self, escrow: CollateralEscrow) -> Result<()> {
        if self.collateral_escrows.len() >= self.config.max_collateral_escrows {
            return Err("collateral escrow capacity exceeded".to_string());
        }
        if !self.forward_contracts.contains_key(&escrow.contract_id) {
            return Err(format!("unknown contract {}", escrow.contract_id));
        }
        if !self.spent_nullifiers.insert(escrow.nullifier.clone()) {
            return Err(format!("duplicate escrow nullifier {}", escrow.nullifier));
        }
        if self.collateral_escrows.contains_key(&escrow.id) {
            return Err(format!("duplicate collateral escrow {}", escrow.id));
        }
        self.collateral_escrows.insert(escrow.id.clone(), escrow);
        self.recompute();
        Ok(())
    }

    pub fn add_settlement_event(&mut self, event: SettlementEvent) -> Result<()> {
        if self.settlement_events.len() >= self.config.max_settlement_events {
            return Err("settlement event capacity exceeded".to_string());
        }
        if !self.forward_contracts.contains_key(&event.contract_id) {
            return Err(format!("unknown contract {}", event.contract_id));
        }
        if self.settlement_events.contains_key(&event.id) {
            return Err(format!("duplicate settlement event {}", event.id));
        }
        self.settlement_events.insert(event.id.clone(), event);
        self.recompute();
        Ok(())
    }

    pub fn add_default_insurance_claim(&mut self, claim: DefaultInsuranceClaim) -> Result<()> {
        if self.default_insurance_claims.len() >= self.config.max_insurance_claims {
            return Err("insurance claim capacity exceeded".to_string());
        }
        if !self.forward_contracts.contains_key(&claim.contract_id) {
            return Err(format!("unknown contract {}", claim.contract_id));
        }
        if self.default_insurance_claims.contains_key(&claim.id) {
            return Err(format!("duplicate insurance claim {}", claim.id));
        }
        self.default_insurance_claims
            .insert(claim.id.clone(), claim);
        self.recompute();
        Ok(())
    }

    pub fn add_low_fee_rebate(&mut self, rebate: LowFeeRebate) -> Result<()> {
        if self.low_fee_rebates.len() >= self.config.max_low_fee_rebates {
            return Err("low-fee rebate capacity exceeded".to_string());
        }
        if !self.forward_contracts.contains_key(&rebate.contract_id) {
            return Err(format!("unknown contract {}", rebate.contract_id));
        }
        if rebate.rebate_bps > self.config.low_fee_rebate_bps {
            return Err("rebate exceeds configured low-fee cap".to_string());
        }
        if self.low_fee_rebates.contains_key(&rebate.id) {
            return Err(format!("duplicate low-fee rebate {}", rebate.id));
        }
        self.low_fee_rebates.insert(rebate.id.clone(), rebate);
        self.recompute();
        Ok(())
    }

    pub fn add_redaction_budget(&mut self, budget: RedactionBudget) -> Result<()> {
        if self.redaction_budgets.len() >= self.config.max_redaction_budgets {
            return Err("redaction budget capacity exceeded".to_string());
        }
        if budget.spent > budget.allowance {
            return Err("redaction budget overspent".to_string());
        }
        if self.redaction_budgets.contains_key(&budget.id) {
            return Err(format!("duplicate redaction budget {}", budget.id));
        }
        self.redaction_budgets.insert(budget.id.clone(), budget);
        self.recompute();
        Ok(())
    }

    pub fn add_operator_summary(&mut self, summary: OperatorSummary) -> Result<()> {
        if self.operator_summaries.contains_key(&summary.id) {
            return Err(format!("duplicate operator summary {}", summary.id));
        }
        self.operator_summaries.insert(summary.id.clone(), summary);
        self.recompute();
        Ok(())
    }

    pub fn operator_public_summary(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": self.config.chain_id,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "active_forwards": self.counters.active_forwards,
            "delivery_cohorts": self.counters.delivery_cohorts,
            "accepted_oracle_reports": self.counters.accepted_oracle_reports,
            "locked_escrows": self.counters.locked_escrows,
            "defaults": self.counters.defaults,
            "paid_insurance_claims": self.counters.paid_insurance_claims,
            "paid_low_fee_rebates": self.counters.paid_low_fee_rebates,
            "exhausted_redaction_budgets": self.counters.exhausted_redaction_budgets,
            "roots": self.roots.public_record(),
            "state_root": self.state_root()
        })
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_oracle_suite": PQ_ORACLE_SUITE,
            "confidential_commitment_suite": CONFIDENTIAL_COMMITMENT_SUITE,
            "escrow_suite": ESCROW_SUITE,
            "insurance_suite": INSURANCE_SUITE,
            "redaction_suite": REDACTION_SUITE,
            "low_fee_rebate_suite": LOW_FEE_REBATE_SUITE,
            "public_record_suite": PUBLIC_RECORD_SUITE,
            "l2_height": self.l2_height,
            "monero_height": self.monero_height,
            "epoch": self.epoch,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root()
        })
    }

    fn compute_counters(&self) -> Counters {
        Counters {
            forward_contracts: self.forward_contracts.len() as u64,
            active_forwards: self
                .forward_contracts
                .values()
                .filter(|contract| contract.status.active())
                .count() as u64,
            delivery_cohorts: self.delivery_cohorts.len() as u64,
            metered_cohorts: self
                .delivery_cohorts
                .values()
                .filter(|cohort| cohort.status.counts_as_delivery())
                .count() as u64,
            oracle_reports: self.pq_oracle_reports.len() as u64,
            accepted_oracle_reports: self
                .pq_oracle_reports
                .values()
                .filter(|report| report.verdict.accepted())
                .count() as u64,
            collateral_escrows: self.collateral_escrows.len() as u64,
            locked_escrows: self
                .collateral_escrows
                .values()
                .filter(|escrow| escrow.status.locked())
                .count() as u64,
            settlement_events: self.settlement_events.len() as u64,
            finalized_settlements: self
                .settlement_events
                .values()
                .filter(|event| event.status == SettlementStatus::Finalized)
                .count() as u64,
            defaults: self
                .forward_contracts
                .values()
                .filter(|contract| contract.status == ForwardStatus::Defaulted)
                .count() as u64,
            insurance_claims: self.default_insurance_claims.len() as u64,
            paid_insurance_claims: self
                .default_insurance_claims
                .values()
                .filter(|claim| claim.status == InsuranceClaimStatus::Paid)
                .count() as u64,
            low_fee_rebates: self.low_fee_rebates.len() as u64,
            paid_low_fee_rebates: self
                .low_fee_rebates
                .values()
                .filter(|rebate| rebate.status == RebateStatus::Paid)
                .count() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            exhausted_redaction_budgets: self
                .redaction_budgets
                .values()
                .filter(|budget| budget.status == RedactionBudgetStatus::Exhausted)
                .count() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
        }
    }

    fn compute_roots(&self) -> Roots {
        let counters = self.compute_counters();
        let forward_leaves =
            values_as_records(self.forward_contracts.values(), |item| item.public_record());
        let cohort_leaves =
            values_as_records(self.delivery_cohorts.values(), |item| item.public_record());
        let report_leaves =
            values_as_records(self.pq_oracle_reports.values(), |item| item.public_record());
        let escrow_leaves = values_as_records(self.collateral_escrows.values(), |item| {
            item.public_record()
        });
        let event_leaves =
            values_as_records(self.settlement_events.values(), |item| item.public_record());
        let insurance_leaves = values_as_records(self.default_insurance_claims.values(), |item| {
            item.public_record()
        });
        let rebate_leaves =
            values_as_records(self.low_fee_rebates.values(), |item| item.public_record());
        let redaction_leaves =
            values_as_records(self.redaction_budgets.values(), |item| item.public_record());
        let summary_leaves = values_as_records(self.operator_summaries.values(), |item| {
            item.public_record()
        });
        let nullifier_leaves = self
            .spent_nullifiers
            .iter()
            .map(|nullifier| json!(nullifier))
            .collect::<Vec<_>>();

        let mut roots = Roots {
            config_root: self.config.state_root(),
            counters_root: counters.state_root(),
            forward_contract_root: merkle_root("forward-contracts", &forward_leaves),
            delivery_cohort_root: merkle_root("delivery-cohorts", &cohort_leaves),
            pq_oracle_report_root: merkle_root("pq-oracle-reports", &report_leaves),
            collateral_escrow_root: merkle_root("collateral-escrows", &escrow_leaves),
            settlement_event_root: merkle_root("settlement-events", &event_leaves),
            default_insurance_root: merkle_root("default-insurance", &insurance_leaves),
            low_fee_rebate_root: merkle_root("low-fee-rebates", &rebate_leaves),
            redaction_budget_root: merkle_root("redaction-budgets", &redaction_leaves),
            operator_summary_root: merkle_root("operator-summaries", &summary_leaves),
            nullifier_root: merkle_root("forward-settlement-nullifiers", &nullifier_leaves),
            state_root: String::new(),
        };
        roots.state_root = roots.state_root();
        roots
    }

    fn install_devnet_fixture(&mut self) {
        let contract_a = ForwardContract {
            id: "fwd-power-hash-001".to_string(),
            market: MarketKind::HybridPowerHashrate,
            buyer_commitment: commitment("buyer", "alpha"),
            seller_commitment: commitment("seller", "hashfarm-west"),
            notional_commitment: commitment("notional", "125000-xmrc"),
            delivery_commitment: commitment("delivery", "42mwh-780phs"),
            price_index_commitment: commitment("index", "ercot-west-hashprice"),
            collateral_policy_id: "margin-policy-devnet-001".to_string(),
            insurance_policy_id: "insurance-mutual-devnet-001".to_string(),
            start_l2_height: self.l2_height - 720,
            maturity_l2_height: self.l2_height + 1_440,
            settlement_asset_id: "confidential-xmr-forward-usd-index".to_string(),
            fee_bps: 14,
            status: ForwardStatus::Delivering,
            privacy_set_size: 524_288,
            pq_authorization_root: commitment("pq-auth", "fwd-power-hash-001"),
            nullifier: nullifier("forward", "fwd-power-hash-001"),
        };
        let contract_b = ForwardContract {
            id: "fwd-curtailment-002".to_string(),
            market: MarketKind::CurtailmentCredit,
            buyer_commitment: commitment("buyer", "beta"),
            seller_commitment: commitment("seller", "grid-flex-east"),
            notional_commitment: commitment("notional", "38000-xmrc"),
            delivery_commitment: commitment("delivery", "19mwh-curtailed"),
            price_index_commitment: commitment("index", "pjm-curtailment"),
            collateral_policy_id: "margin-policy-devnet-002".to_string(),
            insurance_policy_id: "insurance-mutual-devnet-001".to_string(),
            start_l2_height: self.l2_height - 360,
            maturity_l2_height: self.l2_height + 720,
            settlement_asset_id: "confidential-xmr-forward-usd-index".to_string(),
            fee_bps: 10,
            status: ForwardStatus::Open,
            privacy_set_size: 262_144,
            pq_authorization_root: commitment("pq-auth", "fwd-curtailment-002"),
            nullifier: nullifier("forward", "fwd-curtailment-002"),
        };
        let contract_c = ForwardContract {
            id: "fwd-hashrate-003".to_string(),
            market: MarketKind::HashratePhs,
            buyer_commitment: commitment("buyer", "gamma"),
            seller_commitment: commitment("seller", "pool-north"),
            notional_commitment: commitment("notional", "92000-xmrc"),
            delivery_commitment: commitment("delivery", "1200phs-days"),
            price_index_commitment: commitment("index", "monero-hashprice"),
            collateral_policy_id: "margin-policy-devnet-003".to_string(),
            insurance_policy_id: "insurance-mutual-devnet-002".to_string(),
            start_l2_height: self.l2_height - 1_440,
            maturity_l2_height: self.l2_height - 60,
            settlement_asset_id: "confidential-xmr-forward-usd-index".to_string(),
            fee_bps: 18,
            status: ForwardStatus::Defaulted,
            privacy_set_size: 131_072,
            pq_authorization_root: commitment("pq-auth", "fwd-hashrate-003"),
            nullifier: nullifier("forward", "fwd-hashrate-003"),
        };
        for contract in [contract_a, contract_b, contract_c] {
            let _ = self.add_forward_contract(contract);
        }

        let cohorts = vec![
            DeliveryCohort {
                id: "cohort-power-hash-001-a".to_string(),
                contract_id: "fwd-power-hash-001".to_string(),
                market: MarketKind::HybridPowerHashrate,
                cohort_start_height: self.l2_height - 720,
                cohort_end_height: self.l2_height - 360,
                grid_region_commitment: commitment("grid", "ercot-west"),
                miner_pool_commitment: commitment("pool", "west-ml-dsa"),
                expected_quantity_commitment: commitment("expected", "21mwh-390phs"),
                delivered_quantity_commitment: commitment("delivered", "20.6mwh-392phs"),
                renewable_fraction_bps: 6_200,
                curtailment_bps: 80,
                status: DeliveryStatus::Metered,
                oracle_report_ids: vec![
                    "oracle-meter-001".to_string(),
                    "oracle-hashrate-001".to_string(),
                ],
                redaction_budget_id: "redact-fwd-001".to_string(),
            },
            DeliveryCohort {
                id: "cohort-curtailment-002-a".to_string(),
                contract_id: "fwd-curtailment-002".to_string(),
                market: MarketKind::CurtailmentCredit,
                cohort_start_height: self.l2_height - 360,
                cohort_end_height: self.l2_height,
                grid_region_commitment: commitment("grid", "pjm-east"),
                miner_pool_commitment: commitment("pool", "not-applicable"),
                expected_quantity_commitment: commitment("expected", "9.5mwh"),
                delivered_quantity_commitment: commitment("delivered", "9.7mwh"),
                renewable_fraction_bps: 8_700,
                curtailment_bps: 1_140,
                status: DeliveryStatus::Delivered,
                oracle_report_ids: vec!["oracle-curtailment-002".to_string()],
                redaction_budget_id: "redact-fwd-002".to_string(),
            },
            DeliveryCohort {
                id: "cohort-hashrate-003-a".to_string(),
                contract_id: "fwd-hashrate-003".to_string(),
                market: MarketKind::HashratePhs,
                cohort_start_height: self.l2_height - 1_440,
                cohort_end_height: self.l2_height - 720,
                grid_region_commitment: commitment("grid", "unknown"),
                miner_pool_commitment: commitment("pool", "north"),
                expected_quantity_commitment: commitment("expected", "600phs-days"),
                delivered_quantity_commitment: commitment("delivered", "431phs-days"),
                renewable_fraction_bps: 4_100,
                curtailment_bps: 0,
                status: DeliveryStatus::Shortfall,
                oracle_report_ids: vec!["oracle-hashrate-003".to_string()],
                redaction_budget_id: "redact-fwd-003".to_string(),
            },
        ];
        for cohort in cohorts {
            let _ = self.add_delivery_cohort(cohort);
        }

        let reports = vec![
            PqOracleReport {
                id: "oracle-meter-001".to_string(),
                cohort_id: "cohort-power-hash-001-a".to_string(),
                reporter_commitment: commitment("oracle", "meter-west-001"),
                report_kind: OracleReportKind::MeterReading,
                l2_height: self.l2_height - 300,
                source_height: 88_201,
                measurement_commitment: commitment("measurement", "20.6mwh"),
                confidence_bps: 9_850,
                pq_signature_root: commitment("pq-sig", "oracle-meter-001"),
                transcript_root: commitment("transcript", "oracle-meter-001"),
                verdict: OracleVerdict::Accepted,
                expires_at_l2_height: self.l2_height + DEFAULT_ORACLE_REPORT_TTL_BLOCKS,
                nullifier: nullifier("oracle", "oracle-meter-001"),
            },
            PqOracleReport {
                id: "oracle-hashrate-001".to_string(),
                cohort_id: "cohort-power-hash-001-a".to_string(),
                reporter_commitment: commitment("oracle", "pool-west-001"),
                report_kind: OracleReportKind::PoolHashrate,
                l2_height: self.l2_height - 298,
                source_height: self.monero_height - 44,
                measurement_commitment: commitment("measurement", "392phs"),
                confidence_bps: 9_720,
                pq_signature_root: commitment("pq-sig", "oracle-hashrate-001"),
                transcript_root: commitment("transcript", "oracle-hashrate-001"),
                verdict: OracleVerdict::Accepted,
                expires_at_l2_height: self.l2_height + DEFAULT_ORACLE_REPORT_TTL_BLOCKS,
                nullifier: nullifier("oracle", "oracle-hashrate-001"),
            },
            PqOracleReport {
                id: "oracle-curtailment-002".to_string(),
                cohort_id: "cohort-curtailment-002-a".to_string(),
                reporter_commitment: commitment("oracle", "grid-east-002"),
                report_kind: OracleReportKind::GridCurtailment,
                l2_height: self.l2_height - 42,
                source_height: 192_010,
                measurement_commitment: commitment("measurement", "9.7mwh-curtailed"),
                confidence_bps: 9_900,
                pq_signature_root: commitment("pq-sig", "oracle-curtailment-002"),
                transcript_root: commitment("transcript", "oracle-curtailment-002"),
                verdict: OracleVerdict::Accepted,
                expires_at_l2_height: self.l2_height + DEFAULT_ORACLE_REPORT_TTL_BLOCKS,
                nullifier: nullifier("oracle", "oracle-curtailment-002"),
            },
            PqOracleReport {
                id: "oracle-hashrate-003".to_string(),
                cohort_id: "cohort-hashrate-003-a".to_string(),
                reporter_commitment: commitment("oracle", "pool-north-003"),
                report_kind: OracleReportKind::PoolHashrate,
                l2_height: self.l2_height - 620,
                source_height: self.monero_height - 91,
                measurement_commitment: commitment("measurement", "431phs-days"),
                confidence_bps: 8_940,
                pq_signature_root: commitment("pq-sig", "oracle-hashrate-003"),
                transcript_root: commitment("transcript", "oracle-hashrate-003"),
                verdict: OracleVerdict::Disputed,
                expires_at_l2_height: self.l2_height - 440,
                nullifier: nullifier("oracle", "oracle-hashrate-003"),
            },
        ];
        for report in reports {
            let _ = self.add_pq_oracle_report(report);
        }

        let escrows = vec![
            self.devnet_escrow(
                "escrow-fwd-001-buyer",
                "fwd-power-hash-001",
                ContractSide::Buyer,
            ),
            self.devnet_escrow(
                "escrow-fwd-001-seller",
                "fwd-power-hash-001",
                ContractSide::Seller,
            ),
            self.devnet_escrow(
                "escrow-fwd-002-buyer",
                "fwd-curtailment-002",
                ContractSide::Buyer,
            ),
            self.devnet_escrow(
                "escrow-fwd-002-seller",
                "fwd-curtailment-002",
                ContractSide::Seller,
            ),
            CollateralEscrow {
                id: "escrow-fwd-003-seller".to_string(),
                contract_id: "fwd-hashrate-003".to_string(),
                side: ContractSide::Seller,
                owner_commitment: commitment("owner", "escrow-fwd-003-seller"),
                collateral_asset_id: "confidential-xmr".to_string(),
                posted_commitment: commitment("posted", "shortfall-margin"),
                required_initial_margin_commitment: commitment("initial-margin", "fwd-003"),
                required_maintenance_margin_commitment: commitment("maintenance-margin", "fwd-003"),
                locked_until_l2_height: self.l2_height + DEFAULT_DISPUTE_WINDOW_BLOCKS,
                status: EscrowStatus::Liquidating,
                last_margin_call_height: Some(self.l2_height - 700),
                nullifier: nullifier("escrow", "escrow-fwd-003-seller"),
            },
        ];
        for escrow in escrows {
            let _ = self.add_collateral_escrow(escrow);
        }

        let event_root_before = self.state_root();
        let events = vec![
            SettlementEvent {
                id: "settle-open-001".to_string(),
                contract_id: "fwd-power-hash-001".to_string(),
                cohort_id: None,
                event_kind: SettlementEventKind::ContractOpened,
                status: SettlementStatus::Finalized,
                l2_height: self.l2_height - 720,
                amount_commitment: commitment("amount", "open-001"),
                fee_commitment: commitment("fee", "open-001"),
                settlement_root_before: event_root_before.clone(),
                settlement_root_after: commitment("settlement-after", "open-001"),
                operator_commitment: commitment("operator", "devnet-forward-operator"),
                note: "confidential hybrid power/hashrate forward opened".to_string(),
            },
            SettlementEvent {
                id: "settle-delivery-001".to_string(),
                contract_id: "fwd-power-hash-001".to_string(),
                cohort_id: Some("cohort-power-hash-001-a".to_string()),
                event_kind: SettlementEventKind::DeliveryCredited,
                status: SettlementStatus::Applied,
                l2_height: self.l2_height - 240,
                amount_commitment: commitment("amount", "delivery-001"),
                fee_commitment: commitment("fee", "delivery-001"),
                settlement_root_before: event_root_before.clone(),
                settlement_root_after: commitment("settlement-after", "delivery-001"),
                operator_commitment: commitment("operator", "devnet-forward-operator"),
                note: "meter and hashrate reports netted inside cohort tolerance".to_string(),
            },
            SettlementEvent {
                id: "settle-default-003".to_string(),
                contract_id: "fwd-hashrate-003".to_string(),
                cohort_id: Some("cohort-hashrate-003-a".to_string()),
                event_kind: SettlementEventKind::DefaultDeclared,
                status: SettlementStatus::Finalized,
                l2_height: self.l2_height - 120,
                amount_commitment: commitment("amount", "default-003"),
                fee_commitment: commitment("fee", "default-003"),
                settlement_root_before: event_root_before,
                settlement_root_after: commitment("settlement-after", "default-003"),
                operator_commitment: commitment("operator", "devnet-forward-operator"),
                note: "hashrate delivery shortfall exceeded tolerance".to_string(),
            },
        ];
        for event in events {
            let _ = self.add_settlement_event(event);
        }

        let claims = vec![DefaultInsuranceClaim {
            id: "claim-hashrate-003".to_string(),
            contract_id: "fwd-hashrate-003".to_string(),
            claimant_commitment: commitment("claimant", "buyer-gamma"),
            default_reason: DefaultReason::DeliveryShortfall,
            loss_commitment: commitment("loss", "fwd-hashrate-003"),
            insured_payout_commitment: commitment("payout", "fwd-hashrate-003"),
            premium_commitment: commitment("premium", "insurance-mutual-devnet-002"),
            evidence_root: commitment("evidence", "claim-hashrate-003"),
            status: InsuranceClaimStatus::Approved,
            opened_l2_height: self.l2_height - 118,
            paid_l2_height: None,
        }];
        for claim in claims {
            let _ = self.add_default_insurance_claim(claim);
        }

        let rebates = vec![
            LowFeeRebate {
                id: "rebate-fwd-001".to_string(),
                contract_id: "fwd-power-hash-001".to_string(),
                beneficiary_commitment: commitment("beneficiary", "buyer-alpha"),
                fee_asset_id: "confidential-xmr".to_string(),
                gross_fee_commitment: commitment("gross-fee", "fwd-001"),
                rebate_commitment: commitment("rebate", "fwd-001"),
                rebate_bps: 18,
                status: RebateStatus::Applied,
                reserved_l2_height: self.l2_height - 719,
                paid_l2_height: None,
            },
            LowFeeRebate {
                id: "rebate-fwd-002".to_string(),
                contract_id: "fwd-curtailment-002".to_string(),
                beneficiary_commitment: commitment("beneficiary", "grid-flex-east"),
                fee_asset_id: "confidential-xmr".to_string(),
                gross_fee_commitment: commitment("gross-fee", "fwd-002"),
                rebate_commitment: commitment("rebate", "fwd-002"),
                rebate_bps: 10,
                status: RebateStatus::Reserved,
                reserved_l2_height: self.l2_height - 359,
                paid_l2_height: None,
            },
        ];
        for rebate in rebates {
            let _ = self.add_low_fee_rebate(rebate);
        }

        let budgets = vec![
            RedactionBudget {
                id: "redact-fwd-001".to_string(),
                subject_commitment: commitment("subject", "fwd-power-hash-001"),
                epoch: self.epoch,
                allowance: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
                spent: 11,
                purpose_root: commitment("purpose", "operator-safety-summary"),
                status: RedactionBudgetStatus::Available,
                last_spent_l2_height: Some(self.l2_height - 12),
            },
            RedactionBudget {
                id: "redact-fwd-002".to_string(),
                subject_commitment: commitment("subject", "fwd-curtailment-002"),
                epoch: self.epoch,
                allowance: DEFAULT_REDACTION_BUDGET_PER_EPOCH,
                spent: 7,
                purpose_root: commitment("purpose", "oracle-median-disclosure"),
                status: RedactionBudgetStatus::Available,
                last_spent_l2_height: Some(self.l2_height - 8),
            },
            RedactionBudget {
                id: "redact-fwd-003".to_string(),
                subject_commitment: commitment("subject", "fwd-hashrate-003"),
                epoch: self.epoch,
                allowance: 16,
                spent: 16,
                purpose_root: commitment("purpose", "default-evidence"),
                status: RedactionBudgetStatus::Exhausted,
                last_spent_l2_height: Some(self.l2_height - 110),
            },
        ];
        for budget in budgets {
            let _ = self.add_redaction_budget(budget);
        }

        let summary = OperatorSummary {
            id: "operator-summary-devnet-2818".to_string(),
            operator_commitment: commitment("operator", "devnet-forward-operator"),
            epoch: self.epoch,
            active_contracts: 2,
            delivery_cohorts: 3,
            accepted_oracle_reports: 3,
            disputed_oracle_reports: 1,
            settled_contracts: 0,
            defaulted_contracts: 1,
            escrow_health_bps: 8_940,
            rebate_liability_commitment: commitment("rebate-liability", "epoch-2818"),
            insurance_liability_commitment: commitment("insurance-liability", "epoch-2818"),
            redaction_spend: 34,
            summary_root: commitment("summary", "operator-summary-devnet-2818"),
        };
        let _ = self.add_operator_summary(summary);
    }

    fn devnet_escrow(&self, id: &str, contract_id: &str, side: ContractSide) -> CollateralEscrow {
        CollateralEscrow {
            id: id.to_string(),
            contract_id: contract_id.to_string(),
            side,
            owner_commitment: commitment("owner", id),
            collateral_asset_id: "confidential-xmr".to_string(),
            posted_commitment: commitment("posted", id),
            required_initial_margin_commitment: commitment("initial-margin", contract_id),
            required_maintenance_margin_commitment: commitment("maintenance-margin", contract_id),
            locked_until_l2_height: self.l2_height + DEFAULT_DISPUTE_WINDOW_BLOCKS,
            status: EscrowStatus::MarginHealthy,
            last_margin_call_height: None,
            nullifier: nullifier("escrow", id),
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn demo() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

pub fn operator_summary(state: &State) -> Value {
    state.operator_public_summary()
}

pub fn state_root_from_public_record(record: &Value) -> String {
    domain_hash(PUBLIC_RECORD_SUITE, &[HashPart::Json(record)], 32)
}

fn values_as_records<'a, T, I, F>(values: I, mut f: F) -> Vec<Value>
where
    I: IntoIterator<Item = &'a T>,
    T: 'a,
    F: FnMut(&'a T) -> Value,
{
    values.into_iter().map(|value| f(value)).collect()
}

fn commitment(domain: &str, seed: &str) -> String {
    domain_hash(
        "confidential-forward-commitment",
        &[HashPart::Str(domain), HashPart::Str(seed)],
        32,
    )
}

fn nullifier(domain: &str, seed: &str) -> String {
    domain_hash(
        "confidential-forward-nullifier",
        &[HashPart::Str(domain), HashPart::Str(seed)],
        32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devnet_public_record_has_stable_state_root() {
        let state = State::devnet();
        assert_eq!(state.state_root(), state.roots.state_root);
        assert_eq!(
            state.public_record()["state_root"],
            json!(state.state_root())
        );
    }

    #[test]
    fn duplicate_forward_nullifier_is_rejected() {
        let mut state = State::default();
        let contract = ForwardContract {
            id: "fwd-test".to_string(),
            market: MarketKind::PowerMwh,
            buyer_commitment: commitment("buyer", "test"),
            seller_commitment: commitment("seller", "test"),
            notional_commitment: commitment("notional", "test"),
            delivery_commitment: commitment("delivery", "test"),
            price_index_commitment: commitment("index", "test"),
            collateral_policy_id: "policy".to_string(),
            insurance_policy_id: "insurance".to_string(),
            start_l2_height: 1,
            maturity_l2_height: 2,
            settlement_asset_id: "asset".to_string(),
            fee_bps: 1,
            status: ForwardStatus::Open,
            privacy_set_size: 1,
            pq_authorization_root: commitment("pq", "test"),
            nullifier: nullifier("forward", "same"),
        };
        assert!(state.add_forward_contract(contract.clone()).is_ok());
        let mut duplicate = contract;
        duplicate.id = "fwd-test-2".to_string();
        assert!(state.add_forward_contract(duplicate).is_err());
    }
}
