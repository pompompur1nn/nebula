use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingctViewtagFeeRebateOracleRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-ringct-viewtag-fee-rebate-oracle-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_PROTOCOL_VERSION;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_SCHEMA_VERSION: u64 = 1;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_HASH_SUITE: &str =
    "SHAKE256-domain-separated-canonical-json";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_ATTESTATION_SCHEME: &str =
    "ml-dsa-87+slh-dsa-shake-192f-ringct-viewtag-fee-rebate-oracle-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_REDACTION_SCHEME: &str =
    "bounded-operator-safe-ringct-viewtag-redaction-budget-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_SETTLEMENT_SCHEME: &str =
    "private-sponsor-fee-rebate-settlement-root-v1";
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEVNET_HEIGHT: u64 =
    741_440;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEVNET_EPOCH: u64 = 88;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MAX_BPS: u64 = 10_000;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_DECOYS: u64 = 15;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_COHORT_OUTPUTS: u64 =
    4_096;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_PRIVACY_SCORE_BPS: u64 =
    8_600;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_TARGET_VIEWTAG_PRESSURE_BPS:
    u64 = 5_000;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEFAULT_REBATE_BPS: u64 =
    125;
pub const MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEFAULT_SPONSOR_BUFFER_BPS:
    u64 = 2_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStatus {
    Draft,
    Scanning,
    Measured,
    Guarded,
    RebateEligible,
    Settled,
    Quarantined,
}

impl CohortStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scanning => "scanning",
            Self::Measured => "measured",
            Self::Guarded => "guarded",
            Self::RebateEligible => "rebate_eligible",
            Self::Settled => "settled",
            Self::Quarantined => "quarantined",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureBand {
    Low,
    Normal,
    Elevated,
    Congested,
    Critical,
}

impl PressureBand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Elevated => "elevated",
            Self::Congested => "congested",
            Self::Critical => "critical",
        }
    }

    pub fn from_bps(value: u64) -> Self {
        match value {
            0..=3_499 => Self::Low,
            3_500..=5_499 => Self::Normal,
            5_500..=7_499 => Self::Elevated,
            7_500..=8_999 => Self::Congested,
            _ => Self::Critical,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebateSignalKind {
    BaseFeeRelief,
    ViewtagPressureRelief,
    DecoyQualityReward,
    SponsorInventoryRebalance,
    EmergencyPrivacyCredit,
}

impl RebateSignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BaseFeeRelief => "base_fee_relief",
            Self::ViewtagPressureRelief => "viewtag_pressure_relief",
            Self::DecoyQualityReward => "decoy_quality_reward",
            Self::SponsorInventoryRebalance => "sponsor_inventory_rebalance",
            Self::EmergencyPrivacyCredit => "emergency_privacy_credit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Pending,
    Accepted,
    Superseded,
    Challenged,
    Revoked,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Challenged => "challenged",
            Self::Revoked => "revoked",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafeguardSeverity {
    Informational,
    Warning,
    Hold,
    Quarantine,
}

impl SafeguardSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Warning => "warning",
            Self::Hold => "hold",
            Self::Quarantine => "quarantine",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    Reserved,
    Netting,
    Payable,
    Paid,
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Netting => "netting",
            Self::Payable => "payable",
            Self::Paid => "paid",
            Self::Disputed => "disputed",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub monero_network: String,
    pub l2_network: String,
    pub fee_asset_id: String,
    pub rebate_asset_id: String,
    pub oracle_committee_id: String,
    pub settlement_sponsor_set_id: String,
    pub devnet_height: u64,
    pub devnet_epoch: u64,
    pub min_decoys: u64,
    pub min_cohort_outputs: u64,
    pub min_privacy_score_bps: u64,
    pub target_viewtag_pressure_bps: u64,
    pub default_rebate_bps: u64,
    pub sponsor_buffer_bps: u64,
    pub max_operator_redactions_per_epoch: u64,
    pub max_public_hint_bytes_per_report: u64,
    pub pq_attestation_scheme: String,
    pub redaction_scheme: String,
    pub settlement_scheme: String,
    pub hash_suite: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_SCHEMA_VERSION,
            monero_network: "monero-devnet".to_string(),
            l2_network: "nebula-devnet".to_string(),
            fee_asset_id: "piconero-devnet".to_string(),
            rebate_asset_id: "private-fee-credit-devnet".to_string(),
            oracle_committee_id: "pq-ringct-viewtag-oracle-committee-devnet".to_string(),
            settlement_sponsor_set_id: "viewtag-fee-rebate-sponsors-devnet".to_string(),
            devnet_height:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEVNET_HEIGHT,
            devnet_epoch: MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEVNET_EPOCH,
            min_decoys: MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_DECOYS,
            min_cohort_outputs:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_COHORT_OUTPUTS,
            min_privacy_score_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MIN_PRIVACY_SCORE_BPS,
            target_viewtag_pressure_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_TARGET_VIEWTAG_PRESSURE_BPS,
            default_rebate_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEFAULT_REBATE_BPS,
            sponsor_buffer_bps:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_DEFAULT_SPONSOR_BUFFER_BPS,
            max_operator_redactions_per_epoch: 128,
            max_public_hint_bytes_per_report: 512,
            pq_attestation_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_ATTESTATION_SCHEME
                    .to_string(),
            redaction_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_REDACTION_SCHEME
                    .to_string(),
            settlement_scheme:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_SETTLEMENT_SCHEME
                    .to_string(),
            hash_suite:
                MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_HASH_SUITE
                    .to_string(),
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "fee_asset_id": self.fee_asset_id,
            "rebate_asset_id": self.rebate_asset_id,
            "oracle_committee_id": self.oracle_committee_id,
            "settlement_sponsor_set_id": self.settlement_sponsor_set_id,
            "devnet_height": self.devnet_height,
            "devnet_epoch": self.devnet_epoch,
            "min_decoys": self.min_decoys,
            "min_cohort_outputs": self.min_cohort_outputs,
            "min_privacy_score_bps": self.min_privacy_score_bps,
            "target_viewtag_pressure_bps": self.target_viewtag_pressure_bps,
            "default_rebate_bps": self.default_rebate_bps,
            "sponsor_buffer_bps": self.sponsor_buffer_bps,
            "max_operator_redactions_per_epoch": self.max_operator_redactions_per_epoch,
            "max_public_hint_bytes_per_report": self.max_public_hint_bytes_per_report,
            "pq_attestation_scheme": self.pq_attestation_scheme,
            "redaction_scheme": self.redaction_scheme,
            "settlement_scheme": self.settlement_scheme,
            "hash_suite": self.hash_suite,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Counters {
    pub scan_cohorts: u64,
    pub pressure_reports: u64,
    pub rebate_signals: u64,
    pub pq_attestations: u64,
    pub decoy_safeguards: u64,
    pub sponsor_settlements: u64,
    pub redaction_budgets: u64,
    pub operator_summaries: u64,
    pub quarantined_cohorts: u64,
    pub payable_rebates: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scan_cohorts": self.scan_cohorts,
            "pressure_reports": self.pressure_reports,
            "rebate_signals": self.rebate_signals,
            "pq_attestations": self.pq_attestations,
            "decoy_safeguards": self.decoy_safeguards,
            "sponsor_settlements": self.sponsor_settlements,
            "redaction_budgets": self.redaction_budgets,
            "operator_summaries": self.operator_summaries,
            "quarantined_cohorts": self.quarantined_cohorts,
            "payable_rebates": self.payable_rebates,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RingCtScanCohort {
    pub cohort_id: String,
    pub scan_epoch: u64,
    pub first_monero_height: u64,
    pub last_monero_height: u64,
    pub output_count: u64,
    pub scanned_output_commitment_root: String,
    pub viewtag_bucket_root: String,
    pub decoy_age_histogram_root: String,
    pub ring_member_commitment_root: String,
    pub median_ring_size: u64,
    pub min_ring_size: u64,
    pub viewtag_match_count: u64,
    pub encrypted_scan_note_root: String,
    pub status: CohortStatus,
}

impl RingCtScanCohort {
    pub fn viewtag_pressure_bps(&self) -> u64 {
        if self.output_count == 0 {
            return 0;
        }
        self.viewtag_match_count.saturating_mul(10_000) / self.output_count
    }

    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "scan_epoch": self.scan_epoch,
            "first_monero_height": self.first_monero_height,
            "last_monero_height": self.last_monero_height,
            "output_count": self.output_count,
            "scanned_output_commitment_root": self.scanned_output_commitment_root,
            "viewtag_bucket_root": self.viewtag_bucket_root,
            "decoy_age_histogram_root": self.decoy_age_histogram_root,
            "ring_member_commitment_root": self.ring_member_commitment_root,
            "median_ring_size": self.median_ring_size,
            "min_ring_size": self.min_ring_size,
            "viewtag_match_count": self.viewtag_match_count,
            "viewtag_pressure_bps": self.viewtag_pressure_bps(),
            "encrypted_scan_note_root": self.encrypted_scan_note_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-FEE-REBATE-COHORT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViewtagPressureReport {
    pub report_id: String,
    pub cohort_id: String,
    pub oracle_round: u64,
    pub pressure_band: PressureBand,
    pub pressure_bps: u64,
    pub rolling_pressure_bps: u64,
    pub scan_latency_ms_p50: u64,
    pub scan_latency_ms_p95: u64,
    pub wallet_rescan_cost_microunits: u64,
    pub false_positive_floor_bps: u64,
    pub public_hint_root: String,
    pub redacted_detail_root: String,
}

impl ViewtagPressureReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "cohort_id": self.cohort_id,
            "oracle_round": self.oracle_round,
            "pressure_band": self.pressure_band.as_str(),
            "pressure_bps": self.pressure_bps,
            "rolling_pressure_bps": self.rolling_pressure_bps,
            "scan_latency_ms_p50": self.scan_latency_ms_p50,
            "scan_latency_ms_p95": self.scan_latency_ms_p95,
            "wallet_rescan_cost_microunits": self.wallet_rescan_cost_microunits,
            "false_positive_floor_bps": self.false_positive_floor_bps,
            "public_hint_root": self.public_hint_root,
            "redacted_detail_root": self.redacted_detail_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-PRESSURE-REPORT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeeRebateSignal {
    pub signal_id: String,
    pub cohort_id: String,
    pub report_id: String,
    pub kind: RebateSignalKind,
    pub rebate_bps: u64,
    pub max_rebate_piconero: u64,
    pub min_privacy_score_bps: u64,
    pub eligible_output_count: u64,
    pub sponsor_pool_id: String,
    pub activation_height: u64,
    pub expiry_height: u64,
    pub nullifier_domain_root: String,
}

impl FeeRebateSignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "cohort_id": self.cohort_id,
            "report_id": self.report_id,
            "kind": self.kind.as_str(),
            "rebate_bps": self.rebate_bps,
            "max_rebate_piconero": self.max_rebate_piconero,
            "min_privacy_score_bps": self.min_privacy_score_bps,
            "eligible_output_count": self.eligible_output_count,
            "sponsor_pool_id": self.sponsor_pool_id,
            "activation_height": self.activation_height,
            "expiry_height": self.expiry_height,
            "nullifier_domain_root": self.nullifier_domain_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-FEE-REBATE-SIGNAL",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqOracleAttestation {
    pub attestation_id: String,
    pub oracle_node_id: String,
    pub committee_id: String,
    pub round: u64,
    pub cohort_id: String,
    pub report_id: String,
    pub signal_id: String,
    pub statement_root: String,
    pub pq_public_key_commitment: String,
    pub signature_commitment: String,
    pub transcript_root: String,
    pub status: AttestationStatus,
}

impl PqOracleAttestation {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "oracle_node_id": self.oracle_node_id,
            "committee_id": self.committee_id,
            "round": self.round,
            "cohort_id": self.cohort_id,
            "report_id": self.report_id,
            "signal_id": self.signal_id,
            "statement_root": self.statement_root,
            "pq_public_key_commitment": self.pq_public_key_commitment,
            "signature_commitment": self.signature_commitment,
            "transcript_root": self.transcript_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "PQ-RINGCT-VIEWTAG-FEE-REBATE-ORACLE-ATTESTATION",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecoyQualitySafeguard {
    pub safeguard_id: String,
    pub cohort_id: String,
    pub severity: SafeguardSeverity,
    pub min_ring_size: u64,
    pub median_ring_size: u64,
    pub young_decoy_share_bps: u64,
    pub reused_decoy_share_bps: u64,
    pub cluster_entropy_bps: u64,
    pub privacy_score_bps: u64,
    pub hold_rebate: bool,
    pub reason_code: String,
    pub remediation_hint_root: String,
}

impl DecoyQualitySafeguard {
    pub fn passes(&self, config: &Config) -> bool {
        !self.hold_rebate
            && self.min_ring_size >= config.min_decoys
            && self.privacy_score_bps >= config.min_privacy_score_bps
            && self.severity < SafeguardSeverity::Hold
    }

    pub fn public_record(&self) -> Value {
        json!({
            "safeguard_id": self.safeguard_id,
            "cohort_id": self.cohort_id,
            "severity": self.severity.as_str(),
            "min_ring_size": self.min_ring_size,
            "median_ring_size": self.median_ring_size,
            "young_decoy_share_bps": self.young_decoy_share_bps,
            "reused_decoy_share_bps": self.reused_decoy_share_bps,
            "cluster_entropy_bps": self.cluster_entropy_bps,
            "privacy_score_bps": self.privacy_score_bps,
            "hold_rebate": self.hold_rebate,
            "reason_code": self.reason_code,
            "remediation_hint_root": self.remediation_hint_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-DECOY-QUALITY-SAFEGUARD",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SponsorSettlement {
    pub settlement_id: String,
    pub sponsor_id: String,
    pub sponsor_pool_id: String,
    pub signal_id: String,
    pub cohort_id: String,
    pub payable_rebate_piconero: u64,
    pub reserved_rebate_piconero: u64,
    pub sponsor_fee_piconero: u64,
    pub netted_rebate_piconero: u64,
    pub claim_count: u64,
    pub settlement_height: u64,
    pub claim_nullifier_root: String,
    pub receipt_root: String,
    pub status: SettlementStatus,
}

impl SponsorSettlement {
    pub fn public_record(&self) -> Value {
        json!({
            "settlement_id": self.settlement_id,
            "sponsor_id": self.sponsor_id,
            "sponsor_pool_id": self.sponsor_pool_id,
            "signal_id": self.signal_id,
            "cohort_id": self.cohort_id,
            "payable_rebate_piconero": self.payable_rebate_piconero,
            "reserved_rebate_piconero": self.reserved_rebate_piconero,
            "sponsor_fee_piconero": self.sponsor_fee_piconero,
            "netted_rebate_piconero": self.netted_rebate_piconero,
            "claim_count": self.claim_count,
            "settlement_height": self.settlement_height,
            "claim_nullifier_root": self.claim_nullifier_root,
            "receipt_root": self.receipt_root,
            "status": self.status.as_str(),
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-SPONSOR-SETTLEMENT",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RedactionBudget {
    pub budget_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub allowed_redactions: u64,
    pub used_redactions: u64,
    pub allowed_public_hint_bytes: u64,
    pub used_public_hint_bytes: u64,
    pub withheld_field_root: String,
    pub budget_commitment_root: String,
}

impl RedactionBudget {
    pub fn remaining_redactions(&self) -> u64 {
        self.allowed_redactions.saturating_sub(self.used_redactions)
    }

    pub fn remaining_public_hint_bytes(&self) -> u64 {
        self.allowed_public_hint_bytes
            .saturating_sub(self.used_public_hint_bytes)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "allowed_redactions": self.allowed_redactions,
            "used_redactions": self.used_redactions,
            "remaining_redactions": self.remaining_redactions(),
            "allowed_public_hint_bytes": self.allowed_public_hint_bytes,
            "used_public_hint_bytes": self.used_public_hint_bytes,
            "remaining_public_hint_bytes": self.remaining_public_hint_bytes(),
            "withheld_field_root": self.withheld_field_root,
            "budget_commitment_root": self.budget_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-REDACTION-BUDGET",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorSafeSummary {
    pub summary_id: String,
    pub operator_id: String,
    pub epoch: u64,
    pub cohort_count: u64,
    pub report_count: u64,
    pub eligible_rebate_count: u64,
    pub quarantined_cohort_count: u64,
    pub median_pressure_bps: u64,
    pub max_pressure_band: PressureBand,
    pub aggregate_payable_rebate_piconero: u64,
    pub public_summary_root: String,
    pub private_detail_commitment_root: String,
}

impl OperatorSafeSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "operator_id": self.operator_id,
            "epoch": self.epoch,
            "cohort_count": self.cohort_count,
            "report_count": self.report_count,
            "eligible_rebate_count": self.eligible_rebate_count,
            "quarantined_cohort_count": self.quarantined_cohort_count,
            "median_pressure_bps": self.median_pressure_bps,
            "max_pressure_band": self.max_pressure_band.as_str(),
            "aggregate_payable_rebate_piconero": self.aggregate_payable_rebate_piconero,
            "public_summary_root": self.public_summary_root,
            "private_detail_commitment_root": self.private_detail_commitment_root,
        })
    }

    pub fn root(&self) -> String {
        domain_hash(
            "RINGCT-VIEWTAG-OPERATOR-SAFE-SUMMARY",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Roots {
    pub cohort_root: String,
    pub pressure_report_root: String,
    pub rebate_signal_root: String,
    pub pq_attestation_root: String,
    pub decoy_safeguard_root: String,
    pub sponsor_settlement_root: String,
    pub redaction_budget_root: String,
    pub operator_summary_root: String,
    pub eligible_cohort_root: String,
    pub quarantine_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_root": self.cohort_root,
            "pressure_report_root": self.pressure_report_root,
            "rebate_signal_root": self.rebate_signal_root,
            "pq_attestation_root": self.pq_attestation_root,
            "decoy_safeguard_root": self.decoy_safeguard_root,
            "sponsor_settlement_root": self.sponsor_settlement_root,
            "redaction_budget_root": self.redaction_budget_root,
            "operator_summary_root": self.operator_summary_root,
            "eligible_cohort_root": self.eligible_cohort_root,
            "quarantine_root": self.quarantine_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub scan_cohorts: BTreeMap<String, RingCtScanCohort>,
    pub pressure_reports: BTreeMap<String, ViewtagPressureReport>,
    pub rebate_signals: BTreeMap<String, FeeRebateSignal>,
    pub pq_attestations: BTreeMap<String, PqOracleAttestation>,
    pub decoy_safeguards: BTreeMap<String, DecoyQualitySafeguard>,
    pub sponsor_settlements: BTreeMap<String, SponsorSettlement>,
    pub redaction_budgets: BTreeMap<String, RedactionBudget>,
    pub operator_summaries: BTreeMap<String, OperatorSafeSummary>,
    pub eligible_cohorts: BTreeSet<String>,
    pub quarantined_cohorts: BTreeSet<String>,
}

impl Default for State {
    fn default() -> Self {
        let mut state = Self {
            config: Config::default(),
            counters: Counters::default(),
            roots: Roots::default(),
            scan_cohorts: BTreeMap::new(),
            pressure_reports: BTreeMap::new(),
            rebate_signals: BTreeMap::new(),
            pq_attestations: BTreeMap::new(),
            decoy_safeguards: BTreeMap::new(),
            sponsor_settlements: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            operator_summaries: BTreeMap::new(),
            eligible_cohorts: BTreeSet::new(),
            quarantined_cohorts: BTreeSet::new(),
        };
        state.recompute();
        state
    }
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::default();
        let mut state = Self {
            config: config.clone(),
            ..Self::default()
        };

        let cohort_a = RingCtScanCohort {
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            scan_epoch: config.devnet_epoch,
            first_monero_height: config.devnet_height - 720,
            last_monero_height: config.devnet_height - 361,
            output_count: 18_432,
            scanned_output_commitment_root: sample_root("cohort-a-scanned-output", 18_432),
            viewtag_bucket_root: sample_root("cohort-a-viewtag-bucket", 256),
            decoy_age_histogram_root: sample_root("cohort-a-decoy-age-histogram", 64),
            ring_member_commitment_root: sample_root("cohort-a-ring-member", 294_912),
            median_ring_size: 16,
            min_ring_size: 16,
            viewtag_match_count: 8_816,
            encrypted_scan_note_root: sample_root("cohort-a-encrypted-scan-note", 24),
            status: CohortStatus::RebateEligible,
        };
        let cohort_b = RingCtScanCohort {
            cohort_id: "ringct-viewtag-cohort-devnet-088-b".to_string(),
            scan_epoch: config.devnet_epoch,
            first_monero_height: config.devnet_height - 360,
            last_monero_height: config.devnet_height,
            output_count: 21_504,
            scanned_output_commitment_root: sample_root("cohort-b-scanned-output", 21_504),
            viewtag_bucket_root: sample_root("cohort-b-viewtag-bucket", 256),
            decoy_age_histogram_root: sample_root("cohort-b-decoy-age-histogram", 64),
            ring_member_commitment_root: sample_root("cohort-b-ring-member", 344_064),
            median_ring_size: 16,
            min_ring_size: 14,
            viewtag_match_count: 12_176,
            encrypted_scan_note_root: sample_root("cohort-b-encrypted-scan-note", 24),
            status: CohortStatus::Guarded,
        };

        state.insert_scan_cohort(cohort_a);
        state.insert_scan_cohort(cohort_b);

        let report_a = ViewtagPressureReport {
            report_id: "viewtag-pressure-report-devnet-088-a".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            oracle_round: 88_001,
            pressure_band: PressureBand::Normal,
            pressure_bps: 4_783,
            rolling_pressure_bps: 4_912,
            scan_latency_ms_p50: 18,
            scan_latency_ms_p95: 44,
            wallet_rescan_cost_microunits: 92_000,
            false_positive_floor_bps: 39,
            public_hint_root: sample_root("report-a-public-hint", 8),
            redacted_detail_root: sample_root("report-a-redacted-detail", 16),
        };
        let report_b = ViewtagPressureReport {
            report_id: "viewtag-pressure-report-devnet-088-b".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-b".to_string(),
            oracle_round: 88_002,
            pressure_band: PressureBand::Elevated,
            pressure_bps: 5_662,
            rolling_pressure_bps: 5_221,
            scan_latency_ms_p50: 27,
            scan_latency_ms_p95: 73,
            wallet_rescan_cost_microunits: 151_000,
            false_positive_floor_bps: 44,
            public_hint_root: sample_root("report-b-public-hint", 8),
            redacted_detail_root: sample_root("report-b-redacted-detail", 16),
        };
        state.insert_pressure_report(report_a);
        state.insert_pressure_report(report_b);

        let signal_a = FeeRebateSignal {
            signal_id: "fee-rebate-signal-devnet-088-a".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            report_id: "viewtag-pressure-report-devnet-088-a".to_string(),
            kind: RebateSignalKind::BaseFeeRelief,
            rebate_bps: config.default_rebate_bps,
            max_rebate_piconero: 750_000_000,
            min_privacy_score_bps: config.min_privacy_score_bps,
            eligible_output_count: 17_920,
            sponsor_pool_id: "sponsor-pool-viewtag-devnet-primary".to_string(),
            activation_height: config.devnet_height + 1,
            expiry_height: config.devnet_height + 720,
            nullifier_domain_root: sample_root("signal-a-nullifier-domain", 32),
        };
        let signal_b = FeeRebateSignal {
            signal_id: "fee-rebate-signal-devnet-088-b".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-b".to_string(),
            report_id: "viewtag-pressure-report-devnet-088-b".to_string(),
            kind: RebateSignalKind::ViewtagPressureRelief,
            rebate_bps: 175,
            max_rebate_piconero: 1_050_000_000,
            min_privacy_score_bps: config.min_privacy_score_bps + 200,
            eligible_output_count: 0,
            sponsor_pool_id: "sponsor-pool-viewtag-devnet-primary".to_string(),
            activation_height: config.devnet_height + 1,
            expiry_height: config.devnet_height + 360,
            nullifier_domain_root: sample_root("signal-b-nullifier-domain", 32),
        };
        state.insert_rebate_signal(signal_a);
        state.insert_rebate_signal(signal_b);

        state.insert_decoy_safeguard(DecoyQualitySafeguard {
            safeguard_id: "decoy-quality-safeguard-devnet-088-a".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            severity: SafeguardSeverity::Informational,
            min_ring_size: 16,
            median_ring_size: 16,
            young_decoy_share_bps: 2_180,
            reused_decoy_share_bps: 17,
            cluster_entropy_bps: 9_240,
            privacy_score_bps: 9_180,
            hold_rebate: false,
            reason_code: "decoy_quality_within_guardrails".to_string(),
            remediation_hint_root: sample_root("safeguard-a-remediation", 4),
        });
        state.insert_decoy_safeguard(DecoyQualitySafeguard {
            safeguard_id: "decoy-quality-safeguard-devnet-088-b".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-b".to_string(),
            severity: SafeguardSeverity::Hold,
            min_ring_size: 14,
            median_ring_size: 16,
            young_decoy_share_bps: 3_540,
            reused_decoy_share_bps: 92,
            cluster_entropy_bps: 8_210,
            privacy_score_bps: 8_420,
            hold_rebate: true,
            reason_code: "low_min_ring_size_and_entropy_hold".to_string(),
            remediation_hint_root: sample_root("safeguard-b-remediation", 4),
        });

        state.insert_pq_attestation(PqOracleAttestation {
            attestation_id: "pq-oracle-attestation-devnet-088-a".to_string(),
            oracle_node_id: "oracle-node-ml-dsa-87-01".to_string(),
            committee_id: config.oracle_committee_id.clone(),
            round: 88_001,
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            report_id: "viewtag-pressure-report-devnet-088-a".to_string(),
            signal_id: "fee-rebate-signal-devnet-088-a".to_string(),
            statement_root: sample_root("attestation-a-statement", 1),
            pq_public_key_commitment: sample_root("attestation-a-pq-public-key", 1),
            signature_commitment: sample_root("attestation-a-signature", 1),
            transcript_root: sample_root("attestation-a-transcript", 5),
            status: AttestationStatus::Accepted,
        });
        state.insert_pq_attestation(PqOracleAttestation {
            attestation_id: "pq-oracle-attestation-devnet-088-b".to_string(),
            oracle_node_id: "oracle-node-slh-dsa-02".to_string(),
            committee_id: config.oracle_committee_id.clone(),
            round: 88_002,
            cohort_id: "ringct-viewtag-cohort-devnet-088-b".to_string(),
            report_id: "viewtag-pressure-report-devnet-088-b".to_string(),
            signal_id: "fee-rebate-signal-devnet-088-b".to_string(),
            statement_root: sample_root("attestation-b-statement", 1),
            pq_public_key_commitment: sample_root("attestation-b-pq-public-key", 1),
            signature_commitment: sample_root("attestation-b-signature", 1),
            transcript_root: sample_root("attestation-b-transcript", 5),
            status: AttestationStatus::Pending,
        });

        state.insert_sponsor_settlement(SponsorSettlement {
            settlement_id: "sponsor-settlement-devnet-088-a".to_string(),
            sponsor_id: "rebate-sponsor-devnet-alameda-lab".to_string(),
            sponsor_pool_id: "sponsor-pool-viewtag-devnet-primary".to_string(),
            signal_id: "fee-rebate-signal-devnet-088-a".to_string(),
            cohort_id: "ringct-viewtag-cohort-devnet-088-a".to_string(),
            payable_rebate_piconero: 412_500_000,
            reserved_rebate_piconero: 550_000_000,
            sponsor_fee_piconero: 8_250_000,
            netted_rebate_piconero: 404_250_000,
            claim_count: 5_216,
            settlement_height: config.devnet_height + 42,
            claim_nullifier_root: sample_root("settlement-a-claim-nullifier", 5_216),
            receipt_root: sample_root("settlement-a-receipt", 5_216),
            status: SettlementStatus::Payable,
        });

        state.insert_redaction_budget(RedactionBudget {
            budget_id: "redaction-budget-devnet-operator-01-088".to_string(),
            operator_id: "operator-viewtag-oracle-devnet-01".to_string(),
            epoch: config.devnet_epoch,
            allowed_redactions: config.max_operator_redactions_per_epoch,
            used_redactions: 19,
            allowed_public_hint_bytes: config.max_public_hint_bytes_per_report * 16,
            used_public_hint_bytes: 2_944,
            withheld_field_root: sample_root("operator-01-withheld-fields", 19),
            budget_commitment_root: sample_root("operator-01-redaction-budget", 1),
        });

        state.insert_operator_summary(OperatorSafeSummary {
            summary_id: "operator-safe-summary-devnet-088".to_string(),
            operator_id: "operator-viewtag-oracle-devnet-01".to_string(),
            epoch: config.devnet_epoch,
            cohort_count: 2,
            report_count: 2,
            eligible_rebate_count: 1,
            quarantined_cohort_count: 0,
            median_pressure_bps: 5_221,
            max_pressure_band: PressureBand::Elevated,
            aggregate_payable_rebate_piconero: 412_500_000,
            public_summary_root: sample_root("operator-summary-public", 1),
            private_detail_commitment_root: sample_root("operator-summary-private-detail", 1),
        });

        state.recompute();
        state
    }

    pub fn insert_scan_cohort(&mut self, cohort: RingCtScanCohort) {
        if cohort.status == CohortStatus::RebateEligible {
            self.eligible_cohorts.insert(cohort.cohort_id.clone());
        }
        if cohort.status == CohortStatus::Quarantined {
            self.quarantined_cohorts.insert(cohort.cohort_id.clone());
        }
        self.scan_cohorts.insert(cohort.cohort_id.clone(), cohort);
        self.recompute();
    }

    pub fn insert_pressure_report(&mut self, report: ViewtagPressureReport) {
        self.pressure_reports
            .insert(report.report_id.clone(), report);
        self.recompute();
    }

    pub fn insert_rebate_signal(&mut self, signal: FeeRebateSignal) {
        self.rebate_signals.insert(signal.signal_id.clone(), signal);
        self.recompute();
    }

    pub fn insert_pq_attestation(&mut self, attestation: PqOracleAttestation) {
        self.pq_attestations
            .insert(attestation.attestation_id.clone(), attestation);
        self.recompute();
    }

    pub fn insert_decoy_safeguard(&mut self, safeguard: DecoyQualitySafeguard) {
        if !safeguard.passes(&self.config) {
            self.quarantined_cohorts.insert(safeguard.cohort_id.clone());
            self.eligible_cohorts.remove(&safeguard.cohort_id);
        }
        self.decoy_safeguards
            .insert(safeguard.safeguard_id.clone(), safeguard);
        self.recompute();
    }

    pub fn insert_sponsor_settlement(&mut self, settlement: SponsorSettlement) {
        self.sponsor_settlements
            .insert(settlement.settlement_id.clone(), settlement);
        self.recompute();
    }

    pub fn insert_redaction_budget(&mut self, budget: RedactionBudget) {
        self.redaction_budgets
            .insert(budget.budget_id.clone(), budget);
        self.recompute();
    }

    pub fn insert_operator_summary(&mut self, summary: OperatorSafeSummary) {
        self.operator_summaries
            .insert(summary.summary_id.clone(), summary);
        self.recompute();
    }

    pub fn operator_safe_snapshot(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "devnet_epoch": self.config.devnet_epoch,
            "state_root": self.state_root(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "eligible_cohorts": self.eligible_cohorts.iter().cloned().collect::<Vec<_>>(),
            "quarantined_cohorts": self.quarantined_cohorts.iter().cloned().collect::<Vec<_>>(),
            "summaries": self.operator_summaries.values().map(OperatorSafeSummary::public_record).collect::<Vec<_>>(),
        })
    }

    pub fn cohort_pressure_band(&self, cohort_id: &str) -> Option<PressureBand> {
        self.scan_cohorts
            .get(cohort_id)
            .map(|cohort| PressureBand::from_bps(cohort.viewtag_pressure_bps()))
    }

    pub fn cohort_is_rebate_eligible(&self, cohort_id: &str) -> bool {
        self.eligible_cohorts.contains(cohort_id) && !self.quarantined_cohorts.contains(cohort_id)
    }

    pub fn accepted_attestation_count(&self, signal_id: &str) -> u64 {
        self.pq_attestations
            .values()
            .filter(|attestation| {
                attestation.signal_id == signal_id
                    && attestation.status == AttestationStatus::Accepted
            })
            .count() as u64
    }

    pub fn payable_rebate_piconero(&self) -> u64 {
        self.sponsor_settlements
            .values()
            .filter(|settlement| settlement.status == SettlementStatus::Payable)
            .map(|settlement| settlement.payable_rebate_piconero)
            .sum()
    }

    pub fn reserved_rebate_piconero(&self) -> u64 {
        self.sponsor_settlements
            .values()
            .map(|settlement| settlement.reserved_rebate_piconero)
            .sum()
    }

    pub fn settlement_buffer_bps(&self) -> u64 {
        let payable = self.payable_rebate_piconero();
        if payable == 0 {
            return 0;
        }
        self.reserved_rebate_piconero().saturating_mul(10_000) / payable
    }

    pub fn redaction_budget_remaining(&self, operator_id: &str, epoch: u64) -> Option<Value> {
        self.redaction_budgets
            .values()
            .find(|budget| budget.operator_id == operator_id && budget.epoch == epoch)
            .map(|budget| {
                json!({
                    "operator_id": operator_id,
                    "epoch": epoch,
                    "remaining_redactions": budget.remaining_redactions(),
                    "remaining_public_hint_bytes": budget.remaining_public_hint_bytes(),
                    "budget_root": budget.root(),
                })
            })
    }

    pub fn rebate_signal_for_cohort(&self, cohort_id: &str) -> Vec<Value> {
        self.rebate_signals
            .values()
            .filter(|signal| signal.cohort_id == cohort_id)
            .map(|signal| {
                json!({
                    "signal_id": signal.signal_id,
                    "kind": signal.kind.as_str(),
                    "rebate_bps": signal.rebate_bps,
                    "eligible_output_count": signal.eligible_output_count,
                    "accepted_attestations": self.accepted_attestation_count(&signal.signal_id),
                    "signal_root": signal.root(),
                })
            })
            .collect()
    }

    pub fn operator_rebate_liability_record(&self) -> Value {
        json!({
            "payable_rebate_piconero": self.payable_rebate_piconero(),
            "reserved_rebate_piconero": self.reserved_rebate_piconero(),
            "settlement_buffer_bps": self.settlement_buffer_bps(),
            "target_sponsor_buffer_bps": self.config.sponsor_buffer_bps,
            "payable_settlement_count": self.counters.payable_rebates,
            "settlement_root": self.roots.sponsor_settlement_root,
        })
    }

    pub fn privacy_guardrail_record(&self) -> Value {
        let failing = self
            .decoy_safeguards
            .values()
            .filter(|safeguard| !safeguard.passes(&self.config))
            .map(|safeguard| {
                json!({
                    "safeguard_id": safeguard.safeguard_id,
                    "cohort_id": safeguard.cohort_id,
                    "severity": safeguard.severity.as_str(),
                    "privacy_score_bps": safeguard.privacy_score_bps,
                    "reason_code": safeguard.reason_code,
                })
            })
            .collect::<Vec<_>>();
        json!({
            "min_decoys": self.config.min_decoys,
            "min_privacy_score_bps": self.config.min_privacy_score_bps,
            "quarantined_cohorts": self.quarantined_cohorts.iter().cloned().collect::<Vec<_>>(),
            "failing_safeguards": failing,
            "decoy_safeguard_root": self.roots.decoy_safeguard_root,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("protocol version mismatch".to_string());
        }
        if self.config.default_rebate_bps
            > MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MAX_BPS
        {
            return Err("default rebate bps exceeds max bps".to_string());
        }
        for cohort in self.scan_cohorts.values() {
            if cohort.output_count < self.config.min_cohort_outputs {
                return Err(format!(
                    "cohort {} is below min cohort outputs",
                    cohort.cohort_id
                ));
            }
            if cohort.min_ring_size < self.config.min_decoys
                && cohort.status == CohortStatus::RebateEligible
            {
                return Err(format!(
                    "cohort {} eligible below min decoys",
                    cohort.cohort_id
                ));
            }
        }
        for signal in self.rebate_signals.values() {
            if signal.rebate_bps
                > MONERO_L2_PQ_PRIVATE_RINGCT_VIEWTAG_FEE_REBATE_ORACLE_RUNTIME_MAX_BPS
            {
                return Err(format!("signal {} exceeds max bps", signal.signal_id));
            }
            if !self.scan_cohorts.contains_key(&signal.cohort_id) {
                return Err(format!(
                    "signal {} references missing cohort",
                    signal.signal_id
                ));
            }
        }
        for report in self.pressure_reports.values() {
            if !self.scan_cohorts.contains_key(&report.cohort_id) {
                return Err(format!(
                    "report {} references missing cohort",
                    report.report_id
                ));
            }
        }
        for attestation in self.pq_attestations.values() {
            if !self.rebate_signals.contains_key(&attestation.signal_id) {
                return Err(format!(
                    "attestation {} references missing signal",
                    attestation.attestation_id
                ));
            }
        }
        Ok(())
    }

    pub fn recompute(&mut self) {
        self.counters = Counters {
            scan_cohorts: self.scan_cohorts.len() as u64,
            pressure_reports: self.pressure_reports.len() as u64,
            rebate_signals: self.rebate_signals.len() as u64,
            pq_attestations: self.pq_attestations.len() as u64,
            decoy_safeguards: self.decoy_safeguards.len() as u64,
            sponsor_settlements: self.sponsor_settlements.len() as u64,
            redaction_budgets: self.redaction_budgets.len() as u64,
            operator_summaries: self.operator_summaries.len() as u64,
            quarantined_cohorts: self.quarantined_cohorts.len() as u64,
            payable_rebates: self
                .sponsor_settlements
                .values()
                .filter(|settlement| settlement.status == SettlementStatus::Payable)
                .count() as u64,
        };
        self.roots = Roots {
            cohort_root: map_root(
                "RINGCT-VIEWTAG-FEE-REBATE-COHORTS",
                self.scan_cohorts
                    .values()
                    .map(RingCtScanCohort::public_record),
            ),
            pressure_report_root: map_root(
                "RINGCT-VIEWTAG-PRESSURE-REPORTS",
                self.pressure_reports
                    .values()
                    .map(ViewtagPressureReport::public_record),
            ),
            rebate_signal_root: map_root(
                "RINGCT-VIEWTAG-FEE-REBATE-SIGNALS",
                self.rebate_signals
                    .values()
                    .map(FeeRebateSignal::public_record),
            ),
            pq_attestation_root: map_root(
                "PQ-RINGCT-VIEWTAG-FEE-REBATE-ORACLE-ATTESTATIONS",
                self.pq_attestations
                    .values()
                    .map(PqOracleAttestation::public_record),
            ),
            decoy_safeguard_root: map_root(
                "RINGCT-DECOY-QUALITY-SAFEGUARDS",
                self.decoy_safeguards
                    .values()
                    .map(DecoyQualitySafeguard::public_record),
            ),
            sponsor_settlement_root: map_root(
                "RINGCT-VIEWTAG-SPONSOR-SETTLEMENTS",
                self.sponsor_settlements
                    .values()
                    .map(SponsorSettlement::public_record),
            ),
            redaction_budget_root: map_root(
                "RINGCT-VIEWTAG-REDACTION-BUDGETS",
                self.redaction_budgets
                    .values()
                    .map(RedactionBudget::public_record),
            ),
            operator_summary_root: map_root(
                "RINGCT-VIEWTAG-OPERATOR-SAFE-SUMMARIES",
                self.operator_summaries
                    .values()
                    .map(OperatorSafeSummary::public_record),
            ),
            eligible_cohort_root: set_root(
                "RINGCT-VIEWTAG-ELIGIBLE-COHORTS",
                self.eligible_cohorts.iter().cloned(),
            ),
            quarantine_root: set_root(
                "RINGCT-VIEWTAG-QUARANTINED-COHORTS",
                self.quarantined_cohorts.iter().cloned(),
            ),
        };
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "scan_cohorts": self.scan_cohorts.values().map(RingCtScanCohort::public_record).collect::<Vec<_>>(),
            "pressure_reports": self.pressure_reports.values().map(ViewtagPressureReport::public_record).collect::<Vec<_>>(),
            "rebate_signals": self.rebate_signals.values().map(FeeRebateSignal::public_record).collect::<Vec<_>>(),
            "pq_attestations": self.pq_attestations.values().map(PqOracleAttestation::public_record).collect::<Vec<_>>(),
            "decoy_safeguards": self.decoy_safeguards.values().map(DecoyQualitySafeguard::public_record).collect::<Vec<_>>(),
            "sponsor_settlements": self.sponsor_settlements.values().map(SponsorSettlement::public_record).collect::<Vec<_>>(),
            "redaction_budgets": self.redaction_budgets.values().map(RedactionBudget::public_record).collect::<Vec<_>>(),
            "operator_summaries": self.operator_summaries.values().map(OperatorSafeSummary::public_record).collect::<Vec<_>>(),
            "eligible_cohorts": self.eligible_cohorts.iter().cloned().collect::<Vec<_>>(),
            "quarantined_cohorts": self.quarantined_cohorts.iter().cloned().collect::<Vec<_>>(),
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root(),
            "runtime": self.public_record_without_root(),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_root())
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

pub fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "RINGCT-VIEWTAG-FEE-REBATE-ORACLE-RUNTIME-STATE",
        &[HashPart::Json(record)],
        32,
    )
}

fn map_root<I>(domain: &str, records: I) -> String
where
    I: IntoIterator<Item = Value>,
{
    let leaves = records.into_iter().collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn set_root<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn sample_root(label: &str, count: u64) -> String {
    domain_hash(
        "RINGCT-VIEWTAG-FEE-REBATE-ORACLE-RUNTIME-SAMPLE",
        &[HashPart::Str(label), HashPart::U64(count)],
        32,
    )
}
