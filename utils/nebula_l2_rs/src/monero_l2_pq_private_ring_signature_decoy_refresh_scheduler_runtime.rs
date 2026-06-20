use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqPrivateRingSignatureDecoyRefreshSchedulerRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_RING_SIGNATURE_DECOY_REFRESH_SCHEDULER_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-private-ring-signature-decoy-refresh-scheduler-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_RING_SIGNATURE_DECOY_REFRESH_SCHEDULER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-private-l2-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_SCHEDULER_ID: &str =
    "monero-l2-pq-private-ring-signature-decoy-refresh-scheduler-devnet";
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_WATCHER_SUITE: &str = "ML-DSA-87+SLH-DSA-SHAKE-256f-ring-decoy-refresh-watcher-v1";
pub const DECOY_COHORT_SCHEME: &str = "monero-ring-signature-decoy-age-cohort-root-v1";
pub const CHURN_WINDOW_SCHEME: &str = "monero-private-output-churn-window-root-v1";
pub const SPONSORED_BATCH_SCHEME: &str = "low-fee-sponsored-decoy-refresh-batch-root-v1";
pub const QUARANTINE_SCHEME: &str = "private-decoy-refresh-quarantine-root-v1";
pub const REDACTION_BUDGET_SCHEME: &str = "operator-safe-decoy-refresh-redaction-budget-root-v1";
pub const PUBLIC_SUMMARY_SCHEME: &str = "operator-safe-decoy-refresh-public-summary-root-v1";
pub const DEVNET_HEIGHT: u64 = 1_128_960;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_RING_SIZE: u16 = 64;
pub const DEFAULT_MIN_COHORT_OUTPUTS: u64 = 65_536;
pub const DEFAULT_TARGET_FRESHNESS_BPS: u64 = 8_200;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_WATCHER_QUORUM: u16 = 5;
pub const DEFAULT_LOW_FEE_SPONSOR_BPS: u64 = 2;
pub const DEFAULT_MAX_REFRESHES_PER_BATCH: usize = 512;
pub const DEFAULT_MIN_CHURN_SPAN_BLOCKS: u64 = 720;
pub const DEFAULT_MAX_CHURN_SPAN_BLOCKS: u64 = 10_080;
pub const DEFAULT_QUARANTINE_BLOCKS: u64 = 2_160;
pub const DEFAULT_REDACTION_BUDGET_BLOCKS: u64 = 10_080;
pub const MAX_DECOY_COHORTS: usize = 1_048_576;
pub const MAX_CHURN_WINDOWS: usize = 524_288;
pub const MAX_REFRESH_PLANS: usize = 1_048_576;
pub const MAX_PQ_WATCHER_ATTESTATIONS: usize = 2_097_152;
pub const MAX_SUBADDRESS_COHORTS: usize = 524_288;
pub const MAX_SPONSORED_BATCHES: usize = 524_288;
pub const MAX_QUARANTINES: usize = 262_144;
pub const MAX_REDACTION_BUDGETS: usize = 262_144;
pub const MAX_PUBLIC_SUMMARIES: usize = 262_144;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecoyAgeCohort {
    Fresh,
    Recent,
    Settled,
    Mature,
    DeepHistory,
    Archive,
}

impl DecoyAgeCohort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Recent => "recent",
            Self::Settled => "settled",
            Self::Mature => "mature",
            Self::DeepHistory => "deep_history",
            Self::Archive => "archive",
        }
    }

    pub fn target_weight_bps(self) -> u64 {
        match self {
            Self::Fresh => 1_400,
            Self::Recent => 2_400,
            Self::Settled => 2_800,
            Self::Mature => 1_900,
            Self::DeepHistory => 1_100,
            Self::Archive => 400,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshLane {
    WalletMaintenance,
    BridgeWithdrawal,
    MerchantPayment,
    DexSettlement,
    VaultSweep,
    IncidentRecovery,
}

impl RefreshLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletMaintenance => "wallet_maintenance",
            Self::BridgeWithdrawal => "bridge_withdrawal",
            Self::MerchantPayment => "merchant_payment",
            Self::DexSettlement => "dex_settlement",
            Self::VaultSweep => "vault_sweep",
            Self::IncidentRecovery => "incident_recovery",
        }
    }

    pub fn min_ring_size(self, config: &Config) -> u16 {
        match self {
            Self::WalletMaintenance | Self::MerchantPayment => config.min_ring_size,
            Self::BridgeWithdrawal | Self::DexSettlement => config.min_ring_size.saturating_add(16),
            Self::VaultSweep | Self::IncidentRecovery => config.min_ring_size.saturating_add(32),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleStatus {
    Draft,
    Scheduled,
    Attested,
    Batched,
    Published,
    Quarantined,
    Expired,
}

impl ScheduleStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Scheduled => "scheduled",
            Self::Attested => "attested",
            Self::Batched => "batched",
            Self::Published => "published",
            Self::Quarantined => "quarantined",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(
            self,
            Self::Scheduled | Self::Attested | Self::Batched | Self::Published
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Observed,
    Accepted,
    Superseded,
    Slashed,
    Expired,
}

impl AttestationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Accepted => "accepted",
            Self::Superseded => "superseded",
            Self::Slashed => "slashed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    ThinCohort,
    StaleOutputs,
    CorrelatedSubaddress,
    WatcherDispute,
    FeeSpike,
    OperatorPause,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThinCohort => "thin_cohort",
            Self::StaleOutputs => "stale_outputs",
            Self::CorrelatedSubaddress => "correlated_subaddress",
            Self::WatcherDispute => "watcher_dispute",
            Self::FeeSpike => "fee_spike",
            Self::OperatorPause => "operator_pause",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub scheduler_id: String,
    pub hash_suite: String,
    pub pq_watcher_suite: String,
    pub min_ring_size: u16,
    pub min_cohort_outputs: u64,
    pub target_freshness_bps: u64,
    pub min_pq_security_bits: u16,
    pub watcher_quorum: u16,
    pub low_fee_sponsor_bps: u64,
    pub max_refreshes_per_batch: usize,
    pub min_churn_span_blocks: u64,
    pub max_churn_span_blocks: u64,
    pub quarantine_blocks: u64,
    pub redaction_budget_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            scheduler_id: DEVNET_SCHEDULER_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_watcher_suite: PQ_WATCHER_SUITE.to_string(),
            min_ring_size: DEFAULT_MIN_RING_SIZE,
            min_cohort_outputs: DEFAULT_MIN_COHORT_OUTPUTS,
            target_freshness_bps: DEFAULT_TARGET_FRESHNESS_BPS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            watcher_quorum: DEFAULT_WATCHER_QUORUM,
            low_fee_sponsor_bps: DEFAULT_LOW_FEE_SPONSOR_BPS,
            max_refreshes_per_batch: DEFAULT_MAX_REFRESHES_PER_BATCH,
            min_churn_span_blocks: DEFAULT_MIN_CHURN_SPAN_BLOCKS,
            max_churn_span_blocks: DEFAULT_MAX_CHURN_SPAN_BLOCKS,
            quarantine_blocks: DEFAULT_QUARANTINE_BLOCKS,
            redaction_budget_blocks: DEFAULT_REDACTION_BUDGET_BLOCKS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub next_sequence: u64,
    pub decoy_cohorts: usize,
    pub churn_windows: usize,
    pub refresh_plans: usize,
    pub pq_watcher_attestations: usize,
    pub subaddress_cohorts: usize,
    pub sponsored_batches: usize,
    pub quarantines: usize,
    pub redaction_budgets: usize,
    pub public_summaries: usize,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub counters_root: String,
    pub decoy_cohort_root: String,
    pub churn_window_root: String,
    pub refresh_plan_root: String,
    pub pq_watcher_attestation_root: String,
    pub subaddress_cohort_root: String,
    pub sponsored_batch_root: String,
    pub quarantine_root: String,
    pub redaction_budget_root: String,
    pub public_summary_root: String,
    pub operator_safe_index_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: record_root("config", &config.public_record()),
            counters_root: record_root("counters", &counters.public_record()),
            decoy_cohort_root: empty_root("decoy_cohorts"),
            churn_window_root: empty_root("churn_windows"),
            refresh_plan_root: empty_root("refresh_plans"),
            pq_watcher_attestation_root: empty_root("pq_watcher_attestations"),
            subaddress_cohort_root: empty_root("subaddress_cohorts"),
            sponsored_batch_root: empty_root("sponsored_batches"),
            quarantine_root: empty_root("quarantines"),
            redaction_budget_root: empty_root("redaction_budgets"),
            public_summary_root: empty_root("public_summaries"),
            operator_safe_index_root: empty_root("operator_safe_index"),
            state_root: String::new(),
        };
        roots.state_root = record_root("roots", &roots.public_record_without_state_root());
        roots
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "counters_root": self.counters_root,
            "decoy_cohort_root": self.decoy_cohort_root,
            "churn_window_root": self.churn_window_root,
            "refresh_plan_root": self.refresh_plan_root,
            "pq_watcher_attestation_root": self.pq_watcher_attestation_root,
            "subaddress_cohort_root": self.subaddress_cohort_root,
            "sponsored_batch_root": self.sponsored_batch_root,
            "quarantine_root": self.quarantine_root,
            "redaction_budget_root": self.redaction_budget_root,
            "public_summary_root": self.public_summary_root,
            "operator_safe_index_root": self.operator_safe_index_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root.clone());
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyCohortRequest {
    pub cohort_label: String,
    pub age_cohort: DecoyAgeCohort,
    pub start_height: u64,
    pub end_height: u64,
    pub output_commitment_root: String,
    pub histogram_root: String,
    pub output_count: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DecoyCohortRecord {
    pub cohort_id: String,
    pub age_cohort: DecoyAgeCohort,
    pub start_height: u64,
    pub end_height: u64,
    pub output_commitment_root: String,
    pub histogram_root: String,
    pub output_count: u64,
    pub median_age_blocks: u64,
    pub p95_age_blocks: u64,
    pub freshness_bps: u64,
    pub privacy_weight_bps: u64,
    pub accepted_at_height: u64,
}

impl DecoyCohortRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "cohort_id": self.cohort_id,
            "age_cohort": self.age_cohort.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "output_commitment_root": self.output_commitment_root,
            "histogram_root": self.histogram_root,
            "output_count": self.output_count,
            "median_age_blocks": self.median_age_blocks,
            "p95_age_blocks": self.p95_age_blocks,
            "freshness_bps": self.freshness_bps,
            "privacy_weight_bps": self.privacy_weight_bps,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChurnWindowRequest {
    pub lane: RefreshLane,
    pub window_label: String,
    pub start_height: u64,
    pub end_height: u64,
    pub spend_output_root: String,
    pub decoy_output_root: String,
    pub min_refresh_count: u64,
    pub fee_ceiling_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ChurnWindowRecord {
    pub window_id: String,
    pub lane: RefreshLane,
    pub start_height: u64,
    pub end_height: u64,
    pub spend_output_root: String,
    pub decoy_output_root: String,
    pub min_refresh_count: u64,
    pub fee_ceiling_piconero: u64,
    pub churn_span_blocks: u64,
    pub accepted_at_height: u64,
}

impl ChurnWindowRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane": self.lane.as_str(),
            "start_height": self.start_height,
            "end_height": self.end_height,
            "spend_output_root": self.spend_output_root,
            "decoy_output_root": self.decoy_output_root,
            "min_refresh_count": self.min_refresh_count,
            "fee_ceiling_piconero": self.fee_ceiling_piconero,
            "churn_span_blocks": self.churn_span_blocks,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohortRequest {
    pub subaddress_cohort_label: String,
    pub account_tag_root: String,
    pub lane: RefreshLane,
    pub member_count: u64,
    pub scan_hint_root: String,
    pub unlinkability_floor_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressCohortRecord {
    pub subaddress_cohort_id: String,
    pub account_tag_root: String,
    pub lane: RefreshLane,
    pub member_count: u64,
    pub scan_hint_root: String,
    pub unlinkability_floor_bps: u64,
    pub accepted_at_height: u64,
}

impl SubaddressCohortRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "subaddress_cohort_id": self.subaddress_cohort_id,
            "account_tag_root": self.account_tag_root,
            "lane": self.lane.as_str(),
            "member_count": self.member_count,
            "scan_hint_root": self.scan_hint_root,
            "unlinkability_floor_bps": self.unlinkability_floor_bps,
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshPlanRequest {
    pub lane: RefreshLane,
    pub cohort_ids: Vec<String>,
    pub churn_window_id: String,
    pub subaddress_cohort_id: String,
    pub ring_member_root: String,
    pub decoy_selection_root: String,
    pub nullifier_guard_root: String,
    pub requested_refresh_count: u64,
    pub target_ring_size: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RefreshPlanRecord {
    pub plan_id: String,
    pub lane: RefreshLane,
    pub cohort_ids: Vec<String>,
    pub churn_window_id: String,
    pub subaddress_cohort_id: String,
    pub ring_member_root: String,
    pub decoy_selection_root: String,
    pub nullifier_guard_root: String,
    pub requested_refresh_count: u64,
    pub target_ring_size: u16,
    pub aggregate_freshness_bps: u64,
    pub status: ScheduleStatus,
    pub scheduled_at_height: u64,
}

impl RefreshPlanRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "plan_id": self.plan_id,
            "lane": self.lane.as_str(),
            "cohort_ids": self.cohort_ids,
            "churn_window_id": self.churn_window_id,
            "subaddress_cohort_id": self.subaddress_cohort_id,
            "ring_member_root": self.ring_member_root,
            "decoy_selection_root": self.decoy_selection_root,
            "nullifier_guard_root": self.nullifier_guard_root,
            "requested_refresh_count": self.requested_refresh_count,
            "target_ring_size": self.target_ring_size,
            "aggregate_freshness_bps": self.aggregate_freshness_bps,
            "status": self.status.as_str(),
            "scheduled_at_height": self.scheduled_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestationRequest {
    pub watcher_id: String,
    pub plan_id: String,
    pub observed_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub freshness_floor_bps: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PqWatcherAttestationRecord {
    pub attestation_id: String,
    pub watcher_id: String,
    pub plan_id: String,
    pub observed_root: String,
    pub pq_signature_root: String,
    pub transcript_root: String,
    pub pq_security_bits: u16,
    pub freshness_floor_bps: u64,
    pub status: AttestationStatus,
    pub accepted_at_height: u64,
}

impl PqWatcherAttestationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "watcher_id": self.watcher_id,
            "plan_id": self.plan_id,
            "observed_root": self.observed_root,
            "pq_signature_root": self.pq_signature_root,
            "transcript_root": self.transcript_root,
            "pq_security_bits": self.pq_security_bits,
            "freshness_floor_bps": self.freshness_floor_bps,
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredRefreshBatchRequest {
    pub sponsor_id: String,
    pub lane: RefreshLane,
    pub plan_ids: Vec<String>,
    pub fee_sponsor_root: String,
    pub batch_execution_root: String,
    pub max_fee_piconero: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SponsoredRefreshBatchRecord {
    pub batch_id: String,
    pub sponsor_id: String,
    pub lane: RefreshLane,
    pub plan_ids: Vec<String>,
    pub fee_sponsor_root: String,
    pub batch_execution_root: String,
    pub max_fee_piconero: u64,
    pub sponsored_fee_piconero: u64,
    pub status: ScheduleStatus,
    pub accepted_at_height: u64,
}

impl SponsoredRefreshBatchRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "batch_id": self.batch_id,
            "sponsor_id": self.sponsor_id,
            "lane": self.lane.as_str(),
            "plan_ids": self.plan_ids,
            "fee_sponsor_root": self.fee_sponsor_root,
            "batch_execution_root": self.batch_execution_root,
            "max_fee_piconero": self.max_fee_piconero,
            "sponsored_fee_piconero": self.sponsored_fee_piconero,
            "status": self.status.as_str(),
            "accepted_at_height": self.accepted_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub subject_id: String,
    pub reason: QuarantineReason,
    pub evidence_root: String,
    pub release_height: u64,
    pub public_note_root: String,
}

impl QuarantineRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "quarantine_id": self.quarantine_id,
            "subject_id": self.subject_id,
            "reason": self.reason.as_str(),
            "evidence_root": self.evidence_root,
            "release_height": self.release_height,
            "public_note_root": self.public_note_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RedactionBudgetRecord {
    pub budget_id: String,
    pub subject_id: String,
    pub disclosed_field_root: String,
    pub max_records: u64,
    pub expires_at_height: u64,
    pub operator_scope_root: String,
}

impl RedactionBudgetRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "budget_id": self.budget_id,
            "subject_id": self.subject_id,
            "disclosed_field_root": self.disclosed_field_root,
            "max_records": self.max_records,
            "expires_at_height": self.expires_at_height,
            "operator_scope_root": self.operator_scope_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OperatorSummary {
    pub protocol_version: String,
    pub state_root: String,
    pub active_refresh_plans: u64,
    pub quarantined_subjects: u64,
    pub accepted_attestations: u64,
    pub sponsored_batches: u64,
    pub average_freshness_bps: u64,
    pub min_ring_size: u16,
    pub watcher_quorum: u16,
}

impl OperatorSummary {
    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub current_height: u64,
    pub counters: Counters,
    pub roots: Roots,
    pub decoy_cohorts: BTreeMap<String, DecoyCohortRecord>,
    pub churn_windows: BTreeMap<String, ChurnWindowRecord>,
    pub refresh_plans: BTreeMap<String, RefreshPlanRecord>,
    pub pq_watcher_attestations: BTreeMap<String, PqWatcherAttestationRecord>,
    pub subaddress_cohorts: BTreeMap<String, SubaddressCohortRecord>,
    pub sponsored_batches: BTreeMap<String, SponsoredRefreshBatchRecord>,
    pub quarantines: BTreeMap<String, QuarantineRecord>,
    pub redaction_budgets: BTreeMap<String, RedactionBudgetRecord>,
    pub public_summaries: BTreeMap<String, Value>,
}

impl State {
    pub fn new(config: Config, current_height: u64) -> Self {
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        Self {
            config,
            current_height,
            counters,
            roots,
            decoy_cohorts: BTreeMap::new(),
            churn_windows: BTreeMap::new(),
            refresh_plans: BTreeMap::new(),
            pq_watcher_attestations: BTreeMap::new(),
            subaddress_cohorts: BTreeMap::new(),
            sponsored_batches: BTreeMap::new(),
            quarantines: BTreeMap::new(),
            redaction_budgets: BTreeMap::new(),
            public_summaries: BTreeMap::new(),
        }
    }

    pub fn devnet() -> Self {
        let mut state = Self::new(Config::devnet(), DEVNET_HEIGHT);
        seed_devnet(&mut state).expect("devnet ring signature decoy refresh scheduler");
        state.refresh_roots();
        state
    }

    pub fn demo() -> Self {
        Self::devnet()
    }

    pub fn register_decoy_cohort(&mut self, request: DecoyCohortRequest) -> Result<String> {
        ensure_capacity(self.decoy_cohorts.len(), MAX_DECOY_COHORTS, "decoy cohorts")?;
        ensure_range(request.start_height, request.end_height, "decoy cohort")?;
        if request.output_count < self.config.min_cohort_outputs {
            return Err("decoy cohort output count below privacy floor".to_string());
        }
        let sequence = self.next_sequence();
        let cohort_id = decoy_cohort_id(sequence, &request);
        let freshness_bps = freshness_score(
            request.median_age_blocks,
            request.p95_age_blocks,
            self.config.max_churn_span_blocks,
        );
        let record = DecoyCohortRecord {
            cohort_id: cohort_id.clone(),
            age_cohort: request.age_cohort,
            start_height: request.start_height,
            end_height: request.end_height,
            output_commitment_root: request.output_commitment_root,
            histogram_root: request.histogram_root,
            output_count: request.output_count,
            median_age_blocks: request.median_age_blocks,
            p95_age_blocks: request.p95_age_blocks,
            freshness_bps,
            privacy_weight_bps: request.age_cohort.target_weight_bps(),
            accepted_at_height: self.current_height,
        };
        self.decoy_cohorts.insert(cohort_id.clone(), record);
        self.refresh_roots();
        Ok(cohort_id)
    }

    pub fn open_churn_window(&mut self, request: ChurnWindowRequest) -> Result<String> {
        ensure_capacity(self.churn_windows.len(), MAX_CHURN_WINDOWS, "churn windows")?;
        ensure_range(request.start_height, request.end_height, "churn window")?;
        let span = request.end_height.saturating_sub(request.start_height);
        if span < self.config.min_churn_span_blocks || span > self.config.max_churn_span_blocks {
            return Err("churn window span outside configured privacy bounds".to_string());
        }
        let sequence = self.next_sequence();
        let window_id = churn_window_id(sequence, &request);
        let record = ChurnWindowRecord {
            window_id: window_id.clone(),
            lane: request.lane,
            start_height: request.start_height,
            end_height: request.end_height,
            spend_output_root: request.spend_output_root,
            decoy_output_root: request.decoy_output_root,
            min_refresh_count: request.min_refresh_count,
            fee_ceiling_piconero: request.fee_ceiling_piconero,
            churn_span_blocks: span,
            accepted_at_height: self.current_height,
        };
        self.churn_windows.insert(window_id.clone(), record);
        self.refresh_roots();
        Ok(window_id)
    }

    pub fn register_subaddress_cohort(
        &mut self,
        request: SubaddressCohortRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.subaddress_cohorts.len(),
            MAX_SUBADDRESS_COHORTS,
            "subaddress cohorts",
        )?;
        if request.member_count < self.config.min_cohort_outputs / 2 {
            return Err("subaddress cohort member count below privacy floor".to_string());
        }
        let sequence = self.next_sequence();
        let subaddress_cohort_id = subaddress_cohort_id(sequence, &request);
        let record = SubaddressCohortRecord {
            subaddress_cohort_id: subaddress_cohort_id.clone(),
            account_tag_root: request.account_tag_root,
            lane: request.lane,
            member_count: request.member_count,
            scan_hint_root: request.scan_hint_root,
            unlinkability_floor_bps: request.unlinkability_floor_bps.min(MAX_BPS),
            accepted_at_height: self.current_height,
        };
        self.subaddress_cohorts
            .insert(subaddress_cohort_id.clone(), record);
        self.refresh_roots();
        Ok(subaddress_cohort_id)
    }

    pub fn schedule_refresh(&mut self, request: RefreshPlanRequest) -> Result<String> {
        ensure_capacity(self.refresh_plans.len(), MAX_REFRESH_PLANS, "refresh plans")?;
        if !self.churn_windows.contains_key(&request.churn_window_id) {
            return Err("refresh plan references unknown churn window".to_string());
        }
        if !self
            .subaddress_cohorts
            .contains_key(&request.subaddress_cohort_id)
        {
            return Err("refresh plan references unknown subaddress cohort".to_string());
        }
        let cohort_ids = sorted_vec(request.cohort_ids);
        if cohort_ids.is_empty() {
            return Err("refresh plan requires at least one decoy age cohort".to_string());
        }
        let mut total_freshness = 0u64;
        for cohort_id in &cohort_ids {
            let cohort = self
                .decoy_cohorts
                .get(cohort_id)
                .ok_or_else(|| "refresh plan references unknown decoy cohort".to_string())?;
            total_freshness = total_freshness.saturating_add(cohort.freshness_bps);
        }
        let aggregate_freshness_bps = total_freshness / cohort_ids.len() as u64;
        if aggregate_freshness_bps < self.config.target_freshness_bps {
            return Err("refresh plan freshness below scheduler target".to_string());
        }
        if request.target_ring_size < request.lane.min_ring_size(&self.config) {
            return Err("refresh plan target ring size below lane floor".to_string());
        }
        let sequence = self.next_sequence();
        let plan_id = refresh_plan_id(sequence, &request, &cohort_ids);
        let record = RefreshPlanRecord {
            plan_id: plan_id.clone(),
            lane: request.lane,
            cohort_ids,
            churn_window_id: request.churn_window_id,
            subaddress_cohort_id: request.subaddress_cohort_id,
            ring_member_root: request.ring_member_root,
            decoy_selection_root: request.decoy_selection_root,
            nullifier_guard_root: request.nullifier_guard_root,
            requested_refresh_count: request.requested_refresh_count,
            target_ring_size: request.target_ring_size,
            aggregate_freshness_bps,
            status: ScheduleStatus::Scheduled,
            scheduled_at_height: self.current_height,
        };
        self.refresh_plans.insert(plan_id.clone(), record);
        self.refresh_roots();
        Ok(plan_id)
    }

    pub fn attest_refresh(&mut self, request: PqWatcherAttestationRequest) -> Result<String> {
        ensure_capacity(
            self.pq_watcher_attestations.len(),
            MAX_PQ_WATCHER_ATTESTATIONS,
            "pq watcher attestations",
        )?;
        if request.pq_security_bits < self.config.min_pq_security_bits {
            return Err("pq watcher attestation below security floor".to_string());
        }
        let plan = self
            .refresh_plans
            .get_mut(&request.plan_id)
            .ok_or_else(|| "pq watcher attestation references unknown refresh plan".to_string())?;
        if request.freshness_floor_bps > plan.aggregate_freshness_bps {
            return Err("pq watcher attestation freshness floor exceeds plan".to_string());
        }
        plan.status = ScheduleStatus::Attested;
        let sequence = self.next_sequence();
        let attestation_id = pq_watcher_attestation_id(sequence, &request);
        let record = PqWatcherAttestationRecord {
            attestation_id: attestation_id.clone(),
            watcher_id: request.watcher_id,
            plan_id: request.plan_id,
            observed_root: request.observed_root,
            pq_signature_root: request.pq_signature_root,
            transcript_root: request.transcript_root,
            pq_security_bits: request.pq_security_bits,
            freshness_floor_bps: request.freshness_floor_bps,
            status: AttestationStatus::Accepted,
            accepted_at_height: self.current_height,
        };
        self.pq_watcher_attestations
            .insert(attestation_id.clone(), record);
        self.refresh_roots();
        Ok(attestation_id)
    }

    pub fn sponsor_refresh_batch(
        &mut self,
        request: SponsoredRefreshBatchRequest,
    ) -> Result<String> {
        ensure_capacity(
            self.sponsored_batches.len(),
            MAX_SPONSORED_BATCHES,
            "sponsored batches",
        )?;
        let plan_ids = sorted_vec(request.plan_ids);
        if plan_ids.is_empty() {
            return Err("sponsored refresh batch requires at least one plan".to_string());
        }
        if plan_ids.len() > self.config.max_refreshes_per_batch {
            return Err("sponsored refresh batch exceeds configured size".to_string());
        }
        for plan_id in &plan_ids {
            let plan = self
                .refresh_plans
                .get_mut(plan_id)
                .ok_or_else(|| "sponsored batch references unknown refresh plan".to_string())?;
            if !plan.status.active() {
                return Err("sponsored batch references inactive refresh plan".to_string());
            }
            plan.status = ScheduleStatus::Batched;
        }
        let sequence = self.next_sequence();
        let batch_id = sponsored_batch_id(sequence, &request, &plan_ids);
        let sponsored_fee_piconero = request
            .max_fee_piconero
            .saturating_mul(self.config.low_fee_sponsor_bps)
            / MAX_BPS;
        let record = SponsoredRefreshBatchRecord {
            batch_id: batch_id.clone(),
            sponsor_id: request.sponsor_id,
            lane: request.lane,
            plan_ids,
            fee_sponsor_root: request.fee_sponsor_root,
            batch_execution_root: request.batch_execution_root,
            max_fee_piconero: request.max_fee_piconero,
            sponsored_fee_piconero,
            status: ScheduleStatus::Batched,
            accepted_at_height: self.current_height,
        };
        self.sponsored_batches.insert(batch_id.clone(), record);
        self.refresh_roots();
        Ok(batch_id)
    }

    pub fn quarantine_subject(
        &mut self,
        subject_id: &str,
        reason: QuarantineReason,
        evidence_root: String,
        public_note_root: String,
    ) -> Result<String> {
        ensure_capacity(self.quarantines.len(), MAX_QUARANTINES, "quarantines")?;
        if let Some(plan) = self.refresh_plans.get_mut(subject_id) {
            plan.status = ScheduleStatus::Quarantined;
        }
        let sequence = self.next_sequence();
        let quarantine_id = root_from_parts(
            "MONERO-L2-PQ-DECOY-REFRESH-QUARANTINE-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(subject_id),
                HashPart::Str(reason.as_str()),
                HashPart::Str(&evidence_root),
            ],
        );
        let record = QuarantineRecord {
            quarantine_id: quarantine_id.clone(),
            subject_id: subject_id.to_string(),
            reason,
            evidence_root,
            release_height: self
                .current_height
                .saturating_add(self.config.quarantine_blocks),
            public_note_root,
        };
        self.quarantines.insert(quarantine_id.clone(), record);
        self.refresh_roots();
        Ok(quarantine_id)
    }

    pub fn record_redaction_budget(
        &mut self,
        subject_id: &str,
        disclosed_field_root: String,
        max_records: u64,
        operator_scope_root: String,
    ) -> Result<String> {
        ensure_capacity(
            self.redaction_budgets.len(),
            MAX_REDACTION_BUDGETS,
            "redaction budgets",
        )?;
        let sequence = self.next_sequence();
        let budget_id = root_from_parts(
            "MONERO-L2-PQ-DECOY-REFRESH-REDACTION-BUDGET-ID",
            &[
                HashPart::U64(sequence),
                HashPart::Str(subject_id),
                HashPart::Str(&disclosed_field_root),
                HashPart::U64(max_records),
            ],
        );
        let record = RedactionBudgetRecord {
            budget_id: budget_id.clone(),
            subject_id: subject_id.to_string(),
            disclosed_field_root,
            max_records,
            expires_at_height: self
                .current_height
                .saturating_add(self.config.redaction_budget_blocks),
            operator_scope_root,
        };
        self.redaction_budgets.insert(budget_id.clone(), record);
        self.refresh_roots();
        Ok(budget_id)
    }

    pub fn operator_summary(&self) -> OperatorSummary {
        let state_root = self.state_root();
        let active_refresh_plans = self
            .refresh_plans
            .values()
            .filter(|plan| plan.status.active())
            .count() as u64;
        let accepted_attestations = self
            .pq_watcher_attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Accepted)
            .count() as u64;
        let total_freshness = self
            .refresh_plans
            .values()
            .map(|plan| plan.aggregate_freshness_bps)
            .sum::<u64>();
        let average_freshness_bps = if self.refresh_plans.is_empty() {
            0
        } else {
            total_freshness / self.refresh_plans.len() as u64
        };
        OperatorSummary {
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root,
            active_refresh_plans,
            quarantined_subjects: self.quarantines.len() as u64,
            accepted_attestations,
            sponsored_batches: self.sponsored_batches.len() as u64,
            average_freshness_bps,
            min_ring_size: self.config.min_ring_size,
            watcher_quorum: self.config.watcher_quorum,
        }
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        record["state_root"] = json!(self.state_root());
        record
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        self.counters.decoy_cohorts = self.decoy_cohorts.len();
        self.counters.churn_windows = self.churn_windows.len();
        self.counters.refresh_plans = self.refresh_plans.len();
        self.counters.pq_watcher_attestations = self.pq_watcher_attestations.len();
        self.counters.subaddress_cohorts = self.subaddress_cohorts.len();
        self.counters.sponsored_batches = self.sponsored_batches.len();
        self.counters.quarantines = self.quarantines.len();
        self.counters.redaction_budgets = self.redaction_budgets.len();
        self.counters.public_summaries = self.public_summaries.len();
        self.roots.config_root = record_root("config", &self.config.public_record());
        self.roots.counters_root = record_root("counters", &self.counters.public_record());
        self.roots.decoy_cohort_root = map_root(
            "decoy_cohorts",
            &self.decoy_cohorts,
            DecoyCohortRecord::public_record,
        );
        self.roots.churn_window_root = map_root(
            "churn_windows",
            &self.churn_windows,
            ChurnWindowRecord::public_record,
        );
        self.roots.refresh_plan_root = map_root(
            "refresh_plans",
            &self.refresh_plans,
            RefreshPlanRecord::public_record,
        );
        self.roots.pq_watcher_attestation_root = map_root(
            "pq_watcher_attestations",
            &self.pq_watcher_attestations,
            PqWatcherAttestationRecord::public_record,
        );
        self.roots.subaddress_cohort_root = map_root(
            "subaddress_cohorts",
            &self.subaddress_cohorts,
            SubaddressCohortRecord::public_record,
        );
        self.roots.sponsored_batch_root = map_root(
            "sponsored_batches",
            &self.sponsored_batches,
            SponsoredRefreshBatchRecord::public_record,
        );
        self.roots.quarantine_root = map_root(
            "quarantines",
            &self.quarantines,
            QuarantineRecord::public_record,
        );
        self.roots.redaction_budget_root = map_root(
            "redaction_budgets",
            &self.redaction_budgets,
            RedactionBudgetRecord::public_record,
        );
        self.roots.public_summary_root = value_map_root("public_summaries", &self.public_summaries);
        self.roots.operator_safe_index_root = record_root(
            "operator_safe_index",
            &json!({
                "summary_root": self.roots.public_summary_root,
                "redaction_budget_root": self.roots.redaction_budget_root,
                "quarantine_root": self.roots.quarantine_root,
                "summary": self.operator_summary_without_state_root().public_record(),
            }),
        );
        self.roots.state_root = self.state_root();
    }

    fn operator_summary_without_state_root(&self) -> OperatorSummary {
        let active_refresh_plans = self
            .refresh_plans
            .values()
            .filter(|plan| plan.status.active())
            .count() as u64;
        let accepted_attestations = self
            .pq_watcher_attestations
            .values()
            .filter(|attestation| attestation.status == AttestationStatus::Accepted)
            .count() as u64;
        let total_freshness = self
            .refresh_plans
            .values()
            .map(|plan| plan.aggregate_freshness_bps)
            .sum::<u64>();
        let average_freshness_bps = if self.refresh_plans.is_empty() {
            0
        } else {
            total_freshness / self.refresh_plans.len() as u64
        };
        OperatorSummary {
            protocol_version: PROTOCOL_VERSION.to_string(),
            state_root: String::new(),
            active_refresh_plans,
            quarantined_subjects: self.quarantines.len() as u64,
            accepted_attestations,
            sponsored_batches: self.sponsored_batches.len() as u64,
            average_freshness_bps,
            min_ring_size: self.config.min_ring_size,
            watcher_quorum: self.config.watcher_quorum,
        }
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "pq_watcher_suite": PQ_WATCHER_SUITE,
            "decoy_cohort_scheme": DECOY_COHORT_SCHEME,
            "churn_window_scheme": CHURN_WINDOW_SCHEME,
            "sponsored_batch_scheme": SPONSORED_BATCH_SCHEME,
            "quarantine_scheme": QUARANTINE_SCHEME,
            "redaction_budget_scheme": REDACTION_BUDGET_SCHEME,
            "public_summary_scheme": PUBLIC_SUMMARY_SCHEME,
            "current_height": self.current_height,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record_without_state_root(),
            "operator_summary": self.operator_summary_without_state_root().public_record(),
        })
    }

    fn next_sequence(&mut self) -> u64 {
        self.counters.next_sequence = self.counters.next_sequence.saturating_add(1);
        self.counters.next_sequence
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new(Config::devnet(), DEVNET_HEIGHT)
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

pub fn refresh_roots(state: &mut State) {
    state.refresh_roots();
}

fn seed_devnet(state: &mut State) -> Result<()> {
    let fresh = state.register_decoy_cohort(DecoyCohortRequest {
        cohort_label: "fresh-wallet-maintenance".to_string(),
        age_cohort: DecoyAgeCohort::Recent,
        start_height: DEVNET_HEIGHT - 1_440,
        end_height: DEVNET_HEIGHT - 72,
        output_commitment_root: deterministic_devnet_root("fresh-output-commitments", 1),
        histogram_root: deterministic_devnet_root("fresh-age-histogram", 1),
        output_count: 131_072,
        median_age_blocks: 420,
        p95_age_blocks: 3_600,
    })?;
    let mature = state.register_decoy_cohort(DecoyCohortRequest {
        cohort_label: "mature-bridge-withdrawal".to_string(),
        age_cohort: DecoyAgeCohort::Mature,
        start_height: DEVNET_HEIGHT - 86_400,
        end_height: DEVNET_HEIGHT - 14_400,
        output_commitment_root: deterministic_devnet_root("mature-output-commitments", 2),
        histogram_root: deterministic_devnet_root("mature-age-histogram", 2),
        output_count: 196_608,
        median_age_blocks: 720,
        p95_age_blocks: 1_200,
    })?;
    let window = state.open_churn_window(ChurnWindowRequest {
        lane: RefreshLane::BridgeWithdrawal,
        window_label: "bridge-low-fee-refresh-window".to_string(),
        start_height: DEVNET_HEIGHT + 24,
        end_height: DEVNET_HEIGHT + 1_464,
        spend_output_root: deterministic_devnet_root("spend-output-window", 3),
        decoy_output_root: deterministic_devnet_root("decoy-output-window", 3),
        min_refresh_count: 256,
        fee_ceiling_piconero: 18_000_000,
    })?;
    let subaddress = state.register_subaddress_cohort(SubaddressCohortRequest {
        subaddress_cohort_label: "bridge-subaddress-cohort-a".to_string(),
        account_tag_root: deterministic_devnet_root("account-tag-root", 4),
        lane: RefreshLane::BridgeWithdrawal,
        member_count: 65_536,
        scan_hint_root: deterministic_devnet_root("scan-hint-root", 4),
        unlinkability_floor_bps: 8_900,
    })?;
    let plan = state.schedule_refresh(RefreshPlanRequest {
        lane: RefreshLane::BridgeWithdrawal,
        cohort_ids: vec![fresh, mature],
        churn_window_id: window,
        subaddress_cohort_id: subaddress,
        ring_member_root: deterministic_devnet_root("ring-member-root", 5),
        decoy_selection_root: deterministic_devnet_root("decoy-selection-root", 5),
        nullifier_guard_root: deterministic_devnet_root("nullifier-guard-root", 5),
        requested_refresh_count: 384,
        target_ring_size: 96,
    })?;
    state.attest_refresh(PqWatcherAttestationRequest {
        watcher_id: "pq-decoy-refresh-watcher-a".to_string(),
        plan_id: plan.clone(),
        observed_root: deterministic_devnet_root("watcher-observed-root", 6),
        pq_signature_root: deterministic_devnet_root("watcher-pq-signature-root", 6),
        transcript_root: deterministic_devnet_root("watcher-transcript-root", 6),
        pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
        freshness_floor_bps: 8_500,
    })?;
    state.sponsor_refresh_batch(SponsoredRefreshBatchRequest {
        sponsor_id: "low-fee-refresh-sponsor-a".to_string(),
        lane: RefreshLane::BridgeWithdrawal,
        plan_ids: vec![plan.clone()],
        fee_sponsor_root: deterministic_devnet_root("fee-sponsor-root", 7),
        batch_execution_root: deterministic_devnet_root("batch-execution-root", 7),
        max_fee_piconero: 18_000_000,
    })?;
    state.record_redaction_budget(
        &plan,
        deterministic_devnet_root("disclosed-fields-root", 8),
        64,
        deterministic_devnet_root("operator-scope-root", 8),
    )?;
    state.public_summaries.insert(
        "devnet-operator-safe-summary".to_string(),
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "summary_kind": "decoy_refresh_health",
            "active_refresh_plans": 1,
            "redaction": "roots_only",
            "monero_network": DEVNET_MONERO_NETWORK,
        }),
    );
    Ok(())
}

pub fn root_from_parts(domain: &str, parts: &[HashPart<'_>]) -> String {
    domain_hash(domain, parts, 32)
}

pub fn deterministic_devnet_root(label: &str, index: u64) -> String {
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-SCHEDULER-DEVNET-ROOT",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(DEVNET_SCHEDULER_ID),
            HashPart::Str(label),
            HashPart::U64(index),
        ],
    )
}

pub fn decoy_cohort_id(sequence: u64, request: &DecoyCohortRequest) -> String {
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-COHORT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.cohort_label),
            HashPart::Str(request.age_cohort.as_str()),
            HashPart::U64(request.start_height),
            HashPart::U64(request.end_height),
            HashPart::Str(&request.output_commitment_root),
        ],
    )
}

pub fn churn_window_id(sequence: u64, request: &ChurnWindowRequest) -> String {
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-CHURN-WINDOW-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(request.lane.as_str()),
            HashPart::Str(&request.window_label),
            HashPart::U64(request.start_height),
            HashPart::U64(request.end_height),
            HashPart::Str(&request.decoy_output_root),
        ],
    )
}

pub fn subaddress_cohort_id(sequence: u64, request: &SubaddressCohortRequest) -> String {
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-SUBADDRESS-COHORT-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.subaddress_cohort_label),
            HashPart::Str(&request.account_tag_root),
            HashPart::Str(request.lane.as_str()),
            HashPart::U64(request.member_count),
        ],
    )
}

pub fn refresh_plan_id(
    sequence: u64,
    request: &RefreshPlanRequest,
    cohort_ids: &[String],
) -> String {
    let cohorts = json!(cohort_ids);
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-PLAN-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(request.lane.as_str()),
            HashPart::Json(&cohorts),
            HashPart::Str(&request.churn_window_id),
            HashPart::Str(&request.subaddress_cohort_id),
            HashPart::Str(&request.decoy_selection_root),
        ],
    )
}

pub fn pq_watcher_attestation_id(sequence: u64, request: &PqWatcherAttestationRequest) -> String {
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-WATCHER-ATTESTATION-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.watcher_id),
            HashPart::Str(&request.plan_id),
            HashPart::Str(&request.observed_root),
            HashPart::Str(&request.pq_signature_root),
        ],
    )
}

pub fn sponsored_batch_id(
    sequence: u64,
    request: &SponsoredRefreshBatchRequest,
    plan_ids: &[String],
) -> String {
    let plans = json!(plan_ids);
    root_from_parts(
        "MONERO-L2-PQ-DECOY-REFRESH-SPONSORED-BATCH-ID",
        &[
            HashPart::U64(sequence),
            HashPart::Str(&request.sponsor_id),
            HashPart::Str(request.lane.as_str()),
            HashPart::Json(&plans),
            HashPart::Str(&request.batch_execution_root),
        ],
    )
}

fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-refresh-scheduler:{domain}:record"),
        &[HashPart::Json(record)],
        32,
    )
}

fn state_root_from_record(record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-decoy-refresh-scheduler:state-root",
        &[HashPart::Json(record)],
        32,
    )
}

fn empty_root(domain: &str) -> String {
    domain_hash(
        &format!("monero-l2-pq-decoy-refresh-scheduler:{domain}:empty"),
        &[HashPart::Str(PROTOCOL_VERSION)],
        32,
    )
}

fn map_root<T, F>(domain: &str, map: &BTreeMap<String, T>, public: F) -> String
where
    F: Fn(&T) -> Value,
{
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": public(value)}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-decoy-refresh-scheduler:{domain}"),
        &leaves,
    )
}

fn value_map_root(domain: &str, map: &BTreeMap<String, Value>) -> String {
    let leaves = map
        .iter()
        .map(|(key, value)| json!({"key": key, "record": value}))
        .collect::<Vec<_>>();
    merkle_root(
        &format!("monero-l2-pq-decoy-refresh-scheduler:{domain}"),
        &leaves,
    )
}

fn ensure_capacity(current: usize, max: usize, label: &str) -> Result<()> {
    if current >= max {
        Err(format!("{label} capacity exceeded"))
    } else {
        Ok(())
    }
}

fn ensure_range(start_height: u64, end_height: u64, label: &str) -> Result<()> {
    if start_height > end_height {
        Err(format!("{label} start height exceeds end height"))
    } else {
        Ok(())
    }
}

fn freshness_score(median_age: u64, p95_age: u64, stale_after: u64) -> u64 {
    if p95_age >= stale_after {
        return 0;
    }
    let median_component =
        MAX_BPS.saturating_sub(median_age.saturating_mul(MAX_BPS) / stale_after.max(1));
    let tail_component =
        MAX_BPS.saturating_sub(p95_age.saturating_mul(MAX_BPS) / stale_after.max(1));
    ((median_component.saturating_mul(55) + tail_component.saturating_mul(45)) / 100).min(MAX_BPS)
}

fn sorted_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
