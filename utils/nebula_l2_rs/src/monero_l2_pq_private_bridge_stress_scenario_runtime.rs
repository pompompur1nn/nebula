use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type Runtime = State;

pub const MONERO_L2_PQ_PRIVATE_BRIDGE_STRESS_SCENARIO_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-private-bridge-stress-scenario-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_PRIVATE_BRIDGE_STRESS_SCENARIO_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_BRIDGE_ID: &str = "monero-l2-pq-private-bridge-stress-scenario-devnet";
pub const DEVNET_ASSET_ID: &str = "wxmr-devnet";
pub const DEVNET_FEE_ASSET_ID: &str = "piconero-devnet";
pub const DEVNET_HEIGHT: u64 = 1_620_000;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PQ_STRESS_ATTESTATION_SUITE: &str =
    "ML-KEM-1024+ML-DSA-87+SLH-DSA-SHAKE-256f-private-bridge-stress-v1";
pub const WATCHER_ATTESTATION_SCHEME: &str = "pq-monero-watchtower-stress-attestation-root-v1";
pub const RESERVE_RECORD_SCHEME: &str = "private-bridge-stress-reserve-record-root-v1";
pub const LIQUIDITY_RECORD_SCHEME: &str = "private-bridge-stress-liquidity-record-root-v1";
pub const OUTCOME_RECEIPT_SCHEME: &str = "private-bridge-stress-outcome-receipt-root-v1";
pub const REPLAY_DOMAIN: &str = "nebula-monero-l2-pq-private-bridge-stress-scenario-devnet";
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_WATCHER_QUORUM_BPS: u64 = 6_700;
pub const DEFAULT_DISAGREEMENT_ESCALATION_BPS: u64 = 2_500;
pub const DEFAULT_MIN_RESERVE_COVERAGE_BPS: u64 = 10_500;
pub const DEFAULT_TARGET_RESERVE_COVERAGE_BPS: u64 = 12_500;
pub const DEFAULT_CRITICAL_RESERVE_COVERAGE_BPS: u64 = 9_500;
pub const DEFAULT_MAX_REORG_DEPTH: u64 = 96;
pub const DEFAULT_FINALITY_DELAY_BLOCKS: u64 = 144;
pub const DEFAULT_WITHDRAWAL_QUEUE_LIMIT: u64 = 4_096;
pub const DEFAULT_LOW_FEE_RESCUE_BUDGET_UNITS: u64 = 4_000_000;
pub const DEFAULT_FEE_SPIKE_BPS: u64 = 1_800;
pub const DEFAULT_SUBADDRESS_CHURN_LIMIT: u64 = 65_536;
pub const DEFAULT_VIEWKEY_AUDIT_LIMIT: u64 = 8_192;
pub const MAX_SCENARIOS: usize = 1_048_576;
pub const MAX_EVENTS: usize = 4_194_304;
pub const MAX_REQUESTS: usize = 4_194_304;
pub const MAX_WATCHER_ATTESTATIONS: usize = 8_388_608;
pub const MAX_LIQUIDITY_RECORDS: usize = 2_097_152;
pub const MAX_RESERVE_RECORDS: usize = 2_097_152;
pub const MAX_OUTCOME_RECEIPTS: usize = 4_194_304;

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $label:expr),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }
        }
    };
}

string_enum!(StressScenarioKind {
    DeepReorg => "deep_reorg",
    DelayedFinality => "delayed_finality",
    LiquidityExhaustion => "liquidity_exhaustion",
    FeeSpike => "fee_spike",
    WatchtowerDisagreement => "watchtower_disagreement",
    SubaddressChurn => "subaddress_churn",
    ViewKeyAuditDemand => "view_key_audit_demand",
    WithdrawalQueueCongestion => "withdrawal_queue_congestion",
    ReserveMismatch => "reserve_mismatch",
    EmergencyLowFeeRescue => "emergency_low_fee_rescue",
});

impl StressScenarioKind {
    pub fn default_severity(self) -> StressSeverity {
        match self {
            Self::DeepReorg | Self::ReserveMismatch => StressSeverity::Critical,
            Self::LiquidityExhaustion
            | Self::WithdrawalQueueCongestion
            | Self::EmergencyLowFeeRescue => StressSeverity::High,
            Self::DelayedFinality
            | Self::FeeSpike
            | Self::WatchtowerDisagreement
            | Self::ViewKeyAuditDemand => StressSeverity::Medium,
            Self::SubaddressChurn => StressSeverity::Low,
        }
    }
}

string_enum!(StressSeverity {
    Low => "low",
    Medium => "medium",
    High => "high",
    Critical => "critical",
});

impl StressSeverity {
    pub fn score(self) -> u64 {
        match self {
            Self::Low => 10,
            Self::Medium => 30,
            Self::High => 70,
            Self::Critical => 100,
        }
    }
}

string_enum!(ScenarioStatus {
    Drafted => "drafted",
    Queued => "queued",
    Running => "running",
    Mitigating => "mitigating",
    Resolved => "resolved",
    Failed => "failed",
    Cancelled => "cancelled",
});

impl ScenarioStatus {
    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Drafted | Self::Queued | Self::Running | Self::Mitigating
        )
    }
}

string_enum!(WatcherPosition {
    Confirmed => "confirmed",
    Reorged => "reorged",
    Delayed => "delayed",
    Invalid => "invalid",
    Unknown => "unknown",
});

string_enum!(LiquidityPosture {
    Healthy => "healthy",
    Tight => "tight",
    Exhausted => "exhausted",
    BackstopOnly => "backstop_only",
    Frozen => "frozen",
});

string_enum!(ReservePosture {
    Matched => "matched",
    OverCollateralized => "over_collateralized",
    UnderCollateralized => "under_collateralized",
    Mismatched => "mismatched",
    Unknown => "unknown",
});

string_enum!(RequestKind {
    Withdrawal => "withdrawal",
    Rescue => "rescue",
    AuditDisclosure => "audit_disclosure",
    WatcherEscalation => "watcher_escalation",
    LiquidityBackstop => "liquidity_backstop",
    ReserveReconcile => "reserve_reconcile",
});

string_enum!(RequestStatus {
    Submitted => "submitted",
    Accepted => "accepted",
    Queued => "queued",
    Throttled => "throttled",
    Executed => "executed",
    Rejected => "rejected",
    Expired => "expired",
});

impl RequestStatus {
    pub fn live(self) -> bool {
        matches!(
            self,
            Self::Submitted | Self::Accepted | Self::Queued | Self::Throttled
        )
    }
}

string_enum!(OutcomeKind {
    NoAction => "no_action",
    Delayed => "delayed",
    Throttled => "throttled",
    Backstopped => "backstopped",
    Rescued => "rescued",
    Reconciled => "reconciled",
    Escalated => "escalated",
    FailedInvariant => "failed_invariant",
});

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub l2_network: String,
    pub monero_network: String,
    pub bridge_id: String,
    pub asset_id: String,
    pub fee_asset_id: String,
    pub hash_suite: String,
    pub pq_attestation_suite: String,
    pub watcher_attestation_scheme: String,
    pub reserve_record_scheme: String,
    pub liquidity_record_scheme: String,
    pub outcome_receipt_scheme: String,
    pub replay_domain: String,
    pub min_pq_security_bits: u16,
    pub min_watcher_quorum_bps: u64,
    pub disagreement_escalation_bps: u64,
    pub min_reserve_coverage_bps: u64,
    pub target_reserve_coverage_bps: u64,
    pub critical_reserve_coverage_bps: u64,
    pub max_reorg_depth: u64,
    pub finality_delay_blocks: u64,
    pub withdrawal_queue_limit: u64,
    pub low_fee_rescue_budget_units: u64,
    pub fee_spike_bps: u64,
    pub subaddress_churn_limit: u64,
    pub viewkey_audit_limit: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            bridge_id: DEVNET_BRIDGE_ID.to_string(),
            asset_id: DEVNET_ASSET_ID.to_string(),
            fee_asset_id: DEVNET_FEE_ASSET_ID.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            pq_attestation_suite: PQ_STRESS_ATTESTATION_SUITE.to_string(),
            watcher_attestation_scheme: WATCHER_ATTESTATION_SCHEME.to_string(),
            reserve_record_scheme: RESERVE_RECORD_SCHEME.to_string(),
            liquidity_record_scheme: LIQUIDITY_RECORD_SCHEME.to_string(),
            outcome_receipt_scheme: OUTCOME_RECEIPT_SCHEME.to_string(),
            replay_domain: REPLAY_DOMAIN.to_string(),
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_watcher_quorum_bps: DEFAULT_MIN_WATCHER_QUORUM_BPS,
            disagreement_escalation_bps: DEFAULT_DISAGREEMENT_ESCALATION_BPS,
            min_reserve_coverage_bps: DEFAULT_MIN_RESERVE_COVERAGE_BPS,
            target_reserve_coverage_bps: DEFAULT_TARGET_RESERVE_COVERAGE_BPS,
            critical_reserve_coverage_bps: DEFAULT_CRITICAL_RESERVE_COVERAGE_BPS,
            max_reorg_depth: DEFAULT_MAX_REORG_DEPTH,
            finality_delay_blocks: DEFAULT_FINALITY_DELAY_BLOCKS,
            withdrawal_queue_limit: DEFAULT_WITHDRAWAL_QUEUE_LIMIT,
            low_fee_rescue_budget_units: DEFAULT_LOW_FEE_RESCUE_BUDGET_UNITS,
            fee_spike_bps: DEFAULT_FEE_SPIKE_BPS,
            subaddress_churn_limit: DEFAULT_SUBADDRESS_CHURN_LIMIT,
            viewkey_audit_limit: DEFAULT_VIEWKEY_AUDIT_LIMIT,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("unexpected protocol version".to_string());
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err("unexpected schema version".to_string());
        }
        if self.min_watcher_quorum_bps > MAX_BPS {
            return Err("watcher quorum bps exceeds MAX_BPS".to_string());
        }
        if self.disagreement_escalation_bps > MAX_BPS {
            return Err("disagreement escalation bps exceeds MAX_BPS".to_string());
        }
        if self.critical_reserve_coverage_bps > self.min_reserve_coverage_bps {
            return Err("critical reserve coverage must not exceed minimum coverage".to_string());
        }
        if self.min_reserve_coverage_bps > self.target_reserve_coverage_bps {
            return Err("minimum reserve coverage must not exceed target coverage".to_string());
        }
        if self.max_reorg_depth == 0 || self.finality_delay_blocks == 0 {
            return Err("stress thresholds must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "chain_id": CHAIN_ID,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "bridge_id": self.bridge_id,
            "asset_id": self.asset_id,
            "fee_asset_id": self.fee_asset_id,
            "hash_suite": self.hash_suite,
            "pq_attestation_suite": self.pq_attestation_suite,
            "watcher_attestation_scheme": self.watcher_attestation_scheme,
            "reserve_record_scheme": self.reserve_record_scheme,
            "liquidity_record_scheme": self.liquidity_record_scheme,
            "outcome_receipt_scheme": self.outcome_receipt_scheme,
            "replay_domain": self.replay_domain,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_watcher_quorum_bps": self.min_watcher_quorum_bps,
            "disagreement_escalation_bps": self.disagreement_escalation_bps,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "target_reserve_coverage_bps": self.target_reserve_coverage_bps,
            "critical_reserve_coverage_bps": self.critical_reserve_coverage_bps,
            "max_reorg_depth": self.max_reorg_depth,
            "finality_delay_blocks": self.finality_delay_blocks,
            "withdrawal_queue_limit": self.withdrawal_queue_limit,
            "low_fee_rescue_budget_units": self.low_fee_rescue_budget_units,
            "fee_spike_bps": self.fee_spike_bps,
            "subaddress_churn_limit": self.subaddress_churn_limit,
            "viewkey_audit_limit": self.viewkey_audit_limit,
        })
    }

    pub fn root(&self) -> String {
        payload_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub scenarios: u64,
    pub events: u64,
    pub requests: u64,
    pub watcher_attestations: u64,
    pub liquidity_records: u64,
    pub reserve_records: u64,
    pub outcome_receipts: u64,
    pub invariant_checks: u64,
    pub escalations: u64,
    pub low_fee_rescues: u64,
    pub rejected_inputs: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "scenarios": self.scenarios,
            "events": self.events,
            "requests": self.requests,
            "watcher_attestations": self.watcher_attestations,
            "liquidity_records": self.liquidity_records,
            "reserve_records": self.reserve_records,
            "outcome_receipts": self.outcome_receipts,
            "invariant_checks": self.invariant_checks,
            "escalations": self.escalations,
            "low_fee_rescues": self.low_fee_rescues,
            "rejected_inputs": self.rejected_inputs,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub scenario_root: String,
    pub event_root: String,
    pub request_root: String,
    pub watcher_attestation_root: String,
    pub liquidity_record_root: String,
    pub reserve_record_root: String,
    pub outcome_receipt_root: String,
    pub invariant_root: String,
    pub counter_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty() -> Self {
        Self {
            scenario_root: merkle_root("MONERO-BRIDGE-STRESS-SCENARIOS", &[]),
            event_root: merkle_root("MONERO-BRIDGE-STRESS-EVENTS", &[]),
            request_root: merkle_root("MONERO-BRIDGE-STRESS-REQUESTS", &[]),
            watcher_attestation_root: merkle_root("MONERO-BRIDGE-STRESS-WATCHERS", &[]),
            liquidity_record_root: merkle_root("MONERO-BRIDGE-STRESS-LIQUIDITY", &[]),
            reserve_record_root: merkle_root("MONERO-BRIDGE-STRESS-RESERVES", &[]),
            outcome_receipt_root: merkle_root("MONERO-BRIDGE-STRESS-OUTCOMES", &[]),
            invariant_root: merkle_root("MONERO-BRIDGE-STRESS-INVARIANTS", &[]),
            counter_root: merkle_root("MONERO-BRIDGE-STRESS-COUNTERS", &[]),
            state_root: domain_hash(
                "MONERO-BRIDGE-STRESS-EMPTY-STATE",
                &[HashPart::Str(CHAIN_ID)],
                32,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario_root": self.scenario_root,
            "event_root": self.event_root,
            "request_root": self.request_root,
            "watcher_attestation_root": self.watcher_attestation_root,
            "liquidity_record_root": self.liquidity_record_root,
            "reserve_record_root": self.reserve_record_root,
            "outcome_receipt_root": self.outcome_receipt_root,
            "invariant_root": self.invariant_root,
            "counter_root": self.counter_root,
            "state_root": self.state_root,
        })
    }
}

impl Default for Roots {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeepReorgStress {
    pub observed_depth: u64,
    pub orphaned_l2_batches: u64,
    pub affected_deposit_notes: u64,
    pub affected_withdrawal_notes: u64,
    pub reorg_anchor_root: String,
}

impl DeepReorgStress {
    pub fn public_record(&self) -> Value {
        json!({
            "observed_depth": self.observed_depth,
            "orphaned_l2_batches": self.orphaned_l2_batches,
            "affected_deposit_notes": self.affected_deposit_notes,
            "affected_withdrawal_notes": self.affected_withdrawal_notes,
            "reorg_anchor_root": self.reorg_anchor_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelayedFinalityStress {
    pub delayed_blocks: u64,
    pub pending_anchor_count: u64,
    pub oldest_pending_height: u64,
    pub finality_vote_root: String,
}

impl DelayedFinalityStress {
    pub fn public_record(&self) -> Value {
        json!({
            "delayed_blocks": self.delayed_blocks,
            "pending_anchor_count": self.pending_anchor_count,
            "oldest_pending_height": self.oldest_pending_height,
            "finality_vote_root": self.finality_vote_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityExhaustionStress {
    pub requested_units: u64,
    pub available_units: u64,
    pub backstop_units: u64,
    pub exhausted_provider_count: u64,
    pub liquidity_root: String,
}

impl LiquidityExhaustionStress {
    pub fn public_record(&self) -> Value {
        json!({
            "requested_units": self.requested_units,
            "available_units": self.available_units,
            "backstop_units": self.backstop_units,
            "exhausted_provider_count": self.exhausted_provider_count,
            "liquidity_root": self.liquidity_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeeSpikeStress {
    pub baseline_fee_per_kb: u64,
    pub observed_fee_per_kb: u64,
    pub spike_bps: u64,
    pub sponsor_budget_units: u64,
    pub fee_oracle_root: String,
}

impl FeeSpikeStress {
    pub fn public_record(&self) -> Value {
        json!({
            "baseline_fee_per_kb": self.baseline_fee_per_kb,
            "observed_fee_per_kb": self.observed_fee_per_kb,
            "spike_bps": self.spike_bps,
            "sponsor_budget_units": self.sponsor_budget_units,
            "fee_oracle_root": self.fee_oracle_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatchtowerDisagreementStress {
    pub agreeing_weight: u64,
    pub disagreeing_weight: u64,
    pub abstaining_weight: u64,
    pub disputed_anchor_root: String,
    pub evidence_root: String,
}

impl WatchtowerDisagreementStress {
    pub fn total_weight(&self) -> u64 {
        self.agreeing_weight
            .saturating_add(self.disagreeing_weight)
            .saturating_add(self.abstaining_weight)
    }

    pub fn disagreement_bps(&self) -> u64 {
        let total = self.total_weight();
        if total == 0 {
            0
        } else {
            self.disagreeing_weight.saturating_mul(MAX_BPS) / total
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "agreeing_weight": self.agreeing_weight,
            "disagreeing_weight": self.disagreeing_weight,
            "abstaining_weight": self.abstaining_weight,
            "disagreement_bps": self.disagreement_bps(),
            "disputed_anchor_root": self.disputed_anchor_root,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SubaddressChurnStress {
    pub new_subaddresses: u64,
    pub retired_subaddresses: u64,
    pub view_tag_buckets: u64,
    pub churn_epoch: u64,
    pub subaddress_root: String,
}

impl SubaddressChurnStress {
    pub fn public_record(&self) -> Value {
        json!({
            "new_subaddresses": self.new_subaddresses,
            "retired_subaddresses": self.retired_subaddresses,
            "view_tag_buckets": self.view_tag_buckets,
            "churn_epoch": self.churn_epoch,
            "subaddress_root": self.subaddress_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ViewKeyAuditDemandStress {
    pub requested_disclosures: u64,
    pub approved_disclosures: u64,
    pub auditor_weight: u64,
    pub viewkey_policy_root: String,
    pub encrypted_grant_root: String,
}

impl ViewKeyAuditDemandStress {
    pub fn public_record(&self) -> Value {
        json!({
            "requested_disclosures": self.requested_disclosures,
            "approved_disclosures": self.approved_disclosures,
            "auditor_weight": self.auditor_weight,
            "viewkey_policy_root": self.viewkey_policy_root,
            "encrypted_grant_root": self.encrypted_grant_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WithdrawalQueueCongestionStress {
    pub queue_depth: u64,
    pub executable_count: u64,
    pub expired_count: u64,
    pub max_wait_blocks: u64,
    pub queue_root: String,
}

impl WithdrawalQueueCongestionStress {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_depth": self.queue_depth,
            "executable_count": self.executable_count,
            "expired_count": self.expired_count,
            "max_wait_blocks": self.max_wait_blocks,
            "queue_root": self.queue_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveMismatchStress {
    pub monero_reserve_units: u64,
    pub l2_liability_units: u64,
    pub proof_age_blocks: u64,
    pub reserve_root: String,
    pub liability_root: String,
}

impl ReserveMismatchStress {
    pub fn coverage_bps(&self) -> u64 {
        if self.l2_liability_units == 0 {
            MAX_BPS
        } else {
            self.monero_reserve_units.saturating_mul(MAX_BPS) / self.l2_liability_units
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "monero_reserve_units": self.monero_reserve_units,
            "l2_liability_units": self.l2_liability_units,
            "coverage_bps": self.coverage_bps(),
            "proof_age_blocks": self.proof_age_blocks,
            "reserve_root": self.reserve_root,
            "liability_root": self.liability_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyLowFeeRescueStress {
    pub rescue_budget_units: u64,
    pub stranded_request_count: u64,
    pub estimated_fee_units: u64,
    pub rescue_lane_root: String,
    pub sponsor_root: String,
}

impl EmergencyLowFeeRescueStress {
    pub fn public_record(&self) -> Value {
        json!({
            "rescue_budget_units": self.rescue_budget_units,
            "stranded_request_count": self.stranded_request_count,
            "estimated_fee_units": self.estimated_fee_units,
            "rescue_lane_root": self.rescue_lane_root,
            "sponsor_root": self.sponsor_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "stress", rename_all = "snake_case")]
pub enum StressScenario {
    DeepReorg(DeepReorgStress),
    DelayedFinality(DelayedFinalityStress),
    LiquidityExhaustion(LiquidityExhaustionStress),
    FeeSpike(FeeSpikeStress),
    WatchtowerDisagreement(WatchtowerDisagreementStress),
    SubaddressChurn(SubaddressChurnStress),
    ViewKeyAuditDemand(ViewKeyAuditDemandStress),
    WithdrawalQueueCongestion(WithdrawalQueueCongestionStress),
    ReserveMismatch(ReserveMismatchStress),
    EmergencyLowFeeRescue(EmergencyLowFeeRescueStress),
}

impl StressScenario {
    pub fn kind(&self) -> StressScenarioKind {
        match self {
            Self::DeepReorg(_) => StressScenarioKind::DeepReorg,
            Self::DelayedFinality(_) => StressScenarioKind::DelayedFinality,
            Self::LiquidityExhaustion(_) => StressScenarioKind::LiquidityExhaustion,
            Self::FeeSpike(_) => StressScenarioKind::FeeSpike,
            Self::WatchtowerDisagreement(_) => StressScenarioKind::WatchtowerDisagreement,
            Self::SubaddressChurn(_) => StressScenarioKind::SubaddressChurn,
            Self::ViewKeyAuditDemand(_) => StressScenarioKind::ViewKeyAuditDemand,
            Self::WithdrawalQueueCongestion(_) => StressScenarioKind::WithdrawalQueueCongestion,
            Self::ReserveMismatch(_) => StressScenarioKind::ReserveMismatch,
            Self::EmergencyLowFeeRescue(_) => StressScenarioKind::EmergencyLowFeeRescue,
        }
    }

    pub fn public_record(&self) -> Value {
        match self {
            Self::DeepReorg(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::DelayedFinality(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::LiquidityExhaustion(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::FeeSpike(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::WatchtowerDisagreement(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::SubaddressChurn(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::ViewKeyAuditDemand(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::WithdrawalQueueCongestion(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::ReserveMismatch(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
            Self::EmergencyLowFeeRescue(stress) => {
                json!({ "kind": self.kind().as_str(), "stress": stress.public_record() })
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScenarioRecord {
    pub scenario_id: String,
    pub operator_commitment: String,
    pub kind: StressScenarioKind,
    pub severity: StressSeverity,
    pub status: ScenarioStatus,
    pub scenario: StressScenario,
    pub created_at_height: u64,
    pub updated_at_height: u64,
    pub expires_at_height: u64,
    pub mitigation_root: String,
    pub replay_fence: String,
}

impl ScenarioRecord {
    pub fn new(
        sequence: u64,
        operator_commitment: &str,
        scenario: StressScenario,
        created_at_height: u64,
        expires_at_height: u64,
        mitigation_root: &str,
    ) -> Self {
        let kind = scenario.kind();
        let replay_fence = deterministic_id(
            "SCENARIO-REPLAY-FENCE",
            &[operator_commitment, kind.as_str(), mitigation_root],
            sequence,
        );
        let scenario_record = scenario.public_record();
        let scenario_id = domain_hash(
            "MONERO-BRIDGE-STRESS-SCENARIO-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(operator_commitment),
                HashPart::Str(kind.as_str()),
                HashPart::Json(&scenario_record),
                HashPart::U64(created_at_height),
                HashPart::U64(expires_at_height),
                HashPart::Str(mitigation_root),
            ],
            32,
        );
        Self {
            scenario_id,
            operator_commitment: operator_commitment.to_string(),
            kind,
            severity: kind.default_severity(),
            status: ScenarioStatus::Queued,
            scenario,
            created_at_height,
            updated_at_height: created_at_height,
            expires_at_height,
            mitigation_root: mitigation_root.to_string(),
            replay_fence,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind != self.scenario.kind() {
            return Err("scenario kind does not match embedded scenario".to_string());
        }
        if self.expires_at_height <= self.created_at_height {
            return Err("scenario expires before it can run".to_string());
        }
        if self.operator_commitment.is_empty() || self.mitigation_root.is_empty() {
            return Err("scenario has an empty commitment field".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "scenario_id": self.scenario_id,
            "operator_commitment": self.operator_commitment,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "scenario": self.scenario.public_record(),
            "created_at_height": self.created_at_height,
            "updated_at_height": self.updated_at_height,
            "expires_at_height": self.expires_at_height,
            "mitigation_root": self.mitigation_root,
            "replay_fence": self.replay_fence,
        })
    }

    pub fn root(&self) -> String {
        payload_root("SCENARIO", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StressEvent {
    pub event_id: String,
    pub scenario_id: String,
    pub event_type: String,
    pub height: u64,
    pub sequence: u64,
    pub payload: Value,
}

impl StressEvent {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        event_type: &str,
        height: u64,
        payload: Value,
    ) -> Self {
        let event_id = domain_hash(
            "MONERO-BRIDGE-STRESS-EVENT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(scenario_id),
                HashPart::Str(event_type),
                HashPart::U64(height),
                HashPart::U64(sequence),
                HashPart::Json(&payload),
            ],
            32,
        );
        Self {
            event_id,
            scenario_id: scenario_id.to_string(),
            event_type: event_type.to_string(),
            height,
            sequence,
            payload,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "scenario_id": self.scenario_id,
            "event_type": self.event_type,
            "height": self.height,
            "sequence": self.sequence,
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BridgeRequest {
    pub request_id: String,
    pub scenario_id: String,
    pub kind: RequestKind,
    pub status: RequestStatus,
    pub owner_commitment: String,
    pub amount_units: u64,
    pub fee_budget_units: u64,
    pub priority: u64,
    pub submitted_at_height: u64,
    pub expires_at_height: u64,
    pub nullifier_root: String,
    pub payload_root: String,
}

impl BridgeRequest {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        kind: RequestKind,
        owner_commitment: &str,
        amount_units: u64,
        fee_budget_units: u64,
        submitted_at_height: u64,
        expires_at_height: u64,
        nullifier_root: &str,
        payload_root_value: &str,
    ) -> Self {
        let priority = kind_priority(kind)
            .saturating_add(amount_units / 1_000_000)
            .saturating_add(fee_budget_units / 100_000);
        let request_id = domain_hash(
            "MONERO-BRIDGE-STRESS-REQUEST-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(owner_commitment),
                HashPart::U64(amount_units),
                HashPart::U64(fee_budget_units),
                HashPart::U64(submitted_at_height),
                HashPart::U64(expires_at_height),
                HashPart::Str(nullifier_root),
                HashPart::Str(payload_root_value),
            ],
            32,
        );
        Self {
            request_id,
            scenario_id: scenario_id.to_string(),
            kind,
            status: RequestStatus::Submitted,
            owner_commitment: owner_commitment.to_string(),
            amount_units,
            fee_budget_units,
            priority,
            submitted_at_height,
            expires_at_height,
            nullifier_root: nullifier_root.to_string(),
            payload_root: payload_root_value.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.owner_commitment.is_empty()
            || self.nullifier_root.is_empty()
            || self.payload_root.is_empty()
        {
            return Err("request has an empty commitment field".to_string());
        }
        if self.expires_at_height <= self.submitted_at_height {
            return Err("request expiry is not after submission".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "request_id": self.request_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "owner_commitment": self.owner_commitment,
            "amount_units": self.amount_units,
            "fee_budget_units": self.fee_budget_units,
            "priority": self.priority,
            "submitted_at_height": self.submitted_at_height,
            "expires_at_height": self.expires_at_height,
            "nullifier_root": self.nullifier_root,
            "payload_root": self.payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WatcherAttestation {
    pub attestation_id: String,
    pub scenario_id: String,
    pub watcher_id: String,
    pub position: WatcherPosition,
    pub weight: u64,
    pub observed_monero_height: u64,
    pub observed_l2_height: u64,
    pub subject_root: String,
    pub evidence_root: String,
    pub pq_signature_root: String,
    pub signed_at_height: u64,
}

impl WatcherAttestation {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        watcher_id: &str,
        position: WatcherPosition,
        weight: u64,
        observed_monero_height: u64,
        observed_l2_height: u64,
        subject_root: &str,
        evidence_root: &str,
        pq_signature_root: &str,
        signed_at_height: u64,
    ) -> Self {
        let attestation_id = domain_hash(
            "MONERO-BRIDGE-STRESS-WATCHER-ATTESTATION-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(watcher_id),
                HashPart::Str(position.as_str()),
                HashPart::U64(weight),
                HashPart::U64(observed_monero_height),
                HashPart::U64(observed_l2_height),
                HashPart::Str(subject_root),
                HashPart::Str(evidence_root),
                HashPart::Str(pq_signature_root),
            ],
            32,
        );
        Self {
            attestation_id,
            scenario_id: scenario_id.to_string(),
            watcher_id: watcher_id.to_string(),
            position,
            weight,
            observed_monero_height,
            observed_l2_height,
            subject_root: subject_root.to_string(),
            evidence_root: evidence_root.to_string(),
            pq_signature_root: pq_signature_root.to_string(),
            signed_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "attestation_id": self.attestation_id,
            "scenario_id": self.scenario_id,
            "watcher_id": self.watcher_id,
            "position": self.position.as_str(),
            "weight": self.weight,
            "observed_monero_height": self.observed_monero_height,
            "observed_l2_height": self.observed_l2_height,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "pq_signature_root": self.pq_signature_root,
            "signed_at_height": self.signed_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiquidityRecord {
    pub liquidity_id: String,
    pub scenario_id: String,
    pub provider_commitment: String,
    pub posture: LiquidityPosture,
    pub available_units: u64,
    pub reserved_units: u64,
    pub backstop_units: u64,
    pub max_single_withdrawal_units: u64,
    pub fee_ceiling_bps: u64,
    pub updated_at_height: u64,
}

impl LiquidityRecord {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        provider_commitment: &str,
        available_units: u64,
        reserved_units: u64,
        backstop_units: u64,
        max_single_withdrawal_units: u64,
        fee_ceiling_bps: u64,
        updated_at_height: u64,
    ) -> Self {
        let posture = if available_units == 0 {
            LiquidityPosture::Exhausted
        } else if available_units < reserved_units {
            LiquidityPosture::Tight
        } else {
            LiquidityPosture::Healthy
        };
        let liquidity_id = domain_hash(
            "MONERO-BRIDGE-STRESS-LIQUIDITY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(provider_commitment),
                HashPart::U64(available_units),
                HashPart::U64(reserved_units),
                HashPart::U64(backstop_units),
                HashPart::U64(updated_at_height),
            ],
            32,
        );
        Self {
            liquidity_id,
            scenario_id: scenario_id.to_string(),
            provider_commitment: provider_commitment.to_string(),
            posture,
            available_units,
            reserved_units,
            backstop_units,
            max_single_withdrawal_units,
            fee_ceiling_bps,
            updated_at_height,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "liquidity_id": self.liquidity_id,
            "scenario_id": self.scenario_id,
            "provider_commitment": self.provider_commitment,
            "posture": self.posture.as_str(),
            "available_units": self.available_units,
            "reserved_units": self.reserved_units,
            "backstop_units": self.backstop_units,
            "max_single_withdrawal_units": self.max_single_withdrawal_units,
            "fee_ceiling_bps": self.fee_ceiling_bps,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReserveRecord {
    pub reserve_id: String,
    pub scenario_id: String,
    pub custodian_commitment: String,
    pub posture: ReservePosture,
    pub monero_reserve_units: u64,
    pub l2_liability_units: u64,
    pub pending_exit_units: u64,
    pub reserve_proof_root: String,
    pub liability_root: String,
    pub updated_at_height: u64,
}

impl ReserveRecord {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        custodian_commitment: &str,
        monero_reserve_units: u64,
        l2_liability_units: u64,
        pending_exit_units: u64,
        reserve_proof_root: &str,
        liability_root: &str,
        updated_at_height: u64,
    ) -> Self {
        let coverage = coverage_bps(
            monero_reserve_units,
            l2_liability_units.saturating_add(pending_exit_units),
        );
        let posture = if coverage < DEFAULT_CRITICAL_RESERVE_COVERAGE_BPS {
            ReservePosture::Mismatched
        } else if coverage < DEFAULT_MIN_RESERVE_COVERAGE_BPS {
            ReservePosture::UnderCollateralized
        } else if coverage > DEFAULT_TARGET_RESERVE_COVERAGE_BPS {
            ReservePosture::OverCollateralized
        } else {
            ReservePosture::Matched
        };
        let reserve_id = domain_hash(
            "MONERO-BRIDGE-STRESS-RESERVE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(custodian_commitment),
                HashPart::U64(monero_reserve_units),
                HashPart::U64(l2_liability_units),
                HashPart::U64(pending_exit_units),
                HashPart::Str(reserve_proof_root),
                HashPart::Str(liability_root),
            ],
            32,
        );
        Self {
            reserve_id,
            scenario_id: scenario_id.to_string(),
            custodian_commitment: custodian_commitment.to_string(),
            posture,
            monero_reserve_units,
            l2_liability_units,
            pending_exit_units,
            reserve_proof_root: reserve_proof_root.to_string(),
            liability_root: liability_root.to_string(),
            updated_at_height,
        }
    }

    pub fn coverage_bps(&self) -> u64 {
        coverage_bps(
            self.monero_reserve_units,
            self.l2_liability_units
                .saturating_add(self.pending_exit_units),
        )
    }

    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "scenario_id": self.scenario_id,
            "custodian_commitment": self.custodian_commitment,
            "posture": self.posture.as_str(),
            "monero_reserve_units": self.monero_reserve_units,
            "l2_liability_units": self.l2_liability_units,
            "pending_exit_units": self.pending_exit_units,
            "coverage_bps": self.coverage_bps(),
            "reserve_proof_root": self.reserve_proof_root,
            "liability_root": self.liability_root,
            "updated_at_height": self.updated_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutcomeReceipt {
    pub receipt_id: String,
    pub scenario_id: String,
    pub kind: OutcomeKind,
    pub severity: StressSeverity,
    pub request_root: String,
    pub watcher_root: String,
    pub liquidity_root: String,
    pub reserve_root: String,
    pub invariant_root: String,
    pub executed_at_height: u64,
    pub notes: String,
}

impl OutcomeReceipt {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        kind: OutcomeKind,
        severity: StressSeverity,
        request_root: &str,
        watcher_root: &str,
        liquidity_root: &str,
        reserve_root: &str,
        invariant_root: &str,
        executed_at_height: u64,
        notes: &str,
    ) -> Self {
        let receipt_id = domain_hash(
            "MONERO-BRIDGE-STRESS-OUTCOME-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(request_root),
                HashPart::Str(watcher_root),
                HashPart::Str(liquidity_root),
                HashPart::Str(reserve_root),
                HashPart::Str(invariant_root),
                HashPart::U64(executed_at_height),
            ],
            32,
        );
        Self {
            receipt_id,
            scenario_id: scenario_id.to_string(),
            kind,
            severity,
            request_root: request_root.to_string(),
            watcher_root: watcher_root.to_string(),
            liquidity_root: liquidity_root.to_string(),
            reserve_root: reserve_root.to_string(),
            invariant_root: invariant_root.to_string(),
            executed_at_height,
            notes: notes.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "receipt_id": self.receipt_id,
            "scenario_id": self.scenario_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "request_root": self.request_root,
            "watcher_root": self.watcher_root,
            "liquidity_root": self.liquidity_root,
            "reserve_root": self.reserve_root,
            "invariant_root": self.invariant_root,
            "executed_at_height": self.executed_at_height,
            "notes": self.notes,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InvariantCheck {
    pub invariant_id: String,
    pub scenario_id: String,
    pub name: String,
    pub passed: bool,
    pub severity: StressSeverity,
    pub observed_value: u64,
    pub threshold_value: u64,
    pub evidence_root: String,
}

impl InvariantCheck {
    pub fn new(
        sequence: u64,
        scenario_id: &str,
        name: &str,
        passed: bool,
        severity: StressSeverity,
        observed_value: u64,
        threshold_value: u64,
        evidence_root: &str,
    ) -> Self {
        let invariant_id = domain_hash(
            "MONERO-BRIDGE-STRESS-INVARIANT-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::U64(sequence),
                HashPart::Str(scenario_id),
                HashPart::Str(name),
                HashPart::Str(if passed { "passed" } else { "failed" }),
                HashPart::U64(observed_value),
                HashPart::U64(threshold_value),
                HashPart::Str(evidence_root),
            ],
            32,
        );
        Self {
            invariant_id,
            scenario_id: scenario_id.to_string(),
            name: name.to_string(),
            passed,
            severity,
            observed_value,
            threshold_value,
            evidence_root: evidence_root.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "invariant_id": self.invariant_id,
            "scenario_id": self.scenario_id,
            "name": self.name,
            "passed": self.passed,
            "severity": self.severity.as_str(),
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub roots: Roots,
    pub scenarios: BTreeMap<String, ScenarioRecord>,
    pub events: BTreeMap<String, StressEvent>,
    pub requests: BTreeMap<String, BridgeRequest>,
    pub watcher_attestations: BTreeMap<String, WatcherAttestation>,
    pub liquidity_records: BTreeMap<String, LiquidityRecord>,
    pub reserve_records: BTreeMap<String, ReserveRecord>,
    pub outcome_receipts: BTreeMap<String, OutcomeReceipt>,
    pub invariant_checks: BTreeMap<String, InvariantCheck>,
    pub replay_fences: BTreeSet<String>,
}

impl State {
    pub fn with_config(config: Config) -> Result<Self> {
        config.validate()?;
        let mut state = Self {
            config,
            counters: Counters::default(),
            roots: Roots::empty(),
            scenarios: BTreeMap::new(),
            events: BTreeMap::new(),
            requests: BTreeMap::new(),
            watcher_attestations: BTreeMap::new(),
            liquidity_records: BTreeMap::new(),
            reserve_records: BTreeMap::new(),
            outcome_receipts: BTreeMap::new(),
            invariant_checks: BTreeMap::new(),
            replay_fences: BTreeSet::new(),
        };
        state.refresh_roots();
        Ok(state)
    }

    pub fn devnet() -> Result<Self> {
        let mut state = Self::with_config(Config::devnet())?;
        seed_devnet_scenarios(&mut state)?;
        state.run_invariant_checks(DEVNET_HEIGHT.saturating_add(12));
        state.issue_outcome_receipts(DEVNET_HEIGHT.saturating_add(24));
        Ok(state)
    }

    pub fn demo() -> Result<Self> {
        Self::devnet()
    }

    pub fn register_scenario(&mut self, mut scenario: ScenarioRecord) -> Result<String> {
        scenario.validate()?;
        if self.scenarios.len() >= MAX_SCENARIOS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("scenario capacity exhausted".to_string());
        }
        if self.replay_fences.contains(&scenario.replay_fence) {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("scenario replay fence already used".to_string());
        }
        scenario.status = ScenarioStatus::Running;
        let scenario_id = scenario.scenario_id.clone();
        self.replay_fences.insert(scenario.replay_fence.clone());
        self.scenarios.insert(scenario_id.clone(), scenario);
        self.counters.scenarios = self.counters.scenarios.saturating_add(1);
        self.push_event(
            &scenario_id,
            "scenario_registered",
            DEVNET_HEIGHT.saturating_add(self.counters.scenarios),
            json!({ "scenario_id": scenario_id, "registered": true }),
        );
        self.refresh_roots();
        Ok(scenario_id)
    }

    pub fn submit_request(&mut self, mut request: BridgeRequest) -> Result<String> {
        request.validate()?;
        if self.requests.len() >= MAX_REQUESTS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("request capacity exhausted".to_string());
        }
        if !self.scenarios.contains_key(&request.scenario_id) {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("request references unknown scenario".to_string());
        }
        if self
            .requests
            .values()
            .any(|existing| existing.nullifier_root == request.nullifier_root)
        {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("request nullifier already used".to_string());
        }
        request.status = if self.live_request_count() >= self.config.withdrawal_queue_limit {
            RequestStatus::Throttled
        } else {
            RequestStatus::Queued
        };
        let request_id = request.request_id.clone();
        let scenario_id = request.scenario_id.clone();
        self.requests.insert(request_id.clone(), request);
        self.counters.requests = self.counters.requests.saturating_add(1);
        self.push_event(
            &scenario_id,
            "request_submitted",
            DEVNET_HEIGHT.saturating_add(self.counters.requests),
            json!({ "request_id": request_id, "live_request_count": self.live_request_count() }),
        );
        self.refresh_roots();
        Ok(request_id)
    }

    pub fn record_watcher_attestation(
        &mut self,
        attestation: WatcherAttestation,
    ) -> Result<String> {
        if self.watcher_attestations.len() >= MAX_WATCHER_ATTESTATIONS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("watcher attestation capacity exhausted".to_string());
        }
        if !self.scenarios.contains_key(&attestation.scenario_id) {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("attestation references unknown scenario".to_string());
        }
        if attestation.watcher_id.is_empty() || attestation.weight == 0 {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("attestation has empty watcher or zero weight".to_string());
        }
        let id = attestation.attestation_id.clone();
        let scenario_id = attestation.scenario_id.clone();
        self.watcher_attestations.insert(id.clone(), attestation);
        self.counters.watcher_attestations = self.counters.watcher_attestations.saturating_add(1);
        self.push_event(
            &scenario_id,
            "watcher_attested",
            DEVNET_HEIGHT,
            json!({ "attestation_id": id }),
        );
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_liquidity(&mut self, record: LiquidityRecord) -> Result<String> {
        if self.liquidity_records.len() >= MAX_LIQUIDITY_RECORDS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("liquidity record capacity exhausted".to_string());
        }
        if record.fee_ceiling_bps > MAX_BPS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("liquidity fee ceiling exceeds MAX_BPS".to_string());
        }
        let id = record.liquidity_id.clone();
        let scenario_id = record.scenario_id.clone();
        self.liquidity_records.insert(id.clone(), record);
        self.counters.liquidity_records = self.counters.liquidity_records.saturating_add(1);
        self.push_event(
            &scenario_id,
            "liquidity_recorded",
            DEVNET_HEIGHT,
            json!({ "liquidity_id": id }),
        );
        self.refresh_roots();
        Ok(id)
    }

    pub fn record_reserve(&mut self, record: ReserveRecord) -> Result<String> {
        if self.reserve_records.len() >= MAX_RESERVE_RECORDS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return Err("reserve record capacity exhausted".to_string());
        }
        let id = record.reserve_id.clone();
        let scenario_id = record.scenario_id.clone();
        self.reserve_records.insert(id.clone(), record);
        self.counters.reserve_records = self.counters.reserve_records.saturating_add(1);
        self.push_event(
            &scenario_id,
            "reserve_recorded",
            DEVNET_HEIGHT,
            json!({ "reserve_id": id }),
        );
        self.refresh_roots();
        Ok(id)
    }

    pub fn run_invariant_checks(&mut self, height: u64) -> Vec<InvariantCheck> {
        let mut checks = Vec::new();
        let scenario_ids = self.scenarios.keys().cloned().collect::<Vec<_>>();
        for scenario_id in scenario_ids {
            if let Some(scenario) = self.scenarios.get(&scenario_id) {
                let severity = scenario.severity;
                checks.extend(self.scenario_invariants(&scenario_id, severity));
            }
        }
        for mut check in checks.clone() {
            check.evidence_root = payload_root("INVARIANT-EVIDENCE", &check.public_record());
            self.invariant_checks
                .insert(check.invariant_id.clone(), check);
            self.counters.invariant_checks = self.counters.invariant_checks.saturating_add(1);
        }
        self.push_event(
            "global",
            "invariants_checked",
            height,
            json!({ "check_count": checks.len(), "failed_count": checks.iter().filter(|c| !c.passed).count() }),
        );
        self.refresh_roots();
        checks
    }

    pub fn issue_outcome_receipts(&mut self, height: u64) -> Vec<OutcomeReceipt> {
        let mut receipts = Vec::new();
        let scenario_ids = self.scenarios.keys().cloned().collect::<Vec<_>>();
        for scenario_id in scenario_ids {
            if let Some(scenario) = self.scenarios.get(&scenario_id) {
                let failed = self
                    .invariant_checks
                    .values()
                    .any(|check| check.scenario_id == scenario_id && !check.passed);
                let kind = self.derive_outcome_kind(&scenario_id, scenario, failed);
                let request_root = self.request_root_for_scenario(&scenario_id);
                let watcher_root = self.watcher_root_for_scenario(&scenario_id);
                let liquidity_root = self.liquidity_root_for_scenario(&scenario_id);
                let reserve_root = self.reserve_root_for_scenario(&scenario_id);
                let invariant_root = self.invariant_root_for_scenario(&scenario_id);
                let notes = outcome_notes(kind, scenario.kind);
                let receipt = OutcomeReceipt::new(
                    self.counters.outcome_receipts.saturating_add(1),
                    &scenario_id,
                    kind,
                    scenario.severity,
                    &request_root,
                    &watcher_root,
                    &liquidity_root,
                    &reserve_root,
                    &invariant_root,
                    height,
                    notes,
                );
                receipts.push(receipt);
            }
        }
        for receipt in receipts.clone() {
            if self.outcome_receipts.len() >= MAX_OUTCOME_RECEIPTS {
                self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
                break;
            }
            if receipt.kind == OutcomeKind::Escalated {
                self.counters.escalations = self.counters.escalations.saturating_add(1);
            }
            if receipt.kind == OutcomeKind::Rescued {
                self.counters.low_fee_rescues = self.counters.low_fee_rescues.saturating_add(1);
            }
            self.outcome_receipts
                .insert(receipt.receipt_id.clone(), receipt);
            self.counters.outcome_receipts = self.counters.outcome_receipts.saturating_add(1);
        }
        self.refresh_roots();
        receipts
    }

    pub fn live_request_count(&self) -> u64 {
        self.requests
            .values()
            .filter(|request| request.status.live())
            .count() as u64
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut object) = record {
            object.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "scenarios": self.scenarios.values().map(ScenarioRecord::public_record).collect::<Vec<_>>(),
            "events": self.events.values().map(StressEvent::public_record).collect::<Vec<_>>(),
            "requests": self.requests.values().map(BridgeRequest::public_record).collect::<Vec<_>>(),
            "watcher_attestations": self.watcher_attestations.values().map(WatcherAttestation::public_record).collect::<Vec<_>>(),
            "liquidity_records": self.liquidity_records.values().map(LiquidityRecord::public_record).collect::<Vec<_>>(),
            "reserve_records": self.reserve_records.values().map(ReserveRecord::public_record).collect::<Vec<_>>(),
            "outcome_receipts": self.outcome_receipts.values().map(OutcomeReceipt::public_record).collect::<Vec<_>>(),
            "invariant_checks": self.invariant_checks.values().map(InvariantCheck::public_record).collect::<Vec<_>>(),
            "replay_fence_root": merkle_root("MONERO-BRIDGE-STRESS-REPLAY-FENCES", &self.replay_fences.iter().map(|fence| json!(fence)).collect::<Vec<_>>()),
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record_without_state_root())
    }

    pub fn refresh_roots(&mut self) {
        let scenario_records = self
            .scenarios
            .values()
            .map(ScenarioRecord::public_record)
            .collect::<Vec<_>>();
        let event_records = self
            .events
            .values()
            .map(StressEvent::public_record)
            .collect::<Vec<_>>();
        let request_records = self
            .requests
            .values()
            .map(BridgeRequest::public_record)
            .collect::<Vec<_>>();
        let watcher_records = self
            .watcher_attestations
            .values()
            .map(WatcherAttestation::public_record)
            .collect::<Vec<_>>();
        let liquidity_records = self
            .liquidity_records
            .values()
            .map(LiquidityRecord::public_record)
            .collect::<Vec<_>>();
        let reserve_records = self
            .reserve_records
            .values()
            .map(ReserveRecord::public_record)
            .collect::<Vec<_>>();
        let receipt_records = self
            .outcome_receipts
            .values()
            .map(OutcomeReceipt::public_record)
            .collect::<Vec<_>>();
        let invariant_records = self
            .invariant_checks
            .values()
            .map(InvariantCheck::public_record)
            .collect::<Vec<_>>();
        let counter_records = vec![self.counters.public_record()];
        self.roots = Roots {
            scenario_root: merkle_root("MONERO-BRIDGE-STRESS-SCENARIOS", &scenario_records),
            event_root: merkle_root("MONERO-BRIDGE-STRESS-EVENTS", &event_records),
            request_root: merkle_root("MONERO-BRIDGE-STRESS-REQUESTS", &request_records),
            watcher_attestation_root: merkle_root(
                "MONERO-BRIDGE-STRESS-WATCHERS",
                &watcher_records,
            ),
            liquidity_record_root: merkle_root(
                "MONERO-BRIDGE-STRESS-LIQUIDITY",
                &liquidity_records,
            ),
            reserve_record_root: merkle_root("MONERO-BRIDGE-STRESS-RESERVES", &reserve_records),
            outcome_receipt_root: merkle_root("MONERO-BRIDGE-STRESS-OUTCOMES", &receipt_records),
            invariant_root: merkle_root("MONERO-BRIDGE-STRESS-INVARIANTS", &invariant_records),
            counter_root: merkle_root("MONERO-BRIDGE-STRESS-COUNTERS", &counter_records),
            state_root: self.state_root(),
        };
    }

    fn push_event(&mut self, scenario_id: &str, event_type: &str, height: u64, payload: Value) {
        if self.events.len() >= MAX_EVENTS {
            self.counters.rejected_inputs = self.counters.rejected_inputs.saturating_add(1);
            return;
        }
        let sequence = self.counters.events.saturating_add(1);
        let event = StressEvent::new(sequence, scenario_id, event_type, height, payload);
        self.events.insert(event.event_id.clone(), event);
        self.counters.events = sequence;
    }

    fn scenario_invariants(
        &self,
        scenario_id: &str,
        severity: StressSeverity,
    ) -> Vec<InvariantCheck> {
        let mut checks = Vec::new();
        if let Some(scenario) = self.scenarios.get(scenario_id) {
            match &scenario.scenario {
                StressScenario::DeepReorg(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "deep_reorg_depth_within_configured_limit",
                    stress.observed_depth <= self.config.max_reorg_depth,
                    severity,
                    stress.observed_depth,
                    self.config.max_reorg_depth,
                    &stress.reorg_anchor_root,
                )),
                StressScenario::DelayedFinality(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "delayed_finality_within_configured_window",
                    stress.delayed_blocks <= self.config.finality_delay_blocks,
                    severity,
                    stress.delayed_blocks,
                    self.config.finality_delay_blocks,
                    &stress.finality_vote_root,
                )),
                StressScenario::LiquidityExhaustion(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "liquidity_plus_backstop_covers_requested_units",
                    stress.available_units.saturating_add(stress.backstop_units)
                        >= stress.requested_units,
                    severity,
                    stress.available_units.saturating_add(stress.backstop_units),
                    stress.requested_units,
                    &stress.liquidity_root,
                )),
                StressScenario::FeeSpike(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "fee_spike_within_rescue_policy",
                    stress.spike_bps <= self.config.fee_spike_bps
                        || stress.sponsor_budget_units >= stress.observed_fee_per_kb,
                    severity,
                    stress.spike_bps,
                    self.config.fee_spike_bps,
                    &stress.fee_oracle_root,
                )),
                StressScenario::WatchtowerDisagreement(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "watchtower_disagreement_below_escalation_threshold",
                    stress.disagreement_bps() <= self.config.disagreement_escalation_bps,
                    severity,
                    stress.disagreement_bps(),
                    self.config.disagreement_escalation_bps,
                    &stress.evidence_root,
                )),
                StressScenario::SubaddressChurn(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "subaddress_churn_within_viewtag_capacity",
                    stress
                        .new_subaddresses
                        .saturating_add(stress.retired_subaddresses)
                        <= self.config.subaddress_churn_limit,
                    severity,
                    stress
                        .new_subaddresses
                        .saturating_add(stress.retired_subaddresses),
                    self.config.subaddress_churn_limit,
                    &stress.subaddress_root,
                )),
                StressScenario::ViewKeyAuditDemand(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "viewkey_audit_demand_within_grant_capacity",
                    stress.requested_disclosures <= self.config.viewkey_audit_limit,
                    severity,
                    stress.requested_disclosures,
                    self.config.viewkey_audit_limit,
                    &stress.encrypted_grant_root,
                )),
                StressScenario::WithdrawalQueueCongestion(stress) => {
                    checks.push(InvariantCheck::new(
                        self.counters
                            .invariant_checks
                            .saturating_add(checks.len() as u64)
                            .saturating_add(1),
                        scenario_id,
                        "withdrawal_queue_within_configured_limit",
                        stress.queue_depth <= self.config.withdrawal_queue_limit,
                        severity,
                        stress.queue_depth,
                        self.config.withdrawal_queue_limit,
                        &stress.queue_root,
                    ))
                }
                StressScenario::ReserveMismatch(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "reserve_coverage_above_minimum",
                    stress.coverage_bps() >= self.config.min_reserve_coverage_bps,
                    severity,
                    stress.coverage_bps(),
                    self.config.min_reserve_coverage_bps,
                    &stress.reserve_root,
                )),
                StressScenario::EmergencyLowFeeRescue(stress) => checks.push(InvariantCheck::new(
                    self.counters
                        .invariant_checks
                        .saturating_add(checks.len() as u64)
                        .saturating_add(1),
                    scenario_id,
                    "emergency_low_fee_rescue_budget_covers_estimate",
                    stress
                        .rescue_budget_units
                        .min(self.config.low_fee_rescue_budget_units)
                        >= stress.estimated_fee_units,
                    severity,
                    stress.rescue_budget_units,
                    stress.estimated_fee_units,
                    &stress.rescue_lane_root,
                )),
            }
        }
        checks
    }

    fn derive_outcome_kind(
        &self,
        scenario_id: &str,
        scenario: &ScenarioRecord,
        failed: bool,
    ) -> OutcomeKind {
        if failed {
            return OutcomeKind::FailedInvariant;
        }
        match scenario.kind {
            StressScenarioKind::DeepReorg | StressScenarioKind::WatchtowerDisagreement => {
                OutcomeKind::Escalated
            }
            StressScenarioKind::DelayedFinality => OutcomeKind::Delayed,
            StressScenarioKind::LiquidityExhaustion => OutcomeKind::Backstopped,
            StressScenarioKind::FeeSpike | StressScenarioKind::EmergencyLowFeeRescue => {
                OutcomeKind::Rescued
            }
            StressScenarioKind::WithdrawalQueueCongestion => OutcomeKind::Throttled,
            StressScenarioKind::ReserveMismatch => OutcomeKind::Reconciled,
            StressScenarioKind::SubaddressChurn | StressScenarioKind::ViewKeyAuditDemand => {
                if self
                    .requests
                    .values()
                    .any(|request| request.scenario_id == scenario_id && request.status.live())
                {
                    OutcomeKind::Throttled
                } else {
                    OutcomeKind::NoAction
                }
            }
        }
    }

    fn request_root_for_scenario(&self, scenario_id: &str) -> String {
        public_record_root(
            "MONERO-BRIDGE-STRESS-SCENARIO-REQUESTS",
            self.requests
                .values()
                .filter(|record| record.scenario_id == scenario_id)
                .map(BridgeRequest::public_record)
                .collect(),
        )
    }

    fn watcher_root_for_scenario(&self, scenario_id: &str) -> String {
        public_record_root(
            "MONERO-BRIDGE-STRESS-SCENARIO-WATCHERS",
            self.watcher_attestations
                .values()
                .filter(|record| record.scenario_id == scenario_id)
                .map(WatcherAttestation::public_record)
                .collect(),
        )
    }

    fn liquidity_root_for_scenario(&self, scenario_id: &str) -> String {
        public_record_root(
            "MONERO-BRIDGE-STRESS-SCENARIO-LIQUIDITY",
            self.liquidity_records
                .values()
                .filter(|record| record.scenario_id == scenario_id)
                .map(LiquidityRecord::public_record)
                .collect(),
        )
    }

    fn reserve_root_for_scenario(&self, scenario_id: &str) -> String {
        public_record_root(
            "MONERO-BRIDGE-STRESS-SCENARIO-RESERVES",
            self.reserve_records
                .values()
                .filter(|record| record.scenario_id == scenario_id)
                .map(ReserveRecord::public_record)
                .collect(),
        )
    }

    fn invariant_root_for_scenario(&self, scenario_id: &str) -> String {
        public_record_root(
            "MONERO-BRIDGE-STRESS-SCENARIO-INVARIANTS",
            self.invariant_checks
                .values()
                .filter(|record| record.scenario_id == scenario_id)
                .map(InvariantCheck::public_record)
                .collect(),
        )
    }
}

pub fn devnet() -> Result<State> {
    State::devnet()
}

pub fn demo() -> Result<State> {
    State::demo()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn public_record_root(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

pub fn payload_root(label: &str, payload: &Value) -> String {
    domain_hash(
        &format!("MONERO-BRIDGE-STRESS-{label}"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(payload),
        ],
        32,
    )
}

pub fn public_record_id(label: &str, record: &Value) -> String {
    domain_hash(
        &format!("MONERO-BRIDGE-STRESS-{label}-ID"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn state_root_from_record(record: &Value) -> String {
    payload_root("STATE", record)
}

pub fn deterministic_id(domain: &str, parts: &[&str], sequence: u64) -> String {
    let mut hash_parts = vec![
        HashPart::Str(CHAIN_ID),
        HashPart::Str(PROTOCOL_VERSION),
        HashPart::Str(REPLAY_DOMAIN),
        HashPart::U64(sequence),
    ];
    for part in parts {
        hash_parts.push(HashPart::Str(part));
    }
    domain_hash(domain, &hash_parts, 32)
}

pub fn deterministic_root(domain: &str, label: &str, sequence: u64) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(sequence),
        ],
        32,
    )
}

pub fn coverage_bps(reserve_units: u64, liability_units: u64) -> u64 {
    if liability_units == 0 {
        MAX_BPS
    } else {
        reserve_units.saturating_mul(MAX_BPS) / liability_units
    }
}

fn kind_priority(kind: RequestKind) -> u64 {
    match kind {
        RequestKind::Rescue => 1_000,
        RequestKind::LiquidityBackstop => 940,
        RequestKind::ReserveReconcile => 900,
        RequestKind::WatcherEscalation => 860,
        RequestKind::Withdrawal => 760,
        RequestKind::AuditDisclosure => 700,
    }
}

fn outcome_notes(kind: OutcomeKind, scenario_kind: StressScenarioKind) -> &'static str {
    match (kind, scenario_kind) {
        (OutcomeKind::FailedInvariant, _) => {
            "one or more configured bridge stress invariants failed"
        }
        (OutcomeKind::Escalated, StressScenarioKind::DeepReorg) => {
            "deep reorg stress escalated to finality safety operators"
        }
        (OutcomeKind::Escalated, StressScenarioKind::WatchtowerDisagreement) => {
            "watchtower disagreement escalated for evidence arbitration"
        }
        (OutcomeKind::Backstopped, _) => "liquidity backstop covered stressed withdrawal demand",
        (OutcomeKind::Rescued, _) => "low-fee rescue path funded stressed bridge execution",
        (OutcomeKind::Reconciled, _) => "reserve reconciliation receipt issued",
        (OutcomeKind::Throttled, _) => "queue pressure throttled without breaking privacy fences",
        (OutcomeKind::Delayed, _) => "finality delay acknowledged within configured policy",
        _ => "scenario completed without additional action",
    }
}

fn seed_devnet_scenarios(state: &mut State) -> Result<()> {
    let scenarios = vec![
        StressScenario::DeepReorg(DeepReorgStress {
            observed_depth: 64,
            orphaned_l2_batches: 8,
            affected_deposit_notes: 512,
            affected_withdrawal_notes: 384,
            reorg_anchor_root: deterministic_root("DEVNET-DEEP-REORG", "anchor", 1),
        }),
        StressScenario::DelayedFinality(DelayedFinalityStress {
            delayed_blocks: 96,
            pending_anchor_count: 42,
            oldest_pending_height: DEVNET_HEIGHT.saturating_sub(96),
            finality_vote_root: deterministic_root("DEVNET-DELAYED-FINALITY", "votes", 2),
        }),
        StressScenario::LiquidityExhaustion(LiquidityExhaustionStress {
            requested_units: 8_000_000,
            available_units: 4_500_000,
            backstop_units: 4_000_000,
            exhausted_provider_count: 7,
            liquidity_root: deterministic_root("DEVNET-LIQUIDITY-EXHAUSTION", "liquidity", 3),
        }),
        StressScenario::FeeSpike(FeeSpikeStress {
            baseline_fee_per_kb: 24,
            observed_fee_per_kb: 410,
            spike_bps: 1_708,
            sponsor_budget_units: 1_000_000,
            fee_oracle_root: deterministic_root("DEVNET-FEE-SPIKE", "oracle", 4),
        }),
        StressScenario::WatchtowerDisagreement(WatchtowerDisagreementStress {
            agreeing_weight: 72,
            disagreeing_weight: 12,
            abstaining_weight: 4,
            disputed_anchor_root: deterministic_root("DEVNET-WATCHTOWER-DISAGREEMENT", "anchor", 5),
            evidence_root: deterministic_root("DEVNET-WATCHTOWER-DISAGREEMENT", "evidence", 5),
        }),
        StressScenario::SubaddressChurn(SubaddressChurnStress {
            new_subaddresses: 32_000,
            retired_subaddresses: 12_000,
            view_tag_buckets: 2_048,
            churn_epoch: 9,
            subaddress_root: deterministic_root("DEVNET-SUBADDRESS-CHURN", "subaddresses", 6),
        }),
        StressScenario::ViewKeyAuditDemand(ViewKeyAuditDemandStress {
            requested_disclosures: 6_144,
            approved_disclosures: 5_888,
            auditor_weight: 48,
            viewkey_policy_root: deterministic_root("DEVNET-VIEWKEY-AUDIT", "policy", 7),
            encrypted_grant_root: deterministic_root("DEVNET-VIEWKEY-AUDIT", "grant", 7),
        }),
        StressScenario::WithdrawalQueueCongestion(WithdrawalQueueCongestionStress {
            queue_depth: 3_840,
            executable_count: 2_240,
            expired_count: 9,
            max_wait_blocks: 88,
            queue_root: deterministic_root("DEVNET-WITHDRAWAL-QUEUE", "queue", 8),
        }),
        StressScenario::ReserveMismatch(ReserveMismatchStress {
            monero_reserve_units: 12_000_000,
            l2_liability_units: 11_000_000,
            proof_age_blocks: 18,
            reserve_root: deterministic_root("DEVNET-RESERVE-MISMATCH", "reserve", 9),
            liability_root: deterministic_root("DEVNET-RESERVE-MISMATCH", "liability", 9),
        }),
        StressScenario::EmergencyLowFeeRescue(EmergencyLowFeeRescueStress {
            rescue_budget_units: 3_500_000,
            stranded_request_count: 768,
            estimated_fee_units: 2_250_000,
            rescue_lane_root: deterministic_root("DEVNET-LOW-FEE-RESCUE", "lane", 10),
            sponsor_root: deterministic_root("DEVNET-LOW-FEE-RESCUE", "sponsor", 10),
        }),
    ];

    for (index, scenario) in scenarios.into_iter().enumerate() {
        let sequence = index as u64 + 1;
        let record = ScenarioRecord::new(
            sequence,
            "devnet-stress-operator",
            scenario,
            DEVNET_HEIGHT.saturating_add(sequence),
            DEVNET_HEIGHT.saturating_add(720).saturating_add(sequence),
            &deterministic_root("DEVNET-STRESS-MITIGATION", "plan", sequence),
        );
        let scenario_id = state.register_scenario(record)?;
        state.submit_request(BridgeRequest::new(
            sequence,
            &scenario_id,
            if sequence % 3 == 0 {
                RequestKind::Rescue
            } else {
                RequestKind::Withdrawal
            },
            "devnet-private-bridge-user",
            1_000_000_u64.saturating_mul(sequence),
            100_000_u64.saturating_mul(sequence),
            DEVNET_HEIGHT.saturating_add(sequence),
            DEVNET_HEIGHT.saturating_add(256).saturating_add(sequence),
            &deterministic_root("DEVNET-STRESS-NULLIFIER", "request", sequence),
            &deterministic_root("DEVNET-STRESS-PAYLOAD", "request", sequence),
        ))?;
        state.record_watcher_attestation(WatcherAttestation::new(
            sequence,
            &scenario_id,
            "devnet-watchtower-alpha",
            if sequence == 1 {
                WatcherPosition::Reorged
            } else {
                WatcherPosition::Confirmed
            },
            12,
            DEVNET_HEIGHT.saturating_add(sequence),
            DEVNET_HEIGHT.saturating_add(sequence.saturating_mul(2)),
            &deterministic_root("DEVNET-STRESS-WATCHER-SUBJECT", "subject", sequence),
            &deterministic_root("DEVNET-STRESS-WATCHER-EVIDENCE", "evidence", sequence),
            &deterministic_root("DEVNET-STRESS-WATCHER-SIGNATURE", "signature", sequence),
            DEVNET_HEIGHT.saturating_add(sequence),
        ))?;
        state.record_liquidity(LiquidityRecord::new(
            sequence,
            &scenario_id,
            "devnet-liquidity-provider",
            5_000_000_u64.saturating_add(sequence.saturating_mul(100_000)),
            1_000_000_u64.saturating_mul(sequence),
            2_000_000,
            1_500_000,
            18,
            DEVNET_HEIGHT.saturating_add(sequence),
        ))?;
        state.record_reserve(ReserveRecord::new(
            sequence,
            &scenario_id,
            "devnet-reserve-custodian",
            20_000_000_u64.saturating_add(sequence.saturating_mul(250_000)),
            16_000_000,
            sequence.saturating_mul(125_000),
            &deterministic_root("DEVNET-STRESS-RESERVE-PROOF", "reserve", sequence),
            &deterministic_root("DEVNET-STRESS-LIABILITY", "liability", sequence),
            DEVNET_HEIGHT.saturating_add(sequence),
        ))?;
    }
    Ok(())
}
