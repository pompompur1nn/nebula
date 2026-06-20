use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceAdversarialLiveFeedObservationRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-adversarial-live-feed-observation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_ADVERSARIAL_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SeverityLane {
    Info,
    Watch,
    Caution,
    Critical,
    Catastrophic,
}

impl SeverityLane {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Watch => "watch",
            Self::Caution => "caution",
            Self::Critical => "critical",
            Self::Catastrophic => "catastrophic",
        }
    }

    pub fn rank(&self) -> u64 {
        match self {
            Self::Info => 0,
            Self::Watch => 1,
            Self::Caution => 2,
            Self::Critical => 3,
            Self::Catastrophic => 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AdversarialCaseKind {
    StaleFeed,
    ContradictoryHeaders,
    ShallowFinality,
    DepositOmission,
    ColludingWatchers,
    ReserveUnderflow,
    MetadataLeak,
    PrematureReleaseAttempt,
}

impl AdversarialCaseKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaleFeed => "stale_feed",
            Self::ContradictoryHeaders => "contradictory_headers",
            Self::ShallowFinality => "shallow_finality",
            Self::DepositOmission => "deposit_omission",
            Self::ColludingWatchers => "colluding_watchers",
            Self::ReserveUnderflow => "reserve_underflow",
            Self::MetadataLeak => "metadata_leak",
            Self::PrematureReleaseAttempt => "premature_release_attempt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FailClosedOutcome {
    ObserveOnly,
    HoldRelease,
    HoldExitAndEscalate,
    FreezeLane,
    QuarantineFeed,
    SlashAndFreeze,
}

impl FailClosedOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ObserveOnly => "observe_only",
            Self::HoldRelease => "hold_release",
            Self::HoldExitAndEscalate => "hold_exit_and_escalate",
            Self::FreezeLane => "freeze_lane",
            Self::QuarantineFeed => "quarantine_feed",
            Self::SlashAndFreeze => "slash_and_freeze",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ReleaseHoldReason {
    FeedStale,
    HeaderConflict,
    FinalityTooShallow,
    DepositMissing,
    WatcherCollusion,
    ReserveInsufficient,
    PrivacyLeak,
    ReleaseTooEarly,
}

impl ReleaseHoldReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FeedStale => "feed_stale",
            Self::HeaderConflict => "header_conflict",
            Self::FinalityTooShallow => "finality_too_shallow",
            Self::DepositMissing => "deposit_missing",
            Self::WatcherCollusion => "watcher_collusion",
            Self::ReserveInsufficient => "reserve_insufficient",
            Self::PrivacyLeak => "privacy_leak",
            Self::ReleaseTooEarly => "release_too_early",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub feed_stale_after_ms: u64,
    pub min_monero_confirmations: u64,
    pub min_watcher_quorum: u64,
    pub max_shared_watcher_cluster: u64,
    pub min_reserve_margin_atomic_units: u128,
    pub metadata_leak_budget_bits: u64,
    pub release_delay_blocks: u64,
    pub escalation_sla_ms: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            feed_stale_after_ms: 45_000,
            min_monero_confirmations: 18,
            min_watcher_quorum: 5,
            max_shared_watcher_cluster: 2,
            min_reserve_margin_atomic_units: 5_000_000_000_000,
            metadata_leak_budget_bits: 8,
            release_delay_blocks: 12,
            escalation_sla_ms: 90_000,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "feed_stale_after_ms": self.feed_stale_after_ms,
            "min_monero_confirmations": self.min_monero_confirmations,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_shared_watcher_cluster": self.max_shared_watcher_cluster,
            "min_reserve_margin_atomic_units": self.min_reserve_margin_atomic_units.to_string(),
            "metadata_leak_budget_bits": self.metadata_leak_budget_bits,
            "release_delay_blocks": self.release_delay_blocks,
            "escalation_sla_ms": self.escalation_sla_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedFeedEvidence {
    pub evidence_id: String,
    pub source_id: String,
    pub watcher_id: String,
    pub observed_at_ms: u64,
    pub monero_height: u64,
    pub l2_height: u64,
    pub header_hash: String,
    pub deposit_root: String,
    pub reserve_root: String,
    pub payload_commitment: String,
    pub relay_signature_root: String,
}

impl ObservedFeedEvidence {
    pub fn new(
        source_id: &str,
        watcher_id: &str,
        observed_at_ms: u64,
        monero_height: u64,
        l2_height: u64,
        header_hash: &str,
        deposit_root: &str,
        reserve_root: &str,
    ) -> Self {
        let payload_commitment = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-LIVE-FEED-PAYLOAD",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(source_id),
                HashPart::Str(watcher_id),
                HashPart::U64(observed_at_ms),
                HashPart::U64(monero_height),
                HashPart::U64(l2_height),
                HashPart::Str(header_hash),
                HashPart::Str(deposit_root),
                HashPart::Str(reserve_root),
            ],
            32,
        );
        let relay_signature_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-LIVE-FEED-SIGNATURE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(watcher_id),
                HashPart::Str(&payload_commitment),
            ],
            32,
        );
        let evidence_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-LIVE-FEED-EVIDENCE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(source_id),
                HashPart::Str(watcher_id),
                HashPart::Str(&payload_commitment),
            ],
            20,
        );
        Self {
            evidence_id,
            source_id: source_id.to_string(),
            watcher_id: watcher_id.to_string(),
            observed_at_ms,
            monero_height,
            l2_height,
            header_hash: header_hash.to_string(),
            deposit_root: deposit_root.to_string(),
            reserve_root: reserve_root.to_string(),
            payload_commitment,
            relay_signature_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "source_id": self.source_id,
            "watcher_id": self.watcher_id,
            "observed_at_ms": self.observed_at_ms,
            "monero_height": self.monero_height,
            "l2_height": self.l2_height,
            "header_hash": self.header_hash,
            "deposit_root": self.deposit_root,
            "reserve_root": self.reserve_root,
            "payload_commitment": self.payload_commitment,
            "relay_signature_root": self.relay_signature_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub case_id: String,
    pub expected_field: String,
    pub observed_field: String,
    pub expected_value: String,
    pub observed_value: String,
    pub evidence_ids: Vec<String>,
}

impl MismatchRecord {
    pub fn new(
        case_id: &str,
        expected_field: &str,
        observed_field: &str,
        expected_value: &str,
        observed_value: &str,
        evidence_ids: Vec<String>,
    ) -> Self {
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-MISMATCH-EVIDENCE",
            &string_values(&evidence_ids),
        );
        let mismatch_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-MISMATCH-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(case_id),
                HashPart::Str(expected_field),
                HashPart::Str(observed_field),
                HashPart::Str(expected_value),
                HashPart::Str(observed_value),
                HashPart::Str(&evidence_root),
            ],
            20,
        );
        Self {
            mismatch_id,
            case_id: case_id.to_string(),
            expected_field: expected_field.to_string(),
            observed_field: observed_field.to_string(),
            expected_value: expected_value.to_string(),
            observed_value: observed_value.to_string(),
            evidence_ids,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "mismatch_id": self.mismatch_id,
            "case_id": self.case_id,
            "expected_field": self.expected_field,
            "observed_field": self.observed_field,
            "expected_value": self.expected_value,
            "observed_value": self.observed_value,
            "evidence_ids": self.evidence_ids,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialCaseRecord {
    pub case_id: String,
    pub kind: AdversarialCaseKind,
    pub severity: SeverityLane,
    pub outcome: FailClosedOutcome,
    pub lane_id: String,
    pub exit_id: String,
    pub opened_at_ms: u64,
    pub deadline_ms: u64,
    pub expected_fail_closed: String,
    pub evidence_ids: Vec<String>,
    pub mismatch_ids: Vec<String>,
    pub root: String,
}

impl AdversarialCaseRecord {
    pub fn new(
        kind: AdversarialCaseKind,
        severity: SeverityLane,
        outcome: FailClosedOutcome,
        lane_id: &str,
        exit_id: &str,
        opened_at_ms: u64,
        deadline_ms: u64,
        expected_fail_closed: &str,
        evidence_ids: Vec<String>,
        mismatch_ids: Vec<String>,
    ) -> Self {
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-CASE-EVIDENCE",
            &string_values(&evidence_ids),
        );
        let mismatch_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-CASE-MISMATCH",
            &string_values(&mismatch_ids),
        );
        let case_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-CASE-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(kind.as_str()),
                HashPart::Str(lane_id),
                HashPart::Str(exit_id),
                HashPart::U64(opened_at_ms),
                HashPart::Str(&evidence_root),
                HashPart::Str(&mismatch_root),
            ],
            20,
        );
        let root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-CASE-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&case_id),
                HashPart::Str(kind.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(outcome.as_str()),
                HashPart::Str(lane_id),
                HashPart::Str(exit_id),
                HashPart::U64(deadline_ms),
                HashPart::Str(expected_fail_closed),
                HashPart::Str(&evidence_root),
                HashPart::Str(&mismatch_root),
            ],
            32,
        );
        Self {
            case_id,
            kind,
            severity,
            outcome,
            lane_id: lane_id.to_string(),
            exit_id: exit_id.to_string(),
            opened_at_ms,
            deadline_ms,
            expected_fail_closed: expected_fail_closed.to_string(),
            evidence_ids,
            mismatch_ids,
            root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "severity_rank": self.severity.rank(),
            "outcome": self.outcome.as_str(),
            "lane_id": self.lane_id,
            "exit_id": self.exit_id,
            "opened_at_ms": self.opened_at_ms,
            "deadline_ms": self.deadline_ms,
            "expected_fail_closed": self.expected_fail_closed,
            "evidence_ids": self.evidence_ids,
            "mismatch_ids": self.mismatch_ids,
            "root": self.root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub exit_id: String,
    pub lane_id: String,
    pub reason: ReleaseHoldReason,
    pub severity: SeverityLane,
    pub active: bool,
    pub opened_at_ms: u64,
    pub release_after_ms: u64,
    pub case_ids: Vec<String>,
    pub evidence_root: String,
}

impl ReleaseHold {
    pub fn new(
        exit_id: &str,
        lane_id: &str,
        reason: ReleaseHoldReason,
        severity: SeverityLane,
        opened_at_ms: u64,
        release_after_ms: u64,
        case_ids: Vec<String>,
        evidence_ids: Vec<String>,
    ) -> Self {
        let evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-RELEASE-HOLD-EVIDENCE",
            &string_values(&evidence_ids),
        );
        let case_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-RELEASE-HOLD-CASE",
            &string_values(&case_ids),
        );
        let hold_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-RELEASE-HOLD-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(exit_id),
                HashPart::Str(lane_id),
                HashPart::Str(reason.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::U64(opened_at_ms),
                HashPart::Str(&case_root),
                HashPart::Str(&evidence_root),
            ],
            20,
        );
        Self {
            hold_id,
            exit_id: exit_id.to_string(),
            lane_id: lane_id.to_string(),
            reason,
            severity,
            active: true,
            opened_at_ms,
            release_after_ms,
            case_ids,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "hold_id": self.hold_id,
            "exit_id": self.exit_id,
            "lane_id": self.lane_id,
            "reason": self.reason.as_str(),
            "severity": self.severity.as_str(),
            "severity_rank": self.severity.rank(),
            "active": self.active,
            "opened_at_ms": self.opened_at_ms,
            "release_after_ms": self.release_after_ms,
            "case_ids": self.case_ids,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRoots {
    pub observed_feed_evidence_root: String,
    pub mismatch_root: String,
    pub adversarial_case_root: String,
    pub expected_fail_closed_outcome_root: String,
    pub severity_lane_root: String,
    pub release_hold_root: String,
}

impl RuntimeRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "observed_feed_evidence_root": self.observed_feed_evidence_root,
            "mismatch_root": self.mismatch_root,
            "adversarial_case_root": self.adversarial_case_root,
            "expected_fail_closed_outcome_root": self.expected_fail_closed_outcome_root,
            "severity_lane_root": self.severity_lane_root,
            "release_hold_root": self.release_hold_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCounters {
    pub observed_feed_evidence: u64,
    pub mismatches: u64,
    pub adversarial_cases: u64,
    pub active_release_holds: u64,
    pub critical_or_worse_cases: u64,
}

impl RuntimeCounters {
    pub fn public_record(&self) -> Value {
        json!({
            "observed_feed_evidence": self.observed_feed_evidence,
            "mismatches": self.mismatches,
            "adversarial_cases": self.adversarial_cases,
            "active_release_holds": self.active_release_holds,
            "critical_or_worse_cases": self.critical_or_worse_cases,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub observed_feed_evidence: BTreeMap<String, ObservedFeedEvidence>,
    pub mismatches: BTreeMap<String, MismatchRecord>,
    pub adversarial_cases: BTreeMap<String, AdversarialCaseRecord>,
    pub release_holds: BTreeMap<String, ReleaseHold>,
}

impl State {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            observed_feed_evidence: BTreeMap::new(),
            mismatches: BTreeMap::new(),
            adversarial_cases: BTreeMap::new(),
            release_holds: BTreeMap::new(),
        }
    }

    pub fn observe_feed(&mut self, evidence: ObservedFeedEvidence) -> Result<String> {
        if self
            .observed_feed_evidence
            .contains_key(&evidence.evidence_id)
        {
            return Err(format!("duplicate feed evidence {}", evidence.evidence_id));
        }
        let evidence_id = evidence.evidence_id.clone();
        self.observed_feed_evidence
            .insert(evidence_id.clone(), evidence);
        Ok(evidence_id)
    }

    pub fn record_mismatch(&mut self, mismatch: MismatchRecord) -> Result<String> {
        if self.mismatches.contains_key(&mismatch.mismatch_id) {
            return Err(format!("duplicate mismatch {}", mismatch.mismatch_id));
        }
        let missing = mismatch
            .evidence_ids
            .iter()
            .filter(|id| !self.observed_feed_evidence.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "mismatch references unknown evidence {}",
                missing.join(",")
            ));
        }
        let mismatch_id = mismatch.mismatch_id.clone();
        self.mismatches.insert(mismatch_id.clone(), mismatch);
        Ok(mismatch_id)
    }

    pub fn record_case(&mut self, case: AdversarialCaseRecord) -> Result<String> {
        if self.adversarial_cases.contains_key(&case.case_id) {
            return Err(format!("duplicate adversarial case {}", case.case_id));
        }
        let missing_evidence = case
            .evidence_ids
            .iter()
            .filter(|id| !self.observed_feed_evidence.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_evidence.is_empty() {
            return Err(format!(
                "case references unknown evidence {}",
                missing_evidence.join(",")
            ));
        }
        let missing_mismatches = case
            .mismatch_ids
            .iter()
            .filter(|id| !self.mismatches.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_mismatches.is_empty() {
            return Err(format!(
                "case references unknown mismatch {}",
                missing_mismatches.join(",")
            ));
        }
        let case_id = case.case_id.clone();
        self.adversarial_cases.insert(case_id.clone(), case);
        Ok(case_id)
    }

    pub fn hold_release(&mut self, hold: ReleaseHold) -> Result<String> {
        if self.release_holds.contains_key(&hold.hold_id) {
            return Err(format!("duplicate release hold {}", hold.hold_id));
        }
        let missing_cases = hold
            .case_ids
            .iter()
            .filter(|id| !self.adversarial_cases.contains_key(*id))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_cases.is_empty() {
            return Err(format!(
                "release hold references unknown case {}",
                missing_cases.join(",")
            ));
        }
        let hold_id = hold.hold_id.clone();
        self.release_holds.insert(hold_id.clone(), hold);
        Ok(hold_id)
    }

    pub fn counters(&self) -> RuntimeCounters {
        RuntimeCounters {
            observed_feed_evidence: self.observed_feed_evidence.len() as u64,
            mismatches: self.mismatches.len() as u64,
            adversarial_cases: self.adversarial_cases.len() as u64,
            active_release_holds: self
                .release_holds
                .values()
                .filter(|hold| hold.active)
                .count() as u64,
            critical_or_worse_cases: self
                .adversarial_cases
                .values()
                .filter(|case| case.severity.rank() >= SeverityLane::Critical.rank())
                .count() as u64,
        }
    }

    pub fn roots(&self) -> RuntimeRoots {
        let evidence_records = self
            .observed_feed_evidence
            .values()
            .map(ObservedFeedEvidence::public_record)
            .collect::<Vec<_>>();
        let mismatch_records = self
            .mismatches
            .values()
            .map(MismatchRecord::public_record)
            .collect::<Vec<_>>();
        let case_records = self
            .adversarial_cases
            .values()
            .map(AdversarialCaseRecord::public_record)
            .collect::<Vec<_>>();
        let hold_records = self
            .release_holds
            .values()
            .map(ReleaseHold::public_record)
            .collect::<Vec<_>>();
        let expected_outcomes = self
            .adversarial_cases
            .values()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "kind": case.kind.as_str(),
                    "outcome": case.outcome.as_str(),
                    "expected_fail_closed": case.expected_fail_closed,
                })
            })
            .collect::<Vec<_>>();
        let severity_lanes = self
            .adversarial_cases
            .values()
            .map(|case| {
                json!({
                    "case_id": case.case_id,
                    "severity": case.severity.as_str(),
                    "severity_rank": case.severity.rank(),
                })
            })
            .collect::<Vec<_>>();

        RuntimeRoots {
            observed_feed_evidence_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-OBSERVED-FEED-EVIDENCE",
                &evidence_records,
            ),
            mismatch_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-MISMATCH",
                &mismatch_records,
            ),
            adversarial_case_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-CASE",
                &case_records,
            ),
            expected_fail_closed_outcome_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-EXPECTED-FAIL-CLOSED-OUTCOME",
                &expected_outcomes,
            ),
            severity_lane_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-SEVERITY-LANE",
                &severity_lanes,
            ),
            release_hold_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-RELEASE-HOLD",
                &hold_records,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "config": self.config.public_record(),
            "roots": self.roots().public_record(),
            "counters": self.counters().public_record(),
            "observed_feed_evidence": self.observed_feed_evidence
                .values()
                .map(ObservedFeedEvidence::public_record)
                .collect::<Vec<_>>(),
            "mismatches": self.mismatches
                .values()
                .map(MismatchRecord::public_record)
                .collect::<Vec<_>>(),
            "adversarial_cases": self.adversarial_cases
                .values()
                .map(AdversarialCaseRecord::public_record)
                .collect::<Vec<_>>(),
            "release_holds": self.release_holds
                .values()
                .map(ReleaseHold::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-ADVERSARIAL-LIVE-FEED-OBSERVATION-STATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let mut state = State::new(Config::devnet());
    let cases = devnet_case_plan();
    for seed in cases {
        let source_id = format!("monero-feed-{}", seed.source_suffix);
        let primary_watcher = format!("watcher-{:02}", seed.watcher_index);
        let secondary_watcher = format!("watcher-{:02}", seed.watcher_index + 1);
        let lane_id = format!("forced-exit-lane-{}", seed.source_suffix);
        let exit_id = format!("exit-{}", seed.label);
        let opened_at_ms = seed.observed_at_ms + seed.hold_offset_ms;
        let primary_header = format!("xmr-header-{}-primary", seed.monero_height);
        let secondary_header = if seed.kind == AdversarialCaseKind::ContradictoryHeaders {
            format!("xmr-header-{}-conflict", seed.monero_height)
        } else {
            format!(
                "xmr-header-{}-primary",
                seed.monero_height + seed.secondary_height_delta
            )
        };
        let primary_deposit_root = format!("deposit-root-{}-primary", seed.label);
        let secondary_deposit_root = if seed.kind == AdversarialCaseKind::DepositOmission {
            "deposit-root-omitted-forced-exit".to_string()
        } else {
            primary_deposit_root.clone()
        };
        let primary_reserve_root = format!("reserve-root-{}-primary", seed.label);
        let secondary_reserve_root = if seed.kind == AdversarialCaseKind::ReserveUnderflow {
            "reserve-root-underflow".to_string()
        } else {
            primary_reserve_root.clone()
        };
        let primary = ObservedFeedEvidence::new(
            &source_id,
            &primary_watcher,
            seed.observed_at_ms,
            seed.monero_height,
            seed.l2_height,
            &primary_header,
            &primary_deposit_root,
            &primary_reserve_root,
        );
        let secondary = ObservedFeedEvidence::new(
            &source_id,
            &secondary_watcher,
            seed.observed_at_ms + 1_000,
            seed.monero_height + seed.secondary_height_delta,
            seed.l2_height,
            &secondary_header,
            &secondary_deposit_root,
            &secondary_reserve_root,
        );
        let primary_id = primary.evidence_id.clone();
        let secondary_id = secondary.evidence_id.clone();
        let _ = state.observe_feed(primary);
        let _ = state.observe_feed(secondary);
        let mismatch = MismatchRecord::new(
            "pending",
            seed.expected_field,
            seed.observed_field,
            seed.expected_value,
            seed.observed_value,
            vec![primary_id.clone(), secondary_id.clone()],
        );
        let mismatch_id = mismatch.mismatch_id.clone();
        let _ = state.record_mismatch(mismatch);
        let case = AdversarialCaseRecord::new(
            seed.kind,
            seed.severity.clone(),
            seed.outcome,
            &lane_id,
            &exit_id,
            opened_at_ms,
            opened_at_ms + seed.deadline_delta_ms,
            seed.expected_fail_closed,
            vec![primary_id.clone(), secondary_id.clone()],
            vec![mismatch_id],
        );
        let case_id = case.case_id.clone();
        let _ = state.record_case(case);
        let hold = ReleaseHold::new(
            &exit_id,
            &lane_id,
            seed.hold_reason,
            seed.severity,
            opened_at_ms,
            opened_at_ms + seed.release_after_delta_ms,
            vec![case_id],
            vec![primary_id, secondary_id],
        );
        let _ = state.hold_release(hold);
    }
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn string_values(values: &[String]) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String(value.clone()))
        .collect::<Vec<_>>()
}

#[derive(Clone, Debug)]
struct DevnetCaseSeed {
    kind: AdversarialCaseKind,
    severity: SeverityLane,
    outcome: FailClosedOutcome,
    hold_reason: ReleaseHoldReason,
    label: &'static str,
    source_suffix: &'static str,
    watcher_index: u64,
    observed_at_ms: u64,
    hold_offset_ms: u64,
    deadline_delta_ms: u64,
    release_after_delta_ms: u64,
    monero_height: u64,
    secondary_height_delta: u64,
    l2_height: u64,
    expected_field: &'static str,
    observed_field: &'static str,
    expected_value: &'static str,
    observed_value: &'static str,
    expected_fail_closed: &'static str,
}

fn devnet_case_plan() -> Vec<DevnetCaseSeed> {
    vec![
        DevnetCaseSeed {
            kind: AdversarialCaseKind::StaleFeed,
            severity: SeverityLane::Caution,
            outcome: FailClosedOutcome::QuarantineFeed,
            hold_reason: ReleaseHoldReason::FeedStale,
            label: "stale-feed",
            source_suffix: "a",
            watcher_index: 1,
            observed_at_ms: 1_720_000_000_000,
            hold_offset_ms: 50_000,
            deadline_delta_ms: 90_000,
            release_after_delta_ms: 180_000,
            monero_height: 3_120_000,
            secondary_height_delta: 0,
            l2_height: 880_000,
            expected_field: "observed_at_ms",
            observed_field: "freshness_deadline_ms",
            expected_value: "within_45000",
            observed_value: "age_50000",
            expected_fail_closed: "quarantine feed and hold affected exits until fresh quorum",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::ContradictoryHeaders,
            severity: SeverityLane::Critical,
            outcome: FailClosedOutcome::HoldExitAndEscalate,
            hold_reason: ReleaseHoldReason::HeaderConflict,
            label: "header-conflict",
            source_suffix: "b",
            watcher_index: 3,
            observed_at_ms: 1_720_000_100_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 90_000,
            release_after_delta_ms: 240_000,
            monero_height: 3_120_018,
            secondary_height_delta: 0,
            l2_height: 880_012,
            expected_field: "header_hash",
            observed_field: "header_hash",
            expected_value: "single_canonical_header",
            observed_value: "two_headers_same_height",
            expected_fail_closed: "hold exit and escalate canonical-header dispute",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::ShallowFinality,
            severity: SeverityLane::Caution,
            outcome: FailClosedOutcome::HoldRelease,
            hold_reason: ReleaseHoldReason::FinalityTooShallow,
            label: "shallow-finality",
            source_suffix: "c",
            watcher_index: 5,
            observed_at_ms: 1_720_000_200_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 120_000,
            release_after_delta_ms: 360_000,
            monero_height: 3_120_020,
            secondary_height_delta: 1,
            l2_height: 880_020,
            expected_field: "confirmations",
            observed_field: "confirmations",
            expected_value: "18",
            observed_value: "4",
            expected_fail_closed: "hold release until minimum monero confirmations accrue",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::DepositOmission,
            severity: SeverityLane::Critical,
            outcome: FailClosedOutcome::FreezeLane,
            hold_reason: ReleaseHoldReason::DepositMissing,
            label: "deposit-omission",
            source_suffix: "d",
            watcher_index: 7,
            observed_at_ms: 1_720_000_300_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 90_000,
            release_after_delta_ms: 480_000,
            monero_height: 3_120_040,
            secondary_height_delta: 0,
            l2_height: 880_040,
            expected_field: "deposit_root",
            observed_field: "deposit_root",
            expected_value: "includes_forced_exit_deposit",
            observed_value: "omits_forced_exit_deposit",
            expected_fail_closed: "freeze lane and require inclusion proof before release",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::ColludingWatchers,
            severity: SeverityLane::Critical,
            outcome: FailClosedOutcome::SlashAndFreeze,
            hold_reason: ReleaseHoldReason::WatcherCollusion,
            label: "collusion",
            source_suffix: "e",
            watcher_index: 9,
            observed_at_ms: 1_720_000_400_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 90_000,
            release_after_delta_ms: 600_000,
            monero_height: 3_120_060,
            secondary_height_delta: 0,
            l2_height: 880_060,
            expected_field: "watcher_cluster_size",
            observed_field: "watcher_cluster_size",
            expected_value: "2",
            observed_value: "4",
            expected_fail_closed: "slash colluding watcher cluster and freeze release lane",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::ReserveUnderflow,
            severity: SeverityLane::Catastrophic,
            outcome: FailClosedOutcome::FreezeLane,
            hold_reason: ReleaseHoldReason::ReserveInsufficient,
            label: "reserve-underflow",
            source_suffix: "f",
            watcher_index: 10,
            observed_at_ms: 1_720_000_500_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 60_000,
            release_after_delta_ms: 900_000,
            monero_height: 3_120_080,
            secondary_height_delta: 0,
            l2_height: 880_080,
            expected_field: "reserve_margin_atomic_units",
            observed_field: "reserve_margin_atomic_units",
            expected_value: "5000000000000",
            observed_value: "-750000000000",
            expected_fail_closed: "freeze exits and route reserve shortfall to emergency control",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::MetadataLeak,
            severity: SeverityLane::Critical,
            outcome: FailClosedOutcome::HoldExitAndEscalate,
            hold_reason: ReleaseHoldReason::PrivacyLeak,
            label: "metadata-leak",
            source_suffix: "g",
            watcher_index: 12,
            observed_at_ms: 1_720_000_600_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 120_000,
            release_after_delta_ms: 720_000,
            monero_height: 3_120_100,
            secondary_height_delta: 0,
            l2_height: 880_100,
            expected_field: "metadata_leak_bits",
            observed_field: "metadata_leak_bits",
            expected_value: "8",
            observed_value: "21",
            expected_fail_closed: "hold release and rotate privacy envelope metadata keys",
        },
        DevnetCaseSeed {
            kind: AdversarialCaseKind::PrematureReleaseAttempt,
            severity: SeverityLane::Critical,
            outcome: FailClosedOutcome::HoldRelease,
            hold_reason: ReleaseHoldReason::ReleaseTooEarly,
            label: "premature-release",
            source_suffix: "h",
            watcher_index: 14,
            observed_at_ms: 1_720_000_700_000,
            hold_offset_ms: 1_000,
            deadline_delta_ms: 90_000,
            release_after_delta_ms: 840_000,
            monero_height: 3_120_120,
            secondary_height_delta: 0,
            l2_height: 880_120,
            expected_field: "release_delay_blocks",
            observed_field: "elapsed_release_delay_blocks",
            expected_value: "12",
            observed_value: "3",
            expected_fail_closed: "hold release until canonical delay and watcher quorum clear",
        },
    ]
}
