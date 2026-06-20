use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageReleasePolicyLiveReceiptAdjudicatorRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_LIVE_RECEIPT_ADJUDICATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-release-policy-live-receipt-adjudicator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RELEASE_POLICY_LIVE_RECEIPT_ADJUDICATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ADJUDICATOR_SUITE: &str =
    "monero-l2-pq-force-exit-package-release-policy-live-receipt-adjudicator-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-release-policy-live-receipt-adjudicator-devnet-0001";
pub const DEFAULT_RECEIPT_EPOCH: u64 = 78;
pub const DEFAULT_L2_HEIGHT: u64 = 892_078;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_078_892;
pub const DEFAULT_MAX_STALE_L2_DELTA: u64 = 8;
pub const DEFAULT_MAX_STALE_MONERO_DELTA: u64 = 5;
pub const DEFAULT_MIN_REQUIRED_LANES: u64 = 7;
pub const DEFAULT_MIN_ACCEPTED_LANES: u64 = 7;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub adjudicator_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub receipt_epoch: u64,
    pub adjudicator_l2_height: u64,
    pub adjudicator_monero_height: u64,
    pub max_stale_l2_delta: u64,
    pub max_stale_monero_delta: u64,
    pub min_required_lanes: u64,
    pub min_accepted_lanes: u64,
    pub require_policy_binding_root: bool,
    pub require_reviewer_quorum_root: bool,
    pub require_replacement_manifest_root: bool,
    pub require_cross_domain_root: bool,
    pub fail_closed_on_deferred_gate: bool,
    pub fail_closed_on_stale_receipt: bool,
    pub fail_closed_on_any_mismatch: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            adjudicator_suite: ADJUDICATOR_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            receipt_epoch: DEFAULT_RECEIPT_EPOCH,
            adjudicator_l2_height: DEFAULT_L2_HEIGHT,
            adjudicator_monero_height: DEFAULT_MONERO_HEIGHT,
            max_stale_l2_delta: DEFAULT_MAX_STALE_L2_DELTA,
            max_stale_monero_delta: DEFAULT_MAX_STALE_MONERO_DELTA,
            min_required_lanes: DEFAULT_MIN_REQUIRED_LANES,
            min_accepted_lanes: DEFAULT_MIN_ACCEPTED_LANES,
            require_policy_binding_root: true,
            require_reviewer_quorum_root: true,
            require_replacement_manifest_root: true,
            require_cross_domain_root: true,
            fail_closed_on_deferred_gate: true,
            fail_closed_on_stale_receipt: true,
            fail_closed_on_any_mismatch: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "adjudicator_suite": self.adjudicator_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "force_exit_package_id": self.force_exit_package_id,
            "receipt_epoch": self.receipt_epoch,
            "adjudicator_l2_height": self.adjudicator_l2_height,
            "adjudicator_monero_height": self.adjudicator_monero_height,
            "max_stale_l2_delta": self.max_stale_l2_delta,
            "max_stale_monero_delta": self.max_stale_monero_delta,
            "min_required_lanes": self.min_required_lanes,
            "min_accepted_lanes": self.min_accepted_lanes,
            "require_policy_binding_root": self.require_policy_binding_root,
            "require_reviewer_quorum_root": self.require_reviewer_quorum_root,
            "require_replacement_manifest_root": self.require_replacement_manifest_root,
            "require_cross_domain_root": self.require_cross_domain_root,
            "fail_closed_on_deferred_gate": self.fail_closed_on_deferred_gate,
            "fail_closed_on_stale_receipt": self.fail_closed_on_stale_receipt,
            "fail_closed_on_any_mismatch": self.fail_closed_on_any_mismatch,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptLane {
    CompileRuntime,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
    CrossDomainPolicy,
}

impl ReceiptLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileRuntime => "compile_runtime",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
            Self::CrossDomainPolicy => "cross_domain_policy",
        }
    }

    pub fn release_weight(self) -> u64 {
        match self {
            Self::CompileRuntime => 18,
            Self::RuntimeReplay => 17,
            Self::AuditSecurity => 20,
            Self::BridgeCustody => 15,
            Self::WalletWatchtower => 13,
            Self::PqReservePrivacy => 12,
            Self::CrossDomainPolicy => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    LiveAccepted,
    DeferredFixture,
    ReviewerPending,
    Stale,
    Mismatch,
    Missing,
}

impl ActivationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveAccepted => "live_accepted",
            Self::DeferredFixture => "deferred_fixture",
            Self::ReviewerPending => "reviewer_pending",
            Self::Stale => "stale",
            Self::Mismatch => "mismatch",
            Self::Missing => "missing",
        }
    }

    pub fn is_live_accepted(self) -> bool {
        matches!(self, Self::LiveAccepted)
    }

    pub fn is_fail_closed(self) -> bool {
        !self.is_live_accepted()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDecision {
    PermitRelease,
    HoldForLiveReceipt,
    HoldForReviewer,
    HoldForFreshness,
    HoldForMismatch,
    HoldForMissingPolicy,
}

impl ReleaseDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PermitRelease => "permit_release",
            Self::HoldForLiveReceipt => "hold_for_live_receipt",
            Self::HoldForReviewer => "hold_for_reviewer",
            Self::HoldForFreshness => "hold_for_freshness",
            Self::HoldForMismatch => "hold_for_mismatch",
            Self::HoldForMissingPolicy => "hold_for_missing_policy",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::PermitRelease)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldSeverity {
    None,
    Advisory,
    Blocking,
    Critical,
}

impl HoldSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Advisory => "advisory",
            Self::Blocking => "blocking",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveReceiptSignal {
    pub signal_id: String,
    pub lane: ReceiptLane,
    pub source_runtime: String,
    pub expected_receipt_root: String,
    pub observed_receipt_root: String,
    pub reviewer_quorum_root: String,
    pub replacement_manifest_root: String,
    pub release_policy_binding_root: String,
    pub cross_domain_root: String,
    pub observed_l2_height: u64,
    pub observed_monero_height: u64,
    pub reviewer_count: u64,
    pub observer_count: u64,
    pub status: ActivationStatus,
    pub note: String,
}

impl LiveReceiptSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ReceiptLane,
        source_runtime: &str,
        expected_receipt_root: &str,
        observed_receipt_root: &str,
        reviewer_quorum_root: &str,
        replacement_manifest_root: &str,
        release_policy_binding_root: &str,
        cross_domain_root: &str,
        observed_l2_height: u64,
        observed_monero_height: u64,
        reviewer_count: u64,
        observer_count: u64,
        status: ActivationStatus,
        note: &str,
    ) -> Self {
        let signal_id = live_receipt_signal_id(
            lane,
            source_runtime,
            expected_receipt_root,
            observed_receipt_root,
            reviewer_quorum_root,
            replacement_manifest_root,
            release_policy_binding_root,
            cross_domain_root,
            observed_l2_height,
            observed_monero_height,
            status,
        );
        Self {
            signal_id,
            lane,
            source_runtime: source_runtime.to_string(),
            expected_receipt_root: expected_receipt_root.to_string(),
            observed_receipt_root: observed_receipt_root.to_string(),
            reviewer_quorum_root: reviewer_quorum_root.to_string(),
            replacement_manifest_root: replacement_manifest_root.to_string(),
            release_policy_binding_root: release_policy_binding_root.to_string(),
            cross_domain_root: cross_domain_root.to_string(),
            observed_l2_height,
            observed_monero_height,
            reviewer_count,
            observer_count,
            status,
            note: note.to_string(),
        }
    }

    pub fn roots_match(&self) -> bool {
        self.expected_receipt_root == self.observed_receipt_root
    }

    pub fn has_policy_roots(&self) -> bool {
        !self.reviewer_quorum_root.is_empty()
            && !self.replacement_manifest_root.is_empty()
            && !self.release_policy_binding_root.is_empty()
            && !self.cross_domain_root.is_empty()
    }

    pub fn is_fresh(&self, config: &Config) -> bool {
        let l2_delta = config
            .adjudicator_l2_height
            .saturating_sub(self.observed_l2_height);
        let monero_delta = config
            .adjudicator_monero_height
            .saturating_sub(self.observed_monero_height);
        l2_delta <= config.max_stale_l2_delta && monero_delta <= config.max_stale_monero_delta
    }

    pub fn is_live_accepted(&self, config: &Config) -> bool {
        self.status.is_live_accepted()
            && self.roots_match()
            && self.has_policy_roots()
            && self.is_fresh(config)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "lane": self.lane.as_str(),
            "source_runtime": self.source_runtime,
            "expected_receipt_root": self.expected_receipt_root,
            "observed_receipt_root": self.observed_receipt_root,
            "reviewer_quorum_root": self.reviewer_quorum_root,
            "replacement_manifest_root": self.replacement_manifest_root,
            "release_policy_binding_root": self.release_policy_binding_root,
            "cross_domain_root": self.cross_domain_root,
            "observed_l2_height": self.observed_l2_height,
            "observed_monero_height": self.observed_monero_height,
            "reviewer_count": self.reviewer_count,
            "observer_count": self.observer_count,
            "status": self.status.as_str(),
            "note": self.note,
            "roots_match": self.roots_match(),
            "has_policy_roots": self.has_policy_roots(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live-receipt-signal", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdjudicationRequirement {
    pub lane: ReceiptLane,
    pub required: bool,
    pub min_reviewers: u64,
    pub min_observers: u64,
    pub required_weight: u64,
    pub required_policy_binding_root: String,
    pub required_manifest_root: String,
    pub hold_label: String,
}

impl AdjudicationRequirement {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lane: ReceiptLane,
        required: bool,
        min_reviewers: u64,
        min_observers: u64,
        required_policy_binding_root: &str,
        required_manifest_root: &str,
        hold_label: &str,
    ) -> Self {
        Self {
            lane,
            required,
            min_reviewers,
            min_observers,
            required_weight: lane.release_weight(),
            required_policy_binding_root: required_policy_binding_root.to_string(),
            required_manifest_root: required_manifest_root.to_string(),
            hold_label: hold_label.to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "required": self.required,
            "min_reviewers": self.min_reviewers,
            "min_observers": self.min_observers,
            "required_weight": self.required_weight,
            "required_policy_binding_root": self.required_policy_binding_root,
            "required_manifest_root": self.required_manifest_root,
            "hold_label": self.hold_label,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("adjudication-requirement", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LaneAdjudication {
    pub lane: ReceiptLane,
    pub adjudication_id: String,
    pub requirement_root: String,
    pub signal_root: String,
    pub decision: ReleaseDecision,
    pub severity: HoldSeverity,
    pub accepted: bool,
    pub fresh: bool,
    pub roots_match: bool,
    pub reviewer_quorum_met: bool,
    pub observer_quorum_met: bool,
    pub policy_root_met: bool,
    pub manifest_root_met: bool,
    pub release_weight: u64,
    pub hold_reason: String,
}

impl LaneAdjudication {
    pub fn from_signal(
        config: &Config,
        requirement: &AdjudicationRequirement,
        signal: &LiveReceiptSignal,
    ) -> Self {
        let fresh = signal.is_fresh(config);
        let roots_match = signal.roots_match();
        let reviewer_quorum_met = signal.reviewer_count >= requirement.min_reviewers;
        let observer_quorum_met = signal.observer_count >= requirement.min_observers;
        let policy_root_met =
            signal.release_policy_binding_root == requirement.required_policy_binding_root;
        let manifest_root_met =
            signal.replacement_manifest_root == requirement.required_manifest_root;
        let accepted = requirement.required
            && signal.status.is_live_accepted()
            && fresh
            && roots_match
            && reviewer_quorum_met
            && observer_quorum_met
            && policy_root_met
            && manifest_root_met
            && signal.has_policy_roots();
        let decision = lane_decision(
            signal.status,
            fresh,
            roots_match,
            reviewer_quorum_met,
            observer_quorum_met,
            policy_root_met,
            manifest_root_met,
            accepted,
        );
        let severity = lane_severity(decision, requirement.required);
        let hold_reason = lane_hold_reason(requirement, signal, decision);
        let requirement_root = requirement.state_root();
        let signal_root = signal.state_root();
        let adjudication_id = lane_adjudication_id(
            requirement.lane,
            &requirement_root,
            &signal_root,
            decision,
            severity,
            accepted,
            &hold_reason,
        );
        Self {
            lane: requirement.lane,
            adjudication_id,
            requirement_root,
            signal_root,
            decision,
            severity,
            accepted,
            fresh,
            roots_match,
            reviewer_quorum_met,
            observer_quorum_met,
            policy_root_met,
            manifest_root_met,
            release_weight: requirement.required_weight,
            hold_reason,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "adjudication_id": self.adjudication_id,
            "requirement_root": self.requirement_root,
            "signal_root": self.signal_root,
            "decision": self.decision.as_str(),
            "severity": self.severity.as_str(),
            "accepted": self.accepted,
            "fresh": self.fresh,
            "roots_match": self.roots_match,
            "reviewer_quorum_met": self.reviewer_quorum_met,
            "observer_quorum_met": self.observer_quorum_met,
            "policy_root_met": self.policy_root_met,
            "manifest_root_met": self.manifest_root_met,
            "release_weight": self.release_weight,
            "hold_reason": self.hold_reason,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("lane-adjudication", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub required_lanes: u64,
    pub accepted_lanes: u64,
    pub held_lanes: u64,
    pub stale_lanes: u64,
    pub mismatch_lanes: u64,
    pub reviewer_pending_lanes: u64,
    pub missing_policy_lanes: u64,
    pub release_weight_total: u64,
    pub accepted_weight_total: u64,
}

impl Counters {
    pub fn from_lanes(lanes: &[LaneAdjudication]) -> Self {
        let mut counters = Self::default();
        for lane in lanes {
            counters.release_weight_total = counters
                .release_weight_total
                .saturating_add(lane.release_weight);
            if lane.accepted {
                counters.accepted_lanes = counters.accepted_lanes.saturating_add(1);
                counters.accepted_weight_total = counters
                    .accepted_weight_total
                    .saturating_add(lane.release_weight);
            } else {
                counters.held_lanes = counters.held_lanes.saturating_add(1);
            }
            counters.required_lanes = counters.required_lanes.saturating_add(1);
            if !lane.fresh {
                counters.stale_lanes = counters.stale_lanes.saturating_add(1);
            }
            if !lane.roots_match {
                counters.mismatch_lanes = counters.mismatch_lanes.saturating_add(1);
            }
            if !lane.reviewer_quorum_met || !lane.observer_quorum_met {
                counters.reviewer_pending_lanes = counters.reviewer_pending_lanes.saturating_add(1);
            }
            if !lane.policy_root_met || !lane.manifest_root_met {
                counters.missing_policy_lanes = counters.missing_policy_lanes.saturating_add(1);
            }
        }
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "required_lanes": self.required_lanes,
            "accepted_lanes": self.accepted_lanes,
            "held_lanes": self.held_lanes,
            "stale_lanes": self.stale_lanes,
            "mismatch_lanes": self.mismatch_lanes,
            "reviewer_pending_lanes": self.reviewer_pending_lanes,
            "missing_policy_lanes": self.missing_policy_lanes,
            "release_weight_total": self.release_weight_total,
            "accepted_weight_total": self.accepted_weight_total,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub requirement_root: String,
    pub signal_root: String,
    pub lane_adjudication_root: String,
    pub accepted_lane_root: String,
    pub held_lane_root: String,
    pub counter_root: String,
    pub final_release_policy_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "signal_root": self.signal_root,
            "lane_adjudication_root": self.lane_adjudication_root,
            "accepted_lane_root": self.accepted_lane_root,
            "held_lane_root": self.held_lane_root,
            "counter_root": self.counter_root,
            "final_release_policy_root": self.final_release_policy_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub requirements: Vec<AdjudicationRequirement>,
    pub signals: Vec<LiveReceiptSignal>,
    pub lane_adjudications: Vec<LaneAdjudication>,
    pub counters: Counters,
    pub release_allowed: bool,
    pub final_decision: ReleaseDecision,
    pub final_hold_reason: String,
    pub roots: Roots,
}

impl State {
    pub fn new(
        config: Config,
        requirements: Vec<AdjudicationRequirement>,
        signals: Vec<LiveReceiptSignal>,
    ) -> Self {
        let lane_adjudications = requirements
            .iter()
            .filter_map(|requirement| {
                signals
                    .iter()
                    .find(|signal| signal.lane == requirement.lane)
                    .map(|signal| LaneAdjudication::from_signal(&config, requirement, signal))
            })
            .collect::<Vec<_>>();
        let counters = Counters::from_lanes(&lane_adjudications);
        let release_allowed = release_allowed(&config, &counters, &lane_adjudications);
        let final_decision = final_release_decision(&config, &counters, release_allowed);
        let final_hold_reason =
            final_hold_reason(&config, &counters, &lane_adjudications, final_decision);
        let roots = build_roots(
            &config,
            &requirements,
            &signals,
            &lane_adjudications,
            &counters,
            release_allowed,
            final_decision,
            &final_hold_reason,
        );
        Self {
            config,
            requirements,
            signals,
            lane_adjudications,
            counters,
            release_allowed,
            final_decision,
            final_hold_reason,
            roots,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = devnet_requirements();
        let signals = devnet_signals(&config, &requirements);
        Self::new(config, requirements, signals)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(AdjudicationRequirement::public_record).collect::<Vec<_>>(),
            "signals": self.signals.iter().map(LiveReceiptSignal::public_record).collect::<Vec<_>>(),
            "lane_adjudications": self.lane_adjudications.iter().map(LaneAdjudication::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "release_allowed": self.release_allowed,
            "final_decision": self.final_decision.as_str(),
            "final_hold_reason": self.final_hold_reason,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn devnet_requirements() -> Vec<AdjudicationRequirement> {
    [
        ReceiptLane::CompileRuntime,
        ReceiptLane::RuntimeReplay,
        ReceiptLane::AuditSecurity,
        ReceiptLane::BridgeCustody,
        ReceiptLane::WalletWatchtower,
        ReceiptLane::PqReservePrivacy,
        ReceiptLane::CrossDomainPolicy,
    ]
    .iter()
    .map(|lane| {
        let policy_root = fixture_root("policy-binding", lane.as_str());
        let manifest_root = fixture_root("replacement-manifest", lane.as_str());
        AdjudicationRequirement::new(
            *lane,
            true,
            if *lane == ReceiptLane::AuditSecurity {
                3
            } else {
                2
            },
            if *lane == ReceiptLane::CrossDomainPolicy {
                6
            } else {
                3
            },
            &policy_root,
            &manifest_root,
            &format!("{} live receipt activation required", lane.as_str()),
        )
    })
    .collect()
}

pub fn devnet_signals(
    config: &Config,
    requirements: &[AdjudicationRequirement],
) -> Vec<LiveReceiptSignal> {
    requirements
        .iter()
        .map(|requirement| {
            let expected = fixture_root("expected-live-receipt", requirement.lane.as_str());
            let (observed, status, l2_delta, monero_delta, reviewers, observers, note) =
                devnet_signal_shape(requirement.lane, &expected);
            LiveReceiptSignal::new(
                requirement.lane,
                &format!("{}-activation-runtime", requirement.lane.as_str()),
                &expected,
                &observed,
                &fixture_root("reviewer-quorum", requirement.lane.as_str()),
                &requirement.required_manifest_root,
                &requirement.required_policy_binding_root,
                &fixture_root("cross-domain", requirement.lane.as_str()),
                config.adjudicator_l2_height.saturating_sub(l2_delta),
                config
                    .adjudicator_monero_height
                    .saturating_sub(monero_delta),
                reviewers,
                observers,
                status,
                note,
            )
        })
        .collect()
}

pub fn devnet_signal_shape(
    lane: ReceiptLane,
    expected_root: &str,
) -> (String, ActivationStatus, u64, u64, u64, u64, &'static str) {
    match lane {
        ReceiptLane::CompileRuntime => (
            expected_root.to_string(),
            ActivationStatus::ReviewerPending,
            2,
            2,
            1,
            3,
            "compile and cargo-family gates are wired but still lack live reviewer quorum",
        ),
        ReceiptLane::RuntimeReplay => (
            expected_root.to_string(),
            ActivationStatus::DeferredFixture,
            1,
            1,
            2,
            3,
            "runtime replay receipt still points at deferred fixture evidence",
        ),
        ReceiptLane::AuditSecurity => (
            expected_root.to_string(),
            ActivationStatus::ReviewerPending,
            3,
            3,
            2,
            4,
            "security review receipt requires the final independent reviewer quorum",
        ),
        ReceiptLane::BridgeCustody => (
            expected_root.to_string(),
            ActivationStatus::LiveAccepted,
            2,
            1,
            2,
            3,
            "bridge custody receipt is live accepted in the devnet packet",
        ),
        ReceiptLane::WalletWatchtower => (
            expected_root.to_string(),
            ActivationStatus::LiveAccepted,
            4,
            2,
            2,
            3,
            "wallet and watchtower replay receipt is live accepted in the devnet packet",
        ),
        ReceiptLane::PqReservePrivacy => (
            fixture_root("observed-mismatch", lane.as_str()),
            ActivationStatus::Mismatch,
            2,
            2,
            2,
            3,
            "PQ reserve privacy receipt is intentionally mismatched to keep release held",
        ),
        ReceiptLane::CrossDomainPolicy => (
            expected_root.to_string(),
            ActivationStatus::LiveAccepted,
            9,
            6,
            2,
            6,
            "cross-domain root is fresh enough for observation but follows held lanes",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn lane_decision(
    status: ActivationStatus,
    fresh: bool,
    roots_match: bool,
    reviewer_quorum_met: bool,
    observer_quorum_met: bool,
    policy_root_met: bool,
    manifest_root_met: bool,
    accepted: bool,
) -> ReleaseDecision {
    if accepted {
        return ReleaseDecision::PermitRelease;
    }
    if !policy_root_met || !manifest_root_met {
        return ReleaseDecision::HoldForMissingPolicy;
    }
    if !roots_match || matches!(status, ActivationStatus::Mismatch) {
        return ReleaseDecision::HoldForMismatch;
    }
    if !fresh || matches!(status, ActivationStatus::Stale) {
        return ReleaseDecision::HoldForFreshness;
    }
    if !reviewer_quorum_met
        || !observer_quorum_met
        || matches!(status, ActivationStatus::ReviewerPending)
    {
        return ReleaseDecision::HoldForReviewer;
    }
    ReleaseDecision::HoldForLiveReceipt
}

pub fn lane_severity(decision: ReleaseDecision, required: bool) -> HoldSeverity {
    if decision.permits_release() {
        HoldSeverity::None
    } else if !required {
        HoldSeverity::Advisory
    } else if matches!(
        decision,
        ReleaseDecision::HoldForMismatch | ReleaseDecision::HoldForMissingPolicy
    ) {
        HoldSeverity::Critical
    } else {
        HoldSeverity::Blocking
    }
}

pub fn lane_hold_reason(
    requirement: &AdjudicationRequirement,
    signal: &LiveReceiptSignal,
    decision: ReleaseDecision,
) -> String {
    if decision.permits_release() {
        return format!("{} live receipt accepted", requirement.lane.as_str());
    }
    format!(
        "{} held by {}: status={}, reviewers={}/{}, observers={}/{}, note={}",
        requirement.lane.as_str(),
        decision.as_str(),
        signal.status.as_str(),
        signal.reviewer_count,
        requirement.min_reviewers,
        signal.observer_count,
        requirement.min_observers,
        signal.note
    )
}

pub fn release_allowed(
    config: &Config,
    counters: &Counters,
    lane_adjudications: &[LaneAdjudication],
) -> bool {
    counters.required_lanes >= config.min_required_lanes
        && counters.accepted_lanes >= config.min_accepted_lanes
        && lane_adjudications.iter().all(|lane| lane.accepted)
        && !(config.fail_closed_on_any_mismatch && counters.mismatch_lanes > 0)
        && !(config.fail_closed_on_stale_receipt && counters.stale_lanes > 0)
        && !(config.fail_closed_on_deferred_gate && counters.held_lanes > 0)
}

pub fn final_release_decision(
    config: &Config,
    counters: &Counters,
    release_allowed: bool,
) -> ReleaseDecision {
    if release_allowed {
        ReleaseDecision::PermitRelease
    } else if config.fail_closed_on_any_mismatch && counters.mismatch_lanes > 0 {
        ReleaseDecision::HoldForMismatch
    } else if config.fail_closed_on_stale_receipt && counters.stale_lanes > 0 {
        ReleaseDecision::HoldForFreshness
    } else if counters.missing_policy_lanes > 0 {
        ReleaseDecision::HoldForMissingPolicy
    } else if counters.reviewer_pending_lanes > 0 {
        ReleaseDecision::HoldForReviewer
    } else {
        ReleaseDecision::HoldForLiveReceipt
    }
}

pub fn final_hold_reason(
    config: &Config,
    counters: &Counters,
    lane_adjudications: &[LaneAdjudication],
    final_decision: ReleaseDecision,
) -> String {
    if final_decision.permits_release() {
        return "all required live receipt lanes accepted; production release may proceed"
            .to_string();
    }
    let held = lane_adjudications
        .iter()
        .filter(|lane| !lane.accepted)
        .map(|lane| format!("{}:{}", lane.lane.as_str(), lane.decision.as_str()))
        .collect::<Vec<_>>();
    format!(
        "release held by {}; accepted_lanes={}/{}, held_lanes={}, mismatch_lanes={}, stale_lanes={}, reviewer_pending_lanes={}, max_l2_delta={}, max_monero_delta={}, held={}",
        final_decision.as_str(),
        counters.accepted_lanes,
        config.min_accepted_lanes,
        counters.held_lanes,
        counters.mismatch_lanes,
        counters.stale_lanes,
        counters.reviewer_pending_lanes,
        config.max_stale_l2_delta,
        config.max_stale_monero_delta,
        held.join("|")
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_roots(
    config: &Config,
    requirements: &[AdjudicationRequirement],
    signals: &[LiveReceiptSignal],
    lane_adjudications: &[LaneAdjudication],
    counters: &Counters,
    release_allowed: bool,
    final_decision: ReleaseDecision,
    final_hold_reason: &str,
) -> Roots {
    let config_root = config.state_root();
    let requirement_root = merkle_root(
        "release-policy-live-receipt-adjudicator-requirements",
        &requirements
            .iter()
            .map(AdjudicationRequirement::state_root)
            .collect::<Vec<_>>(),
    );
    let signal_root = merkle_root(
        "release-policy-live-receipt-adjudicator-signals",
        &signals
            .iter()
            .map(LiveReceiptSignal::state_root)
            .collect::<Vec<_>>(),
    );
    let lane_adjudication_root = merkle_root(
        "release-policy-live-receipt-adjudicator-lanes",
        &lane_adjudications
            .iter()
            .map(LaneAdjudication::state_root)
            .collect::<Vec<_>>(),
    );
    let accepted_lane_root = merkle_root(
        "release-policy-live-receipt-adjudicator-accepted-lanes",
        &lane_adjudications
            .iter()
            .filter(|lane| lane.accepted)
            .map(LaneAdjudication::state_root)
            .collect::<Vec<_>>(),
    );
    let held_lane_root = merkle_root(
        "release-policy-live-receipt-adjudicator-held-lanes",
        &lane_adjudications
            .iter()
            .filter(|lane| !lane.accepted)
            .map(LaneAdjudication::state_root)
            .collect::<Vec<_>>(),
    );
    let counter_root = counters.state_root();
    let final_release_policy_root = final_policy_root(
        &config_root,
        &requirement_root,
        &signal_root,
        &lane_adjudication_root,
        &counter_root,
        release_allowed,
        final_decision,
        final_hold_reason,
    );
    let state_root = adjudicator_state_root(
        &config_root,
        &requirement_root,
        &signal_root,
        &lane_adjudication_root,
        &accepted_lane_root,
        &held_lane_root,
        &counter_root,
        &final_release_policy_root,
    );
    Roots {
        config_root,
        requirement_root,
        signal_root,
        lane_adjudication_root,
        accepted_lane_root,
        held_lane_root,
        counter_root,
        final_release_policy_root,
        state_root,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn live_receipt_signal_id(
    lane: ReceiptLane,
    source_runtime: &str,
    expected_receipt_root: &str,
    observed_receipt_root: &str,
    reviewer_quorum_root: &str,
    replacement_manifest_root: &str,
    release_policy_binding_root: &str,
    cross_domain_root: &str,
    observed_l2_height: u64,
    observed_monero_height: u64,
    status: ActivationStatus,
) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-SIGNAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(expected_receipt_root),
            HashPart::Str(observed_receipt_root),
            HashPart::Str(reviewer_quorum_root),
            HashPart::Str(replacement_manifest_root),
            HashPart::Str(release_policy_binding_root),
            HashPart::Str(cross_domain_root),
            HashPart::U64(observed_l2_height),
            HashPart::U64(observed_monero_height),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

pub fn lane_adjudication_id(
    lane: ReceiptLane,
    requirement_root: &str,
    signal_root: &str,
    decision: ReleaseDecision,
    severity: HoldSeverity,
    accepted: bool,
    hold_reason: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-LANE-ADJUDICATION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(requirement_root),
            HashPart::Str(signal_root),
            HashPart::Str(decision.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(if accepted { "accepted" } else { "held" }),
            HashPart::Str(hold_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn final_policy_root(
    config_root: &str,
    requirement_root: &str,
    signal_root: &str,
    lane_adjudication_root: &str,
    counter_root: &str,
    release_allowed: bool,
    final_decision: ReleaseDecision,
    final_hold_reason: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-FINAL-POLICY",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(config_root),
            HashPart::Str(requirement_root),
            HashPart::Str(signal_root),
            HashPart::Str(lane_adjudication_root),
            HashPart::Str(counter_root),
            HashPart::Str(if release_allowed {
                "release-allowed"
            } else {
                "release-held"
            }),
            HashPart::Str(final_decision.as_str()),
            HashPart::Str(final_hold_reason),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn adjudicator_state_root(
    config_root: &str,
    requirement_root: &str,
    signal_root: &str,
    lane_adjudication_root: &str,
    accepted_lane_root: &str,
    held_lane_root: &str,
    counter_root: &str,
    final_release_policy_root: &str,
) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-ADJUDICATOR-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(config_root),
            HashPart::Str(requirement_root),
            HashPart::Str(signal_root),
            HashPart::Str(lane_adjudication_root),
            HashPart::Str(accepted_lane_root),
            HashPart::Str(held_lane_root),
            HashPart::Str(counter_root),
            HashPart::Str(final_release_policy_root),
        ],
        32,
    )
}

pub fn fixture_root(kind: &str, value: &str) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-ADJUDICATOR-FIXTURE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "RELEASE-POLICY-LIVE-RECEIPT-ADJUDICATOR-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}
