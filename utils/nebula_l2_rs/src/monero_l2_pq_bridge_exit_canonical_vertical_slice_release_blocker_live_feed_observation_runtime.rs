use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerLiveFeedObservationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-live-feed-observation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const LIVE_FEED_OBSERVATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-blocker-live-feed-observation-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-release-candidate-live-feed-observation-devnet-v1";
pub const DEFAULT_OBSERVATION_EPOCH: u64 = 7;
pub const REQUIRED_LIVE_FEED_LANES: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    MoneroHeaders,
    DepositLocks,
    PqWatchers,
    ReserveSufficiency,
    AdversarialCases,
    PrivacySurfaces,
    PqReleaseHolds,
    ProductionReleaseGates,
}

impl BlockerLane {
    pub fn all() -> [Self; REQUIRED_LIVE_FEED_LANES] {
        [
            Self::MoneroHeaders,
            Self::DepositLocks,
            Self::PqWatchers,
            Self::ReserveSufficiency,
            Self::AdversarialCases,
            Self::PrivacySurfaces,
            Self::PqReleaseHolds,
            Self::ProductionReleaseGates,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaders => "monero_headers",
            Self::DepositLocks => "deposit_locks",
            Self::PqWatchers => "pq_watchers",
            Self::ReserveSufficiency => "reserve_sufficiency",
            Self::AdversarialCases => "adversarial_cases",
            Self::PrivacySurfaces => "privacy_surfaces",
            Self::PqReleaseHolds => "pq_release_holds",
            Self::ProductionReleaseGates => "production_release_gates",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationKind {
    HeaderContinuity,
    HeaderReorgFence,
    DepositLockFinality,
    DepositNoteLinkage,
    PqWatcherQuorum,
    PqAttestationFreshness,
    ReserveProofFreshness,
    ReserveLiquidityFloor,
    AdversarialReplayCase,
    AdversarialMismatchCase,
    PrivacyLeakRegression,
    PrivacySurfaceRedaction,
    PqAuthorityRotation,
    PqSignatureSuiteHold,
    OperatorSignoff,
    ProductionGoNoGo,
}

impl ObservationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeaderContinuity => "header_continuity",
            Self::HeaderReorgFence => "header_reorg_fence",
            Self::DepositLockFinality => "deposit_lock_finality",
            Self::DepositNoteLinkage => "deposit_note_linkage",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::PqAttestationFreshness => "pq_attestation_freshness",
            Self::ReserveProofFreshness => "reserve_proof_freshness",
            Self::ReserveLiquidityFloor => "reserve_liquidity_floor",
            Self::AdversarialReplayCase => "adversarial_replay_case",
            Self::AdversarialMismatchCase => "adversarial_mismatch_case",
            Self::PrivacyLeakRegression => "privacy_leak_regression",
            Self::PrivacySurfaceRedaction => "privacy_surface_redaction",
            Self::PqAuthorityRotation => "pq_authority_rotation",
            Self::PqSignatureSuiteHold => "pq_signature_suite_hold",
            Self::OperatorSignoff => "operator_signoff",
            Self::ProductionGoNoGo => "production_go_no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Observed,
    Missing,
    Mismatched,
    Stale,
    HoldOpen,
    Blocked,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Missing => "missing",
            Self::Mismatched => "mismatched",
            Self::Stale => "stale",
            Self::HoldOpen => "hold_open",
            Self::Blocked => "blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        match self {
            Self::Observed => false,
            Self::Missing | Self::Mismatched | Self::Stale | Self::HoldOpen | Self::Blocked => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Informational,
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Informational => "informational",
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Informational => 1,
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRequirement {
    Required,
    RequiredQuorum,
    RequiredFreshness,
    RequiredRootMatch,
    RequiredHumanSignoff,
}

impl SourceRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::RequiredQuorum => "required_quorum",
            Self::RequiredFreshness => "required_freshness",
            Self::RequiredRootMatch => "required_root_match",
            Self::RequiredHumanSignoff => "required_human_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionDecision {
    Go,
    Hold,
    NoGo,
}

impl ProductionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Hold => "hold",
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub observation_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub observation_epoch: u64,
    pub required_live_feed_lanes: usize,
    pub min_watcher_quorum: u64,
    pub min_reserve_coverage_bps: u64,
    pub max_feed_lag_blocks: u64,
    pub fail_closed_on_missing_feed: bool,
    pub fail_closed_on_mismatched_root: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            observation_suite: LIVE_FEED_OBSERVATION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            observation_epoch: DEFAULT_OBSERVATION_EPOCH,
            required_live_feed_lanes: REQUIRED_LIVE_FEED_LANES,
            min_watcher_quorum: 3,
            min_reserve_coverage_bps: 10_500,
            max_feed_lag_blocks: 2,
            fail_closed_on_missing_feed: true,
            fail_closed_on_mismatched_root: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "observation_suite": self.observation_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "observation_epoch": self.observation_epoch,
            "required_live_feed_lanes": self.required_live_feed_lanes,
            "min_watcher_quorum": self.min_watcher_quorum,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "max_feed_lag_blocks": self.max_feed_lag_blocks,
            "fail_closed_on_missing_feed": self.fail_closed_on_missing_feed,
            "fail_closed_on_mismatched_root": self.fail_closed_on_mismatched_root,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LiveFeedSource {
    pub source_id: String,
    pub lane: BlockerLane,
    pub requirement: SourceRequirement,
    pub adapter_id: String,
    pub expected_feed_root: String,
    pub min_confirmations: u64,
    pub min_quorum: u64,
    pub max_lag_blocks: u64,
    pub release_blocking: bool,
}

impl LiveFeedSource {
    pub fn public_record(&self) -> Value {
        json!({
            "source_id": self.source_id,
            "lane": self.lane.as_str(),
            "requirement": self.requirement.as_str(),
            "adapter_id": self.adapter_id,
            "expected_feed_root": self.expected_feed_root,
            "min_confirmations": self.min_confirmations,
            "min_quorum": self.min_quorum,
            "max_lag_blocks": self.max_lag_blocks,
            "release_blocking": self.release_blocking,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("live-feed-source", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeedObservation {
    pub observation_id: String,
    pub source_id: String,
    pub lane: BlockerLane,
    pub kind: ObservationKind,
    pub status: ObservationStatus,
    pub severity: BlockerSeverity,
    pub observed_at_height: u64,
    pub expected_height: u64,
    pub expected_root: String,
    pub observed_root: String,
    pub observed_quorum: u64,
    pub required_quorum: u64,
    pub reserve_coverage_bps: u64,
    pub privacy_surface_count: u64,
    pub pq_hold_count: u64,
    pub missing_evidence: Vec<String>,
    pub mismatch_evidence: Vec<String>,
    pub clearance_requirement: String,
}

impl FeedObservation {
    pub fn roots_match(&self) -> bool {
        self.expected_root == self.observed_root
    }

    pub fn feed_lag_blocks(&self) -> u64 {
        self.expected_height.saturating_sub(self.observed_at_height)
    }

    pub fn release_blocking(&self) -> bool {
        self.status.blocks_release()
            || !self.roots_match()
            || self.observed_quorum < self.required_quorum
            || self.reserve_coverage_bps < 10_000
            || !self.missing_evidence.is_empty()
            || !self.mismatch_evidence.is_empty()
            || self.pq_hold_count > 0
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "source_id": self.source_id,
            "lane": self.lane.as_str(),
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "observed_at_height": self.observed_at_height,
            "expected_height": self.expected_height,
            "feed_lag_blocks": self.feed_lag_blocks(),
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "roots_match": self.roots_match(),
            "observed_quorum": self.observed_quorum,
            "required_quorum": self.required_quorum,
            "reserve_coverage_bps": self.reserve_coverage_bps,
            "privacy_surface_count": self.privacy_surface_count,
            "pq_hold_count": self.pq_hold_count,
            "missing_evidence": self.missing_evidence,
            "mismatch_evidence": self.mismatch_evidence,
            "clearance_requirement": self.clearance_requirement,
            "release_blocking": self.release_blocking(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("feed-observation", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockerLaneSummary {
    pub lane: BlockerLane,
    pub source_count: u64,
    pub observation_count: u64,
    pub missing_count: u64,
    pub mismatch_count: u64,
    pub stale_count: u64,
    pub hold_count: u64,
    pub release_stop_count: u64,
    pub max_severity: BlockerSeverity,
    pub lane_blocked: bool,
    pub lane_root: String,
}

impl BlockerLaneSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "source_count": self.source_count,
            "observation_count": self.observation_count,
            "missing_count": self.missing_count,
            "mismatch_count": self.mismatch_count,
            "stale_count": self.stale_count,
            "hold_count": self.hold_count,
            "release_stop_count": self.release_stop_count,
            "max_severity": self.max_severity.as_str(),
            "lane_blocked": self.lane_blocked,
            "lane_root": self.lane_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("blocker-lane-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseGate {
    pub gate_id: String,
    pub decision: ProductionDecision,
    pub open_blockers: u64,
    pub release_stop_blockers: u64,
    pub missing_observations: u64,
    pub mismatched_observations: u64,
    pub privacy_holds: u64,
    pub pq_holds: u64,
    pub go_no_go_reason: String,
    pub gate_root: String,
}

impl ReleaseGate {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "decision": self.decision.as_str(),
            "open_blockers": self.open_blockers,
            "release_stop_blockers": self.release_stop_blockers,
            "missing_observations": self.missing_observations,
            "mismatched_observations": self.mismatched_observations,
            "privacy_holds": self.privacy_holds,
            "pq_holds": self.pq_holds,
            "go_no_go_reason": self.go_no_go_reason,
            "gate_root": self.gate_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release-gate", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub source_root: String,
    pub observation_root: String,
    pub lane_summary_root: String,
    pub missing_observation_root: String,
    pub mismatch_observation_root: String,
    pub privacy_hold_root: String,
    pub pq_hold_root: String,
    pub release_gate_root: String,
    pub state_root: String,
}

impl StateRoots {
    pub fn public_record_without_state_root(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "source_root": self.source_root,
            "observation_root": self.observation_root,
            "lane_summary_root": self.lane_summary_root,
            "missing_observation_root": self.missing_observation_root,
            "mismatch_observation_root": self.mismatch_observation_root,
            "privacy_hold_root": self.privacy_hold_root,
            "pq_hold_root": self.pq_hold_root,
            "release_gate_root": self.release_gate_root,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "state_root".to_string(),
                Value::String(self.state_root.clone()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub sources: BTreeMap<String, LiveFeedSource>,
    pub observations: BTreeMap<String, FeedObservation>,
    pub release_gate: ReleaseGate,
}

impl State {
    pub fn new(config: Config) -> Self {
        let sources = BTreeMap::new();
        let observations = BTreeMap::new();
        let release_gate = ReleaseGate {
            gate_id: release_gate_id(&config.release_candidate_id, config.observation_epoch),
            decision: ProductionDecision::Hold,
            open_blockers: 0,
            release_stop_blockers: 0,
            missing_observations: 0,
            mismatched_observations: 0,
            privacy_holds: 0,
            pq_holds: 0,
            go_no_go_reason: "no live-feed observations have been ingested".to_string(),
            gate_root: merkle_root("LIVE-FEED-OBSERVATION-EMPTY-GATE", &[]),
        };
        Self {
            config,
            sources,
            observations,
            release_gate,
        }
    }

    pub fn with_source(mut self, source: LiveFeedSource) -> Result<Self> {
        if source.source_id.is_empty() {
            return Err("live feed source_id must not be empty".to_string());
        }
        self.sources.insert(source.source_id.clone(), source);
        self.refresh_release_gate();
        Ok(self)
    }

    pub fn with_observation(mut self, observation: FeedObservation) -> Result<Self> {
        if observation.observation_id.is_empty() {
            return Err("feed observation_id must not be empty".to_string());
        }
        if !self.sources.contains_key(&observation.source_id) {
            return Err(format!(
                "feed observation {} references unknown source {}",
                observation.observation_id, observation.source_id
            ));
        }
        self.observations
            .insert(observation.observation_id.clone(), observation);
        self.refresh_release_gate();
        Ok(self)
    }

    pub fn lane_summaries(&self) -> Vec<BlockerLaneSummary> {
        BlockerLane::all()
            .iter()
            .map(|lane| self.lane_summary(*lane))
            .collect()
    }

    pub fn lane_summary(&self, lane: BlockerLane) -> BlockerLaneSummary {
        let lane_sources = self
            .sources
            .values()
            .filter(|source| source.lane == lane)
            .collect::<Vec<_>>();
        let lane_observations = self
            .observations
            .values()
            .filter(|observation| observation.lane == lane)
            .collect::<Vec<_>>();
        let missing_count = lane_observations
            .iter()
            .filter(|observation| observation.status == ObservationStatus::Missing)
            .count() as u64;
        let mismatch_count = lane_observations
            .iter()
            .filter(|observation| !observation.roots_match())
            .count() as u64;
        let stale_count = lane_observations
            .iter()
            .filter(|observation| observation.status == ObservationStatus::Stale)
            .count() as u64;
        let hold_count = lane_observations
            .iter()
            .filter(|observation| {
                observation.status == ObservationStatus::HoldOpen || observation.pq_hold_count > 0
            })
            .count() as u64;
        let release_stop_count = lane_observations
            .iter()
            .filter(|observation| observation.severity == BlockerSeverity::ReleaseStop)
            .count() as u64;
        let mut max_severity = BlockerSeverity::Informational;
        for observation in &lane_observations {
            if observation.severity.score() > max_severity.score() {
                max_severity = observation.severity;
            }
        }
        let lane_blocked = lane_sources.len() != lane_observations.len()
            || lane_observations
                .iter()
                .any(|observation| observation.release_blocking());
        let lane_items = lane_observations
            .iter()
            .map(|observation| observation.state_root())
            .collect::<Vec<_>>();
        let lane_root = merkle_root(
            &format!("LIVE-FEED-OBSERVATION-LANE-{}", lane.as_str()),
            &lane_items,
        );

        BlockerLaneSummary {
            lane,
            source_count: lane_sources.len() as u64,
            observation_count: lane_observations.len() as u64,
            missing_count,
            mismatch_count,
            stale_count,
            hold_count,
            release_stop_count,
            max_severity,
            lane_blocked,
            lane_root,
        }
    }

    pub fn missing_observations(&self) -> Vec<&FeedObservation> {
        self.observations
            .values()
            .filter(|observation| observation.status == ObservationStatus::Missing)
            .collect()
    }

    pub fn mismatched_observations(&self) -> Vec<&FeedObservation> {
        self.observations
            .values()
            .filter(|observation| !observation.roots_match())
            .collect()
    }

    pub fn privacy_holds(&self) -> Vec<&FeedObservation> {
        self.observations
            .values()
            .filter(|observation| {
                observation.lane == BlockerLane::PrivacySurfaces
                    && (observation.release_blocking() || observation.privacy_surface_count > 0)
            })
            .collect()
    }

    pub fn pq_holds(&self) -> Vec<&FeedObservation> {
        self.observations
            .values()
            .filter(|observation| {
                observation.lane == BlockerLane::PqReleaseHolds
                    || observation.lane == BlockerLane::PqWatchers
                    || observation.pq_hold_count > 0
            })
            .filter(|observation| observation.release_blocking())
            .collect()
    }

    pub fn production_decision(&self) -> ProductionDecision {
        if !self.config.production_release_allowed {
            return ProductionDecision::NoGo;
        }
        if self
            .observations
            .values()
            .any(|observation| observation.severity == BlockerSeverity::ReleaseStop)
        {
            return ProductionDecision::NoGo;
        }
        if self
            .lane_summaries()
            .iter()
            .any(|summary| summary.lane_blocked)
        {
            return ProductionDecision::Hold;
        }
        ProductionDecision::Go
    }

    pub fn refresh_release_gate(&mut self) {
        let missing_observations = self.missing_observations().len() as u64;
        let mismatched_observations = self.mismatched_observations().len() as u64;
        let privacy_holds = self.privacy_holds().len() as u64;
        let pq_holds = self.pq_holds().len() as u64;
        let open_blockers = self
            .observations
            .values()
            .filter(|observation| observation.release_blocking())
            .count() as u64;
        let release_stop_blockers = self
            .observations
            .values()
            .filter(|observation| observation.severity == BlockerSeverity::ReleaseStop)
            .count() as u64;
        let decision = self.production_decision();
        let go_no_go_reason = release_reason(
            decision,
            open_blockers,
            missing_observations,
            mismatched_observations,
            privacy_holds,
            pq_holds,
            self.config.production_release_allowed,
        );
        let gate_id = release_gate_id(
            &self.config.release_candidate_id,
            self.config.observation_epoch,
        );
        let gate_root = domain_hash(
            "LIVE-FEED-OBSERVATION-RELEASE-GATE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&gate_id),
                HashPart::Str(decision.as_str()),
                HashPart::Int(open_blockers as i128),
                HashPart::Int(release_stop_blockers as i128),
                HashPart::Int(missing_observations as i128),
                HashPart::Int(mismatched_observations as i128),
                HashPart::Int(privacy_holds as i128),
                HashPart::Int(pq_holds as i128),
            ],
            32,
        );
        self.release_gate = ReleaseGate {
            gate_id,
            decision,
            open_blockers,
            release_stop_blockers,
            missing_observations,
            mismatched_observations,
            privacy_holds,
            pq_holds,
            go_no_go_reason,
            gate_root,
        };
    }

    pub fn roots(&self) -> StateRoots {
        let config_root = self.config.state_root();
        let source_root = merkle_root(
            "LIVE-FEED-OBSERVATION-SOURCES",
            &self
                .sources
                .values()
                .map(LiveFeedSource::state_root)
                .collect::<Vec<_>>(),
        );
        let observation_root = merkle_root(
            "LIVE-FEED-OBSERVATIONS",
            &self
                .observations
                .values()
                .map(FeedObservation::state_root)
                .collect::<Vec<_>>(),
        );
        let lane_summary_root = merkle_root(
            "LIVE-FEED-OBSERVATION-LANE-SUMMARIES",
            &self
                .lane_summaries()
                .iter()
                .map(BlockerLaneSummary::state_root)
                .collect::<Vec<_>>(),
        );
        let missing_observation_root = merkle_root(
            "LIVE-FEED-OBSERVATION-MISSING",
            &self
                .missing_observations()
                .iter()
                .map(|observation| observation.state_root())
                .collect::<Vec<_>>(),
        );
        let mismatch_observation_root = merkle_root(
            "LIVE-FEED-OBSERVATION-MISMATCH",
            &self
                .mismatched_observations()
                .iter()
                .map(|observation| observation.state_root())
                .collect::<Vec<_>>(),
        );
        let privacy_hold_root = merkle_root(
            "LIVE-FEED-OBSERVATION-PRIVACY-HOLDS",
            &self
                .privacy_holds()
                .iter()
                .map(|observation| observation.state_root())
                .collect::<Vec<_>>(),
        );
        let pq_hold_root = merkle_root(
            "LIVE-FEED-OBSERVATION-PQ-HOLDS",
            &self
                .pq_holds()
                .iter()
                .map(|observation| observation.state_root())
                .collect::<Vec<_>>(),
        );
        let release_gate_root = self.release_gate.state_root();
        let root_record = json!({
            "config_root": config_root.clone(),
            "source_root": source_root.clone(),
            "observation_root": observation_root.clone(),
            "lane_summary_root": lane_summary_root.clone(),
            "missing_observation_root": missing_observation_root.clone(),
            "mismatch_observation_root": mismatch_observation_root.clone(),
            "privacy_hold_root": privacy_hold_root.clone(),
            "pq_hold_root": pq_hold_root.clone(),
            "release_gate_root": release_gate_root.clone(),
        });
        let state_root = record_root("state", &root_record);
        StateRoots {
            config_root,
            source_root,
            observation_root,
            lane_summary_root,
            missing_observation_root,
            mismatch_observation_root,
            privacy_hold_root,
            pq_hold_root,
            release_gate_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "sources": self.sources.values().map(LiveFeedSource::public_record).collect::<Vec<_>>(),
            "observations": self.observations.values().map(FeedObservation::public_record).collect::<Vec<_>>(),
            "lane_summaries": self.lane_summaries().iter().map(BlockerLaneSummary::public_record).collect::<Vec<_>>(),
            "release_gate": self.release_gate.public_record(),
            "roots": self.roots().public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let mut state = State::new(config.clone());
    for source in devnet_sources(&config) {
        if let Ok(next) = state.clone().with_source(source) {
            state = next;
        }
    }
    for observation in devnet_observations(&config) {
        if let Ok(next) = state.clone().with_observation(observation) {
            state = next;
        }
    }
    state.refresh_release_gate();
    state
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn devnet_sources(config: &Config) -> Vec<LiveFeedSource> {
    vec![
        source(
            config,
            BlockerLane::MoneroHeaders,
            SourceRequirement::RequiredRootMatch,
            "monero-header-reorg-adapter",
            18,
            1,
        ),
        source(
            config,
            BlockerLane::DepositLocks,
            SourceRequirement::RequiredRootMatch,
            "deposit-lock-watcher-adapter",
            20,
            1,
        ),
        source(
            config,
            BlockerLane::PqWatchers,
            SourceRequirement::RequiredQuorum,
            "pq-watcher-quorum-adapter",
            0,
            config.min_watcher_quorum,
        ),
        source(
            config,
            BlockerLane::ReserveSufficiency,
            SourceRequirement::RequiredFreshness,
            "reserve-release-adapter",
            0,
            1,
        ),
        source(
            config,
            BlockerLane::AdversarialCases,
            SourceRequirement::Required,
            "adversarial-case-harness",
            0,
            1,
        ),
        source(
            config,
            BlockerLane::PrivacySurfaces,
            SourceRequirement::RequiredHumanSignoff,
            "privacy-surface-regression-harness",
            0,
            1,
        ),
        source(
            config,
            BlockerLane::PqReleaseHolds,
            SourceRequirement::RequiredHumanSignoff,
            "pq-release-authority-hold-ledger",
            0,
            config.min_watcher_quorum,
        ),
        source(
            config,
            BlockerLane::ProductionReleaseGates,
            SourceRequirement::RequiredHumanSignoff,
            "production-release-go-no-go-gate",
            0,
            1,
        ),
    ]
}

fn devnet_observations(config: &Config) -> Vec<FeedObservation> {
    vec![
        observation(
            config,
            1,
            BlockerLane::MoneroHeaders,
            ObservationKind::HeaderContinuity,
            ObservationStatus::Observed,
            BlockerSeverity::Watch,
            1,
            1,
            10_500,
            vec![],
            vec![],
        ),
        observation(
            config,
            2,
            BlockerLane::MoneroHeaders,
            ObservationKind::HeaderReorgFence,
            ObservationStatus::Mismatched,
            BlockerSeverity::ReleaseStop,
            1,
            1,
            10_500,
            vec![],
            vec!["header tip root diverged from reorg fence root"],
        ),
        observation(
            config,
            3,
            BlockerLane::DepositLocks,
            ObservationKind::DepositLockFinality,
            ObservationStatus::Missing,
            BlockerSeverity::ReleaseStop,
            1,
            1,
            10_500,
            vec!["deposit lock finality receipt missing"],
            vec![],
        ),
        observation(
            config,
            4,
            BlockerLane::DepositLocks,
            ObservationKind::DepositNoteLinkage,
            ObservationStatus::Observed,
            BlockerSeverity::Major,
            1,
            1,
            10_500,
            vec![],
            vec![],
        ),
        observation(
            config,
            5,
            BlockerLane::PqWatchers,
            ObservationKind::PqWatcherQuorum,
            ObservationStatus::Stale,
            BlockerSeverity::Critical,
            2,
            config.min_watcher_quorum,
            10_500,
            vec!["fresh pq watcher quorum frame missing"],
            vec![],
        ),
        observation(
            config,
            6,
            BlockerLane::ReserveSufficiency,
            ObservationKind::ReserveLiquidityFloor,
            ObservationStatus::Observed,
            BlockerSeverity::Critical,
            1,
            1,
            9_800,
            vec![],
            vec!["reserve coverage below configured release floor"],
        ),
        observation(
            config,
            7,
            BlockerLane::AdversarialCases,
            ObservationKind::AdversarialMismatchCase,
            ObservationStatus::Blocked,
            BlockerSeverity::ReleaseStop,
            1,
            1,
            10_500,
            vec![],
            vec!["negative replay still produces admissible release transcript"],
        ),
        observation(
            config,
            8,
            BlockerLane::PrivacySurfaces,
            ObservationKind::PrivacyLeakRegression,
            ObservationStatus::HoldOpen,
            BlockerSeverity::ReleaseStop,
            1,
            1,
            10_500,
            vec!["privacy signoff hold remains open"],
            vec![],
        ),
        observation(
            config,
            9,
            BlockerLane::PqReleaseHolds,
            ObservationKind::PqAuthorityRotation,
            ObservationStatus::HoldOpen,
            BlockerSeverity::Critical,
            2,
            config.min_watcher_quorum,
            10_500,
            vec!["pq authority rotation release hold remains open"],
            vec![],
        ),
        observation(
            config,
            10,
            BlockerLane::ProductionReleaseGates,
            ObservationKind::ProductionGoNoGo,
            ObservationStatus::Blocked,
            BlockerSeverity::ReleaseStop,
            1,
            1,
            10_500,
            vec!["production signoff intentionally no-go"],
            vec![],
        ),
    ]
}

fn source(
    config: &Config,
    lane: BlockerLane,
    requirement: SourceRequirement,
    adapter_id: &str,
    min_confirmations: u64,
    min_quorum: u64,
) -> LiveFeedSource {
    let source_id = format!("{}-source-{}", config.release_candidate_id, lane.as_str());
    let expected_feed_root = domain_hash(
        "LIVE-FEED-OBSERVATION-EXPECTED-SOURCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.release_candidate_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(requirement.as_str()),
            HashPart::Str(adapter_id),
            HashPart::Int(config.observation_epoch as i128),
        ],
        32,
    );
    LiveFeedSource {
        source_id,
        lane,
        requirement,
        adapter_id: adapter_id.to_string(),
        expected_feed_root,
        min_confirmations,
        min_quorum,
        max_lag_blocks: config.max_feed_lag_blocks,
        release_blocking: true,
    }
}

fn observation(
    config: &Config,
    sequence: u64,
    lane: BlockerLane,
    kind: ObservationKind,
    status: ObservationStatus,
    severity: BlockerSeverity,
    observed_quorum: u64,
    required_quorum: u64,
    reserve_coverage_bps: u64,
    missing_evidence: Vec<&str>,
    mismatch_evidence: Vec<&str>,
) -> FeedObservation {
    let source_id = format!("{}-source-{}", config.release_candidate_id, lane.as_str());
    let observation_id = format!(
        "{}-observation-{:02}-{}",
        config.release_candidate_id,
        sequence,
        kind.as_str()
    );
    let expected_root = domain_hash(
        "LIVE-FEED-OBSERVATION-EXPECTED-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&config.release_candidate_id),
            HashPart::Str(lane.as_str()),
            HashPart::Str(kind.as_str()),
            HashPart::Int(sequence as i128),
        ],
        32,
    );
    let observed_root = if status == ObservationStatus::Observed {
        expected_root.clone()
    } else {
        domain_hash(
            "LIVE-FEED-OBSERVATION-ACTUAL-ROOT",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&config.release_candidate_id),
                HashPart::Str(status.as_str()),
                HashPart::Str(kind.as_str()),
                HashPart::Int(sequence as i128),
            ],
            32,
        )
    };
    FeedObservation {
        observation_id,
        source_id,
        lane,
        kind,
        status,
        severity,
        observed_at_height: 880_000 + sequence,
        expected_height: 880_000 + sequence + config.max_feed_lag_blocks,
        expected_root,
        observed_root,
        observed_quorum,
        required_quorum,
        reserve_coverage_bps,
        privacy_surface_count: privacy_surface_count(lane, status),
        pq_hold_count: pq_hold_count(lane, status),
        missing_evidence: missing_evidence
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>(),
        mismatch_evidence: mismatch_evidence
            .iter()
            .map(|item| item.to_string())
            .collect::<Vec<_>>(),
        clearance_requirement: clearance_requirement(lane, status).to_string(),
    }
}

fn release_gate_id(release_candidate_id: &str, observation_epoch: u64) -> String {
    domain_hash(
        "LIVE-FEED-OBSERVATION-RELEASE-GATE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(release_candidate_id),
            HashPart::Int(observation_epoch as i128),
        ],
        16,
    )
}

fn release_reason(
    decision: ProductionDecision,
    open_blockers: u64,
    missing: u64,
    mismatched: u64,
    privacy_holds: u64,
    pq_holds: u64,
    production_release_allowed: bool,
) -> String {
    if !production_release_allowed {
        return "production release flag is disabled while live-feed blockers remain under observation"
            .to_string();
    }
    match decision {
        ProductionDecision::Go => "all release-blocker live-feed lanes are observed and clear".to_string(),
        ProductionDecision::Hold => format!(
            "release hold: {} open blockers, {} missing, {} mismatched, {} privacy holds, {} pq holds",
            open_blockers, missing, mismatched, privacy_holds, pq_holds
        ),
        ProductionDecision::NoGo => format!(
            "production no-go: {} open blockers include release-stop severity evidence",
            open_blockers
        ),
    }
}

fn clearance_requirement(lane: BlockerLane, status: ObservationStatus) -> &'static str {
    match (lane, status) {
        (_, ObservationStatus::Observed) => "retain observation in live-feed evidence bundle",
        (BlockerLane::MoneroHeaders, _) => {
            "replay monero header feed and reconcile reorg fence root"
        }
        (BlockerLane::DepositLocks, _) => {
            "ingest final deposit lock receipt and deposit-note linkage root"
        }
        (BlockerLane::PqWatchers, _) => "refresh pq watcher quorum with current attestation root",
        (BlockerLane::ReserveSufficiency, _) => {
            "publish reserve proof above release coverage floor"
        }
        (BlockerLane::AdversarialCases, _) => "clear adversarial negative case before release gate",
        (BlockerLane::PrivacySurfaces, _) => {
            "complete privacy signoff and publish redacted surface root"
        }
        (BlockerLane::PqReleaseHolds, _) => {
            "complete pq authority hold clearance and rotation signoff"
        }
        (BlockerLane::ProductionReleaseGates, _) => {
            "record production go decision with all lane roots attached"
        }
    }
}

fn privacy_surface_count(lane: BlockerLane, status: ObservationStatus) -> u64 {
    if lane == BlockerLane::PrivacySurfaces && status != ObservationStatus::Observed {
        return 3;
    }
    0
}

fn pq_hold_count(lane: BlockerLane, status: ObservationStatus) -> u64 {
    if (lane == BlockerLane::PqReleaseHolds || lane == BlockerLane::PqWatchers)
        && status != ObservationStatus::Observed
    {
        return 2;
    }
    0
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "LIVE-FEED-OBSERVATION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
