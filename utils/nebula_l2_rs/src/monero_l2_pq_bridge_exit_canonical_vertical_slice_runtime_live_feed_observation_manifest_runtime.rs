use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceRuntimeLiveFeedObservationManifestRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_LIVE_FEED_OBSERVATION_MANIFEST_RUNTIME_PROTOCOL_VERSION:
    &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-runtime-live-feed-observation-manifest-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RUNTIME_LIVE_FEED_OBSERVATION_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str = "live-feed-observation-manifest/1";
pub const HASH_SUITE: &str = "nebula-domain-hash+json-merkle-v1";
pub const OBSERVATION_SUITE: &str = "monero-live-feed-observation+fail-closed-v1";
pub const DEFAULT_RUNTIME_GATE: &str = "cargo-runtime-heavy-gate-deferred";
pub const DEFAULT_RELEASE_CANDIDATE: &str = "bridge-exit-live-feed-observation-rc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LiveFeedLane {
    MoneroHeader,
    DepositLock,
    PqWatcherQuorum,
    ReserveLiquidity,
    AdversarialFeed,
    ReleaseBlocker,
    EvidenceAcceptance,
}

impl LiveFeedLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeader => "monero_header",
            Self::DepositLock => "deposit_lock",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::ReserveLiquidity => "reserve_liquidity",
            Self::AdversarialFeed => "adversarial_feed",
            Self::ReleaseBlocker => "release_blocker",
            Self::EvidenceAcceptance => "evidence_acceptance",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::MoneroHeader => "Monero header and finality feed",
            Self::DepositLock => "Monero deposit lock feed",
            Self::PqWatcherQuorum => "PQ watcher quorum feed",
            Self::ReserveLiquidity => "reserve and liquidity feed",
            Self::AdversarialFeed => "adversarial live-feed probes",
            Self::ReleaseBlocker => "release blocker feed aggregator",
            Self::EvidenceAcceptance => "evidence acceptance feed",
        }
    }

    pub fn required_sources(self) -> u64 {
        match self {
            Self::MoneroHeader => 4,
            Self::DepositLock => 4,
            Self::PqWatcherQuorum => 3,
            Self::ReserveLiquidity => 3,
            Self::AdversarialFeed => 2,
            Self::ReleaseBlocker => 4,
            Self::EvidenceAcceptance => 3,
        }
    }

    pub fn requires_wallet_surface(self) -> bool {
        matches!(self, Self::DepositLock | Self::EvidenceAcceptance)
    }

    pub fn requires_fail_closed(self) -> bool {
        matches!(self, Self::AdversarialFeed | Self::ReleaseBlocker)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LiveFeedSource {
    MoneroDaemonPrimary,
    MoneroDaemonSecondary,
    PqWatcherQuorum,
    OperatorExport,
    WalletReplay,
    AuditorReplay,
    ReserveReporter,
}

impl LiveFeedSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroDaemonPrimary => "monero_daemon_primary",
            Self::MoneroDaemonSecondary => "monero_daemon_secondary",
            Self::PqWatcherQuorum => "pq_watcher_quorum",
            Self::OperatorExport => "operator_export",
            Self::WalletReplay => "wallet_replay",
            Self::AuditorReplay => "auditor_replay",
            Self::ReserveReporter => "reserve_reporter",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LiveFeedStatus {
    DeferredUntilRuntime,
    ObservedMatch,
    MissingSourceQuorum,
    StaleFeed,
    ConflictingFeed,
    PrivacySurfaceMismatch,
    ReleaseBlocked,
}

impl LiveFeedStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeferredUntilRuntime => "deferred_until_runtime",
            Self::ObservedMatch => "observed_match",
            Self::MissingSourceQuorum => "missing_source_quorum",
            Self::StaleFeed => "stale_feed",
            Self::ConflictingFeed => "conflicting_feed",
            Self::PrivacySurfaceMismatch => "privacy_surface_mismatch",
            Self::ReleaseBlocked => "release_blocked",
        }
    }

    pub fn blocks_release(self) -> bool {
        !matches!(self, Self::ObservedMatch)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifestVerdict {
    LiveObservationRequired,
    ReleaseBlockedUntilLiveFeedsMatch,
    HeavyGateReadyWhenCargoAllowed,
}

impl ManifestVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LiveObservationRequired => "live_observation_required",
            Self::ReleaseBlockedUntilLiveFeedsMatch => "release_blocked_until_live_feeds_match",
            Self::HeavyGateReadyWhenCargoAllowed => "heavy_gate_ready_when_cargo_allowed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: String,
    pub hash_suite: String,
    pub observation_suite: String,
    pub runtime_gate: String,
    pub release_candidate: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub min_monero_finality_depth: u64,
    pub max_feed_lag_blocks: u64,
    pub min_pq_watcher_quorum: u64,
    pub min_reserve_coverage_bps: u64,
    pub mismatch_policy: String,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            observation_suite: OBSERVATION_SUITE.to_string(),
            runtime_gate: DEFAULT_RUNTIME_GATE.to_string(),
            release_candidate: DEFAULT_RELEASE_CANDIDATE.to_string(),
            l2_reference_height: 74_000,
            monero_reference_height: 3_260_720,
            min_monero_finality_depth: 20,
            max_feed_lag_blocks: 3,
            min_pq_watcher_quorum: 5,
            min_reserve_coverage_bps: 10_500,
            mismatch_policy: "block forced-exit release and preserve evidence roots".to_string(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "observation_suite": self.observation_suite,
            "runtime_gate": self.runtime_gate,
            "release_candidate": self.release_candidate,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "min_monero_finality_depth": self.min_monero_finality_depth,
            "max_feed_lag_blocks": self.max_feed_lag_blocks,
            "min_pq_watcher_quorum": self.min_pq_watcher_quorum,
            "min_reserve_coverage_bps": self.min_reserve_coverage_bps,
            "mismatch_policy": self.mismatch_policy,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-manifest-config",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedObservationRequirement {
    pub lane: LiveFeedLane,
    pub lane_label: String,
    pub required_sources: u64,
    pub required_source_root: String,
    pub expected_observation_root: String,
    pub replay_stub_root: String,
    pub live_feed_contract_root: String,
    pub fail_closed_required: bool,
    pub wallet_surface_required: bool,
    pub finality_depth_required: u64,
    pub max_feed_lag_blocks: u64,
    pub pq_quorum_required: u64,
    pub reserve_coverage_bps_required: u64,
}

impl LiveFeedObservationRequirement {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "lane_label": self.lane_label,
            "required_sources": self.required_sources,
            "required_source_root": self.required_source_root,
            "expected_observation_root": self.expected_observation_root,
            "replay_stub_root": self.replay_stub_root,
            "live_feed_contract_root": self.live_feed_contract_root,
            "fail_closed_required": self.fail_closed_required,
            "wallet_surface_required": self.wallet_surface_required,
            "finality_depth_required": self.finality_depth_required,
            "max_feed_lag_blocks": self.max_feed_lag_blocks,
            "pq_quorum_required": self.pq_quorum_required,
            "reserve_coverage_bps_required": self.reserve_coverage_bps_required,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-requirement",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedObservationRecord {
    pub lane: LiveFeedLane,
    pub source_roots: BTreeMap<String, String>,
    pub observed_source_count: u64,
    pub observed_feed_root: String,
    pub observed_height: u64,
    pub observed_lag_blocks: u64,
    pub observed_finality_depth: u64,
    pub observed_pq_quorum: u64,
    pub observed_reserve_coverage_bps: u64,
    pub wallet_surface_root: String,
    pub privacy_surface_root: String,
    pub operator_evidence_root: String,
    pub auditor_evidence_root: String,
    pub expected_matches_live: bool,
    pub source_quorum_satisfied: bool,
    pub finality_satisfied: bool,
    pub pq_quorum_satisfied: bool,
    pub reserve_coverage_satisfied: bool,
    pub privacy_surface_satisfied: bool,
    pub release_blockers: u64,
    pub status: LiveFeedStatus,
}

impl LiveFeedObservationRecord {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "source_roots": self.source_roots,
            "observed_source_count": self.observed_source_count,
            "observed_feed_root": self.observed_feed_root,
            "observed_height": self.observed_height,
            "observed_lag_blocks": self.observed_lag_blocks,
            "observed_finality_depth": self.observed_finality_depth,
            "observed_pq_quorum": self.observed_pq_quorum,
            "observed_reserve_coverage_bps": self.observed_reserve_coverage_bps,
            "wallet_surface_root": self.wallet_surface_root,
            "privacy_surface_root": self.privacy_surface_root,
            "operator_evidence_root": self.operator_evidence_root,
            "auditor_evidence_root": self.auditor_evidence_root,
            "expected_matches_live": self.expected_matches_live,
            "source_quorum_satisfied": self.source_quorum_satisfied,
            "finality_satisfied": self.finality_satisfied,
            "pq_quorum_satisfied": self.pq_quorum_satisfied,
            "reserve_coverage_satisfied": self.reserve_coverage_satisfied,
            "privacy_surface_satisfied": self.privacy_surface_satisfied,
            "release_blockers": self.release_blockers,
            "status": self.status.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-observation-record",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.observed_feed_root),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedMismatch {
    pub lane: LiveFeedLane,
    pub mismatch_code: String,
    pub expected_root: String,
    pub observed_root: String,
    pub evidence_root: String,
    pub severity: String,
    pub release_effect: String,
}

impl LiveFeedMismatch {
    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane.as_str(),
            "mismatch_code": self.mismatch_code,
            "expected_root": self.expected_root,
            "observed_root": self.observed_root,
            "evidence_root": self.evidence_root,
            "severity": self.severity,
            "release_effect": self.release_effect,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-mismatch",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(self.lane.as_str()),
                HashPart::Str(&self.mismatch_code),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedCounters {
    pub total_lanes: u64,
    pub release_blocked_lanes: u64,
    pub missing_source_quorum_lanes: u64,
    pub stale_feed_lanes: u64,
    pub conflicting_feed_lanes: u64,
    pub privacy_surface_mismatch_lanes: u64,
    pub source_roots_required: u64,
    pub source_roots_observed: u64,
}

impl LiveFeedCounters {
    pub fn from_records(
        requirements: &[LiveFeedObservationRequirement],
        records: &[LiveFeedObservationRecord],
    ) -> Self {
        let mut counters = Self {
            total_lanes: records.len() as u64,
            release_blocked_lanes: 0,
            missing_source_quorum_lanes: 0,
            stale_feed_lanes: 0,
            conflicting_feed_lanes: 0,
            privacy_surface_mismatch_lanes: 0,
            source_roots_required: requirements
                .iter()
                .map(|requirement| requirement.required_sources)
                .sum(),
            source_roots_observed: records
                .iter()
                .map(|record| record.observed_source_count)
                .sum(),
        };

        for record in records {
            if record.status.blocks_release() {
                counters.release_blocked_lanes += 1;
            }
            match record.status {
                LiveFeedStatus::MissingSourceQuorum | LiveFeedStatus::DeferredUntilRuntime => {
                    counters.missing_source_quorum_lanes += 1;
                }
                LiveFeedStatus::StaleFeed => counters.stale_feed_lanes += 1,
                LiveFeedStatus::ConflictingFeed => counters.conflicting_feed_lanes += 1,
                LiveFeedStatus::PrivacySurfaceMismatch => {
                    counters.privacy_surface_mismatch_lanes += 1;
                }
                LiveFeedStatus::ReleaseBlocked => counters.release_blocked_lanes += 1,
                LiveFeedStatus::ObservedMatch => {}
            }
        }

        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_lanes": self.total_lanes,
            "release_blocked_lanes": self.release_blocked_lanes,
            "missing_source_quorum_lanes": self.missing_source_quorum_lanes,
            "stale_feed_lanes": self.stale_feed_lanes,
            "conflicting_feed_lanes": self.conflicting_feed_lanes,
            "privacy_surface_mismatch_lanes": self.privacy_surface_mismatch_lanes,
            "source_roots_required": self.source_roots_required,
            "source_roots_observed": self.source_roots_observed,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-counters",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedRoots {
    pub config_root: String,
    pub requirement_root: String,
    pub observation_root: String,
    pub source_root: String,
    pub mismatch_root: String,
    pub finality_root: String,
    pub pq_quorum_root: String,
    pub reserve_root: String,
    pub privacy_surface_root: String,
    pub release_hold_root: String,
    pub counter_root: String,
}

impl LiveFeedRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "requirement_root": self.requirement_root,
            "observation_root": self.observation_root,
            "source_root": self.source_root,
            "mismatch_root": self.mismatch_root,
            "finality_root": self.finality_root,
            "pq_quorum_root": self.pq_quorum_root,
            "reserve_root": self.reserve_root,
            "privacy_surface_root": self.privacy_surface_root,
            "release_hold_root": self.release_hold_root,
            "counter_root": self.counter_root,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-roots",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Json(&self.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveFeedObservationManifest {
    pub manifest_id: String,
    pub config: Config,
    pub requirements: Vec<LiveFeedObservationRequirement>,
    pub records: Vec<LiveFeedObservationRecord>,
    pub mismatches: Vec<LiveFeedMismatch>,
    pub counters: LiveFeedCounters,
    pub roots: LiveFeedRoots,
    pub release_holds: BTreeMap<String, String>,
    pub verdict: ManifestVerdict,
}

impl LiveFeedObservationManifest {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let requirements = observation_requirements(&config);
        let records = observation_records(&config, &requirements);
        let mismatches = mismatch_records(&requirements, &records);
        let counters = LiveFeedCounters::from_records(&requirements, &records);
        let release_holds = release_hold_reasons(&records);
        let roots = LiveFeedRoots {
            config_root: config.state_root(),
            requirement_root: requirement_merkle(&requirements),
            observation_root: observation_merkle(&records),
            source_root: source_merkle(&records),
            mismatch_root: mismatch_merkle(&mismatches),
            finality_root: finality_merkle(&records),
            pq_quorum_root: pq_quorum_merkle(&records),
            reserve_root: reserve_merkle(&records),
            privacy_surface_root: privacy_surface_merkle(&records),
            release_hold_root: hold_root(&release_holds),
            counter_root: counters.state_root(),
        };
        let manifest_id = manifest_id(&config, &roots);
        let verdict = if counters.release_blocked_lanes == 0 {
            ManifestVerdict::HeavyGateReadyWhenCargoAllowed
        } else {
            ManifestVerdict::ReleaseBlockedUntilLiveFeedsMatch
        };

        Self {
            manifest_id,
            config,
            requirements,
            records,
            mismatches,
            counters,
            roots,
            release_holds,
            verdict,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "manifest_id": self.manifest_id,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "requirements": self.requirements.iter().map(LiveFeedObservationRequirement::public_record).collect::<Vec<_>>(),
            "records": self.records.iter().map(LiveFeedObservationRecord::public_record).collect::<Vec<_>>(),
            "mismatches": self.mismatches.iter().map(LiveFeedMismatch::public_record).collect::<Vec<_>>(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "release_holds": self.release_holds,
            "verdict": self.verdict.as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-live-feed-observation-manifest-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.manifest_id),
                HashPart::Str(&self.roots.state_root()),
                HashPart::Json(&self.counters.public_record()),
            ],
            32,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub manifest: LiveFeedObservationManifest,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let manifest = LiveFeedObservationManifest::devnet();
        let state_root = manifest.state_root();
        Self {
            manifest,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "state_root": self.state_root,
            "manifest": self.manifest.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
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

fn observation_requirements(config: &Config) -> Vec<LiveFeedObservationRequirement> {
    [
        LiveFeedLane::MoneroHeader,
        LiveFeedLane::DepositLock,
        LiveFeedLane::PqWatcherQuorum,
        LiveFeedLane::ReserveLiquidity,
        LiveFeedLane::AdversarialFeed,
        LiveFeedLane::ReleaseBlocker,
        LiveFeedLane::EvidenceAcceptance,
    ]
    .into_iter()
    .map(|lane| LiveFeedObservationRequirement {
        lane,
        lane_label: lane.label().to_string(),
        required_sources: lane.required_sources(),
        required_source_root: required_source_root(lane),
        expected_observation_root: expected_observation_root(lane),
        replay_stub_root: replay_stub_root(lane),
        live_feed_contract_root: live_feed_contract_root(lane),
        fail_closed_required: lane.requires_fail_closed(),
        wallet_surface_required: lane.requires_wallet_surface(),
        finality_depth_required: config.min_monero_finality_depth,
        max_feed_lag_blocks: config.max_feed_lag_blocks,
        pq_quorum_required: config.min_pq_watcher_quorum,
        reserve_coverage_bps_required: config.min_reserve_coverage_bps,
    })
    .collect()
}

fn observation_records(
    config: &Config,
    requirements: &[LiveFeedObservationRequirement],
) -> Vec<LiveFeedObservationRecord> {
    requirements
        .iter()
        .enumerate()
        .map(|(index, requirement)| {
            let observed_source_count = 0;
            let observed_finality_depth = 0;
            let observed_pq_quorum = 0;
            let observed_reserve_coverage_bps = 0;
            let expected_matches_live = false;
            let source_quorum_satisfied = false;
            let finality_satisfied = false;
            let pq_quorum_satisfied = false;
            let reserve_coverage_satisfied = false;
            let privacy_surface_satisfied = false;
            let status = status_for(
                observed_source_count,
                requirement.required_sources,
                observed_finality_depth,
                requirement.finality_depth_required,
                expected_matches_live,
                privacy_surface_satisfied,
            );
            let release_blockers = release_blocker_count(
                requirement,
                observed_source_count,
                observed_finality_depth,
                observed_pq_quorum,
                observed_reserve_coverage_bps,
                expected_matches_live,
                privacy_surface_satisfied,
            );

            LiveFeedObservationRecord {
                lane: requirement.lane,
                source_roots: source_roots(requirement.lane),
                observed_source_count,
                observed_feed_root: deferred_live_root(requirement.lane),
                observed_height: config.monero_reference_height + index as u64,
                observed_lag_blocks: config.max_feed_lag_blocks + 1,
                observed_finality_depth,
                observed_pq_quorum,
                observed_reserve_coverage_bps,
                wallet_surface_root: wallet_surface_root(requirement.lane),
                privacy_surface_root: privacy_surface_root(requirement.lane),
                operator_evidence_root: operator_evidence_root(requirement.lane),
                auditor_evidence_root: auditor_evidence_root(requirement.lane),
                expected_matches_live,
                source_quorum_satisfied,
                finality_satisfied,
                pq_quorum_satisfied,
                reserve_coverage_satisfied,
                privacy_surface_satisfied,
                release_blockers,
                status,
            }
        })
        .collect()
}

fn status_for(
    observed_source_count: u64,
    required_sources: u64,
    observed_finality_depth: u64,
    required_finality_depth: u64,
    expected_matches_live: bool,
    privacy_surface_satisfied: bool,
) -> LiveFeedStatus {
    if observed_source_count < required_sources {
        return LiveFeedStatus::MissingSourceQuorum;
    }
    if observed_finality_depth < required_finality_depth {
        return LiveFeedStatus::StaleFeed;
    }
    if !privacy_surface_satisfied {
        return LiveFeedStatus::PrivacySurfaceMismatch;
    }
    if !expected_matches_live {
        return LiveFeedStatus::ConflictingFeed;
    }
    LiveFeedStatus::ObservedMatch
}

fn release_blocker_count(
    requirement: &LiveFeedObservationRequirement,
    observed_source_count: u64,
    observed_finality_depth: u64,
    observed_pq_quorum: u64,
    observed_reserve_coverage_bps: u64,
    expected_matches_live: bool,
    privacy_surface_satisfied: bool,
) -> u64 {
    let mut blockers = 0;
    if observed_source_count < requirement.required_sources {
        blockers += requirement.required_sources - observed_source_count;
    }
    if observed_finality_depth < requirement.finality_depth_required {
        blockers += 1;
    }
    if observed_pq_quorum < requirement.pq_quorum_required {
        blockers += 1;
    }
    if observed_reserve_coverage_bps < requirement.reserve_coverage_bps_required {
        blockers += 1;
    }
    if !expected_matches_live {
        blockers += 1;
    }
    if !privacy_surface_satisfied {
        blockers += 1;
    }
    if requirement.fail_closed_required {
        blockers += 1;
    }
    blockers
}

fn source_roots(lane: LiveFeedLane) -> BTreeMap<String, String> {
    [
        LiveFeedSource::MoneroDaemonPrimary,
        LiveFeedSource::MoneroDaemonSecondary,
        LiveFeedSource::PqWatcherQuorum,
        LiveFeedSource::OperatorExport,
        LiveFeedSource::WalletReplay,
        LiveFeedSource::AuditorReplay,
        LiveFeedSource::ReserveReporter,
    ]
    .into_iter()
    .map(|source| {
        (
            source.as_str().to_string(),
            domain_hash(
                "monero-l2-pq-bridge-exit-live-feed-source-root",
                &[
                    HashPart::Str(CHAIN_ID),
                    HashPart::Str(PROTOCOL_VERSION),
                    HashPart::Str(lane.as_str()),
                    HashPart::Str(source.as_str()),
                ],
                32,
            ),
        )
    })
    .collect()
}

fn required_source_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-required-source-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("required-source-set"),
        ],
        32,
    )
}

fn expected_observation_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-expected-observation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("expected-live-feed-observation"),
        ],
        32,
    )
}

fn replay_stub_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-replay-stub-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("replace-replay-stub-under-heavy-gate"),
        ],
        32,
    )
}

fn live_feed_contract_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-contract-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("live-feed-contract"),
        ],
        32,
    )
}

fn deferred_live_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-deferred-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("live-feed-observation-deferred"),
        ],
        32,
    )
}

fn wallet_surface_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-wallet-surface-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("wallet-visible-feed-surface"),
        ],
        32,
    )
}

fn privacy_surface_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-privacy-surface-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("privacy-preserving-feed-surface"),
        ],
        32,
    )
}

fn operator_evidence_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-operator-evidence-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("operator-live-feed-evidence"),
        ],
        32,
    )
}

fn auditor_evidence_root(lane: LiveFeedLane) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-auditor-evidence-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane.as_str()),
            HashPart::Str("auditor-live-feed-evidence"),
        ],
        32,
    )
}

fn mismatch_records(
    requirements: &[LiveFeedObservationRequirement],
    records: &[LiveFeedObservationRecord],
) -> Vec<LiveFeedMismatch> {
    records
        .iter()
        .filter(|record| record.status.blocks_release())
        .map(|record| {
            let expected_root = requirements
                .iter()
                .find(|requirement| requirement.lane == record.lane)
                .map(|requirement| requirement.expected_observation_root.clone())
                .unwrap_or_else(|| expected_observation_root(record.lane));
            LiveFeedMismatch {
                lane: record.lane,
                mismatch_code: mismatch_code(record).to_string(),
                expected_root,
                observed_root: record.observed_feed_root.clone(),
                evidence_root: mismatch_evidence_root(record),
                severity: "release_blocking".to_string(),
                release_effect: "retain forced-exit hold until live feed observation matches"
                    .to_string(),
            }
        })
        .collect()
}

fn mismatch_code(record: &LiveFeedObservationRecord) -> &'static str {
    if !record.source_quorum_satisfied {
        "missing_source_quorum"
    } else if !record.finality_satisfied {
        "stale_or_shallow_finality"
    } else if !record.pq_quorum_satisfied {
        "pq_watcher_quorum_missing"
    } else if !record.reserve_coverage_satisfied {
        "reserve_liquidity_coverage_missing"
    } else if !record.privacy_surface_satisfied {
        "privacy_surface_mismatch"
    } else if !record.expected_matches_live {
        "live_feed_root_mismatch"
    } else {
        "release_hold"
    }
}

fn mismatch_evidence_root(record: &LiveFeedObservationRecord) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-mismatch-evidence",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(record.lane.as_str()),
            HashPart::Str(record.status.as_str()),
            HashPart::Str(&record.observed_feed_root),
        ],
        32,
    )
}

fn requirement_merkle(requirements: &[LiveFeedObservationRequirement]) -> String {
    let leaves = requirements
        .iter()
        .map(|requirement| {
            json!({
                "requirement_root": requirement.state_root(),
                "record": requirement.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-requirements", &leaves)
}

fn observation_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "record_root": record.state_root(),
                "record": record.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-observations", &leaves)
}

fn source_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .flat_map(|record| {
            record.source_roots.iter().map(|(source, root)| {
                json!({
                    "lane": record.lane.as_str(),
                    "source": source,
                    "source_root": root,
                })
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-sources", &leaves)
}

fn mismatch_merkle(mismatches: &[LiveFeedMismatch]) -> String {
    let leaves = mismatches
        .iter()
        .map(|mismatch| {
            json!({
                "mismatch_root": mismatch.state_root(),
                "record": mismatch.public_record(),
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-mismatches", &leaves)
}

fn finality_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "observed_height": record.observed_height,
                "observed_lag_blocks": record.observed_lag_blocks,
                "observed_finality_depth": record.observed_finality_depth,
                "finality_satisfied": record.finality_satisfied,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-finality", &leaves)
}

fn pq_quorum_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "observed_pq_quorum": record.observed_pq_quorum,
                "pq_quorum_satisfied": record.pq_quorum_satisfied,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-pq-quorum", &leaves)
}

fn reserve_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "observed_reserve_coverage_bps": record.observed_reserve_coverage_bps,
                "reserve_coverage_satisfied": record.reserve_coverage_satisfied,
            })
        })
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-reserve", &leaves)
}

fn privacy_surface_merkle(records: &[LiveFeedObservationRecord]) -> String {
    let leaves = records
        .iter()
        .map(|record| {
            json!({
                "lane": record.lane.as_str(),
                "wallet_surface_root": record.wallet_surface_root,
                "privacy_surface_root": record.privacy_surface_root,
                "privacy_surface_satisfied": record.privacy_surface_satisfied,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-live-feed-privacy-surfaces",
        &leaves,
    )
}

fn release_hold_reasons(records: &[LiveFeedObservationRecord]) -> BTreeMap<String, String> {
    let mut reasons = BTreeMap::new();
    reasons.insert(
        "live_monero_headers".to_string(),
        "live Monero header and finality feeds must match replay roots before release".to_string(),
    );
    reasons.insert(
        "deposit_lock_observation".to_string(),
        "deposit lock observations must match wallet-visible and operator evidence roots"
            .to_string(),
    );
    reasons.insert(
        "pq_watcher_quorum".to_string(),
        "PQ watcher quorum observations must meet threshold and signature-domain requirements"
            .to_string(),
    );
    reasons.insert(
        "reserve_liquidity".to_string(),
        "reserve and liquidity feeds must prove release capacity before forced-exit settlement"
            .to_string(),
    );
    reasons.insert(
        "privacy_surface".to_string(),
        "live feed exports must not add wallet-linkable metadata".to_string(),
    );
    for record in records {
        if record.status.blocks_release() {
            reasons.insert(
                format!("lane_{}", record.lane.as_str()),
                format!(
                    "{} remains {} with {} blockers",
                    record.lane.label(),
                    record.status.as_str(),
                    record.release_blockers
                ),
            );
        }
    }
    reasons
}

fn hold_root(reasons: &BTreeMap<String, String>) -> String {
    let leaves = reasons
        .iter()
        .map(|(key, value)| json!({ "key": key, "value": value }))
        .collect::<Vec<_>>();
    merkle_root("monero-l2-pq-bridge-exit-live-feed-release-holds", &leaves)
}

fn manifest_id(config: &Config, roots: &LiveFeedRoots) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-live-feed-manifest-id",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(config.l2_reference_height),
            HashPart::U64(config.monero_reference_height),
            HashPart::Str(&roots.requirement_root),
            HashPart::Str(&roots.observation_root),
            HashPart::Str(&roots.source_root),
            HashPart::Str(&roots.mismatch_root),
            HashPart::Str(&roots.release_hold_root),
        ],
        16,
    )
}
