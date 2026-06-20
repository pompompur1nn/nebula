use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSlicePqWatcherQuorumLiveFeedObservationRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_WATCHER_QUORUM_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-watcher-quorum-live-feed-observation-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_PQ_WATCHER_QUORUM_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const OBSERVATION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-pq-watcher-quorum-live-feed-observation-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_FEED_EPOCH: u64 = 144;
pub const DEFAULT_SOURCE_HEIGHT: u64 = 2_771_440;
pub const DEFAULT_L2_HEIGHT: u64 = 884_224;
pub const DEFAULT_MAX_OBSERVER_LAG_BLOCKS: u64 = 2;
pub const DEFAULT_MAX_SOURCE_LAG_BLOCKS: u64 = 4;
pub const DEFAULT_MIN_RELEASE_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_EMERGENCY_WEIGHT_BPS: u16 = 8_500;
pub const DEFAULT_MIN_WATCHER_COUNT: u16 = 5;
pub const DEFAULT_MAX_COLLUSION_CLUSTER_BPS: u16 = 3_400;
pub const DEFAULT_MAX_STALE_WATCHERS: u16 = 1;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const MAX_BPS: u16 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PqSignatureScheme {
    MlDsa87,
    SlhDsaShake256f,
    HybridMlDsaSlhDsaShake,
}

impl PqSignatureScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MlDsa87 => "ml_dsa_87",
            Self::SlhDsaShake256f => "slh_dsa_shake_256f",
            Self::HybridMlDsaSlhDsaShake => "hybrid_ml_dsa_slh_dsa_shake",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedLaneKind {
    MoneroHeaders,
    DepositLocks,
    ForcedExitClaims,
    SettlementReceipts,
    ReserveProofs,
    ChallengeWindows,
}

impl FeedLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaders => "monero_headers",
            Self::DepositLocks => "deposit_locks",
            Self::ForcedExitClaims => "forced_exit_claims",
            Self::SettlementReceipts => "settlement_receipts",
            Self::ReserveProofs => "reserve_proofs",
            Self::ChallengeWindows => "challenge_windows",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Accepted,
    Stale,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Stale => "stale",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Accepted)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    StaleWatcher,
    MissingWatcher,
    ColludingCluster,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleWatcher => "stale_watcher",
            Self::MissingWatcher => "missing_watcher",
            Self::ColludingCluster => "colluding_cluster",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldKind {
    ThresholdShortfall,
    LiveFeedMismatch,
    CollusionSuspected,
}

impl ReleaseHoldKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ThresholdShortfall => "threshold_shortfall",
            Self::LiveFeedMismatch => "live_feed_mismatch",
            Self::CollusionSuspected => "collusion_suspected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub observation_suite: String,
    pub vertical_slice_id: String,
    pub feed_epoch: u64,
    pub source_height: u64,
    pub l2_height: u64,
    pub max_observer_lag_blocks: u64,
    pub max_source_lag_blocks: u64,
    pub min_release_weight_bps: u16,
    pub min_emergency_weight_bps: u16,
    pub min_watcher_count: u16,
    pub max_collusion_cluster_bps: u16,
    pub max_stale_watchers: u16,
    pub min_pq_security_bits: u16,
    pub fail_closed_on_mismatch: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            observation_suite: OBSERVATION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            feed_epoch: DEFAULT_FEED_EPOCH,
            source_height: DEFAULT_SOURCE_HEIGHT,
            l2_height: DEFAULT_L2_HEIGHT,
            max_observer_lag_blocks: DEFAULT_MAX_OBSERVER_LAG_BLOCKS,
            max_source_lag_blocks: DEFAULT_MAX_SOURCE_LAG_BLOCKS,
            min_release_weight_bps: DEFAULT_MIN_RELEASE_WEIGHT_BPS,
            min_emergency_weight_bps: DEFAULT_MIN_EMERGENCY_WEIGHT_BPS,
            min_watcher_count: DEFAULT_MIN_WATCHER_COUNT,
            max_collusion_cluster_bps: DEFAULT_MAX_COLLUSION_CLUSTER_BPS,
            max_stale_watchers: DEFAULT_MAX_STALE_WATCHERS,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            fail_closed_on_mismatch: true,
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
            "feed_epoch": self.feed_epoch,
            "source_height": self.source_height,
            "l2_height": self.l2_height,
            "max_observer_lag_blocks": self.max_observer_lag_blocks,
            "max_source_lag_blocks": self.max_source_lag_blocks,
            "min_release_weight_bps": self.min_release_weight_bps,
            "min_emergency_weight_bps": self.min_emergency_weight_bps,
            "min_watcher_count": self.min_watcher_count,
            "max_collusion_cluster_bps": self.max_collusion_cluster_bps,
            "max_stale_watchers": self.max_stale_watchers,
            "min_pq_security_bits": self.min_pq_security_bits,
            "fail_closed_on_mismatch": self.fail_closed_on_mismatch,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqSignatureDomain {
    pub domain_id: String,
    pub scheme: PqSignatureScheme,
    pub label: String,
    pub feed_lane: FeedLaneKind,
    pub epoch: u64,
    pub pq_security_bits: u16,
    pub transcript_root: String,
    pub domain_root: String,
}

impl PqSignatureDomain {
    pub fn new(
        scheme: PqSignatureScheme,
        feed_lane: FeedLaneKind,
        epoch: u64,
        pq_security_bits: u16,
        transcript_root: impl Into<String>,
    ) -> Self {
        let transcript_root = transcript_root.into();
        let label = format!(
            "{}:{}:{}:v1",
            OBSERVATION_SUITE,
            feed_lane.as_str(),
            scheme.as_str()
        );
        let domain_root = domain_hash(
            "MONERO-L2-PQ-WATCHER-LIVE-FEED-SIGNATURE-DOMAIN",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&label),
                HashPart::Str(feed_lane.as_str()),
                HashPart::Str(scheme.as_str()),
                HashPart::Int(epoch as i128),
                HashPart::Int(pq_security_bits as i128),
                HashPart::Str(&transcript_root),
            ],
            32,
        );
        let domain_id = domain_hash(
            "MONERO-L2-PQ-WATCHER-LIVE-FEED-SIGNATURE-DOMAIN-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&domain_root),
            ],
            32,
        );
        Self {
            domain_id,
            scheme,
            label,
            feed_lane,
            epoch,
            pq_security_bits,
            transcript_root,
            domain_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.domain_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherObservation {
    pub observation_id: String,
    pub watcher_id: String,
    pub operator_cluster_id: String,
    pub feed_lane: FeedLaneKind,
    pub status: ObservationStatus,
    pub weight_bps: u16,
    pub source_height: u64,
    pub observed_l2_height: u64,
    pub feed_epoch: u64,
    pub live_feed_root: String,
    pub canonical_expected_root: String,
    pub pq_domain_id: String,
    pub pq_signature_commitment: String,
    pub attestation_root: String,
}

impl WatcherObservation {
    pub fn new(
        watcher_id: impl Into<String>,
        operator_cluster_id: impl Into<String>,
        feed_lane: FeedLaneKind,
        status: ObservationStatus,
        weight_bps: u16,
        heights: ObservationHeights,
        roots: ObservationRoots,
        pq_domain_id: impl Into<String>,
        pq_signature_commitment: impl Into<String>,
    ) -> Self {
        let watcher_id = watcher_id.into();
        let operator_cluster_id = operator_cluster_id.into();
        let pq_domain_id = pq_domain_id.into();
        let pq_signature_commitment = pq_signature_commitment.into();
        let attestation_root = watcher_attestation_root(
            &watcher_id,
            &operator_cluster_id,
            feed_lane,
            status,
            weight_bps,
            &heights,
            &roots,
            &pq_domain_id,
            &pq_signature_commitment,
        );
        let observation_id = domain_hash(
            "MONERO-L2-PQ-WATCHER-LIVE-FEED-OBSERVATION-ID",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&watcher_id),
                HashPart::Str(feed_lane.as_str()),
                HashPart::Str(&attestation_root),
            ],
            32,
        );
        Self {
            observation_id,
            watcher_id,
            operator_cluster_id,
            feed_lane,
            status,
            weight_bps,
            source_height: heights.source_height,
            observed_l2_height: heights.observed_l2_height,
            feed_epoch: heights.feed_epoch,
            live_feed_root: roots.live_feed_root,
            canonical_expected_root: roots.canonical_expected_root,
            pq_domain_id,
            pq_signature_commitment,
            attestation_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.attestation_root.clone()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct ObservationHeights {
    pub source_height: u64,
    pub observed_l2_height: u64,
    pub feed_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ObservationRoots {
    pub live_feed_root: String,
    pub canonical_expected_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QuorumThreshold {
    pub lane: FeedLaneKind,
    pub required_weight_bps: u16,
    pub observed_weight_bps: u16,
    pub required_watcher_count: u16,
    pub observed_watcher_count: u16,
    pub threshold_met: bool,
    pub threshold_root: String,
}

impl QuorumThreshold {
    pub fn evaluate(
        lane: FeedLaneKind,
        config: &Config,
        observations: &[WatcherObservation],
    ) -> Self {
        let mut observed_weight_bps = 0u16;
        let mut observed_watcher_count = 0u16;
        for observation in observations {
            if observation.feed_lane == lane && observation.status.counts_for_quorum() {
                observed_weight_bps = observed_weight_bps.saturating_add(observation.weight_bps);
                observed_watcher_count = observed_watcher_count.saturating_add(1);
            }
        }
        let required_weight_bps = match lane {
            FeedLaneKind::ChallengeWindows | FeedLaneKind::SettlementReceipts => {
                config.min_emergency_weight_bps
            }
            _ => config.min_release_weight_bps,
        };
        let required_watcher_count = config.min_watcher_count;
        let threshold_met = observed_weight_bps >= required_weight_bps
            && observed_watcher_count >= required_watcher_count;
        let threshold_root = domain_hash(
            "MONERO-L2-PQ-WATCHER-LIVE-FEED-THRESHOLD",
            &[
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane.as_str()),
                HashPart::Int(required_weight_bps as i128),
                HashPart::Int(observed_weight_bps as i128),
                HashPart::Int(required_watcher_count as i128),
                HashPart::Int(observed_watcher_count as i128),
                HashPart::Str(if threshold_met { "met" } else { "not_met" }),
            ],
            32,
        );
        Self {
            lane,
            required_weight_bps,
            observed_weight_bps,
            required_watcher_count,
            observed_watcher_count,
            threshold_met,
            threshold_root,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherEvidence {
    pub evidence_id: String,
    pub kind: EvidenceKind,
    pub watcher_id: String,
    pub feed_lane: FeedLaneKind,
    pub observed_root: String,
    pub expected_root: String,
    pub reporter_watcher_id: String,
    pub evidence_height: u64,
    pub slashing_hint_bps: u16,
    pub release_blocking: bool,
    pub evidence_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CollusionMarker {
    pub marker_id: String,
    pub operator_cluster_id: String,
    pub watcher_ids: Vec<String>,
    pub combined_weight_bps: u16,
    pub max_allowed_weight_bps: u16,
    pub common_observed_root: String,
    pub conflicting_expected_root: String,
    pub release_blocking: bool,
    pub marker_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MismatchRecord {
    pub mismatch_id: String,
    pub feed_lane: FeedLaneKind,
    pub expected_root: String,
    pub observed_root: String,
    pub affected_watchers: Vec<String>,
    pub blocking_reason: ReleaseHoldKind,
    pub release_blocking: bool,
    pub mismatch_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseHold {
    pub hold_id: String,
    pub kind: ReleaseHoldKind,
    pub lane: FeedLaneKind,
    pub severity: String,
    pub condition: String,
    pub evidence_root: String,
    pub clears_when: String,
    pub hold_root: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateRoots {
    pub config_root: String,
    pub signature_domain_root: String,
    pub observation_root: String,
    pub threshold_root: String,
    pub evidence_root: String,
    pub collusion_marker_root: String,
    pub mismatch_root: String,
    pub release_hold_root: String,
}

impl StateRoots {}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub signature_domains: Vec<PqSignatureDomain>,
    pub observations: Vec<WatcherObservation>,
    pub thresholds: Vec<QuorumThreshold>,
    pub evidence: Vec<WatcherEvidence>,
    pub collusion_markers: Vec<CollusionMarker>,
    pub mismatches: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>,
    pub watcher_weights: BTreeMap<String, u16>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let canonical_header_root = record_root(
            "DEVNET-CANONICAL-MONERO-HEADER",
            &json!({
                "height": config.source_height,
                "hash": "9d4d3cb8f5dbe7c214e6c3a64f80e6427f9f2733f3bfabae4b8ce2aa0f8f91d1",
                "finality_confirmations": 24,
            }),
        );
        let stale_header_root = record_root(
            "DEVNET-STALE-MONERO-HEADER",
            &json!({
                "height": config.source_height.saturating_sub(6),
                "hash": "5f06f6a462bc41fd55ac5520f6cbe62425a7dbfe20184f9261629eb1efd65210",
                "finality_confirmations": 18,
            }),
        );
        let reserve_root = record_root(
            "DEVNET-RESERVE-PROOF",
            &json!({
                "vault_epoch": config.feed_epoch,
                "reserve_commitment": "reserve-proof-devnet-root-144",
                "liquidity_floor_met": true,
            }),
        );
        let claim_root = record_root(
            "DEVNET-FORCED-EXIT-CLAIM",
            &json!({
                "claim_batch": "forced-exit-claim-batch-devnet-009",
                "challenge_window_open": true,
                "canonical_exit_spine": config.vertical_slice_id,
            }),
        );

        let signature_domains = vec![
            PqSignatureDomain::new(
                PqSignatureScheme::MlDsa87,
                FeedLaneKind::MoneroHeaders,
                config.feed_epoch,
                config.min_pq_security_bits,
                &canonical_header_root,
            ),
            PqSignatureDomain::new(
                PqSignatureScheme::SlhDsaShake256f,
                FeedLaneKind::ReserveProofs,
                config.feed_epoch,
                config.min_pq_security_bits,
                &reserve_root,
            ),
            PqSignatureDomain::new(
                PqSignatureScheme::HybridMlDsaSlhDsaShake,
                FeedLaneKind::ForcedExitClaims,
                config.feed_epoch,
                config.min_pq_security_bits,
                &claim_root,
            ),
        ];

        let header_domain_id = signature_domains[0].domain_id.clone();
        let reserve_domain_id = signature_domains[1].domain_id.clone();
        let header_heights = ObservationHeights {
            source_height: config.source_height,
            observed_l2_height: config.l2_height,
            feed_epoch: config.feed_epoch,
        };
        let stale_heights = ObservationHeights {
            source_height: config.source_height.saturating_sub(6),
            observed_l2_height: config.l2_height.saturating_sub(3),
            feed_epoch: config.feed_epoch,
        };
        let header_roots = ObservationRoots {
            live_feed_root: canonical_header_root.clone(),
            canonical_expected_root: canonical_header_root.clone(),
        };
        let stale_roots = ObservationRoots {
            live_feed_root: stale_header_root.clone(),
            canonical_expected_root: canonical_header_root.clone(),
        };
        let reserve_roots = ObservationRoots {
            live_feed_root: reserve_root.clone(),
            canonical_expected_root: reserve_root.clone(),
        };
        let observations = vec![
            WatcherObservation::new(
                "watcher-alpha",
                "cluster-north",
                FeedLaneKind::MoneroHeaders,
                ObservationStatus::Accepted,
                1_900,
                header_heights,
                header_roots.clone(),
                &header_domain_id,
                "pq-sig-commitment-alpha-header-144",
            ),
            WatcherObservation::new(
                "watcher-beta",
                "cluster-east",
                FeedLaneKind::MoneroHeaders,
                ObservationStatus::Accepted,
                1_800,
                header_heights,
                header_roots.clone(),
                &header_domain_id,
                "pq-sig-commitment-beta-header-144",
            ),
            WatcherObservation::new(
                "watcher-gamma",
                "cluster-west",
                FeedLaneKind::MoneroHeaders,
                ObservationStatus::Accepted,
                1_700,
                header_heights,
                header_roots.clone(),
                &header_domain_id,
                "pq-sig-commitment-gamma-header-144",
            ),
            WatcherObservation::new(
                "watcher-delta",
                "cluster-south",
                FeedLaneKind::MoneroHeaders,
                ObservationStatus::Accepted,
                1_600,
                header_heights,
                header_roots,
                &header_domain_id,
                "pq-sig-commitment-delta-header-144",
            ),
            WatcherObservation::new(
                "watcher-epsilon",
                "cluster-east",
                FeedLaneKind::MoneroHeaders,
                ObservationStatus::Stale,
                1_100,
                stale_heights,
                stale_roots,
                &header_domain_id,
                "pq-sig-commitment-epsilon-stale-header-144",
            ),
            WatcherObservation::new(
                "watcher-alpha",
                "cluster-north",
                FeedLaneKind::ReserveProofs,
                ObservationStatus::Accepted,
                1_900,
                header_heights,
                reserve_roots,
                &reserve_domain_id,
                "pq-sig-commitment-alpha-reserve-144",
            ),
        ];

        let thresholds = vec![
            QuorumThreshold::evaluate(FeedLaneKind::MoneroHeaders, &config, &observations),
            QuorumThreshold::evaluate(FeedLaneKind::ReserveProofs, &config, &observations),
            QuorumThreshold::evaluate(FeedLaneKind::ForcedExitClaims, &config, &observations),
        ];

        let stale_evidence_root = record_root(
            "DEVNET-STALE-WATCHER-EVIDENCE",
            &json!({"watcher": "watcher-epsilon", "observed": stale_header_root, "expected": canonical_header_root}),
        );
        let missing_evidence_root = record_root(
            "DEVNET-MISSING-WATCHER-EVIDENCE",
            &json!({"watcher": "watcher-zeta", "lane": FeedLaneKind::SettlementReceipts.as_str()}),
        );
        let evidence = vec![
            WatcherEvidence {
                evidence_id: record_id("EVIDENCE-ID", &stale_evidence_root),
                kind: EvidenceKind::StaleWatcher,
                watcher_id: "watcher-epsilon".to_string(),
                feed_lane: FeedLaneKind::MoneroHeaders,
                observed_root: stale_header_root.clone(),
                expected_root: canonical_header_root.clone(),
                reporter_watcher_id: "watcher-alpha".to_string(),
                evidence_height: config.l2_height,
                slashing_hint_bps: 500,
                release_blocking: true,
                evidence_root: stale_evidence_root,
            },
            WatcherEvidence {
                evidence_id: record_id("EVIDENCE-ID", &missing_evidence_root),
                kind: EvidenceKind::MissingWatcher,
                watcher_id: "watcher-zeta".to_string(),
                feed_lane: FeedLaneKind::SettlementReceipts,
                observed_root: "missing".to_string(),
                expected_root: "settlement-receipt-root-required".to_string(),
                reporter_watcher_id: "watcher-beta".to_string(),
                evidence_height: config.l2_height,
                slashing_hint_bps: 250,
                release_blocking: true,
                evidence_root: missing_evidence_root,
            },
        ];

        let collusion_root = record_root(
            "DEVNET-COLLUSION-MARKER",
            &json!({"cluster": "cluster-east", "watchers": ["watcher-beta", "watcher-epsilon"], "combined_weight_bps": 2900}),
        );
        let collusion_markers = vec![CollusionMarker {
            marker_id: record_id("COLLUSION-ID", &collusion_root),
            operator_cluster_id: "cluster-east".to_string(),
            watcher_ids: vec!["watcher-beta".to_string(), "watcher-epsilon".to_string()],
            combined_weight_bps: 2_900,
            max_allowed_weight_bps: config.max_collusion_cluster_bps,
            common_observed_root: stale_header_root.clone(),
            conflicting_expected_root: canonical_header_root.clone(),
            release_blocking: false,
            marker_root: collusion_root,
        }];

        let mismatch_root = record_root(
            "DEVNET-MISMATCH",
            &json!({"lane": FeedLaneKind::MoneroHeaders.as_str(), "expected": canonical_header_root, "observed": stale_header_root}),
        );
        let mismatches = vec![MismatchRecord {
            mismatch_id: record_id("MISMATCH-ID", &mismatch_root),
            feed_lane: FeedLaneKind::MoneroHeaders,
            expected_root: canonical_header_root.clone(),
            observed_root: stale_header_root,
            affected_watchers: vec!["watcher-epsilon".to_string()],
            blocking_reason: ReleaseHoldKind::LiveFeedMismatch,
            release_blocking: true,
            mismatch_root,
        }];

        let mismatch_hold_root = record_root(
            "DEVNET-MISMATCH-HOLD",
            &json!({"evidence": mismatches[0].mismatch_root}),
        );
        let threshold_hold_root = record_root(
            "DEVNET-THRESHOLD-HOLD",
            &json!({"threshold": thresholds[1].threshold_root}),
        );
        let release_holds = vec![
            ReleaseHold {
                hold_id: record_id("RELEASE-HOLD-ID", &mismatch_hold_root),
                kind: ReleaseHoldKind::LiveFeedMismatch,
                lane: FeedLaneKind::MoneroHeaders,
                severity: "release_stop".to_string(),
                condition: "stale watcher reported a header root outside the canonical forced-exit spine".to_string(),
                evidence_root: mismatches[0].mismatch_root.clone(),
                clears_when: "all active watchers attest to the canonical header root in the configured PQ domain".to_string(),
                hold_root: mismatch_hold_root,
            },
            ReleaseHold {
                hold_id: record_id("RELEASE-HOLD-ID", &threshold_hold_root),
                kind: ReleaseHoldKind::ThresholdShortfall,
                lane: FeedLaneKind::ReserveProofs,
                severity: "critical".to_string(),
                condition: "reserve proof lane has a live observation but not enough independent watcher weight".to_string(),
                evidence_root: thresholds[1].threshold_root.clone(),
                clears_when: "reserve proof lane reaches configured release quorum weight and watcher count".to_string(),
                hold_root: threshold_hold_root,
            },
        ];

        let mut watcher_weights = BTreeMap::new();
        for observation in &observations {
            watcher_weights
                .entry(observation.watcher_id.clone())
                .or_insert(observation.weight_bps);
        }

        Self {
            config,
            signature_domains,
            observations,
            thresholds,
            evidence,
            collusion_markers,
            mismatches,
            release_holds,
            watcher_weights,
        }
    }

    pub fn roots(&self) -> StateRoots {
        let signature_domain_leaves = self
            .signature_domains
            .iter()
            .map(PqSignatureDomain::state_root)
            .collect::<Vec<_>>();
        let observation_leaves = self
            .observations
            .iter()
            .map(WatcherObservation::state_root)
            .collect::<Vec<_>>();
        let threshold_leaves = self
            .thresholds
            .iter()
            .map(|threshold| threshold.threshold_root.clone())
            .collect::<Vec<_>>();
        let evidence_leaves = self
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_root.clone())
            .collect::<Vec<_>>();
        let collusion_leaves = self
            .collusion_markers
            .iter()
            .map(|marker| marker.marker_root.clone())
            .collect::<Vec<_>>();
        let mismatch_leaves = self
            .mismatches
            .iter()
            .map(|mismatch| mismatch.mismatch_root.clone())
            .collect::<Vec<_>>();
        let release_hold_leaves = self
            .release_holds
            .iter()
            .map(|hold| hold.hold_root.clone())
            .collect::<Vec<_>>();
        StateRoots {
            config_root: self.config.state_root(),
            signature_domain_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-SIGNATURE-DOMAINS",
                &signature_domain_leaves,
            ),
            observation_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-OBSERVATIONS",
                &observation_leaves,
            ),
            threshold_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-THRESHOLDS",
                &threshold_leaves,
            ),
            evidence_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-EVIDENCE-ROOT",
                &evidence_leaves,
            ),
            collusion_marker_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-COLLUSION-MARKERS",
                &collusion_leaves,
            ),
            mismatch_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-MISMATCHES",
                &mismatch_leaves,
            ),
            release_hold_root: merkle_root(
                "MONERO-L2-PQ-WATCHER-LIVE-FEED-RELEASE-HOLDS",
                &release_hold_leaves,
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "signature_domains": self.signature_domains,
            "observations": self.observations,
            "thresholds": self.thresholds,
            "evidence": self.evidence,
            "collusion_markers": self.collusion_markers,
            "mismatches": self.mismatches,
            "release_holds": self.release_holds,
            "watcher_weights": self.watcher_weights,
            "roots": roots,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-WATCHER-LIVE-FEED-OBSERVATION-STATE",
            &[HashPart::Json(&self.public_record())],
            32,
        )
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

fn watcher_attestation_root(
    watcher_id: &str,
    operator_cluster_id: &str,
    feed_lane: FeedLaneKind,
    status: ObservationStatus,
    weight_bps: u16,
    heights: &ObservationHeights,
    roots: &ObservationRoots,
    pq_domain_id: &str,
    pq_signature_commitment: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-WATCHER-LIVE-FEED-ATTESTATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(operator_cluster_id),
            HashPart::Str(feed_lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Int(weight_bps as i128),
            HashPart::Int(heights.source_height as i128),
            HashPart::Int(heights.observed_l2_height as i128),
            HashPart::Int(heights.feed_epoch as i128),
            HashPart::Str(&roots.live_feed_root),
            HashPart::Str(&roots.canonical_expected_root),
            HashPart::Str(pq_domain_id),
            HashPart::Str(pq_signature_commitment),
        ],
        32,
    )
}

fn record_root(domain: &str, value: &Value) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-WATCHER-LIVE-FEED-{domain}"),
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

fn record_id(domain: &str, root: &str) -> String {
    domain_hash(
        &format!("MONERO-L2-PQ-WATCHER-LIVE-FEED-{domain}"),
        &[HashPart::Str(PROTOCOL_VERSION), HashPart::Str(root)],
        32,
    )
}
