use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
#[rustfmt::skip]
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceMoneroHeaderLiveFeedObservationRuntimeResult<T> = Result<T>;
pub type Runtime = State;

#[rustfmt::skip]
pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_HEADER_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION: &str = "monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-header-live-feed-observation-runtime/v1";
#[rustfmt::skip]
pub const PROTOCOL_VERSION: &str = MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_MONERO_HEADER_LIVE_FEED_OBSERVATION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: &str =
    "2026-06-19.forced-exit.vertical-slice.monero-header-live-feed-observation.v1";
pub const HASH_SUITE: &str = "nebula-l2-devnet-shake256-32/domain-separated-json-merkle-v1";

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-monero-header-live-feed-observation-runtime";

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String, pub protocol_version: String, pub schema_version: String, pub hash_suite: String,
    pub monero_network: String, pub bridge_id: String, pub forced_exit_spine_id: String,
    pub min_finality_depth_blocks: u64, pub warning_finality_depth_blocks: u64, pub max_reorg_window_blocks: u64,
    pub stale_feed_threshold_blocks: u64, pub stale_feed_threshold_seconds: u64,
    pub watcher_quorum: u64, pub watcher_supermajority: u64,
    pub release_hold_required_on_stale_feed: bool, pub release_hold_required_on_reorg_risk: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
            hash_suite: HASH_SUITE.to_string(),
            monero_network: "monero-devnet-regtest".to_string(),
            bridge_id: "xmr-pq-canonical-forced-exit-bridge".to_string(),
            forced_exit_spine_id: "forced-exit-canonical-vertical-slice-spine-v1".to_string(),
            min_finality_depth_blocks: 20,
            warning_finality_depth_blocks: 32,
            max_reorg_window_blocks: 64,
            stale_feed_threshold_blocks: 3,
            stale_feed_threshold_seconds: 360,
            watcher_quorum: 5,
            watcher_supermajority: 4,
            release_hold_required_on_stale_feed: true,
            release_hold_required_on_reorg_risk: true,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "bridge_id": self.bridge_id, "chain_id": self.chain_id, "forced_exit_spine_id": self.forced_exit_spine_id,
            "hash_suite": self.hash_suite, "max_reorg_window_blocks": self.max_reorg_window_blocks,
            "min_finality_depth_blocks": self.min_finality_depth_blocks, "monero_network": self.monero_network,
            "protocol_version": self.protocol_version, "release_hold_required_on_reorg_risk": self.release_hold_required_on_reorg_risk,
            "release_hold_required_on_stale_feed": self.release_hold_required_on_stale_feed, "schema_version": self.schema_version,
            "stale_feed_threshold_blocks": self.stale_feed_threshold_blocks, "stale_feed_threshold_seconds": self.stale_feed_threshold_seconds,
            "warning_finality_depth_blocks": self.warning_finality_depth_blocks, "watcher_quorum": self.watcher_quorum,
            "watcher_supermajority": self.watcher_supermajority,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus { Accepted, Warning, Held, Rejected }

impl ObservationStatus {
    #[rustfmt::skip]
    pub fn as_str(self) -> &'static str {
        match self { Self::Accepted => "accepted", Self::Warning => "warning", Self::Held => "held", Self::Rejected => "rejected" }
    }
}

#[rustfmt::skip]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHoldKind { None, StaleFeed, ReorgRisk, WatcherMismatch, ExpectedRootMismatch }

impl ReleaseHoldKind {
    #[rustfmt::skip]
    pub fn as_str(self) -> &'static str {
        match self { Self::None => "none", Self::StaleFeed => "stale_feed", Self::ReorgRisk => "reorg_risk", Self::WatcherMismatch => "watcher_mismatch", Self::ExpectedRootMismatch => "expected_root_mismatch" }
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MoneroHeaderObservation {
    pub observation_id: String, pub sequence: u64, pub source: String, pub height: u64,
    pub timestamp_seconds: u64, pub observed_at_l2_height: u64,
    pub block_hash: String, pub previous_block_hash: String, pub merkle_root: String, pub pow_hash: String,
    pub cumulative_difficulty: u128, pub nonce: u64, pub tx_count: u64,
    pub miner_tx_hash: String, pub raw_header_commitment: String, pub status: ObservationStatus,
}

impl MoneroHeaderObservation {
    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "block_hash": self.block_hash, "cumulative_difficulty": self.cumulative_difficulty.to_string(),
            "height": self.height, "merkle_root": self.merkle_root, "miner_tx_hash": self.miner_tx_hash,
            "nonce": self.nonce, "observation_id": self.observation_id, "observed_at_l2_height": self.observed_at_l2_height,
            "pow_hash": self.pow_hash, "previous_block_hash": self.previous_block_hash, "raw_header_commitment": self.raw_header_commitment,
            "sequence": self.sequence, "source": self.source, "status": self.status.as_str(),
            "timestamp_seconds": self.timestamp_seconds, "tx_count": self.tx_count,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FinalityWindow {
    pub window_id: String, pub anchor_height: u64, pub finalized_height: u64, pub observed_tip_height: u64,
    pub depth_blocks: u64, pub min_required_depth_blocks: u64, pub warning_depth_blocks: u64,
    pub finalized_block_hash: String, pub tip_block_hash: String,
    pub safe_for_forced_exit_release: bool, pub status: ObservationStatus,
}

impl FinalityWindow {
    pub fn new(
        config: &Config,
        anchor_height: u64,
        observed_tip_height: u64,
        finalized_block_hash: &str,
        tip_block_hash: &str,
    ) -> Self {
        let depth_blocks = observed_tip_height.saturating_sub(anchor_height);
        let finalized_height = anchor_height;
        let safe_for_forced_exit_release = depth_blocks >= config.min_finality_depth_blocks;
        let status = if safe_for_forced_exit_release {
            ObservationStatus::Accepted
        } else if depth_blocks >= config.warning_finality_depth_blocks {
            ObservationStatus::Warning
        } else {
            ObservationStatus::Held
        };
        let window_id = domain_hash(
            &domain("finality-window-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(anchor_height),
                HashPart::U64(observed_tip_height),
                HashPart::Str(finalized_block_hash),
                HashPart::Str(tip_block_hash),
            ],
            32,
        );

        Self {
            window_id,
            anchor_height,
            finalized_height,
            observed_tip_height,
            depth_blocks,
            min_required_depth_blocks: config.min_finality_depth_blocks,
            warning_depth_blocks: config.warning_finality_depth_blocks,
            finalized_block_hash: finalized_block_hash.to_string(),
            tip_block_hash: tip_block_hash.to_string(),
            safe_for_forced_exit_release,
            status,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "anchor_height": self.anchor_height, "depth_blocks": self.depth_blocks, "finalized_block_hash": self.finalized_block_hash,
            "finalized_height": self.finalized_height, "min_required_depth_blocks": self.min_required_depth_blocks,
            "observed_tip_height": self.observed_tip_height, "safe_for_forced_exit_release": self.safe_for_forced_exit_release,
            "status": self.status.as_str(), "tip_block_hash": self.tip_block_hash,
            "warning_depth_blocks": self.warning_depth_blocks, "window_id": self.window_id,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StaleFeedEvidence {
    pub evidence_id: String, pub feed_id: String, pub last_observed_height: u64, pub current_monero_height: u64,
    pub last_observed_timestamp_seconds: u64, pub checked_at_timestamp_seconds: u64,
    pub lag_blocks: u64, pub lag_seconds: u64, pub threshold_blocks: u64, pub threshold_seconds: u64,
    pub stale: bool, pub release_hold: ReleaseHoldKind,
}

impl StaleFeedEvidence {
    pub fn new(
        config: &Config,
        feed_id: &str,
        last_observed_height: u64,
        current_monero_height: u64,
        last_observed_timestamp_seconds: u64,
        checked_at_timestamp_seconds: u64,
    ) -> Self {
        let lag_blocks = current_monero_height.saturating_sub(last_observed_height);
        let lag_seconds =
            checked_at_timestamp_seconds.saturating_sub(last_observed_timestamp_seconds);
        let stale = lag_blocks > config.stale_feed_threshold_blocks
            || lag_seconds > config.stale_feed_threshold_seconds;
        let release_hold = if stale && config.release_hold_required_on_stale_feed {
            ReleaseHoldKind::StaleFeed
        } else {
            ReleaseHoldKind::None
        };
        let evidence_id = domain_hash(
            &domain("stale-feed-evidence-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(feed_id),
                HashPart::U64(last_observed_height),
                HashPart::U64(current_monero_height),
                HashPart::U64(lag_blocks),
                HashPart::U64(lag_seconds),
                HashPart::Str(release_hold.as_str()),
            ],
            32,
        );

        Self {
            evidence_id,
            feed_id: feed_id.to_string(),
            last_observed_height,
            current_monero_height,
            last_observed_timestamp_seconds,
            checked_at_timestamp_seconds,
            lag_blocks,
            lag_seconds,
            threshold_blocks: config.stale_feed_threshold_blocks,
            threshold_seconds: config.stale_feed_threshold_seconds,
            stale,
            release_hold,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "checked_at_timestamp_seconds": self.checked_at_timestamp_seconds, "current_monero_height": self.current_monero_height,
            "evidence_id": self.evidence_id, "feed_id": self.feed_id, "lag_blocks": self.lag_blocks, "lag_seconds": self.lag_seconds,
            "last_observed_height": self.last_observed_height, "last_observed_timestamp_seconds": self.last_observed_timestamp_seconds,
            "release_hold": self.release_hold.as_str(), "stale": self.stale, "threshold_blocks": self.threshold_blocks,
            "threshold_seconds": self.threshold_seconds,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReorgRiskRecord {
    pub risk_id: String, pub competing_height: u64, pub canonical_hash: String, pub competing_hash: String,
    pub divergence_depth_blocks: u64, pub max_reorg_window_blocks: u64,
    pub affected_exit_ids: Vec<String>, pub risk_level: String, pub release_hold: ReleaseHoldKind,
}

impl ReorgRiskRecord {
    pub fn new(
        config: &Config,
        competing_height: u64,
        canonical_tip_height: u64,
        canonical_hash: &str,
        competing_hash: &str,
        affected_exit_ids: Vec<&str>,
    ) -> Self {
        let divergence_depth_blocks = canonical_tip_height.saturating_sub(competing_height);
        let risk_level = if divergence_depth_blocks <= config.min_finality_depth_blocks {
            "critical"
        } else if divergence_depth_blocks <= config.max_reorg_window_blocks {
            "watch"
        } else {
            "archival"
        }
        .to_string();
        let release_hold = if risk_level != "archival" && config.release_hold_required_on_reorg_risk
        {
            ReleaseHoldKind::ReorgRisk
        } else {
            ReleaseHoldKind::None
        };
        let affected_exit_ids = affected_exit_ids
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let affected_root = string_root("affected-exits", &affected_exit_ids);
        let risk_id = domain_hash(
            &domain("reorg-risk-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(competing_height),
                HashPart::U64(canonical_tip_height),
                HashPart::Str(canonical_hash),
                HashPart::Str(competing_hash),
                HashPart::U64(divergence_depth_blocks),
                HashPart::Str(&affected_root),
                HashPart::Str(release_hold.as_str()),
            ],
            32,
        );

        Self {
            risk_id,
            competing_height,
            canonical_hash: canonical_hash.to_string(),
            competing_hash: competing_hash.to_string(),
            divergence_depth_blocks,
            max_reorg_window_blocks: config.max_reorg_window_blocks,
            affected_exit_ids,
            risk_level,
            release_hold,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "affected_exit_ids": self.affected_exit_ids, "canonical_hash": self.canonical_hash,
            "competing_hash": self.competing_hash, "competing_height": self.competing_height,
            "divergence_depth_blocks": self.divergence_depth_blocks, "max_reorg_window_blocks": self.max_reorg_window_blocks,
            "release_hold": self.release_hold.as_str(), "risk_id": self.risk_id, "risk_level": self.risk_level,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WatcherCrossCheck {
    pub cross_check_id: String, pub watcher_id: String, pub observed_height: u64,
    pub observed_hash: String, pub observed_tip_hash: String, pub signed_root: String,
    pub agrees_with_canonical: bool, pub latency_blocks: u64, pub status: ObservationStatus,
}

impl WatcherCrossCheck {
    pub fn new(
        watcher_id: &str,
        observed_height: u64,
        observed_hash: &str,
        observed_tip_hash: &str,
        canonical_hash: &str,
        canonical_tip_height: u64,
    ) -> Self {
        let agrees_with_canonical = observed_hash == canonical_hash;
        let latency_blocks = canonical_tip_height.saturating_sub(observed_height);
        let status = if agrees_with_canonical && latency_blocks <= 2 {
            ObservationStatus::Accepted
        } else if agrees_with_canonical {
            ObservationStatus::Warning
        } else {
            ObservationStatus::Held
        };
        let signed_root = domain_hash(
            &domain("watcher-signed-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(watcher_id),
                HashPart::U64(observed_height),
                HashPart::Str(observed_hash),
                HashPart::Str(observed_tip_hash),
                HashPart::U64(latency_blocks),
                HashPart::Str(status.as_str()),
            ],
            32,
        );
        let cross_check_id = domain_hash(
            &domain("watcher-cross-check-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(watcher_id),
                HashPart::Str(&signed_root),
            ],
            32,
        );

        Self {
            cross_check_id,
            watcher_id: watcher_id.to_string(),
            observed_height,
            observed_hash: observed_hash.to_string(),
            observed_tip_hash: observed_tip_hash.to_string(),
            signed_root,
            agrees_with_canonical,
            latency_blocks,
            status,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "agrees_with_canonical": self.agrees_with_canonical, "cross_check_id": self.cross_check_id,
            "latency_blocks": self.latency_blocks, "observed_hash": self.observed_hash, "observed_height": self.observed_height,
            "observed_tip_hash": self.observed_tip_hash, "signed_root": self.signed_root,
            "status": self.status.as_str(), "watcher_id": self.watcher_id,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MismatchRecord {
    pub mismatch_id: String, pub lane: String, pub expected_root: String, pub observed_root: String,
    pub first_seen_l2_height: u64, pub last_seen_l2_height: u64,
    pub release_hold: ReleaseHoldKind, pub evidence_root: String,
}

impl MismatchRecord {
    pub fn new(
        lane: &str,
        expected_root: &str,
        observed_root: &str,
        first_seen_l2_height: u64,
        last_seen_l2_height: u64,
        evidence_records: &[Value],
    ) -> Self {
        let evidence_root = merkle_root(&domain("mismatch-evidence"), evidence_records);
        let release_hold = if expected_root == observed_root {
            ReleaseHoldKind::None
        } else {
            ReleaseHoldKind::ExpectedRootMismatch
        };
        let mismatch_id = domain_hash(
            &domain("mismatch-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(lane),
                HashPart::Str(expected_root),
                HashPart::Str(observed_root),
                HashPart::U64(first_seen_l2_height),
                HashPart::U64(last_seen_l2_height),
                HashPart::Str(&evidence_root),
                HashPart::Str(release_hold.as_str()),
            ],
            32,
        );

        Self {
            mismatch_id,
            lane: lane.to_string(),
            expected_root: expected_root.to_string(),
            observed_root: observed_root.to_string(),
            first_seen_l2_height,
            last_seen_l2_height,
            release_hold,
            evidence_root,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_root": self.evidence_root, "expected_root": self.expected_root,
            "first_seen_l2_height": self.first_seen_l2_height, "lane": self.lane,
            "last_seen_l2_height": self.last_seen_l2_height, "mismatch_id": self.mismatch_id,
            "observed_root": self.observed_root, "release_hold": self.release_hold.as_str(),
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReleaseHold {
    pub hold_id: String, pub hold_kind: ReleaseHoldKind, pub reason: String,
    pub opened_at_l2_height: u64, pub observed_monero_height: u64, pub blocking_root: String,
    pub can_auto_release_after_height: u64, pub operator_action: String,
}

impl ReleaseHold {
    pub fn new(
        hold_kind: ReleaseHoldKind,
        reason: &str,
        opened_at_l2_height: u64,
        observed_monero_height: u64,
        blocking_root: &str,
        can_auto_release_after_height: u64,
        operator_action: &str,
    ) -> Self {
        let hold_id = domain_hash(
            &domain("release-hold-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(hold_kind.as_str()),
                HashPart::Str(reason),
                HashPart::U64(opened_at_l2_height),
                HashPart::U64(observed_monero_height),
                HashPart::Str(blocking_root),
                HashPart::U64(can_auto_release_after_height),
            ],
            32,
        );

        Self {
            hold_id,
            hold_kind,
            reason: reason.to_string(),
            opened_at_l2_height,
            observed_monero_height,
            blocking_root: blocking_root.to_string(),
            can_auto_release_after_height,
            operator_action: operator_action.to_string(),
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "blocking_root": self.blocking_root, "can_auto_release_after_height": self.can_auto_release_after_height,
            "hold_id": self.hold_id, "hold_kind": self.hold_kind.as_str(), "observed_monero_height": self.observed_monero_height,
            "opened_at_l2_height": self.opened_at_l2_height, "operator_action": self.operator_action, "reason": self.reason,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedRoots {
    pub header_observation_root: String, pub finality_window_root: String, pub stale_feed_evidence_root: String,
    pub reorg_risk_root: String, pub watcher_cross_check_root: String,
    pub mismatch_root: String, pub release_hold_root: String, pub aggregate_expected_root: String,
}

impl ExpectedRoots {
    pub fn from_state_parts(
        header_observation_root: String,
        finality_window_root: String,
        stale_feed_evidence_root: String,
        reorg_risk_root: String,
        watcher_cross_check_root: String,
        mismatch_root: String,
        release_hold_root: String,
    ) -> Self {
        let aggregate_expected_root = domain_hash(
            &domain("aggregate-expected-root"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&header_observation_root),
                HashPart::Str(&finality_window_root),
                HashPart::Str(&stale_feed_evidence_root),
                HashPart::Str(&reorg_risk_root),
                HashPart::Str(&watcher_cross_check_root),
                HashPart::Str(&mismatch_root),
                HashPart::Str(&release_hold_root),
            ],
            32,
        );

        Self {
            header_observation_root,
            finality_window_root,
            stale_feed_evidence_root,
            reorg_risk_root,
            watcher_cross_check_root,
            mismatch_root,
            release_hold_root,
            aggregate_expected_root,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "aggregate_expected_root": self.aggregate_expected_root, "finality_window_root": self.finality_window_root,
            "header_observation_root": self.header_observation_root, "mismatch_root": self.mismatch_root,
            "release_hold_root": self.release_hold_root, "reorg_risk_root": self.reorg_risk_root,
            "stale_feed_evidence_root": self.stale_feed_evidence_root, "watcher_cross_check_root": self.watcher_cross_check_root,
        })
    }
}

#[rustfmt::skip]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub config: Config, pub runtime_id: String, pub observation_epoch: u64,
    pub l2_observation_height: u64, pub monero_tip_height: u64, pub canonical_tip_hash: String,
    pub headers: Vec<MoneroHeaderObservation>, pub finality_windows: Vec<FinalityWindow>,
    pub stale_feed_evidence: Vec<StaleFeedEvidence>, pub reorg_risks: Vec<ReorgRiskRecord>,
    pub watcher_cross_checks: Vec<WatcherCrossCheck>, pub mismatches: Vec<MismatchRecord>,
    pub release_holds: Vec<ReleaseHold>, pub expected_roots: ExpectedRoots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let headers = devnet_headers();
        let mut canonical_tip_height = 0;
        let mut canonical_tip_hash = String::new();
        for header in &headers {
            if header.height >= canonical_tip_height {
                canonical_tip_height = header.height;
                canonical_tip_hash = header.block_hash.clone();
            }
        }
        let finality_windows = devnet_finality_windows(&config, &headers);
        let stale_feed_evidence = devnet_stale_feed_evidence(&config, canonical_tip_height);
        let reorg_risks = devnet_reorg_risks(&config, canonical_tip_height, &canonical_tip_hash);
        let watcher_cross_checks =
            devnet_watcher_cross_checks(canonical_tip_height, &canonical_tip_hash);
        let provisional_mismatch_root = merkle_root(&domain("mismatch"), &[]);
        let provisional_release_hold_root = merkle_root(&domain("release-hold"), &[]);
        #[rustfmt::skip]
        let header_root = records_root("header-observation", &headers.iter().map(MoneroHeaderObservation::public_record).collect::<Vec<_>>());
        #[rustfmt::skip]
        let finality_root = records_root("finality-window", &finality_windows.iter().map(FinalityWindow::public_record).collect::<Vec<_>>());
        #[rustfmt::skip]
        let stale_root = records_root("stale-feed-evidence", &stale_feed_evidence.iter().map(StaleFeedEvidence::public_record).collect::<Vec<_>>());
        #[rustfmt::skip]
        let reorg_root = records_root("reorg-risk", &reorg_risks.iter().map(ReorgRiskRecord::public_record).collect::<Vec<_>>());
        #[rustfmt::skip]
        let watcher_root = records_root("watcher-cross-check", &watcher_cross_checks.iter().map(WatcherCrossCheck::public_record).collect::<Vec<_>>());
        let mismatches = devnet_mismatches(&header_root, &watcher_root, &watcher_cross_checks);
        #[rustfmt::skip]
        let mismatch_root = records_root("mismatch", &mismatches.iter().map(MismatchRecord::public_record).collect::<Vec<_>>());
        let release_holds = devnet_release_holds(
            &stale_feed_evidence,
            &reorg_risks,
            &mismatches,
            canonical_tip_height,
        );
        #[rustfmt::skip]
        let release_hold_root = records_root("release-hold", &release_holds.iter().map(ReleaseHold::public_record).collect::<Vec<_>>());
        let expected_roots = ExpectedRoots::from_state_parts(
            header_root,
            finality_root,
            stale_root,
            reorg_root,
            watcher_root,
            if mismatches.is_empty() {
                provisional_mismatch_root
            } else {
                mismatch_root
            },
            if release_holds.is_empty() {
                provisional_release_hold_root
            } else {
                release_hold_root
            },
        );

        Self {
            config,
            runtime_id: format!("{DOMAIN}:devnet"),
            observation_epoch: 17,
            l2_observation_height: 1_260_144,
            monero_tip_height: canonical_tip_height,
            canonical_tip_hash,
            headers,
            finality_windows,
            stale_feed_evidence,
            reorg_risks,
            watcher_cross_checks,
            mismatches,
            release_holds,
            expected_roots,
        }
    }

    #[rustfmt::skip]
    pub fn public_record(&self) -> Value {
        json!({
            "canonical_tip_hash": self.canonical_tip_hash, "chain_id": CHAIN_ID, "config": self.config.public_record(),
            "expected_roots": self.expected_roots.public_record(), "finality_window_count": self.finality_windows.len() as u64,
            "finality_window_root": self.finality_window_root(), "hash_suite": HASH_SUITE,
            "header_observation_count": self.headers.len() as u64, "header_observation_root": self.header_observation_root(),
            "l2_observation_height": self.l2_observation_height, "mismatch_count": self.mismatches.len() as u64,
            "mismatch_root": self.mismatch_root(), "monero_tip_height": self.monero_tip_height,
            "observation_epoch": self.observation_epoch, "protocol_version": PROTOCOL_VERSION,
            "release_hold_count": self.release_holds.len() as u64, "release_hold_root": self.release_hold_root(),
            "reorg_risk_count": self.reorg_risks.len() as u64, "reorg_risk_root": self.reorg_risk_root(),
            "runtime_id": self.runtime_id, "schema_version": SCHEMA_VERSION,
            "stale_feed_evidence_count": self.stale_feed_evidence.len() as u64, "stale_feed_evidence_root": self.stale_feed_evidence_root(),
            "state_root": self.state_root(), "watcher_cross_check_count": self.watcher_cross_checks.len() as u64,
            "watcher_cross_check_root": self.watcher_cross_check_root(),
        })
    }

    #[rustfmt::skip]
    pub fn header_observation_root(&self) -> String {
        records_root("header-observation", &self.headers.iter().map(MoneroHeaderObservation::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn finality_window_root(&self) -> String {
        records_root("finality-window", &self.finality_windows.iter().map(FinalityWindow::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn stale_feed_evidence_root(&self) -> String {
        records_root("stale-feed-evidence", &self.stale_feed_evidence.iter().map(StaleFeedEvidence::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn reorg_risk_root(&self) -> String {
        records_root("reorg-risk", &self.reorg_risks.iter().map(ReorgRiskRecord::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn watcher_cross_check_root(&self) -> String {
        records_root("watcher-cross-check", &self.watcher_cross_checks.iter().map(WatcherCrossCheck::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn mismatch_root(&self) -> String {
        records_root("mismatch", &self.mismatches.iter().map(MismatchRecord::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn release_hold_root(&self) -> String {
        records_root("release-hold", &self.release_holds.iter().map(ReleaseHold::public_record).collect::<Vec<_>>())
    }

    #[rustfmt::skip]
    pub fn state_root(&self) -> String {
        let config_record = self.config.public_record();
        let expected_record = self.expected_roots.public_record();
        domain_hash(
            &domain("state"),
            &[
                HashPart::Str(CHAIN_ID), HashPart::Str(PROTOCOL_VERSION), HashPart::Str(SCHEMA_VERSION),
                HashPart::Json(&config_record), HashPart::Str(&self.runtime_id), HashPart::U64(self.observation_epoch),
                HashPart::U64(self.l2_observation_height), HashPart::U64(self.monero_tip_height),
                HashPart::Str(&self.canonical_tip_hash), HashPart::Json(&expected_record),
                HashPart::Str(&self.header_observation_root()), HashPart::Str(&self.finality_window_root()),
                HashPart::Str(&self.stale_feed_evidence_root()), HashPart::Str(&self.reorg_risk_root()),
                HashPart::Str(&self.watcher_cross_check_root()), HashPart::Str(&self.mismatch_root()),
                HashPart::Str(&self.release_hold_root()),
            ],
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

fn devnet_headers() -> Vec<MoneroHeaderObservation> {
    let mut headers = Vec::new();
    let mut previous_block_hash = "xmr-devnet-3180099-6eea9e70b3a57f12d9".to_string();

    for sequence in 0..5 {
        let height = 3_180_100 + sequence;
        let source = match sequence {
            2 => "monerod-rpc-b",
            4 => "monerod-rpc-c",
            _ => "monerod-rpc-a",
        };
        let block_hash = domain_hash(
            &domain("devnet-header-hash"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(height),
                HashPart::Str(&previous_block_hash),
                HashPart::Str(source),
            ],
            32,
        );
        let merkle_root_value = domain_hash(
            &domain("devnet-header-merkle"),
            &[HashPart::U64(height), HashPart::U64(4 + sequence)],
            32,
        );
        let pow_hash = domain_hash(
            &domain("devnet-header-pow"),
            &[HashPart::U64(height), HashPart::U64(1_004_201 + sequence)],
            32,
        );
        let miner_tx_hash = domain_hash(
            &domain("devnet-header-miner-tx"),
            &[HashPart::U64(height), HashPart::Str(&block_hash)],
            32,
        );
        let raw_header_commitment = domain_hash(
            &domain("raw-header"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(source),
                HashPart::U64(sequence),
                HashPart::U64(height),
                HashPart::U64(1_718_240_000 + (sequence * 120)),
                HashPart::Str(&block_hash),
                HashPart::Str(&previous_block_hash),
                HashPart::Str(&merkle_root_value),
                HashPart::Str(&pow_hash),
                HashPart::Int((11_420_004_884_100u128 + (sequence as u128 * 1_143_500)) as i128),
                HashPart::U64(1_004_201 + sequence),
                HashPart::U64(4 + sequence),
                HashPart::Str(&miner_tx_hash),
            ],
            32,
        );
        let observation_id = domain_hash(
            &domain("header-observation-id"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::U64(sequence),
                HashPart::U64(height),
                HashPart::Str(&block_hash),
                HashPart::Str(&raw_header_commitment),
            ],
            32,
        );

        headers.push(MoneroHeaderObservation {
            observation_id,
            sequence,
            source: source.to_string(),
            height,
            timestamp_seconds: 1_718_240_000 + (sequence * 120),
            observed_at_l2_height: 1_260_100 + (sequence * 4),
            block_hash: block_hash.clone(),
            previous_block_hash,
            merkle_root: merkle_root_value,
            pow_hash,
            cumulative_difficulty: 11_420_004_884_100u128 + (sequence as u128 * 1_143_500),
            nonce: 1_004_201 + sequence,
            tx_count: 4 + sequence,
            miner_tx_hash,
            raw_header_commitment,
            status: ObservationStatus::Accepted,
        });
        previous_block_hash = block_hash;
    }

    headers
}

fn devnet_finality_windows(
    config: &Config,
    headers: &[MoneroHeaderObservation],
) -> Vec<FinalityWindow> {
    headers
        .iter()
        .take(3)
        .map(|header| {
            FinalityWindow::new(
                config,
                header.height,
                header.height + config.min_finality_depth_blocks + 1,
                &header.block_hash,
                "xmr-devnet-finality-tip-3180125-d1f7e3",
            )
        })
        .collect::<Vec<_>>()
}

fn devnet_stale_feed_evidence(
    config: &Config,
    current_monero_height: u64,
) -> Vec<StaleFeedEvidence> {
    vec![
        StaleFeedEvidence::new(
            config,
            "monero-header-live-feed-primary",
            current_monero_height,
            current_monero_height,
            1_718_240_480,
            1_718_240_540,
        ),
        StaleFeedEvidence::new(
            config,
            "monero-header-live-feed-secondary",
            current_monero_height.saturating_sub(5),
            current_monero_height,
            1_718_239_760,
            1_718_240_540,
        ),
    ]
}

fn devnet_reorg_risks(
    config: &Config,
    canonical_tip_height: u64,
    canonical_tip_hash: &str,
) -> Vec<ReorgRiskRecord> {
    vec![
        ReorgRiskRecord::new(
            config,
            canonical_tip_height.saturating_sub(2),
            canonical_tip_height,
            canonical_tip_hash,
            "xmr-devnet-3180102-alt-7e210bd3a4",
            vec!["forced-exit-devnet-0007"],
        ),
        ReorgRiskRecord::new(
            config,
            canonical_tip_height.saturating_sub(72),
            canonical_tip_height,
            "xmr-devnet-3180032-archival-canonical-0bb8",
            "xmr-devnet-3180032-archival-alt-f3a9",
            Vec::new(),
        ),
    ]
}

fn devnet_watcher_cross_checks(
    canonical_tip_height: u64,
    canonical_tip_hash: &str,
) -> Vec<WatcherCrossCheck> {
    vec![
        WatcherCrossCheck::new(
            "pq-watcher-alpha",
            canonical_tip_height,
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_height,
        ),
        WatcherCrossCheck::new(
            "pq-watcher-beta",
            canonical_tip_height.saturating_sub(1),
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_height,
        ),
        WatcherCrossCheck::new(
            "pq-watcher-gamma",
            canonical_tip_height.saturating_sub(2),
            "xmr-devnet-3180104-c8d9f1b4a02e79d352",
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_height,
        ),
        WatcherCrossCheck::new(
            "pq-watcher-delta",
            canonical_tip_height.saturating_sub(2),
            "xmr-devnet-3180104-c8d9f1b4a02e79d352",
            canonical_tip_hash,
            canonical_tip_hash,
            canonical_tip_height,
        ),
        WatcherCrossCheck::new(
            "pq-watcher-epsilon",
            canonical_tip_height.saturating_sub(2),
            "xmr-devnet-3180104-alt-reorg-7a55d9",
            "xmr-devnet-3180104-alt-reorg-7a55d9",
            canonical_tip_hash,
            canonical_tip_height,
        ),
    ]
}

fn devnet_mismatches(
    header_root: &str,
    watcher_root: &str,
    watcher_cross_checks: &[WatcherCrossCheck],
) -> Vec<MismatchRecord> {
    let watcher_evidence = watcher_cross_checks
        .iter()
        .filter(|check| !check.agrees_with_canonical)
        .map(WatcherCrossCheck::public_record)
        .collect::<Vec<_>>();

    vec![MismatchRecord::new(
        "watcher_cross_check_root",
        header_root,
        watcher_root,
        1_260_118,
        1_260_124,
        &watcher_evidence,
    )]
}

fn devnet_release_holds(
    stale_feed_evidence: &[StaleFeedEvidence],
    reorg_risks: &[ReorgRiskRecord],
    mismatches: &[MismatchRecord],
    monero_tip_height: u64,
) -> Vec<ReleaseHold> {
    let mut holds = Vec::new();

    for stale in stale_feed_evidence {
        if stale.release_hold != ReleaseHoldKind::None {
            holds.push(ReleaseHold::new(
                stale.release_hold,
                "secondary Monero header feed exceeded freshness bounds",
                1_260_124,
                stale.current_monero_height,
                &record_root("stale-feed-evidence", &stale.public_record()),
                monero_tip_height + 3,
                "refresh feed source and replay header observations before release",
            ));
        }
    }

    for risk in reorg_risks {
        if risk.release_hold != ReleaseHoldKind::None {
            holds.push(ReleaseHold::new(
                risk.release_hold,
                "competing Monero header is inside forced-exit finality window",
                1_260_126,
                risk.competing_height,
                &record_root("reorg-risk", &risk.public_record()),
                monero_tip_height + risk.max_reorg_window_blocks,
                "wait for finality depth or attach dispute evidence",
            ));
        }
    }

    for mismatch in mismatches {
        if mismatch.release_hold != ReleaseHoldKind::None {
            holds.push(ReleaseHold::new(
                ReleaseHoldKind::WatcherMismatch,
                "watcher quorum contains non-canonical header observation",
                1_260_128,
                monero_tip_height,
                &record_root("mismatch", &mismatch.public_record()),
                monero_tip_height + 20,
                "collect quorum replacement signatures over canonical tip",
            ));
        }
    }

    holds
}

#[rustfmt::skip]
fn record_root(label: &str, record: &Value) -> String {
    domain_hash(&domain(label), &[HashPart::Str(CHAIN_ID), HashPart::Json(record)], 32)
}

fn records_root(label: &str, records: &[Value]) -> String {
    merkle_root(&domain(label), records)
}

#[rustfmt::skip]
fn string_root(label: &str, values: &[String]) -> String {
    merkle_root(&domain(label), &values.iter().map(|value| json!({ "value": value })).collect::<Vec<_>>())
}

fn domain(label: &str) -> String {
    format!("{DOMAIN}:{label}")
}
