use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeMoneroWatcherProcessFeedRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_MONERO_WATCHER_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-monero-watcher-process-feed-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_MONERO_WATCHER_PROCESS_FEED_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PROCESS_FEED_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-monero-watcher-process-feed-v1";
pub const DEFAULT_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_FEED_EPOCH: u64 = 144;
pub const DEFAULT_CANONICAL_HEIGHT: u64 = 3_500_144;
pub const DEFAULT_L2_HEIGHT: u64 = 884_512;
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_FINALITY_CONFIRMATIONS: u64 = 24;
pub const DEFAULT_REORG_WINDOW: u64 = 18;
pub const DEFAULT_MIN_WATCHER_WEIGHT_BPS: u16 = 7_200;
pub const DEFAULT_MIN_WATCHER_COUNT: u16 = 4;
pub const DEFAULT_MAX_STALE_LAG: u64 = 3;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedLane {
    DepositLocks,
    MoneroHeaders,
    WatchedTxRoots,
    ConfirmationWindows,
}

impl FeedLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLocks => "deposit_locks",
            Self::MoneroHeaders => "monero_headers",
            Self::WatchedTxRoots => "watched_tx_roots",
            Self::ConfirmationWindows => "confirmation_windows",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Canonical,
    Pending,
    Reorged,
    Stale,
}

impl ObservationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Pending => "pending",
            Self::Reorged => "reorged",
            Self::Stale => "stale",
        }
    }

    pub fn counts_for_quorum(self) -> bool {
        matches!(self, Self::Canonical)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    ReorgDetected,
    ConfirmationShortfall,
    WatcherQuorumShortfall,
    WatchedRootMismatch,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReorgDetected => "reorg_detected",
            Self::ConfirmationShortfall => "confirmation_shortfall",
            Self::WatcherQuorumShortfall => "watcher_quorum_shortfall",
            Self::WatchedRootMismatch => "watched_root_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub process_feed_suite: String,
    pub monero_network: String,
    pub feed_epoch: u64,
    pub canonical_height: u64,
    pub l2_height: u64,
    pub min_confirmations: u64,
    pub finality_confirmations: u64,
    pub reorg_window: u64,
    pub min_watcher_weight_bps: u16,
    pub min_watcher_count: u16,
    pub max_stale_lag: u64,
    pub fail_closed_on_blocker: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            process_feed_suite: PROCESS_FEED_SUITE.to_string(),
            monero_network: DEFAULT_MONERO_NETWORK.to_string(),
            feed_epoch: DEFAULT_FEED_EPOCH,
            canonical_height: DEFAULT_CANONICAL_HEIGHT,
            l2_height: DEFAULT_L2_HEIGHT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            finality_confirmations: DEFAULT_FINALITY_CONFIRMATIONS,
            reorg_window: DEFAULT_REORG_WINDOW,
            min_watcher_weight_bps: DEFAULT_MIN_WATCHER_WEIGHT_BPS,
            min_watcher_count: DEFAULT_MIN_WATCHER_COUNT,
            max_stale_lag: DEFAULT_MAX_STALE_LAG,
            fail_closed_on_blocker: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "process_feed_suite": self.process_feed_suite,
            "monero_network": self.monero_network,
            "feed_epoch": self.feed_epoch,
            "canonical_height": self.canonical_height,
            "l2_height": self.l2_height,
            "min_confirmations": self.min_confirmations,
            "finality_confirmations": self.finality_confirmations,
            "reorg_window": self.reorg_window,
            "min_watcher_weight_bps": self.min_watcher_weight_bps,
            "min_watcher_count": self.min_watcher_count,
            "max_stale_lag": self.max_stale_lag,
            "fail_closed_on_blocker": self.fail_closed_on_blocker,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DepositLock {
    pub lock_id: String,
    pub user_escape_id: String,
    pub lock_txid: String,
    pub output_index: u64,
    pub amount_commitment_root: String,
    pub destination_commitment_root: String,
    pub nullifier_root: String,
    pub observed_height: u64,
    pub confirmation_count: u64,
    pub lock_root: String,
}

impl DepositLock {
    pub fn devnet(
        config: &Config,
        user_escape_id: &str,
        ordinal: u64,
        confirmation_count: u64,
    ) -> Self {
        let lock_txid = label_root("lock_txid", user_escape_id, ordinal);
        let amount_commitment_root = label_root("amount_commitment", user_escape_id, ordinal);
        let destination_commitment_root =
            label_root("destination_commitment", user_escape_id, ordinal);
        let nullifier_root = label_root("nullifier", user_escape_id, ordinal);
        let observed_height = config.canonical_height.saturating_sub(confirmation_count);
        let lock_seed = json!({
            "user_escape_id": user_escape_id,
            "lock_txid": lock_txid,
            "output_index": ordinal,
            "amount_commitment_root": amount_commitment_root,
            "destination_commitment_root": destination_commitment_root,
            "nullifier_root": nullifier_root,
            "observed_height": observed_height,
            "confirmation_count": confirmation_count,
        });
        let lock_root = record_root("deposit_lock", &lock_seed);
        let lock_id = record_id("deposit_lock_id", &lock_root, ordinal);
        Self {
            lock_id,
            user_escape_id: user_escape_id.to_string(),
            lock_txid,
            output_index: ordinal,
            amount_commitment_root,
            destination_commitment_root,
            nullifier_root,
            observed_height,
            confirmation_count,
            lock_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lock_id": self.lock_id,
            "user_escape_id": self.user_escape_id,
            "lock_txid": self.lock_txid,
            "output_index": self.output_index,
            "amount_commitment_root": self.amount_commitment_root,
            "destination_commitment_root": self.destination_commitment_root,
            "nullifier_root": self.nullifier_root,
            "observed_height": self.observed_height,
            "confirmation_count": self.confirmation_count,
            "lock_root": self.lock_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.lock_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherObservation {
    pub observation_id: String,
    pub watcher_id: String,
    pub operator_id: String,
    pub lane: FeedLane,
    pub status: ObservationStatus,
    pub watcher_weight_bps: u16,
    pub observed_height: u64,
    pub canonical_height: u64,
    pub confirmation_count: u64,
    pub deposit_lock_id: String,
    pub deposit_lock_root: String,
    pub watched_tx_root: String,
    pub expected_tx_root: String,
    pub header_root: String,
    pub process_feed_root: String,
    pub attestation_root: String,
}

impl WatcherObservation {
    pub fn new(
        config: &Config,
        watcher_id: &str,
        operator_id: &str,
        watcher_weight_bps: u16,
        lane: FeedLane,
        status: ObservationStatus,
        deposit_lock: &DepositLock,
        root_set: &WatchedRootSet,
    ) -> Self {
        let observed_height = if status == ObservationStatus::Stale {
            deposit_lock
                .observed_height
                .saturating_sub(config.max_stale_lag + 1)
        } else {
            deposit_lock.observed_height
        };
        let confirmation_count = config.canonical_height.saturating_sub(observed_height);
        let watched_tx_root = if status == ObservationStatus::Reorged {
            root_set.reorged_tx_root.clone()
        } else {
            root_set.canonical_tx_root.clone()
        };
        let header_root = if status == ObservationStatus::Reorged {
            root_set.reorged_header_root.clone()
        } else {
            root_set.canonical_header_root.clone()
        };
        let process_feed_root = process_feed_root(
            lane,
            &deposit_lock.lock_id,
            &watched_tx_root,
            &header_root,
            observed_height,
            confirmation_count,
        );
        let attestation_root = watcher_attestation_root(
            watcher_id,
            operator_id,
            watcher_weight_bps,
            lane,
            status,
            &deposit_lock.lock_root,
            &watched_tx_root,
            &root_set.canonical_tx_root,
            &process_feed_root,
        );
        let observation_id =
            record_id("watcher_observation_id", &attestation_root, observed_height);
        Self {
            observation_id,
            watcher_id: watcher_id.to_string(),
            operator_id: operator_id.to_string(),
            lane,
            status,
            watcher_weight_bps,
            observed_height,
            canonical_height: config.canonical_height,
            confirmation_count,
            deposit_lock_id: deposit_lock.lock_id.clone(),
            deposit_lock_root: deposit_lock.lock_root.clone(),
            watched_tx_root,
            expected_tx_root: root_set.canonical_tx_root.clone(),
            header_root,
            process_feed_root,
            attestation_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "observation_id": self.observation_id,
            "watcher_id": self.watcher_id,
            "operator_id": self.operator_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "watcher_weight_bps": self.watcher_weight_bps,
            "observed_height": self.observed_height,
            "canonical_height": self.canonical_height,
            "confirmation_count": self.confirmation_count,
            "deposit_lock_id": self.deposit_lock_id,
            "deposit_lock_root": self.deposit_lock_root,
            "watched_tx_root": self.watched_tx_root,
            "expected_tx_root": self.expected_tx_root,
            "header_root": self.header_root,
            "process_feed_root": self.process_feed_root,
            "attestation_root": self.attestation_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.attestation_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatchedRootSet {
    pub canonical_header_root: String,
    pub reorged_header_root: String,
    pub canonical_tx_root: String,
    pub reorged_tx_root: String,
    pub watched_tx_root: String,
    pub confirmation_window_root: String,
}

impl WatchedRootSet {
    pub fn from_locks(config: &Config, locks: &[DepositLock]) -> Self {
        let lock_records = locks
            .iter()
            .map(DepositLock::public_record)
            .collect::<Vec<_>>();
        let canonical_header_root = record_root(
            "canonical_monero_header",
            &json!({
                "network": config.monero_network,
                "height": config.canonical_height,
                "feed_epoch": config.feed_epoch,
                "reorg_window": config.reorg_window,
            }),
        );
        let reorged_header_root = record_root(
            "reorged_monero_header",
            &json!({
                "network": config.monero_network,
                "height": config.canonical_height.saturating_sub(config.reorg_window),
                "feed_epoch": config.feed_epoch,
                "status": "non_canonical",
            }),
        );
        let canonical_tx_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHED-TX",
            &lock_records,
        );
        let reorged_tx_root = record_root(
            "reorged_watched_tx_root",
            &json!({
                "canonical_tx_root": canonical_tx_root,
                "reorged_header_root": reorged_header_root,
            }),
        );
        let confirmation_window_root = record_root(
            "confirmation_window",
            &json!({
                "min_confirmations": config.min_confirmations,
                "finality_confirmations": config.finality_confirmations,
                "canonical_height": config.canonical_height,
                "reorg_window": config.reorg_window,
            }),
        );
        let watched_tx_root = record_root(
            "watched_tx_root_binding",
            &json!({
                "canonical_header_root": canonical_header_root,
                "canonical_tx_root": canonical_tx_root,
                "confirmation_window_root": confirmation_window_root,
            }),
        );
        Self {
            canonical_header_root,
            reorged_header_root,
            canonical_tx_root,
            reorged_tx_root,
            watched_tx_root,
            confirmation_window_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "canonical_header_root": self.canonical_header_root,
            "reorged_header_root": self.reorged_header_root,
            "canonical_tx_root": self.canonical_tx_root,
            "reorged_tx_root": self.reorged_tx_root,
            "watched_tx_root": self.watched_tx_root,
            "confirmation_window_root": self.confirmation_window_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WatcherQuorum {
    pub quorum_id: String,
    pub lane: FeedLane,
    pub required_weight_bps: u16,
    pub observed_weight_bps: u16,
    pub required_watcher_count: u16,
    pub observed_watcher_count: u16,
    pub quorum_met: bool,
    pub quorum_root: String,
}

impl WatcherQuorum {
    pub fn evaluate(config: &Config, lane: FeedLane, observations: &[WatcherObservation]) -> Self {
        let mut observed_weight_bps = 0u16;
        let mut observed_watcher_count = 0u16;
        for observation in observations {
            if observation.lane == lane && observation.status.counts_for_quorum() {
                observed_weight_bps =
                    observed_weight_bps.saturating_add(observation.watcher_weight_bps);
                observed_watcher_count = observed_watcher_count.saturating_add(1);
            }
        }
        let quorum_met = observed_weight_bps >= config.min_watcher_weight_bps
            && observed_watcher_count >= config.min_watcher_count;
        let quorum_root = quorum_root(
            lane,
            config.min_watcher_weight_bps,
            observed_weight_bps,
            config.min_watcher_count,
            observed_watcher_count,
            quorum_met,
        );
        let quorum_id = record_id("watcher_quorum_id", &quorum_root, config.feed_epoch);
        Self {
            quorum_id,
            lane,
            required_weight_bps: config.min_watcher_weight_bps,
            observed_weight_bps,
            required_watcher_count: config.min_watcher_count,
            observed_watcher_count,
            quorum_met,
            quorum_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "quorum_id": self.quorum_id,
            "lane": self.lane.as_str(),
            "required_weight_bps": self.required_weight_bps,
            "observed_weight_bps": self.observed_weight_bps,
            "required_watcher_count": self.required_watcher_count,
            "observed_watcher_count": self.observed_watcher_count,
            "quorum_met": self.quorum_met,
            "quorum_root": self.quorum_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FinalityWindow {
    pub window_id: String,
    pub deposit_lock_id: String,
    pub confirmation_count: u64,
    pub min_confirmations: u64,
    pub finality_confirmations: u64,
    pub reorg_window: u64,
    pub is_confirmed: bool,
    pub is_final: bool,
    pub finality_root: String,
}

impl FinalityWindow {
    pub fn from_lock(config: &Config, lock: &DepositLock) -> Self {
        let is_confirmed = lock.confirmation_count >= config.min_confirmations;
        let is_final = lock.confirmation_count >= config.finality_confirmations;
        let finality_root = finality_window_root(
            &lock.lock_id,
            lock.confirmation_count,
            config.min_confirmations,
            config.finality_confirmations,
            config.reorg_window,
            is_confirmed,
            is_final,
        );
        let window_id = record_id("finality_window_id", &finality_root, lock.output_index);
        Self {
            window_id,
            deposit_lock_id: lock.lock_id.clone(),
            confirmation_count: lock.confirmation_count,
            min_confirmations: config.min_confirmations,
            finality_confirmations: config.finality_confirmations,
            reorg_window: config.reorg_window,
            is_confirmed,
            is_final,
            finality_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "deposit_lock_id": self.deposit_lock_id,
            "confirmation_count": self.confirmation_count,
            "min_confirmations": self.min_confirmations,
            "finality_confirmations": self.finality_confirmations,
            "reorg_window": self.reorg_window,
            "is_confirmed": self.is_confirmed,
            "is_final": self.is_final,
            "finality_root": self.finality_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailClosedBlocker {
    pub blocker_id: String,
    pub kind: BlockerKind,
    pub subject_id: String,
    pub severity: String,
    pub evidence_root: String,
    pub release_blocked: bool,
    pub clears_when: String,
    pub blocker_root: String,
}

impl FailClosedBlocker {
    pub fn new(
        kind: BlockerKind,
        subject_id: &str,
        severity: &str,
        evidence_root: &str,
        release_blocked: bool,
        clears_when: &str,
        ordinal: u64,
    ) -> Self {
        let blocker_root = blocker_root(
            kind,
            subject_id,
            severity,
            evidence_root,
            release_blocked,
            clears_when,
        );
        let blocker_id = record_id("fail_closed_blocker_id", &blocker_root, ordinal);
        Self {
            blocker_id,
            kind,
            subject_id: subject_id.to_string(),
            severity: severity.to_string(),
            evidence_root: evidence_root.to_string(),
            release_blocked,
            clears_when: clears_when.to_string(),
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "subject_id": self.subject_id,
            "severity": self.severity,
            "evidence_root": self.evidence_root,
            "release_blocked": self.release_blocked,
            "clears_when": self.clears_when,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub deposit_lock_root: String,
    pub watched_root_set_root: String,
    pub observation_root: String,
    pub finality_window_root: String,
    pub watcher_quorum_root: String,
    pub blocker_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "deposit_lock_root": self.deposit_lock_root,
            "watched_root_set_root": self.watched_root_set_root,
            "observation_root": self.observation_root,
            "finality_window_root": self.finality_window_root,
            "watcher_quorum_root": self.watcher_quorum_root,
            "blocker_root": self.blocker_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub deposit_locks: Vec<DepositLock>,
    pub watched_roots: WatchedRootSet,
    pub observations: Vec<WatcherObservation>,
    pub finality_windows: Vec<FinalityWindow>,
    pub watcher_quorums: Vec<WatcherQuorum>,
    pub blockers: Vec<FailClosedBlocker>,
    pub watcher_weights: BTreeMap<String, u16>,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let deposit_locks = vec![
            DepositLock::devnet(&config, "user-escape-devnet-canonical-0001", 1, 28),
            DepositLock::devnet(&config, "user-escape-devnet-pending-0002", 2, 6),
            DepositLock::devnet(&config, "user-escape-devnet-reorg-0003", 3, 14),
        ];
        let watched_roots = WatchedRootSet::from_locks(&config, &deposit_locks);
        let observations = devnet_observations(&config, &deposit_locks, &watched_roots);
        let finality_windows = deposit_locks
            .iter()
            .map(|lock| FinalityWindow::from_lock(&config, lock))
            .collect::<Vec<_>>();
        let watcher_quorums = vec![
            WatcherQuorum::evaluate(&config, FeedLane::DepositLocks, &observations),
            WatcherQuorum::evaluate(&config, FeedLane::WatchedTxRoots, &observations),
            WatcherQuorum::evaluate(&config, FeedLane::ConfirmationWindows, &observations),
        ];
        let blockers = devnet_blockers(&config, &observations, &finality_windows, &watcher_quorums);
        let mut watcher_weights = BTreeMap::new();
        for observation in &observations {
            watcher_weights.insert(
                observation.watcher_id.clone(),
                observation.watcher_weight_bps,
            );
        }
        let roots = compute_roots(
            &config,
            &deposit_locks,
            &watched_roots,
            &observations,
            &finality_windows,
            &watcher_quorums,
            &blockers,
        );
        Self {
            config,
            deposit_locks,
            watched_roots,
            observations,
            finality_windows,
            watcher_quorums,
            blockers,
            watcher_weights,
            roots,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "config": self.config.public_record(),
            "deposit_locks": self.deposit_locks.iter().map(DepositLock::public_record).collect::<Vec<_>>(),
            "watched_roots": self.watched_roots.public_record(),
            "observations": self.observations.iter().map(WatcherObservation::public_record).collect::<Vec<_>>(),
            "finality_windows": self.finality_windows.iter().map(FinalityWindow::public_record).collect::<Vec<_>>(),
            "watcher_quorums": self.watcher_quorums.iter().map(WatcherQuorum::public_record).collect::<Vec<_>>(),
            "blockers": self.blockers.iter().map(FailClosedBlocker::public_record).collect::<Vec<_>>(),
            "watcher_weights": self.watcher_weights,
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

fn devnet_observations(
    config: &Config,
    locks: &[DepositLock],
    roots: &WatchedRootSet,
) -> Vec<WatcherObservation> {
    let watchers = [
        ("watcher-alpha", "operator-north", 1_900u16),
        ("watcher-beta", "operator-east", 1_800u16),
        ("watcher-gamma", "operator-west", 1_700u16),
        ("watcher-delta", "operator-south", 1_600u16),
        ("watcher-epsilon", "operator-archive", 1_200u16),
    ];
    let mut observations = Vec::new();
    for (watcher_id, operator_id, weight) in watchers {
        observations.push(WatcherObservation::new(
            config,
            watcher_id,
            operator_id,
            weight,
            FeedLane::DepositLocks,
            ObservationStatus::Canonical,
            &locks[0],
            roots,
        ));
    }
    observations.push(WatcherObservation::new(
        config,
        "watcher-alpha",
        "operator-north",
        1_900,
        FeedLane::ConfirmationWindows,
        ObservationStatus::Pending,
        &locks[1],
        roots,
    ));
    observations.push(WatcherObservation::new(
        config,
        "watcher-beta",
        "operator-east",
        1_800,
        FeedLane::ConfirmationWindows,
        ObservationStatus::Pending,
        &locks[1],
        roots,
    ));
    observations.push(WatcherObservation::new(
        config,
        "watcher-gamma",
        "operator-west",
        1_700,
        FeedLane::WatchedTxRoots,
        ObservationStatus::Reorged,
        &locks[2],
        roots,
    ));
    observations.push(WatcherObservation::new(
        config,
        "watcher-epsilon",
        "operator-archive",
        1_200,
        FeedLane::MoneroHeaders,
        ObservationStatus::Stale,
        &locks[2],
        roots,
    ));
    observations
}

fn devnet_blockers(
    config: &Config,
    observations: &[WatcherObservation],
    finality_windows: &[FinalityWindow],
    quorums: &[WatcherQuorum],
) -> Vec<FailClosedBlocker> {
    let mut blockers = Vec::new();
    let release_blocked = config.fail_closed_on_blocker;
    for (index, window) in finality_windows.iter().enumerate() {
        if !window.is_confirmed {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::ConfirmationShortfall,
                &window.deposit_lock_id,
                "release_stop",
                &window.finality_root,
                release_blocked,
                "deposit lock reaches the configured minimum confirmation count",
                index as u64,
            ));
        }
    }
    for observation in observations {
        if observation.status == ObservationStatus::Reorged {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::ReorgDetected,
                &observation.observation_id,
                "critical",
                &observation.attestation_root,
                release_blocked,
                "watchers re-attest to the canonical watched transaction root",
                observation.observed_height,
            ));
        }
        if observation.watched_tx_root != observation.expected_tx_root {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::WatchedRootMismatch,
                &observation.observation_id,
                "release_stop",
                &observation.process_feed_root,
                release_blocked,
                "process feed root equals the canonical watched transaction root",
                observation.confirmation_count,
            ));
        }
    }
    for quorum in quorums {
        if !quorum.quorum_met {
            blockers.push(FailClosedBlocker::new(
                BlockerKind::WatcherQuorumShortfall,
                &quorum.quorum_id,
                "release_stop",
                &quorum.quorum_root,
                release_blocked,
                "independent watcher count and weight satisfy the configured quorum",
                quorum.observed_weight_bps as u64,
            ));
        }
    }
    blockers
}

fn compute_roots(
    config: &Config,
    locks: &[DepositLock],
    watched_roots: &WatchedRootSet,
    observations: &[WatcherObservation],
    finality_windows: &[FinalityWindow],
    quorums: &[WatcherQuorum],
    blockers: &[FailClosedBlocker],
) -> Roots {
    let lock_records = locks
        .iter()
        .map(DepositLock::public_record)
        .collect::<Vec<_>>();
    let observation_records = observations
        .iter()
        .map(WatcherObservation::public_record)
        .collect::<Vec<_>>();
    let finality_records = finality_windows
        .iter()
        .map(FinalityWindow::public_record)
        .collect::<Vec<_>>();
    let quorum_records = quorums
        .iter()
        .map(WatcherQuorum::public_record)
        .collect::<Vec<_>>();
    let blocker_records = blockers
        .iter()
        .map(FailClosedBlocker::public_record)
        .collect::<Vec<_>>();
    let mut roots = Roots {
        config_root: config.state_root(),
        deposit_lock_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-DEPOSIT-LOCKS",
            &lock_records,
        ),
        watched_root_set_root: record_root("watched_root_set", &watched_roots.public_record()),
        observation_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-OBSERVATIONS",
            &observation_records,
        ),
        finality_window_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-FINALITY-WINDOWS",
            &finality_records,
        ),
        watcher_quorum_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-QUORUMS",
            &quorum_records,
        ),
        blocker_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-BLOCKERS",
            &blocker_records,
        ),
        state_root: String::new(),
    };
    roots.state_root = state_root_from_roots(&roots);
    roots
}

fn state_root_from_roots(roots: &Roots) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-PROCESS-FEED-STATE",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&roots.config_root),
            HashPart::Str(&roots.deposit_lock_root),
            HashPart::Str(&roots.watched_root_set_root),
            HashPart::Str(&roots.observation_root),
            HashPart::Str(&roots.finality_window_root),
            HashPart::Str(&roots.watcher_quorum_root),
            HashPart::Str(&roots.blocker_root),
        ],
        32,
    )
}

fn process_feed_root(
    lane: FeedLane,
    deposit_lock_id: &str,
    watched_tx_root: &str,
    header_root: &str,
    observed_height: u64,
    confirmation_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-PROCESS-FEED",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(deposit_lock_id),
            HashPart::Str(watched_tx_root),
            HashPart::Str(header_root),
            HashPart::U64(observed_height),
            HashPart::U64(confirmation_count),
        ],
        32,
    )
}

fn watcher_attestation_root(
    watcher_id: &str,
    operator_id: &str,
    watcher_weight_bps: u16,
    lane: FeedLane,
    status: ObservationStatus,
    deposit_lock_root: &str,
    watched_tx_root: &str,
    expected_tx_root: &str,
    process_feed_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-ATTESTATION",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(watcher_id),
            HashPart::Str(operator_id),
            HashPart::U64(watcher_weight_bps as u64),
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(deposit_lock_root),
            HashPart::Str(watched_tx_root),
            HashPart::Str(expected_tx_root),
            HashPart::Str(process_feed_root),
        ],
        32,
    )
}

fn quorum_root(
    lane: FeedLane,
    required_weight_bps: u16,
    observed_weight_bps: u16,
    required_watcher_count: u16,
    observed_watcher_count: u16,
    quorum_met: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-QUORUM",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(required_weight_bps as u64),
            HashPart::U64(observed_weight_bps as u64),
            HashPart::U64(required_watcher_count as u64),
            HashPart::U64(observed_watcher_count as u64),
            HashPart::Str(bool_str(quorum_met)),
        ],
        32,
    )
}

fn finality_window_root(
    deposit_lock_id: &str,
    confirmation_count: u64,
    min_confirmations: u64,
    finality_confirmations: u64,
    reorg_window: u64,
    is_confirmed: bool,
    is_final: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-FINALITY-WINDOW",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(deposit_lock_id),
            HashPart::U64(confirmation_count),
            HashPart::U64(min_confirmations),
            HashPart::U64(finality_confirmations),
            HashPart::U64(reorg_window),
            HashPart::Str(bool_str(is_confirmed)),
            HashPart::Str(bool_str(is_final)),
        ],
        32,
    )
}

fn blocker_root(
    kind: BlockerKind,
    subject_id: &str,
    severity: &str,
    evidence_root: &str,
    release_blocked: bool,
    clears_when: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-FAIL-CLOSED-BLOCKER",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(severity),
            HashPart::Str(evidence_root),
            HashPart::Str(bool_str(release_blocked)),
            HashPart::Str(clears_when),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-PROCESS-FEED-RECORD",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn record_id(kind: &str, root: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-PROCESS-FEED-ID",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(root),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn label_root(kind: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-USER-ESCAPE-WATCHER-PROCESS-FEED-LABEL",
        &[
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
