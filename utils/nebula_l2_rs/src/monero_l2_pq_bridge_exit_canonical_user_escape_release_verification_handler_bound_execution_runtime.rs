use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeReleaseVerificationHandlerBoundExecutionRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-release-verification-handler-bound-execution-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_RELEASE_VERIFICATION_HANDLER_BOUND_EXECUTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const EXECUTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-release-handler-bound-execution-v1";
pub const DEFAULT_NETWORK: &str = "devnet";
pub const DEFAULT_ESCAPE_ID: &str =
    "canonical-user-escape-handler-bound-release-execution-devnet-0001";
pub const DEFAULT_HANDLER_SESSION_ID: &str =
    "canonical-user-escape-release-verification-handler-bound-execution-session-0001";
pub const DEFAULT_EXECUTION_ID: &str =
    "canonical-user-escape-release-verification-handler-bound-execution-record-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseExecutionVerdict {
    ReleaseAuthorized,
    ReleaseHeld,
    ReleaseRejected,
}

impl ReleaseExecutionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReleaseAuthorized => "release_authorized",
            Self::ReleaseHeld => "release_held",
            Self::ReleaseRejected => "release_rejected",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneExecutionStatus {
    Accepted,
    Watch,
    Blocked,
}

impl LaneExecutionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }

    pub fn permits_release(self) -> bool {
        matches!(self, Self::Accepted)
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub execution_suite: String,
    pub network: String,
    pub escape_id: String,
    pub handler_session_id: String,
    pub execution_id: String,
    pub min_verifier_quorum_weight: u64,
    pub min_pq_custody_quorum_weight: u64,
    pub min_broadcast_confirmations: u64,
    pub min_liquidity_coverage_bps: u64,
    pub challenge_window_blocks: u64,
    pub fail_closed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            execution_suite: EXECUTION_SUITE.to_string(),
            network: DEFAULT_NETWORK.to_string(),
            escape_id: DEFAULT_ESCAPE_ID.to_string(),
            handler_session_id: DEFAULT_HANDLER_SESSION_ID.to_string(),
            execution_id: DEFAULT_EXECUTION_ID.to_string(),
            min_verifier_quorum_weight: 67,
            min_pq_custody_quorum_weight: 67,
            min_broadcast_confirmations: 20,
            min_liquidity_coverage_bps: 10_000,
            challenge_window_blocks: 720,
            fail_closed: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "execution_suite": self.execution_suite,
            "network": self.network,
            "escape_id": self.escape_id,
            "handler_session_id": self.handler_session_id,
            "execution_id": self.execution_id,
            "min_verifier_quorum_weight": self.min_verifier_quorum_weight,
            "min_pq_custody_quorum_weight": self.min_pq_custody_quorum_weight,
            "min_broadcast_confirmations": self.min_broadcast_confirmations,
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps,
            "challenge_window_blocks": self.challenge_window_blocks,
            "fail_closed": bool_label(self.fail_closed)
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandlerBoundRoots {
    pub handler_binding_root: String,
    pub verifier_root: String,
    pub pq_custody_root: String,
    pub broadcast_root: String,
    pub liquidity_root: String,
    pub challenge_root: String,
}

impl HandlerBoundRoots {
    pub fn devnet(config: &Config) -> Self {
        Self {
            handler_binding_root: lane_root("handler-binding", &config.escape_id),
            verifier_root: lane_root("handler-bound-verifier", &config.escape_id),
            pq_custody_root: lane_root("pq-custody", &config.escape_id),
            broadcast_root: lane_root("monero-broadcast", &config.escape_id),
            liquidity_root: lane_root("liquidity", &config.escape_id),
            challenge_root: lane_root("challenge-window", &config.escape_id),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "handler_binding_root": self.handler_binding_root,
            "verifier_root": self.verifier_root,
            "pq_custody_root": self.pq_custody_root,
            "broadcast_root": self.broadcast_root,
            "liquidity_root": self.liquidity_root,
            "challenge_root": self.challenge_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("handler_bound_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionLaneRecord {
    pub lane: String,
    pub consumed_root: String,
    pub status: LaneExecutionStatus,
    pub observed_weight: u64,
    pub required_weight: u64,
    pub execution_note: String,
    pub lane_execution_root: String,
}

impl ExecutionLaneRecord {
    pub fn new(
        lane: &str,
        consumed_root: &str,
        status: LaneExecutionStatus,
        observed_weight: u64,
        required_weight: u64,
        execution_note: &str,
    ) -> Self {
        let lane_execution_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-handler-bound-lane-execution",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(lane),
                HashPart::Str(consumed_root),
                HashPart::Str(status.as_str()),
                HashPart::U64(observed_weight),
                HashPart::U64(required_weight),
                HashPart::Str(execution_note),
            ],
            32,
        );

        Self {
            lane: lane.to_string(),
            consumed_root: consumed_root.to_string(),
            status,
            observed_weight,
            required_weight,
            execution_note: execution_note.to_string(),
            lane_execution_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane": self.lane,
            "consumed_root": self.consumed_root,
            "status": self.status.as_str(),
            "observed_weight": self.observed_weight,
            "required_weight": self.required_weight,
            "execution_note": self.execution_note,
            "lane_execution_root": self.lane_execution_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("execution_lane", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ReleaseExecutionRecord {
    pub verdict: ReleaseExecutionVerdict,
    pub release_ready: bool,
    pub accepted_lane_count: u64,
    pub watched_lane_count: u64,
    pub blocked_lane_count: u64,
    pub lane_execution_root: String,
    pub release_execution_root: String,
}

impl ReleaseExecutionRecord {
    pub fn from_lanes(lanes: &[ExecutionLaneRecord]) -> Self {
        let accepted_lane_count = lanes
            .iter()
            .filter(|lane| lane.status.permits_release())
            .count() as u64;
        let watched_lane_count = lanes
            .iter()
            .filter(|lane| matches!(lane.status, LaneExecutionStatus::Watch))
            .count() as u64;
        let blocked_lane_count = lanes
            .iter()
            .filter(|lane| lane.status.blocks_release())
            .count() as u64;
        let release_ready = lanes
            .iter()
            .all(|lane| lane.status == LaneExecutionStatus::Accepted);
        let verdict = if release_ready {
            ReleaseExecutionVerdict::ReleaseAuthorized
        } else if blocked_lane_count == 0 {
            ReleaseExecutionVerdict::ReleaseHeld
        } else {
            ReleaseExecutionVerdict::ReleaseRejected
        };
        let lane_execution_root = lane_set_root(lanes);
        let release_execution_root = domain_hash(
            "monero-l2-pq-bridge-user-escape-handler-bound-release-execution-verdict",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(verdict.as_str()),
                HashPart::Str(bool_label(release_ready)),
                HashPart::U64(accepted_lane_count),
                HashPart::U64(watched_lane_count),
                HashPart::U64(blocked_lane_count),
                HashPart::Str(&lane_execution_root),
            ],
            32,
        );

        Self {
            verdict,
            release_ready,
            accepted_lane_count,
            watched_lane_count,
            blocked_lane_count,
            lane_execution_root,
            release_execution_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "release_ready": bool_label(self.release_ready),
            "accepted_lane_count": self.accepted_lane_count,
            "watched_lane_count": self.watched_lane_count,
            "blocked_lane_count": self.blocked_lane_count,
            "lane_execution_root": self.lane_execution_root,
            "release_execution_root": self.release_execution_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_execution", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub handler_bound_roots: HandlerBoundRoots,
    pub lanes: Vec<ExecutionLaneRecord>,
    pub release_execution: ReleaseExecutionRecord,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let handler_bound_roots = HandlerBoundRoots::devnet(&config);
        let lanes = vec![
            ExecutionLaneRecord::new(
                "handler_bound_verifier",
                &handler_bound_roots.verifier_root,
                LaneExecutionStatus::Accepted,
                71,
                config.min_verifier_quorum_weight,
                "handler-bound release verifier quorum accepted the forced-exit release lane",
            ),
            ExecutionLaneRecord::new(
                "pq_custody",
                &handler_bound_roots.pq_custody_root,
                LaneExecutionStatus::Accepted,
                72,
                config.min_pq_custody_quorum_weight,
                "post-quantum custody quorum released the custody share envelope",
            ),
            ExecutionLaneRecord::new(
                "monero_broadcast",
                &handler_bound_roots.broadcast_root,
                LaneExecutionStatus::Accepted,
                24,
                config.min_broadcast_confirmations,
                "monero broadcast proof met confirmation and fee-bound requirements",
            ),
            ExecutionLaneRecord::new(
                "liquidity",
                &handler_bound_roots.liquidity_root,
                LaneExecutionStatus::Accepted,
                10_250,
                config.min_liquidity_coverage_bps,
                "liquidity coverage exceeds release execution coverage floor",
            ),
            ExecutionLaneRecord::new(
                "challenge_window",
                &handler_bound_roots.challenge_root,
                LaneExecutionStatus::Accepted,
                720,
                config.challenge_window_blocks,
                "challenge window closed without a blocking dispute root",
            ),
        ];
        let release_execution = ReleaseExecutionRecord::from_lanes(&lanes);

        Self {
            config,
            handler_bound_roots,
            lanes,
            release_execution,
        }
    }

    pub fn public_record(&self) -> Value {
        let lane_records = self
            .lanes
            .iter()
            .map(ExecutionLaneRecord::public_record)
            .collect::<Vec<_>>();

        json!({
            "config": self.config.public_record(),
            "handler_bound_roots": self.handler_bound_roots.public_record(),
            "lanes": lane_records,
            "release_execution": self.release_execution.public_record(),
            "config_root": self.config.state_root(),
            "handler_bound_roots_root": self.handler_bound_roots.state_root(),
            "lane_execution_root": self.release_execution.lane_execution_root,
            "release_execution_root": self.release_execution.release_execution_root
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
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

fn lane_set_root(lanes: &[ExecutionLaneRecord]) -> String {
    let records = lanes
        .iter()
        .map(ExecutionLaneRecord::public_record)
        .collect::<Vec<_>>();

    merkle_root(
        "monero-l2-pq-bridge-user-escape-handler-bound-release-execution-lanes",
        &records,
    )
}

fn lane_root(lane: &str, escape_id: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-handler-bound-release-execution-consumed-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(lane),
            HashPart::Str(escape_id),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-user-escape-handler-bound-release-execution-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn bool_label(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
