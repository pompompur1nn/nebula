use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalReleaseCandidateGoNoGoMatrixRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_CANDIDATE_GO_NO_GO_MATRIX_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-release-candidate-go-no-go-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_RELEASE_CANDIDATE_GO_NO_GO_MATRIX_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MATRIX_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-release-candidate-go-no-go-matrix-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-heavy-gate-release-candidate-devnet-v1";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixDomain {
    UserEscape,
    LiveFeeds,
    PqAuthority,
    Reserves,
    Privacy,
    FailureCases,
    WalletCliPayloads,
    CargoRuntimeExecution,
    Audits,
    ProductionRelease,
}

impl MatrixDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UserEscape => "user_escape",
            Self::LiveFeeds => "live_feeds",
            Self::PqAuthority => "pq_authority",
            Self::Reserves => "reserves",
            Self::Privacy => "privacy",
            Self::FailureCases => "failure_cases",
            Self::WalletCliPayloads => "wallet_cli_payloads",
            Self::CargoRuntimeExecution => "cargo_runtime_execution",
            Self::Audits => "audits",
            Self::ProductionRelease => "production_release",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Go,
    NoGo,
    Watch,
}

impl GateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGo => "no_go",
            Self::Watch => "watch",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Complete,
    DeterministicDevnet,
    PendingExecution,
    PendingAudit,
    ReleaseHold,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DeterministicDevnet => "deterministic_devnet",
            Self::PendingExecution => "pending_execution",
            Self::PendingAudit => "pending_audit",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub matrix_suite: String,
    pub release_candidate_id: String,
    pub monero_network: String,
    pub l2_network: String,
    pub requires_runtime_execution: bool,
    pub requires_audit_signoff: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            matrix_suite: MATRIX_SUITE.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            requires_runtime_execution: true,
            requires_audit_signoff: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "matrix_suite": self.matrix_suite,
            "release_candidate_id": self.release_candidate_id,
            "monero_network": self.monero_network,
            "l2_network": self.l2_network,
            "requires_runtime_execution": self.requires_runtime_execution,
            "requires_audit_signoff": self.requires_audit_signoff,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateEntry {
    pub domain: MatrixDomain,
    pub decision: GateDecision,
    pub evidence_status: EvidenceStatus,
    pub owner_lane: String,
    pub release_condition: String,
    pub evidence_root: String,
    pub blocks_heavy_gate_scheduling: bool,
    pub blocks_production_release: bool,
}

impl GateEntry {
    pub fn public_record(&self) -> Value {
        json!({
            "domain": self.domain.as_str(),
            "decision": self.decision.as_str(),
            "evidence_status": self.evidence_status.as_str(),
            "owner_lane": self.owner_lane,
            "release_condition": self.release_condition,
            "evidence_root": self.evidence_root,
            "blocks_heavy_gate_scheduling": self.blocks_heavy_gate_scheduling,
            "blocks_production_release": self.blocks_production_release,
            "entry_root": self.entry_root(),
        })
    }

    pub fn entry_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RC-GATE-ENTRY",
            &[
                HashPart::Str(self.domain.as_str()),
                HashPart::Str(self.decision.as_str()),
                HashPart::Str(self.evidence_status.as_str()),
                HashPart::Str(&self.owner_lane),
                HashPart::Str(&self.release_condition),
                HashPart::Str(&self.evidence_root),
                HashPart::Str(bool_str(self.blocks_heavy_gate_scheduling)),
                HashPart::Str(bool_str(self.blocks_production_release)),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeavyGateSchedule {
    pub schedule_id: String,
    pub activation_height: u64,
    pub forced_exit_window_blocks: u64,
    pub challenge_window_blocks: u64,
    pub max_concurrent_exits: u64,
    pub decision: GateDecision,
    pub reason: String,
}

impl HeavyGateSchedule {
    pub fn public_record(&self) -> Value {
        json!({
            "schedule_id": self.schedule_id,
            "activation_height": self.activation_height,
            "forced_exit_window_blocks": self.forced_exit_window_blocks,
            "challenge_window_blocks": self.challenge_window_blocks,
            "max_concurrent_exits": self.max_concurrent_exits,
            "decision": self.decision.as_str(),
            "reason": self.reason,
            "schedule_root": self.schedule_root(),
        })
    }

    pub fn schedule_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RC-HEAVY-GATE-SCHEDULE",
            &[
                HashPart::Str(&self.schedule_id),
                HashPart::U64(self.activation_height),
                HashPart::U64(self.forced_exit_window_blocks),
                HashPart::U64(self.challenge_window_blocks),
                HashPart::U64(self.max_concurrent_exits),
                HashPart::Str(self.decision.as_str()),
                HashPart::Str(&self.reason),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevnetData {
    pub devnet_id: String,
    pub l2_reference_height: u64,
    pub monero_reference_height: u64,
    pub canonical_exit_batch_root: String,
    pub live_feed_root: String,
    pub pq_authority_root: String,
    pub reserve_snapshot_root: String,
    pub privacy_review_root: String,
    pub failure_case_root: String,
    pub wallet_cli_payload_root: String,
}

impl DevnetData {
    pub fn public_record(&self) -> Value {
        json!({
            "devnet_id": self.devnet_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "canonical_exit_batch_root": self.canonical_exit_batch_root,
            "live_feed_root": self.live_feed_root,
            "pq_authority_root": self.pq_authority_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "privacy_review_root": self.privacy_review_root,
            "failure_case_root": self.failure_case_root,
            "wallet_cli_payload_root": self.wallet_cli_payload_root,
            "devnet_data_root": self.devnet_data_root(),
        })
    }

    pub fn devnet_data_root(&self) -> String {
        record_root("DEVNET-DATA", &self.public_record_without_root())
    }

    fn public_record_without_root(&self) -> Value {
        json!({
            "devnet_id": self.devnet_id,
            "l2_reference_height": self.l2_reference_height,
            "monero_reference_height": self.monero_reference_height,
            "canonical_exit_batch_root": self.canonical_exit_batch_root,
            "live_feed_root": self.live_feed_root,
            "pq_authority_root": self.pq_authority_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
            "privacy_review_root": self.privacy_review_root,
            "failure_case_root": self.failure_case_root,
            "wallet_cli_payload_root": self.wallet_cli_payload_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub devnet_data: DevnetData,
    pub heavy_gate_schedule: HeavyGateSchedule,
    pub gates: Vec<GateEntry>,
    pub heavy_gate_scheduling_decision: GateDecision,
    pub production_release_decision: GateDecision,
}

impl State {
    pub fn public_record(&self) -> Value {
        let gate_records = self
            .gates
            .iter()
            .map(GateEntry::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "devnet_data": self.devnet_data.public_record(),
            "heavy_gate_schedule": self.heavy_gate_schedule.public_record(),
            "gates": gate_records,
            "gate_matrix_root": self.gate_matrix_root(),
            "heavy_gate_scheduling_decision": self.heavy_gate_scheduling_decision.as_str(),
            "production_release_decision": self.production_release_decision.as_str(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RC-GO-NO-GO-STATE",
            &[
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&self.devnet_data.devnet_data_root()),
                HashPart::Str(&self.heavy_gate_schedule.schedule_root()),
                HashPart::Str(&self.gate_matrix_root()),
                HashPart::Str(self.heavy_gate_scheduling_decision.as_str()),
                HashPart::Str(self.production_release_decision.as_str()),
            ],
            32,
        )
    }

    pub fn gate_matrix_root(&self) -> String {
        let records = self
            .gates
            .iter()
            .map(GateEntry::public_record)
            .collect::<Vec<_>>();
        merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-RC-GO-NO-GO-MATRIX", &records)
    }
}

pub fn devnet() -> State {
    let devnet_data = DevnetData {
        devnet_id: "monero-l2-pq-bridge-exit-rc-devnet-2026-06-18".to_string(),
        l2_reference_height: 4_220_144,
        monero_reference_height: 3_510_400,
        canonical_exit_batch_root: seed_root("canonical-exit-batch"),
        live_feed_root: seed_root("live-feed-heartbeats"),
        pq_authority_root: seed_root("pq-authority-quorum"),
        reserve_snapshot_root: seed_root("reserve-snapshot"),
        privacy_review_root: seed_root("privacy-envelope"),
        failure_case_root: seed_root("failure-case-corpus"),
        wallet_cli_payload_root: seed_root("wallet-cli-payloads"),
    };

    let heavy_gate_schedule = HeavyGateSchedule {
        schedule_id: "heavy-gate-schedule-devnet-activation-4220800".to_string(),
        activation_height: 4_220_800,
        forced_exit_window_blocks: 720,
        challenge_window_blocks: 288,
        max_concurrent_exits: 64,
        decision: GateDecision::Go,
        reason: "deterministic devnet evidence clears bridge forced-exit heavy-gate scheduling"
            .to_string(),
    };

    let gates = vec![
        gate(
            MatrixDomain::UserEscape,
            GateDecision::Go,
            EvidenceStatus::DeterministicDevnet,
            "protocol_safety",
            "forced-exit escape path accepts canonical user claim batches",
            &devnet_data.canonical_exit_batch_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::LiveFeeds,
            GateDecision::Go,
            EvidenceStatus::DeterministicDevnet,
            "operator_integration",
            "watcher and sequencer feeds are fresh for scheduling",
            &devnet_data.live_feed_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::PqAuthority,
            GateDecision::Go,
            EvidenceStatus::Complete,
            "pq_key_management",
            "post-quantum authority quorum signs the release-candidate schedule",
            &devnet_data.pq_authority_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::Reserves,
            GateDecision::Go,
            EvidenceStatus::DeterministicDevnet,
            "reserve_liquidity",
            "reserve snapshot covers the scheduled forced-exit batch on devnet",
            &devnet_data.reserve_snapshot_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::Privacy,
            GateDecision::Go,
            EvidenceStatus::DeterministicDevnet,
            "privacy",
            "release-candidate records remain roots-only for user and wallet metadata",
            &devnet_data.privacy_review_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::FailureCases,
            GateDecision::Go,
            EvidenceStatus::DeterministicDevnet,
            "protocol_safety",
            "challenge, timeout, replay, duplicate, and reserve-gap cases are represented",
            &devnet_data.failure_case_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::WalletCliPayloads,
            GateDecision::Go,
            EvidenceStatus::Complete,
            "wallet_cli",
            "wallet payload roots match the canonical forced-exit admission envelope",
            &devnet_data.wallet_cli_payload_root,
            false,
            false,
        ),
        gate(
            MatrixDomain::CargoRuntimeExecution,
            GateDecision::NoGo,
            EvidenceStatus::PendingExecution,
            "cargo_runtime",
            "production release waits for explicit runtime execution outside this shard",
            &seed_root("cargo-runtime-execution-pending"),
            false,
            true,
        ),
        gate(
            MatrixDomain::Audits,
            GateDecision::NoGo,
            EvidenceStatus::PendingAudit,
            "security_audit",
            "production release waits for completed bridge, privacy, and reserve audits",
            &seed_root("audit-signoff-pending"),
            false,
            true,
        ),
        gate(
            MatrixDomain::ProductionRelease,
            GateDecision::NoGo,
            EvidenceStatus::ReleaseHold,
            "production_governance",
            "production release remains held until execution and audits complete",
            &seed_root("production-release-hold"),
            false,
            true,
        ),
    ];

    State {
        config: Config::devnet(),
        devnet_data,
        heavy_gate_schedule,
        gates,
        heavy_gate_scheduling_decision: GateDecision::Go,
        production_release_decision: GateDecision::NoGo,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn gate(
    domain: MatrixDomain,
    decision: GateDecision,
    evidence_status: EvidenceStatus,
    owner_lane: &str,
    release_condition: &str,
    evidence_root: &str,
    blocks_heavy_gate_scheduling: bool,
    blocks_production_release: bool,
) -> GateEntry {
    GateEntry {
        domain,
        decision,
        evidence_status,
        owner_lane: owner_lane.to_string(),
        release_condition: release_condition.to_string(),
        evidence_root: evidence_root.to_string(),
        blocks_heavy_gate_scheduling,
        blocks_production_release,
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RC-GO-NO-GO-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn seed_root(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RC-GO-NO-GO-SEED",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(label)],
        32,
    )
}
