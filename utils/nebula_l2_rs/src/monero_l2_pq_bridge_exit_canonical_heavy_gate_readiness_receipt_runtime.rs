use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalHeavyGateReadinessReceiptRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_READINESS_RECEIPT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-heavy-gate-readiness-receipt-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_HEAVY_GATE_READINESS_RECEIPT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RECEIPT_SUITE: &str = "monero-l2-pq-bridge-exit-canonical-heavy-gate-readiness-v1";
pub const DEFAULT_MIN_SCHEDULE_READY_LANES: u64 = 6;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLaneKind {
    ReplayBundle,
    LiveFeedBoundary,
    WalletClaimExport,
    PqKeyRotation,
    ReserveProofHandoff,
    PrivacyAuditArtifacts,
    ProductionBlockers,
    HeavyGateExecutionStatus,
}

impl EvidenceLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayBundle => "replay_bundle",
            Self::LiveFeedBoundary => "live_feed_boundary",
            Self::WalletClaimExport => "wallet_claim_export",
            Self::PqKeyRotation => "pq_key_rotation",
            Self::ReserveProofHandoff => "reserve_proof_handoff",
            Self::PrivacyAuditArtifacts => "privacy_audit_artifacts",
            Self::ProductionBlockers => "production_blockers",
            Self::HeavyGateExecutionStatus => "heavy_gate_execution_status",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceLaneStatus {
    Ready,
    Deferred,
    Blocked,
}

impl EvidenceLaneStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessAnswer {
    ScheduleReady,
    NotReady,
}

impl ReadinessAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScheduleReady => "schedule_ready",
            Self::NotReady => "not_ready",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub receipt_suite: String,
    pub min_schedule_ready_lanes: u64,
    pub cargo_execution_deferred: bool,
    pub runtime_execution_deferred: bool,
    pub hard_execution_evidence_required: bool,
    pub external_audit_evidence_required: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            receipt_suite: RECEIPT_SUITE.to_string(),
            min_schedule_ready_lanes: DEFAULT_MIN_SCHEDULE_READY_LANES,
            cargo_execution_deferred: true,
            runtime_execution_deferred: true,
            hard_execution_evidence_required: true,
            external_audit_evidence_required: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "receipt_suite": self.receipt_suite,
            "min_schedule_ready_lanes": self.min_schedule_ready_lanes,
            "cargo_execution_deferred": self.cargo_execution_deferred,
            "runtime_execution_deferred": self.runtime_execution_deferred,
            "hard_execution_evidence_required": self.hard_execution_evidence_required,
            "external_audit_evidence_required": self.external_audit_evidence_required,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvidenceLane {
    pub lane_id: String,
    pub kind: EvidenceLaneKind,
    pub status: EvidenceLaneStatus,
    pub schedule_gate_ready: bool,
    pub production_blocker: bool,
    pub deferred_execution: bool,
    pub evidence_label: String,
    pub observed: String,
    pub required_before_production: String,
    pub source_commitment: String,
    pub lane_root: String,
}

impl EvidenceLane {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EvidenceLaneKind,
        status: EvidenceLaneStatus,
        schedule_gate_ready: bool,
        production_blocker: bool,
        deferred_execution: bool,
        evidence_label: impl Into<String>,
        observed: impl Into<String>,
        required_before_production: impl Into<String>,
        source_commitment: impl Into<String>,
    ) -> Self {
        let evidence_label = evidence_label.into();
        let observed = observed.into();
        let required_before_production = required_before_production.into();
        let source_commitment = source_commitment.into();
        let lane_root = evidence_lane_root(
            kind,
            status,
            schedule_gate_ready,
            production_blocker,
            deferred_execution,
            &evidence_label,
            &observed,
            &required_before_production,
            &source_commitment,
        );
        let lane_id = evidence_lane_id(kind, &lane_root);
        Self {
            lane_id,
            kind,
            status,
            schedule_gate_ready,
            production_blocker,
            deferred_execution,
            evidence_label,
            observed,
            required_before_production,
            source_commitment,
            lane_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "schedule_gate_ready": self.schedule_gate_ready,
            "production_blocker": self.production_blocker,
            "deferred_execution": self.deferred_execution,
            "evidence_label": self.evidence_label,
            "observed": self.observed,
            "required_before_production": self.required_before_production,
            "source_commitment": self.source_commitment,
            "lane_root": self.lane_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("evidence_lane", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeavyGateReadinessReceipt {
    pub receipt_id: String,
    pub answer: ReadinessAnswer,
    pub heavy_gates_may_be_scheduled: bool,
    pub heavy_gates_executed: bool,
    pub production_release_blocked: bool,
    pub canonical_answer: String,
    pub cargo_runtime_execution: String,
    pub readiness_lanes_total: u64,
    pub schedule_ready_lanes: u64,
    pub deferred_lanes: u64,
    pub blocked_lanes: u64,
    pub production_blockers: u64,
    pub lanes: BTreeMap<String, EvidenceLane>,
    pub roots: HeavyGateReadinessRoots,
}

impl HeavyGateReadinessReceipt {
    pub fn public_record(&self) -> Value {
        let lanes = self
            .lanes
            .values()
            .map(EvidenceLane::public_record)
            .collect::<Vec<_>>();
        json!({
            "receipt_id": self.receipt_id,
            "answer": self.answer.as_str(),
            "heavy_gates_may_be_scheduled": self.heavy_gates_may_be_scheduled,
            "heavy_gates_executed": self.heavy_gates_executed,
            "production_release_blocked": self.production_release_blocked,
            "canonical_answer": self.canonical_answer,
            "cargo_runtime_execution": self.cargo_runtime_execution,
            "readiness_lanes_total": self.readiness_lanes_total,
            "schedule_ready_lanes": self.schedule_ready_lanes,
            "deferred_lanes": self.deferred_lanes,
            "blocked_lanes": self.blocked_lanes,
            "production_blockers": self.production_blockers,
            "lanes": lanes,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("heavy_gate_readiness_receipt", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HeavyGateReadinessRoots {
    pub lane_root: String,
    pub schedule_root: String,
    pub production_blocker_root: String,
    pub deferred_execution_root: String,
    pub receipt_root: String,
}

impl HeavyGateReadinessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_root": self.lane_root,
            "schedule_root": self.schedule_root,
            "production_blocker_root": self.production_blocker_root,
            "deferred_execution_root": self.deferred_execution_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub receipt: HeavyGateReadinessReceipt,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let lanes = devnet_lanes();
        let receipt = build_receipt(&config, lanes);
        let state_record = json!({
            "config_root": config.state_root(),
            "receipt_root": receipt.state_root(),
        });
        let state_root = record_root("state", &state_record);
        Self {
            config,
            receipt,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "receipt": self.receipt.public_record(),
            "state_root": self.state_root,
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
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

fn devnet_lanes() -> Vec<EvidenceLane> {
    vec![
        EvidenceLane::new(
            EvidenceLaneKind::ReplayBundle,
            EvidenceLaneStatus::Ready,
            true,
            false,
            false,
            "forced-exit replay bundle",
            "canonical replay vectors are sealed for bridge exit scheduling evidence",
            "retain replay bundle hash with heavy-gate execution transcript",
            source_commitment("replay-bundle-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::LiveFeedBoundary,
            EvidenceLaneStatus::Ready,
            true,
            false,
            false,
            "live feed boundary",
            "live Monero feed remains bounded at adapter ingress and does not imply production execution",
            "bind actual live-feed adapter output into the hard execution receipt",
            source_commitment("live-feed-boundary-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::WalletClaimExport,
            EvidenceLaneStatus::Ready,
            true,
            false,
            false,
            "wallet claim export",
            "redacted wallet claim export contains forced-exit user answer material",
            "attach audited wallet export manifest to release evidence",
            source_commitment("wallet-claim-export-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::PqKeyRotation,
            EvidenceLaneStatus::Ready,
            true,
            false,
            false,
            "PQ key rotation",
            "post-quantum authority rotation handoff is represented by deterministic commitments",
            "capture live signer quorum and rotation proof during hard execution",
            source_commitment("pq-key-rotation-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::ReserveProofHandoff,
            EvidenceLaneStatus::Ready,
            true,
            false,
            false,
            "reserve proof handoff",
            "reserve proof handoff is present as a canonical receipt lane",
            "replace devnet commitment with production reserve proof and custodian attestation",
            source_commitment("reserve-proof-handoff-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::PrivacyAuditArtifacts,
            EvidenceLaneStatus::Deferred,
            true,
            true,
            true,
            "privacy audit artifacts",
            "artifact inventory is sufficient to schedule heavy gates, while external audit evidence is deferred",
            "complete privacy audit review and attach signed findings closure",
            source_commitment("privacy-audit-artifacts-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::ProductionBlockers,
            EvidenceLaneStatus::Blocked,
            false,
            true,
            true,
            "production blockers",
            "production release remains blocked by missing hard execution and audit evidence",
            "execute heavy gates and close release audit blockers",
            source_commitment("production-blockers-devnet-rc"),
        ),
        EvidenceLane::new(
            EvidenceLaneKind::HeavyGateExecutionStatus,
            EvidenceLaneStatus::Deferred,
            true,
            true,
            true,
            "heavy-gate execution status",
            "heavy gates are ready to be scheduled but have not been executed in cargo or runtime",
            "record hard cargo/runtime execution receipt before production release",
            source_commitment("heavy-gate-execution-status-devnet-rc"),
        ),
    ]
}

fn build_receipt(config: &Config, lanes: Vec<EvidenceLane>) -> HeavyGateReadinessReceipt {
    let lanes_by_id = lanes
        .into_iter()
        .map(|lane| (lane.lane_id.clone(), lane))
        .collect::<BTreeMap<_, _>>();
    let readiness_lanes_total = lanes_by_id.len() as u64;
    let schedule_ready_lanes = lanes_by_id
        .values()
        .filter(|lane| lane.schedule_gate_ready)
        .count() as u64;
    let deferred_lanes = lanes_by_id
        .values()
        .filter(|lane| lane.status == EvidenceLaneStatus::Deferred)
        .count() as u64;
    let blocked_lanes = lanes_by_id
        .values()
        .filter(|lane| lane.status == EvidenceLaneStatus::Blocked)
        .count() as u64;
    let production_blockers = lanes_by_id
        .values()
        .filter(|lane| lane.production_blocker)
        .count() as u64;
    let heavy_gates_may_be_scheduled =
        schedule_ready_lanes >= config.min_schedule_ready_lanes && blocked_lanes <= 1;
    let heavy_gates_executed = false;
    let production_release_blocked = production_blockers > 0 || !config.production_release_allowed;
    let answer = if heavy_gates_may_be_scheduled {
        ReadinessAnswer::ScheduleReady
    } else {
        ReadinessAnswer::NotReady
    };
    let roots = readiness_roots(&lanes_by_id);
    let receipt_basis = json!({
        "chain_id": config.chain_id,
        "protocol_version": config.protocol_version,
        "answer": answer.as_str(),
        "heavy_gates_may_be_scheduled": heavy_gates_may_be_scheduled,
        "heavy_gates_executed": heavy_gates_executed,
        "production_release_blocked": production_release_blocked,
        "lane_root": roots.lane_root.clone(),
        "production_blocker_root": roots.production_blocker_root.clone(),
        "deferred_execution_root": roots.deferred_execution_root.clone(),
    });
    let receipt_id = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-READINESS-RECEIPT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Json(&receipt_basis),
        ],
        32,
    );
    let roots = HeavyGateReadinessRoots {
        receipt_root: record_root("receipt_basis", &receipt_basis),
        ..roots
    };
    HeavyGateReadinessReceipt {
        receipt_id,
        answer,
        heavy_gates_may_be_scheduled,
        heavy_gates_executed,
        production_release_blocked,
        canonical_answer: "heavy gates may be scheduled for the release candidate; cargo/runtime execution is deferred and production release remains blocked until hard execution and audit evidence exist".to_string(),
        cargo_runtime_execution: "deferred".to_string(),
        readiness_lanes_total,
        schedule_ready_lanes,
        deferred_lanes,
        blocked_lanes,
        production_blockers,
        lanes: lanes_by_id,
        roots,
    }
}

fn readiness_roots(lanes: &BTreeMap<String, EvidenceLane>) -> HeavyGateReadinessRoots {
    let lane_records = lanes
        .values()
        .map(EvidenceLane::public_record)
        .collect::<Vec<_>>();
    let schedule_records = lanes
        .values()
        .filter(|lane| lane.schedule_gate_ready)
        .map(EvidenceLane::public_record)
        .collect::<Vec<_>>();
    let production_blocker_records = lanes
        .values()
        .filter(|lane| lane.production_blocker)
        .map(EvidenceLane::public_record)
        .collect::<Vec<_>>();
    let deferred_execution_records = lanes
        .values()
        .filter(|lane| lane.deferred_execution)
        .map(EvidenceLane::public_record)
        .collect::<Vec<_>>();
    HeavyGateReadinessRoots {
        lane_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-LANES",
            &lane_records,
        ),
        schedule_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-SCHEDULE-READY",
            &schedule_records,
        ),
        production_blocker_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-PRODUCTION-BLOCKERS",
            &production_blocker_records,
        ),
        deferred_execution_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-DEFERRED-EXECUTION",
            &deferred_execution_records,
        ),
        receipt_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-RECEIPT-PENDING",
            &[],
        ),
    }
}

fn evidence_lane_root(
    kind: EvidenceLaneKind,
    status: EvidenceLaneStatus,
    schedule_gate_ready: bool,
    production_blocker: bool,
    deferred_execution: bool,
    evidence_label: &str,
    observed: &str,
    required_before_production: &str,
    source_commitment: &str,
) -> String {
    let payload = json!({
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "kind": kind.as_str(),
        "status": status.as_str(),
        "schedule_gate_ready": schedule_gate_ready,
        "production_blocker": production_blocker,
        "deferred_execution": deferred_execution,
        "evidence_label": evidence_label,
        "observed": observed,
        "required_before_production": required_before_production,
        "source_commitment": source_commitment,
    });
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-EVIDENCE-LANE",
        &[HashPart::Json(&payload)],
        32,
    )
}

fn evidence_lane_id(kind: EvidenceLaneKind, lane_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-EVIDENCE-LANE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane_root),
        ],
        20,
    )
}

fn source_commitment(label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-SOURCE-COMMITMENT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-HEAVY-GATE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::U64(SCHEMA_VERSION),
            HashPart::Json(record),
        ],
        32,
    )
}
