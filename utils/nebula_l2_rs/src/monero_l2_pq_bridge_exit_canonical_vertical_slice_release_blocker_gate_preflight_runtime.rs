use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerGatePreflightRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-preflight-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_GATE_PREFLIGHT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PREFLIGHT_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-gate-preflight-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-candidate-devnet-v1";
pub const REQUIRED_PREFLIGHT_BLOCKERS: usize = 10;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightBlockerKind {
    CargoRuntimeDeferred,
    LiveFeedSwapMissing,
    ForcedExitDrillMissing,
    IndependentAuditOpen,
    PrivacyLeakageReviewOpen,
    PqVerificationPending,
    ReserveProofMissing,
    ProductionReleaseHeld,
    ExpectedNoGoRoots,
    ReleaseHold,
}

impl PreflightBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::LiveFeedSwapMissing => "live_feed_swap_missing",
            Self::ForcedExitDrillMissing => "forced_exit_drill_missing",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::PrivacyLeakageReviewOpen => "privacy_leakage_review_open",
            Self::PqVerificationPending => "pq_verification_pending",
            Self::ReserveProofMissing => "reserve_proof_missing",
            Self::ProductionReleaseHeld => "production_release_held",
            Self::ExpectedNoGoRoots => "expected_no_go_roots",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightLane {
    CargoRuntime,
    FeedBoundary,
    ForcedExitDrill,
    IndependentAudit,
    PrivacyLeakage,
    PqVerification,
    ReserveProof,
    ReleaseGovernance,
    GateEvidence,
    ReleaseHold,
}

impl PreflightLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntime => "cargo_runtime",
            Self::FeedBoundary => "feed_boundary",
            Self::ForcedExitDrill => "forced_exit_drill",
            Self::IndependentAudit => "independent_audit",
            Self::PrivacyLeakage => "privacy_leakage",
            Self::PqVerification => "pq_verification",
            Self::ReserveProof => "reserve_proof",
            Self::ReleaseGovernance => "release_governance",
            Self::GateEvidence => "gate_evidence",
            Self::ReleaseHold => "release_hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightDecision {
    NoGo,
}

impl PreflightDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseHold {
    Held,
}

impl ReleaseHold {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub preflight_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub required_preflight_blockers: usize,
    pub cargo_runtime_execution_allowed: bool,
    pub release_execution_allowed: bool,
    pub requires_expected_no_go_roots: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            preflight_suite: PREFLIGHT_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            required_preflight_blockers: REQUIRED_PREFLIGHT_BLOCKERS,
            cargo_runtime_execution_allowed: false,
            release_execution_allowed: false,
            requires_expected_no_go_roots: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "preflight_suite": self.preflight_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "required_preflight_blockers": self.required_preflight_blockers,
            "cargo_runtime_execution_allowed": self.cargo_runtime_execution_allowed,
            "release_execution_allowed": self.release_execution_allowed,
            "requires_expected_no_go_roots": self.requires_expected_no_go_roots,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightEvidence {
    pub evidence_id: String,
    pub sequence: u64,
    pub kind: PreflightBlockerKind,
    pub lane: PreflightLane,
    pub decision: PreflightDecision,
    pub observed_status: String,
    pub blocked_action: String,
    pub required_clearance: String,
    pub no_go_root: String,
    pub evidence_root: String,
    pub cargo_runtime_blocked: bool,
    pub release_blocked: bool,
}

impl PreflightEvidence {
    pub fn new(
        sequence: u64,
        kind: PreflightBlockerKind,
        lane: PreflightLane,
        observed_status: impl Into<String>,
        blocked_action: impl Into<String>,
        required_clearance: impl Into<String>,
    ) -> Self {
        let decision = PreflightDecision::NoGo;
        let observed_status = observed_status.into();
        let blocked_action = blocked_action.into();
        let required_clearance = required_clearance.into();
        let no_go_root = preflight_no_go_root(
            sequence,
            kind,
            lane,
            decision,
            &observed_status,
            &blocked_action,
            &required_clearance,
        );
        let evidence_root = preflight_evidence_root(
            sequence,
            kind,
            lane,
            &observed_status,
            &blocked_action,
            &required_clearance,
            &no_go_root,
        );
        let evidence_id = preflight_evidence_id(sequence, kind, &evidence_root);

        Self {
            evidence_id,
            sequence,
            kind,
            lane,
            decision,
            observed_status,
            blocked_action,
            required_clearance,
            no_go_root,
            evidence_root,
            cargo_runtime_blocked: true,
            release_blocked: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "sequence": self.sequence,
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "decision": self.decision.as_str(),
            "observed_status": self.observed_status,
            "blocked_action": self.blocked_action,
            "required_clearance": self.required_clearance,
            "no_go_root": self.no_go_root,
            "evidence_root": self.evidence_root,
            "cargo_runtime_blocked": self.cargo_runtime_blocked,
            "release_blocked": self.release_blocked,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight_evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PreflightSummary {
    pub decision: PreflightDecision,
    pub release_hold: ReleaseHold,
    pub blocker_count: usize,
    pub cargo_runtime_blocker_count: usize,
    pub release_blocker_count: usize,
    pub evidence_root: String,
    pub expected_no_go_root: String,
    pub release_hold_root: String,
}

impl PreflightSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "decision": self.decision.as_str(),
            "release_hold": self.release_hold.as_str(),
            "blocker_count": self.blocker_count,
            "cargo_runtime_blocker_count": self.cargo_runtime_blocker_count,
            "release_blocker_count": self.release_blocker_count,
            "evidence_root": self.evidence_root,
            "expected_no_go_root": self.expected_no_go_root,
            "release_hold_root": self.release_hold_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("preflight_summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub preflight_evidence: BTreeMap<String, PreflightEvidence>,
    pub summary: PreflightSummary,
    pub config_root: String,
    pub preflight_evidence_root: String,
    pub expected_no_go_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let preflight_evidence = deterministic_preflight_evidence();
        match Self::from_parts(config, preflight_evidence) {
            Ok(state) => state,
            Err(error) => fallback_state(error),
        }
    }

    pub fn from_parts(
        config: Config,
        preflight_evidence: BTreeMap<String, PreflightEvidence>,
    ) -> Result<Self> {
        if config.chain_id != CHAIN_ID {
            return Err("release-blocker preflight chain_id mismatch".to_string());
        }
        if config.protocol_version != PROTOCOL_VERSION {
            return Err("release-blocker preflight protocol version mismatch".to_string());
        }
        if config.hash_suite != HASH_SUITE {
            return Err("release-blocker preflight hash suite mismatch".to_string());
        }
        if preflight_evidence.len() != config.required_preflight_blockers {
            return Err("release-blocker preflight blocker count mismatch".to_string());
        }

        let records = preflight_records(&preflight_evidence);
        let expected_records = expected_no_go_records(&preflight_evidence);
        let preflight_evidence_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-EVIDENCE",
            &records,
        );
        let expected_no_go_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-EXPECTED-NO-GO",
            &expected_records,
        );
        let release_hold_root = release_hold_root(&expected_no_go_root, &preflight_evidence_root);
        let summary = summarize_preflight(
            &preflight_evidence,
            &preflight_evidence_root,
            &expected_no_go_root,
            &release_hold_root,
        );
        let config_root = config.state_root();
        let summary_root = summary.state_root();
        let public_record = state_public_record(
            &config,
            &preflight_evidence,
            &summary,
            &config_root,
            &preflight_evidence_root,
            &expected_no_go_root,
            &summary_root,
        );
        let public_record_root = record_root("preflight_public_record", &public_record);
        let state_root = preflight_state_root(
            &config_root,
            &preflight_evidence_root,
            &expected_no_go_root,
            &summary_root,
            &public_record_root,
        );

        Ok(Self {
            config,
            preflight_evidence,
            summary,
            config_root,
            preflight_evidence_root,
            expected_no_go_root,
            summary_root,
            public_record_root,
            state_root,
        })
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.preflight_evidence,
            &self.summary,
            &self.config_root,
            &self.preflight_evidence_root,
            &self.expected_no_go_root,
            &self.summary_root,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn cargo_runtime_allowed(&self) -> bool {
        self.config.cargo_runtime_execution_allowed
            && self
                .preflight_evidence
                .values()
                .all(|evidence| !evidence.cargo_runtime_blocked)
    }

    pub fn release_allowed(&self) -> bool {
        self.config.release_execution_allowed
            && self
                .preflight_evidence
                .values()
                .all(|evidence| !evidence.release_blocked)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

impl Default for State {
    fn default() -> Self {
        Self::devnet()
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

pub fn deterministic_preflight_evidence() -> BTreeMap<String, PreflightEvidence> {
    let evidence = vec![
        PreflightEvidence::new(
            1,
            PreflightBlockerKind::CargoRuntimeDeferred,
            PreflightLane::CargoRuntime,
            "cargo_runtime_deferred",
            "cargo and runtime execution",
            "publish deterministic cargo/runtime receipts before execution is allowed",
        ),
        PreflightEvidence::new(
            2,
            PreflightBlockerKind::LiveFeedSwapMissing,
            PreflightLane::FeedBoundary,
            "live_feed_swap_missing",
            "bridge exit live feed execution",
            "swap fixture feeds to live boundary roots with replayable handoff evidence",
        ),
        PreflightEvidence::new(
            3,
            PreflightBlockerKind::ForcedExitDrillMissing,
            PreflightLane::ForcedExitDrill,
            "forced_exit_drill_missing",
            "forced-exit drill release",
            "complete deposit lock, note transfer, forced-exit claim, and settlement drill",
        ),
        PreflightEvidence::new(
            4,
            PreflightBlockerKind::IndependentAuditOpen,
            PreflightLane::IndependentAudit,
            "independent_audit_open",
            "release candidate promotion",
            "attach independent audit closure roots and remediation acceptance",
        ),
        PreflightEvidence::new(
            5,
            PreflightBlockerKind::PrivacyLeakageReviewOpen,
            PreflightLane::PrivacyLeakage,
            "privacy_leakage_review_open",
            "privacy-sensitive exit evidence publication",
            "close leakage review for linkage, metadata, watcher, and wallet evidence exposure",
        ),
        PreflightEvidence::new(
            6,
            PreflightBlockerKind::PqVerificationPending,
            PreflightLane::PqVerification,
            "pq_verification_pending",
            "post-quantum release authority",
            "verify PQ key bundle, rotation drill, quorum transcript, and watcher attestations",
        ),
        PreflightEvidence::new(
            7,
            PreflightBlockerKind::ReserveProofMissing,
            PreflightLane::ReserveProof,
            "reserve_proof_missing",
            "settlement liquidity release",
            "bind reserve proof manifest, reserve snapshot, and handoff acceptance roots",
        ),
        PreflightEvidence::new(
            8,
            PreflightBlockerKind::ProductionReleaseHeld,
            PreflightLane::ReleaseGovernance,
            "production_release_held",
            "production release execution",
            "clear runtime, feed, drill, audit, privacy, PQ, and reserve blockers",
        ),
        PreflightEvidence::new(
            9,
            PreflightBlockerKind::ExpectedNoGoRoots,
            PreflightLane::GateEvidence,
            "expected_no_go_roots_required",
            "runtime gate bypass",
            "preserve expected no-go roots before any cargo/runtime execution",
        ),
        PreflightEvidence::new(
            10,
            PreflightBlockerKind::ReleaseHold,
            PreflightLane::ReleaseHold,
            "release_hold_active",
            "forced-exit spine release",
            "keep release hold active until every no-go root is replaced by clearance evidence",
        ),
    ];

    evidence
        .into_iter()
        .map(|entry| (entry.kind.as_str().to_string(), entry))
        .collect()
}

fn summarize_preflight(
    evidence: &BTreeMap<String, PreflightEvidence>,
    evidence_root: &str,
    expected_no_go_root: &str,
    release_hold_root: &str,
) -> PreflightSummary {
    let cargo_runtime_blocker_count = evidence
        .values()
        .filter(|entry| entry.cargo_runtime_blocked)
        .count();
    let release_blocker_count = evidence
        .values()
        .filter(|entry| entry.release_blocked)
        .count();

    PreflightSummary {
        decision: PreflightDecision::NoGo,
        release_hold: ReleaseHold::Held,
        blocker_count: evidence.len(),
        cargo_runtime_blocker_count,
        release_blocker_count,
        evidence_root: evidence_root.to_string(),
        expected_no_go_root: expected_no_go_root.to_string(),
        release_hold_root: release_hold_root.to_string(),
    }
}

fn preflight_records(evidence: &BTreeMap<String, PreflightEvidence>) -> Vec<Value> {
    evidence
        .values()
        .map(PreflightEvidence::public_record)
        .collect()
}

fn expected_no_go_records(evidence: &BTreeMap<String, PreflightEvidence>) -> Vec<Value> {
    evidence
        .values()
        .map(|entry| {
            json!({
                "kind": entry.kind.as_str(),
                "lane": entry.lane.as_str(),
                "decision": entry.decision.as_str(),
                "no_go_root": entry.no_go_root,
            })
        })
        .collect()
}

fn state_public_record(
    config: &Config,
    evidence: &BTreeMap<String, PreflightEvidence>,
    summary: &PreflightSummary,
    config_root: &str,
    preflight_evidence_root: &str,
    expected_no_go_root: &str,
    summary_root: &str,
) -> Value {
    json!({
        "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_gate_preflight_state",
        "chain_id": CHAIN_ID,
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "config": config.public_record(),
        "preflight_evidence": preflight_records(evidence),
        "summary": summary.public_record(),
        "roots": {
            "config_root": config_root,
            "preflight_evidence_root": preflight_evidence_root,
            "expected_no_go_root": expected_no_go_root,
            "summary_root": summary_root,
        },
        "cargo_runtime_allowed": false,
        "release_allowed": false,
    })
}

fn preflight_no_go_root(
    sequence: u64,
    kind: PreflightBlockerKind,
    lane: PreflightLane,
    decision: PreflightDecision,
    observed_status: &str,
    blocked_action: &str,
    required_clearance: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-NO-GO",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(decision.as_str()),
            HashPart::Str(observed_status),
            HashPart::Str(blocked_action),
            HashPart::Str(required_clearance),
        ],
        32,
    )
}

fn preflight_evidence_root(
    sequence: u64,
    kind: PreflightBlockerKind,
    lane: PreflightLane,
    observed_status: &str,
    blocked_action: &str,
    required_clearance: &str,
    no_go_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-EVIDENCE-ITEM",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(observed_status),
            HashPart::Str(blocked_action),
            HashPart::Str(required_clearance),
            HashPart::Str(no_go_root),
        ],
        32,
    )
}

fn preflight_evidence_id(sequence: u64, kind: PreflightBlockerKind, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-EVIDENCE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(sequence),
            HashPart::Str(kind.as_str()),
            HashPart::Str(evidence_root),
        ],
        16,
    )
}

fn release_hold_root(expected_no_go_root: &str, evidence_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-RELEASE-HOLD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(ReleaseHold::Held.as_str()),
            HashPart::Str(PreflightDecision::NoGo.as_str()),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

fn preflight_state_root(
    config_root: &str,
    preflight_evidence_root: &str,
    expected_no_go_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(preflight_evidence_root),
            HashPart::Str(expected_no_go_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(error: String) -> State {
    let config = Config::devnet();
    let preflight_evidence = BTreeMap::new();
    let fallback_root = domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-GATE-PREFLIGHT-FALLBACK",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&error),
        ],
        32,
    );
    let summary = PreflightSummary {
        decision: PreflightDecision::NoGo,
        release_hold: ReleaseHold::Held,
        blocker_count: 0,
        cargo_runtime_blocker_count: 0,
        release_blocker_count: 0,
        evidence_root: fallback_root.clone(),
        expected_no_go_root: fallback_root.clone(),
        release_hold_root: fallback_root.clone(),
    };
    let config_root = config.state_root();
    let summary_root = summary.state_root();
    let public_record_root = record_root(
        "preflight_fallback_public_record",
        &json!({
            "error": error,
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
        }),
    );
    let state_root = preflight_state_root(
        &config_root,
        &fallback_root,
        &fallback_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        preflight_evidence,
        summary,
        config_root,
        preflight_evidence_root: fallback_root.clone(),
        expected_no_go_root: fallback_root,
        summary_root,
        public_record_root,
        state_root,
    }
}
