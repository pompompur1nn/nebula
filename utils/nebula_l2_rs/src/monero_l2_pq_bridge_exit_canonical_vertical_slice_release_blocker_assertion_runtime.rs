use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalVerticalSliceReleaseBlockerAssertionRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_ASSERTION_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-assertion-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_VERTICAL_SLICE_RELEASE_BLOCKER_ASSERTION_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const ASSERTION_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-blocker-assertions-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-forced-exit-vertical-slice-devnet-v1";
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-vertical-slice-release-candidate-devnet-v1";
pub const REQUIRED_BLOCKER_COUNT: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    CargoRuntimeDeferred,
    LiveFeedNotSwapped,
    ForcedExitNotExecuted,
    IndependentAuditOpen,
    PrivacyReviewOpen,
    PqKeyVerificationPending,
    ReserveProofHandoffPending,
    ProductionReleaseHeld,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeDeferred => "cargo_runtime_deferred",
            Self::LiveFeedNotSwapped => "live_feed_not_swapped",
            Self::ForcedExitNotExecuted => "forced_exit_not_executed",
            Self::IndependentAuditOpen => "independent_audit_open",
            Self::PrivacyReviewOpen => "privacy_review_open",
            Self::PqKeyVerificationPending => "pq_key_verification_pending",
            Self::ReserveProofHandoffPending => "reserve_proof_handoff_pending",
            Self::ProductionReleaseHeld => "production_release_held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    RuntimeHarness,
    LiveFeedIntegration,
    ForcedExitExecution,
    IndependentAudit,
    PrivacyReview,
    PqAuthority,
    ReserveProof,
    ReleaseGovernance,
}

impl BlockerLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeHarness => "runtime_harness",
            Self::LiveFeedIntegration => "live_feed_integration",
            Self::ForcedExitExecution => "forced_exit_execution",
            Self::IndependentAudit => "independent_audit",
            Self::PrivacyReview => "privacy_review",
            Self::PqAuthority => "pq_authority",
            Self::ReserveProof => "reserve_proof",
            Self::ReleaseGovernance => "release_governance",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Deferred,
    PendingSwap,
    PendingExecution,
    Open,
    PendingVerification,
    PendingHandoff,
    Held,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::PendingSwap => "pending_swap",
            Self::PendingExecution => "pending_execution",
            Self::Open => "open",
            Self::PendingVerification => "pending_verification",
            Self::PendingHandoff => "pending_handoff",
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseDisposition {
    Blocked,
    Held,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blocked => "blocked",
            Self::Held => "held",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub assertion_suite: String,
    pub vertical_slice_id: String,
    pub release_candidate_id: String,
    pub required_blocker_count: usize,
    pub requires_public_record: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            assertion_suite: ASSERTION_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            required_blocker_count: REQUIRED_BLOCKER_COUNT,
            requires_public_record: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "assertion_suite": self.assertion_suite,
            "vertical_slice_id": self.vertical_slice_id,
            "release_candidate_id": self.release_candidate_id,
            "required_blocker_count": self.required_blocker_count,
            "requires_public_record": self.requires_public_record,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("CONFIG", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseBlockerAssertion {
    pub kind: BlockerKind,
    pub lane: BlockerLane,
    pub status: BlockerStatus,
    pub severity: BlockerSeverity,
    pub assertion: String,
    pub release_condition: String,
    pub evidence_root: String,
    pub blocks_forced_exit_release: bool,
    pub blocks_production_release: bool,
}

impl ReleaseBlockerAssertion {
    pub fn new(
        kind: BlockerKind,
        lane: BlockerLane,
        status: BlockerStatus,
        severity: BlockerSeverity,
        assertion: impl Into<String>,
        release_condition: impl Into<String>,
    ) -> Self {
        let assertion = assertion.into();
        let release_condition = release_condition.into();
        let evidence_root = evidence_root(kind, lane, status, &assertion, &release_condition);

        Self {
            kind,
            lane,
            status,
            severity,
            assertion,
            release_condition,
            evidence_root,
            blocks_forced_exit_release: true,
            blocks_production_release: true,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "severity_score": self.severity.score(),
            "assertion": self.assertion,
            "release_condition": self.release_condition,
            "evidence_root": self.evidence_root,
            "blocks_forced_exit_release": self.blocks_forced_exit_release,
            "blocks_production_release": self.blocks_production_release,
        })
    }

    pub fn assertion_root(&self) -> String {
        record_root("ASSERTION", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub blockers: Vec<ReleaseBlockerAssertion>,
    pub disposition: ReleaseDisposition,
}

impl State {
    pub fn devnet() -> Self {
        Self {
            config: Config::devnet(),
            blockers: deterministic_blockers(),
            disposition: ReleaseDisposition::Blocked,
        }
    }

    pub fn public_record(&self) -> Value {
        let assertion_records = self
            .blockers
            .iter()
            .map(ReleaseBlockerAssertion::public_record)
            .collect::<Vec<_>>();

        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_vertical_slice_release_blocker_assertion_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "config": self.config.public_record(),
            "disposition": self.disposition.as_str(),
            "required_blocker_count": self.config.required_blocker_count,
            "blocker_count": self.blockers.len(),
            "blocks_forced_exit_release": self.blocks_forced_exit_release(),
            "blocks_production_release": self.blocks_production_release(),
            "assertion_root": assertion_collection_root(&assertion_records),
            "assertions": assertion_records,
        })
    }

    pub fn state_root(&self) -> String {
        state_root_from_record(&self.public_record())
    }

    pub fn blocks_forced_exit_release(&self) -> bool {
        self.blockers
            .iter()
            .any(|blocker| blocker.blocks_forced_exit_release)
    }

    pub fn blocks_production_release(&self) -> bool {
        !self.config.production_release_allowed
            || self
                .blockers
                .iter()
                .any(|blocker| blocker.blocks_production_release)
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err("release blocker assertion config chain_id mismatch".to_string());
        }
        if self.config.protocol_version != PROTOCOL_VERSION {
            return Err("release blocker assertion protocol version mismatch".to_string());
        }
        if self.config.schema_version != SCHEMA_VERSION {
            return Err("release blocker assertion schema version mismatch".to_string());
        }
        if self.config.hash_suite != HASH_SUITE {
            return Err("release blocker assertion hash suite mismatch".to_string());
        }
        if self.blockers.len() != self.config.required_blocker_count {
            return Err("release blocker assertion count mismatch".to_string());
        }
        if !self.blocks_production_release() {
            return Err("release blocker assertion state must hold production release".to_string());
        }

        Ok(())
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
    State::devnet().public_record()
}

pub fn state_root() -> String {
    State::devnet().state_root()
}

pub fn deterministic_blockers() -> Vec<ReleaseBlockerAssertion> {
    vec![
        ReleaseBlockerAssertion::new(
            BlockerKind::CargoRuntimeDeferred,
            BlockerLane::RuntimeHarness,
            BlockerStatus::Deferred,
            BlockerSeverity::ReleaseStop,
            "cargo/runtime execution remains deferred for the forced-exit vertical slice",
            "run the owned cargo runtime harness and publish deterministic receipts",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::LiveFeedNotSwapped,
            BlockerLane::LiveFeedIntegration,
            BlockerStatus::PendingSwap,
            BlockerSeverity::Critical,
            "live Monero and L2 feeds are still using stubbed devnet adapters",
            "swap stub feeds for live-feed boundary contracts with replayable receipts",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::ForcedExitNotExecuted,
            BlockerLane::ForcedExitExecution,
            BlockerStatus::PendingExecution,
            BlockerSeverity::ReleaseStop,
            "canonical forced-exit path has not executed end to end",
            "execute deposit lock, private note transfer, forced exit claim, and settlement receipt",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::IndependentAuditOpen,
            BlockerLane::IndependentAudit,
            BlockerStatus::Open,
            BlockerSeverity::ReleaseStop,
            "independent audit signoff is open for the release candidate",
            "attach independent audit closure with scope, findings, and remediation roots",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::PrivacyReviewOpen,
            BlockerLane::PrivacyReview,
            BlockerStatus::Open,
            BlockerSeverity::Critical,
            "privacy review remains open for wallet recovery and forced-exit evidence",
            "publish privacy review closure for linkage, metadata, and watcher evidence exposure",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::PqKeyVerificationPending,
            BlockerLane::PqAuthority,
            BlockerStatus::PendingVerification,
            BlockerSeverity::Critical,
            "post-quantum release authority keys are pending verification",
            "verify PQ key ceremony, rotation drill, quorum transcript, and watcher attestations",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::ReserveProofHandoffPending,
            BlockerLane::ReserveProof,
            BlockerStatus::PendingHandoff,
            BlockerSeverity::Critical,
            "reserve proof handoff is pending for settlement liquidity",
            "handoff reserve proof manifest with reserve snapshot and release authority roots",
        ),
        ReleaseBlockerAssertion::new(
            BlockerKind::ProductionReleaseHeld,
            BlockerLane::ReleaseGovernance,
            BlockerStatus::Held,
            BlockerSeverity::ReleaseStop,
            "production release is held until every blocker is cleared",
            "flip production release only after runtime, audit, privacy, PQ, reserve, and live-feed evidence clears",
        ),
    ]
}

pub fn state_root_from_record(record: &Value) -> String {
    record_root("STATE", record)
}

fn evidence_root(
    kind: BlockerKind,
    lane: BlockerLane,
    status: BlockerStatus,
    assertion: &str,
    release_condition: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-EVIDENCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind.as_str()),
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(assertion),
            HashPart::Str(release_condition),
        ],
        32,
    )
}

fn assertion_collection_root(records: &[Value]) -> String {
    if records.is_empty() {
        return merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-ASSERTION-EMPTY",
            &[],
        );
    }

    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-ASSERTION",
        records,
    )
}

fn record_root(label: &str, value: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-VERTICAL-SLICE-RELEASE-BLOCKER-ASSERTION-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(HASH_SUITE),
            HashPart::Str(label),
            HashPart::Json(value),
        ],
        32,
    )
}
