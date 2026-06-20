use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalProductionBlockerBurnDownRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRODUCTION_BLOCKER_BURN_DOWN_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-production-blocker-burn-down-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_PRODUCTION_BLOCKER_BURN_DOWN_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const BURN_DOWN_SUITE: &str =
    "monero-l2-pq-bridge-exit-canonical-production-blocker-burn-down-v1";
pub const DEFAULT_MIN_BLOCKERS: usize = 10;
pub const DEFAULT_RELEASE_CANDIDATE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-production-rc-devnet-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerLane {
    CargoRuntimeGates,
    LiveMoneroFeeds,
    LiveSettlementHandlers,
    PqKeyVerification,
    ReserveProof,
    PrivacyAudit,
    ForcedExitExecution,
    SecurityAudit,
    OperatorRunbook,
    ReleaseSignoff,
}

impl BlockerLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoRuntimeGates => "cargo_runtime_gates",
            Self::LiveMoneroFeeds => "live_monero_feeds",
            Self::LiveSettlementHandlers => "live_settlement_handlers",
            Self::PqKeyVerification => "pq_key_verification",
            Self::ReserveProof => "reserve_proof",
            Self::PrivacyAudit => "privacy_audit",
            Self::ForcedExitExecution => "forced_exit_execution",
            Self::SecurityAudit => "security_audit",
            Self::OperatorRunbook => "operator_runbook",
            Self::ReleaseSignoff => "release_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerStatus {
    Open,
    EvidenceImproving,
    EvidencePending,
    ExternalAuditPending,
    SignoffHold,
    Cleared,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::EvidenceImproving => "evidence_improving",
            Self::EvidencePending => "evidence_pending",
            Self::ExternalAuditPending => "external_audit_pending",
            Self::SignoffHold => "signoff_hold",
            Self::Cleared => "cleared",
        }
    }

    pub fn blocks_production(self) -> bool {
        !matches!(self, Self::Cleared)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Watch,
    Major,
    Critical,
    ReleaseStop,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Major => "major",
            Self::Critical => "critical",
            Self::ReleaseStop => "release_stop",
        }
    }

    pub fn score(self) -> u64 {
        match self {
            Self::Watch => 2,
            Self::Major => 3,
            Self::Critical => 4,
            Self::ReleaseStop => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerdict {
    ProductionBlocked,
    EvidenceWatch,
    ProductionClear,
}

impl ReleaseVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductionBlocked => "production_blocked",
            Self::EvidenceWatch => "evidence_watch",
            Self::ProductionClear => "production_clear",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub burn_down_suite: String,
    pub release_candidate_id: String,
    pub min_blockers: usize,
    pub require_hard_evidence: bool,
    pub user_escape_first: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            burn_down_suite: BURN_DOWN_SUITE.to_string(),
            release_candidate_id: DEFAULT_RELEASE_CANDIDATE_ID.to_string(),
            min_blockers: DEFAULT_MIN_BLOCKERS,
            require_hard_evidence: true,
            user_escape_first: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "burn_down_suite": self.burn_down_suite,
            "release_candidate_id": self.release_candidate_id,
            "min_blockers": self.min_blockers,
            "require_hard_evidence": self.require_hard_evidence,
            "user_escape_first": self.user_escape_first,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DevnetEvidence {
    pub devnet_id: String,
    pub epoch: u64,
    pub canonical_transcript_id: String,
    pub escape_design_status: String,
    pub production_release_status: String,
    pub hard_evidence_policy: String,
    pub canonical_replay_root: String,
    pub forced_exit_replay_root: String,
    pub settlement_handler_root: String,
    pub reserve_snapshot_root: String,
}

impl DevnetEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "devnet_id": self.devnet_id,
            "epoch": self.epoch,
            "canonical_transcript_id": self.canonical_transcript_id,
            "escape_design_status": self.escape_design_status,
            "production_release_status": self.production_release_status,
            "hard_evidence_policy": self.hard_evidence_policy,
            "canonical_replay_root": self.canonical_replay_root,
            "forced_exit_replay_root": self.forced_exit_replay_root,
            "settlement_handler_root": self.settlement_handler_root,
            "reserve_snapshot_root": self.reserve_snapshot_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("devnet-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionBlocker {
    pub blocker_id: String,
    pub lane: BlockerLane,
    pub status: BlockerStatus,
    pub severity: BlockerSeverity,
    pub burn_down_order: u64,
    pub owner: String,
    pub title: String,
    pub evidence_claim: String,
    pub hard_evidence_required: String,
    pub current_evidence_root: String,
    pub acceptance_root: String,
    pub dependency_root: String,
    pub blocks_user_escape: bool,
    pub blocks_production_release: bool,
    pub blocker_root: String,
}

impl ProductionBlocker {
    pub fn new(
        lane: BlockerLane,
        status: BlockerStatus,
        severity: BlockerSeverity,
        burn_down_order: u64,
        owner: &str,
        title: &str,
        evidence_claim: &str,
        hard_evidence_required: &str,
        blocks_user_escape: bool,
        devnet: &DevnetEvidence,
    ) -> Self {
        let current_evidence_root = lane_evidence_root(lane, status, evidence_claim, devnet);
        let acceptance_root = lane_acceptance_root(lane, hard_evidence_required);
        let dependency_root = lane_dependency_root(lane, &current_evidence_root, &acceptance_root);
        let blocker_id = blocker_id(lane, burn_down_order, &dependency_root);
        let blocks_production_release = status.blocks_production();
        let blocker_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-BLOCKER",
            &[
                HashPart::Str(&blocker_id),
                HashPart::Str(lane.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::U64(burn_down_order),
                HashPart::Str(owner),
                HashPart::Str(title),
                HashPart::Str(&current_evidence_root),
                HashPart::Str(&acceptance_root),
                HashPart::Str(&dependency_root),
                HashPart::Str(if blocks_user_escape { "yes" } else { "no" }),
                HashPart::Str(if blocks_production_release {
                    "yes"
                } else {
                    "no"
                }),
            ],
            32,
        );

        Self {
            blocker_id,
            lane,
            status,
            severity,
            burn_down_order,
            owner: owner.to_string(),
            title: title.to_string(),
            evidence_claim: evidence_claim.to_string(),
            hard_evidence_required: hard_evidence_required.to_string(),
            current_evidence_root,
            acceptance_root,
            dependency_root,
            blocks_user_escape,
            blocks_production_release,
            blocker_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "lane": self.lane.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "burn_down_order": self.burn_down_order,
            "owner": self.owner,
            "title": self.title,
            "evidence_claim": self.evidence_claim,
            "hard_evidence_required": self.hard_evidence_required,
            "current_evidence_root": self.current_evidence_root,
            "acceptance_root": self.acceptance_root,
            "dependency_root": self.dependency_root,
            "blocks_user_escape": self.blocks_user_escape,
            "blocks_production_release": self.blocks_production_release,
            "blocker_root": self.blocker_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BurnDownSummary {
    pub verdict: ReleaseVerdict,
    pub total_blockers: u64,
    pub open_blockers: u64,
    pub production_blockers: u64,
    pub user_escape_blockers: u64,
    pub cleared_blockers: u64,
    pub weighted_risk_score: u64,
    pub user_escape_design: String,
    pub production_release: String,
    pub next_required_evidence: String,
    pub blocker_root: String,
}

impl BurnDownSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "verdict": self.verdict.as_str(),
            "total_blockers": self.total_blockers,
            "open_blockers": self.open_blockers,
            "production_blockers": self.production_blockers,
            "user_escape_blockers": self.user_escape_blockers,
            "cleared_blockers": self.cleared_blockers,
            "weighted_risk_score": self.weighted_risk_score,
            "user_escape_design": self.user_escape_design,
            "production_release": self.production_release,
            "next_required_evidence": self.next_required_evidence,
            "blocker_root": self.blocker_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("burn-down-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub devnet_evidence: DevnetEvidence,
    pub blockers: Vec<ProductionBlocker>,
    pub summary: BurnDownSummary,
    pub config_root: String,
    pub devnet_evidence_root: String,
    pub blocker_root: String,
    pub summary_root: String,
    pub public_record_root: String,
    pub state_root: String,
}

impl State {
    pub fn from_parts(
        config: Config,
        devnet_evidence: DevnetEvidence,
        mut blockers: Vec<ProductionBlocker>,
    ) -> Result<Self> {
        if blockers.len() < config.min_blockers {
            return Err(format!(
                "production blocker burn-down requires at least {} blockers",
                config.min_blockers
            ));
        }

        blockers.sort_by_key(|blocker| blocker.burn_down_order);
        let config_root = config.state_root();
        let devnet_evidence_root = devnet_evidence.state_root();
        let blocker_root = blockers_root(&blockers);
        let summary = summarize(&blockers, &blocker_root);
        let summary_root = summary.state_root();
        let public_record = state_public_record(
            &config,
            &devnet_evidence,
            &blockers,
            &summary,
            &config_root,
            &devnet_evidence_root,
            &blocker_root,
            &summary_root,
        );
        let public_record_root = record_root("burn-down-public-record", &public_record);
        let state_root = burn_down_state_root(
            &config_root,
            &devnet_evidence_root,
            &blocker_root,
            &summary_root,
            &public_record_root,
        );

        Ok(Self {
            config,
            devnet_evidence,
            blockers,
            summary,
            config_root,
            devnet_evidence_root,
            blocker_root,
            summary_root,
            public_record_root,
            state_root,
        })
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let devnet_evidence = devnet_evidence(&config);
        let blockers = devnet_blockers(&devnet_evidence);
        match Self::from_parts(config, devnet_evidence, blockers) {
            Ok(state) => state,
            Err(error) => fallback_state(error.as_str()),
        }
    }

    pub fn public_record(&self) -> Value {
        state_public_record(
            &self.config,
            &self.devnet_evidence,
            &self.blockers,
            &self.summary,
            &self.config_root,
            &self.devnet_evidence_root,
            &self.blocker_root,
            &self.summary_root,
        )
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn production_blockers(&self) -> Vec<ProductionBlocker> {
        self.blockers
            .iter()
            .filter(|blocker| blocker.blocks_production_release)
            .cloned()
            .collect()
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

fn devnet_evidence(config: &Config) -> DevnetEvidence {
    DevnetEvidence {
        devnet_id: "nebula-monero-l2-pq-bridge-exit-devnet".to_string(),
        epoch: 42,
        canonical_transcript_id: config.release_candidate_id.clone(),
        escape_design_status:
            "user-escape design is improving across replay, reserve, and wallet evidence lanes"
                .to_string(),
        production_release_status:
            "production release remains blocked until hard evidence clears every release-stop lane"
                .to_string(),
        hard_evidence_policy:
            "accept live feed receipts, settlement execution receipts, reserve attestations, audit signoff, and operator runbook rehearsal roots"
                .to_string(),
        canonical_replay_root: named_root("canonical-replay", &config.release_candidate_id),
        forced_exit_replay_root: named_root("forced-exit-replay", "devnet-forced-exit-escape-v3"),
        settlement_handler_root: named_root("settlement-handler", "live-handler-shadow-run-v2"),
        reserve_snapshot_root: named_root("reserve-snapshot", "wxmr-reserve-proof-devnet-42"),
    }
}

fn devnet_blockers(devnet: &DevnetEvidence) -> Vec<ProductionBlocker> {
    vec![
        ProductionBlocker::new(
            BlockerLane::CargoRuntimeGates,
            BlockerStatus::EvidencePending,
            BlockerSeverity::ReleaseStop,
            10,
            "runtime",
            "cargo and runtime gates are not cleared for production replay",
            "canonical harness wiring exists in design evidence, while full release gate evidence is pending",
            "green cargo, runtime harness, fixture replay, and release-gate receipts from the owned production stack",
            false,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::LiveMoneroFeeds,
            BlockerStatus::Open,
            BlockerSeverity::ReleaseStop,
            20,
            "monero-feed",
            "live Monero feed receipts are still synthetic or shadow-only",
            "header, reorg, and lock evidence paths have deterministic devnet roots but no production feed receipt",
            "signed live feed receipt roots covering header continuity, reorg depth, and lock evidence freshness",
            true,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::LiveSettlementHandlers,
            BlockerStatus::EvidenceImproving,
            BlockerSeverity::Critical,
            30,
            "settlement",
            "live settlement handlers are improving but not release-proven",
            "shadow-run settlement handler roots are present and user escape replay coverage is increasing",
            "live settlement execution receipts for forced exit, challenge, release, and reserve paths",
            true,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::PqKeyVerification,
            BlockerStatus::EvidencePending,
            BlockerSeverity::Critical,
            40,
            "pq-authority",
            "PQ key verification needs independent transcript evidence",
            "key rotation and watcher attestations have devnet roots but production quorum verification remains pending",
            "independent ML-DSA and SLH-DSA authority verification transcript roots with quorum replay",
            false,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::ReserveProof,
            BlockerStatus::EvidencePending,
            BlockerSeverity::ReleaseStop,
            50,
            "reserve",
            "reserve proof has not cleared live sufficiency evidence",
            "reserve snapshots are deterministic and linked to escape replay, but live custody coverage is not signed off",
            "reserve proof, liquidity sufficiency, and custody release authority roots for the production reserve",
            true,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::PrivacyAudit,
            BlockerStatus::ExternalAuditPending,
            BlockerSeverity::Critical,
            60,
            "privacy",
            "privacy audit remains pending for replay consolidation",
            "private note and wallet evidence designs reduce linkage risk, while audit evidence is incomplete",
            "external privacy review roots covering note linkage, wallet reconstruction, and receipt scanning",
            false,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::ForcedExitExecution,
            BlockerStatus::EvidenceImproving,
            BlockerSeverity::ReleaseStop,
            70,
            "forced-exit",
            "forced-exit execution is improving but lacks hard production evidence",
            "devnet replay shows the user-escape path becoming more credible under operator failure",
            "successful forced-exit execution receipts under live handler, reserve, and watcher quorum conditions",
            true,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::SecurityAudit,
            BlockerStatus::ExternalAuditPending,
            BlockerSeverity::ReleaseStop,
            80,
            "security",
            "security audit signoff is not complete",
            "security harness and signoff manifests exist, but production acceptance is still held",
            "security audit closure roots with threat-model, slashing, settlement, and release authority coverage",
            false,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::OperatorRunbook,
            BlockerStatus::EvidencePending,
            BlockerSeverity::Major,
            90,
            "operator",
            "operator runbook lacks rehearsal evidence",
            "runbook text and wallet recovery drills are present, while production operator rehearsal is unproven",
            "operator rehearsal roots for incident response, reorg handling, reserve exhaustion, and user recovery",
            false,
            devnet,
        ),
        ProductionBlocker::new(
            BlockerLane::ReleaseSignoff,
            BlockerStatus::SignoffHold,
            BlockerSeverity::ReleaseStop,
            100,
            "release",
            "release signoff is held until all hard evidence lands",
            "release posture explicitly favors user escape improvement without production release approval",
            "release authority signoff roots binding every cleared blocker and its accepted evidence",
            false,
            devnet,
        ),
    ]
}

fn summarize(blockers: &[ProductionBlocker], blocker_root: &str) -> BurnDownSummary {
    let total_blockers = blockers.len() as u64;
    let production_blockers = blockers
        .iter()
        .filter(|blocker| blocker.blocks_production_release)
        .count() as u64;
    let user_escape_blockers = blockers
        .iter()
        .filter(|blocker| blocker.blocks_user_escape)
        .count() as u64;
    let cleared_blockers = blockers
        .iter()
        .filter(|blocker| blocker.status == BlockerStatus::Cleared)
        .count() as u64;
    let weighted_risk_score = blockers
        .iter()
        .filter(|blocker| blocker.blocks_production_release)
        .map(|blocker| blocker.severity.score())
        .sum::<u64>();
    let verdict = if production_blockers > 0 {
        ReleaseVerdict::ProductionBlocked
    } else if user_escape_blockers > 0 {
        ReleaseVerdict::EvidenceWatch
    } else {
        ReleaseVerdict::ProductionClear
    };

    BurnDownSummary {
        verdict,
        total_blockers,
        open_blockers: production_blockers,
        production_blockers,
        user_escape_blockers,
        cleared_blockers,
        weighted_risk_score,
        user_escape_design:
            "improving: replay consolidation is strengthening user escape, but live proof remains required"
                .to_string(),
        production_release:
            "blocked: hard evidence has not cleared live feeds, settlement, reserve, audit, and signoff lanes"
                .to_string(),
        next_required_evidence:
            "bind live receipts and external audit signoffs into the canonical replay public record"
                .to_string(),
        blocker_root: blocker_root.to_string(),
    }
}

fn state_public_record(
    config: &Config,
    devnet_evidence: &DevnetEvidence,
    blockers: &[ProductionBlocker],
    summary: &BurnDownSummary,
    config_root: &str,
    devnet_evidence_root: &str,
    blocker_root: &str,
    summary_root: &str,
) -> Value {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "schema_version": SCHEMA_VERSION,
        "hash_suite": HASH_SUITE,
        "config": config.public_record(),
        "devnet_evidence": devnet_evidence.public_record(),
        "blockers": blockers.iter().map(ProductionBlocker::public_record).collect::<Vec<_>>(),
        "summary": summary.public_record(),
        "roots": {
            "config_root": config_root,
            "devnet_evidence_root": devnet_evidence_root,
            "blocker_root": blocker_root,
            "summary_root": summary_root,
        },
    })
}

fn blockers_root(blockers: &[ProductionBlocker]) -> String {
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-BLOCKERS",
        &blockers
            .iter()
            .map(ProductionBlocker::public_record)
            .collect::<Vec<_>>(),
    )
}

fn burn_down_state_root(
    config_root: &str,
    devnet_evidence_root: &str,
    blocker_root: &str,
    summary_root: &str,
    public_record_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(config_root),
            HashPart::Str(devnet_evidence_root),
            HashPart::Str(blocker_root),
            HashPart::Str(summary_root),
            HashPart::Str(public_record_root),
        ],
        32,
    )
}

fn blocker_id(lane: BlockerLane, burn_down_order: u64, dependency_root: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::U64(burn_down_order),
            HashPart::Str(dependency_root),
        ],
        16,
    )
}

fn lane_evidence_root(
    lane: BlockerLane,
    status: BlockerStatus,
    evidence_claim: &str,
    devnet: &DevnetEvidence,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-EVIDENCE",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(evidence_claim),
            HashPart::Str(&devnet.canonical_replay_root),
            HashPart::Str(&devnet.forced_exit_replay_root),
            HashPart::Str(&devnet.settlement_handler_root),
            HashPart::Str(&devnet.reserve_snapshot_root),
        ],
        32,
    )
}

fn lane_acceptance_root(lane: BlockerLane, hard_evidence_required: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-ACCEPTANCE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(lane.as_str()),
            HashPart::Str(hard_evidence_required),
        ],
        32,
    )
}

fn lane_dependency_root(
    lane: BlockerLane,
    current_evidence_root: &str,
    acceptance_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-DEPENDENCY",
        &[
            HashPart::Str(lane.as_str()),
            HashPart::Str(current_evidence_root),
            HashPart::Str(acceptance_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn named_root(kind: &str, value: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-CANONICAL-PRODUCTION-BLOCKER-BURN-DOWN-NAMED-ROOT",
        &[HashPart::Str(kind), HashPart::Str(value)],
        32,
    )
}

fn fallback_state(error: &str) -> State {
    let config = Config::devnet();
    let devnet_evidence = DevnetEvidence {
        devnet_id: "fallback".to_string(),
        epoch: 0,
        canonical_transcript_id: config.release_candidate_id.clone(),
        escape_design_status: "user-escape design is improving but fallback evidence is active"
            .to_string(),
        production_release_status: "production release remains blocked".to_string(),
        hard_evidence_policy: error.to_string(),
        canonical_replay_root: named_root("fallback-canonical-replay", error),
        forced_exit_replay_root: named_root("fallback-forced-exit-replay", error),
        settlement_handler_root: named_root("fallback-settlement-handler", error),
        reserve_snapshot_root: named_root("fallback-reserve-snapshot", error),
    };
    let blockers = devnet_blockers(&devnet_evidence);
    let config_root = config.state_root();
    let devnet_evidence_root = devnet_evidence.state_root();
    let blocker_root = blockers_root(&blockers);
    let summary = summarize(&blockers, &blocker_root);
    let summary_root = summary.state_root();
    let public_record = state_public_record(
        &config,
        &devnet_evidence,
        &blockers,
        &summary,
        &config_root,
        &devnet_evidence_root,
        &blocker_root,
        &summary_root,
    );
    let public_record_root = record_root("fallback-burn-down-public-record", &public_record);
    let state_root = burn_down_state_root(
        &config_root,
        &devnet_evidence_root,
        &blocker_root,
        &summary_root,
        &public_record_root,
    );

    State {
        config,
        devnet_evidence,
        blockers,
        summary,
        config_root,
        devnet_evidence_root,
        blocker_root,
        summary_root,
        public_record_root,
        state_root,
    }
}
