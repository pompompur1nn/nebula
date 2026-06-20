use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalAuditScopeClosureManifestRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_AUDIT_SCOPE_CLOSURE_MANIFEST_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-audit-scope-closure-manifest-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_AUDIT_SCOPE_CLOSURE_MANIFEST_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const MANIFEST_SUITE: &str =
    "monero-l2-pq-bridge-exit-heavy-gate-audit-scope-closure-manifest-v1";
pub const DEVNET_L2_NETWORK: &str = "nebula-devnet";
pub const DEVNET_MONERO_NETWORK: &str = "monero-devnet";
pub const DEFAULT_REQUIRED_SCOPE_COUNT: usize = 10;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditScope {
    CustodyLockReleaseAuthority,
    ForcedExits,
    MoneroReorgAssumptions,
    PqKeyRotation,
    LiquidityReserve,
    PrivacyMetadata,
    WalletRecovery,
    FailureHarness,
    LiveFeedHandoff,
    ProductionReleaseSignoff,
}

impl AuditScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CustodyLockReleaseAuthority => "custody_lock_release_authority",
            Self::ForcedExits => "forced_exits",
            Self::MoneroReorgAssumptions => "monero_reorg_assumptions",
            Self::PqKeyRotation => "pq_key_rotation",
            Self::LiquidityReserve => "liquidity_reserve",
            Self::PrivacyMetadata => "privacy_metadata",
            Self::WalletRecovery => "wallet_recovery",
            Self::FailureHarness => "failure_harness",
            Self::LiveFeedHandoff => "live_feed_handoff",
            Self::ProductionReleaseSignoff => "production_release_signoff",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeClosureStatus {
    EvidenceCovered,
    Open,
}

impl ScopeClosureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EvidenceCovered => "evidence_covered",
            Self::Open => "open",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub manifest_suite: String,
    pub l2_network: String,
    pub monero_network: String,
    pub required_scope_count: usize,
    pub release_candidate_review: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            manifest_suite: MANIFEST_SUITE.to_string(),
            l2_network: DEVNET_L2_NETWORK.to_string(),
            monero_network: DEVNET_MONERO_NETWORK.to_string(),
            required_scope_count: DEFAULT_REQUIRED_SCOPE_COUNT,
            release_candidate_review: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "manifest_suite": self.manifest_suite,
            "l2_network": self.l2_network,
            "monero_network": self.monero_network,
            "required_scope_count": self.required_scope_count,
            "release_candidate_review": self.release_candidate_review,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::devnet()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedEvidence {
    pub evidence_id: String,
    pub label: String,
    pub source_manifest: String,
    pub evidence_root: String,
    pub artifact_count: u64,
    pub release_candidate_relevant: String,
}

impl GeneratedEvidence {
    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "label": self.label,
            "source_manifest": self.source_manifest,
            "evidence_root": self.evidence_root,
            "artifact_count": self.artifact_count,
            "release_candidate_relevant": self.release_candidate_relevant,
        })
    }

    pub fn root(&self) -> String {
        record_root("generated-evidence", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditScopeClosure {
    pub scope: AuditScope,
    pub status: ScopeClosureStatus,
    pub closure_reason: String,
    pub evidence_ids: Vec<String>,
    pub evidence_root: String,
    pub open_item: String,
    pub release_candidate_blocker: String,
    pub production_release_blocker: String,
}

impl AuditScopeClosure {
    pub fn public_record(&self) -> Value {
        json!({
            "scope": self.scope.as_str(),
            "status": self.status.as_str(),
            "closure_reason": self.closure_reason,
            "evidence_ids": self.evidence_ids,
            "evidence_root": self.evidence_root,
            "open_item": self.open_item,
            "release_candidate_blocker": self.release_candidate_blocker,
            "production_release_blocker": self.production_release_blocker,
        })
    }

    pub fn root(&self) -> String {
        record_root("audit-scope-closure", &self.public_record())
    }

    pub fn is_closed(&self) -> bool {
        self.status == ScopeClosureStatus::EvidenceCovered
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClosureSummary {
    pub release_candidate: String,
    pub no_production_release_answer: String,
    pub required_scope_count: usize,
    pub covered_scope_count: usize,
    pub open_scope_count: usize,
    pub release_candidate_blocker_count: usize,
    pub production_release_blocker_count: usize,
    pub evidence_manifest_root: String,
    pub covered_scope_root: String,
    pub open_scope_root: String,
    pub scope_closure_root: String,
    pub manifest_root: String,
}

impl ClosureSummary {
    pub fn public_record(&self) -> Value {
        json!({
            "release_candidate": self.release_candidate,
            "no_production_release_answer": self.no_production_release_answer,
            "required_scope_count": self.required_scope_count,
            "covered_scope_count": self.covered_scope_count,
            "open_scope_count": self.open_scope_count,
            "release_candidate_blocker_count": self.release_candidate_blocker_count,
            "production_release_blocker_count": self.production_release_blocker_count,
            "evidence_manifest_root": self.evidence_manifest_root,
            "covered_scope_root": self.covered_scope_root,
            "open_scope_root": self.open_scope_root,
            "scope_closure_root": self.scope_closure_root,
            "manifest_root": self.manifest_root,
        })
    }

    pub fn root(&self) -> String {
        record_root("closure-summary", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub generated_evidence: Vec<GeneratedEvidence>,
    pub scope_closures: Vec<AuditScopeClosure>,
    pub summary: ClosureSummary,
}

impl State {
    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "generated_evidence": self
                .generated_evidence
                .iter()
                .map(GeneratedEvidence::public_record)
                .collect::<Vec<_>>(),
            "scope_closures": self
                .scope_closures
                .iter()
                .map(AuditScopeClosure::public_record)
                .collect::<Vec<_>>(),
            "summary": self.summary.public_record(),
            "state_root": self.state_root(),
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "monero-l2-pq-bridge-exit-audit-scope-closure-state",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&self.config.state_root()),
                HashPart::Str(&generated_evidence_root(&self.generated_evidence)),
                HashPart::Str(&scope_closure_root(&self.scope_closures)),
                HashPart::Str(&self.summary.root()),
            ],
            32,
        )
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    let generated_evidence = devnet_generated_evidence();
    let scope_closures = devnet_scope_closures(&generated_evidence);
    let summary = closure_summary(&config, &generated_evidence, &scope_closures);

    State {
        config,
        generated_evidence,
        scope_closures,
        summary,
    }
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn closure_summary(
    config: &Config,
    generated_evidence: &[GeneratedEvidence],
    scope_closures: &[AuditScopeClosure],
) -> ClosureSummary {
    let covered_scope_records = scope_closures
        .iter()
        .filter(|scope| scope.is_closed())
        .map(AuditScopeClosure::public_record)
        .collect::<Vec<_>>();
    let open_scope_records = scope_closures
        .iter()
        .filter(|scope| !scope.is_closed())
        .map(AuditScopeClosure::public_record)
        .collect::<Vec<_>>();
    let release_candidate_blocker_count = scope_closures
        .iter()
        .filter(|scope| scope.release_candidate_blocker == "yes")
        .count();
    let production_release_blocker_count = scope_closures
        .iter()
        .filter(|scope| scope.production_release_blocker == "yes")
        .count();
    let evidence_manifest_root = generated_evidence_root(generated_evidence);
    let covered_scope_root = merkle_root(
        "monero-l2-pq-bridge-exit-audit-covered-scopes",
        &covered_scope_records,
    );
    let open_scope_root = merkle_root(
        "monero-l2-pq-bridge-exit-audit-open-scopes",
        &open_scope_records,
    );
    let scope_closure_root = scope_closure_root(scope_closures);
    let manifest_root = manifest_root(
        &evidence_manifest_root,
        &covered_scope_root,
        &open_scope_root,
        &scope_closure_root,
        covered_scope_records.len() as u64,
        open_scope_records.len() as u64,
        production_release_blocker_count as u64,
    );

    ClosureSummary {
        release_candidate: "bridge-forced-exit-heavy-gate".to_string(),
        no_production_release_answer:
            "production release remains disallowed until open audit scopes close".to_string(),
        required_scope_count: config.required_scope_count,
        covered_scope_count: covered_scope_records.len(),
        open_scope_count: open_scope_records.len(),
        release_candidate_blocker_count,
        production_release_blocker_count,
        evidence_manifest_root,
        covered_scope_root,
        open_scope_root,
        scope_closure_root,
        manifest_root,
    }
}

fn devnet_generated_evidence() -> Vec<GeneratedEvidence> {
    vec![
        evidence(
            "custody-lock-release-authority-generated-evidence",
            "custody lock release authority traces",
            "bridge-exit-custody-authority-heavy-gate-manifest",
            9,
        ),
        evidence(
            "forced-exit-generated-evidence",
            "forced exit queue and dispute harness receipts",
            "bridge-exit-forced-exit-heavy-gate-manifest",
            12,
        ),
        evidence(
            "monero-reorg-generated-evidence",
            "Monero delayed-finality and reorg quarantine assumptions",
            "bridge-exit-monero-reorg-heavy-gate-manifest",
            7,
        ),
        evidence(
            "pq-key-rotation-generated-evidence",
            "post-quantum key rotation ceremony transcripts",
            "bridge-exit-pq-key-rotation-heavy-gate-manifest",
            8,
        ),
        evidence(
            "privacy-metadata-generated-evidence",
            "wallet metadata redaction and unlinkability artifact set",
            "canonical-privacy-audit-artifact-manifest",
            8,
        ),
        evidence(
            "failure-harness-generated-evidence",
            "failure harness replay matrix and circuit breaker receipts",
            "security-audit-harness-adapter-report",
            14,
        ),
        evidence(
            "live-feed-handoff-generated-evidence",
            "live feed handoff shadow-mode digest and operator handoff log",
            "bridge-exit-live-feed-handoff-heavy-gate-manifest",
            5,
        ),
    ]
}

fn devnet_scope_closures(generated_evidence: &[GeneratedEvidence]) -> Vec<AuditScopeClosure> {
    vec![
        covered_scope(
            AuditScope::CustodyLockReleaseAuthority,
            "generated custody authority evidence covers lock ownership, release quorum, emergency pause, and replay-protected operator actions",
            &["custody-lock-release-authority-generated-evidence"],
            generated_evidence,
        ),
        covered_scope(
            AuditScope::ForcedExits,
            "generated forced-exit evidence covers queue admission, forced withdrawal scheduling, dispute timers, and canonical receipt emission",
            &["forced-exit-generated-evidence", "failure-harness-generated-evidence"],
            generated_evidence,
        ),
        covered_scope(
            AuditScope::MoneroReorgAssumptions,
            "generated reorg evidence covers delayed finality windows, orphan quarantine, watcher confirmation thresholds, and replay bounds",
            &["monero-reorg-generated-evidence", "failure-harness-generated-evidence"],
            generated_evidence,
        ),
        covered_scope(
            AuditScope::PqKeyRotation,
            "generated key rotation evidence covers hybrid signer rotation, old-key retirement, ceremony transcript roots, and signer quorum continuity",
            &["pq-key-rotation-generated-evidence"],
            generated_evidence,
        ),
        open_scope(
            AuditScope::LiquidityReserve,
            "liquidity reserve evidence is not sufficient for production release because reserve exhaustion and rebalance latency remain under audit",
            "reserve backstop sizing, emergency rebalance proof, and exit liquidity dry-run signoff remain open",
            &["forced-exit-generated-evidence"],
            generated_evidence,
            false,
        ),
        covered_scope(
            AuditScope::PrivacyMetadata,
            "generated privacy evidence covers wallet metadata redaction, deposit-exit unlinkability, watcher metadata minimization, and local-only recovery logs",
            &["privacy-metadata-generated-evidence"],
            generated_evidence,
        ),
        open_scope(
            AuditScope::WalletRecovery,
            "wallet recovery has generated privacy artifacts but still lacks independent recovery drill approval for production operations",
            "operator-independent recovery drill and recovery committee escalation transcript remain open",
            &["privacy-metadata-generated-evidence"],
            generated_evidence,
            false,
        ),
        covered_scope(
            AuditScope::FailureHarness,
            "generated failure harness evidence covers replayed watcher faults, delayed Monero confirmations, dispute timeout edges, and circuit breaker activation",
            &["failure-harness-generated-evidence"],
            generated_evidence,
        ),
        covered_scope(
            AuditScope::LiveFeedHandoff,
            "generated live-feed evidence covers shadow-mode feed parity, handoff checkpoints, and operator acknowledgement roots for release-candidate review",
            &["live-feed-handoff-generated-evidence"],
            generated_evidence,
        ),
        open_scope(
            AuditScope::ProductionReleaseSignoff,
            "production release signoff is intentionally open for this heavy-gate release candidate",
            "final security, liquidity, recovery, and production operations signoffs remain open",
            &[
                "custody-lock-release-authority-generated-evidence",
                "forced-exit-generated-evidence",
                "monero-reorg-generated-evidence",
                "pq-key-rotation-generated-evidence",
                "privacy-metadata-generated-evidence",
                "failure-harness-generated-evidence",
                "live-feed-handoff-generated-evidence",
            ],
            generated_evidence,
            true,
        ),
    ]
}

fn evidence(
    evidence_id: &str,
    label: &str,
    source_manifest: &str,
    artifact_count: u64,
) -> GeneratedEvidence {
    let evidence_root = domain_hash(
        "monero-l2-pq-bridge-exit-audit-scope-closure-generated-evidence",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(evidence_id),
            HashPart::Str(source_manifest),
            HashPart::U64(artifact_count),
        ],
        32,
    );

    GeneratedEvidence {
        evidence_id: evidence_id.to_string(),
        label: label.to_string(),
        source_manifest: source_manifest.to_string(),
        evidence_root,
        artifact_count,
        release_candidate_relevant: "yes".to_string(),
    }
}

fn covered_scope(
    scope: AuditScope,
    closure_reason: &str,
    evidence_ids: &[&str],
    generated_evidence: &[GeneratedEvidence],
) -> AuditScopeClosure {
    scope_closure(
        scope,
        ScopeClosureStatus::EvidenceCovered,
        closure_reason,
        evidence_ids,
        generated_evidence,
        "none",
        false,
        false,
    )
}

fn open_scope(
    scope: AuditScope,
    closure_reason: &str,
    open_item: &str,
    evidence_ids: &[&str],
    generated_evidence: &[GeneratedEvidence],
    release_candidate_blocker: bool,
) -> AuditScopeClosure {
    scope_closure(
        scope,
        ScopeClosureStatus::Open,
        closure_reason,
        evidence_ids,
        generated_evidence,
        open_item,
        release_candidate_blocker,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn scope_closure(
    scope: AuditScope,
    status: ScopeClosureStatus,
    closure_reason: &str,
    evidence_ids: &[&str],
    generated_evidence: &[GeneratedEvidence],
    open_item: &str,
    release_candidate_blocker: bool,
    production_release_blocker: bool,
) -> AuditScopeClosure {
    let evidence_ids = evidence_ids
        .iter()
        .map(|evidence_id| (*evidence_id).to_string())
        .collect::<Vec<_>>();
    let evidence_records = generated_evidence
        .iter()
        .filter(|evidence| evidence_ids.contains(&evidence.evidence_id))
        .map(GeneratedEvidence::public_record)
        .collect::<Vec<_>>();
    let evidence_root = merkle_root(
        "monero-l2-pq-bridge-exit-audit-scope-closure-scope-evidence",
        &evidence_records,
    );

    AuditScopeClosure {
        scope,
        status,
        closure_reason: closure_reason.to_string(),
        evidence_ids,
        evidence_root,
        open_item: open_item.to_string(),
        release_candidate_blocker: yes_no(release_candidate_blocker).to_string(),
        production_release_blocker: yes_no(production_release_blocker).to_string(),
    }
}

fn generated_evidence_root(generated_evidence: &[GeneratedEvidence]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-audit-scope-closure-generated-evidence",
        &generated_evidence
            .iter()
            .map(GeneratedEvidence::public_record)
            .collect::<Vec<_>>(),
    )
}

fn scope_closure_root(scope_closures: &[AuditScopeClosure]) -> String {
    merkle_root(
        "monero-l2-pq-bridge-exit-audit-scope-closures",
        &scope_closures
            .iter()
            .map(AuditScopeClosure::public_record)
            .collect::<Vec<_>>(),
    )
}

fn manifest_root(
    evidence_manifest_root: &str,
    covered_scope_root: &str,
    open_scope_root: &str,
    scope_closure_root: &str,
    covered_scope_count: u64,
    open_scope_count: u64,
    production_release_blocker_count: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-audit-scope-closure-manifest",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(evidence_manifest_root),
            HashPart::Str(covered_scope_root),
            HashPart::Str(open_scope_root),
            HashPart::Str(scope_closure_root),
            HashPart::U64(covered_scope_count),
            HashPart::U64(open_scope_count),
            HashPart::U64(production_release_blocker_count),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-audit-scope-closure-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}
