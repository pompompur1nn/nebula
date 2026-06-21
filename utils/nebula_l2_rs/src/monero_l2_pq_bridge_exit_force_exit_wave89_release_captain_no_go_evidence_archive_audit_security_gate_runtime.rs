use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, Error>;
pub type Runtime = State;

const DOMAIN_CONFIG: &str = "wave89.release_captain.no_go.config.v1";
const DOMAIN_RECORD: &str = "wave89.release_captain.no_go.record.v1";
const DOMAIN_BLOCKER: &str = "wave89.release_captain.no_go.blocker.v1";
const DOMAIN_RECEIPT: &str = "wave89.release_captain.no_go.receipt.v1";
const DOMAIN_DECISION: &str = "wave89.release_captain.no_go.decision.v1";
const DOMAIN_ROOT: &str = "wave89.release_captain.no_go.root.v1";
const DEFAULT_MIN_RECEIPTS: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    EmptyField(&'static str),
    DuplicateRecord(String),
    DuplicateBlocker(String),
    DuplicateReceipt(String),
    MissingRecord(String),
    MissingBlocker(String),
    InvalidTransition(&'static str),
    ReleaseHeld(String),
    EvidenceRejected(String),
    ReceiptRejected(String),
    ClockUnavailable,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EmptyField(field) => write!(f, "empty required field: {}", field),
            Error::DuplicateRecord(id) => write!(f, "duplicate evidence record: {}", id),
            Error::DuplicateBlocker(id) => write!(f, "duplicate blocker: {}", id),
            Error::DuplicateReceipt(id) => write!(f, "duplicate reviewer receipt: {}", id),
            Error::MissingRecord(id) => write!(f, "missing evidence record: {}", id),
            Error::MissingBlocker(id) => write!(f, "missing blocker: {}", id),
            Error::InvalidTransition(msg) => write!(f, "invalid release transition: {}", msg),
            Error::ReleaseHeld(msg) => write!(f, "release held: {}", msg),
            Error::EvidenceRejected(msg) => write!(f, "evidence rejected: {}", msg),
            Error::ReceiptRejected(msg) => write!(f, "reviewer receipt rejected: {}", msg),
            Error::ClockUnavailable => write!(f, "system clock is unavailable"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashRoot(pub String);

impl HashRoot {
    pub fn new(domain: &str, parts: &[String]) -> Self {
        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        parts.len().hash(&mut hasher);
        for part in parts {
            part.len().hash(&mut hasher);
            part.hash(&mut hasher);
        }
        HashRoot(format!("{:016x}", hasher.finish()))
    }

    pub fn mix(domain: &str, roots: &[HashRoot]) -> Self {
        let parts = roots.iter().map(|root| root.0.clone()).collect::<Vec<_>>();
        HashRoot::new(domain, &parts)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HashRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Result<Self> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::ClockUnavailable)?;
        Ok(Timestamp(duration.as_secs()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn fail_closed(self) -> bool {
        matches!(self, Severity::High | Severity::Critical)
    }

    pub fn weight(self) -> u64 {
        match self {
            Severity::Info => 1,
            Severity::Low => 2,
            Severity::Medium => 4,
            Severity::High => 8,
            Severity::Critical => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EvidenceClass {
    AuditFinding,
    AdversarialBlocker,
    PrivacyBlocker,
    SecurityReview,
    ReplayDecision,
    ReviewerReceipt,
    ReleaseCaptainOverride,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockerKind {
    Audit,
    Adversarial,
    Privacy,
    Security,
    ReplayIntegrity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlockerStatus {
    Unresolved,
    Mitigated,
    AcceptedRisk,
    FalsePositive,
}

impl BlockerStatus {
    pub fn holds_release(self) -> bool {
        matches!(self, BlockerStatus::Unresolved)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReceiptVerdict {
    ConfirmNoGo,
    ConfirmHold,
    NeedsMoreEvidence,
    Dispute,
    Clear,
}

impl ReceiptVerdict {
    pub fn no_go_aligned(self) -> bool {
        matches!(
            self,
            ReceiptVerdict::ConfirmNoGo
                | ReceiptVerdict::ConfirmHold
                | ReceiptVerdict::NeedsMoreEvidence
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReleaseDecision {
    NoGo,
    Held,
    Candidate,
    Released,
}

impl ReleaseDecision {
    pub fn is_open(self) -> bool {
        matches!(self, ReleaseDecision::NoGo | ReleaseDecision::Held)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub wave: u32,
    pub previous_wave: u32,
    pub release_id: String,
    pub network: String,
    pub release_captain: String,
    pub min_reviewer_receipts: usize,
    pub fail_closed: bool,
    pub require_privacy_roots_only: bool,
    pub require_adversarial_replay: bool,
    pub allowed_reviewers: BTreeSet<String>,
    pub created_at: Timestamp,
}

impl Config {
    pub fn new(
        release_id: impl Into<String>,
        network: impl Into<String>,
        release_captain: impl Into<String>,
    ) -> Result<Self> {
        let mut config = Config {
            wave: 89,
            previous_wave: 88,
            release_id: release_id.into(),
            network: network.into(),
            release_captain: release_captain.into(),
            min_reviewer_receipts: DEFAULT_MIN_RECEIPTS,
            fail_closed: true,
            require_privacy_roots_only: true,
            require_adversarial_replay: true,
            allowed_reviewers: BTreeSet::new(),
            created_at: Timestamp(0),
        };
        config.created_at = timestamp_or_zero();
        config.validate()?;
        Ok(config)
    }

    pub fn devnet() -> Self {
        let mut reviewers = BTreeSet::new();
        reviewers.insert("audit".to_string());
        reviewers.insert("privacy".to_string());
        reviewers.insert("security".to_string());
        Config {
            wave: 89,
            previous_wave: 88,
            release_id: "devnet-wave89-no-go-evidence-archive".to_string(),
            network: "devnet".to_string(),
            release_captain: "release-captain".to_string(),
            min_reviewer_receipts: DEFAULT_MIN_RECEIPTS,
            fail_closed: true,
            require_privacy_roots_only: true,
            require_adversarial_replay: true,
            allowed_reviewers: reviewers,
            created_at: Timestamp(0),
        }
    }

    pub fn with_reviewer(mut self, reviewer: impl Into<String>) -> Result<Self> {
        let reviewer = reviewer.into();
        ensure_not_empty("reviewer", &reviewer)?;
        self.allowed_reviewers.insert(reviewer);
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<()> {
        ensure_not_empty("release_id", &self.release_id)?;
        ensure_not_empty("network", &self.network)?;
        ensure_not_empty("release_captain", &self.release_captain)?;
        if self.wave <= self.previous_wave {
            return Err(Error::EvidenceRejected(
                "wave must be newer than previous replay wave".to_string(),
            ));
        }
        if self.min_reviewer_receipts == 0 {
            return Err(Error::ReceiptRejected(
                "at least one reviewer receipt is required".to_string(),
            ));
        }
        Ok(())
    }

    pub fn root(&self) -> HashRoot {
        let reviewers = self.allowed_reviewers.iter().cloned().collect::<Vec<_>>();
        let mut parts = vec![
            self.wave.to_string(),
            self.previous_wave.to_string(),
            self.release_id.clone(),
            self.network.clone(),
            self.release_captain.clone(),
            self.min_reviewer_receipts.to_string(),
            self.fail_closed.to_string(),
            self.require_privacy_roots_only.to_string(),
            self.require_adversarial_replay.to_string(),
            self.created_at.0.to_string(),
        ];
        parts.extend(reviewers);
        HashRoot::new(DOMAIN_CONFIG, &parts)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivacyRecord {
    pub commitment_root: HashRoot,
    pub transcript_root: HashRoot,
    pub witness_root: HashRoot,
    pub redaction_root: HashRoot,
}

impl PrivacyRecord {
    pub fn roots_only(
        commitment_root: impl Into<String>,
        transcript_root: impl Into<String>,
        witness_root: impl Into<String>,
        redaction_root: impl Into<String>,
    ) -> Result<Self> {
        let commitment_root = commitment_root.into();
        let transcript_root = transcript_root.into();
        let witness_root = witness_root.into();
        let redaction_root = redaction_root.into();
        ensure_not_empty("commitment_root", &commitment_root)?;
        ensure_not_empty("transcript_root", &transcript_root)?;
        ensure_not_empty("witness_root", &witness_root)?;
        ensure_not_empty("redaction_root", &redaction_root)?;
        Ok(PrivacyRecord {
            commitment_root: HashRoot(commitment_root),
            transcript_root: HashRoot(transcript_root),
            witness_root: HashRoot(witness_root),
            redaction_root: HashRoot(redaction_root),
        })
    }

    pub fn root(&self) -> HashRoot {
        HashRoot::mix(
            "wave89.release_captain.no_go.privacy_roots.v1",
            &[
                self.commitment_root.clone(),
                self.transcript_root.clone(),
                self.witness_root.clone(),
                self.redaction_root.clone(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String,
    pub class: EvidenceClass,
    pub severity: Severity,
    pub title: String,
    pub wave88_decision_id: String,
    pub source_root: HashRoot,
    pub privacy: PrivacyRecord,
    pub tags: BTreeSet<String>,
    pub created_at: Timestamp,
}

impl EvidenceRecord {
    pub fn new(
        id: impl Into<String>,
        class: EvidenceClass,
        severity: Severity,
        title: impl Into<String>,
        wave88_decision_id: impl Into<String>,
        source_root: impl Into<String>,
        privacy: PrivacyRecord,
    ) -> Result<Self> {
        let id = id.into();
        let title = title.into();
        let wave88_decision_id = wave88_decision_id.into();
        let source_root = source_root.into();
        ensure_not_empty("evidence.id", &id)?;
        ensure_not_empty("evidence.title", &title)?;
        ensure_not_empty("evidence.wave88_decision_id", &wave88_decision_id)?;
        ensure_not_empty("evidence.source_root", &source_root)?;
        Ok(EvidenceRecord {
            id,
            class,
            severity,
            title,
            wave88_decision_id,
            source_root: HashRoot(source_root),
            privacy,
            tags: BTreeSet::new(),
            created_at: timestamp_or_zero(),
        })
    }

    pub fn with_tag(mut self, tag: impl Into<String>) -> Result<Self> {
        let tag = tag.into();
        ensure_not_empty("evidence.tag", &tag)?;
        self.tags.insert(tag);
        Ok(self)
    }

    pub fn root(&self) -> HashRoot {
        let mut parts = vec![
            self.id.clone(),
            format!("{:?}", self.class),
            format!("{:?}", self.severity),
            self.title.clone(),
            self.wave88_decision_id.clone(),
            self.source_root.0.clone(),
            self.privacy.root().0,
            self.created_at.0.to_string(),
        ];
        parts.extend(self.tags.iter().cloned());
        HashRoot::new(DOMAIN_RECORD, &parts)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditFinding {
    pub finding_id: String,
    pub component: String,
    pub evidence_id: String,
    pub severity: Severity,
    pub unresolved: bool,
    pub remediation_root: Option<HashRoot>,
}

impl AuditFinding {
    pub fn unresolved(
        finding_id: impl Into<String>,
        component: impl Into<String>,
        evidence_id: impl Into<String>,
        severity: Severity,
    ) -> Result<Self> {
        let finding_id = finding_id.into();
        let component = component.into();
        let evidence_id = evidence_id.into();
        ensure_not_empty("audit.finding_id", &finding_id)?;
        ensure_not_empty("audit.component", &component)?;
        ensure_not_empty("audit.evidence_id", &evidence_id)?;
        Ok(AuditFinding {
            finding_id,
            component,
            evidence_id,
            severity,
            unresolved: true,
            remediation_root: None,
        })
    }

    pub fn with_remediation_root(mut self, root: impl Into<String>) -> Result<Self> {
        let root = root.into();
        ensure_not_empty("audit.remediation_root", &root)?;
        self.remediation_root = Some(HashRoot(root));
        self.unresolved = false;
        Ok(self)
    }

    pub fn root(&self) -> HashRoot {
        HashRoot::new(
            "wave89.release_captain.no_go.audit_finding.v1",
            &[
                self.finding_id.clone(),
                self.component.clone(),
                self.evidence_id.clone(),
                format!("{:?}", self.severity),
                self.unresolved.to_string(),
                self.remediation_root
                    .as_ref()
                    .map(|root| root.0.clone())
                    .match_or_empty(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdversarialReplay {
    pub scenario_id: String,
    pub adversary_model: String,
    pub transcript_root: HashRoot,
    pub exploitability: Severity,
    pub deterministic_replay: bool,
}

impl AdversarialReplay {
    pub fn new(
        scenario_id: impl Into<String>,
        adversary_model: impl Into<String>,
        transcript_root: impl Into<String>,
        exploitability: Severity,
    ) -> Result<Self> {
        let scenario_id = scenario_id.into();
        let adversary_model = adversary_model.into();
        let transcript_root = transcript_root.into();
        ensure_not_empty("adversarial.scenario_id", &scenario_id)?;
        ensure_not_empty("adversarial.adversary_model", &adversary_model)?;
        ensure_not_empty("adversarial.transcript_root", &transcript_root)?;
        Ok(AdversarialReplay {
            scenario_id,
            adversary_model,
            transcript_root: HashRoot(transcript_root),
            exploitability,
            deterministic_replay: true,
        })
    }

    pub fn root(&self) -> HashRoot {
        HashRoot::new(
            "wave89.release_captain.no_go.adversarial_replay.v1",
            &[
                self.scenario_id.clone(),
                self.adversary_model.clone(),
                self.transcript_root.0.clone(),
                format!("{:?}", self.exploitability),
                self.deterministic_replay.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocker {
    pub id: String,
    pub kind: BlockerKind,
    pub status: BlockerStatus,
    pub severity: Severity,
    pub summary: String,
    pub evidence_ids: BTreeSet<String>,
    pub replay: Option<AdversarialReplay>,
    pub opened_at: Timestamp,
    pub resolved_at: Option<Timestamp>,
}

impl Blocker {
    pub fn new(
        id: impl Into<String>,
        kind: BlockerKind,
        severity: Severity,
        summary: impl Into<String>,
    ) -> Result<Self> {
        let id = id.into();
        let summary = summary.into();
        ensure_not_empty("blocker.id", &id)?;
        ensure_not_empty("blocker.summary", &summary)?;
        Ok(Blocker {
            id,
            kind,
            status: BlockerStatus::Unresolved,
            severity,
            summary,
            evidence_ids: BTreeSet::new(),
            replay: None,
            opened_at: timestamp_or_zero(),
            resolved_at: None,
        })
    }

    pub fn add_evidence(mut self, evidence_id: impl Into<String>) -> Result<Self> {
        let evidence_id = evidence_id.into();
        ensure_not_empty("blocker.evidence_id", &evidence_id)?;
        self.evidence_ids.insert(evidence_id);
        Ok(self)
    }

    pub fn with_replay(mut self, replay: AdversarialReplay) -> Self {
        self.replay = Some(replay);
        self
    }

    pub fn resolve(mut self, status: BlockerStatus, root: HashRoot) -> Result<Self> {
        if status == BlockerStatus::Unresolved {
            return Err(Error::InvalidTransition(
                "resolve requires a terminal blocker status",
            ));
        }
        self.status = status;
        self.resolved_at = Some(timestamp_or_zero());
        self.evidence_ids.insert(format!("resolution:{}", root.0));
        Ok(self)
    }

    pub fn holds_release(&self) -> bool {
        self.status.holds_release() || self.severity.fail_closed()
    }

    pub fn root(&self) -> HashRoot {
        let mut parts = vec![
            self.id.clone(),
            format!("{:?}", self.kind),
            format!("{:?}", self.status),
            format!("{:?}", self.severity),
            self.summary.clone(),
            self.opened_at.0.to_string(),
            option_timestamp_to_u64(self.resolved_at).to_string(),
        ];
        parts.extend(self.evidence_ids.iter().cloned());
        if let Some(replay) = &self.replay {
            parts.push(replay.root().0);
        }
        HashRoot::new(DOMAIN_BLOCKER, &parts)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerReceipt {
    pub id: String,
    pub reviewer: String,
    pub role: String,
    pub blocker_id: String,
    pub verdict: ReceiptVerdict,
    pub evidence_root: HashRoot,
    pub signed_root: HashRoot,
    pub received_at: Timestamp,
}

impl ReviewerReceipt {
    pub fn new(
        id: impl Into<String>,
        reviewer: impl Into<String>,
        role: impl Into<String>,
        blocker_id: impl Into<String>,
        verdict: ReceiptVerdict,
        evidence_root: impl Into<String>,
    ) -> Result<Self> {
        let id = id.into();
        let reviewer = reviewer.into();
        let role = role.into();
        let blocker_id = blocker_id.into();
        let evidence_root = evidence_root.into();
        ensure_not_empty("receipt.id", &id)?;
        ensure_not_empty("receipt.reviewer", &reviewer)?;
        ensure_not_empty("receipt.role", &role)?;
        ensure_not_empty("receipt.blocker_id", &blocker_id)?;
        ensure_not_empty("receipt.evidence_root", &evidence_root)?;
        let received_at = timestamp_or_zero();
        let signed_root = HashRoot::new(
            DOMAIN_RECEIPT,
            &[
                id.clone(),
                reviewer.clone(),
                role.clone(),
                blocker_id.clone(),
                format!("{:?}", verdict),
                evidence_root.clone(),
                received_at.0.to_string(),
            ],
        );
        Ok(ReviewerReceipt {
            id,
            reviewer,
            role,
            blocker_id,
            verdict,
            evidence_root: HashRoot(evidence_root),
            signed_root,
            received_at,
        })
    }

    pub fn root(&self) -> HashRoot {
        HashRoot::new(
            DOMAIN_RECEIPT,
            &[
                self.id.clone(),
                self.reviewer.clone(),
                self.role.clone(),
                self.blocker_id.clone(),
                format!("{:?}", self.verdict),
                self.evidence_root.0.clone(),
                self.signed_root.0.clone(),
                self.received_at.0.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionSnapshot {
    pub release_id: String,
    pub decision: ReleaseDecision,
    pub reason: String,
    pub blocker_count: usize,
    pub unresolved_count: usize,
    pub critical_count: usize,
    pub evidence_root: HashRoot,
    pub blocker_root: HashRoot,
    pub receipt_root: HashRoot,
    pub decided_at: Timestamp,
}

impl DecisionSnapshot {
    pub fn root(&self) -> HashRoot {
        HashRoot::new(
            DOMAIN_DECISION,
            &[
                self.release_id.clone(),
                format!("{:?}", self.decision),
                self.reason.clone(),
                self.blocker_count.to_string(),
                self.unresolved_count.to_string(),
                self.critical_count.to_string(),
                self.evidence_root.0.clone(),
                self.blocker_root.0.clone(),
                self.receipt_root.0.clone(),
                self.decided_at.0.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub release_id: String,
    pub network: String,
    pub wave: u32,
    pub previous_wave: u32,
    pub decision: ReleaseDecision,
    pub config_root: HashRoot,
    pub evidence_root: HashRoot,
    pub blocker_root: HashRoot,
    pub receipt_root: HashRoot,
    pub state_root: HashRoot,
    pub unresolved_blockers: usize,
    pub fail_closed: bool,
}

impl PublicRecord {
    pub fn root(&self) -> HashRoot {
        HashRoot::new(
            "wave89.release_captain.no_go.public_record.v1",
            &[
                self.release_id.clone(),
                self.network.clone(),
                self.wave.to_string(),
                self.previous_wave.to_string(),
                format!("{:?}", self.decision),
                self.config_root.0.clone(),
                self.evidence_root.0.clone(),
                self.blocker_root.0.clone(),
                self.receipt_root.0.clone(),
                self.state_root.0.clone(),
                self.unresolved_blockers.to_string(),
                self.fail_closed.to_string(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveSummary {
    pub evidence_records: usize,
    pub blockers: usize,
    pub receipts: usize,
    pub audit_findings: usize,
    pub unresolved: usize,
    pub decision: ReleaseDecision,
    pub state_root: HashRoot,
}

#[derive(Clone, Debug)]
pub struct State {
    pub config: Config,
    pub evidence: BTreeMap<String, EvidenceRecord>,
    pub blockers: BTreeMap<String, Blocker>,
    pub audit_findings: BTreeMap<String, AuditFinding>,
    pub receipts: BTreeMap<String, ReviewerReceipt>,
    pub decision_log: Vec<DecisionSnapshot>,
    reviewer_index: HashMap<String, HashSet<String>>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(State {
            config,
            evidence: BTreeMap::new(),
            blockers: BTreeMap::new(),
            audit_findings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            decision_log: Vec::new(),
            reviewer_index: HashMap::new(),
        })
    }

    pub fn add_evidence(&mut self, record: EvidenceRecord) -> Result<HashRoot> {
        self.validate_evidence(&record)?;
        if self.evidence.contains_key(&record.id) {
            return Err(Error::DuplicateRecord(record.id));
        }
        let root = record.root();
        self.evidence.insert(record.id.clone(), record);
        Ok(root)
    }

    pub fn add_audit_finding(&mut self, finding: AuditFinding) -> Result<HashRoot> {
        if !self.evidence.contains_key(&finding.evidence_id) {
            return Err(Error::MissingRecord(finding.evidence_id));
        }
        if self.audit_findings.contains_key(&finding.finding_id) {
            return Err(Error::DuplicateRecord(finding.finding_id));
        }
        let root = finding.root();
        self.audit_findings
            .insert(finding.finding_id.clone(), finding);
        Ok(root)
    }

    pub fn add_blocker(&mut self, blocker: Blocker) -> Result<HashRoot> {
        self.validate_blocker(&blocker)?;
        if self.blockers.contains_key(&blocker.id) {
            return Err(Error::DuplicateBlocker(blocker.id));
        }
        let root = blocker.root();
        self.blockers.insert(blocker.id.clone(), blocker);
        Ok(root)
    }

    pub fn update_blocker_status(
        &mut self,
        blocker_id: &str,
        status: BlockerStatus,
        resolution_root: impl Into<String>,
    ) -> Result<HashRoot> {
        ensure_not_empty("blocker_id", blocker_id)?;
        let resolution_root = resolution_root.into();
        ensure_not_empty("resolution_root", &resolution_root)?;
        let existing = self
            .blockers
            .remove(blocker_id)
            .ok_or_else(|| Error::MissingBlocker(blocker_id.to_string()))?;
        let updated = existing.resolve(status, HashRoot(resolution_root))?;
        let root = updated.root();
        self.blockers.insert(blocker_id.to_string(), updated);
        Ok(root)
    }

    pub fn add_receipt(&mut self, receipt: ReviewerReceipt) -> Result<HashRoot> {
        self.validate_receipt(&receipt)?;
        if self.receipts.contains_key(&receipt.id) {
            return Err(Error::DuplicateReceipt(receipt.id));
        }
        let root = receipt.root();
        self.reviewer_index
            .entry(receipt.blocker_id.clone())
            .or_insert_with(HashSet::new)
            .insert(receipt.reviewer.clone());
        self.receipts.insert(receipt.id.clone(), receipt);
        Ok(root)
    }

    pub fn decide(&mut self) -> DecisionSnapshot {
        let unresolved = self.unresolved_blockers();
        let critical = self.critical_blockers();
        let receipts = self.no_go_receipt_count();
        let required_receipts_met = receipts >= self.config.min_reviewer_receipts;
        let decision = if unresolved > 0 || critical > 0 {
            ReleaseDecision::NoGo
        } else if self.config.fail_closed && !required_receipts_met {
            ReleaseDecision::Held
        } else {
            ReleaseDecision::Candidate
        };
        let reason = self.decision_reason(decision, unresolved, critical, receipts);
        let snapshot = DecisionSnapshot {
            release_id: self.config.release_id.clone(),
            decision,
            reason,
            blocker_count: self.blockers.len(),
            unresolved_count: unresolved,
            critical_count: critical,
            evidence_root: self.evidence_root(),
            blocker_root: self.blocker_root(),
            receipt_root: self.receipt_root(),
            decided_at: timestamp_or_zero(),
        };
        self.decision_log.push(snapshot.clone());
        snapshot
    }

    pub fn enforce_no_go(&mut self) -> Result<DecisionSnapshot> {
        let snapshot = self.decide();
        match snapshot.decision {
            ReleaseDecision::NoGo | ReleaseDecision::Held => Ok(snapshot),
            ReleaseDecision::Candidate | ReleaseDecision::Released => Err(Error::ReleaseHeld(
                "no-go archive gate cannot be bypassed without unresolved blocker review"
                    .to_string(),
            )),
        }
    }

    pub fn attempt_release(&mut self) -> Result<DecisionSnapshot> {
        let snapshot = self.decide();
        if snapshot.decision == ReleaseDecision::Candidate {
            let released = DecisionSnapshot {
                decision: ReleaseDecision::Released,
                reason: "all archived blockers resolved and receipt threshold satisfied"
                    .to_string(),
                ..snapshot
            };
            self.decision_log.push(released.clone());
            Ok(released)
        } else {
            Err(Error::ReleaseHeld(snapshot.reason))
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        let decision = self
            .decision_log
            .last()
            .map(|snapshot| snapshot.decision)
            .map_or_held_decision();
        let evidence_root = self.evidence_root();
        let blocker_root = self.blocker_root();
        let receipt_root = self.receipt_root();
        let config_root = self.config.root();
        let state_root = self.state_root();
        PublicRecord {
            release_id: self.config.release_id.clone(),
            network: self.config.network.clone(),
            wave: self.config.wave,
            previous_wave: self.config.previous_wave,
            decision,
            config_root,
            evidence_root,
            blocker_root,
            receipt_root,
            state_root,
            unresolved_blockers: self.unresolved_blockers(),
            fail_closed: self.config.fail_closed,
        }
    }

    pub fn summary(&self) -> ArchiveSummary {
        ArchiveSummary {
            evidence_records: self.evidence.len(),
            blockers: self.blockers.len(),
            receipts: self.receipts.len(),
            audit_findings: self.audit_findings.len(),
            unresolved: self.unresolved_blockers(),
            decision: self
                .decision_log
                .last()
                .map(|snapshot| snapshot.decision)
                .map_or_held_decision(),
            state_root: self.state_root(),
        }
    }

    pub fn state_root(&self) -> HashRoot {
        HashRoot::mix(
            DOMAIN_ROOT,
            &[
                self.config.root(),
                self.evidence_root(),
                self.blocker_root(),
                self.audit_root(),
                self.receipt_root(),
                self.decision_root(),
            ],
        )
    }

    pub fn evidence_root(&self) -> HashRoot {
        let roots = self
            .evidence
            .values()
            .map(EvidenceRecord::root)
            .collect::<Vec<_>>();
        HashRoot::mix("wave89.release_captain.no_go.evidence_set.v1", &roots)
    }

    pub fn blocker_root(&self) -> HashRoot {
        let roots = self
            .blockers
            .values()
            .map(Blocker::root)
            .collect::<Vec<_>>();
        HashRoot::mix("wave89.release_captain.no_go.blocker_set.v1", &roots)
    }

    pub fn audit_root(&self) -> HashRoot {
        let roots = self
            .audit_findings
            .values()
            .map(AuditFinding::root)
            .collect::<Vec<_>>();
        HashRoot::mix("wave89.release_captain.no_go.audit_set.v1", &roots)
    }

    pub fn receipt_root(&self) -> HashRoot {
        let roots = self
            .receipts
            .values()
            .map(ReviewerReceipt::root)
            .collect::<Vec<_>>();
        HashRoot::mix("wave89.release_captain.no_go.receipt_set.v1", &roots)
    }

    pub fn decision_root(&self) -> HashRoot {
        let roots = self
            .decision_log
            .iter()
            .map(DecisionSnapshot::root)
            .collect::<Vec<_>>();
        HashRoot::mix("wave89.release_captain.no_go.decision_set.v1", &roots)
    }

    pub fn unresolved_blockers(&self) -> usize {
        self.blockers
            .values()
            .filter(|blocker| blocker.status.holds_release())
            .count()
    }

    pub fn critical_blockers(&self) -> usize {
        self.blockers
            .values()
            .filter(|blocker| blocker.severity == Severity::Critical && blocker.holds_release())
            .count()
    }

    pub fn no_go_receipt_count(&self) -> usize {
        self.receipts
            .values()
            .filter(|receipt| receipt.verdict.no_go_aligned())
            .count()
    }

    pub fn blocker_receipt_count(&self, blocker_id: &str) -> usize {
        self.reviewer_index
            .get(blocker_id)
            .map(HashSet::len)
            .map_or_zero()
    }

    fn validate_evidence(&self, record: &EvidenceRecord) -> Result<()> {
        if self.config.require_privacy_roots_only && record.privacy.root().0.is_empty() {
            return Err(Error::EvidenceRejected(
                "privacy record must contain deterministic roots".to_string(),
            ));
        }
        if record.class == EvidenceClass::ReplayDecision
            && !record.wave88_decision_id.contains("wave88")
        {
            return Err(Error::EvidenceRejected(
                "replay decision evidence must reference wave88".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_blocker(&self, blocker: &Blocker) -> Result<()> {
        if blocker.evidence_ids.is_empty() {
            return Err(Error::EvidenceRejected(
                "blocker must reference at least one evidence record".to_string(),
            ));
        }
        for evidence_id in &blocker.evidence_ids {
            if !self.evidence.contains_key(evidence_id) {
                return Err(Error::MissingRecord(evidence_id.clone()));
            }
        }
        if self.config.require_adversarial_replay
            && blocker.kind == BlockerKind::Adversarial
            && blocker.replay.is_none()
        {
            return Err(Error::EvidenceRejected(
                "adversarial blocker requires deterministic replay roots".to_string(),
            ));
        }
        Ok(())
    }

    fn validate_receipt(&self, receipt: &ReviewerReceipt) -> Result<()> {
        if !self.blockers.contains_key(&receipt.blocker_id) {
            return Err(Error::MissingBlocker(receipt.blocker_id.clone()));
        }
        if !self.config.allowed_reviewers.is_empty()
            && !self.config.allowed_reviewers.contains(&receipt.reviewer)
        {
            return Err(Error::ReceiptRejected(format!(
                "reviewer {} is not allowed for this gate",
                receipt.reviewer
            )));
        }
        let duplicate_for_blocker = self
            .reviewer_index
            .get(&receipt.blocker_id)
            .map(|reviewers| reviewers.contains(&receipt.reviewer))
            .map_or_false();
        if duplicate_for_blocker {
            return Err(Error::ReceiptRejected(format!(
                "reviewer {} already receipted blocker {}",
                receipt.reviewer, receipt.blocker_id
            )));
        }
        Ok(())
    }

    fn decision_reason(
        &self,
        decision: ReleaseDecision,
        unresolved: usize,
        critical: usize,
        receipts: usize,
    ) -> String {
        match decision {
            ReleaseDecision::NoGo => format!(
                "fail-closed no-go: unresolved={}, critical={}, receipts={}/{}",
                unresolved, critical, receipts, self.config.min_reviewer_receipts
            ),
            ReleaseDecision::Held => format!(
                "release held pending receipts: receipts={}/{}",
                receipts, self.config.min_reviewer_receipts
            ),
            ReleaseDecision::Candidate => {
                "candidate only: no release until captain records final authorization".to_string()
            }
            ReleaseDecision::Released => "released".to_string(),
        }
    }
}

pub fn devnet() -> Runtime {
    let mut state = match State::new(Config::devnet()) {
        Ok(state) => state,
        Err(_) => State {
            config: Config::devnet(),
            evidence: BTreeMap::new(),
            blockers: BTreeMap::new(),
            audit_findings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            decision_log: Vec::new(),
            reviewer_index: HashMap::new(),
        },
    };
    let privacy = match PrivacyRecord::roots_only(
        "devnet-commitment-root",
        "devnet-transcript-root",
        "devnet-witness-root",
        "devnet-redaction-root",
    ) {
        Ok(privacy) => privacy,
        Err(_) => PrivacyRecord {
            commitment_root: HashRoot("devnet-commitment-root".to_string()),
            transcript_root: HashRoot("devnet-transcript-root".to_string()),
            witness_root: HashRoot("devnet-witness-root".to_string()),
            redaction_root: HashRoot("devnet-redaction-root".to_string()),
        },
    };
    let evidence = EvidenceRecord::new(
        "wave89-devnet-evidence-privacy-001",
        EvidenceClass::PrivacyBlocker,
        Severity::High,
        "Wave 88 replay left privacy proof transcript unresolved",
        "wave88-go-no-go-replay-privacy-001",
        "wave88-source-root-privacy-001",
        privacy,
    );
    if let Ok(record) = evidence {
        let evidence_id = record.id.clone();
        let _ = state.add_evidence(record);
        let blocker = Blocker::new(
            "wave89-devnet-blocker-privacy-001",
            BlockerKind::Privacy,
            Severity::High,
            "privacy transcript roots require release-captain no-go archive",
        )
        .and_then(|blocker| blocker.add_evidence(evidence_id));
        if let Ok(blocker) = blocker {
            let _ = state.add_blocker(blocker);
        }
    }
    let _ = state.enforce_no_go();
    state
}

pub fn public_record(state: &State) -> PublicRecord {
    state.public_record()
}

pub fn state_root(state: &State) -> HashRoot {
    state.state_root()
}

fn ensure_not_empty(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(Error::EmptyField(field))
    } else {
        Ok(())
    }
}

fn timestamp_or_zero() -> Timestamp {
    match Timestamp::now() {
        Ok(timestamp) => timestamp,
        Err(_) => Timestamp(0),
    }
}

fn option_timestamp_to_u64(timestamp: Option<Timestamp>) -> u64 {
    match timestamp {
        Some(value) => value.0,
        None => 0,
    }
}

trait OptionStringExt {
    fn match_or_empty(self) -> String;
}

impl OptionStringExt for Option<String> {
    fn match_or_empty(self) -> String {
        match self {
            Some(value) => value,
            None => String::new(),
        }
    }
}

trait OptionDecisionExt {
    fn map_or_held_decision(self) -> ReleaseDecision;
}

impl OptionDecisionExt for Option<ReleaseDecision> {
    fn map_or_held_decision(self) -> ReleaseDecision {
        match self {
            Some(decision) => decision,
            None => ReleaseDecision::Held,
        }
    }
}

trait OptionUsizeExt {
    fn map_or_zero(self) -> usize;
}

impl OptionUsizeExt for Option<usize> {
    fn map_or_zero(self) -> usize {
        match self {
            Some(value) => value,
            None => 0,
        }
    }
}

trait OptionBoolExt {
    fn map_or_false(self) -> bool;
}

impl OptionBoolExt for Option<bool> {
    fn map_or_false(self) -> bool {
        match self {
            Some(value) => value,
            None => false,
        }
    }
}
