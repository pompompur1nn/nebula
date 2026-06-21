use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, Error>;
pub type Runtime = State;

const DOMAIN_CONFIG: &str = "wave89.release_captain.no_go.config";
const DOMAIN_STATE: &str = "wave89.release_captain.no_go.state";
const DOMAIN_RECORD: &str = "wave89.release_captain.no_go.public_record";
const DOMAIN_TRANSCRIPT: &str = "wave89.release_captain.no_go.transcript";
const DOMAIN_BLOCKER: &str = "wave89.release_captain.no_go.blocker";
const DOMAIN_RECEIPT: &str = "wave89.release_captain.no_go.receipt";
const DOMAIN_DECISION: &str = "wave88.release_captain.decision";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub network: Network,
    pub release_name: String,
    pub release_captain: String,
    pub fail_closed: bool,
    pub require_accepted_receipts: bool,
    pub allow_deferred_roots: bool,
    pub min_receipts_to_open: usize,
    pub max_archive_records: usize,
    pub max_transcript_events: usize,
    pub no_go_labels: BTreeSet<String>,
    pub accepted_receipt_labels: BTreeSet<String>,
}

impl Config {
    pub fn new(network: Network, release_name: &str, release_captain: &str) -> Self {
        let mut no_go_labels = BTreeSet::new();
        no_go_labels.insert("wave88-runtime-replay-mismatch".to_string());
        no_go_labels.insert("deferred-root-present".to_string());
        no_go_labels.insert("release-captain-no-go".to_string());

        let mut accepted_receipt_labels = BTreeSet::new();
        accepted_receipt_labels.insert("accepted-runtime-replay-receipt".to_string());
        accepted_receipt_labels.insert("runtime-replay-root-replaced".to_string());

        Self {
            network,
            release_name: release_name.to_string(),
            release_captain: release_captain.to_string(),
            fail_closed: true,
            require_accepted_receipts: true,
            allow_deferred_roots: false,
            min_receipts_to_open: 1,
            max_archive_records: 512,
            max_transcript_events: 2048,
            no_go_labels,
            accepted_receipt_labels,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Network::Devnet, "wave89-devnet", "release-captain")
    }

    pub fn config_root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_CONFIG);
        h.field("network", self.network.as_str());
        h.field("release_name", &self.release_name);
        h.field("release_captain", &self.release_captain);
        h.bool("fail_closed", self.fail_closed);
        h.bool("require_accepted_receipts", self.require_accepted_receipts);
        h.bool("allow_deferred_roots", self.allow_deferred_roots);
        h.usize("min_receipts_to_open", self.min_receipts_to_open);
        h.usize("max_archive_records", self.max_archive_records);
        h.usize("max_transcript_events", self.max_transcript_events);
        h.set("no_go_labels", &self.no_go_labels);
        h.set("accepted_receipt_labels", &self.accepted_receipt_labels);
        h.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Network {
    Devnet,
    Testnet,
    Mainnet,
    Custom(String),
}

impl Network {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Devnet => "devnet",
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
            Self::Custom(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Root(pub u64);

impl Root {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn hex(self) -> String {
        format!("{:016x}", self.0)
    }

    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Root {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub release: ReleaseGate,
    archive: BTreeMap<EvidenceId, EvidenceRecord>,
    wave88_decisions: BTreeMap<DecisionId, Wave88Decision>,
    transcript: ReplayTranscript,
    blockers: BTreeMap<BlockerId, MismatchBlocker>,
    receipts: BTreeMap<ReceiptId, RuntimeReplayReceipt>,
    audit: VecDeque<AuditEvent>,
    next_evidence: u64,
    next_decision: u64,
    next_blocker: u64,
    next_receipt: u64,
    next_audit: u64,
}

impl State {
    pub fn new(config: Config) -> Self {
        let release = ReleaseGate::new(config.config_root());
        Self {
            config,
            release,
            archive: BTreeMap::new(),
            wave88_decisions: BTreeMap::new(),
            transcript: ReplayTranscript::new(),
            blockers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            audit: VecDeque::new(),
            next_evidence: 1,
            next_decision: 1,
            next_blocker: 1,
            next_receipt: 1,
            next_audit: 1,
        }
    }

    pub fn devnet() -> Self {
        Self::new(Config::devnet())
    }

    pub fn ingest_wave88_decision(&mut self, input: Wave88DecisionInput) -> Result<DecisionId> {
        if input.subject.trim().is_empty() {
            return Err(Error::EmptyField("decision.subject"));
        }
        if input.decision_root.is_zero() {
            return Err(Error::ZeroRoot("decision.decision_root"));
        }

        let id = DecisionId(self.next_decision);
        self.next_decision = self.next_decision.saturating_add(1);
        let decision = Wave88Decision {
            id,
            subject: input.subject,
            decision_root: input.decision_root,
            replay_root: input.replay_root,
            deferred_root: input.deferred_root,
            mismatch_root: input.mismatch_root,
            labels: input.labels,
            accepted: input.accepted,
            observed_at: input.observed_at,
        };

        let decision_root = decision.root();
        if decision.has_no_go_signal(&self.config) {
            let blocker_id =
                self.add_blocker(BlockerKind::Wave88DecisionNoGo, decision_root, id.0)?;
            self.release
                .hold(ReleaseReason::Wave88NoGo, blocker_id.root());
        }
        if decision.deferred_root.is_some() && !self.config.allow_deferred_roots {
            let blocker_id =
                self.add_blocker(BlockerKind::DeferredReplayRoot, decision_root, id.0)?;
            self.release
                .hold(ReleaseReason::DeferredRoot, blocker_id.root());
        }
        if decision.mismatch_root.is_some() {
            let blocker_id = self.add_blocker(BlockerKind::ReplayMismatch, decision_root, id.0)?;
            self.release
                .hold(ReleaseReason::ReplayMismatch, blocker_id.root());
        }

        self.transcript
            .push(ReplayEvent::decision(id, decision_root));
        self.wave88_decisions.insert(id, decision);
        self.audit("ingest_wave88_decision", decision_root);
        self.enforce_archive_limit();
        self.enforce_transcript_limit();
        self.recompute_gate();
        Ok(id)
    }

    pub fn archive_mismatch_evidence(&mut self, input: EvidenceInput) -> Result<EvidenceId> {
        input.validate()?;
        let id = EvidenceId(self.next_evidence);
        self.next_evidence = self.next_evidence.saturating_add(1);
        let record = EvidenceRecord {
            id,
            kind: input.kind,
            source: input.source,
            subject: input.subject,
            evidence_root: input.evidence_root,
            required_root: input.required_root,
            observed_root: input.observed_root,
            transcript_root: self.transcript.root(),
            receipt_root: None,
            privacy: PrivacyMode::RootsOnly,
            labels: input.labels,
            archived_at: input.archived_at,
            status: EvidenceStatus::ArchivedNoGo,
        };
        let record_root = record.root();
        self.archive.insert(id, record);
        let blocker_id = self.add_blocker(BlockerKind::ArchivedEvidenceNoGo, record_root, id.0)?;
        self.release
            .hold(ReleaseReason::EvidenceArchived, blocker_id.root());
        self.transcript.push(ReplayEvent::evidence(id, record_root));
        self.audit("archive_mismatch_evidence", record_root);
        self.enforce_archive_limit();
        self.enforce_transcript_limit();
        self.recompute_gate();
        Ok(id)
    }

    pub fn append_replay_event(&mut self, input: ReplayEventInput) -> Result<ReplayEventId> {
        input.validate()?;
        let event = ReplayEvent {
            id: ReplayEventId(self.transcript.next_id),
            phase: input.phase,
            source: input.source,
            subject_root: input.subject_root,
            replay_root: input.replay_root,
            accepted_receipt_root: input.accepted_receipt_root,
            note_root: input.note_root,
            occurred_at: input.occurred_at,
        };
        let event_id = event.id;
        let event_root = event.root();
        self.transcript.push(event);
        self.audit("append_replay_event", event_root);
        self.enforce_transcript_limit();
        self.recompute_gate();
        Ok(event_id)
    }

    pub fn accept_runtime_replay_receipt(
        &mut self,
        input: RuntimeReplayReceiptInput,
    ) -> Result<ReceiptId> {
        input.validate()?;
        if input.deferred_root_replaced.is_zero() {
            return Err(Error::ZeroRoot("receipt.deferred_root_replaced"));
        }
        let id = ReceiptId(self.next_receipt);
        self.next_receipt = self.next_receipt.saturating_add(1);
        let receipt = RuntimeReplayReceipt {
            id,
            source: input.source,
            subject: input.subject,
            accepted_root: input.accepted_root,
            transcript_root: input.transcript_root,
            deferred_root_replaced: input.deferred_root_replaced,
            labels: input.labels,
            accepted_at: input.accepted_at,
            status: ReceiptStatus::Accepted,
        };
        if !receipt.has_accepted_label(&self.config) {
            return Err(Error::ReceiptNotAccepted);
        }

        let receipt_root = receipt.root();
        self.receipts.insert(id, receipt);
        self.attach_receipt_to_matching_evidence(receipt_root);
        self.transcript.push(ReplayEvent::receipt(id, receipt_root));
        self.audit("accept_runtime_replay_receipt", receipt_root);
        self.clear_blockers_replaced_by_receipt(receipt_root);
        self.enforce_transcript_limit();
        self.recompute_gate();
        Ok(id)
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            release_name: self.config.release_name.clone(),
            network: self.config.network.clone(),
            release_status: self.release.status,
            release_reason: self.release.reason,
            config_root: self.config.config_root(),
            archive_root: self.archive_root(),
            decisions_root: self.decisions_root(),
            transcript_root: self.transcript.root(),
            blockers_root: self.blockers_root(),
            receipts_root: self.receipts_root(),
            state_root: self.state_root(),
            evidence_count: self.archive.len(),
            decision_count: self.wave88_decisions.len(),
            blocker_count: self.active_blocker_count(),
            accepted_receipt_count: self.accepted_receipt_count(),
            roots_only: true,
        }
    }

    pub fn state_root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_STATE);
        h.root("config", self.config.config_root());
        h.root("release", self.release.root());
        h.root("archive", self.archive_root());
        h.root("decisions", self.decisions_root());
        h.root("transcript", self.transcript.root());
        h.root("blockers", self.blockers_root());
        h.root("receipts", self.receipts_root());
        h.root("audit", self.audit_root());
        h.usize("active_blockers", self.active_blocker_count());
        h.usize("accepted_receipts", self.accepted_receipt_count());
        h.finish()
    }

    pub fn archive_root(&self) -> Root {
        let mut h = RootBuilder::new("archive");
        for (id, record) in &self.archive {
            h.u64("id", id.0);
            h.root("record", record.root());
        }
        h.finish()
    }

    pub fn decisions_root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_DECISION);
        for (id, decision) in &self.wave88_decisions {
            h.u64("id", id.0);
            h.root("decision", decision.root());
        }
        h.finish()
    }

    pub fn blockers_root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_BLOCKER);
        for (id, blocker) in &self.blockers {
            h.u64("id", id.0);
            h.root("blocker", blocker.root());
        }
        h.finish()
    }

    pub fn receipts_root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_RECEIPT);
        for (id, receipt) in &self.receipts {
            h.u64("id", id.0);
            h.root("receipt", receipt.root());
        }
        h.finish()
    }

    pub fn audit_root(&self) -> Root {
        let mut h = RootBuilder::new("audit");
        for event in &self.audit {
            h.root("event", event.root());
        }
        h.finish()
    }

    pub fn active_blocker_count(&self) -> usize {
        self.blockers
            .values()
            .filter(|b| b.status == BlockerStatus::Active)
            .count()
    }

    pub fn accepted_receipt_count(&self) -> usize {
        self.receipts
            .values()
            .filter(|r| r.status == ReceiptStatus::Accepted)
            .count()
    }

    pub fn evidence(&self, id: EvidenceId) -> Option<&EvidenceRecord> {
        self.archive.get(&id)
    }

    pub fn blocker(&self, id: BlockerId) -> Option<&MismatchBlocker> {
        self.blockers.get(&id)
    }

    pub fn receipt(&self, id: ReceiptId) -> Option<&RuntimeReplayReceipt> {
        self.receipts.get(&id)
    }

    pub fn transcript(&self) -> &ReplayTranscript {
        &self.transcript
    }

    fn add_blocker(
        &mut self,
        kind: BlockerKind,
        source_root: Root,
        source_nonce: u64,
    ) -> Result<BlockerId> {
        if source_root.is_zero() {
            return Err(Error::ZeroRoot("blocker.source_root"));
        }
        let id = BlockerId(self.next_blocker);
        self.next_blocker = self.next_blocker.saturating_add(1);
        let blocker = MismatchBlocker {
            id,
            kind,
            source_root,
            source_nonce,
            transcript_root: self.transcript.root(),
            status: BlockerStatus::Active,
            opened_at: now_seconds(),
            cleared_by_receipt_root: None,
        };
        self.blockers.insert(id, blocker);
        Ok(id)
    }

    fn attach_receipt_to_matching_evidence(&mut self, receipt_root: Root) {
        for record in self.archive.values_mut() {
            if record.receipt_root.is_none() && record.status == EvidenceStatus::ArchivedNoGo {
                record.receipt_root = Some(receipt_root);
                record.status = EvidenceStatus::ReceiptAttached;
            }
        }
    }

    fn clear_blockers_replaced_by_receipt(&mut self, receipt_root: Root) {
        for blocker in self.blockers.values_mut() {
            if blocker.status == BlockerStatus::Active {
                blocker.status = BlockerStatus::ClearedByAcceptedReceipt;
                blocker.cleared_by_receipt_root = Some(receipt_root);
            }
        }
    }

    fn recompute_gate(&mut self) {
        let active_blockers = self.active_blocker_count();
        let accepted_receipts = self.accepted_receipt_count();
        if self.config.fail_closed && active_blockers > 0 {
            self.release.status = ReleaseStatus::HeldNoGo;
            self.release.reason = ReleaseReason::ActiveBlocker;
            self.release.last_gate_root = self.gate_material_root();
            return;
        }
        if self.config.require_accepted_receipts
            && accepted_receipts < self.config.min_receipts_to_open
        {
            self.release.status = ReleaseStatus::HeldNoGo;
            self.release.reason = ReleaseReason::MissingAcceptedReceipt;
            self.release.last_gate_root = self.gate_material_root();
            return;
        }
        self.release.status = ReleaseStatus::OpenByAcceptedReplay;
        self.release.reason = ReleaseReason::AcceptedReceiptsPresent;
        self.release.last_gate_root = self.gate_material_root();
    }

    fn gate_material_root(&self) -> Root {
        let mut h = RootBuilder::new("gate_material");
        h.root("archive", self.archive_root());
        h.root("transcript", self.transcript.root());
        h.root("blockers", self.blockers_root());
        h.root("receipts", self.receipts_root());
        h.usize("active_blockers", self.active_blocker_count());
        h.usize("accepted_receipts", self.accepted_receipt_count());
        h.finish()
    }

    fn audit(&mut self, action: &str, action_root: Root) {
        let event = AuditEvent {
            id: self.next_audit,
            action: action.to_string(),
            action_root,
            state_hint_root: self.gate_material_root(),
            at: now_seconds(),
        };
        self.next_audit = self.next_audit.saturating_add(1);
        self.audit.push_back(event);
        while self.audit.len() > self.config.max_archive_records {
            self.audit.pop_front();
        }
    }

    fn enforce_archive_limit(&mut self) {
        while self.archive.len() > self.config.max_archive_records {
            let first = self.archive.keys().next().copied();
            if let Some(id) = first {
                self.archive.remove(&id);
            } else {
                break;
            }
        }
    }

    fn enforce_transcript_limit(&mut self) {
        self.transcript
            .truncate_front(self.config.max_transcript_events);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseGate {
    pub status: ReleaseStatus,
    pub reason: ReleaseReason,
    pub config_root: Root,
    pub last_gate_root: Root,
}

impl ReleaseGate {
    pub fn new(config_root: Root) -> Self {
        Self {
            status: ReleaseStatus::HeldNoGo,
            reason: ReleaseReason::FailClosedDefault,
            config_root,
            last_gate_root: config_root,
        }
    }

    pub fn hold(&mut self, reason: ReleaseReason, material_root: Root) {
        self.status = ReleaseStatus::HeldNoGo;
        self.reason = reason;
        self.last_gate_root = material_root;
    }

    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new("release_gate");
        h.field("status", self.status.as_str());
        h.field("reason", self.reason.as_str());
        h.root("config_root", self.config_root);
        h.root("last_gate_root", self.last_gate_root);
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseStatus {
    HeldNoGo,
    OpenByAcceptedReplay,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeldNoGo => "held-no-go",
            Self::OpenByAcceptedReplay => "open-by-accepted-replay",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseReason {
    FailClosedDefault,
    Wave88NoGo,
    DeferredRoot,
    ReplayMismatch,
    EvidenceArchived,
    ActiveBlocker,
    MissingAcceptedReceipt,
    AcceptedReceiptsPresent,
}

impl ReleaseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FailClosedDefault => "fail-closed-default",
            Self::Wave88NoGo => "wave88-no-go",
            Self::DeferredRoot => "deferred-root",
            Self::ReplayMismatch => "replay-mismatch",
            Self::EvidenceArchived => "evidence-archived",
            Self::ActiveBlocker => "active-blocker",
            Self::MissingAcceptedReceipt => "missing-accepted-receipt",
            Self::AcceptedReceiptsPresent => "accepted-receipts-present",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub release_name: String,
    pub network: Network,
    pub release_status: ReleaseStatus,
    pub release_reason: ReleaseReason,
    pub config_root: Root,
    pub archive_root: Root,
    pub decisions_root: Root,
    pub transcript_root: Root,
    pub blockers_root: Root,
    pub receipts_root: Root,
    pub state_root: Root,
    pub evidence_count: usize,
    pub decision_count: usize,
    pub blocker_count: usize,
    pub accepted_receipt_count: usize,
    pub roots_only: bool,
}

impl PublicRecord {
    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_RECORD);
        h.field("release_name", &self.release_name);
        h.field("network", self.network.as_str());
        h.field("release_status", self.release_status.as_str());
        h.field("release_reason", self.release_reason.as_str());
        h.root("config_root", self.config_root);
        h.root("archive_root", self.archive_root);
        h.root("decisions_root", self.decisions_root);
        h.root("transcript_root", self.transcript_root);
        h.root("blockers_root", self.blockers_root);
        h.root("receipts_root", self.receipts_root);
        h.root("state_root", self.state_root);
        h.usize("evidence_count", self.evidence_count);
        h.usize("decision_count", self.decision_count);
        h.usize("blocker_count", self.blocker_count);
        h.usize("accepted_receipt_count", self.accepted_receipt_count);
        h.bool("roots_only", self.roots_only);
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecisionId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockerId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReceiptId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReplayEventId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wave88DecisionInput {
    pub subject: String,
    pub decision_root: Root,
    pub replay_root: Root,
    pub deferred_root: Option<Root>,
    pub mismatch_root: Option<Root>,
    pub labels: BTreeSet<String>,
    pub accepted: bool,
    pub observed_at: u64,
}

impl Wave88DecisionInput {
    pub fn no_go(
        subject: &str,
        decision_root: Root,
        replay_root: Root,
        mismatch_root: Root,
    ) -> Self {
        let mut labels = BTreeSet::new();
        labels.insert("wave88-runtime-replay-mismatch".to_string());
        labels.insert("release-captain-no-go".to_string());
        Self {
            subject: subject.to_string(),
            decision_root,
            replay_root,
            deferred_root: None,
            mismatch_root: Some(mismatch_root),
            labels,
            accepted: false,
            observed_at: now_seconds(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wave88Decision {
    pub id: DecisionId,
    pub subject: String,
    pub decision_root: Root,
    pub replay_root: Root,
    pub deferred_root: Option<Root>,
    pub mismatch_root: Option<Root>,
    pub labels: BTreeSet<String>,
    pub accepted: bool,
    pub observed_at: u64,
}

impl Wave88Decision {
    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_DECISION);
        h.u64("id", self.id.0);
        h.field("subject", &self.subject);
        h.root("decision_root", self.decision_root);
        h.root("replay_root", self.replay_root);
        h.optional_root("deferred_root", self.deferred_root);
        h.optional_root("mismatch_root", self.mismatch_root);
        h.set("labels", &self.labels);
        h.bool("accepted", self.accepted);
        h.u64("observed_at", self.observed_at);
        h.finish()
    }

    pub fn has_no_go_signal(&self, config: &Config) -> bool {
        !self.accepted
            || self
                .labels
                .iter()
                .any(|label| config.no_go_labels.contains(label))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceInput {
    pub kind: EvidenceKind,
    pub source: EvidenceSource,
    pub subject: String,
    pub evidence_root: Root,
    pub required_root: Root,
    pub observed_root: Root,
    pub labels: BTreeSet<String>,
    pub archived_at: u64,
}

impl EvidenceInput {
    pub fn replay_mismatch(subject: &str, required_root: Root, observed_root: Root) -> Self {
        let mut labels = BTreeSet::new();
        labels.insert("runtime-replay-mismatch".to_string());
        labels.insert("release-captain-no-go".to_string());
        let mut h = RootBuilder::new("evidence_input");
        h.field("subject", subject);
        h.root("required", required_root);
        h.root("observed", observed_root);
        Self {
            kind: EvidenceKind::ReplayMismatch,
            source: EvidenceSource::RuntimeReplay,
            subject: subject.to_string(),
            evidence_root: h.finish(),
            required_root,
            observed_root,
            labels,
            archived_at: now_seconds(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.subject.trim().is_empty() {
            return Err(Error::EmptyField("evidence.subject"));
        }
        if self.evidence_root.is_zero() {
            return Err(Error::ZeroRoot("evidence.evidence_root"));
        }
        if self.required_root.is_zero() {
            return Err(Error::ZeroRoot("evidence.required_root"));
        }
        if self.observed_root.is_zero() {
            return Err(Error::ZeroRoot("evidence.observed_root"));
        }
        if self.required_root == self.observed_root {
            return Err(Error::RootsMatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub source: EvidenceSource,
    pub subject: String,
    pub evidence_root: Root,
    pub required_root: Root,
    pub observed_root: Root,
    pub transcript_root: Root,
    pub receipt_root: Option<Root>,
    pub privacy: PrivacyMode,
    pub labels: BTreeSet<String>,
    pub archived_at: u64,
    pub status: EvidenceStatus,
}

impl EvidenceRecord {
    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new("evidence_record");
        h.u64("id", self.id.0);
        h.field("kind", self.kind.as_str());
        h.field("source", self.source.as_str());
        h.field("subject", &self.subject);
        h.root("evidence_root", self.evidence_root);
        h.root("required_root", self.required_root);
        h.root("observed_root", self.observed_root);
        h.root("transcript_root", self.transcript_root);
        h.optional_root("receipt_root", self.receipt_root);
        h.field("privacy", self.privacy.as_str());
        h.set("labels", &self.labels);
        h.u64("archived_at", self.archived_at);
        h.field("status", self.status.as_str());
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    ReplayMismatch,
    DeferredRoot,
    ReleaseCaptainNoGo,
    OperatorAttestationGap,
    ReceiptReplacementGap,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayMismatch => "replay-mismatch",
            Self::DeferredRoot => "deferred-root",
            Self::ReleaseCaptainNoGo => "release-captain-no-go",
            Self::OperatorAttestationGap => "operator-attestation-gap",
            Self::ReceiptReplacementGap => "receipt-replacement-gap",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    Wave88Decision,
    RuntimeReplay,
    ReleaseCaptain,
    Operator,
    DevnetHarness,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave88Decision => "wave88-decision",
            Self::RuntimeReplay => "runtime-replay",
            Self::ReleaseCaptain => "release-captain",
            Self::Operator => "operator",
            Self::DevnetHarness => "devnet-harness",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivacyMode {
    RootsOnly,
}

impl PrivacyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootsOnly => "roots-only",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceStatus {
    ArchivedNoGo,
    ReceiptAttached,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArchivedNoGo => "archived-no-go",
            Self::ReceiptAttached => "receipt-attached",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTranscript {
    events: VecDeque<ReplayEvent>,
    next_id: u64,
}

impl ReplayTranscript {
    pub fn new() -> Self {
        Self {
            events: VecDeque::new(),
            next_id: 1,
        }
    }

    pub fn events(&self) -> impl Iterator<Item = &ReplayEvent> {
        self.events.iter()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_TRANSCRIPT);
        for event in &self.events {
            h.root("event", event.root());
        }
        h.u64("next_id", self.next_id);
        h.finish()
    }

    fn push(&mut self, mut event: ReplayEvent) {
        event.id = ReplayEventId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.events.push_back(event);
    }

    fn truncate_front(&mut self, max_events: usize) {
        while self.events.len() > max_events {
            self.events.pop_front();
        }
    }
}

impl Default for ReplayTranscript {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayEventInput {
    pub phase: ReplayPhase,
    pub source: EvidenceSource,
    pub subject_root: Root,
    pub replay_root: Root,
    pub accepted_receipt_root: Option<Root>,
    pub note_root: Option<Root>,
    pub occurred_at: u64,
}

impl ReplayEventInput {
    pub fn validate(&self) -> Result<()> {
        if self.subject_root.is_zero() {
            return Err(Error::ZeroRoot("replay_event.subject_root"));
        }
        if self.replay_root.is_zero() {
            return Err(Error::ZeroRoot("replay_event.replay_root"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayEvent {
    pub id: ReplayEventId,
    pub phase: ReplayPhase,
    pub source: EvidenceSource,
    pub subject_root: Root,
    pub replay_root: Root,
    pub accepted_receipt_root: Option<Root>,
    pub note_root: Option<Root>,
    pub occurred_at: u64,
}

impl ReplayEvent {
    pub fn decision(id: DecisionId, decision_root: Root) -> Self {
        Self {
            id: ReplayEventId(0),
            phase: ReplayPhase::Wave88DecisionImported,
            source: EvidenceSource::Wave88Decision,
            subject_root: mix_roots("decision-id", Root(id.0), decision_root),
            replay_root: decision_root,
            accepted_receipt_root: None,
            note_root: None,
            occurred_at: now_seconds(),
        }
    }

    pub fn evidence(id: EvidenceId, record_root: Root) -> Self {
        Self {
            id: ReplayEventId(0),
            phase: ReplayPhase::NoGoEvidenceArchived,
            source: EvidenceSource::ReleaseCaptain,
            subject_root: mix_roots("evidence-id", Root(id.0), record_root),
            replay_root: record_root,
            accepted_receipt_root: None,
            note_root: None,
            occurred_at: now_seconds(),
        }
    }

    pub fn receipt(id: ReceiptId, receipt_root: Root) -> Self {
        Self {
            id: ReplayEventId(0),
            phase: ReplayPhase::AcceptedReceiptImported,
            source: EvidenceSource::RuntimeReplay,
            subject_root: mix_roots("receipt-id", Root(id.0), receipt_root),
            replay_root: receipt_root,
            accepted_receipt_root: Some(receipt_root),
            note_root: None,
            occurred_at: now_seconds(),
        }
    }

    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new("replay_event");
        h.u64("id", self.id.0);
        h.field("phase", self.phase.as_str());
        h.field("source", self.source.as_str());
        h.root("subject_root", self.subject_root);
        h.root("replay_root", self.replay_root);
        h.optional_root("accepted_receipt_root", self.accepted_receipt_root);
        h.optional_root("note_root", self.note_root);
        h.u64("occurred_at", self.occurred_at);
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReplayPhase {
    Wave88DecisionImported,
    RuntimeReplayStarted,
    RuntimeReplayFinished,
    RuntimeReplayMismatch,
    NoGoEvidenceArchived,
    DeferredRootObserved,
    AcceptedReceiptImported,
    GateRecomputed,
}

impl ReplayPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave88DecisionImported => "wave88-decision-imported",
            Self::RuntimeReplayStarted => "runtime-replay-started",
            Self::RuntimeReplayFinished => "runtime-replay-finished",
            Self::RuntimeReplayMismatch => "runtime-replay-mismatch",
            Self::NoGoEvidenceArchived => "no-go-evidence-archived",
            Self::DeferredRootObserved => "deferred-root-observed",
            Self::AcceptedReceiptImported => "accepted-receipt-imported",
            Self::GateRecomputed => "gate-recomputed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MismatchBlocker {
    pub id: BlockerId,
    pub kind: BlockerKind,
    pub source_root: Root,
    pub source_nonce: u64,
    pub transcript_root: Root,
    pub status: BlockerStatus,
    pub opened_at: u64,
    pub cleared_by_receipt_root: Option<Root>,
}

impl MismatchBlocker {
    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_BLOCKER);
        h.u64("id", self.id.0);
        h.field("kind", self.kind.as_str());
        h.root("source_root", self.source_root);
        h.u64("source_nonce", self.source_nonce);
        h.root("transcript_root", self.transcript_root);
        h.field("status", self.status.as_str());
        h.u64("opened_at", self.opened_at);
        h.optional_root("cleared_by_receipt_root", self.cleared_by_receipt_root);
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockerKind {
    Wave88DecisionNoGo,
    ReplayMismatch,
    DeferredReplayRoot,
    ArchivedEvidenceNoGo,
}

impl BlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave88DecisionNoGo => "wave88-decision-no-go",
            Self::ReplayMismatch => "replay-mismatch",
            Self::DeferredReplayRoot => "deferred-replay-root",
            Self::ArchivedEvidenceNoGo => "archived-evidence-no-go",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BlockerStatus {
    Active,
    ClearedByAcceptedReceipt,
}

impl BlockerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ClearedByAcceptedReceipt => "cleared-by-accepted-receipt",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReplayReceiptInput {
    pub source: EvidenceSource,
    pub subject: String,
    pub accepted_root: Root,
    pub transcript_root: Root,
    pub deferred_root_replaced: Root,
    pub labels: BTreeSet<String>,
    pub accepted_at: u64,
}

impl RuntimeReplayReceiptInput {
    pub fn accepted(
        subject: &str,
        accepted_root: Root,
        transcript_root: Root,
        deferred_root_replaced: Root,
    ) -> Self {
        let mut labels = BTreeSet::new();
        labels.insert("accepted-runtime-replay-receipt".to_string());
        labels.insert("runtime-replay-root-replaced".to_string());
        Self {
            source: EvidenceSource::RuntimeReplay,
            subject: subject.to_string(),
            accepted_root,
            transcript_root,
            deferred_root_replaced,
            labels,
            accepted_at: now_seconds(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.subject.trim().is_empty() {
            return Err(Error::EmptyField("receipt.subject"));
        }
        if self.accepted_root.is_zero() {
            return Err(Error::ZeroRoot("receipt.accepted_root"));
        }
        if self.transcript_root.is_zero() {
            return Err(Error::ZeroRoot("receipt.transcript_root"));
        }
        if self.labels.is_empty() {
            return Err(Error::EmptyField("receipt.labels"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeReplayReceipt {
    pub id: ReceiptId,
    pub source: EvidenceSource,
    pub subject: String,
    pub accepted_root: Root,
    pub transcript_root: Root,
    pub deferred_root_replaced: Root,
    pub labels: BTreeSet<String>,
    pub accepted_at: u64,
    pub status: ReceiptStatus,
}

impl RuntimeReplayReceipt {
    pub fn has_accepted_label(&self, config: &Config) -> bool {
        self.labels
            .iter()
            .any(|label| config.accepted_receipt_labels.contains(label))
    }

    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new(DOMAIN_RECEIPT);
        h.u64("id", self.id.0);
        h.field("source", self.source.as_str());
        h.field("subject", &self.subject);
        h.root("accepted_root", self.accepted_root);
        h.root("transcript_root", self.transcript_root);
        h.root("deferred_root_replaced", self.deferred_root_replaced);
        h.set("labels", &self.labels);
        h.u64("accepted_at", self.accepted_at);
        h.field("status", self.status.as_str());
        h.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiptStatus {
    Accepted,
}

impl ReceiptStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub id: u64,
    pub action: String,
    pub action_root: Root,
    pub state_hint_root: Root,
    pub at: u64,
}

impl AuditEvent {
    pub fn root(&self) -> Root {
        let mut h = RootBuilder::new("audit_event");
        h.u64("id", self.id);
        h.field("action", &self.action);
        h.root("action_root", self.action_root);
        h.root("state_hint_root", self.state_hint_root);
        h.u64("at", self.at);
        h.finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    EmptyField(&'static str),
    ZeroRoot(&'static str),
    RootsMatch,
    ReceiptNotAccepted,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "empty field: {}", field),
            Self::ZeroRoot(field) => write!(f, "zero root: {}", field),
            Self::RootsMatch => write!(f, "required and observed roots match"),
            Self::ReceiptNotAccepted => {
                write!(f, "receipt is missing an accepted runtime replay label")
            }
        }
    }
}

impl std::error::Error for Error {}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record(runtime: &Runtime) -> PublicRecord {
    runtime.public_record()
}

pub fn state_root(runtime: &Runtime) -> Root {
    runtime.state_root()
}

pub fn root_from_parts(domain: &str, parts: &[Root]) -> Root {
    let mut h = RootBuilder::new(domain);
    for part in parts {
        h.root("part", *part);
    }
    h.finish()
}

pub fn labels(items: &[&str]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for item in items {
        out.insert((*item).to_string());
    }
    out
}

pub fn summarize_by_status(records: &[PublicRecord]) -> HashMap<&'static str, usize> {
    let mut counts = HashMap::new();
    for record in records {
        let key = record.release_status.as_str();
        let current = match counts.get(key).copied() {
            Some(value) => value,
            None => 0usize,
        };
        let next = current.saturating_add(1);
        counts.insert(key, next);
    }
    counts
}

fn mix_roots(domain: &str, left: Root, right: Root) -> Root {
    let mut h = RootBuilder::new(domain);
    h.root("left", left);
    h.root("right", right);
    h.finish()
}

fn now_seconds() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

struct RootBuilder {
    state: u64,
}

impl RootBuilder {
    fn new(domain: &str) -> Self {
        let mut builder = Self {
            state: 0xcbf2_9ce4_8422_2325,
        };
        builder.field("domain", domain);
        builder
    }

    fn field(&mut self, name: &str, value: &str) {
        self.absorb(name);
        self.absorb(value);
    }

    fn bool(&mut self, name: &str, value: bool) {
        self.field(name, if value { "true" } else { "false" });
    }

    fn usize(&mut self, name: &str, value: usize) {
        self.u64(name, value as u64);
    }

    fn u64(&mut self, name: &str, value: u64) {
        self.absorb(name);
        self.absorb_u64(value);
    }

    fn root(&mut self, name: &str, value: Root) {
        self.u64(name, value.0);
    }

    fn optional_root(&mut self, name: &str, value: Option<Root>) {
        match value {
            Some(root) => {
                self.field(name, "some");
                self.root(name, root);
            }
            None => self.field(name, "none"),
        }
    }

    fn set(&mut self, name: &str, values: &BTreeSet<String>) {
        self.absorb(name);
        self.usize("len", values.len());
        for value in values {
            self.absorb(value);
        }
    }

    fn finish(self) -> Root {
        Root(splitmix64(self.state ^ 0x9e37_79b9_7f4a_7c15))
    }

    fn absorb(&mut self, value: &str) {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        self.absorb_u64(hasher.finish());
        self.absorb_u64(value.len() as u64);
    }

    fn absorb_u64(&mut self, value: u64) {
        self.state ^= splitmix64(value.wrapping_add(0x9e37_79b9_7f4a_7c15));
        self.state = self
            .state
            .rotate_left(27)
            .wrapping_mul(0x94d0_49bb_1331_11eb);
        self.state ^= self.state >> 31;
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
