use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::hash::{Hash, Hasher};

pub type Result<T> = std::result::Result<T, Error>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave89-release-captain-no-go-evidence-archive-wallet-watchtower-gate-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "stdlib-default-hasher-domain-separated-roots-v1";
pub const DEFAULT_CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
pub const DEFAULT_RELEASE_ID: &str = "wave89-release-captain-no-go-replay";
pub const DEFAULT_SOURCE_WAVE: u64 = 88;
pub const DEFAULT_QUORUM: usize = 3;
pub const DEFAULT_MIN_WALLET_RECORDS: usize = 3;
pub const DEFAULT_MIN_ESCAPE_RECORDS: usize = 2;
pub const DEFAULT_MIN_RUNBOOK_RECORDS: usize = 2;
pub const DEFAULT_MAX_RECORDS: usize = 16_384;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidConfig(String),
    DuplicateRecord(String),
    MissingRecord(String),
    RecordLimitReached,
    RedactionLeak(String),
    QuorumNotMet(String),
    ReleaseHeld(String),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig(_) => "invalid_config",
            Self::DuplicateRecord(_) => "duplicate_record",
            Self::MissingRecord(_) => "missing_record",
            Self::RecordLimitReached => "record_limit_reached",
            Self::RedactionLeak(_) => "redaction_leak",
            Self::QuorumNotMet(_) => "quorum_not_met",
            Self::ReleaseHeld(_) => "release_held",
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::InvalidConfig(value)
            | Self::DuplicateRecord(value)
            | Self::MissingRecord(value)
            | Self::RedactionLeak(value)
            | Self::QuorumNotMet(value)
            | Self::ReleaseHeld(value) => value,
            Self::RecordLimitReached => "record limit reached",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub chain_id: String,
    pub release_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub source_wave: u64,
    pub required_watchtower_quorum: usize,
    pub min_wallet_records: usize,
    pub min_escape_records: usize,
    pub min_runbook_records: usize,
    pub max_records: usize,
    pub fail_closed: bool,
    pub production_release_allowed: bool,
    pub require_roots_only_public_record: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            release_id: DEFAULT_RELEASE_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            source_wave: DEFAULT_SOURCE_WAVE,
            required_watchtower_quorum: DEFAULT_QUORUM,
            min_wallet_records: DEFAULT_MIN_WALLET_RECORDS,
            min_escape_records: DEFAULT_MIN_ESCAPE_RECORDS,
            min_runbook_records: DEFAULT_MIN_RUNBOOK_RECORDS,
            max_records: DEFAULT_MAX_RECORDS,
            fail_closed: true,
            production_release_allowed: false,
            require_roots_only_public_record: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.chain_id.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "chain_id must not be empty".to_string(),
            ));
        }
        if self.release_id.trim().is_empty() {
            return Err(Error::InvalidConfig(
                "release_id must not be empty".to_string(),
            ));
        }
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(Error::InvalidConfig(
                "invalid protocol version for wave89 no-go archive".to_string(),
            ));
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(Error::InvalidConfig(
                "unsupported schema version".to_string(),
            ));
        }
        if self.required_watchtower_quorum == 0 {
            return Err(Error::InvalidConfig(
                "watchtower quorum must be greater than zero".to_string(),
            ));
        }
        if self.max_records == 0 {
            return Err(Error::InvalidConfig(
                "max_records must be greater than zero".to_string(),
            ));
        }
        if !self.fail_closed {
            return Err(Error::InvalidConfig(
                "release-captain no-go archive must fail closed".to_string(),
            ));
        }
        if self.production_release_allowed {
            return Err(Error::InvalidConfig(
                "devnet no-go evidence archive cannot allow production release".to_string(),
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            "config",
            vec![
                ("chain_id", self.chain_id.clone()),
                ("release_id", self.release_id.clone()),
                ("protocol_version", self.protocol_version.clone()),
                ("schema_version", self.schema_version.to_string()),
                ("hash_suite", self.hash_suite.clone()),
                ("source_wave", self.source_wave.to_string()),
                (
                    "required_watchtower_quorum",
                    self.required_watchtower_quorum.to_string(),
                ),
                ("fail_closed", self.fail_closed.to_string()),
                (
                    "production_release_allowed",
                    self.production_release_allowed.to_string(),
                ),
            ],
        )
    }

    pub fn state_root(&self) -> Root {
        self.public_record().root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Root(pub u64);

impl Root {
    pub fn zero() -> Self {
        Self(0)
    }

    pub fn hex(self) -> String {
        format!("{:016x}", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRecord {
    pub domain: String,
    pub root: Root,
    pub fields: BTreeMap<String, String>,
}

impl PublicRecord {
    pub fn new(domain: &str, fields: Vec<(&str, String)>) -> Self {
        let mut map = BTreeMap::new();
        for (key, value) in fields {
            map.insert(key.to_string(), value);
        }
        let root = root_for_pairs(domain, &map);
        Self {
            domain: domain.to_string(),
            root,
            fields: map,
        }
    }

    pub fn roots_only(domain: &str, roots: Vec<(&str, Root)>) -> Self {
        let mut fields = BTreeMap::new();
        for (key, value) in roots {
            fields.insert(key.to_string(), value.hex());
        }
        let root = root_for_pairs(domain, &fields);
        Self {
            domain: domain.to_string(),
            root,
            fields,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvidenceKind {
    WalletVisibleForcedExit,
    WatchtowerObservation,
    UserEscapeBlocker,
    RedactedRunbookBlocker,
    ReplayDecision,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletVisibleForcedExit => "wallet_visible_forced_exit",
            Self::WatchtowerObservation => "watchtower_observation",
            Self::UserEscapeBlocker => "user_escape_blocker",
            Self::RedactedRunbookBlocker => "redacted_runbook_blocker",
            Self::ReplayDecision => "replay_decision",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Severity {
    Info,
    Warning,
    Blocking,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Blocking => "blocking",
            Self::Critical => "critical",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Blocking | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Decision {
    Go,
    Watch,
    NoGo,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::Watch => "watch",
            Self::NoGo => "no_go",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ReleaseStatus {
    Held,
    NoGo,
    Watch,
    Go,
}

impl ReleaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::NoGo => "no_go",
            Self::Watch => "watch",
            Self::Go => "go",
        }
    }

    pub fn allows_release(self) -> bool {
        matches!(self, Self::Go)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletForcedExitEvidence {
    pub id: String,
    pub wallet_root: Root,
    pub forced_exit_root: Root,
    pub runbook_root: Root,
    pub replay_decision: Decision,
    pub wallet_visible: bool,
    pub exit_window_height: u64,
    pub severity: Severity,
}

impl WalletForcedExitEvidence {
    pub fn new(
        id: &str,
        wallet_root: Root,
        forced_exit_root: Root,
        runbook_root: Root,
        replay_decision: Decision,
        exit_window_height: u64,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.to_string(),
            wallet_root,
            forced_exit_root,
            runbook_root,
            replay_decision,
            wallet_visible: true,
            exit_window_height,
            severity,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            EvidenceKind::WalletVisibleForcedExit.as_str(),
            vec![
                ("id", self.id.clone()),
                ("wallet_root", self.wallet_root.hex()),
                ("forced_exit_root", self.forced_exit_root.hex()),
                ("runbook_root", self.runbook_root.hex()),
                ("replay_decision", self.replay_decision.as_str().to_string()),
                ("wallet_visible", self.wallet_visible.to_string()),
                ("exit_window_height", self.exit_window_height.to_string()),
                ("severity", self.severity.as_str().to_string()),
            ],
        )
    }

    pub fn blocks_release(&self) -> bool {
        !self.wallet_visible
            || self.replay_decision == Decision::NoGo
            || self.severity.blocks_release()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchtowerObservation {
    pub id: String,
    pub watchtower_id: String,
    pub observation_root: Root,
    pub forced_exit_root: Root,
    pub signature_root: Root,
    pub observed_height: u64,
    pub accepts_no_go: bool,
    pub severity: Severity,
}

impl WatchtowerObservation {
    pub fn new(
        id: &str,
        watchtower_id: &str,
        observation_root: Root,
        forced_exit_root: Root,
        signature_root: Root,
        observed_height: u64,
        accepts_no_go: bool,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.to_string(),
            watchtower_id: watchtower_id.to_string(),
            observation_root,
            forced_exit_root,
            signature_root,
            observed_height,
            accepts_no_go,
            severity,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            EvidenceKind::WatchtowerObservation.as_str(),
            vec![
                ("id", self.id.clone()),
                ("watchtower_id", self.watchtower_id.clone()),
                ("observation_root", self.observation_root.hex()),
                ("forced_exit_root", self.forced_exit_root.hex()),
                ("signature_root", self.signature_root.hex()),
                ("observed_height", self.observed_height.to_string()),
                ("accepts_no_go", self.accepts_no_go.to_string()),
                ("severity", self.severity.as_str().to_string()),
            ],
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.accepts_no_go || self.severity.blocks_release()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserEscapeBlocker {
    pub id: String,
    pub escape_path_root: Root,
    pub affected_wallet_class_root: Root,
    pub blocker_root: Root,
    pub workaround_root: Root,
    pub reproducible: bool,
    pub severity: Severity,
}

impl UserEscapeBlocker {
    pub fn new(
        id: &str,
        escape_path_root: Root,
        affected_wallet_class_root: Root,
        blocker_root: Root,
        workaround_root: Root,
        reproducible: bool,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.to_string(),
            escape_path_root,
            affected_wallet_class_root,
            blocker_root,
            workaround_root,
            reproducible,
            severity,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            EvidenceKind::UserEscapeBlocker.as_str(),
            vec![
                ("id", self.id.clone()),
                ("escape_path_root", self.escape_path_root.hex()),
                (
                    "affected_wallet_class_root",
                    self.affected_wallet_class_root.hex(),
                ),
                ("blocker_root", self.blocker_root.hex()),
                ("workaround_root", self.workaround_root.hex()),
                ("reproducible", self.reproducible.to_string()),
                ("severity", self.severity.as_str().to_string()),
            ],
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.reproducible && self.severity.blocks_release()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedRunbookBlocker {
    pub id: String,
    pub runbook_root: Root,
    pub redaction_policy_root: Root,
    pub blocker_root: Root,
    pub operator_ack_root: Root,
    pub redacted_summary: String,
    pub release_hold: bool,
    pub severity: Severity,
}

impl RedactedRunbookBlocker {
    pub fn new(
        id: &str,
        runbook_root: Root,
        redaction_policy_root: Root,
        blocker_root: Root,
        operator_ack_root: Root,
        redacted_summary: &str,
        release_hold: bool,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.to_string(),
            runbook_root,
            redaction_policy_root,
            blocker_root,
            operator_ack_root,
            redacted_summary: redacted_summary.to_string(),
            release_hold,
            severity,
        }
    }

    pub fn validate_redaction(&self) -> Result<()> {
        let lowered = self.redacted_summary.to_ascii_lowercase();
        let banned = [
            "private key",
            "seed phrase",
            "mnemonic",
            "view key",
            "spend key",
            "raw transcript",
            "wallet address",
            "monero address",
            "secret",
        ];
        for term in banned.iter() {
            if lowered.contains(*term) {
                return Err(Error::RedactionLeak(format!(
                    "redacted runbook blocker {} contains sensitive term {}",
                    self.id, term
                )));
            }
        }
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            EvidenceKind::RedactedRunbookBlocker.as_str(),
            vec![
                ("id", self.id.clone()),
                ("runbook_root", self.runbook_root.hex()),
                ("redaction_policy_root", self.redaction_policy_root.hex()),
                ("blocker_root", self.blocker_root.hex()),
                ("operator_ack_root", self.operator_ack_root.hex()),
                (
                    "summary_root",
                    stable_root("summary", &self.redacted_summary).hex(),
                ),
                ("release_hold", self.release_hold.to_string()),
                ("severity", self.severity.as_str().to_string()),
            ],
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.release_hold || self.severity.blocks_release()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplayDecision {
    pub id: String,
    pub source_wave: u64,
    pub captain_root: Root,
    pub wallet_archive_root: Root,
    pub watchtower_quorum_root: Root,
    pub user_escape_root: Root,
    pub runbook_root: Root,
    pub decision: Decision,
    pub reason_root: Root,
}

impl ReplayDecision {
    pub fn new(
        id: &str,
        source_wave: u64,
        captain_root: Root,
        wallet_archive_root: Root,
        watchtower_quorum_root: Root,
        user_escape_root: Root,
        runbook_root: Root,
        decision: Decision,
        reason_root: Root,
    ) -> Self {
        Self {
            id: id.to_string(),
            source_wave,
            captain_root,
            wallet_archive_root,
            watchtower_quorum_root,
            user_escape_root,
            runbook_root,
            decision,
            reason_root,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::new(
            EvidenceKind::ReplayDecision.as_str(),
            vec![
                ("id", self.id.clone()),
                ("source_wave", self.source_wave.to_string()),
                ("captain_root", self.captain_root.hex()),
                ("wallet_archive_root", self.wallet_archive_root.hex()),
                ("watchtower_quorum_root", self.watchtower_quorum_root.hex()),
                ("user_escape_root", self.user_escape_root.hex()),
                ("runbook_root", self.runbook_root.hex()),
                ("decision", self.decision.as_str().to_string()),
                ("reason_root", self.reason_root.hex()),
            ],
        )
    }

    pub fn blocks_release(&self) -> bool {
        self.decision != Decision::Go
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateReport {
    pub status: ReleaseStatus,
    pub state_root: Root,
    pub blocker_count: usize,
    pub wallet_record_count: usize,
    pub watchtower_quorum_count: usize,
    pub escape_blocker_count: usize,
    pub runbook_blocker_count: usize,
    pub replay_decision_count: usize,
    pub reasons: Vec<String>,
}

impl GateReport {
    pub fn public_record(&self) -> PublicRecord {
        let mut fields = vec![
            ("status", self.status.as_str().to_string()),
            ("state_root", self.state_root.hex()),
            ("blocker_count", self.blocker_count.to_string()),
            ("wallet_record_count", self.wallet_record_count.to_string()),
            (
                "watchtower_quorum_count",
                self.watchtower_quorum_count.to_string(),
            ),
            (
                "escape_blocker_count",
                self.escape_blocker_count.to_string(),
            ),
            (
                "runbook_blocker_count",
                self.runbook_blocker_count.to_string(),
            ),
            (
                "replay_decision_count",
                self.replay_decision_count.to_string(),
            ),
        ];
        fields.push((
            "reason_root",
            root_for_strings("gate_report_reasons", &self.reasons).hex(),
        ));
        PublicRecord::new("gate_report", fields)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    wallet_evidence: BTreeMap<String, WalletForcedExitEvidence>,
    watchtower_observations: BTreeMap<String, WatchtowerObservation>,
    user_escape_blockers: BTreeMap<String, UserEscapeBlocker>,
    runbook_blockers: BTreeMap<String, RedactedRunbookBlocker>,
    replay_decisions: BTreeMap<String, ReplayDecision>,
    sealed_roots: BTreeSet<Root>,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            wallet_evidence: BTreeMap::new(),
            watchtower_observations: BTreeMap::new(),
            user_escape_blockers: BTreeMap::new(),
            runbook_blockers: BTreeMap::new(),
            replay_decisions: BTreeMap::new(),
            sealed_roots: BTreeSet::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = Self {
            config: Config::devnet(),
            wallet_evidence: BTreeMap::new(),
            watchtower_observations: BTreeMap::new(),
            user_escape_blockers: BTreeMap::new(),
            runbook_blockers: BTreeMap::new(),
            replay_decisions: BTreeMap::new(),
            sealed_roots: BTreeSet::new(),
        };
        state.seed_devnet_archive();
        state
    }

    pub fn add_wallet_evidence(&mut self, evidence: WalletForcedExitEvidence) -> Result<Root> {
        self.ensure_capacity()?;
        if self.wallet_evidence.contains_key(&evidence.id) {
            return Err(Error::DuplicateRecord(evidence.id));
        }
        let root = evidence.public_record().root;
        self.wallet_evidence.insert(evidence.id.clone(), evidence);
        self.sealed_roots.insert(root);
        Ok(root)
    }

    pub fn add_watchtower_observation(
        &mut self,
        observation: WatchtowerObservation,
    ) -> Result<Root> {
        self.ensure_capacity()?;
        if self.watchtower_observations.contains_key(&observation.id) {
            return Err(Error::DuplicateRecord(observation.id));
        }
        let root = observation.public_record().root;
        self.watchtower_observations
            .insert(observation.id.clone(), observation);
        self.sealed_roots.insert(root);
        Ok(root)
    }

    pub fn add_user_escape_blocker(&mut self, blocker: UserEscapeBlocker) -> Result<Root> {
        self.ensure_capacity()?;
        if self.user_escape_blockers.contains_key(&blocker.id) {
            return Err(Error::DuplicateRecord(blocker.id));
        }
        let root = blocker.public_record().root;
        self.user_escape_blockers
            .insert(blocker.id.clone(), blocker);
        self.sealed_roots.insert(root);
        Ok(root)
    }

    pub fn add_runbook_blocker(&mut self, blocker: RedactedRunbookBlocker) -> Result<Root> {
        self.ensure_capacity()?;
        blocker.validate_redaction()?;
        if self.runbook_blockers.contains_key(&blocker.id) {
            return Err(Error::DuplicateRecord(blocker.id));
        }
        let root = blocker.public_record().root;
        self.runbook_blockers.insert(blocker.id.clone(), blocker);
        self.sealed_roots.insert(root);
        Ok(root)
    }

    pub fn add_replay_decision(&mut self, decision: ReplayDecision) -> Result<Root> {
        self.ensure_capacity()?;
        if self.replay_decisions.contains_key(&decision.id) {
            return Err(Error::DuplicateRecord(decision.id));
        }
        let root = decision.public_record().root;
        self.replay_decisions.insert(decision.id.clone(), decision);
        self.sealed_roots.insert(root);
        Ok(root)
    }

    pub fn wallet_evidence(&self, id: &str) -> Result<&WalletForcedExitEvidence> {
        self.wallet_evidence
            .get(id)
            .ok_or_else(|| Error::MissingRecord(format!("wallet evidence {} not found", id)))
    }

    pub fn watchtower_observation(&self, id: &str) -> Result<&WatchtowerObservation> {
        self.watchtower_observations
            .get(id)
            .ok_or_else(|| Error::MissingRecord(format!("watchtower observation {} not found", id)))
    }

    pub fn user_escape_blocker(&self, id: &str) -> Result<&UserEscapeBlocker> {
        self.user_escape_blockers
            .get(id)
            .ok_or_else(|| Error::MissingRecord(format!("user escape blocker {} not found", id)))
    }

    pub fn runbook_blocker(&self, id: &str) -> Result<&RedactedRunbookBlocker> {
        self.runbook_blockers
            .get(id)
            .ok_or_else(|| Error::MissingRecord(format!("runbook blocker {} not found", id)))
    }

    pub fn replay_decision(&self, id: &str) -> Result<&ReplayDecision> {
        self.replay_decisions
            .get(id)
            .ok_or_else(|| Error::MissingRecord(format!("replay decision {} not found", id)))
    }

    pub fn wallet_archive_root(&self) -> Root {
        self.collection_root(
            EvidenceKind::WalletVisibleForcedExit.as_str(),
            self.wallet_evidence
                .values()
                .map(|evidence| evidence.public_record().root)
                .collect(),
        )
    }

    pub fn watchtower_quorum_root(&self) -> Root {
        self.collection_root(
            EvidenceKind::WatchtowerObservation.as_str(),
            self.watchtower_observations
                .values()
                .map(|observation| observation.public_record().root)
                .collect(),
        )
    }

    pub fn user_escape_root(&self) -> Root {
        self.collection_root(
            EvidenceKind::UserEscapeBlocker.as_str(),
            self.user_escape_blockers
                .values()
                .map(|blocker| blocker.public_record().root)
                .collect(),
        )
    }

    pub fn runbook_root(&self) -> Root {
        self.collection_root(
            EvidenceKind::RedactedRunbookBlocker.as_str(),
            self.runbook_blockers
                .values()
                .map(|blocker| blocker.public_record().root)
                .collect(),
        )
    }

    pub fn replay_root(&self) -> Root {
        self.collection_root(
            EvidenceKind::ReplayDecision.as_str(),
            self.replay_decisions
                .values()
                .map(|decision| decision.public_record().root)
                .collect(),
        )
    }

    pub fn state_root(&self) -> Root {
        let mut fields = BTreeMap::new();
        fields.insert("config_root".to_string(), self.config.state_root().hex());
        fields.insert(
            "wallet_archive_root".to_string(),
            self.wallet_archive_root().hex(),
        );
        fields.insert(
            "watchtower_quorum_root".to_string(),
            self.watchtower_quorum_root().hex(),
        );
        fields.insert(
            "user_escape_root".to_string(),
            self.user_escape_root().hex(),
        );
        fields.insert("runbook_root".to_string(), self.runbook_root().hex());
        fields.insert("replay_root".to_string(), self.replay_root().hex());
        fields.insert("sealed_root".to_string(), self.sealed_root().hex());
        fields.insert("record_count".to_string(), self.record_count().to_string());
        root_for_pairs("state_root", &fields)
    }

    pub fn sealed_root(&self) -> Root {
        let roots = self.sealed_roots.iter().copied().collect();
        merkleish_root("sealed_roots", roots)
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord::roots_only(
            "wave89_release_captain_no_go_archive",
            vec![
                ("config_root", self.config.state_root()),
                ("wallet_archive_root", self.wallet_archive_root()),
                ("watchtower_quorum_root", self.watchtower_quorum_root()),
                ("user_escape_root", self.user_escape_root()),
                ("runbook_root", self.runbook_root()),
                ("replay_root", self.replay_root()),
                ("sealed_root", self.sealed_root()),
                ("state_root", self.state_root()),
            ],
        )
    }

    pub fn release_report(&self) -> GateReport {
        let mut reasons = Vec::new();
        let mut blocker_count = 0usize;

        if self.config.fail_closed {
            reasons.push("fail_closed_semantics_enabled".to_string());
        } else {
            reasons.push("fail_closed_semantics_missing".to_string());
            blocker_count += 1;
        }

        if self.wallet_evidence.len() < self.config.min_wallet_records {
            blocker_count += 1;
            reasons.push(format!(
                "wallet_visible_forced_exit_records_below_floor:{}<{}",
                self.wallet_evidence.len(),
                self.config.min_wallet_records
            ));
        }

        if self.user_escape_blockers.len() < self.config.min_escape_records {
            blocker_count += 1;
            reasons.push(format!(
                "user_escape_blocker_records_below_floor:{}<{}",
                self.user_escape_blockers.len(),
                self.config.min_escape_records
            ));
        }

        if self.runbook_blockers.len() < self.config.min_runbook_records {
            blocker_count += 1;
            reasons.push(format!(
                "redacted_runbook_records_below_floor:{}<{}",
                self.runbook_blockers.len(),
                self.config.min_runbook_records
            ));
        }

        let quorum_count = self.watchtower_quorum_count();
        if quorum_count < self.config.required_watchtower_quorum {
            blocker_count += 1;
            reasons.push(format!(
                "watchtower_quorum_below_floor:{}<{}",
                quorum_count, self.config.required_watchtower_quorum
            ));
        }

        for evidence in self.wallet_evidence.values() {
            if evidence.blocks_release() {
                blocker_count += 1;
                reasons.push(format!("wallet_forced_exit_blocks_release:{}", evidence.id));
            }
        }
        for observation in self.watchtower_observations.values() {
            if observation.blocks_release() {
                blocker_count += 1;
                reasons.push(format!(
                    "watchtower_observation_accepts_no_go:{}",
                    observation.id
                ));
            }
        }
        for blocker in self.user_escape_blockers.values() {
            if blocker.blocks_release() {
                blocker_count += 1;
                reasons.push(format!("user_escape_blocker_active:{}", blocker.id));
            }
        }
        for blocker in self.runbook_blockers.values() {
            if blocker.blocks_release() {
                blocker_count += 1;
                reasons.push(format!("redacted_runbook_blocker_active:{}", blocker.id));
            }
        }
        for decision in self.replay_decisions.values() {
            if decision.blocks_release() {
                blocker_count += 1;
                reasons.push(format!("wave88_replay_decision_not_go:{}", decision.id));
            }
        }

        let status = if blocker_count > 0 {
            ReleaseStatus::NoGo
        } else if self.config.production_release_allowed {
            ReleaseStatus::Go
        } else {
            ReleaseStatus::Held
        };

        GateReport {
            status,
            state_root: self.state_root(),
            blocker_count,
            wallet_record_count: self.wallet_evidence.len(),
            watchtower_quorum_count: quorum_count,
            escape_blocker_count: self.user_escape_blockers.len(),
            runbook_blocker_count: self.runbook_blockers.len(),
            replay_decision_count: self.replay_decisions.len(),
            reasons,
        }
    }

    pub fn assert_release_allowed(&self) -> Result<()> {
        let report = self.release_report();
        if report.status.allows_release() {
            Ok(())
        } else {
            Err(Error::ReleaseHeld(format!(
                "release status {} with {} blockers",
                report.status.as_str(),
                report.blocker_count
            )))
        }
    }

    pub fn no_go_public_record(&self) -> PublicRecord {
        self.release_report().public_record()
    }

    pub fn record_count(&self) -> usize {
        self.wallet_evidence.len()
            + self.watchtower_observations.len()
            + self.user_escape_blockers.len()
            + self.runbook_blockers.len()
            + self.replay_decisions.len()
    }

    pub fn watchtower_quorum_count(&self) -> usize {
        self.watchtower_observations
            .values()
            .filter(|observation| observation.accepts_no_go)
            .map(|observation| observation.watchtower_id.clone())
            .collect::<BTreeSet<String>>()
            .len()
    }

    pub fn roots_only_archive(&self) -> BTreeMap<String, String> {
        let mut archive = BTreeMap::new();
        archive.insert("state_root".to_string(), self.state_root().hex());
        archive.insert(
            "wallet_archive_root".to_string(),
            self.wallet_archive_root().hex(),
        );
        archive.insert(
            "watchtower_quorum_root".to_string(),
            self.watchtower_quorum_root().hex(),
        );
        archive.insert(
            "user_escape_root".to_string(),
            self.user_escape_root().hex(),
        );
        archive.insert("runbook_root".to_string(), self.runbook_root().hex());
        archive.insert("replay_root".to_string(), self.replay_root().hex());
        archive.insert(
            "release_status".to_string(),
            self.release_report().status.as_str().to_string(),
        );
        archive
    }

    fn ensure_capacity(&self) -> Result<()> {
        if self.record_count() >= self.config.max_records {
            Err(Error::RecordLimitReached)
        } else {
            Ok(())
        }
    }

    fn collection_root(&self, domain: &str, roots: Vec<Root>) -> Root {
        merkleish_root(domain, roots)
    }

    fn seed_devnet_archive(&mut self) {
        let wallet_a = WalletForcedExitEvidence::new(
            "wallet-force-exit-visible-a",
            stable_root("wallet", "view-root-a"),
            stable_root("forced-exit", "claim-root-a"),
            stable_root("runbook", "wallet-runbook-a"),
            Decision::NoGo,
            88_010,
            Severity::Blocking,
        );
        let wallet_b = WalletForcedExitEvidence::new(
            "wallet-force-exit-visible-b",
            stable_root("wallet", "view-root-b"),
            stable_root("forced-exit", "claim-root-b"),
            stable_root("runbook", "wallet-runbook-b"),
            Decision::Watch,
            88_011,
            Severity::Warning,
        );
        let wallet_c = WalletForcedExitEvidence::new(
            "wallet-force-exit-visible-c",
            stable_root("wallet", "view-root-c"),
            stable_root("forced-exit", "claim-root-c"),
            stable_root("runbook", "wallet-runbook-c"),
            Decision::NoGo,
            88_012,
            Severity::Critical,
        );

        let tower_a = WatchtowerObservation::new(
            "tower-observation-a",
            "tower-alpha",
            stable_root("tower-observation", "alpha"),
            stable_root("forced-exit", "claim-root-a"),
            stable_root("tower-signature", "alpha-sig"),
            88_020,
            true,
            Severity::Blocking,
        );
        let tower_b = WatchtowerObservation::new(
            "tower-observation-b",
            "tower-beta",
            stable_root("tower-observation", "beta"),
            stable_root("forced-exit", "claim-root-a"),
            stable_root("tower-signature", "beta-sig"),
            88_021,
            true,
            Severity::Blocking,
        );
        let tower_c = WatchtowerObservation::new(
            "tower-observation-c",
            "tower-gamma",
            stable_root("tower-observation", "gamma"),
            stable_root("forced-exit", "claim-root-c"),
            stable_root("tower-signature", "gamma-sig"),
            88_022,
            true,
            Severity::Critical,
        );

        let escape_a = UserEscapeBlocker::new(
            "escape-blocker-a",
            stable_root("escape-path", "offline-wallet-claim"),
            stable_root("wallet-class", "cold-wallet"),
            stable_root("blocker", "missing-watchtower-proof"),
            stable_root("workaround", "manual-relay-not-ready"),
            true,
            Severity::Blocking,
        );
        let escape_b = UserEscapeBlocker::new(
            "escape-blocker-b",
            stable_root("escape-path", "mobile-wallet-claim"),
            stable_root("wallet-class", "mobile-wallet"),
            stable_root("blocker", "runbook-gap"),
            stable_root("workaround", "redacted-drill-pending"),
            true,
            Severity::Blocking,
        );

        let runbook_a = RedactedRunbookBlocker::new(
            "runbook-blocker-a",
            stable_root("runbook", "operator-escape-handoff"),
            stable_root("redaction-policy", "roots-only-v1"),
            stable_root("blocker", "captain-signoff-gap"),
            stable_root("operator-ack", "ack-a"),
            "redacted blocker summary: operator handoff evidence root mismatch",
            true,
            Severity::Blocking,
        );
        let runbook_b = RedactedRunbookBlocker::new(
            "runbook-blocker-b",
            stable_root("runbook", "watchtower-quorum-handoff"),
            stable_root("redaction-policy", "roots-only-v1"),
            stable_root("blocker", "quorum-replay-gap"),
            stable_root("operator-ack", "ack-b"),
            "redacted blocker summary: quorum replay evidence not cleared",
            true,
            Severity::Critical,
        );

        let wallet_archive_root = merkleish_root(
            "devnet-wallet-seed",
            vec![
                wallet_a.public_record().root,
                wallet_b.public_record().root,
                wallet_c.public_record().root,
            ],
        );
        let watchtower_quorum_root = merkleish_root(
            "devnet-watchtower-seed",
            vec![
                tower_a.public_record().root,
                tower_b.public_record().root,
                tower_c.public_record().root,
            ],
        );
        let user_escape_root = merkleish_root(
            "devnet-escape-seed",
            vec![escape_a.public_record().root, escape_b.public_record().root],
        );
        let runbook_root = merkleish_root(
            "devnet-runbook-seed",
            vec![
                runbook_a.public_record().root,
                runbook_b.public_record().root,
            ],
        );

        let replay = ReplayDecision::new(
            "wave88-release-captain-replay-no-go",
            DEFAULT_SOURCE_WAVE,
            stable_root("captain", "release-captain-no-go"),
            wallet_archive_root,
            watchtower_quorum_root,
            user_escape_root,
            runbook_root,
            Decision::NoGo,
            stable_root(
                "reason",
                "forced-exit-watchtower-user-escape-runbook-blockers",
            ),
        );

        let _ = self.add_wallet_evidence(wallet_a);
        let _ = self.add_wallet_evidence(wallet_b);
        let _ = self.add_wallet_evidence(wallet_c);
        let _ = self.add_watchtower_observation(tower_a);
        let _ = self.add_watchtower_observation(tower_b);
        let _ = self.add_watchtower_observation(tower_c);
        let _ = self.add_user_escape_blocker(escape_a);
        let _ = self.add_user_escape_blocker(escape_b);
        let _ = self.add_runbook_blocker(runbook_a);
        let _ = self.add_runbook_blocker(runbook_b);
        let _ = self.add_replay_decision(replay);
    }
}

pub fn devnet() -> Runtime {
    State::devnet()
}

pub fn public_record(runtime: &Runtime) -> PublicRecord {
    runtime.public_record()
}

pub fn state_root(runtime: &Runtime) -> Root {
    runtime.state_root()
}

pub fn stable_root(domain: &str, value: &str) -> Root {
    let mut hasher = DefaultHasher::new();
    "nebula-wave89-root".hash(&mut hasher);
    domain.hash(&mut hasher);
    value.hash(&mut hasher);
    Root(hasher.finish())
}

pub fn root_for_strings(domain: &str, values: &[String]) -> Root {
    let mut hasher = DefaultHasher::new();
    "nebula-wave89-string-root".hash(&mut hasher);
    domain.hash(&mut hasher);
    values.len().hash(&mut hasher);
    for value in values {
        value.hash(&mut hasher);
    }
    Root(hasher.finish())
}

pub fn root_for_pairs(domain: &str, fields: &BTreeMap<String, String>) -> Root {
    let mut hasher = DefaultHasher::new();
    "nebula-wave89-pair-root".hash(&mut hasher);
    domain.hash(&mut hasher);
    fields.len().hash(&mut hasher);
    for (key, value) in fields {
        key.hash(&mut hasher);
        value.hash(&mut hasher);
    }
    Root(hasher.finish())
}

pub fn merkleish_root(domain: &str, roots: Vec<Root>) -> Root {
    let mut sorted = roots;
    sorted.sort();
    let mut layer = Vec::new();
    for root in sorted {
        layer.push(root.0);
    }
    if layer.is_empty() {
        return stable_root(domain, "empty");
    }
    while layer.len() > 1 {
        let mut next = Vec::new();
        let mut index = 0usize;
        while index < layer.len() {
            let left = layer[index];
            let right = if index + 1 < layer.len() {
                layer[index + 1]
            } else {
                layer[index]
            };
            let mut hasher = DefaultHasher::new();
            "nebula-wave89-merkleish-node".hash(&mut hasher);
            domain.hash(&mut hasher);
            left.hash(&mut hasher);
            right.hash(&mut hasher);
            next.push(hasher.finish());
            index += 2;
        }
        layer = next;
    }
    Root(layer[0])
}
