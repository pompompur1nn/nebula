use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::hash::{Hash, Hasher};

pub type Result<T> = std::result::Result<T, ArchiveError>;
pub type Runtime = State;

pub const PROTOCOL_VERSION: &str =
    "monero-l2-pq-bridge-exit-force-exit-wave89-release-captain-no-go-evidence-archive-compile-gate-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const DEFAULT_WAVE: u64 = 89;
pub const SOURCE_REPLAY_WAVE: u64 = 88;
pub const DEFAULT_RELEASE_EPOCH: u64 = 89;
pub const DEFAULT_SOURCE_REPLAY_EPOCH: u64 = 88;
pub const DEFAULT_MIN_EVIDENCE_PACKETS: usize = 12;
pub const DEFAULT_MIN_DECISION_LANES: usize = 6;
pub const DEFAULT_MIN_DEFERRED_GATES: usize = 5;
pub const DEFAULT_MAX_DEFERRED_AGE_BLOCKS: u64 = 144;
pub const DEFAULT_ARCHIVE_HEIGHT: u64 = 890_000;
pub const HELD_RELEASE_LABEL: &str = "release-held";
pub const NO_GO_LABEL: &str = "no-go";
pub const PRIVACY_MODE: &str = "roots-only";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveError {
    EmptyField(&'static str),
    DuplicateId(String),
    UnknownLane(String),
    UnknownEvidence(String),
    UnknownGate(String),
    InvalidRoot { field: &'static str, value: String },
    InvalidHeight,
    ReleaseWouldOpen,
    EvidenceNotArchival(String),
    HeavyGateExecuted(String),
    MissingRequiredEvidence(&'static str),
    PolicyViolation(String),
}

impl fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "empty required field: {}", field),
            Self::DuplicateId(id) => write!(f, "duplicate identifier: {}", id),
            Self::UnknownLane(id) => write!(f, "unknown decision lane: {}", id),
            Self::UnknownEvidence(id) => write!(f, "unknown evidence packet: {}", id),
            Self::UnknownGate(id) => write!(f, "unknown deferred gate: {}", id),
            Self::InvalidRoot { field, value } => {
                write!(f, "invalid root for {}: {}", field, value)
            }
            Self::InvalidHeight => write!(f, "invalid archive height"),
            Self::ReleaseWouldOpen => write!(f, "release would open; archive is fail-closed"),
            Self::EvidenceNotArchival(id) => write!(f, "evidence is not archival: {}", id),
            Self::HeavyGateExecuted(id) => write!(f, "heavy gate was executed: {}", id),
            Self::MissingRequiredEvidence(name) => write!(f, "missing required evidence: {}", name),
            Self::PolicyViolation(detail) => write!(f, "policy violation: {}", detail),
        }
    }
}

impl std::error::Error for ArchiveError {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DecisionLane {
    CompileStatus,
    CargoCheck,
    Clippy,
    Rustfmt,
    Rustc,
    DevnetReplay,
    BridgeCustody,
    PrivacyReserve,
}

impl DecisionLane {
    pub fn all() -> Vec<Self> {
        vec![
            Self::CompileStatus,
            Self::CargoCheck,
            Self::Clippy,
            Self::Rustfmt,
            Self::Rustc,
            Self::DevnetReplay,
            Self::BridgeCustody,
            Self::PrivacyReserve,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CompileStatus => "compile_status",
            Self::CargoCheck => "cargo_check",
            Self::Clippy => "clippy",
            Self::Rustfmt => "rustfmt",
            Self::Rustc => "rustc",
            Self::DevnetReplay => "devnet_replay",
            Self::BridgeCustody => "bridge_custody",
            Self::PrivacyReserve => "privacy_reserve",
        }
    }

    pub fn captain_owner(self) -> &'static str {
        match self {
            Self::CompileStatus => "release-captain-compile",
            Self::CargoCheck => "release-captain-cargo-check",
            Self::Clippy => "release-captain-clippy",
            Self::Rustfmt => "release-captain-rustfmt",
            Self::Rustc => "release-captain-rustc",
            Self::DevnetReplay => "release-captain-devnet",
            Self::BridgeCustody => "release-captain-custody",
            Self::PrivacyReserve => "release-captain-privacy-reserve",
        }
    }

    pub fn is_compile_gate(self) -> bool {
        matches!(
            self,
            Self::CompileStatus | Self::CargoCheck | Self::Clippy | Self::Rustfmt | Self::Rustc
        )
    }

    pub fn from_id(id: &str) -> Option<Self> {
        Self::all().into_iter().find(|lane| lane.as_str() == id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateKind {
    CargoCheck,
    CargoClippy,
    CargoFmtCheck,
    RustcSmoke,
    CargoMetadata,
    IntegrationReplay,
    DevnetFork,
}

impl GateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoCheck => "cargo_check",
            Self::CargoClippy => "cargo_clippy",
            Self::CargoFmtCheck => "cargo_fmt_check",
            Self::RustcSmoke => "rustc_smoke",
            Self::CargoMetadata => "cargo_metadata",
            Self::IntegrationReplay => "integration_replay",
            Self::DevnetFork => "devnet_fork",
        }
    }

    pub fn requires_defer_only(self) -> bool {
        matches!(
            self,
            Self::CargoCheck
                | Self::CargoClippy
                | Self::CargoFmtCheck
                | Self::RustcSmoke
                | Self::CargoMetadata
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvidenceKind {
    Wave88ReplayDecisionRoot,
    CaptainNoGoSignoffRoot,
    DeferredCargoCheckRoot,
    DeferredClippyRoot,
    DeferredRustfmtRoot,
    DeferredRustcRoot,
    DeferredCargoMetadataRoot,
    BridgeCustodyHoldRoot,
    PrivacyBudgetHoldRoot,
    PagerAckRoot,
    RollbackCommandRoot,
    OperatorTranscriptRoot,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wave88ReplayDecisionRoot => "wave88_replay_decision_root",
            Self::CaptainNoGoSignoffRoot => "captain_no_go_signoff_root",
            Self::DeferredCargoCheckRoot => "deferred_cargo_check_root",
            Self::DeferredClippyRoot => "deferred_clippy_root",
            Self::DeferredRustfmtRoot => "deferred_rustfmt_root",
            Self::DeferredRustcRoot => "deferred_rustc_root",
            Self::DeferredCargoMetadataRoot => "deferred_cargo_metadata_root",
            Self::BridgeCustodyHoldRoot => "bridge_custody_hold_root",
            Self::PrivacyBudgetHoldRoot => "privacy_budget_hold_root",
            Self::PagerAckRoot => "pager_ack_root",
            Self::RollbackCommandRoot => "rollback_command_root",
            Self::OperatorTranscriptRoot => "operator_transcript_root",
        }
    }

    pub fn required_for_no_go(self) -> bool {
        matches!(
            self,
            Self::Wave88ReplayDecisionRoot
                | Self::CaptainNoGoSignoffRoot
                | Self::DeferredCargoCheckRoot
                | Self::DeferredClippyRoot
                | Self::DeferredRustfmtRoot
                | Self::DeferredRustcRoot
                | Self::PagerAckRoot
                | Self::RollbackCommandRoot
        )
    }

    pub fn compile_related(self) -> bool {
        matches!(
            self,
            Self::DeferredCargoCheckRoot
                | Self::DeferredClippyRoot
                | Self::DeferredRustfmtRoot
                | Self::DeferredRustcRoot
                | Self::DeferredCargoMetadataRoot
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DecisionStatus {
    Missing,
    Held,
    NoGo,
    DeferredCompileGate,
    RejectedUnhold,
    ReadyAfterExternalGate,
}

impl DecisionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Held => "held",
            Self::NoGo => "no_go",
            Self::DeferredCompileGate => "deferred_compile_gate",
            Self::RejectedUnhold => "rejected_unhold",
            Self::ReadyAfterExternalGate => "ready_after_external_gate",
        }
    }

    pub fn fail_closed(self) -> bool {
        !matches!(self, Self::ReadyAfterExternalGate)
    }

    pub fn contributes_to_no_go(self) -> bool {
        matches!(
            self,
            Self::Held | Self::NoGo | Self::DeferredCompileGate | Self::RejectedUnhold
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ReleaseDisposition {
    Held,
    NoGo,
    BlockedByMissingEvidence,
    BlockedByExecutedHeavyGate,
}

impl ReleaseDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Held => "held",
            Self::NoGo => "no_go",
            Self::BlockedByMissingEvidence => "blocked_by_missing_evidence",
            Self::BlockedByExecutedHeavyGate => "blocked_by_executed_heavy_gate",
        }
    }

    pub fn release_open(self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateExecution {
    Deferred,
    NotScheduled,
    ExecutedOutsideArchive,
}

impl GateExecution {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deferred => "deferred",
            Self::NotScheduled => "not_scheduled",
            Self::ExecutedOutsideArchive => "executed_outside_archive",
        }
    }

    pub fn allowed_in_archive(self) -> bool {
        matches!(self, Self::Deferred | Self::NotScheduled)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Config {
    pub protocol_version: String,
    pub schema_version: u64,
    pub release_wave: u64,
    pub source_replay_wave: u64,
    pub release_epoch: u64,
    pub source_replay_epoch: u64,
    pub archive_height: u64,
    pub max_deferred_age_blocks: u64,
    pub min_evidence_packets: usize,
    pub min_decision_lanes: usize,
    pub min_deferred_gates: usize,
    pub require_roots_only: bool,
    pub require_no_go: bool,
    pub forbid_heavy_gate_execution: bool,
    pub release_label: String,
    pub privacy_mode: String,
}

impl Config {
    pub fn new() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            release_wave: DEFAULT_WAVE,
            source_replay_wave: SOURCE_REPLAY_WAVE,
            release_epoch: DEFAULT_RELEASE_EPOCH,
            source_replay_epoch: DEFAULT_SOURCE_REPLAY_EPOCH,
            archive_height: DEFAULT_ARCHIVE_HEIGHT,
            max_deferred_age_blocks: DEFAULT_MAX_DEFERRED_AGE_BLOCKS,
            min_evidence_packets: DEFAULT_MIN_EVIDENCE_PACKETS,
            min_decision_lanes: DEFAULT_MIN_DECISION_LANES,
            min_deferred_gates: DEFAULT_MIN_DEFERRED_GATES,
            require_roots_only: true,
            require_no_go: true,
            forbid_heavy_gate_execution: true,
            release_label: HELD_RELEASE_LABEL.to_string(),
            privacy_mode: PRIVACY_MODE.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("protocol_version", &self.protocol_version)?;
        require_non_empty("release_label", &self.release_label)?;
        require_non_empty("privacy_mode", &self.privacy_mode)?;
        if self.schema_version == 0 {
            return Err(ArchiveError::PolicyViolation(
                "schema version must be positive".to_string(),
            ));
        }
        if self.release_wave <= self.source_replay_wave {
            return Err(ArchiveError::PolicyViolation(
                "release wave must be after source replay wave".to_string(),
            ));
        }
        if self.archive_height == 0 {
            return Err(ArchiveError::InvalidHeight);
        }
        if !self.require_roots_only {
            return Err(ArchiveError::PolicyViolation(
                "archive must remain roots-only".to_string(),
            ));
        }
        if !self.require_no_go {
            return Err(ArchiveError::ReleaseWouldOpen);
        }
        Ok(())
    }

    pub fn root(&self) -> String {
        digest_pairs(
            "config",
            &[
                ("protocol_version", self.protocol_version.as_str()),
                ("schema_version", &self.schema_version.to_string()),
                ("release_wave", &self.release_wave.to_string()),
                ("source_replay_wave", &self.source_replay_wave.to_string()),
                ("release_epoch", &self.release_epoch.to_string()),
                ("source_replay_epoch", &self.source_replay_epoch.to_string()),
                ("archive_height", &self.archive_height.to_string()),
                (
                    "max_deferred_age_blocks",
                    &self.max_deferred_age_blocks.to_string(),
                ),
                (
                    "min_evidence_packets",
                    &self.min_evidence_packets.to_string(),
                ),
                ("min_decision_lanes", &self.min_decision_lanes.to_string()),
                ("min_deferred_gates", &self.min_deferred_gates.to_string()),
                ("require_roots_only", bool_str(self.require_roots_only)),
                ("require_no_go", bool_str(self.require_no_go)),
                (
                    "forbid_heavy_gate_execution",
                    bool_str(self.forbid_heavy_gate_execution),
                ),
                ("release_label", self.release_label.as_str()),
                ("privacy_mode", self.privacy_mode.as_str()),
            ],
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidencePacket {
    pub id: String,
    pub kind: EvidenceKind,
    pub lane: DecisionLane,
    pub root: String,
    pub source_wave: u64,
    pub source_height: u64,
    pub archived_at_height: u64,
    pub roots_only: bool,
    pub redaction_root: String,
    pub note_root: String,
}

impl EvidencePacket {
    pub fn new(
        id: &str,
        kind: EvidenceKind,
        lane: DecisionLane,
        root: &str,
        source_height: u64,
        archived_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("evidence.id", id)?;
        validate_root("evidence.root", root)?;
        let redaction_root = digest_pairs(
            "redaction",
            &[
                ("id", id),
                ("kind", kind.as_str()),
                ("privacy", PRIVACY_MODE),
                ("lane", lane.as_str()),
            ],
        );
        let note_root = digest_pairs(
            "evidence-note",
            &[
                ("id", id),
                ("source", "wave88-release-captain-replay-drill"),
                ("binding", "deferred-compile-status"),
            ],
        );
        Ok(Self {
            id: id.to_string(),
            kind,
            lane,
            root: root.to_string(),
            source_wave: SOURCE_REPLAY_WAVE,
            source_height,
            archived_at_height,
            roots_only: true,
            redaction_root,
            note_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("evidence.id", &self.id)?;
        validate_root("evidence.root", &self.root)?;
        validate_root("evidence.redaction_root", &self.redaction_root)?;
        validate_root("evidence.note_root", &self.note_root)?;
        if self.source_wave != config.source_replay_wave {
            return Err(ArchiveError::PolicyViolation(format!(
                "evidence {} is not bound to source replay wave",
                self.id
            )));
        }
        if !self.roots_only || !config.require_roots_only {
            return Err(ArchiveError::EvidenceNotArchival(self.id.clone()));
        }
        if self.archived_at_height < self.source_height {
            return Err(ArchiveError::InvalidHeight);
        }
        let age = self.archived_at_height.saturating_sub(self.source_height);
        if age > config.max_deferred_age_blocks {
            return Err(ArchiveError::PolicyViolation(format!(
                "evidence {} exceeds deferred age",
                self.id
            )));
        }
        Ok(())
    }

    pub fn public_root(&self) -> String {
        digest_pairs(
            "evidence-public",
            &[
                ("id", self.id.as_str()),
                ("kind", self.kind.as_str()),
                ("lane", self.lane.as_str()),
                ("root", self.root.as_str()),
                ("source_wave", &self.source_wave.to_string()),
                ("source_height", &self.source_height.to_string()),
                ("archived_at_height", &self.archived_at_height.to_string()),
                ("roots_only", bool_str(self.roots_only)),
                ("redaction_root", self.redaction_root.as_str()),
                ("note_root", self.note_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredGate {
    pub id: String,
    pub kind: GateKind,
    pub lane: DecisionLane,
    pub status_root: String,
    pub scheduled_height: u64,
    pub execution: GateExecution,
    pub defer_reason_root: String,
}

impl DeferredGate {
    pub fn new(
        id: &str,
        kind: GateKind,
        lane: DecisionLane,
        scheduled_height: u64,
        execution: GateExecution,
    ) -> Result<Self> {
        require_non_empty("deferred_gate.id", id)?;
        let status_root = digest_pairs(
            "deferred-gate-status",
            &[
                ("id", id),
                ("kind", kind.as_str()),
                ("lane", lane.as_str()),
                ("execution", execution.as_str()),
                ("policy", "do-not-run-heavy-gate-in-archive"),
            ],
        );
        let defer_reason_root = digest_pairs(
            "deferred-gate-reason",
            &[
                ("id", id),
                ("source_wave", &SOURCE_REPLAY_WAVE.to_string()),
                ("release_wave", &DEFAULT_WAVE.to_string()),
                (
                    "reason",
                    "compile-status-deferred-for-release-captain-no-go",
                ),
            ],
        );
        Ok(Self {
            id: id.to_string(),
            kind,
            lane,
            status_root,
            scheduled_height,
            execution,
            defer_reason_root,
        })
    }

    pub fn validate(&self, config: &Config) -> Result<()> {
        require_non_empty("deferred_gate.id", &self.id)?;
        validate_root("deferred_gate.status_root", &self.status_root)?;
        validate_root("deferred_gate.defer_reason_root", &self.defer_reason_root)?;
        if self.scheduled_height == 0 {
            return Err(ArchiveError::InvalidHeight);
        }
        if config.forbid_heavy_gate_execution && !self.execution.allowed_in_archive() {
            return Err(ArchiveError::HeavyGateExecuted(self.id.clone()));
        }
        if self.kind.requires_defer_only() && self.execution != GateExecution::Deferred {
            return Err(ArchiveError::PolicyViolation(format!(
                "compile gate {} must be deferred",
                self.id
            )));
        }
        Ok(())
    }

    pub fn public_root(&self) -> String {
        digest_pairs(
            "deferred-gate-public",
            &[
                ("id", self.id.as_str()),
                ("kind", self.kind.as_str()),
                ("lane", self.lane.as_str()),
                ("status_root", self.status_root.as_str()),
                ("scheduled_height", &self.scheduled_height.to_string()),
                ("execution", self.execution.as_str()),
                ("defer_reason_root", self.defer_reason_root.as_str()),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneDecision {
    pub lane: DecisionLane,
    pub owner: String,
    pub status: DecisionStatus,
    pub evidence_ids: Vec<String>,
    pub decision_root: String,
    pub no_go_reason_root: String,
    pub release_held: bool,
}

impl LaneDecision {
    pub fn new(
        lane: DecisionLane,
        status: DecisionStatus,
        evidence_ids: Vec<String>,
        reason: &str,
    ) -> Result<Self> {
        require_non_empty("lane_decision.reason", reason)?;
        let owner = lane.captain_owner().to_string();
        let decision_root = digest_pairs(
            "lane-decision",
            &[
                ("lane", lane.as_str()),
                ("owner", owner.as_str()),
                ("status", status.as_str()),
                ("reason", reason),
                ("held", bool_str(status.fail_closed())),
            ],
        );
        let no_go_reason_root = digest_pairs(
            "lane-no-go-reason",
            &[
                ("lane", lane.as_str()),
                ("reason", reason),
                ("source_wave", &SOURCE_REPLAY_WAVE.to_string()),
            ],
        );
        Ok(Self {
            lane,
            owner,
            status,
            evidence_ids,
            decision_root,
            no_go_reason_root,
            release_held: status.fail_closed(),
        })
    }

    pub fn validate(&self, evidence: &BTreeMap<String, EvidencePacket>) -> Result<()> {
        require_non_empty("lane_decision.owner", &self.owner)?;
        validate_root("lane_decision.decision_root", &self.decision_root)?;
        validate_root("lane_decision.no_go_reason_root", &self.no_go_reason_root)?;
        if self.owner != self.lane.captain_owner() {
            return Err(ArchiveError::PolicyViolation(format!(
                "lane {} has invalid owner",
                self.lane.as_str()
            )));
        }
        if !self.release_held || !self.status.fail_closed() {
            return Err(ArchiveError::ReleaseWouldOpen);
        }
        if self.evidence_ids.is_empty() {
            return Err(ArchiveError::MissingRequiredEvidence("lane evidence"));
        }
        let mut seen = BTreeSet::new();
        for id in &self.evidence_ids {
            require_non_empty("lane_decision.evidence_id", id)?;
            if !seen.insert(id.clone()) {
                return Err(ArchiveError::DuplicateId(id.clone()));
            }
            match evidence.get(id) {
                Some(packet) => {
                    if packet.lane != self.lane {
                        return Err(ArchiveError::PolicyViolation(format!(
                            "evidence {} belongs to {} not {}",
                            id,
                            packet.lane.as_str(),
                            self.lane.as_str()
                        )));
                    }
                }
                None => return Err(ArchiveError::UnknownEvidence(id.clone())),
            }
        }
        Ok(())
    }

    pub fn public_root(&self) -> String {
        let evidence_root = ordered_root("lane-evidence-ids", self.evidence_ids.iter());
        digest_pairs(
            "lane-decision-public",
            &[
                ("lane", self.lane.as_str()),
                ("owner", self.owner.as_str()),
                ("status", self.status.as_str()),
                ("evidence_root", evidence_root.as_str()),
                ("decision_root", self.decision_root.as_str()),
                ("no_go_reason_root", self.no_go_reason_root.as_str()),
                ("release_held", bool_str(self.release_held)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptainSeal {
    pub captain_id: String,
    pub decision: ReleaseDisposition,
    pub wave88_replay_root: String,
    pub evidence_archive_root: String,
    pub deferred_gate_root: String,
    pub seal_root: String,
    pub release_held: bool,
    pub no_go: bool,
}

impl CaptainSeal {
    pub fn new(
        captain_id: &str,
        decision: ReleaseDisposition,
        wave88_replay_root: &str,
        evidence_archive_root: &str,
        deferred_gate_root: &str,
    ) -> Result<Self> {
        require_non_empty("captain_seal.captain_id", captain_id)?;
        validate_root("captain_seal.wave88_replay_root", wave88_replay_root)?;
        validate_root("captain_seal.evidence_archive_root", evidence_archive_root)?;
        validate_root("captain_seal.deferred_gate_root", deferred_gate_root)?;
        let release_held = !decision.release_open();
        let no_go = matches!(
            decision,
            ReleaseDisposition::NoGo | ReleaseDisposition::Held
        );
        let seal_root = digest_pairs(
            "captain-seal",
            &[
                ("captain_id", captain_id),
                ("decision", decision.as_str()),
                ("wave88_replay_root", wave88_replay_root),
                ("evidence_archive_root", evidence_archive_root),
                ("deferred_gate_root", deferred_gate_root),
                ("release_held", bool_str(release_held)),
                ("no_go", bool_str(no_go)),
            ],
        );
        Ok(Self {
            captain_id: captain_id.to_string(),
            decision,
            wave88_replay_root: wave88_replay_root.to_string(),
            evidence_archive_root: evidence_archive_root.to_string(),
            deferred_gate_root: deferred_gate_root.to_string(),
            seal_root,
            release_held,
            no_go,
        })
    }

    pub fn validate(&self) -> Result<()> {
        require_non_empty("captain_seal.captain_id", &self.captain_id)?;
        validate_root("captain_seal.wave88_replay_root", &self.wave88_replay_root)?;
        validate_root(
            "captain_seal.evidence_archive_root",
            &self.evidence_archive_root,
        )?;
        validate_root("captain_seal.deferred_gate_root", &self.deferred_gate_root)?;
        validate_root("captain_seal.seal_root", &self.seal_root)?;
        if !self.release_held || !self.no_go {
            return Err(ArchiveError::ReleaseWouldOpen);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRecord {
    pub protocol_version: String,
    pub schema_version: u64,
    pub release_wave: u64,
    pub source_replay_wave: u64,
    pub release_label: String,
    pub privacy_mode: String,
    pub disposition: ReleaseDisposition,
    pub evidence_root: String,
    pub decision_root: String,
    pub deferred_gate_root: String,
    pub captain_seal_root: String,
    pub state_root: String,
    pub evidence_count: usize,
    pub lane_count: usize,
    pub deferred_gate_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSummary {
    pub disposition: ReleaseDisposition,
    pub release_held: bool,
    pub no_go: bool,
    pub compile_gates_deferred: usize,
    pub missing_required_kinds: Vec<EvidenceKind>,
    pub roots_only: bool,
}

impl ArchiveSummary {
    pub fn root(&self) -> String {
        let missing = self
            .missing_required_kinds
            .iter()
            .map(|kind| kind.as_str().to_string())
            .collect::<Vec<String>>();
        let missing_root = ordered_root("missing-required-kinds", missing.iter());
        digest_pairs(
            "archive-summary",
            &[
                ("disposition", self.disposition.as_str()),
                ("release_held", bool_str(self.release_held)),
                ("no_go", bool_str(self.no_go)),
                (
                    "compile_gates_deferred",
                    &self.compile_gates_deferred.to_string(),
                ),
                ("missing_required_root", missing_root.as_str()),
                ("roots_only", bool_str(self.roots_only)),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    pub config: Config,
    pub evidence: BTreeMap<String, EvidencePacket>,
    pub decisions: BTreeMap<DecisionLane, LaneDecision>,
    pub deferred_gates: BTreeMap<String, DeferredGate>,
    pub captain_seal: CaptainSeal,
    pub summary: ArchiveSummary,
}

impl State {
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;
        let evidence = default_evidence(&config)?;
        let deferred_gates = default_deferred_gates(&config)?;
        let decisions = default_decisions(&evidence)?;
        let evidence_archive_root = evidence_root(&evidence);
        let deferred_gate_root = deferred_gate_root(&deferred_gates);
        let wave88_replay_root = digest_pairs(
            "wave88-replay-root-binding",
            &[
                ("source_wave", &config.source_replay_wave.to_string()),
                ("source_epoch", &config.source_replay_epoch.to_string()),
                ("purpose", "release-captain-go-no-go-replay-drill"),
            ],
        );
        let captain_seal = CaptainSeal::new(
            "wave89-release-captain",
            ReleaseDisposition::NoGo,
            &wave88_replay_root,
            &evidence_archive_root,
            &deferred_gate_root,
        )?;
        let mut state = Self {
            config,
            evidence,
            decisions,
            deferred_gates,
            captain_seal,
            summary: ArchiveSummary {
                disposition: ReleaseDisposition::NoGo,
                release_held: true,
                no_go: true,
                compile_gates_deferred: 0,
                missing_required_kinds: Vec::new(),
                roots_only: true,
            },
        };
        state.summary = state.summarize();
        state.validate()?;
        Ok(state)
    }

    pub fn insert_evidence(&mut self, packet: EvidencePacket) -> Result<()> {
        packet.validate(&self.config)?;
        if self.evidence.contains_key(&packet.id) {
            return Err(ArchiveError::DuplicateId(packet.id));
        }
        self.evidence.insert(packet.id.clone(), packet);
        self.refresh_seal()?;
        Ok(())
    }

    pub fn insert_deferred_gate(&mut self, gate: DeferredGate) -> Result<()> {
        gate.validate(&self.config)?;
        if self.deferred_gates.contains_key(&gate.id) {
            return Err(ArchiveError::DuplicateId(gate.id));
        }
        self.deferred_gates.insert(gate.id.clone(), gate);
        self.refresh_seal()?;
        Ok(())
    }

    pub fn set_lane_decision(&mut self, decision: LaneDecision) -> Result<()> {
        decision.validate(&self.evidence)?;
        self.decisions.insert(decision.lane, decision);
        self.refresh_seal()?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        self.config.validate()?;
        if self.evidence.len() < self.config.min_evidence_packets {
            return Err(ArchiveError::MissingRequiredEvidence(
                "evidence packet count",
            ));
        }
        if self.decisions.len() < self.config.min_decision_lanes {
            return Err(ArchiveError::MissingRequiredEvidence("decision lane count"));
        }
        if self.deferred_gates.len() < self.config.min_deferred_gates {
            return Err(ArchiveError::MissingRequiredEvidence("deferred gate count"));
        }
        for packet in self.evidence.values() {
            packet.validate(&self.config)?;
        }
        for gate in self.deferred_gates.values() {
            gate.validate(&self.config)?;
        }
        for decision in self.decisions.values() {
            decision.validate(&self.evidence)?;
        }
        self.validate_required_kinds()?;
        self.validate_compile_gates_deferred()?;
        self.captain_seal.validate()?;
        if self.summary.disposition != ReleaseDisposition::NoGo {
            return Err(ArchiveError::ReleaseWouldOpen);
        }
        if !self.summary.roots_only {
            return Err(ArchiveError::PolicyViolation(
                "summary is not roots-only".to_string(),
            ));
        }
        Ok(())
    }

    pub fn public_record(&self) -> PublicRecord {
        PublicRecord {
            protocol_version: self.config.protocol_version.clone(),
            schema_version: self.config.schema_version,
            release_wave: self.config.release_wave,
            source_replay_wave: self.config.source_replay_wave,
            release_label: self.config.release_label.clone(),
            privacy_mode: self.config.privacy_mode.clone(),
            disposition: self.summary.disposition,
            evidence_root: evidence_root(&self.evidence),
            decision_root: decision_root(&self.decisions),
            deferred_gate_root: deferred_gate_root(&self.deferred_gates),
            captain_seal_root: self.captain_seal.seal_root.clone(),
            state_root: self.root(),
            evidence_count: self.evidence.len(),
            lane_count: self.decisions.len(),
            deferred_gate_count: self.deferred_gates.len(),
        }
    }

    pub fn root(&self) -> String {
        digest_pairs(
            "state",
            &[
                ("config_root", self.config.root().as_str()),
                ("evidence_root", evidence_root(&self.evidence).as_str()),
                ("decision_root", decision_root(&self.decisions).as_str()),
                (
                    "deferred_gate_root",
                    deferred_gate_root(&self.deferred_gates).as_str(),
                ),
                ("captain_seal_root", self.captain_seal.seal_root.as_str()),
                ("summary_root", self.summary.root().as_str()),
            ],
        )
    }

    pub fn summarize(&self) -> ArchiveSummary {
        let missing_required_kinds = required_evidence_kinds()
            .into_iter()
            .filter(|kind| !self.evidence.values().any(|packet| packet.kind == *kind))
            .collect::<Vec<EvidenceKind>>();
        let compile_gates_deferred = self
            .deferred_gates
            .values()
            .filter(|gate| {
                gate.kind.requires_defer_only() && gate.execution == GateExecution::Deferred
            })
            .count();
        let roots_only = self.evidence.values().all(|packet| packet.roots_only);
        let disposition = if !missing_required_kinds.is_empty() {
            ReleaseDisposition::BlockedByMissingEvidence
        } else if self
            .deferred_gates
            .values()
            .any(|gate| !gate.execution.allowed_in_archive())
        {
            ReleaseDisposition::BlockedByExecutedHeavyGate
        } else {
            ReleaseDisposition::NoGo
        };
        ArchiveSummary {
            disposition,
            release_held: true,
            no_go: matches!(
                disposition,
                ReleaseDisposition::NoGo | ReleaseDisposition::Held
            ),
            compile_gates_deferred,
            missing_required_kinds,
            roots_only,
        }
    }

    fn refresh_seal(&mut self) -> Result<()> {
        self.summary = self.summarize();
        let wave88_replay_root = digest_pairs(
            "wave88-replay-root-binding",
            &[
                ("source_wave", &self.config.source_replay_wave.to_string()),
                ("source_epoch", &self.config.source_replay_epoch.to_string()),
                ("purpose", "release-captain-go-no-go-replay-drill"),
            ],
        );
        self.captain_seal = CaptainSeal::new(
            "wave89-release-captain",
            self.summary.disposition,
            &wave88_replay_root,
            &evidence_root(&self.evidence),
            &deferred_gate_root(&self.deferred_gates),
        )?;
        Ok(())
    }

    fn validate_required_kinds(&self) -> Result<()> {
        for kind in required_evidence_kinds() {
            if !self.evidence.values().any(|packet| packet.kind == kind) {
                return Err(ArchiveError::MissingRequiredEvidence(kind.as_str()));
            }
        }
        Ok(())
    }

    fn validate_compile_gates_deferred(&self) -> Result<()> {
        let deferred = self
            .deferred_gates
            .values()
            .filter(|gate| {
                gate.kind.requires_defer_only() && gate.execution == GateExecution::Deferred
            })
            .count();
        if deferred < self.config.min_deferred_gates {
            return Err(ArchiveError::MissingRequiredEvidence(
                "deferred compile gates",
            ));
        }
        for lane in DecisionLane::all()
            .into_iter()
            .filter(|lane| lane.is_compile_gate())
        {
            let has_decision = match self.decisions.get(&lane) {
                Some(decision) => decision.status.contributes_to_no_go(),
                None => false,
            };
            if !has_decision {
                return Err(ArchiveError::UnknownLane(lane.as_str().to_string()));
            }
        }
        Ok(())
    }
}

pub fn devnet() -> State {
    match State::new(Config::new()) {
        Ok(state) => state,
        Err(_) => fallback_state(),
    }
}

pub fn public_record() -> PublicRecord {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().root()
}

fn default_evidence(config: &Config) -> Result<BTreeMap<String, EvidencePacket>> {
    let rows = vec![
        (
            "wave88-replay-compile-root",
            EvidenceKind::Wave88ReplayDecisionRoot,
            DecisionLane::CompileStatus,
            "wave88-compile-status-replay-held",
            config.archive_height.saturating_sub(28),
        ),
        (
            "captain-no-go-signoff-root",
            EvidenceKind::CaptainNoGoSignoffRoot,
            DecisionLane::CompileStatus,
            "wave89-captain-no-go-signoff",
            config.archive_height.saturating_sub(27),
        ),
        (
            "deferred-cargo-check-root",
            EvidenceKind::DeferredCargoCheckRoot,
            DecisionLane::CargoCheck,
            "cargo-check-deferred-status-root",
            config.archive_height.saturating_sub(24),
        ),
        (
            "deferred-clippy-root",
            EvidenceKind::DeferredClippyRoot,
            DecisionLane::Clippy,
            "cargo-clippy-deferred-status-root",
            config.archive_height.saturating_sub(23),
        ),
        (
            "deferred-rustfmt-root",
            EvidenceKind::DeferredRustfmtRoot,
            DecisionLane::Rustfmt,
            "cargo-fmt-check-deferred-status-root",
            config.archive_height.saturating_sub(22),
        ),
        (
            "deferred-rustc-root",
            EvidenceKind::DeferredRustcRoot,
            DecisionLane::Rustc,
            "rustc-smoke-deferred-status-root",
            config.archive_height.saturating_sub(21),
        ),
        (
            "deferred-cargo-metadata-root",
            EvidenceKind::DeferredCargoMetadataRoot,
            DecisionLane::CompileStatus,
            "cargo-metadata-deferred-status-root",
            config.archive_height.saturating_sub(20),
        ),
        (
            "bridge-custody-hold-root",
            EvidenceKind::BridgeCustodyHoldRoot,
            DecisionLane::BridgeCustody,
            "bridge-custody-release-hold-root",
            config.archive_height.saturating_sub(19),
        ),
        (
            "privacy-budget-hold-root",
            EvidenceKind::PrivacyBudgetHoldRoot,
            DecisionLane::PrivacyReserve,
            "privacy-budget-release-hold-root",
            config.archive_height.saturating_sub(18),
        ),
        (
            "pager-ack-root",
            EvidenceKind::PagerAckRoot,
            DecisionLane::DevnetReplay,
            "release-captain-pager-ack-root",
            config.archive_height.saturating_sub(17),
        ),
        (
            "rollback-command-root",
            EvidenceKind::RollbackCommandRoot,
            DecisionLane::DevnetReplay,
            "rollback-command-ready-root",
            config.archive_height.saturating_sub(16),
        ),
        (
            "operator-transcript-root",
            EvidenceKind::OperatorTranscriptRoot,
            DecisionLane::DevnetReplay,
            "operator-transcript-redacted-root",
            config.archive_height.saturating_sub(15),
        ),
    ];
    let mut map = BTreeMap::new();
    for (id, kind, lane, seed, source_height) in rows {
        let root = digest_pairs(
            "default-evidence-root",
            &[
                ("id", id),
                ("kind", kind.as_str()),
                ("lane", lane.as_str()),
                ("seed", seed),
                ("source_wave", &config.source_replay_wave.to_string()),
            ],
        );
        let packet =
            EvidencePacket::new(id, kind, lane, &root, source_height, config.archive_height)?;
        if map.insert(packet.id.clone(), packet).is_some() {
            return Err(ArchiveError::DuplicateId(id.to_string()));
        }
    }
    Ok(map)
}

fn default_deferred_gates(config: &Config) -> Result<BTreeMap<String, DeferredGate>> {
    let rows = vec![
        (
            "gate-cargo-check",
            GateKind::CargoCheck,
            DecisionLane::CargoCheck,
        ),
        (
            "gate-cargo-clippy",
            GateKind::CargoClippy,
            DecisionLane::Clippy,
        ),
        (
            "gate-cargo-fmt-check",
            GateKind::CargoFmtCheck,
            DecisionLane::Rustfmt,
        ),
        (
            "gate-rustc-smoke",
            GateKind::RustcSmoke,
            DecisionLane::Rustc,
        ),
        (
            "gate-cargo-metadata",
            GateKind::CargoMetadata,
            DecisionLane::CompileStatus,
        ),
        (
            "gate-integration-replay",
            GateKind::IntegrationReplay,
            DecisionLane::DevnetReplay,
        ),
        (
            "gate-devnet-fork",
            GateKind::DevnetFork,
            DecisionLane::DevnetReplay,
        ),
    ];
    let mut map = BTreeMap::new();
    for (offset, (id, kind, lane)) in rows.into_iter().enumerate() {
        let gate = DeferredGate::new(
            id,
            kind,
            lane,
            config.archive_height.saturating_add(offset as u64 + 1),
            if kind.requires_defer_only() {
                GateExecution::Deferred
            } else {
                GateExecution::NotScheduled
            },
        )?;
        if map.insert(gate.id.clone(), gate).is_some() {
            return Err(ArchiveError::DuplicateId(id.to_string()));
        }
    }
    Ok(map)
}

fn default_decisions(
    evidence: &BTreeMap<String, EvidencePacket>,
) -> Result<BTreeMap<DecisionLane, LaneDecision>> {
    let mut by_lane: BTreeMap<DecisionLane, Vec<String>> = BTreeMap::new();
    for packet in evidence.values() {
        by_lane
            .entry(packet.lane)
            .or_insert_with(Vec::new)
            .push(packet.id.clone());
    }
    let rows = vec![
        (
            DecisionLane::CompileStatus,
            DecisionStatus::NoGo,
            "wave88 replay binds compile status to release-held no-go",
        ),
        (
            DecisionLane::CargoCheck,
            DecisionStatus::DeferredCompileGate,
            "cargo check status is archived as deferred and not executed",
        ),
        (
            DecisionLane::Clippy,
            DecisionStatus::DeferredCompileGate,
            "clippy status is archived as deferred and not executed",
        ),
        (
            DecisionLane::Rustfmt,
            DecisionStatus::DeferredCompileGate,
            "rustfmt status is archived as deferred and not executed",
        ),
        (
            DecisionLane::Rustc,
            DecisionStatus::DeferredCompileGate,
            "rustc status is archived as deferred and not executed",
        ),
        (
            DecisionLane::DevnetReplay,
            DecisionStatus::RejectedUnhold,
            "devnet replay retains rollback and pager evidence roots",
        ),
        (
            DecisionLane::BridgeCustody,
            DecisionStatus::Held,
            "bridge custody remains held pending external gate completion",
        ),
        (
            DecisionLane::PrivacyReserve,
            DecisionStatus::Held,
            "privacy reserve remains held with roots-only budget evidence",
        ),
    ];
    let mut map = BTreeMap::new();
    for (lane, status, reason) in rows {
        let ids = match by_lane.get(&lane) {
            Some(found) => found.clone(),
            None => Vec::new(),
        };
        let decision = LaneDecision::new(lane, status, ids, reason)?;
        decision.validate(evidence)?;
        map.insert(lane, decision);
    }
    Ok(map)
}

fn fallback_state() -> State {
    let config = Config::new();
    let mut evidence = BTreeMap::new();
    let root = digest_pairs(
        "fallback-evidence-root",
        &[("mode", "fail-closed"), ("reason", "construction-error")],
    );
    let packet = EvidencePacket {
        id: "fallback-no-go-root".to_string(),
        kind: EvidenceKind::CaptainNoGoSignoffRoot,
        lane: DecisionLane::CompileStatus,
        root: root.clone(),
        source_wave: SOURCE_REPLAY_WAVE,
        source_height: DEFAULT_ARCHIVE_HEIGHT,
        archived_at_height: DEFAULT_ARCHIVE_HEIGHT,
        roots_only: true,
        redaction_root: digest_pairs("fallback-redaction", &[("root", root.as_str())]),
        note_root: digest_pairs("fallback-note", &[("root", root.as_str())]),
    };
    evidence.insert(packet.id.clone(), packet);
    let mut deferred_gates = BTreeMap::new();
    let gate = DeferredGate {
        id: "fallback-deferred-gate".to_string(),
        kind: GateKind::CargoCheck,
        lane: DecisionLane::CargoCheck,
        status_root: digest_pairs("fallback-gate-status", &[("status", "deferred")]),
        scheduled_height: DEFAULT_ARCHIVE_HEIGHT.saturating_add(1),
        execution: GateExecution::Deferred,
        defer_reason_root: digest_pairs("fallback-gate-reason", &[("reason", "fail-closed")]),
    };
    deferred_gates.insert(gate.id.clone(), gate);
    let mut decisions = BTreeMap::new();
    let decision = LaneDecision {
        lane: DecisionLane::CompileStatus,
        owner: DecisionLane::CompileStatus.captain_owner().to_string(),
        status: DecisionStatus::NoGo,
        evidence_ids: vec!["fallback-no-go-root".to_string()],
        decision_root: digest_pairs("fallback-decision", &[("decision", "no-go")]),
        no_go_reason_root: digest_pairs("fallback-reason", &[("reason", "fail-closed")]),
        release_held: true,
    };
    decisions.insert(DecisionLane::CompileStatus, decision);
    let captain_seal = CaptainSeal {
        captain_id: "wave89-release-captain".to_string(),
        decision: ReleaseDisposition::NoGo,
        wave88_replay_root: digest_pairs("fallback-wave88", &[("source", "wave88")]),
        evidence_archive_root: evidence_root(&evidence),
        deferred_gate_root: deferred_gate_root(&deferred_gates),
        seal_root: digest_pairs("fallback-seal", &[("decision", "no-go")]),
        release_held: true,
        no_go: true,
    };
    let summary = ArchiveSummary {
        disposition: ReleaseDisposition::NoGo,
        release_held: true,
        no_go: true,
        compile_gates_deferred: 1,
        missing_required_kinds: Vec::new(),
        roots_only: true,
    };
    State {
        config,
        evidence,
        decisions,
        deferred_gates,
        captain_seal,
        summary,
    }
}

fn required_evidence_kinds() -> Vec<EvidenceKind> {
    vec![
        EvidenceKind::Wave88ReplayDecisionRoot,
        EvidenceKind::CaptainNoGoSignoffRoot,
        EvidenceKind::DeferredCargoCheckRoot,
        EvidenceKind::DeferredClippyRoot,
        EvidenceKind::DeferredRustfmtRoot,
        EvidenceKind::DeferredRustcRoot,
        EvidenceKind::PagerAckRoot,
        EvidenceKind::RollbackCommandRoot,
    ]
}

fn evidence_root(evidence: &BTreeMap<String, EvidencePacket>) -> String {
    ordered_root(
        "evidence-root",
        evidence
            .iter()
            .map(|(id, packet)| format!("{}={}", id, packet.public_root())),
    )
}

fn decision_root(decisions: &BTreeMap<DecisionLane, LaneDecision>) -> String {
    ordered_root(
        "decision-root",
        decisions
            .iter()
            .map(|(lane, decision)| format!("{}={}", lane.as_str(), decision.public_root())),
    )
}

fn deferred_gate_root(gates: &BTreeMap<String, DeferredGate>) -> String {
    ordered_root(
        "deferred-gate-root",
        gates
            .iter()
            .map(|(id, gate)| format!("{}={}", id, gate.public_root())),
    )
}

fn require_non_empty(field: &'static str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(ArchiveError::EmptyField(field))
    } else {
        Ok(())
    }
}

fn validate_root(field: &'static str, value: &str) -> Result<()> {
    require_non_empty(field, value)?;
    if value.contains('\n') || value.contains('\r') {
        return Err(ArchiveError::InvalidRoot {
            field,
            value: value.to_string(),
        });
    }
    if value.len() < 16 {
        return Err(ArchiveError::InvalidRoot {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn ordered_root<I, S>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut parts = values
        .into_iter()
        .map(|value| value.as_ref().to_string())
        .collect::<Vec<String>>();
    parts.sort();
    let mut hasher = DefaultHasher::new();
    domain.hash(&mut hasher);
    parts.len().hash(&mut hasher);
    for part in parts {
        part.hash(&mut hasher);
    }
    format!("r{:016x}", hasher.finish())
}

fn digest_pairs(domain: &str, pairs: &[(&str, &str)]) -> String {
    let mut normalized = pairs
        .iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<String>>();
    normalized.sort();
    ordered_root(domain, normalized.iter())
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
