use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitMoneroEvidenceNegativeFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_MONERO_EVIDENCE_NEGATIVE_FIXTURE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-monero-evidence-negative-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_MONERO_EVIDENCE_NEGATIVE_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_SUITE: &str = "monero-l2-pq-bridge-exit-negative-evidence-fixtures-v1";
pub const DEVNET_FIXTURE_LABEL: &str = "devnet-monero-private-l2-bridge-exit-negative-fixtures";
pub const DEFAULT_MIN_LOCK_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_MIN_FINALITY_CONFIRMATIONS: u64 = 20;
pub const DEFAULT_REORG_CHALLENGE_DEPTH: u64 = 20;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 3;
pub const DEFAULT_MAX_PUBLIC_FIXTURES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeFixtureKind {
    InvalidLockConfirmations,
    InvalidFinalityConfirmations,
    ConflictingHeaderWindow,
    ReorgBeyondPolicy,
    WatcherEquivocation,
    WatcherQuorumBelowFloor,
    PrivacyRedactionViolation,
    NoBaseLayerVerifierResidualRisk,
}

impl NegativeFixtureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidLockConfirmations => "invalid_lock_confirmations",
            Self::InvalidFinalityConfirmations => "invalid_finality_confirmations",
            Self::ConflictingHeaderWindow => "conflicting_header_window",
            Self::ReorgBeyondPolicy => "reorg_beyond_policy",
            Self::WatcherEquivocation => "watcher_equivocation",
            Self::WatcherQuorumBelowFloor => "watcher_quorum_below_floor",
            Self::PrivacyRedactionViolation => "privacy_redaction_violation",
            Self::NoBaseLayerVerifierResidualRisk => "no_base_layer_verifier_residual_risk",
        }
    }

    pub fn policy_surface(self) -> &'static str {
        match self {
            Self::InvalidLockConfirmations => "deposit_lock_depth",
            Self::InvalidFinalityConfirmations => "exit_finality_depth",
            Self::ConflictingHeaderWindow => "header_continuity",
            Self::ReorgBeyondPolicy => "reorg_quarantine",
            Self::WatcherEquivocation => "watcher_slashing",
            Self::WatcherQuorumBelowFloor => "watcher_quorum",
            Self::PrivacyRedactionViolation => "privacy_minimization",
            Self::NoBaseLayerVerifierResidualRisk => "base_layer_verifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NegativeFixtureVerdict {
    Reject,
    Quarantine,
    SlashAndQuarantine,
    BlockProductionRelease,
}

impl NegativeFixtureVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Quarantine => "quarantine",
            Self::SlashAndQuarantine => "slash_and_quarantine",
            Self::BlockProductionRelease => "block_production_release",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::BlockProductionRelease)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    DepositLockWatcher,
    MoneroHeaderAdapter,
    FinalityPolicy,
    ReorgWatcher,
    WatcherCommittee,
    PrivacyAuditHarness,
    ReleaseGate,
}

impl EvidenceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositLockWatcher => "deposit_lock_watcher",
            Self::MoneroHeaderAdapter => "monero_header_adapter",
            Self::FinalityPolicy => "finality_policy",
            Self::ReorgWatcher => "reorg_watcher",
            Self::WatcherCommittee => "watcher_committee",
            Self::PrivacyAuditHarness => "privacy_audit_harness",
            Self::ReleaseGate => "release_gate",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionExpectation {
    PublicCommitmentsOnly,
    EncryptedWatcherPayloadOnly,
    ViolationContainsPublicPrivateHint,
}

impl RedactionExpectation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PublicCommitmentsOnly => "public_commitments_only",
            Self::EncryptedWatcherPayloadOnly => "encrypted_watcher_payload_only",
            Self::ViolationContainsPublicPrivateHint => "violation_contains_public_private_hint",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlocker {
    CargoChecksDeferred,
    ProductionReleaseDisabled,
    BaseLayerVerifierAbsent,
    PrivacyRedactionViolation,
    HeaderConflictUnresolved,
    WatcherEquivocationDetected,
}

impl ReleaseBlocker {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoChecksDeferred => "cargo_checks_deferred",
            Self::ProductionReleaseDisabled => "production_release_disabled",
            Self::BaseLayerVerifierAbsent => "base_layer_verifier_absent",
            Self::PrivacyRedactionViolation => "privacy_redaction_violation",
            Self::HeaderConflictUnresolved => "header_conflict_unresolved",
            Self::WatcherEquivocationDetected => "watcher_equivocation_detected",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_suite: String,
    pub fixture_label: String,
    pub min_lock_confirmations: u64,
    pub min_finality_confirmations: u64,
    pub reorg_challenge_depth: u64,
    pub min_watcher_quorum: u64,
    pub base_layer_verifier_enabled: bool,
    pub privacy_redaction_required: bool,
    pub equivocation_slashing_enabled: bool,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_public_fixtures: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_suite: FIXTURE_SUITE.to_string(),
            fixture_label: DEVNET_FIXTURE_LABEL.to_string(),
            min_lock_confirmations: DEFAULT_MIN_LOCK_CONFIRMATIONS,
            min_finality_confirmations: DEFAULT_MIN_FINALITY_CONFIRMATIONS,
            reorg_challenge_depth: DEFAULT_REORG_CHALLENGE_DEPTH,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            base_layer_verifier_enabled: false,
            privacy_redaction_required: true,
            equivocation_slashing_enabled: true,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_public_fixtures: DEFAULT_MAX_PUBLIC_FIXTURES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_suite": self.fixture_suite,
            "fixture_label": self.fixture_label,
            "min_lock_confirmations": self.min_lock_confirmations,
            "min_finality_confirmations": self.min_finality_confirmations,
            "reorg_challenge_depth": self.reorg_challenge_depth,
            "min_watcher_quorum": self.min_watcher_quorum,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "privacy_redaction_required": self.privacy_redaction_required,
            "equivocation_slashing_enabled": self.equivocation_slashing_enabled,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_public_fixtures": self.max_public_fixtures,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NegativeEvidenceFixture {
    pub fixture_id: String,
    pub kind: NegativeFixtureKind,
    pub source: EvidenceSource,
    pub verdict: NegativeFixtureVerdict,
    pub subject_id: String,
    pub monero_height: u64,
    pub observed_confirmations: u64,
    pub required_confirmations: u64,
    pub watcher_count: u64,
    pub required_watcher_count: u64,
    pub header_window_start: u64,
    pub header_window_end: u64,
    pub claimed_header_root: String,
    pub conflicting_header_root: String,
    pub observation_root: String,
    pub redaction_expectation: RedactionExpectation,
    pub public_payload_contains_private_hint: bool,
    pub base_layer_verifier_present: bool,
    pub release_blocker: ReleaseBlocker,
    pub fixture_root: String,
}

impl NegativeEvidenceFixture {
    pub fn invalid_lock_confirmations(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::InvalidLockConfirmations,
            EvidenceSource::DepositLockWatcher,
            NegativeFixtureVerdict::Reject,
            "negative-lock-short-confirmations",
            3_620_110,
            config.min_lock_confirmations.saturating_sub(2),
            config.min_lock_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_101,
            3_620_110,
            RedactionExpectation::PublicCommitmentsOnly,
            false,
            true,
            ReleaseBlocker::ProductionReleaseDisabled,
        )
    }

    pub fn invalid_finality_confirmations(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::InvalidFinalityConfirmations,
            EvidenceSource::FinalityPolicy,
            NegativeFixtureVerdict::Reject,
            "negative-finality-short-confirmations",
            3_620_210,
            config.min_finality_confirmations.saturating_sub(5),
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_191,
            3_620_210,
            RedactionExpectation::PublicCommitmentsOnly,
            false,
            true,
            ReleaseBlocker::ProductionReleaseDisabled,
        )
    }

    pub fn conflicting_header_window(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::ConflictingHeaderWindow,
            EvidenceSource::MoneroHeaderAdapter,
            NegativeFixtureVerdict::Quarantine,
            "negative-conflicting-header-window",
            3_620_330,
            config.min_finality_confirmations,
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_311,
            3_620_330,
            RedactionExpectation::EncryptedWatcherPayloadOnly,
            false,
            true,
            ReleaseBlocker::HeaderConflictUnresolved,
        )
    }

    pub fn reorg_beyond_policy(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::ReorgBeyondPolicy,
            EvidenceSource::ReorgWatcher,
            NegativeFixtureVerdict::Quarantine,
            "negative-reorg-beyond-policy-depth",
            3_620_460,
            config.min_finality_confirmations + 3,
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_460 - config.reorg_challenge_depth - 3,
            3_620_460,
            RedactionExpectation::EncryptedWatcherPayloadOnly,
            false,
            true,
            ReleaseBlocker::HeaderConflictUnresolved,
        )
    }

    pub fn watcher_equivocation(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::WatcherEquivocation,
            EvidenceSource::WatcherCommittee,
            NegativeFixtureVerdict::SlashAndQuarantine,
            "negative-watcher-equivocation",
            3_620_550,
            config.min_finality_confirmations,
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_531,
            3_620_550,
            RedactionExpectation::EncryptedWatcherPayloadOnly,
            false,
            true,
            ReleaseBlocker::WatcherEquivocationDetected,
        )
    }

    pub fn watcher_quorum_below_floor(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::WatcherQuorumBelowFloor,
            EvidenceSource::WatcherCommittee,
            NegativeFixtureVerdict::Reject,
            "negative-watcher-quorum-below-floor",
            3_620_640,
            config.min_finality_confirmations,
            config.min_finality_confirmations,
            config.min_watcher_quorum.saturating_sub(1),
            config.min_watcher_quorum,
            3_620_621,
            3_620_640,
            RedactionExpectation::PublicCommitmentsOnly,
            false,
            true,
            ReleaseBlocker::ProductionReleaseDisabled,
        )
    }

    pub fn privacy_redaction_violation(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::PrivacyRedactionViolation,
            EvidenceSource::PrivacyAuditHarness,
            NegativeFixtureVerdict::BlockProductionRelease,
            "negative-public-private-hint",
            3_620_710,
            config.min_finality_confirmations,
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_691,
            3_620_710,
            RedactionExpectation::ViolationContainsPublicPrivateHint,
            true,
            true,
            ReleaseBlocker::PrivacyRedactionViolation,
        )
    }

    pub fn no_base_layer_verifier_residual_risk(config: &Config) -> Self {
        Self::new(
            NegativeFixtureKind::NoBaseLayerVerifierResidualRisk,
            EvidenceSource::ReleaseGate,
            NegativeFixtureVerdict::BlockProductionRelease,
            "negative-no-base-layer-verifier",
            3_620_800,
            config.min_finality_confirmations,
            config.min_finality_confirmations,
            config.min_watcher_quorum,
            config.min_watcher_quorum,
            3_620_781,
            3_620_800,
            RedactionExpectation::PublicCommitmentsOnly,
            false,
            config.base_layer_verifier_enabled,
            ReleaseBlocker::BaseLayerVerifierAbsent,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: NegativeFixtureKind,
        source: EvidenceSource,
        verdict: NegativeFixtureVerdict,
        subject_id: &str,
        monero_height: u64,
        observed_confirmations: u64,
        required_confirmations: u64,
        watcher_count: u64,
        required_watcher_count: u64,
        header_window_start: u64,
        header_window_end: u64,
        redaction_expectation: RedactionExpectation,
        public_payload_contains_private_hint: bool,
        base_layer_verifier_present: bool,
        release_blocker: ReleaseBlocker,
    ) -> Self {
        let claimed_header_root = labeled_hash("claimed-header-window", subject_id, monero_height);
        let conflicting_header_root = labeled_hash(
            kind.as_str(),
            "conflicting-header-window",
            header_window_end,
        );
        let observation_root = observation_root(
            kind,
            subject_id,
            observed_confirmations,
            watcher_count,
            redaction_expectation,
        );
        let fixture_id = fixture_id(kind, source, subject_id, &observation_root);
        let mut fixture = Self {
            fixture_id,
            kind,
            source,
            verdict,
            subject_id: subject_id.to_string(),
            monero_height,
            observed_confirmations,
            required_confirmations,
            watcher_count,
            required_watcher_count,
            header_window_start,
            header_window_end,
            claimed_header_root,
            conflicting_header_root,
            observation_root,
            redaction_expectation,
            public_payload_contains_private_hint,
            base_layer_verifier_present,
            release_blocker,
            fixture_root: String::new(),
        };
        fixture.fixture_root = fixture.compute_root();
        fixture
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "kind": self.kind.as_str(),
            "policy_surface": self.kind.policy_surface(),
            "source": self.source.as_str(),
            "verdict": self.verdict.as_str(),
            "subject_id": self.subject_id,
            "monero_height": self.monero_height,
            "observed_confirmations": self.observed_confirmations,
            "required_confirmations": self.required_confirmations,
            "watcher_count": self.watcher_count,
            "required_watcher_count": self.required_watcher_count,
            "header_window_start": self.header_window_start,
            "header_window_end": self.header_window_end,
            "claimed_header_root": self.claimed_header_root,
            "conflicting_header_root": self.conflicting_header_root,
            "observation_root": self.observation_root,
            "redaction_expectation": self.redaction_expectation.as_str(),
            "public_payload_contains_private_hint": self.public_payload_contains_private_hint,
            "base_layer_verifier_present": self.base_layer_verifier_present,
            "release_blocker": self.release_blocker.as_str(),
            "fixture_root": self.fixture_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-FIXTURE",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(self.kind.as_str()),
                HashPart::Str(self.source.as_str()),
                HashPart::Str(self.verdict.as_str()),
                HashPart::Str(&self.subject_id),
                HashPart::U64(self.monero_height),
                HashPart::U64(self.observed_confirmations),
                HashPart::U64(self.required_confirmations),
                HashPart::U64(self.watcher_count),
                HashPart::U64(self.required_watcher_count),
                HashPart::U64(self.header_window_start),
                HashPart::U64(self.header_window_end),
                HashPart::Str(&self.claimed_header_root),
                HashPart::Str(&self.conflicting_header_root),
                HashPart::Str(&self.observation_root),
                HashPart::Str(self.redaction_expectation.as_str()),
                HashPart::Str(if self.public_payload_contains_private_hint {
                    "private_hint_present"
                } else {
                    "private_hint_absent"
                }),
                HashPart::Str(if self.base_layer_verifier_present {
                    "base_layer_verifier_present"
                } else {
                    "base_layer_verifier_absent"
                }),
                HashPart::Str(self.release_blocker.as_str()),
            ],
            32,
        )
    }

    pub fn validate_against(&self, config: &Config) -> Result<()> {
        if self.fixture_root != self.compute_root() {
            return Err(format!("fixture root mismatch for {}", self.fixture_id));
        }
        if self.kind == NegativeFixtureKind::InvalidLockConfirmations
            && self.observed_confirmations >= config.min_lock_confirmations
        {
            return Err(
                "invalid lock fixture does not violate lock confirmation floor".to_string(),
            );
        }
        if self.kind == NegativeFixtureKind::InvalidFinalityConfirmations
            && self.observed_confirmations >= config.min_finality_confirmations
        {
            return Err(
                "invalid finality fixture does not violate finality confirmation floor".to_string(),
            );
        }
        if self.kind == NegativeFixtureKind::WatcherQuorumBelowFloor
            && self.watcher_count >= config.min_watcher_quorum
        {
            return Err("watcher quorum fixture does not violate quorum floor".to_string());
        }
        if self.kind == NegativeFixtureKind::PrivacyRedactionViolation
            && !self.public_payload_contains_private_hint
        {
            return Err("privacy violation fixture lacks a public private-hint marker".to_string());
        }
        if self.kind == NegativeFixtureKind::NoBaseLayerVerifierResidualRisk
            && self.base_layer_verifier_present
        {
            return Err("residual-risk fixture unexpectedly has a base-layer verifier".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PolicySummary {
    pub summary_id: String,
    pub fixture_root: String,
    pub rejection_count: u64,
    pub quarantine_count: u64,
    pub slashing_count: u64,
    pub production_blocker_count: u64,
    pub privacy_violation_count: u64,
    pub residual_risk_count: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub summary_root: String,
}

impl PolicySummary {
    pub fn from_fixtures(config: &Config, fixtures: &[NegativeEvidenceFixture]) -> Self {
        let fixture_records = fixtures
            .iter()
            .map(NegativeEvidenceFixture::public_record)
            .collect::<Vec<_>>();
        let fixture_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-FIXTURE-SET",
            &fixture_records,
        );
        let rejection_count = fixtures
            .iter()
            .filter(|fixture| fixture.verdict == NegativeFixtureVerdict::Reject)
            .count() as u64;
        let quarantine_count = fixtures
            .iter()
            .filter(|fixture| {
                matches!(
                    fixture.verdict,
                    NegativeFixtureVerdict::Quarantine | NegativeFixtureVerdict::SlashAndQuarantine
                )
            })
            .count() as u64;
        let slashing_count = fixtures
            .iter()
            .filter(|fixture| fixture.verdict == NegativeFixtureVerdict::SlashAndQuarantine)
            .count() as u64;
        let production_blocker_count = fixtures
            .iter()
            .filter(|fixture| fixture.verdict.blocks_release())
            .count() as u64;
        let privacy_violation_count = fixtures
            .iter()
            .filter(|fixture| fixture.kind == NegativeFixtureKind::PrivacyRedactionViolation)
            .count() as u64;
        let residual_risk_count = fixtures
            .iter()
            .filter(|fixture| {
                fixture.kind == NegativeFixtureKind::NoBaseLayerVerifierResidualRisk
                    || !fixture.base_layer_verifier_present
            })
            .count() as u64;
        let summary_id = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-SUMMARY-ID",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&fixture_root),
                HashPart::U64(rejection_count),
                HashPart::U64(quarantine_count),
                HashPart::U64(production_blocker_count),
            ],
            32,
        );
        let mut summary = Self {
            summary_id,
            fixture_root,
            rejection_count,
            quarantine_count,
            slashing_count,
            production_blocker_count,
            privacy_violation_count,
            residual_risk_count,
            cargo_checks_deferred: config.cargo_checks_deferred,
            production_release_allowed: config.production_release_allowed,
            summary_root: String::new(),
        };
        summary.summary_root = summary.compute_root();
        summary
    }

    pub fn public_record(&self) -> Value {
        json!({
            "summary_id": self.summary_id,
            "fixture_root": self.fixture_root,
            "rejection_count": self.rejection_count,
            "quarantine_count": self.quarantine_count,
            "slashing_count": self.slashing_count,
            "production_blocker_count": self.production_blocker_count,
            "privacy_violation_count": self.privacy_violation_count,
            "residual_risk_count": self.residual_risk_count,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "summary_root": self.summary_root,
        })
    }

    pub fn compute_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-SUMMARY",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.summary_id),
                HashPart::Str(&self.fixture_root),
                HashPart::U64(self.rejection_count),
                HashPart::U64(self.quarantine_count),
                HashPart::U64(self.slashing_count),
                HashPart::U64(self.production_blocker_count),
                HashPart::U64(self.privacy_violation_count),
                HashPart::U64(self.residual_risk_count),
                HashPart::Str(if self.cargo_checks_deferred {
                    "cargo_checks_deferred"
                } else {
                    "cargo_checks_not_deferred"
                }),
                HashPart::Str(if self.production_release_allowed {
                    "production_release_allowed"
                } else {
                    "production_release_blocked"
                }),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fixtures: Vec<NegativeEvidenceFixture>,
    pub policy_summary: PolicySummary,
    pub release_blockers: Vec<ReleaseBlocker>,
    pub config_root: String,
    pub fixture_root: String,
    pub release_blocker_root: String,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let fixtures = devnet_negative_fixtures(&config);
        Self::new(config, fixtures)
    }

    pub fn new(config: Config, fixtures: Vec<NegativeEvidenceFixture>) -> Self {
        let policy_summary = PolicySummary::from_fixtures(&config, &fixtures);
        let release_blockers = release_blockers(&config, &fixtures);
        let config_root = config.state_root();
        let fixture_records = fixtures
            .iter()
            .map(NegativeEvidenceFixture::public_record)
            .collect::<Vec<_>>();
        let fixture_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-FIXTURE-SET",
            &fixture_records,
        );
        let release_blocker_records = release_blockers
            .iter()
            .map(|blocker| json!({"release_blocker": blocker.as_str()}))
            .collect::<Vec<_>>();
        let release_blocker_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-RELEASE-BLOCKERS",
            &release_blocker_records,
        );
        let state_root = compute_state_root(
            &config_root,
            &fixture_root,
            &policy_summary.summary_root,
            &release_blocker_root,
        );
        Self {
            config,
            fixtures,
            policy_summary,
            release_blockers,
            config_root,
            fixture_root,
            release_blocker_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "fixtures": self.fixtures.iter().map(NegativeEvidenceFixture::public_record).collect::<Vec<_>>(),
            "policy_summary": self.policy_summary.public_record(),
            "release_blockers": self.release_blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "config_root": self.config_root,
            "fixture_root": self.fixture_root,
            "release_blocker_root": self.release_blocker_root,
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn validate(&self) -> Result<()> {
        if self.config.chain_id != CHAIN_ID {
            return Err(format!("unexpected chain id {}", self.config.chain_id));
        }
        if self.config.cargo_checks_deferred != true {
            return Err("cargo checks must remain deferred in this fixture runtime".to_string());
        }
        if self.config.production_release_allowed != false {
            return Err(
                "production release must remain disabled for negative fixtures".to_string(),
            );
        }
        if self.fixtures.len() > self.config.max_public_fixtures {
            return Err(format!(
                "fixture count {} exceeds max {}",
                self.fixtures.len(),
                self.config.max_public_fixtures
            ));
        }
        for fixture in &self.fixtures {
            fixture.validate_against(&self.config)?;
        }
        let rebuilt = Self::new(self.config.clone(), self.fixtures.clone());
        if self.state_root != rebuilt.state_root {
            return Err("state root mismatch".to_string());
        }
        Ok(())
    }

    pub fn fixture_by_kind(&self, kind: NegativeFixtureKind) -> Option<&NegativeEvidenceFixture> {
        self.fixtures.iter().find(|fixture| fixture.kind == kind)
    }

    pub fn release_blocker_names(&self) -> Vec<&'static str> {
        self.release_blockers
            .iter()
            .map(|blocker| blocker.as_str())
            .collect()
    }

    pub fn production_release_allowed(&self) -> bool {
        self.config.production_release_allowed
            && self.release_blockers.is_empty()
            && self.policy_summary.production_blocker_count == 0
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

pub fn devnet_negative_fixtures(config: &Config) -> Vec<NegativeEvidenceFixture> {
    vec![
        NegativeEvidenceFixture::invalid_lock_confirmations(config),
        NegativeEvidenceFixture::invalid_finality_confirmations(config),
        NegativeEvidenceFixture::conflicting_header_window(config),
        NegativeEvidenceFixture::reorg_beyond_policy(config),
        NegativeEvidenceFixture::watcher_equivocation(config),
        NegativeEvidenceFixture::watcher_quorum_below_floor(config),
        NegativeEvidenceFixture::privacy_redaction_violation(config),
        NegativeEvidenceFixture::no_base_layer_verifier_residual_risk(config),
    ]
}

pub fn release_blockers(
    config: &Config,
    fixtures: &[NegativeEvidenceFixture],
) -> Vec<ReleaseBlocker> {
    let mut blockers = Vec::new();
    push_unique(&mut blockers, ReleaseBlocker::CargoChecksDeferred);
    if !config.production_release_allowed {
        push_unique(&mut blockers, ReleaseBlocker::ProductionReleaseDisabled);
    }
    if !config.base_layer_verifier_enabled {
        push_unique(&mut blockers, ReleaseBlocker::BaseLayerVerifierAbsent);
    }
    for fixture in fixtures {
        if fixture.public_payload_contains_private_hint {
            push_unique(&mut blockers, ReleaseBlocker::PrivacyRedactionViolation);
        }
        if fixture.kind == NegativeFixtureKind::ConflictingHeaderWindow
            || fixture.kind == NegativeFixtureKind::ReorgBeyondPolicy
        {
            push_unique(&mut blockers, ReleaseBlocker::HeaderConflictUnresolved);
        }
        if fixture.kind == NegativeFixtureKind::WatcherEquivocation {
            push_unique(&mut blockers, ReleaseBlocker::WatcherEquivocationDetected);
        }
    }
    blockers
}

fn push_unique(blockers: &mut Vec<ReleaseBlocker>, blocker: ReleaseBlocker) {
    if !blockers.contains(&blocker) {
        blockers.push(blocker);
    }
}

fn fixture_id(
    kind: NegativeFixtureKind,
    source: EvidenceSource,
    subject_id: &str,
    observation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-FIXTURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(source.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(observation_root),
        ],
        32,
    )
}

fn observation_root(
    kind: NegativeFixtureKind,
    subject_id: &str,
    observed_confirmations: u64,
    watcher_count: u64,
    redaction_expectation: RedactionExpectation,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-OBSERVATION",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind.as_str()),
            HashPart::Str(kind.policy_surface()),
            HashPart::Str(subject_id),
            HashPart::U64(observed_confirmations),
            HashPart::U64(watcher_count),
            HashPart::Str(redaction_expectation.as_str()),
        ],
        32,
    )
}

fn labeled_hash(label: &str, subject_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-LABELED-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-RECORD",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn compute_state_root(
    config_root: &str,
    fixture_root: &str,
    summary_root: &str,
    release_blocker_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-NEGATIVE-EVIDENCE-STATE",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(config_root),
            HashPart::Str(fixture_root),
            HashPart::Str(summary_root),
            HashPart::Str(release_blocker_root),
        ],
        32,
    )
}
