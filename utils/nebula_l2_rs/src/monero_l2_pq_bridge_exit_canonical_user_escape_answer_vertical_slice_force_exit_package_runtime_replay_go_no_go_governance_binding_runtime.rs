use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeAnswerVerticalSliceForceExitPackageRuntimeReplayGoNoGoGovernanceBindingRuntimeResult<
    T,
> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-force-exit-package-runtime-replay-go-no-go-governance-binding-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_ANSWER_VERTICAL_SLICE_FORCE_EXIT_PACKAGE_RUNTIME_REPLAY_GO_NO_GO_GOVERNANCE_BINDING_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const GOVERNANCE_BINDING_SUITE: &str =
    "force-exit-package-runtime-replay-go-no-go-governance-binding-v1";
pub const DEFAULT_VERTICAL_SLICE_ID: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-answer-vertical-slice-devnet-v1";
pub const DEFAULT_FORCE_EXIT_PACKAGE_ID: &str =
    "force-exit-package-runtime-replay-go-no-go-governance-binding-devnet-0001";
pub const DEFAULT_RELEASE_MANIFEST_ID: &str =
    "release-manifest-runtime-replay-go-no-go-governance-binding-devnet-0001";
pub const DEFAULT_GOVERNANCE_ROUND: u64 = 80;
pub const DEFAULT_L2_HEIGHT: u64 = 896_080;
pub const DEFAULT_MONERO_HEIGHT: u64 = 3_080_896;
pub const DEFAULT_MIN_GO_RECORDS: u64 = 8;
pub const DEFAULT_MIN_REVIEWER_QUORUM: u64 = 5;
pub const DEFAULT_MAX_ALLOWED_HOLDS: u64 = 0;
pub const DEFAULT_MAX_L2_FRESHNESS_DELTA: u64 = 8;
pub const DEFAULT_MAX_MONERO_FRESHNESS_DELTA: u64 = 6;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub governance_binding_suite: String,
    pub vertical_slice_id: String,
    pub force_exit_package_id: String,
    pub release_manifest_id: String,
    pub governance_round: u64,
    pub l2_height: u64,
    pub monero_height: u64,
    pub min_go_records: u64,
    pub min_reviewer_quorum: u64,
    pub max_allowed_holds: u64,
    pub max_l2_freshness_delta: u64,
    pub max_monero_freshness_delta: u64,
    pub require_replay_enforcement_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_replay_transcript_root: bool,
    pub require_freshness_root: bool,
    pub require_reviewer_root: bool,
    pub require_operator_acknowledgement: bool,
    pub require_wallet_public_hold_notices: bool,
    pub fail_closed_on_any_violation: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            governance_binding_suite: GOVERNANCE_BINDING_SUITE.to_string(),
            vertical_slice_id: DEFAULT_VERTICAL_SLICE_ID.to_string(),
            force_exit_package_id: DEFAULT_FORCE_EXIT_PACKAGE_ID.to_string(),
            release_manifest_id: DEFAULT_RELEASE_MANIFEST_ID.to_string(),
            governance_round: DEFAULT_GOVERNANCE_ROUND,
            l2_height: DEFAULT_L2_HEIGHT,
            monero_height: DEFAULT_MONERO_HEIGHT,
            min_go_records: DEFAULT_MIN_GO_RECORDS,
            min_reviewer_quorum: DEFAULT_MIN_REVIEWER_QUORUM,
            max_allowed_holds: DEFAULT_MAX_ALLOWED_HOLDS,
            max_l2_freshness_delta: DEFAULT_MAX_L2_FRESHNESS_DELTA,
            max_monero_freshness_delta: DEFAULT_MAX_MONERO_FRESHNESS_DELTA,
            require_replay_enforcement_root: true,
            require_circuit_breaker_root: true,
            require_replay_transcript_root: true,
            require_freshness_root: true,
            require_reviewer_root: true,
            require_operator_acknowledgement: true,
            require_wallet_public_hold_notices: true,
            fail_closed_on_any_violation: true,
        }
    }
}

impl Config {
    pub fn devnet() -> Self {
        Self::default()
    }

    pub fn required_root_count(&self) -> u64 {
        [
            self.require_replay_enforcement_root,
            self.require_circuit_breaker_root,
            self.require_replay_transcript_root,
            self.require_freshness_root,
            self.require_reviewer_root,
            self.require_operator_acknowledgement,
            self.require_wallet_public_hold_notices,
        ]
        .iter()
        .filter(|required| **required)
        .count() as u64
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!(self);
        if let Some(object) = record.as_object_mut() {
            object.insert(
                "required_root_count".to_string(),
                Value::from(self.required_root_count()),
            );
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceTrack {
    RuntimeReplayManifest,
    CircuitBreaker,
    ReplayTranscript,
    FreshnessWindow,
    ReviewerQuorum,
    OperatorAcknowledgement,
    WalletHoldNotice,
    PublicHoldNotice,
}

impl GovernanceTrack {
    pub fn ordered() -> &'static [Self] {
        &[
            Self::RuntimeReplayManifest,
            Self::CircuitBreaker,
            Self::ReplayTranscript,
            Self::FreshnessWindow,
            Self::ReviewerQuorum,
            Self::OperatorAcknowledgement,
            Self::WalletHoldNotice,
            Self::PublicHoldNotice,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeReplayManifest => "runtime_replay_manifest",
            Self::CircuitBreaker => "circuit_breaker",
            Self::ReplayTranscript => "replay_transcript",
            Self::FreshnessWindow => "freshness_window",
            Self::ReviewerQuorum => "reviewer_quorum",
            Self::OperatorAcknowledgement => "operator_acknowledgement",
            Self::WalletHoldNotice => "wallet_hold_notice",
            Self::PublicHoldNotice => "public_hold_notice",
        }
    }

    pub fn release_weight(self) -> u64 {
        1
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceStatus {
    Go,
    MissingRoot,
    RootMismatch,
    Stale,
    ReviewerPending,
    OperatorUnacknowledged,
    WalletNoticeMissing,
    PublicNoticeMissing,
}

impl GovernanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::MissingRoot => "missing_root",
            Self::RootMismatch => "root_mismatch",
            Self::Stale => "stale",
            Self::ReviewerPending => "reviewer_pending",
            Self::OperatorUnacknowledged => "operator_unacknowledged",
            Self::WalletNoticeMissing => "wallet_notice_missing",
            Self::PublicNoticeMissing => "public_notice_missing",
        }
    }

    pub fn permits_go(self) -> bool {
        matches!(self, Self::Go)
    }

    pub fn requires_hold(self) -> bool {
        !self.permits_go()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoNoGoVerdict {
    Go,
    NoGoFailClosed,
    NoGoReplayRootMissing,
    NoGoCircuitBreaker,
    NoGoTranscriptMissing,
    NoGoFreshness,
    NoGoReviewerQuorum,
    NoGoOperatorAck,
    NoGoWalletPublicNotice,
}

impl GoNoGoVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Go => "go",
            Self::NoGoFailClosed => "no_go_fail_closed",
            Self::NoGoReplayRootMissing => "no_go_replay_root_missing",
            Self::NoGoCircuitBreaker => "no_go_circuit_breaker",
            Self::NoGoTranscriptMissing => "no_go_transcript_missing",
            Self::NoGoFreshness => "no_go_freshness",
            Self::NoGoReviewerQuorum => "no_go_reviewer_quorum",
            Self::NoGoOperatorAck => "no_go_operator_ack",
            Self::NoGoWalletPublicNotice => "no_go_wallet_public_notice",
        }
    }

    pub fn production_go(self) -> bool {
        matches!(self, Self::Go)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceRoots {
    pub replay_enforcement_root: String,
    pub circuit_breaker_root: String,
    pub replay_transcript_root: String,
    pub freshness_root: String,
    pub reviewer_root: String,
    pub operator_acknowledgement_root: String,
    pub wallet_hold_notice_root: String,
    pub public_hold_notice_root: String,
    pub release_manifest_root: String,
    pub fail_closed_bus_root: String,
}

impl SourceRoots {
    pub fn devnet(config: &Config) -> Self {
        Self {
            replay_enforcement_root: deterministic_root(
                "replay-enforcement-root",
                &config.release_manifest_id,
            ),
            circuit_breaker_root: deterministic_root(
                "circuit-breaker-root",
                &config.force_exit_package_id,
            ),
            replay_transcript_root: deterministic_root(
                "replay-transcript-root",
                &config.vertical_slice_id,
            ),
            freshness_root: deterministic_root("freshness-root", "freshness-window-accepted"),
            reviewer_root: deterministic_root("reviewer-root", "reviewer-quorum-accepted"),
            operator_acknowledgement_root: deterministic_root(
                "operator-acknowledgement-root",
                "operator-acknowledged-runtime-replay-release",
            ),
            wallet_hold_notice_root: deterministic_root(
                "wallet-hold-notice-root",
                "wallets-notified-of-fail-closed-release-holds",
            ),
            public_hold_notice_root: deterministic_root(
                "public-hold-notice-root",
                "public-status-page-hold-notice-published",
            ),
            release_manifest_root: deterministic_root(
                "release-manifest-root",
                &config.release_manifest_id,
            ),
            fail_closed_bus_root: deterministic_root(
                "fail-closed-bus-root",
                "fail-closed-go-no-go-record-bus",
            ),
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }

    pub fn state_root(&self) -> String {
        record_root("source_roots", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceBindingRecord {
    pub record_id: String,
    pub track: GovernanceTrack,
    pub expected_root: String,
    pub observed_root: String,
    pub binding_root: String,
    pub reviewer_commitment: String,
    pub operator_acknowledged: bool,
    pub wallet_notice_published: bool,
    pub public_notice_published: bool,
    pub l2_delta: u64,
    pub monero_delta: u64,
    pub release_weight: u64,
    pub status: GovernanceStatus,
    pub verdict: GoNoGoVerdict,
    pub hold_reason: String,
}

impl GovernanceBindingRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config,
        source_roots: &SourceRoots,
        track: GovernanceTrack,
        observed_root: &str,
        reviewer_commitment: &str,
        operator_acknowledged: bool,
        wallet_notice_published: bool,
        public_notice_published: bool,
        l2_delta: u64,
        monero_delta: u64,
    ) -> Self {
        let expected_root = expected_track_root(config, source_roots, track);
        let status = classify_governance_status(
            config,
            track,
            &expected_root,
            observed_root,
            reviewer_commitment,
            operator_acknowledged,
            wallet_notice_published,
            public_notice_published,
            l2_delta,
            monero_delta,
        );
        let verdict = verdict_for_status(track, status);
        let hold_reason = hold_reason(track, status);
        let binding_root = governance_binding_root(
            config,
            source_roots,
            track,
            &expected_root,
            observed_root,
            status,
        );
        let record_id = governance_record_id(
            track,
            &expected_root,
            observed_root,
            &binding_root,
            reviewer_commitment,
            status,
            verdict,
        );
        Self {
            record_id,
            track,
            expected_root,
            observed_root: observed_root.to_string(),
            binding_root,
            reviewer_commitment: reviewer_commitment.to_string(),
            operator_acknowledged,
            wallet_notice_published,
            public_notice_published,
            l2_delta,
            monero_delta,
            release_weight: track.release_weight(),
            status,
            verdict,
            hold_reason,
        }
    }

    pub fn permits_go(&self) -> bool {
        self.status.permits_go() && self.verdict.production_go()
    }

    pub fn fail_closed(&self) -> bool {
        !self.permits_go()
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!(self);
        if let Some(object) = record.as_object_mut() {
            object.insert("permits_go".to_string(), Value::from(self.permits_go()));
            object.insert("fail_closed".to_string(), Value::from(self.fail_closed()));
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailClosedGoNoGoRecord {
    pub fail_closed_id: String,
    pub source_record_id: String,
    pub track: GovernanceTrack,
    pub verdict: GoNoGoVerdict,
    pub status: GovernanceStatus,
    pub hold_reason: String,
    pub wallet_notice_root: String,
    pub public_notice_root: String,
    pub fail_closed_root: String,
}

impl FailClosedGoNoGoRecord {
    pub fn from_binding(
        config: &Config,
        source_roots: &SourceRoots,
        binding: &GovernanceBindingRecord,
    ) -> Option<Self> {
        if binding.permits_go() {
            return None;
        }
        let fail_closed_root = fail_closed_root(config, source_roots, binding);
        let fail_closed_id = fail_closed_id(binding, &fail_closed_root);
        Some(Self {
            fail_closed_id,
            source_record_id: binding.record_id.clone(),
            track: binding.track,
            verdict: binding.verdict,
            status: binding.status,
            hold_reason: binding.hold_reason.clone(),
            wallet_notice_root: source_roots.wallet_hold_notice_root.clone(),
            public_notice_root: source_roots.public_hold_notice_root.clone(),
            fail_closed_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub total_records: u64,
    pub go_records: u64,
    pub no_go_records: u64,
    pub hold_records: u64,
    pub fail_closed_records: u64,
    pub reviewer_quorum_count: u64,
    pub operator_acknowledged_count: u64,
    pub wallet_notice_count: u64,
    pub public_notice_count: u64,
    pub stale_records: u64,
    pub root_mismatch_records: u64,
    pub release_weight_go: u64,
    pub release_weight_no_go: u64,
}

impl Counters {
    pub fn from_records(records: &[GovernanceBindingRecord]) -> Self {
        let total_records = records.len() as u64;
        let go_records = records.iter().filter(|record| record.permits_go()).count() as u64;
        let no_go_records = total_records.saturating_sub(go_records);
        let hold_records = records
            .iter()
            .filter(|record| record.status.requires_hold())
            .count() as u64;
        let fail_closed_records =
            records.iter().filter(|record| record.fail_closed()).count() as u64;
        let reviewer_quorum_count = records
            .iter()
            .filter(|record| !record.reviewer_commitment.is_empty())
            .count() as u64;
        let operator_acknowledged_count = records
            .iter()
            .filter(|record| record.operator_acknowledged)
            .count() as u64;
        let wallet_notice_count = records
            .iter()
            .filter(|record| record.wallet_notice_published)
            .count() as u64;
        let public_notice_count = records
            .iter()
            .filter(|record| record.public_notice_published)
            .count() as u64;
        let stale_records = records
            .iter()
            .filter(|record| record.status == GovernanceStatus::Stale)
            .count() as u64;
        let root_mismatch_records = records
            .iter()
            .filter(|record| record.status == GovernanceStatus::RootMismatch)
            .count() as u64;
        let release_weight_go = records
            .iter()
            .filter(|record| record.permits_go())
            .map(|record| record.release_weight)
            .sum();
        let release_weight_no_go = records
            .iter()
            .filter(|record| !record.permits_go())
            .map(|record| record.release_weight)
            .sum();
        Self {
            total_records,
            go_records,
            no_go_records,
            hold_records,
            fail_closed_records,
            reviewer_quorum_count,
            operator_acknowledged_count,
            wallet_notice_count,
            public_notice_count,
            stale_records,
            root_mismatch_records,
            release_weight_go,
            release_weight_no_go,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GovernanceDecision {
    pub decision_id: String,
    pub verdict: GoNoGoVerdict,
    pub production_go: bool,
    pub production_hold: bool,
    pub fail_closed: bool,
    pub reason_root: String,
    pub binding_record_root: String,
    pub fail_closed_record_root: String,
    pub counters_root: String,
}

impl GovernanceDecision {
    pub fn evaluate(
        config: &Config,
        records: &[GovernanceBindingRecord],
        fail_closed_records: &[FailClosedGoNoGoRecord],
        counters: &Counters,
    ) -> Self {
        let record_values = records
            .iter()
            .map(GovernanceBindingRecord::public_record)
            .collect::<Vec<_>>();
        let fail_closed_values = fail_closed_records
            .iter()
            .map(FailClosedGoNoGoRecord::public_record)
            .collect::<Vec<_>>();
        let binding_record_root = merkle_root("GOVERNANCE-BINDING-RECORD", &record_values);
        let fail_closed_record_root = merkle_root(
            "GOVERNANCE-FAIL-CLOSED-GO-NO-GO-RECORD",
            &fail_closed_values,
        );
        let counters_root = record_root("counters", &counters.public_record());
        let enough_go = counters.go_records >= config.min_go_records;
        let enough_reviewers = counters.reviewer_quorum_count >= config.min_reviewer_quorum;
        let allowed_holds = counters.hold_records <= config.max_allowed_holds;
        let fail_closed = config.fail_closed_on_any_violation
            && (!enough_go || !enough_reviewers || !allowed_holds || counters.no_go_records > 0);
        let verdict = if !enough_go {
            GoNoGoVerdict::NoGoReplayRootMissing
        } else if !enough_reviewers {
            GoNoGoVerdict::NoGoReviewerQuorum
        } else if !allowed_holds {
            GoNoGoVerdict::NoGoFailClosed
        } else if counters.no_go_records > 0 {
            GoNoGoVerdict::NoGoFailClosed
        } else {
            GoNoGoVerdict::Go
        };
        let production_go = verdict.production_go() && !fail_closed;
        let production_hold = !production_go;
        let reason_root = governance_reason_root(config, counters, verdict, fail_closed);
        let decision_id = governance_decision_id(
            &binding_record_root,
            &fail_closed_record_root,
            &counters_root,
            &reason_root,
            verdict,
            production_go,
        );
        Self {
            decision_id,
            verdict,
            production_go,
            production_hold,
            fail_closed,
            reason_root,
            binding_record_root,
            fail_closed_record_root,
            counters_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub source_root: String,
    pub binding_record_root: String,
    pub fail_closed_record_root: String,
    pub go_record_root: String,
    pub no_go_record_root: String,
    pub wallet_public_notice_root: String,
    pub counters_root: String,
    pub decision_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn compute(
        config: &Config,
        source_roots: &SourceRoots,
        records: &[GovernanceBindingRecord],
        fail_closed_records: &[FailClosedGoNoGoRecord],
        counters: &Counters,
        decision: &GovernanceDecision,
    ) -> Self {
        let binding_records = records
            .iter()
            .map(GovernanceBindingRecord::public_record)
            .collect::<Vec<_>>();
        let fail_closed_values = fail_closed_records
            .iter()
            .map(FailClosedGoNoGoRecord::public_record)
            .collect::<Vec<_>>();
        let go_records = records
            .iter()
            .filter(|record| record.permits_go())
            .map(GovernanceBindingRecord::public_record)
            .collect::<Vec<_>>();
        let no_go_records = records
            .iter()
            .filter(|record| !record.permits_go())
            .map(GovernanceBindingRecord::public_record)
            .collect::<Vec<_>>();
        let notice_records = fail_closed_records
            .iter()
            .map(|record| {
                json!({
                    "track": record.track.as_str(),
                    "wallet_notice_root": record.wallet_notice_root,
                    "public_notice_root": record.public_notice_root,
                    "fail_closed_root": record.fail_closed_root,
                })
            })
            .collect::<Vec<_>>();
        let config_root = config.state_root();
        let source_root = source_roots.state_root();
        let binding_record_root = merkle_root("GOVERNANCE-BINDING-RECORD", &binding_records);
        let fail_closed_record_root = merkle_root(
            "GOVERNANCE-FAIL-CLOSED-GO-NO-GO-RECORD",
            &fail_closed_values,
        );
        let go_record_root = merkle_root("GOVERNANCE-GO-RECORD", &go_records);
        let no_go_record_root = merkle_root("GOVERNANCE-NO-GO-RECORD", &no_go_records);
        let wallet_public_notice_root =
            merkle_root("GOVERNANCE-WALLET-PUBLIC-HOLD-NOTICE", &notice_records);
        let counters_root = record_root("counters", &counters.public_record());
        let decision_root = record_root("decision", &decision.public_record());
        let state_root = domain_hash(
            "MONERO-RUNTIME-REPLAY-GO-NO-GO-GOVERNANCE-BINDING-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&source_root),
                HashPart::Str(&binding_record_root),
                HashPart::Str(&fail_closed_record_root),
                HashPart::Str(&go_record_root),
                HashPart::Str(&no_go_record_root),
                HashPart::Str(&wallet_public_notice_root),
                HashPart::Str(&counters_root),
                HashPart::Str(&decision_root),
            ],
            32,
        );
        Self {
            config_root,
            source_root,
            binding_record_root,
            fail_closed_record_root,
            go_record_root,
            no_go_record_root,
            wallet_public_notice_root,
            counters_root,
            decision_root,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub source_roots: SourceRoots,
    pub binding_records: Vec<GovernanceBindingRecord>,
    pub fail_closed_records: Vec<FailClosedGoNoGoRecord>,
    pub counters: Counters,
    pub decision: GovernanceDecision,
    pub roots: Roots,
}

impl State {
    pub fn new(
        config: Config,
        source_roots: SourceRoots,
        binding_records: Vec<GovernanceBindingRecord>,
    ) -> Self {
        let fail_closed_records = binding_records
            .iter()
            .filter_map(|record| {
                FailClosedGoNoGoRecord::from_binding(&config, &source_roots, record)
            })
            .collect::<Vec<_>>();
        let counters = Counters::from_records(&binding_records);
        let decision = GovernanceDecision::evaluate(
            &config,
            &binding_records,
            &fail_closed_records,
            &counters,
        );
        let roots = Roots::compute(
            &config,
            &source_roots,
            &binding_records,
            &fail_closed_records,
            &counters,
            &decision,
        );
        Self {
            config,
            source_roots,
            binding_records,
            fail_closed_records,
            counters,
            decision,
            roots,
        }
    }

    pub fn devnet() -> Self {
        let config = Config::devnet();
        let source_roots = SourceRoots::devnet(&config);
        let binding_records = devnet_binding_records(&config, &source_roots);
        Self::new(config, source_roots, binding_records)
    }

    pub fn go(&self) -> bool {
        self.decision.production_go
    }

    pub fn no_go(&self) -> bool {
        self.decision.production_hold
    }

    pub fn public_record(&self) -> Value {
        let mut record = json!(self);
        if let Some(object) = record.as_object_mut() {
            object.insert("go".to_string(), Value::from(self.go()));
            object.insert("no_go".to_string(), Value::from(self.no_go()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
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

fn devnet_binding_records(
    config: &Config,
    source_roots: &SourceRoots,
) -> Vec<GovernanceBindingRecord> {
    GovernanceTrack::ordered()
        .iter()
        .map(|track| {
            let observed_root = expected_track_root(config, source_roots, *track);
            GovernanceBindingRecord::new(
                config,
                source_roots,
                *track,
                &observed_root,
                &reviewer_commitment(*track),
                true,
                true,
                true,
                track_l2_delta(*track),
                track_monero_delta(*track),
            )
        })
        .collect()
}

fn classify_governance_status(
    config: &Config,
    track: GovernanceTrack,
    expected_root: &str,
    observed_root: &str,
    reviewer_commitment: &str,
    operator_acknowledged: bool,
    wallet_notice_published: bool,
    public_notice_published: bool,
    l2_delta: u64,
    monero_delta: u64,
) -> GovernanceStatus {
    if observed_root.is_empty() {
        return GovernanceStatus::MissingRoot;
    }
    if expected_root != observed_root {
        return GovernanceStatus::RootMismatch;
    }
    if l2_delta > config.max_l2_freshness_delta || monero_delta > config.max_monero_freshness_delta
    {
        return GovernanceStatus::Stale;
    }
    if config.require_reviewer_root && reviewer_commitment.is_empty() {
        return GovernanceStatus::ReviewerPending;
    }
    if config.require_operator_acknowledgement
        && matches!(track, GovernanceTrack::OperatorAcknowledgement)
        && !operator_acknowledged
    {
        return GovernanceStatus::OperatorUnacknowledged;
    }
    if config.require_wallet_public_hold_notices
        && matches!(track, GovernanceTrack::WalletHoldNotice)
        && !wallet_notice_published
    {
        return GovernanceStatus::WalletNoticeMissing;
    }
    if config.require_wallet_public_hold_notices
        && matches!(track, GovernanceTrack::PublicHoldNotice)
        && !public_notice_published
    {
        return GovernanceStatus::PublicNoticeMissing;
    }
    GovernanceStatus::Go
}

fn verdict_for_status(track: GovernanceTrack, status: GovernanceStatus) -> GoNoGoVerdict {
    match status {
        GovernanceStatus::Go => GoNoGoVerdict::Go,
        GovernanceStatus::MissingRoot => match track {
            GovernanceTrack::RuntimeReplayManifest => GoNoGoVerdict::NoGoReplayRootMissing,
            GovernanceTrack::ReplayTranscript => GoNoGoVerdict::NoGoTranscriptMissing,
            _ => GoNoGoVerdict::NoGoFailClosed,
        },
        GovernanceStatus::RootMismatch => GoNoGoVerdict::NoGoFailClosed,
        GovernanceStatus::Stale => GoNoGoVerdict::NoGoFreshness,
        GovernanceStatus::ReviewerPending => GoNoGoVerdict::NoGoReviewerQuorum,
        GovernanceStatus::OperatorUnacknowledged => GoNoGoVerdict::NoGoOperatorAck,
        GovernanceStatus::WalletNoticeMissing | GovernanceStatus::PublicNoticeMissing => {
            GoNoGoVerdict::NoGoWalletPublicNotice
        }
    }
}

fn hold_reason(track: GovernanceTrack, status: GovernanceStatus) -> String {
    match status {
        GovernanceStatus::Go => "governance binding accepted for final go record".to_string(),
        GovernanceStatus::MissingRoot => {
            format!("{} required root is missing", track.as_str())
        }
        GovernanceStatus::RootMismatch => {
            format!(
                "{} observed root does not match expected root",
                track.as_str()
            )
        }
        GovernanceStatus::Stale => {
            format!(
                "{} freshness window exceeds configured final-go bound",
                track.as_str()
            )
        }
        GovernanceStatus::ReviewerPending => {
            format!(
                "{} reviewer quorum root is not acknowledged",
                track.as_str()
            )
        }
        GovernanceStatus::OperatorUnacknowledged => {
            "operator acknowledgement is required before final governance go".to_string()
        }
        GovernanceStatus::WalletNoticeMissing => {
            "wallet hold notice must be published before fail-closed no-go".to_string()
        }
        GovernanceStatus::PublicNoticeMissing => {
            "public hold notice must be published before fail-closed no-go".to_string()
        }
    }
}

fn expected_track_root(
    config: &Config,
    source_roots: &SourceRoots,
    track: GovernanceTrack,
) -> String {
    let source_root = match track {
        GovernanceTrack::RuntimeReplayManifest => &source_roots.replay_enforcement_root,
        GovernanceTrack::CircuitBreaker => &source_roots.circuit_breaker_root,
        GovernanceTrack::ReplayTranscript => &source_roots.replay_transcript_root,
        GovernanceTrack::FreshnessWindow => &source_roots.freshness_root,
        GovernanceTrack::ReviewerQuorum => &source_roots.reviewer_root,
        GovernanceTrack::OperatorAcknowledgement => &source_roots.operator_acknowledgement_root,
        GovernanceTrack::WalletHoldNotice => &source_roots.wallet_hold_notice_root,
        GovernanceTrack::PublicHoldNotice => &source_roots.public_hold_notice_root,
    };
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-EXPECTED-TRACK-ROOT",
        &[
            HashPart::Str(&config.release_manifest_id),
            HashPart::Str(&config.force_exit_package_id),
            HashPart::Str(track.as_str()),
            HashPart::Str(source_root),
            HashPart::U64(config.governance_round),
        ],
        32,
    )
}

fn governance_binding_root(
    config: &Config,
    source_roots: &SourceRoots,
    track: GovernanceTrack,
    expected_root: &str,
    observed_root: &str,
    status: GovernanceStatus,
) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-GOVERNANCE-BINDING-ROOT",
        &[
            HashPart::Str(&config.release_manifest_id),
            HashPart::Str(&source_roots.release_manifest_root),
            HashPart::Str(track.as_str()),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(status.as_str()),
        ],
        32,
    )
}

fn governance_record_id(
    track: GovernanceTrack,
    expected_root: &str,
    observed_root: &str,
    binding_root: &str,
    reviewer_commitment: &str,
    status: GovernanceStatus,
    verdict: GoNoGoVerdict,
) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-GOVERNANCE-RECORD-ID",
        &[
            HashPart::Str(track.as_str()),
            HashPart::Str(expected_root),
            HashPart::Str(observed_root),
            HashPart::Str(binding_root),
            HashPart::Str(reviewer_commitment),
            HashPart::Str(status.as_str()),
            HashPart::Str(verdict.as_str()),
        ],
        24,
    )
}

fn fail_closed_root(
    config: &Config,
    source_roots: &SourceRoots,
    binding: &GovernanceBindingRecord,
) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-FAIL-CLOSED-ROOT",
        &[
            HashPart::Str(&config.release_manifest_id),
            HashPart::Str(&source_roots.fail_closed_bus_root),
            HashPart::Str(binding.track.as_str()),
            HashPart::Str(&binding.record_id),
            HashPart::Str(binding.status.as_str()),
            HashPart::Str(binding.verdict.as_str()),
            HashPart::Str(&binding.hold_reason),
        ],
        32,
    )
}

fn fail_closed_id(binding: &GovernanceBindingRecord, fail_closed_root: &str) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-FAIL-CLOSED-ID",
        &[
            HashPart::Str(binding.track.as_str()),
            HashPart::Str(&binding.record_id),
            HashPart::Str(binding.verdict.as_str()),
            HashPart::Str(fail_closed_root),
        ],
        24,
    )
}

fn governance_reason_root(
    config: &Config,
    counters: &Counters,
    verdict: GoNoGoVerdict,
    fail_closed: bool,
) -> String {
    let counter_record = counters.public_record();
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-GOVERNANCE-REASON-ROOT",
        &[
            HashPart::Str(&config.release_manifest_id),
            HashPart::U64(config.governance_round),
            HashPart::Json(&counter_record),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(if fail_closed { "fail_closed" } else { "open" }),
        ],
        32,
    )
}

fn governance_decision_id(
    binding_record_root: &str,
    fail_closed_record_root: &str,
    counters_root: &str,
    reason_root: &str,
    verdict: GoNoGoVerdict,
    production_go: bool,
) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-GOVERNANCE-DECISION-ID",
        &[
            HashPart::Str(binding_record_root),
            HashPart::Str(fail_closed_record_root),
            HashPart::Str(counters_root),
            HashPart::Str(reason_root),
            HashPart::Str(verdict.as_str()),
            HashPart::Str(if production_go { "go" } else { "no_go" }),
        ],
        32,
    )
}

fn reviewer_commitment(track: GovernanceTrack) -> String {
    deterministic_root("reviewer-commitment", track.as_str())
}

fn track_l2_delta(track: GovernanceTrack) -> u64 {
    1 + track as u64 % 3
}

fn track_monero_delta(track: GovernanceTrack) -> u64 {
    1 + track as u64 % 2
}

fn deterministic_root(label: &str, seed: &str) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-DETERMINISTIC-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Str(seed),
        ],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-RUNTIME-REPLAY-GO-NO-GO-RECORD-ROOT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(label),
            HashPart::Json(record),
        ],
        32,
    )
}
