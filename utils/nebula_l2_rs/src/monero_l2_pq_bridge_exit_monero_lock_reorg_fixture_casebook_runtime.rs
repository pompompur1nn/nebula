use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitMoneroLockReorgFixtureCasebookRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_MONERO_LOCK_REORG_FIXTURE_CASEBOOK_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-monero-lock-reorg-fixture-casebook-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_MONERO_LOCK_REORG_FIXTURE_CASEBOOK_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const CASEBOOK_SUITE: &str = "monero-l2-pq-bridge-exit-monero-lock-reorg-fixture-casebook-v1";
pub const DEFAULT_MIN_LOCK_CONFIRMATIONS: u64 = 10;
pub const DEFAULT_DEEP_FINALITY_CONFIRMATIONS: u64 = 60;
pub const DEFAULT_REORG_CHALLENGE_DEPTH: u64 = 20;
pub const DEFAULT_MIN_WATCHER_QUORUM: u64 = 3;
pub const DEFAULT_MAX_METADATA_LINKAGE_BPS: u64 = 25;
pub const DEFAULT_MIN_LIQUIDITY_RESERVE_BPS: u64 = 1_100;
pub const DEFAULT_MAX_CASES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseCategory {
    AcceptedLock,
    AcceptedFinality,
    AcceptedHeader,
    AcceptedReorgProof,
    AcceptedWatcherQuorum,
    RejectedLock,
    RejectedFinality,
    RejectedHeader,
    RejectedReorgProof,
    RejectedWatcherClaim,
    PrivacyConstraint,
    BaseLayerVerifierAssumption,
    LiquidityReserveWatch,
    DepositFailClosed,
    ExitFailClosed,
}

impl CaseCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedLock => "accepted_lock",
            Self::AcceptedFinality => "accepted_finality",
            Self::AcceptedHeader => "accepted_header",
            Self::AcceptedReorgProof => "accepted_reorg_proof",
            Self::AcceptedWatcherQuorum => "accepted_watcher_quorum",
            Self::RejectedLock => "rejected_lock",
            Self::RejectedFinality => "rejected_finality",
            Self::RejectedHeader => "rejected_header",
            Self::RejectedReorgProof => "rejected_reorg_proof",
            Self::RejectedWatcherClaim => "rejected_watcher_claim",
            Self::PrivacyConstraint => "privacy_constraint",
            Self::BaseLayerVerifierAssumption => "base_layer_verifier_assumption",
            Self::LiquidityReserveWatch => "liquidity_reserve_watch",
            Self::DepositFailClosed => "deposit_fail_closed",
            Self::ExitFailClosed => "exit_fail_closed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Accepted,
    Rejected,
    Deferred,
    Blocked,
}

impl CaseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Deferred => "deferred",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalityDepth {
    None,
    Shallow,
    Deep,
}

impl FinalityDepth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Shallow => "shallow",
            Self::Deep => "deep",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReorgProofKind {
    None,
    OrphanHeader,
    CompetingTip,
    DepthExceeded,
    HeaderContinuityBreak,
}

impl ReorgProofKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OrphanHeader => "orphan_header",
            Self::CompetingTip => "competing_tip",
            Self::DepthExceeded => "depth_exceeded",
            Self::HeaderContinuityBreak => "header_continuity_break",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySurface {
    ViewKey,
    Amount,
    Timing,
    OutputIndex,
    WatcherPayload,
}

impl PrivacySurface {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewKey => "view_key",
            Self::Amount => "amount",
            Self::Timing => "timing",
            Self::OutputIndex => "output_index",
            Self::WatcherPayload => "watcher_payload",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailClosedOutcome {
    DepositHeld,
    ExitHeld,
    ReserveHeld,
    ChallengeOpened,
    WatcherSlashQueued,
}

impl FailClosedOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositHeld => "deposit_held",
            Self::ExitHeld => "exit_held",
            Self::ReserveHeld => "reserve_held",
            Self::ChallengeOpened => "challenge_opened",
            Self::WatcherSlashQueued => "watcher_slash_queued",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub casebook_suite: String,
    pub min_lock_confirmations: u64,
    pub deep_finality_confirmations: u64,
    pub reorg_challenge_depth: u64,
    pub min_watcher_quorum: u64,
    pub max_metadata_linkage_bps: u64,
    pub min_liquidity_reserve_bps: u64,
    pub base_layer_verifier_enabled: bool,
    pub redacted_public_record_required: bool,
    pub fail_closed_required: bool,
    pub production_release_allowed: bool,
    pub max_cases: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            casebook_suite: CASEBOOK_SUITE.to_string(),
            min_lock_confirmations: DEFAULT_MIN_LOCK_CONFIRMATIONS,
            deep_finality_confirmations: DEFAULT_DEEP_FINALITY_CONFIRMATIONS,
            reorg_challenge_depth: DEFAULT_REORG_CHALLENGE_DEPTH,
            min_watcher_quorum: DEFAULT_MIN_WATCHER_QUORUM,
            max_metadata_linkage_bps: DEFAULT_MAX_METADATA_LINKAGE_BPS,
            min_liquidity_reserve_bps: DEFAULT_MIN_LIQUIDITY_RESERVE_BPS,
            base_layer_verifier_enabled: false,
            redacted_public_record_required: true,
            fail_closed_required: true,
            production_release_allowed: false,
            max_cases: DEFAULT_MAX_CASES,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "casebook_suite": self.casebook_suite,
            "min_lock_confirmations": self.min_lock_confirmations,
            "deep_finality_confirmations": self.deep_finality_confirmations,
            "reorg_challenge_depth": self.reorg_challenge_depth,
            "min_watcher_quorum": self.min_watcher_quorum,
            "max_metadata_linkage_bps": self.max_metadata_linkage_bps,
            "min_liquidity_reserve_bps": self.min_liquidity_reserve_bps,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "redacted_public_record_required": self.redacted_public_record_required,
            "fail_closed_required": self.fail_closed_required,
            "production_release_allowed": self.production_release_allowed,
            "max_cases": self.max_cases,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureCase {
    pub case_id: String,
    pub category: CaseCategory,
    pub status: CaseStatus,
    pub finality_depth: FinalityDepth,
    pub reorg_proof_kind: ReorgProofKind,
    pub subject_id: String,
    pub monero_height: u64,
    pub confirmations: u64,
    pub reorg_depth: u64,
    pub watcher_count: u64,
    pub header_hash: String,
    pub previous_header_hash: String,
    pub canonical_tip_root: String,
    pub orphan_root: String,
    pub lock_commitment_root: String,
    pub nullifier_commitment_root: String,
    pub privacy_surface: String,
    pub metadata_policy: String,
    pub expected_outcome: FailClosedOutcome,
    pub remediation_hint: String,
    pub evidence_root: String,
}

impl FixtureCase {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: &Config,
        category: CaseCategory,
        status: CaseStatus,
        finality_depth: FinalityDepth,
        reorg_proof_kind: ReorgProofKind,
        subject_id: &str,
        ordinal: u64,
        confirmations: u64,
        reorg_depth: u64,
        watcher_count: u64,
        expected_outcome: FailClosedOutcome,
        remediation_hint: &str,
    ) -> Self {
        let monero_height = 3_600_000 + ordinal;
        let header_hash = labeled_hash(category.as_str(), subject_id, ordinal);
        let previous_header_hash = labeled_hash("previous-header", subject_id, ordinal);
        let canonical_tip_root =
            canonical_tip_root(&header_hash, monero_height, confirmations, watcher_count);
        let orphan_root = orphan_root(reorg_proof_kind, &header_hash, reorg_depth);
        let lock_commitment_root = labeled_hash("lock-commitment", subject_id, ordinal);
        let nullifier_commitment_root = labeled_hash("nullifier-commitment", subject_id, ordinal);
        let privacy_surface = privacy_surface_for(category).as_str().to_string();
        let metadata_policy = metadata_policy_for(category, status).to_string();
        let evidence_root = fixture_case_evidence_root(
            category,
            status,
            finality_depth,
            reorg_proof_kind,
            subject_id,
            monero_height,
            confirmations,
            reorg_depth,
            watcher_count,
            &canonical_tip_root,
            &orphan_root,
            expected_outcome,
            remediation_hint,
        );
        let case_id = fixture_case_id(category, subject_id, &evidence_root, config.schema_version);
        Self {
            case_id,
            category,
            status,
            finality_depth,
            reorg_proof_kind,
            subject_id: subject_id.to_string(),
            monero_height,
            confirmations,
            reorg_depth,
            watcher_count,
            header_hash,
            previous_header_hash,
            canonical_tip_root,
            orphan_root,
            lock_commitment_root,
            nullifier_commitment_root,
            privacy_surface,
            metadata_policy,
            expected_outcome,
            remediation_hint: remediation_hint.to_string(),
            evidence_root,
        }
    }

    pub fn redacted_record(&self) -> Value {
        json!({
            "case_id": self.case_id,
            "category": self.category.as_str(),
            "status": self.status.as_str(),
            "finality_depth": self.finality_depth.as_str(),
            "reorg_proof_kind": self.reorg_proof_kind.as_str(),
            "subject_commitment": redacted_subject_id(&self.subject_id),
            "monero_height": self.monero_height,
            "confirmations": self.confirmations,
            "reorg_depth": self.reorg_depth,
            "watcher_count": self.watcher_count,
            "header_hash": self.header_hash,
            "previous_header_hash": self.previous_header_hash,
            "canonical_tip_root": self.canonical_tip_root,
            "orphan_root": self.orphan_root,
            "lock_commitment_root": self.lock_commitment_root,
            "nullifier_commitment_root": self.nullifier_commitment_root,
            "privacy_surface": self.privacy_surface,
            "metadata_policy": self.metadata_policy,
            "expected_outcome": self.expected_outcome.as_str(),
            "remediation_hint": self.remediation_hint,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("fixture_case", &self.redacted_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyConstraint {
    pub constraint_id: String,
    pub surface: PrivacySurface,
    pub enforced: bool,
    pub max_linkage_bps: u64,
    pub public_value_policy: String,
    pub sealed_payload_root: String,
    pub remediation_hint: String,
    pub constraint_root: String,
}

impl PrivacyConstraint {
    pub fn new(
        surface: PrivacySurface,
        enforced: bool,
        max_linkage_bps: u64,
        public_value_policy: &str,
        remediation_hint: &str,
        ordinal: u64,
    ) -> Self {
        let sealed_payload_root = labeled_hash(surface.as_str(), "sealed-payload", ordinal);
        let constraint_root = domain_hash(
            "MONERO-LOCK-REORG-CASEBOOK-PRIVACY-CONSTRAINT",
            &[
                HashPart::Str(surface.as_str()),
                HashPart::Str(bool_str(enforced)),
                HashPart::U64(max_linkage_bps),
                HashPart::Str(public_value_policy),
                HashPart::Str(&sealed_payload_root),
                HashPart::Str(remediation_hint),
            ],
            32,
        );
        let constraint_id = domain_hash(
            "MONERO-LOCK-REORG-CASEBOOK-PRIVACY-CONSTRAINT-ID",
            &[
                HashPart::Str(surface.as_str()),
                HashPart::Str(&constraint_root),
            ],
            32,
        );
        Self {
            constraint_id,
            surface,
            enforced,
            max_linkage_bps,
            public_value_policy: public_value_policy.to_string(),
            sealed_payload_root,
            remediation_hint: remediation_hint.to_string(),
            constraint_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "constraint_id": self.constraint_id,
            "surface": self.surface.as_str(),
            "enforced": self.enforced,
            "max_linkage_bps": self.max_linkage_bps,
            "public_value_policy": self.public_value_policy,
            "sealed_payload_root": self.sealed_payload_root,
            "remediation_hint": self.remediation_hint,
            "constraint_root": self.constraint_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LiquidityReserveWatch {
    pub watch_id: String,
    pub reserve_status: String,
    pub required_reserve_bps: u64,
    pub observed_reserve_bps: u64,
    pub pending_deposit_count: u64,
    pub pending_exit_count: u64,
    pub reorg_hold_count: u64,
    pub release_window_blocks: u64,
    pub expected_outcome: FailClosedOutcome,
    pub remediation_hint: String,
    pub watch_root: String,
}

impl LiquidityReserveWatch {
    pub fn new(
        config: &Config,
        reserve_status: &str,
        observed_reserve_bps: u64,
        pending_deposit_count: u64,
        pending_exit_count: u64,
        reorg_hold_count: u64,
        ordinal: u64,
    ) -> Self {
        let expected_outcome = if observed_reserve_bps >= config.min_liquidity_reserve_bps {
            FailClosedOutcome::ReserveHeld
        } else {
            FailClosedOutcome::ExitHeld
        };
        let release_window_blocks = config.reorg_challenge_depth + ordinal;
        let remediation_hint = if observed_reserve_bps >= config.min_liquidity_reserve_bps {
            "keep reserve release behind finality and watcher quorum"
        } else {
            "pause exits until reserve proof and reorg window reconcile"
        };
        let watch_root = domain_hash(
            "MONERO-LOCK-REORG-CASEBOOK-LIQUIDITY-WATCH",
            &[
                HashPart::Str(reserve_status),
                HashPart::U64(config.min_liquidity_reserve_bps),
                HashPart::U64(observed_reserve_bps),
                HashPart::U64(pending_deposit_count),
                HashPart::U64(pending_exit_count),
                HashPart::U64(reorg_hold_count),
                HashPart::U64(release_window_blocks),
                HashPart::Str(expected_outcome.as_str()),
                HashPart::Str(remediation_hint),
            ],
            32,
        );
        let watch_id = domain_hash(
            "MONERO-LOCK-REORG-CASEBOOK-LIQUIDITY-WATCH-ID",
            &[HashPart::Str(reserve_status), HashPart::Str(&watch_root)],
            32,
        );
        Self {
            watch_id,
            reserve_status: reserve_status.to_string(),
            required_reserve_bps: config.min_liquidity_reserve_bps,
            observed_reserve_bps,
            pending_deposit_count,
            pending_exit_count,
            reorg_hold_count,
            release_window_blocks,
            expected_outcome,
            remediation_hint: remediation_hint.to_string(),
            watch_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "watch_id": self.watch_id,
            "reserve_status": self.reserve_status,
            "required_reserve_bps": self.required_reserve_bps,
            "observed_reserve_bps": self.observed_reserve_bps,
            "pending_deposit_count": self.pending_deposit_count,
            "pending_exit_count": self.pending_exit_count,
            "reorg_hold_count": self.reorg_hold_count,
            "release_window_blocks": self.release_window_blocks,
            "expected_outcome": self.expected_outcome.as_str(),
            "remediation_hint": self.remediation_hint,
            "watch_root": self.watch_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CasebookReport {
    pub report_id: String,
    pub accepted_case_count: u64,
    pub rejected_case_count: u64,
    pub privacy_constraint_count: u64,
    pub liquidity_watch_count: u64,
    pub fail_closed_case_count: u64,
    pub base_layer_verifier_enabled: bool,
    pub production_release_allowed: bool,
    pub accepted_case_root: String,
    pub rejected_case_root: String,
    pub privacy_constraint_root: String,
    pub liquidity_watch_root: String,
    pub report_root: String,
    pub verdict: String,
}

impl CasebookReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "accepted_case_count": self.accepted_case_count,
            "rejected_case_count": self.rejected_case_count,
            "privacy_constraint_count": self.privacy_constraint_count,
            "liquidity_watch_count": self.liquidity_watch_count,
            "fail_closed_case_count": self.fail_closed_case_count,
            "base_layer_verifier_enabled": self.base_layer_verifier_enabled,
            "production_release_allowed": self.production_release_allowed,
            "accepted_case_root": self.accepted_case_root,
            "rejected_case_root": self.rejected_case_root,
            "privacy_constraint_root": self.privacy_constraint_root,
            "liquidity_watch_root": self.liquidity_watch_root,
            "report_root": self.report_root,
            "verdict": self.verdict,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub accepted_cases: Vec<FixtureCase>,
    pub rejected_cases: Vec<FixtureCase>,
    pub privacy_constraints: Vec<PrivacyConstraint>,
    pub liquidity_watches: Vec<LiquidityReserveWatch>,
    pub report: CasebookReport,
    pub state_root: String,
}

impl State {
    pub fn devnet() -> Self {
        Self::from_config(Config::devnet())
    }

    pub fn from_config(config: Config) -> Self {
        let accepted_cases = accepted_cases(&config);
        let rejected_cases = rejected_cases(&config);
        let privacy_constraints = privacy_constraints(&config);
        let liquidity_watches = liquidity_watches(&config);
        let accepted_case_root = merkle_from_records(
            "MONERO-LOCK-REORG-CASEBOOK-ACCEPTED",
            accepted_cases
                .iter()
                .map(FixtureCase::redacted_record)
                .collect::<Vec<_>>(),
        );
        let rejected_case_root = merkle_from_records(
            "MONERO-LOCK-REORG-CASEBOOK-REJECTED",
            rejected_cases
                .iter()
                .map(FixtureCase::redacted_record)
                .collect::<Vec<_>>(),
        );
        let privacy_constraint_root = merkle_from_records(
            "MONERO-LOCK-REORG-CASEBOOK-PRIVACY",
            privacy_constraints
                .iter()
                .map(PrivacyConstraint::public_record)
                .collect::<Vec<_>>(),
        );
        let liquidity_watch_root = merkle_from_records(
            "MONERO-LOCK-REORG-CASEBOOK-LIQUIDITY",
            liquidity_watches
                .iter()
                .map(LiquidityReserveWatch::public_record)
                .collect::<Vec<_>>(),
        );
        let report = casebook_report(
            &config,
            accepted_cases.len() as u64,
            rejected_cases.len() as u64,
            privacy_constraints.len() as u64,
            liquidity_watches.len() as u64,
            &accepted_case_root,
            &rejected_case_root,
            &privacy_constraint_root,
            &liquidity_watch_root,
        );
        let state_root = state_root_from_parts(
            &config.state_root(),
            &accepted_case_root,
            &rejected_case_root,
            &privacy_constraint_root,
            &liquidity_watch_root,
            &report.report_root,
        );
        Self {
            config,
            accepted_cases,
            rejected_cases,
            privacy_constraints,
            liquidity_watches,
            report,
            state_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "accepted_cases": self.accepted_cases.iter().map(FixtureCase::redacted_record).collect::<Vec<_>>(),
            "rejected_cases": self.rejected_cases.iter().map(FixtureCase::redacted_record).collect::<Vec<_>>(),
            "privacy_constraints": self.privacy_constraints.iter().map(PrivacyConstraint::public_record).collect::<Vec<_>>(),
            "liquidity_watches": self.liquidity_watches.iter().map(LiquidityReserveWatch::public_record).collect::<Vec<_>>(),
            "report": self.report.public_record(),
            "state_root": self.state_root,
        })
    }

    pub fn state_root(&self) -> String {
        self.state_root.clone()
    }

    pub fn accepted_by_category(&self, category: CaseCategory) -> Vec<&FixtureCase> {
        self.accepted_cases
            .iter()
            .filter(|case| case.category == category)
            .collect()
    }

    pub fn rejected_by_category(&self, category: CaseCategory) -> Vec<&FixtureCase> {
        self.rejected_cases
            .iter()
            .filter(|case| case.category == category)
            .collect()
    }

    pub fn validate_casebook(&self) -> Result<()> {
        ensure(
            self.accepted_cases.len() + self.rejected_cases.len() <= self.config.max_cases,
            "casebook exceeds configured public case limit",
        )?;
        ensure(
            self.accepted_cases
                .iter()
                .all(|case| case.status == CaseStatus::Accepted),
            "accepted case catalog contains a non-accepted fixture",
        )?;
        ensure(
            self.rejected_cases
                .iter()
                .all(|case| case.status != CaseStatus::Accepted),
            "rejected case catalog contains an accepted fixture",
        )?;
        ensure(
            self.privacy_constraints
                .iter()
                .all(|constraint| constraint.enforced),
            "privacy constraints must be enforced in public casebook records",
        )?;
        ensure(
            self.rejected_cases
                .iter()
                .all(|case| case.expected_outcome != FailClosedOutcome::WatcherSlashQueued),
            "fixture rejection must hold deposits or exits before watcher penalty flow",
        )?;
        Ok(())
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

pub fn fixture_case_id(
    category: CaseCategory,
    subject_id: &str,
    evidence_root: &str,
    schema_version: u64,
) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-CASE-ID",
        &[
            HashPart::Str(category.as_str()),
            HashPart::Str(subject_id),
            HashPart::Str(evidence_root),
            HashPart::U64(schema_version),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn fixture_case_evidence_root(
    category: CaseCategory,
    status: CaseStatus,
    finality_depth: FinalityDepth,
    reorg_proof_kind: ReorgProofKind,
    subject_id: &str,
    monero_height: u64,
    confirmations: u64,
    reorg_depth: u64,
    watcher_count: u64,
    canonical_tip_root: &str,
    orphan_root: &str,
    expected_outcome: FailClosedOutcome,
    remediation_hint: &str,
) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-CASE-EVIDENCE",
        &[
            HashPart::Str(category.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(finality_depth.as_str()),
            HashPart::Str(reorg_proof_kind.as_str()),
            HashPart::Str(subject_id),
            HashPart::U64(monero_height),
            HashPart::U64(confirmations),
            HashPart::U64(reorg_depth),
            HashPart::U64(watcher_count),
            HashPart::Str(canonical_tip_root),
            HashPart::Str(orphan_root),
            HashPart::Str(expected_outcome.as_str()),
            HashPart::Str(remediation_hint),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

fn accepted_cases(config: &Config) -> Vec<FixtureCase> {
    vec![
        FixtureCase::new(
            config,
            CaseCategory::AcceptedLock,
            CaseStatus::Accepted,
            FinalityDepth::Shallow,
            ReorgProofKind::None,
            "deposit-lock-shallow-finality",
            1,
            config.min_lock_confirmations,
            0,
            config.min_watcher_quorum,
            FailClosedOutcome::DepositHeld,
            "admit deposit note only after shallow lock quorum and redacted proof digest",
        ),
        FixtureCase::new(
            config,
            CaseCategory::AcceptedFinality,
            CaseStatus::Accepted,
            FinalityDepth::Deep,
            ReorgProofKind::None,
            "deposit-lock-deep-finality",
            2,
            config.deep_finality_confirmations,
            0,
            config.min_watcher_quorum + 1,
            FailClosedOutcome::DepositHeld,
            "upgrade deposit from hold to mintable note after deep finality digest",
        ),
        FixtureCase::new(
            config,
            CaseCategory::AcceptedHeader,
            CaseStatus::Accepted,
            FinalityDepth::Deep,
            ReorgProofKind::None,
            "canonical-header-continuity",
            3,
            config.deep_finality_confirmations,
            0,
            config.min_watcher_quorum,
            FailClosedOutcome::ChallengeOpened,
            "bind header continuity root before any exit release path",
        ),
        FixtureCase::new(
            config,
            CaseCategory::AcceptedReorgProof,
            CaseStatus::Accepted,
            FinalityDepth::Shallow,
            ReorgProofKind::OrphanHeader,
            "orphan-proof-within-window",
            4,
            config.min_lock_confirmations + 2,
            3,
            config.min_watcher_quorum,
            FailClosedOutcome::ChallengeOpened,
            "open challenge and keep deposits plus exits held through reorg window",
        ),
        FixtureCase::new(
            config,
            CaseCategory::AcceptedWatcherQuorum,
            CaseStatus::Accepted,
            FinalityDepth::Deep,
            ReorgProofKind::CompetingTip,
            "watcher-quorum-competing-tip",
            5,
            config.deep_finality_confirmations,
            2,
            config.min_watcher_quorum + 2,
            FailClosedOutcome::ChallengeOpened,
            "require quorum transcript before resolving competing tip evidence",
        ),
    ]
}

fn rejected_cases(config: &Config) -> Vec<FixtureCase> {
    vec![
        FixtureCase::new(
            config,
            CaseCategory::RejectedLock,
            CaseStatus::Rejected,
            FinalityDepth::None,
            ReorgProofKind::None,
            "duplicate-lock-evidence",
            10,
            config.min_lock_confirmations,
            0,
            config.min_watcher_quorum,
            FailClosedOutcome::DepositHeld,
            "reject duplicate lock commitment and require a fresh nullifier binding",
        ),
        FixtureCase::new(
            config,
            CaseCategory::RejectedFinality,
            CaseStatus::Rejected,
            FinalityDepth::Shallow,
            ReorgProofKind::None,
            "shallow-finality-exit-attempt",
            11,
            config.min_lock_confirmations - 1,
            0,
            config.min_watcher_quorum,
            FailClosedOutcome::ExitHeld,
            "deny exit release until deep finality confirmations are observed",
        ),
        FixtureCase::new(
            config,
            CaseCategory::RejectedHeader,
            CaseStatus::Rejected,
            FinalityDepth::Shallow,
            ReorgProofKind::HeaderContinuityBreak,
            "broken-header-continuity",
            12,
            config.min_lock_confirmations,
            1,
            config.min_watcher_quorum,
            FailClosedOutcome::ChallengeOpened,
            "quarantine header branch and request continuity proof replay",
        ),
        FixtureCase::new(
            config,
            CaseCategory::RejectedReorgProof,
            CaseStatus::Rejected,
            FinalityDepth::Deep,
            ReorgProofKind::DepthExceeded,
            "deep-reorg-after-certification",
            13,
            config.deep_finality_confirmations,
            config.reorg_challenge_depth + 1,
            config.min_watcher_quorum,
            FailClosedOutcome::ExitHeld,
            "hold exits and escalate to governance challenge because depth exceeds fixture window",
        ),
        FixtureCase::new(
            config,
            CaseCategory::RejectedWatcherClaim,
            CaseStatus::Rejected,
            FinalityDepth::Deep,
            ReorgProofKind::CompetingTip,
            "minority-watcher-claim",
            14,
            config.deep_finality_confirmations,
            2,
            config.min_watcher_quorum - 1,
            FailClosedOutcome::ExitHeld,
            "ignore minority watcher tip claim until quorum evidence appears",
        ),
        FixtureCase::new(
            config,
            CaseCategory::ExitFailClosed,
            CaseStatus::Blocked,
            FinalityDepth::Shallow,
            ReorgProofKind::CompetingTip,
            "exit-against-unstable-tip",
            15,
            config.min_lock_confirmations,
            config.reorg_challenge_depth,
            config.min_watcher_quorum,
            FailClosedOutcome::ExitHeld,
            "fail closed when exit references a tip still inside the challenge window",
        ),
        FixtureCase::new(
            config,
            CaseCategory::BaseLayerVerifierAssumption,
            CaseStatus::Deferred,
            FinalityDepth::Deep,
            ReorgProofKind::None,
            "no-base-layer-verifier-assumption",
            16,
            config.deep_finality_confirmations,
            0,
            config.min_watcher_quorum,
            FailClosedOutcome::ReserveHeld,
            "treat casebook evidence as fixture-only until native Monero verifier is bound",
        ),
    ]
}

fn privacy_constraints(config: &Config) -> Vec<PrivacyConstraint> {
    vec![
        PrivacyConstraint::new(
            PrivacySurface::ViewKey,
            config.redacted_public_record_required,
            config.max_metadata_linkage_bps,
            "publish view-key commitment only",
            "seal watcher payloads and rotate disclosure keys after dispute resolution",
            1,
        ),
        PrivacyConstraint::new(
            PrivacySurface::Amount,
            config.redacted_public_record_required,
            config.max_metadata_linkage_bps,
            "publish amount bucket commitment only",
            "keep exact amounts inside encrypted watcher evidence",
            2,
        ),
        PrivacyConstraint::new(
            PrivacySurface::Timing,
            config.redacted_public_record_required,
            config.max_metadata_linkage_bps,
            "publish confirmation band rather than wall-clock time",
            "round deposit and exit timing to finality bands",
            3,
        ),
        PrivacyConstraint::new(
            PrivacySurface::OutputIndex,
            config.redacted_public_record_required,
            config.max_metadata_linkage_bps,
            "publish membership root without output index",
            "prove inclusion through sealed note witness commitments",
            4,
        ),
        PrivacyConstraint::new(
            PrivacySurface::WatcherPayload,
            config.redacted_public_record_required,
            config.max_metadata_linkage_bps,
            "publish quorum digest without signer payload contents",
            "redact watcher transport metadata from public casebook rows",
            5,
        ),
    ]
}

fn liquidity_watches(config: &Config) -> Vec<LiquidityReserveWatch> {
    vec![
        LiquidityReserveWatch::new(config, "healthy_hold", 1_250, 4, 3, 1, 1),
        LiquidityReserveWatch::new(config, "reorg_pressure", 1_100, 6, 5, 3, 2),
        LiquidityReserveWatch::new(config, "reserve_shortfall", 900, 8, 7, 4, 3),
    ]
}

#[allow(clippy::too_many_arguments)]
fn casebook_report(
    config: &Config,
    accepted_case_count: u64,
    rejected_case_count: u64,
    privacy_constraint_count: u64,
    liquidity_watch_count: u64,
    accepted_case_root: &str,
    rejected_case_root: &str,
    privacy_constraint_root: &str,
    liquidity_watch_root: &str,
) -> CasebookReport {
    let fail_closed_case_count = rejected_case_count + liquidity_watch_count;
    let verdict = if config.base_layer_verifier_enabled && config.production_release_allowed {
        "ready_with_live_verifier"
    } else {
        "fixture_only_fail_closed"
    };
    let report_root = domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-REPORT",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(accepted_case_count),
            HashPart::U64(rejected_case_count),
            HashPart::U64(privacy_constraint_count),
            HashPart::U64(liquidity_watch_count),
            HashPart::U64(fail_closed_case_count),
            HashPart::Str(bool_str(config.base_layer_verifier_enabled)),
            HashPart::Str(bool_str(config.production_release_allowed)),
            HashPart::Str(accepted_case_root),
            HashPart::Str(rejected_case_root),
            HashPart::Str(privacy_constraint_root),
            HashPart::Str(liquidity_watch_root),
            HashPart::Str(verdict),
        ],
        32,
    );
    let report_id = domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-REPORT-ID",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(&report_root)],
        32,
    );
    CasebookReport {
        report_id,
        accepted_case_count,
        rejected_case_count,
        privacy_constraint_count,
        liquidity_watch_count,
        fail_closed_case_count,
        base_layer_verifier_enabled: config.base_layer_verifier_enabled,
        production_release_allowed: config.production_release_allowed,
        accepted_case_root: accepted_case_root.to_string(),
        rejected_case_root: rejected_case_root.to_string(),
        privacy_constraint_root: privacy_constraint_root.to_string(),
        liquidity_watch_root: liquidity_watch_root.to_string(),
        report_root,
        verdict: verdict.to_string(),
    }
}

fn state_root_from_parts(
    config_root: &str,
    accepted_case_root: &str,
    rejected_case_root: &str,
    privacy_constraint_root: &str,
    liquidity_watch_root: &str,
    report_root: &str,
) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-STATE",
        &[
            HashPart::Str(config_root),
            HashPart::Str(accepted_case_root),
            HashPart::Str(rejected_case_root),
            HashPart::Str(privacy_constraint_root),
            HashPart::Str(liquidity_watch_root),
            HashPart::Str(report_root),
        ],
        32,
    )
}

fn canonical_tip_root(
    header_hash: &str,
    monero_height: u64,
    confirmations: u64,
    watcher_count: u64,
) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-CANONICAL-TIP",
        &[
            HashPart::Str(header_hash),
            HashPart::U64(monero_height),
            HashPart::U64(confirmations),
            HashPart::U64(watcher_count),
        ],
        32,
    )
}

fn orphan_root(kind: ReorgProofKind, header_hash: &str, reorg_depth: u64) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-ORPHAN",
        &[
            HashPart::Str(kind.as_str()),
            HashPart::Str(header_hash),
            HashPart::U64(reorg_depth),
        ],
        32,
    )
}

fn labeled_hash(label: &str, subject_id: &str, ordinal: u64) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-LABELED-HASH",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(label),
            HashPart::Str(subject_id),
            HashPart::U64(ordinal),
        ],
        32,
    )
}

fn redacted_subject_id(subject_id: &str) -> String {
    domain_hash(
        "MONERO-LOCK-REORG-CASEBOOK-REDACTED-SUBJECT",
        &[HashPart::Str(CHAIN_ID), HashPart::Str(subject_id)],
        20,
    )
}

fn merkle_from_records(domain: &str, records: Vec<Value>) -> String {
    merkle_root(domain, &records)
}

fn privacy_surface_for(category: CaseCategory) -> PrivacySurface {
    match category {
        CaseCategory::AcceptedLock | CaseCategory::RejectedLock => PrivacySurface::OutputIndex,
        CaseCategory::AcceptedFinality | CaseCategory::RejectedFinality => PrivacySurface::Timing,
        CaseCategory::AcceptedHeader
        | CaseCategory::RejectedHeader
        | CaseCategory::AcceptedReorgProof
        | CaseCategory::RejectedReorgProof => PrivacySurface::WatcherPayload,
        CaseCategory::AcceptedWatcherQuorum | CaseCategory::RejectedWatcherClaim => {
            PrivacySurface::ViewKey
        }
        CaseCategory::PrivacyConstraint => PrivacySurface::Amount,
        CaseCategory::BaseLayerVerifierAssumption
        | CaseCategory::LiquidityReserveWatch
        | CaseCategory::DepositFailClosed
        | CaseCategory::ExitFailClosed => PrivacySurface::Timing,
    }
}

fn metadata_policy_for(category: CaseCategory, status: CaseStatus) -> &'static str {
    match (category, status) {
        (CaseCategory::AcceptedLock, CaseStatus::Accepted) => {
            "commit lock proof while redacting amount and output index"
        }
        (CaseCategory::AcceptedFinality, CaseStatus::Accepted) => {
            "publish finality band and canonical digest only"
        }
        (CaseCategory::AcceptedHeader, CaseStatus::Accepted) => {
            "publish header hash chain without transaction payloads"
        }
        (CaseCategory::AcceptedReorgProof, CaseStatus::Accepted) => {
            "publish orphan digest and sealed branch witness"
        }
        (CaseCategory::AcceptedWatcherQuorum, CaseStatus::Accepted) => {
            "publish quorum count and aggregate digest only"
        }
        (CaseCategory::RejectedLock, _) => "reject duplicated lock digest before note mint",
        (CaseCategory::RejectedFinality, _) => "reject shallow finality for exit release decisions",
        (CaseCategory::RejectedHeader, _) => "reject broken continuity and retain challenge state",
        (CaseCategory::RejectedReorgProof, _) => {
            "reject proof outside configured replay window and hold exits"
        }
        (CaseCategory::RejectedWatcherClaim, _) => {
            "reject minority watcher claim without releasing private payloads"
        }
        (CaseCategory::PrivacyConstraint, _) => "enforce redacted publication for all case rows",
        (CaseCategory::BaseLayerVerifierAssumption, _) => {
            "mark base-layer verification as fixture assumption"
        }
        (CaseCategory::LiquidityReserveWatch, _) => {
            "hold reserve release while reorg watch is unresolved"
        }
        (CaseCategory::DepositFailClosed, _) => {
            "hold deposit note until lock evidence is canonical"
        }
        (CaseCategory::ExitFailClosed, _) => "hold exit until finality and reserve checks pass",
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
