use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::{
        ExitMode as SpineExitMode, SafetyStatus as SpineSafetyStatus, SpineStage,
        State as BridgeExitSpineState, ThreatSurface as SpineThreatSurface,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitInvariantVerifierRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_INVARIANT_VERIFIER_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-invariant-verifier-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_INVARIANT_VERIFIER_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const INVARIANT_SUITE: &str = "monero-l2-bridge-exit-safety-invariants-and-rooted-evidence-v1";
pub const DEVNET_HEIGHT: u64 = 620_256;
pub const DEFAULT_MIN_PQ_SECURITY_BITS: u16 = 256;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 16_384;
pub const DEFAULT_MIN_THREAT_SURFACES: usize = 7;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_EXIT_RESERVE_BPS: u64 = 10_000;
pub const DEFAULT_MAX_ASSESSMENTS: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    PolicyExitAvailability,
    WatcherPqQuorum,
    MoneroFinalityDepth,
    DepositToNoteContinuity,
    PrivateActionReceiptContinuity,
    ForcedExitLiveness,
    ChallengeCoverage,
    NullifierReplayFence,
    PrivacyFloor,
    ThreatModelCoverage,
    FeeCap,
    ReserveCoverage,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyExitAvailability => "policy_exit_availability",
            Self::WatcherPqQuorum => "watcher_pq_quorum",
            Self::MoneroFinalityDepth => "monero_finality_depth",
            Self::DepositToNoteContinuity => "deposit_to_note_continuity",
            Self::PrivateActionReceiptContinuity => "private_action_receipt_continuity",
            Self::ForcedExitLiveness => "forced_exit_liveness",
            Self::ChallengeCoverage => "challenge_coverage",
            Self::NullifierReplayFence => "nullifier_replay_fence",
            Self::PrivacyFloor => "privacy_floor",
            Self::ThreatModelCoverage => "threat_model_coverage",
            Self::FeeCap => "fee_cap",
            Self::ReserveCoverage => "reserve_coverage",
        }
    }

    pub fn all() -> [Self; 12] {
        [
            Self::PolicyExitAvailability,
            Self::WatcherPqQuorum,
            Self::MoneroFinalityDepth,
            Self::DepositToNoteContinuity,
            Self::PrivateActionReceiptContinuity,
            Self::ForcedExitLiveness,
            Self::ChallengeCoverage,
            Self::NullifierReplayFence,
            Self::PrivacyFloor,
            Self::ThreatModelCoverage,
            Self::FeeCap,
            Self::ReserveCoverage,
        ]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantSeverity {
    Info,
    Warning,
    Critical,
}

impl InvariantSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn score_bps(self) -> u64 {
        match self {
            Self::Info => 1_000,
            Self::Warning => 5_000,
            Self::Critical => 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantStatus {
    Passed,
    Watch,
    Failed,
    Deferred,
}

impl InvariantStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Watch => "watch",
            Self::Failed => "failed",
            Self::Deferred => "deferred",
        }
    }

    pub fn passes(self) -> bool {
        matches!(self, Self::Passed | Self::Watch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentStatus {
    Green,
    Watch,
    Failed,
}

impl AssessmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Watch => "watch",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub invariant_suite: String,
    pub genesis_height: u64,
    pub min_pq_security_bits: u16,
    pub min_privacy_set_size: u64,
    pub min_threat_surfaces: usize,
    pub max_user_fee_bps: u64,
    pub min_exit_reserve_bps: u64,
    pub max_assessments: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            invariant_suite: INVARIANT_SUITE.to_string(),
            genesis_height: DEVNET_HEIGHT,
            min_pq_security_bits: DEFAULT_MIN_PQ_SECURITY_BITS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_threat_surfaces: DEFAULT_MIN_THREAT_SURFACES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_exit_reserve_bps: DEFAULT_MIN_EXIT_RESERVE_BPS,
            max_assessments: DEFAULT_MAX_ASSESSMENTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "invariant_suite": self.invariant_suite,
            "genesis_height": self.genesis_height,
            "min_pq_security_bits": self.min_pq_security_bits,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_threat_surfaces": self.min_threat_surfaces,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_exit_reserve_bps": self.min_exit_reserve_bps,
            "max_assessments": self.max_assessments,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-VERIFIER-CONFIG",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InvariantEvidence {
    pub kind: InvariantKind,
    pub status: InvariantStatus,
    pub severity: InvariantSeverity,
    pub summary: String,
    pub required: String,
    pub observed: String,
    pub remediation: String,
    pub evidence_root: String,
}

impl InvariantEvidence {
    pub fn new(
        kind: InvariantKind,
        status: InvariantStatus,
        severity: InvariantSeverity,
        summary: impl Into<String>,
        required: impl Into<String>,
        observed: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let summary = summary.into();
        let required = required.into();
        let observed = observed.into();
        let remediation = remediation.into();
        let evidence_root = domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-EVIDENCE",
            &[
                HashPart::Str(kind.as_str()),
                HashPart::Str(status.as_str()),
                HashPart::Str(severity.as_str()),
                HashPart::Str(&summary),
                HashPart::Str(&required),
                HashPart::Str(&observed),
                HashPart::Str(&remediation),
            ],
            32,
        );
        Self {
            kind,
            status,
            severity,
            summary,
            required,
            observed,
            remediation,
            evidence_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "summary": self.summary,
            "required": self.required,
            "observed": self.observed,
            "remediation": self.remediation,
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub assessments_run: u64,
    pub invariants_passed: u64,
    pub invariants_watch: u64,
    pub invariants_failed: u64,
    pub critical_failures: u64,
    pub deferred_checks: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "assessments_run": self.assessments_run,
            "invariants_passed": self.invariants_passed,
            "invariants_watch": self.invariants_watch,
            "invariants_failed": self.invariants_failed,
            "critical_failures": self.critical_failures,
            "deferred_checks": self.deferred_checks,
        })
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-VERIFIER-COUNTERS",
            &[HashPart::Json(&self.public_record())],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AssessmentRoots {
    pub source_spine_root: String,
    pub policy_root: String,
    pub invariant_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl AssessmentRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "source_spine_root": self.source_spine_root,
            "policy_root": self.policy_root,
            "invariant_root": self.invariant_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-VERIFIER-STATE",
            &[
                HashPart::Str(&self.source_spine_root),
                HashPart::Str(&self.policy_root),
                HashPart::Str(&self.invariant_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityAssessment {
    pub assessment_id: String,
    pub source_spine_root: String,
    pub assessed_height: u64,
    pub status: AssessmentStatus,
    pub invariants: BTreeMap<String, InvariantEvidence>,
    pub roots: AssessmentRoots,
}

impl SecurityAssessment {
    pub fn public_record(&self) -> Value {
        let invariants = self
            .invariants
            .values()
            .map(InvariantEvidence::public_record)
            .collect::<Vec<_>>();
        json!({
            "assessment_id": self.assessment_id,
            "source_spine_root": self.source_spine_root,
            "assessed_height": self.assessed_height,
            "status": self.status.as_str(),
            "invariants": invariants,
            "roots": self.roots.public_record(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub counters: Counters,
    pub latest_assessment: Option<SecurityAssessment>,
    pub assessment_history: Vec<SecurityAssessment>,
    pub roots: AssessmentRoots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = AssessmentRoots {
            source_spine_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-EMPTY-SPINE", &[]),
            policy_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-EMPTY-POLICY", &[]),
            invariant_root: merkle_root("MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-EMPTY-INVARIANTS", &[]),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        let mut state = Self {
            config,
            counters,
            latest_assessment: None,
            assessment_history: Vec::new(),
            roots,
        };
        state.roots.state_root = state.roots.compute_state_root();
        let spine = crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet();
        state
            .assess_spine(&spine, DEVNET_HEIGHT)
            .expect("devnet bridge/exit spine invariant assessment");
        state
    }

    pub fn assess_spine(
        &mut self,
        spine: &BridgeExitSpineState,
        assessed_height: u64,
    ) -> Result<String> {
        let mut invariants = BTreeMap::new();
        for evidence in evaluate_spine_invariants(&self.config, spine, assessed_height) {
            invariants.insert(evidence.kind.as_str().to_string(), evidence);
        }
        require(
            InvariantKind::all()
                .iter()
                .all(|kind| invariants.contains_key(kind.as_str())),
            "invariant assessment missing required bridge/exit invariant",
        )?;

        let status = aggregate_status(&invariants);
        let invariant_records = invariants
            .values()
            .map(InvariantEvidence::public_record)
            .collect::<Vec<_>>();
        let invariant_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-VERIFIER-INVARIANTS",
            &invariant_records,
        );
        let source_spine_root = spine.state_root();
        let policy_root = spine.policy.state_root();
        let assessment_id = assessment_id(&source_spine_root, &invariant_root, assessed_height);

        self.counters.assessments_run += 1;
        self.counters.invariants_passed += invariants
            .values()
            .filter(|item| item.status == InvariantStatus::Passed)
            .count() as u64;
        self.counters.invariants_watch += invariants
            .values()
            .filter(|item| item.status == InvariantStatus::Watch)
            .count() as u64;
        self.counters.invariants_failed += invariants
            .values()
            .filter(|item| item.status == InvariantStatus::Failed)
            .count() as u64;
        self.counters.critical_failures += invariants
            .values()
            .filter(|item| {
                item.status == InvariantStatus::Failed
                    && item.severity == InvariantSeverity::Critical
            })
            .count() as u64;
        self.counters.deferred_checks += invariants
            .values()
            .filter(|item| item.status == InvariantStatus::Deferred)
            .count() as u64;

        let mut roots = AssessmentRoots {
            source_spine_root: source_spine_root.clone(),
            policy_root,
            invariant_root,
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        let assessment = SecurityAssessment {
            assessment_id: assessment_id.clone(),
            source_spine_root,
            assessed_height,
            status,
            invariants,
            roots: roots.clone(),
        };
        self.latest_assessment = Some(assessment.clone());
        self.assessment_history.push(assessment);
        if self.assessment_history.len() > self.config.max_assessments {
            self.assessment_history.remove(0);
        }
        self.roots = roots;
        Ok(assessment_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "latest_assessment": self.latest_assessment.as_ref().map(SecurityAssessment::public_record),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
            "assessment_history_len": self.assessment_history.len(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }
}

pub fn evaluate_spine_invariants(
    config: &Config,
    spine: &BridgeExitSpineState,
    assessed_height: u64,
) -> Vec<InvariantEvidence> {
    vec![
        policy_exit_availability(config, spine),
        watcher_pq_quorum(config, spine),
        monero_finality_depth(config, spine),
        deposit_to_note_continuity(spine),
        private_action_receipt_continuity(spine),
        forced_exit_liveness(spine, assessed_height),
        challenge_coverage(spine),
        nullifier_replay_fence(spine),
        privacy_floor(config, spine),
        threat_model_coverage(config, spine),
        fee_cap(config, spine),
        reserve_coverage(config, spine),
    ]
}

fn policy_exit_availability(_config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let exits_available = spine.policy.withdrawals_enabled
        && spine.policy.forced_exits_enabled
        && spine.policy.safety_status != SpineSafetyStatus::HaltDeposits;
    InvariantEvidence::new(
        InvariantKind::PolicyExitAvailability,
        if exits_available {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "bridge policy must preserve a user exit path",
        "withdrawals enabled, forced exits enabled, and safety mode not halt-only",
        format!(
            "withdrawals={}, forced_exits={}, safety_status={}",
            spine.policy.withdrawals_enabled,
            spine.policy.forced_exits_enabled,
            spine.policy.safety_status.as_str()
        ),
        "switch bridge to exit-only mode and restore forced-exit policy before accepting deposits",
    )
}

fn watcher_pq_quorum(config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let usable = spine.watcher_quorums.values().filter(|quorum| {
        quorum.observed_weight >= quorum.threshold_weight
            && quorum.threshold_weight >= spine.config.min_watcher_weight
            && quorum.min_pq_security_bits >= config.min_pq_security_bits
    });
    let usable_count = usable.count();
    InvariantEvidence::new(
        InvariantKind::WatcherPqQuorum,
        if usable_count > 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "bridge locks and exits require usable post-quantum watcher quorum evidence",
        format!(
            "at least one quorum with observed weight >= threshold and PQ security >= {} bits",
            config.min_pq_security_bits
        ),
        format!(
            "usable_quorums={}, total_quorums={}",
            usable_count,
            spine.watcher_quorums.len()
        ),
        "register or rotate a PQ watcher quorum before certifying deposits or exits",
    )
}

fn monero_finality_depth(_config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let below = spine
        .watcher_quorums
        .values()
        .filter(|quorum| quorum.monero_finality_depth < spine.config.fast_finality_depth)
        .count();
    InvariantEvidence::new(
        InvariantKind::MoneroFinalityDepth,
        if below == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "watcher certificates must cover Monero finality before L2 mint or exit release",
        format!(
            "each quorum finality depth >= fast minimum {}",
            spine.config.fast_finality_depth
        ),
        format!(
            "below_minimum={}, quorum_count={}",
            below,
            spine.watcher_quorums.len()
        ),
        "reject certificates from shallow finality quorums and hold deposits until depth matures",
    )
}

fn deposit_to_note_continuity(spine: &BridgeExitSpineState) -> InvariantEvidence {
    let broken = spine
        .bridge_paths
        .values()
        .filter(|path| {
            matches!(
                path.stage,
                SpineStage::PrivateNoteMinted
                    | SpineStage::PrivateActionRecorded
                    | SpineStage::ReceiptAnchored
                    | SpineStage::WithdrawalRequested
                    | SpineStage::ForcedExitArmed
                    | SpineStage::ExitSettled
            ) && (path.deposit_certificate_root.is_none()
                || path.private_note_commitment.is_none()
                || path.private_state_root.is_none())
        })
        .count();
    InvariantEvidence::new(
        InvariantKind::DepositToNoteContinuity,
        if broken == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "every minted private note must trace back to a certified Monero deposit lock",
        "post-mint paths have deposit certificate, note commitment, and private state root",
        format!(
            "broken_paths={}, total_paths={}",
            broken,
            spine.bridge_paths.len()
        ),
        "quarantine any note path missing deposit certificate or note-state roots",
    )
}

fn private_action_receipt_continuity(spine: &BridgeExitSpineState) -> InvariantEvidence {
    let broken = spine
        .bridge_paths
        .values()
        .filter(|path| {
            let missing_receipt = match path.action_receipt_id.as_ref() {
                Some(receipt_id) => !spine.receipts.contains_key(receipt_id),
                None => true,
            };
            matches!(
                path.stage,
                SpineStage::PrivateActionRecorded
                    | SpineStage::ReceiptAnchored
                    | SpineStage::WithdrawalRequested
                    | SpineStage::ForcedExitArmed
                    | SpineStage::ExitSettled
            ) && missing_receipt
        })
        .count();
    InvariantEvidence::new(
        InvariantKind::PrivateActionReceiptContinuity,
        if broken == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "private transfer/contract actions must produce a retrievable receipt root",
        "post-action paths reference a stored receipt",
        format!(
            "broken_paths={}, receipt_count={}",
            broken,
            spine.receipts.len()
        ),
        "reject exit release for paths whose private action receipt cannot be found",
    )
}

fn forced_exit_liveness(spine: &BridgeExitSpineState, assessed_height: u64) -> InvariantEvidence {
    let forced_ready = spine
        .bridge_paths
        .keys()
        .filter(|path_id| spine.forced_exit_available(path_id, assessed_height))
        .count();
    let armed = spine
        .bridge_paths
        .values()
        .filter(|path| {
            path.exit_mode
                .map(SpineExitMode::needs_forced_exit_delay)
                .unwrap_or(false)
                || path.stage == SpineStage::ForcedExitArmed
        })
        .count();
    let status = if spine.policy.forced_exits_enabled {
        if forced_ready > 0 || armed > 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Watch
        }
    } else {
        InvariantStatus::Failed
    };
    InvariantEvidence::new(
        InvariantKind::ForcedExitLiveness,
        status,
        InvariantSeverity::Critical,
        "users must have an always-available forced-exit route under sequencer failure",
        "forced exits enabled and live/armed paths can transition without sequencer cooperation",
        format!(
            "forced_exits_enabled={}, forced_ready={}, armed_or_forced_paths={}",
            spine.policy.forced_exits_enabled, forced_ready, armed
        ),
        "keep forced exits enabled and surface liveness timeout proofs for every live private note",
    )
}

fn challenge_coverage(spine: &BridgeExitSpineState) -> InvariantEvidence {
    let open_challenges = spine
        .challenges
        .values()
        .filter(|challenge| challenge.status.open())
        .count();
    let malformed = spine
        .challenges
        .values()
        .filter(|challenge| {
            challenge.evidence_root.is_empty()
                || challenge.expires_height <= challenge.opened_height
                || !spine.bridge_paths.contains_key(&challenge.path_id)
        })
        .count();
    InvariantEvidence::new(
        InvariantKind::ChallengeCoverage,
        if malformed == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "exit disputes need bounded challenge windows and rooted evidence",
        "each challenge references an existing path, non-empty evidence, and future expiry",
        format!(
            "open_challenges={}, malformed_challenges={}",
            open_challenges, malformed
        ),
        "reject malformed challenges and quarantine challenged exits until resolution roots exist",
    )
}

fn nullifier_replay_fence(spine: &BridgeExitSpineState) -> InvariantEvidence {
    let exit_nullifiers = spine
        .bridge_paths
        .values()
        .filter_map(|path| path.burn_nullifier.as_ref())
        .count();
    let replay_gap = exit_nullifiers.saturating_sub(spine.spent_nullifiers.len());
    InvariantEvidence::new(
        InvariantKind::NullifierReplayFence,
        if replay_gap == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "withdrawal burns must be protected by a replay/nullifier fence",
        "every path burn nullifier is included in spent nullifier set",
        format!(
            "exit_nullifiers={}, spent_nullifiers={}, replay_gap={}",
            exit_nullifiers,
            spine.spent_nullifiers.len(),
            replay_gap
        ),
        "insert burn nullifiers before accepting exit requests and reject duplicates",
    )
}

fn privacy_floor(config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let below = spine
        .bridge_paths
        .values()
        .filter(|path| path.privacy_set_size < config.min_privacy_set_size)
        .count();
    InvariantEvidence::new(
        InvariantKind::PrivacyFloor,
        if below == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "deposit, action, and exit records must preserve minimum anonymity set floors",
        format!("privacy set size >= {}", config.min_privacy_set_size),
        format!(
            "below_floor={}, total_paths={}",
            below,
            spine.bridge_paths.len()
        ),
        "batch or delay paths whose privacy set is below the configured floor",
    )
}

fn threat_model_coverage(config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let required = [
        SpineThreatSurface::MoneroReorg,
        SpineThreatSurface::WatcherCollusion,
        SpineThreatSurface::SequencerCensorship,
        SpineThreatSurface::LiquidityExhaustion,
        SpineThreatSurface::MetadataLinkage,
        SpineThreatSurface::UpgradeKeyCompromise,
        SpineThreatSurface::PqMigrationFailure,
    ];
    let covered = required
        .iter()
        .filter(|surface| spine.threat_model.contains_key(surface.as_str()))
        .count();
    InvariantEvidence::new(
        InvariantKind::ThreatModelCoverage,
        if covered >= config.min_threat_surfaces {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Warning,
        "bridge/exit spine must name the main Monero private L2 threat surfaces",
        format!(
            "at least {} threat surfaces covered",
            config.min_threat_surfaces
        ),
        format!(
            "covered={}, required={}, total_entries={}",
            covered,
            required.len(),
            spine.threat_model.len()
        ),
        "add missing threat surfaces before raising readiness above prototype level",
    )
}

fn fee_cap(config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let path_violations = spine
        .bridge_paths
        .values()
        .filter(|path| path.max_user_fee_bps > config.max_user_fee_bps)
        .count();
    let receipt_violations = spine
        .receipts
        .values()
        .filter(|receipt| receipt.user_fee_bps > config.max_user_fee_bps)
        .count();
    InvariantEvidence::new(
        InvariantKind::FeeCap,
        if path_violations == 0 && receipt_violations == 0 {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Warning,
        "bridge safety path should keep user fees bounded even during exits",
        format!("user fee bps <= {}", config.max_user_fee_bps),
        format!(
            "path_violations={}, receipt_violations={}",
            path_violations, receipt_violations
        ),
        "route high-fee exits through sponsor/rebate policies or delay non-emergency requests",
    )
}

fn reserve_coverage(config: &Config, spine: &BridgeExitSpineState) -> InvariantEvidence {
    let ok = spine.config.exit_reserve_bps >= config.min_exit_reserve_bps
        && !spine.policy.reserve_root.is_empty();
    InvariantEvidence::new(
        InvariantKind::ReserveCoverage,
        if ok {
            InvariantStatus::Passed
        } else {
            InvariantStatus::Failed
        },
        InvariantSeverity::Critical,
        "exit liveness depends on reserve proof and liquidity backstop coverage",
        format!(
            "exit reserve bps >= {} and reserve root present",
            config.min_exit_reserve_bps
        ),
        format!(
            "exit_reserve_bps={}, reserve_root_present={}",
            spine.config.exit_reserve_bps,
            !spine.policy.reserve_root.is_empty()
        ),
        "switch to exit-only and refresh reserve proofs before admitting new deposits",
    )
}

fn aggregate_status(invariants: &BTreeMap<String, InvariantEvidence>) -> AssessmentStatus {
    if invariants
        .values()
        .any(|item| item.status == InvariantStatus::Failed)
    {
        AssessmentStatus::Failed
    } else if invariants
        .values()
        .any(|item| item.status == InvariantStatus::Watch)
    {
        AssessmentStatus::Watch
    } else {
        AssessmentStatus::Green
    }
}

pub fn assessment_id(
    source_spine_root: &str,
    invariant_root: &str,
    assessed_height: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-INVARIANT-VERIFIER-ASSESSMENT-ID",
        &[
            HashPart::Str(source_spine_root),
            HashPart::Str(invariant_root),
            HashPart::U64(assessed_height),
        ],
        32,
    )
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}
