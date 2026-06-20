use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitCanonicalUserEscapeThreatModelAcceptanceMatrixRuntimeResult<T> =
    Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_THREAT_MODEL_ACCEPTANCE_MATRIX_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-canonical-user-escape-threat-model-acceptance-matrix-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_CANONICAL_USER_ESCAPE_THREAT_MODEL_ACCEPTANCE_MATRIX_RUNTIME_PROTOCOL_VERSION;

const DOMAIN: &str =
    "monero-l2-pq-bridge-exit-canonical-user-escape-threat-model-acceptance-matrix";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub matrix_suite: String,
    pub acceptance_policy: String,
    pub min_threat_count: u64,
    pub require_dry_run_root: u64,
    pub require_wallet_handoff_root: u64,
    pub require_process_feed_root: u64,
    pub require_mismatch_fixture_root: u64,
    pub require_roots_only_privacy: u64,
    pub require_release_held_for_failures: u64,
    pub max_accepted_linkage_fields: u64,
    pub min_pq_security_bits: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            matrix_suite:
                "monero-l2-pq-bridge-exit-canonical-user-escape-accept-hold-reject-matrix-v1"
                    .to_string(),
            acceptance_policy: "explicit-threat-criteria-with-fail-closed-release-holds-v1"
                .to_string(),
            min_threat_count: 9,
            require_dry_run_root: 1,
            require_wallet_handoff_root: 1,
            require_process_feed_root: 1,
            require_mismatch_fixture_root: 1,
            require_roots_only_privacy: 1,
            require_release_held_for_failures: 1,
            max_accepted_linkage_fields: 0,
            min_pq_security_bits: 256,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "matrix_suite": self.matrix_suite,
            "acceptance_policy": self.acceptance_policy,
            "min_threat_count": self.min_threat_count,
            "require_dry_run_root": self.require_dry_run_root,
            "require_wallet_handoff_root": self.require_wallet_handoff_root,
            "require_process_feed_root": self.require_process_feed_root,
            "require_mismatch_fixture_root": self.require_mismatch_fixture_root,
            "require_roots_only_privacy": self.require_roots_only_privacy,
            "require_release_held_for_failures": self.require_release_held_for_failures,
            "max_accepted_linkage_fields": self.max_accepted_linkage_fields,
            "min_pq_security_bits": self.min_pq_security_bits,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCase {
    NominalForcedExit,
    MoneroReorg,
    WatcherCollusion,
    LiquidityExhaustion,
    StalePqEpoch,
    ForgedReceipt,
    ReplayNullifierSeparation,
    MetadataLeakage,
    SequencerUnavailable,
}

impl ThreatCase {
    pub fn ordered() -> [Self; 9] {
        [
            Self::NominalForcedExit,
            Self::MoneroReorg,
            Self::WatcherCollusion,
            Self::LiquidityExhaustion,
            Self::StalePqEpoch,
            Self::ForgedReceipt,
            Self::ReplayNullifierSeparation,
            Self::MetadataLeakage,
            Self::SequencerUnavailable,
        ]
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NominalForcedExit => "nominal_forced_exit",
            Self::MoneroReorg => "monero_reorg",
            Self::WatcherCollusion => "watcher_collusion",
            Self::LiquidityExhaustion => "liquidity_exhaustion",
            Self::StalePqEpoch => "stale_pq_epoch",
            Self::ForgedReceipt => "forged_receipt",
            Self::ReplayNullifierSeparation => "replay_nullifier_separation",
            Self::MetadataLeakage => "metadata_leakage",
            Self::SequencerUnavailable => "sequencer_unavailable",
        }
    }

    pub fn severity(self) -> ThreatSeverity {
        match self {
            Self::NominalForcedExit => ThreatSeverity::Medium,
            Self::SequencerUnavailable => ThreatSeverity::High,
            Self::MoneroReorg
            | Self::WatcherCollusion
            | Self::LiquidityExhaustion
            | Self::StalePqEpoch
            | Self::ForgedReceipt
            | Self::ReplayNullifierSeparation
            | Self::MetadataLeakage => ThreatSeverity::Critical,
        }
    }

    pub fn default_decision(self) -> AcceptanceDecision {
        match self {
            Self::NominalForcedExit => AcceptanceDecision::Accept,
            Self::MoneroReorg
            | Self::LiquidityExhaustion
            | Self::StalePqEpoch
            | Self::SequencerUnavailable => AcceptanceDecision::Hold,
            Self::WatcherCollusion
            | Self::ForgedReceipt
            | Self::ReplayNullifierSeparation
            | Self::MetadataLeakage => AcceptanceDecision::Reject,
        }
    }

    pub fn control_objective(self) -> &'static str {
        match self {
            Self::NominalForcedExit => {
                "accept only roots-bound forced-exit handoff with release still held"
            }
            Self::MoneroReorg => {
                "hold release until replacement finality and watcher quorum roots agree"
            }
            Self::WatcherCollusion => {
                "reject colluding quorum evidence and route watcher bond/slashing review"
            }
            Self::LiquidityExhaustion => {
                "hold release and switch to reserve/backstop queue until coverage returns"
            }
            Self::StalePqEpoch => {
                "hold release until PQ epoch rotation and revocation roots are current"
            }
            Self::ForgedReceipt => "reject receipt root and require settlement transcript replay",
            Self::ReplayNullifierSeparation => {
                "reject replayed claim and preserve nullifier separation proof"
            }
            Self::MetadataLeakage => "reject leaking export and require roots-only wallet evidence",
            Self::SequencerUnavailable => {
                "hold cooperative path and keep forced-exit wallet path available"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Critical,
    High,
    Medium,
}

impl ThreatSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceDecision {
    Accept,
    Hold,
    Reject,
}

impl AcceptanceDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Hold => "hold",
            Self::Reject => "reject",
        }
    }

    pub fn requires_release_hold(self) -> u64 {
        match self {
            Self::Accept => 0,
            Self::Hold | Self::Reject => 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRoots {
    pub bridge_spine_root: String,
    pub reorg_collusion_manifest_root: String,
    pub failure_injection_matrix_root: String,
    pub forced_exit_dry_run_root: String,
    pub wallet_handoff_root: String,
    pub process_feed_binding_root: String,
    pub mismatch_fixture_root: String,
    pub adversarial_fixture_root: String,
    pub source_root: String,
}

impl SourceRoots {
    pub fn devnet() -> Self {
        let bridge_spine = crate::monero_l2_pq_trust_minimized_bridge_exit_spine_runtime::devnet();
        let reorg_collusion =
            crate::monero_l2_pq_bridge_exit_reorg_collusion_threat_model_manifest_runtime::devnet();
        let failure_injection_matrix_root = match crate::monero_l2_pq_bridge_exit_vertical_slice_failure_injection_matrix_runtime::devnet() {
            Ok(state) => state.state_root(),
            Err(reason) => record_root(
                "failure-injection-matrix-gap",
                &json!({ "reason_root": gap_reason_root(&reason) }),
            ),
        };
        let forced_exit_dry_run =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_vertical_dry_run_runtime::devnet();
        let wallet_handoff =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_forced_exit_dry_run_wallet_handoff_runtime::devnet();
        let bridge_spine_root = bridge_spine.state_root();
        let reorg_collusion_manifest_root = reorg_collusion.state_root();
        let forced_exit_dry_run_root = forced_exit_dry_run.state_root();
        let wallet_handoff_root = wallet_handoff.state_root();
        let process_feed_binding_root =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_process_feed_reconciliation_binding_runtime::state_root();
        let mismatch_fixture_root =
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_mismatch_fixture_runtime::state_root();
        let adversarial_fixture_root = failure_injection_matrix_root.clone();
        let source_root = source_root(
            &bridge_spine_root,
            &reorg_collusion_manifest_root,
            &failure_injection_matrix_root,
            &forced_exit_dry_run_root,
            &wallet_handoff_root,
            &process_feed_binding_root,
            &mismatch_fixture_root,
        );

        Self {
            bridge_spine_root,
            reorg_collusion_manifest_root,
            failure_injection_matrix_root,
            forced_exit_dry_run_root,
            wallet_handoff_root,
            process_feed_binding_root,
            mismatch_fixture_root,
            adversarial_fixture_root,
            source_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "bridge_spine_root": self.bridge_spine_root,
            "reorg_collusion_manifest_root": self.reorg_collusion_manifest_root,
            "failure_injection_matrix_root": self.failure_injection_matrix_root,
            "forced_exit_dry_run_root": self.forced_exit_dry_run_root,
            "wallet_handoff_root": self.wallet_handoff_root,
            "process_feed_binding_root": self.process_feed_binding_root,
            "mismatch_fixture_root": self.mismatch_fixture_root,
            "adversarial_fixture_root": self.adversarial_fixture_root,
            "source_root": self.source_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("source-roots", &self.public_record())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceCriterion {
    pub threat: ThreatCase,
    pub criterion_id: String,
    pub severity: ThreatSeverity,
    pub decision: AcceptanceDecision,
    pub accept_if: String,
    pub hold_if: String,
    pub reject_if: String,
    pub required_evidence_root: String,
    pub process_feed_root: String,
    pub wallet_visible_root: String,
    pub privacy_boundary_root: String,
    pub pq_control_root: String,
    pub release_hold_required: u64,
    pub linkage_fields_allowed: u64,
    pub criterion_root: String,
}

impl AcceptanceCriterion {
    pub fn devnet(config: &Config, source: &SourceRoots, threat: ThreatCase, ordinal: u64) -> Self {
        let decision = threat.default_decision();
        let required_evidence_root = required_evidence_root(threat, source);
        let process_feed_root = process_feed_root(threat, source);
        let wallet_visible_root = wallet_visible_root(threat, source);
        let privacy_boundary_root = privacy_boundary_root(threat, source);
        let pq_control_root = pq_control_root(threat, source);
        let criterion_id = criterion_id(threat, ordinal);
        let accept_if = accept_if(threat);
        let hold_if = hold_if(threat);
        let reject_if = reject_if(threat);
        let criterion_root = domain_hash(
            &format!("{DOMAIN}:criterion"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.matrix_suite),
                HashPart::U64(ordinal),
                HashPart::Str(threat.as_str()),
                HashPart::Str(threat.severity().as_str()),
                HashPart::Str(decision.as_str()),
                HashPart::Str(&criterion_id),
                HashPart::Str(&required_evidence_root),
                HashPart::Str(&process_feed_root),
                HashPart::Str(&wallet_visible_root),
                HashPart::Str(&privacy_boundary_root),
                HashPart::Str(&pq_control_root),
                HashPart::U64(decision.requires_release_hold()),
                HashPart::U64(config.max_accepted_linkage_fields),
            ],
            32,
        );

        Self {
            threat,
            criterion_id,
            severity: threat.severity(),
            decision,
            accept_if,
            hold_if,
            reject_if,
            required_evidence_root,
            process_feed_root,
            wallet_visible_root,
            privacy_boundary_root,
            pq_control_root,
            release_hold_required: decision.requires_release_hold(),
            linkage_fields_allowed: config.max_accepted_linkage_fields,
            criterion_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "threat": self.threat.as_str(),
            "criterion_id": self.criterion_id,
            "severity": self.severity.as_str(),
            "decision": self.decision.as_str(),
            "accept_if": self.accept_if,
            "hold_if": self.hold_if,
            "reject_if": self.reject_if,
            "required_evidence_root": self.required_evidence_root,
            "process_feed_root": self.process_feed_root,
            "wallet_visible_root": self.wallet_visible_root,
            "privacy_boundary_root": self.privacy_boundary_root,
            "pq_control_root": self.pq_control_root,
            "release_hold_required": self.release_hold_required,
            "linkage_fields_allowed": self.linkage_fields_allowed,
            "criterion_root": self.criterion_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixVerdict {
    pub threat_count: u64,
    pub accept_count: u64,
    pub hold_count: u64,
    pub reject_count: u64,
    pub release_hold_count: u64,
    pub roots_only_privacy_count: u64,
    pub pq_control_count: u64,
    pub matrix_status: String,
    pub verdict_root: String,
}

impl MatrixVerdict {
    pub fn new(config: &Config, criteria: &[AcceptanceCriterion]) -> Self {
        let threat_count = criteria.len() as u64;
        let accept_count = count_decision(criteria, AcceptanceDecision::Accept);
        let hold_count = count_decision(criteria, AcceptanceDecision::Hold);
        let reject_count = count_decision(criteria, AcceptanceDecision::Reject);
        let release_hold_count = criteria
            .iter()
            .filter(|criterion| criterion.release_hold_required == 1)
            .count() as u64;
        let roots_only_privacy_count = criteria
            .iter()
            .filter(|criterion| {
                criterion.linkage_fields_allowed <= config.max_accepted_linkage_fields
            })
            .count() as u64;
        let pq_control_count = criteria
            .iter()
            .filter(|criterion| !criterion.pq_control_root.is_empty())
            .count() as u64;
        let matrix_status = if threat_count >= config.min_threat_count
            && release_hold_count >= hold_count + reject_count
            && roots_only_privacy_count == threat_count
            && pq_control_count == threat_count
            && accept_count >= 1
            && hold_count >= 1
            && reject_count >= 1
        {
            "accept_hold_reject_matrix_bound"
        } else {
            "accept_hold_reject_matrix_gap"
        }
        .to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.acceptance_policy),
                HashPart::U64(threat_count),
                HashPart::U64(accept_count),
                HashPart::U64(hold_count),
                HashPart::U64(reject_count),
                HashPart::U64(release_hold_count),
                HashPart::U64(roots_only_privacy_count),
                HashPart::U64(pq_control_count),
                HashPart::Str(&matrix_status),
            ],
            32,
        );

        Self {
            threat_count,
            accept_count,
            hold_count,
            reject_count,
            release_hold_count,
            roots_only_privacy_count,
            pq_control_count,
            matrix_status,
            verdict_root,
        }
    }

    pub fn fallback(config: &Config, reason: &str) -> Self {
        let matrix_status = "accept_hold_reject_matrix_construction_gap".to_string();
        let verdict_root = domain_hash(
            &format!("{DOMAIN}:fallback-verdict"),
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(&config.acceptance_policy),
                HashPart::Str(reason),
                HashPart::Str(&matrix_status),
            ],
            32,
        );

        Self {
            threat_count: 0,
            accept_count: 0,
            hold_count: 0,
            reject_count: 0,
            release_hold_count: 1,
            roots_only_privacy_count: 0,
            pq_control_count: 0,
            matrix_status,
            verdict_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "threat_count": self.threat_count,
            "accept_count": self.accept_count,
            "hold_count": self.hold_count,
            "reject_count": self.reject_count,
            "release_hold_count": self.release_hold_count,
            "roots_only_privacy_count": self.roots_only_privacy_count,
            "pq_control_count": self.pq_control_count,
            "matrix_status": self.matrix_status,
            "verdict_root": self.verdict_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub source_roots: SourceRoots,
    pub criteria: Vec<AcceptanceCriterion>,
    pub verdict: MatrixVerdict,
    pub criteria_root: String,
    pub accept_root: String,
    pub hold_root: String,
    pub reject_root: String,
    pub release_hold_root: String,
    pub matrix_root: String,
}

impl State {
    pub fn new(config: Config, source_roots: SourceRoots) -> Result<Self> {
        validate_config(&config)?;

        let criteria = ThreatCase::ordered()
            .iter()
            .enumerate()
            .map(|(index, threat)| {
                AcceptanceCriterion::devnet(&config, &source_roots, *threat, index as u64 + 1)
            })
            .collect::<Vec<_>>();
        let verdict = MatrixVerdict::new(&config, &criteria);
        let criteria_root = criteria_vector_root(&criteria);
        let accept_root = decision_vector_root(&criteria, AcceptanceDecision::Accept);
        let hold_root = decision_vector_root(&criteria, AcceptanceDecision::Hold);
        let reject_root = decision_vector_root(&criteria, AcceptanceDecision::Reject);
        let release_hold_root = release_hold_root(&config, &source_roots, &criteria, &verdict);
        let matrix_root = matrix_root(
            &config,
            &source_roots,
            &verdict,
            &criteria_root,
            &accept_root,
            &hold_root,
            &reject_root,
            &release_hold_root,
        );

        Ok(Self {
            config,
            source_roots,
            criteria,
            verdict,
            criteria_root,
            accept_root,
            hold_root,
            reject_root,
            release_hold_root,
            matrix_root,
        })
    }

    pub fn devnet() -> Self {
        match Self::new(Config::default(), SourceRoots::devnet()) {
            Ok(state) => state,
            Err(reason) => fallback_state(reason),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_canonical_user_escape_threat_model_acceptance_matrix_runtime",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "config": self.config.public_record(),
            "source_roots": self.source_roots.public_record(),
            "criteria_root": self.criteria_root,
            "accept_root": self.accept_root,
            "hold_root": self.hold_root,
            "reject_root": self.reject_root,
            "release_hold_root": self.release_hold_root,
            "matrix_root": self.matrix_root,
            "verdict": self.verdict.public_record(),
            "criteria": self
                .criteria
                .iter()
                .map(AcceptanceCriterion::public_record)
                .collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(
            "state",
            &json!({
                "chain_id": CHAIN_ID,
                "protocol_version": PROTOCOL_VERSION,
                "config_root": self.config.state_root(),
                "source_root": self.source_roots.state_root(),
                "criteria_root": self.criteria_root,
                "accept_root": self.accept_root,
                "hold_root": self.hold_root,
                "reject_root": self.reject_root,
                "release_hold_root": self.release_hold_root,
                "matrix_root": self.matrix_root,
                "verdict_root": self.verdict.verdict_root,
            }),
        )
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

fn validate_config(config: &Config) -> Result<()> {
    if config.chain_id != CHAIN_ID {
        return Err("config chain id must match crate chain id".to_string());
    }
    if config.min_threat_count < ThreatCase::ordered().len() as u64 {
        return Err("minimum threat count must cover all canonical bridge-exit cases".to_string());
    }
    if config.require_release_held_for_failures != 1 {
        return Err("matrix must require release holds for failure decisions".to_string());
    }
    if config.max_accepted_linkage_fields != 0 {
        return Err("matrix must keep accepted linkage fields at zero".to_string());
    }
    Ok(())
}

fn required_evidence_root(threat: ThreatCase, source: &SourceRoots) -> String {
    match threat {
        ThreatCase::NominalForcedExit => source.wallet_handoff_root.clone(),
        ThreatCase::MoneroReorg => source.reorg_collusion_manifest_root.clone(),
        ThreatCase::WatcherCollusion => {
            crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::state_root(
                &crate::monero_l2_pq_bridge_exit_watcher_bond_slashing_runtime::devnet(),
            )
        }
        ThreatCase::LiquidityExhaustion => source.bridge_spine_root.clone(),
        ThreatCase::StalePqEpoch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()
        }
        ThreatCase::ForgedReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()
        }
        ThreatCase::ReplayNullifierSeparation => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_private_note_transfer_proof_runtime::state_root()
        }
        ThreatCase::MetadataLeakage => source.mismatch_fixture_root.clone(),
        ThreatCase::SequencerUnavailable => source.forced_exit_dry_run_root.clone(),
    }
}

fn process_feed_root(threat: ThreatCase, source: &SourceRoots) -> String {
    match threat {
        ThreatCase::NominalForcedExit => source.process_feed_binding_root.clone(),
        ThreatCase::MoneroReorg => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_monero_watcher_process_feed_runtime::state_root()
        }
        ThreatCase::WatcherCollusion => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_adversarial_process_feed_runtime::state_root()
        }
        ThreatCase::LiquidityExhaustion => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_reserve_process_feed_runtime::state_root()
        }
        ThreatCase::StalePqEpoch => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_pq_authority_process_feed_runtime::state_root()
        }
        ThreatCase::ForgedReceipt => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_receipt_process_feed_runtime::state_root()
        }
        ThreatCase::ReplayNullifierSeparation => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()
        }
        ThreatCase::MetadataLeakage => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_wallet_scanner_process_feed_runtime::state_root()
        }
        ThreatCase::SequencerUnavailable => {
            crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_process_feed_runtime::state_root()
        }
    }
}

fn wallet_visible_root(threat: ThreatCase, source: &SourceRoots) -> String {
    domain_hash(
        &format!("{DOMAIN}:wallet-visible"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(threat.as_str()),
            HashPart::Str(&source.wallet_handoff_root),
            HashPart::Str(&source.forced_exit_dry_run_root),
            HashPart::Str(threat.control_objective()),
        ],
        32,
    )
}

fn privacy_boundary_root(threat: ThreatCase, source: &SourceRoots) -> String {
    domain_hash(
        &format!("{DOMAIN}:privacy-boundary"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(threat.as_str()),
            HashPart::Str(&source.wallet_handoff_root),
            HashPart::Str(&source.mismatch_fixture_root),
            HashPart::U64(0),
        ],
        32,
    )
}

fn pq_control_root(threat: ThreatCase, source: &SourceRoots) -> String {
    domain_hash(
        &format!("{DOMAIN}:pq-control"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(threat.as_str()),
            HashPart::Str(&source.bridge_spine_root),
            HashPart::Str(&source.process_feed_binding_root),
            HashPart::Str(&crate::monero_l2_pq_bridge_exit_canonical_user_escape_release_verification_proof_runtime::state_root()),
            HashPart::U64(256),
        ],
        32,
    )
}

fn criterion_id(threat: ThreatCase, ordinal: u64) -> String {
    domain_hash(
        &format!("{DOMAIN}:criterion-id"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::U64(ordinal),
            HashPart::Str(threat.as_str()),
        ],
        16,
    )
}

fn accept_if(threat: ThreatCase) -> String {
    match threat {
        ThreatCase::NominalForcedExit => {
            "accept when dry-run, wallet handoff, roots-only export, PQ authorization, and release-held roots are all present"
        }
        ThreatCase::MoneroReorg => {
            "accept only after replacement Monero finality proof exceeds quarantine depth and watcher quorum roots agree"
        }
        ThreatCase::WatcherCollusion => {
            "accept only after noncolluding quorum evidence replaces colluding witness roots"
        }
        ThreatCase::LiquidityExhaustion => {
            "accept only after reserve coverage and backstop liquidity roots exceed withdrawal claim exposure"
        }
        ThreatCase::StalePqEpoch => {
            "accept only after PQ rotation, revocation, and fresh authority roots are bound"
        }
        ThreatCase::ForgedReceipt => {
            "accept only after settlement transcript replay root matches wallet-visible receipt root"
        }
        ThreatCase::ReplayNullifierSeparation => {
            "accept only after nullifier fence and private-note recovery roots prove no replay"
        }
        ThreatCase::MetadataLeakage => {
            "accept only after roots-only export and zero linkage-field criteria are restored"
        }
        ThreatCase::SequencerUnavailable => {
            "accept only the forced-exit path, not cooperative release, while sequencer liveness is absent"
        }
    }
    .to_string()
}

fn hold_if(threat: ThreatCase) -> String {
    match threat {
        ThreatCase::NominalForcedExit => "hold if any required dry-run handoff root is missing",
        ThreatCase::MoneroReorg => {
            "hold during finality quarantine or conflicting Monero watcher feeds"
        }
        ThreatCase::WatcherCollusion => {
            "hold while bond challenge, arbitration, and quorum replacement are pending"
        }
        ThreatCase::LiquidityExhaustion => {
            "hold while reserve coverage is below withdrawal exposure"
        }
        ThreatCase::StalePqEpoch => "hold while PQ epoch freshness or revocation evidence is stale",
        ThreatCase::ForgedReceipt => "hold while transcript replay is incomplete",
        ThreatCase::ReplayNullifierSeparation => "hold while wallet recovery roots are incomplete",
        ThreatCase::MetadataLeakage => "hold while redaction proof is under review",
        ThreatCase::SequencerUnavailable => {
            "hold cooperative release while preserving forced-exit wallet commands"
        }
    }
    .to_string()
}

fn reject_if(threat: ThreatCase) -> String {
    match threat {
        ThreatCase::NominalForcedExit => {
            "reject if release becomes allowed before heavy gates execute"
        }
        ThreatCase::MoneroReorg => "reject any release rooted in an orphaned Monero lock",
        ThreatCase::WatcherCollusion => "reject colluding watcher quorum attestations",
        ThreatCase::LiquidityExhaustion => {
            "reject release instructions that exceed reserve coverage"
        }
        ThreatCase::StalePqEpoch => "reject stale or revoked PQ authority signatures",
        ThreatCase::ForgedReceipt => {
            "reject forged settlement receipts and duplicate receipt roots"
        }
        ThreatCase::ReplayNullifierSeparation => {
            "reject replayed withdrawal claims and reused nullifier roots"
        }
        ThreatCase::MetadataLeakage => "reject wallet exports that disclose linkable metadata",
        ThreatCase::SequencerUnavailable => {
            "reject operator-only exits when forced-exit commands are available"
        }
    }
    .to_string()
}

fn count_decision(criteria: &[AcceptanceCriterion], decision: AcceptanceDecision) -> u64 {
    criteria
        .iter()
        .filter(|criterion| criterion.decision == decision)
        .count() as u64
}

fn criteria_vector_root(criteria: &[AcceptanceCriterion]) -> String {
    let leaves = criteria
        .iter()
        .map(AcceptanceCriterion::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:criteria-root"), &leaves)
}

fn decision_vector_root(criteria: &[AcceptanceCriterion], decision: AcceptanceDecision) -> String {
    let leaves = criteria
        .iter()
        .filter(|criterion| criterion.decision == decision)
        .map(AcceptanceCriterion::public_record)
        .collect::<Vec<_>>();
    merkle_root(&format!("{DOMAIN}:{}-root", decision.as_str()), &leaves)
}

fn release_hold_root(
    config: &Config,
    source: &SourceRoots,
    criteria: &[AcceptanceCriterion],
    verdict: &MatrixVerdict,
) -> String {
    let release_hold_leaves = criteria
        .iter()
        .filter(|criterion| criterion.release_hold_required == 1)
        .map(AcceptanceCriterion::public_record)
        .collect::<Vec<_>>();
    let release_hold_leaf_root = merkle_root(
        &format!("{DOMAIN}:release-hold-leaf-root"),
        &release_hold_leaves,
    );

    domain_hash(
        &format!("{DOMAIN}:release-hold"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.acceptance_policy),
            HashPart::Str(&source.source_root),
            HashPart::Str(&release_hold_leaf_root),
            HashPart::Str(&verdict.verdict_root),
            HashPart::U64(verdict.release_hold_count),
            HashPart::U64(config.require_release_held_for_failures),
        ],
        32,
    )
}

fn matrix_root(
    config: &Config,
    source: &SourceRoots,
    verdict: &MatrixVerdict,
    criteria_root: &str,
    accept_root: &str,
    hold_root: &str,
    reject_root: &str,
    release_hold_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:matrix"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(&config.matrix_suite),
            HashPart::Str(&source.source_root),
            HashPart::Str(criteria_root),
            HashPart::Str(accept_root),
            HashPart::Str(hold_root),
            HashPart::Str(reject_root),
            HashPart::Str(release_hold_root),
            HashPart::Str(&verdict.verdict_root),
        ],
        32,
    )
}

fn source_root(
    bridge_spine_root: &str,
    reorg_collusion_manifest_root: &str,
    failure_injection_matrix_root: &str,
    forced_exit_dry_run_root: &str,
    wallet_handoff_root: &str,
    process_feed_binding_root: &str,
    mismatch_fixture_root: &str,
) -> String {
    domain_hash(
        &format!("{DOMAIN}:source"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(bridge_spine_root),
            HashPart::Str(reorg_collusion_manifest_root),
            HashPart::Str(failure_injection_matrix_root),
            HashPart::Str(forced_exit_dry_run_root),
            HashPart::Str(wallet_handoff_root),
            HashPart::Str(process_feed_binding_root),
            HashPart::Str(mismatch_fixture_root),
        ],
        32,
    )
}

fn gap_reason_root(reason: &str) -> String {
    domain_hash(
        &format!("{DOMAIN}:gap-reason"),
        &[HashPart::Str(CHAIN_ID), HashPart::Str(reason)],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        &format!("{DOMAIN}:record"),
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn fallback_state(reason: String) -> State {
    let config = Config::default();
    let source_roots = SourceRoots {
        bridge_spine_root: record_root("fallback-bridge-spine", &json!({ "reason": reason })),
        reorg_collusion_manifest_root: record_root(
            "fallback-reorg-collusion",
            &json!({ "reason": reason }),
        ),
        failure_injection_matrix_root: record_root(
            "fallback-failure-matrix",
            &json!({ "reason": reason }),
        ),
        forced_exit_dry_run_root: record_root("fallback-dry-run", &json!({ "reason": reason })),
        wallet_handoff_root: record_root("fallback-wallet-handoff", &json!({ "reason": reason })),
        process_feed_binding_root: record_root(
            "fallback-process-feed",
            &json!({ "reason": reason }),
        ),
        mismatch_fixture_root: record_root("fallback-mismatch", &json!({ "reason": reason })),
        adversarial_fixture_root: record_root("fallback-adversarial", &json!({ "reason": reason })),
        source_root: record_root("fallback-source", &json!({ "reason": reason })),
    };
    let criteria = Vec::new();
    let verdict = MatrixVerdict::fallback(&config, &reason);
    let criteria_root = criteria_vector_root(&criteria);
    let accept_root = decision_vector_root(&criteria, AcceptanceDecision::Accept);
    let hold_root = decision_vector_root(&criteria, AcceptanceDecision::Hold);
    let reject_root = decision_vector_root(&criteria, AcceptanceDecision::Reject);
    let release_hold_root = release_hold_root(&config, &source_roots, &criteria, &verdict);
    let matrix_root = matrix_root(
        &config,
        &source_roots,
        &verdict,
        &criteria_root,
        &accept_root,
        &hold_root,
        &reject_root,
        &release_hold_root,
    );

    State {
        config,
        source_roots,
        criteria,
        verdict,
        criteria_root,
        accept_root,
        hold_root,
        reject_root,
        release_hold_root,
        matrix_root,
    }
}
