use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitVerticalSliceReleaseCandidateScorecardRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_RELEASE_CANDIDATE_SCORECARD_RUNTIME_PROTOCOL_VERSION:
    &str = "nebula-monero-l2-pq-bridge-exit-vertical-slice-release-candidate-scorecard-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_VERTICAL_SLICE_RELEASE_CANDIDATE_SCORECARD_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const SCORECARD_SUITE: &str =
    "monero-l2-pq-bridge-exit-vertical-slice-release-candidate-scorecard-v1";
pub const DEFAULT_MIN_REQUIRED_GATES: u64 = 14;
pub const DEFAULT_MIN_PASSING_GATES: u64 = 10;
pub const DEFAULT_MAX_WATCH_GATES: u64 = 4;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 64;
pub const DEFAULT_MAX_SCORECARDS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScorecardDomain {
    DepositAdmission,
    PrivateNoteTransition,
    PrivateContractAction,
    SettlementReceipt,
    ForcedExitExecution,
    DisputeLiveness,
    SequencerShutdownEscape,
    LiquidityExhaustionRecovery,
    MoneroReorgHandling,
    WatcherCollusionHandling,
    PqAuthorityRotation,
    WalletRecovery,
    PrivacyLeakRegression,
    LowFeeBound,
    CargoRuntimeExecution,
    SecurityAuditSignoff,
}

impl ScorecardDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmission => "deposit_admission",
            Self::PrivateNoteTransition => "private_note_transition",
            Self::PrivateContractAction => "private_contract_action",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedExitExecution => "forced_exit_execution",
            Self::DisputeLiveness => "dispute_liveness",
            Self::SequencerShutdownEscape => "sequencer_shutdown_escape",
            Self::LiquidityExhaustionRecovery => "liquidity_exhaustion_recovery",
            Self::MoneroReorgHandling => "monero_reorg_handling",
            Self::WatcherCollusionHandling => "watcher_collusion_handling",
            Self::PqAuthorityRotation => "pq_authority_rotation",
            Self::WalletRecovery => "wallet_recovery",
            Self::PrivacyLeakRegression => "privacy_leak_regression",
            Self::LowFeeBound => "low_fee_bound",
            Self::CargoRuntimeExecution => "cargo_runtime_execution",
            Self::SecurityAuditSignoff => "security_audit_signoff",
        }
    }

    pub fn is_user_exit_domain(self) -> bool {
        matches!(
            self,
            Self::ForcedExitExecution
                | Self::DisputeLiveness
                | Self::SequencerShutdownEscape
                | Self::LiquidityExhaustionRecovery
                | Self::MoneroReorgHandling
                | Self::WatcherCollusionHandling
                | Self::WalletRecovery
        )
    }

    pub fn is_production_gate(self) -> bool {
        matches!(
            self,
            Self::DepositAdmission
                | Self::PrivateNoteTransition
                | Self::SettlementReceipt
                | Self::ForcedExitExecution
                | Self::DisputeLiveness
                | Self::SequencerShutdownEscape
                | Self::LiquidityExhaustionRecovery
                | Self::MoneroReorgHandling
                | Self::WatcherCollusionHandling
                | Self::PqAuthorityRotation
                | Self::PrivacyLeakRegression
                | Self::CargoRuntimeExecution
                | Self::SecurityAuditSignoff
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Passing,
    Watch,
    Missing,
    Failed,
    Deferred,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passing => "passing",
            Self::Watch => "watch",
            Self::Missing => "missing",
            Self::Failed => "failed",
            Self::Deferred => "deferred",
        }
    }

    pub fn blocks_execution(self) -> bool {
        matches!(self, Self::Missing | Self::Failed)
    }

    pub fn blocks_production(self) -> bool {
        matches!(
            self,
            Self::Watch | Self::Missing | Self::Failed | Self::Deferred
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Pass,
    Watch,
    Blocked,
    Deferred,
}

impl GateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
            Self::Deferred => "deferred",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseCandidateStatus {
    ReadyForDryRun,
    WatchOnly,
    Blocked,
}

impl ReleaseCandidateStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyForDryRun => "ready_for_dry_run",
            Self::WatchOnly => "watch_only",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    MissingCargoExecution,
    MissingBaseLayerVerifier,
    IncompleteThreatModel,
    WeakPqControlPlane,
    WeakPrivacyEvidence,
    WeakLiquidityEvidence,
    UnprovenForcedExit,
    AuditSignoffMissing,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingCargoExecution => "missing_cargo_execution",
            Self::MissingBaseLayerVerifier => "missing_base_layer_verifier",
            Self::IncompleteThreatModel => "incomplete_threat_model",
            Self::WeakPqControlPlane => "weak_pq_control_plane",
            Self::WeakPrivacyEvidence => "weak_privacy_evidence",
            Self::WeakLiquidityEvidence => "weak_liquidity_evidence",
            Self::UnprovenForcedExit => "unproven_forced_exit",
            Self::AuditSignoffMissing => "audit_signoff_missing",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub scorecard_suite: String,
    pub min_required_gates: u64,
    pub min_passing_gates: u64,
    pub max_watch_gates: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
    pub max_scorecards: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            scorecard_suite: SCORECARD_SUITE.to_string(),
            min_required_gates: DEFAULT_MIN_REQUIRED_GATES,
            min_passing_gates: DEFAULT_MIN_PASSING_GATES,
            max_watch_gates: DEFAULT_MAX_WATCH_GATES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            cargo_checks_deferred: true,
            production_release_allowed: false,
            max_scorecards: DEFAULT_MAX_SCORECARDS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "scorecard_suite": self.scorecard_suite,
            "min_required_gates": self.min_required_gates,
            "min_passing_gates": self.min_passing_gates,
            "max_watch_gates": self.max_watch_gates,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_scorecards": self.max_scorecards,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScorecardEvidence {
    pub evidence_id: String,
    pub domain: ScorecardDomain,
    pub status: EvidenceStatus,
    pub source_runtime: String,
    pub source_root: String,
    pub claim: String,
    pub observation: String,
    pub public_commitment_root: String,
    pub private_commitment_root: String,
    pub wallet_scan_root: String,
    pub pq_attestation_root: String,
    pub low_fee_bound_bps: u64,
    pub privacy_set_size: u64,
    pub cargo_execution_required: bool,
    pub user_exit_continuity_preserved: bool,
    pub production_blocker: Option<ProductionBlockerKind>,
    pub evidence_root: String,
}

impl ScorecardEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: ScorecardDomain,
        status: EvidenceStatus,
        source_runtime: impl Into<String>,
        source_root: impl Into<String>,
        claim: impl Into<String>,
        observation: impl Into<String>,
        low_fee_bound_bps: u64,
        privacy_set_size: u64,
        cargo_execution_required: bool,
        user_exit_continuity_preserved: bool,
        production_blocker: Option<ProductionBlockerKind>,
    ) -> Self {
        let source_runtime = source_runtime.into();
        let source_root = source_root.into();
        let claim = claim.into();
        let observation = observation.into();
        let evidence_id = evidence_id(domain, &source_runtime, &claim);
        let public_commitment_root =
            public_commitment_root(domain, status, &source_runtime, &source_root, &claim);
        let private_commitment_root =
            private_commitment_root(domain, &evidence_id, &observation, privacy_set_size);
        let wallet_scan_root = wallet_scan_root(domain, &evidence_id, privacy_set_size);
        let pq_attestation_root = pq_attestation_root(domain, &source_runtime, &source_root);
        let public_record = json!({
            "evidence_id": evidence_id,
            "domain": domain.as_str(),
            "status": status.as_str(),
            "source_runtime": source_runtime,
            "source_root": source_root,
            "claim": claim,
            "observation": observation,
            "public_commitment_root": public_commitment_root,
            "private_commitment_root": private_commitment_root,
            "wallet_scan_root": wallet_scan_root,
            "pq_attestation_root": pq_attestation_root,
            "low_fee_bound_bps": low_fee_bound_bps,
            "privacy_set_size": privacy_set_size,
            "cargo_execution_required": cargo_execution_required,
            "user_exit_continuity_preserved": user_exit_continuity_preserved,
            "production_blocker": production_blocker.map(ProductionBlockerKind::as_str),
        });
        let evidence_root = record_root("scorecard-evidence", &public_record);

        Self {
            evidence_id,
            domain,
            status,
            source_runtime,
            source_root,
            claim,
            observation,
            public_commitment_root,
            private_commitment_root,
            wallet_scan_root,
            pq_attestation_root,
            low_fee_bound_bps,
            privacy_set_size,
            cargo_execution_required,
            user_exit_continuity_preserved,
            production_blocker,
            evidence_root,
        }
    }

    pub fn gate_status(&self, config: &Config) -> GateStatus {
        if self.status == EvidenceStatus::Deferred {
            return GateStatus::Deferred;
        }
        if self.status.blocks_execution()
            || self.low_fee_bound_bps > config.max_user_fee_bps
            || self.privacy_set_size < config.min_privacy_set_size
            || (self.domain.is_user_exit_domain() && !self.user_exit_continuity_preserved)
        {
            return GateStatus::Blocked;
        }
        if self.status == EvidenceStatus::Watch || self.production_blocker.is_some() {
            return GateStatus::Watch;
        }
        GateStatus::Pass
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_id": self.evidence_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "source_runtime": self.source_runtime,
            "source_root": self.source_root,
            "claim": self.claim,
            "observation": self.observation,
            "public_commitment_root": self.public_commitment_root,
            "private_commitment_root": self.private_commitment_root,
            "wallet_scan_root": self.wallet_scan_root,
            "pq_attestation_root": self.pq_attestation_root,
            "low_fee_bound_bps": self.low_fee_bound_bps,
            "privacy_set_size": self.privacy_set_size,
            "cargo_execution_required": self.cargo_execution_required,
            "user_exit_continuity_preserved": self.user_exit_continuity_preserved,
            "production_blocker": self.production_blocker.map(ProductionBlockerKind::as_str),
            "evidence_root": self.evidence_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GateAssessment {
    pub gate_id: String,
    pub domain: ScorecardDomain,
    pub status: GateStatus,
    pub requirement: String,
    pub evidence_root: String,
    pub source_runtime: String,
    pub blocks_user_exit: bool,
    pub blocks_dry_run: bool,
    pub blocks_production: bool,
    pub remediation_hint: String,
    pub gate_root: String,
}

impl GateAssessment {
    pub fn from_evidence(config: &Config, evidence: &ScorecardEvidence) -> Self {
        let status = evidence.gate_status(config);
        let blocks_user_exit = evidence.domain.is_user_exit_domain()
            && (status == GateStatus::Blocked || !evidence.user_exit_continuity_preserved);
        let blocks_dry_run = status == GateStatus::Blocked;
        let blocks_production = evidence.domain.is_production_gate()
            && (status != GateStatus::Pass
                || evidence.status.blocks_production()
                || evidence.production_blocker.is_some()
                || config.cargo_checks_deferred);
        let requirement = gate_requirement(evidence.domain);
        let remediation_hint =
            remediation_hint(evidence.domain, status, evidence.production_blocker);
        let gate_id = gate_id(evidence.domain, &evidence.evidence_root);
        let public_record = json!({
            "gate_id": gate_id,
            "domain": evidence.domain.as_str(),
            "status": status.as_str(),
            "requirement": requirement,
            "evidence_root": evidence.evidence_root,
            "source_runtime": evidence.source_runtime,
            "blocks_user_exit": blocks_user_exit,
            "blocks_dry_run": blocks_dry_run,
            "blocks_production": blocks_production,
            "remediation_hint": remediation_hint,
        });
        let gate_root = record_root("scorecard-gate", &public_record);

        Self {
            gate_id,
            domain: evidence.domain,
            status,
            requirement,
            evidence_root: evidence.evidence_root.clone(),
            source_runtime: evidence.source_runtime.clone(),
            blocks_user_exit,
            blocks_dry_run,
            blocks_production,
            remediation_hint,
            gate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "requirement": self.requirement,
            "evidence_root": self.evidence_root,
            "source_runtime": self.source_runtime,
            "blocks_user_exit": self.blocks_user_exit,
            "blocks_dry_run": self.blocks_dry_run,
            "blocks_production": self.blocks_production,
            "remediation_hint": self.remediation_hint,
            "gate_root": self.gate_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScorecardCounters {
    pub total_gates: u64,
    pub passing_gates: u64,
    pub watch_gates: u64,
    pub blocked_gates: u64,
    pub deferred_gates: u64,
    pub production_blockers: u64,
    pub user_exit_blockers: u64,
    pub cargo_execution_required: u64,
}

impl ScorecardCounters {
    pub fn from_gates(evidence: &[ScorecardEvidence], gates: &[GateAssessment]) -> Self {
        let mut counters = Self {
            total_gates: gates.len() as u64,
            ..Self::default()
        };

        for gate in gates {
            match gate.status {
                GateStatus::Pass => counters.passing_gates += 1,
                GateStatus::Watch => counters.watch_gates += 1,
                GateStatus::Blocked => counters.blocked_gates += 1,
                GateStatus::Deferred => counters.deferred_gates += 1,
            }
            if gate.blocks_production {
                counters.production_blockers += 1;
            }
            if gate.blocks_user_exit {
                counters.user_exit_blockers += 1;
            }
        }

        counters.cargo_execution_required = evidence
            .iter()
            .filter(|item| item.cargo_execution_required)
            .count() as u64;
        counters
    }

    pub fn public_record(&self) -> Value {
        json!({
            "total_gates": self.total_gates,
            "passing_gates": self.passing_gates,
            "watch_gates": self.watch_gates,
            "blocked_gates": self.blocked_gates,
            "deferred_gates": self.deferred_gates,
            "production_blockers": self.production_blockers,
            "user_exit_blockers": self.user_exit_blockers,
            "cargo_execution_required": self.cargo_execution_required,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScorecardRoots {
    pub evidence_root: String,
    pub gate_root: String,
    pub counter_root: String,
    pub blocker_root: String,
    pub release_candidate_root: String,
}

impl ScorecardRoots {
    pub fn new(
        evidence: &[ScorecardEvidence],
        gates: &[GateAssessment],
        counters: &ScorecardCounters,
        production_blockers: &[ProductionBlockerKind],
        report_id: &str,
    ) -> Self {
        let evidence_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-scorecard-evidence",
            evidence
                .iter()
                .map(|item| item.evidence_root.clone())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let gate_root = merkle_root(
            "monero-l2-pq-bridge-exit-release-scorecard-gates",
            gates
                .iter()
                .map(|item| item.gate_root.clone())
                .collect::<Vec<_>>()
                .as_slice(),
        );
        let counter_root = record_root("scorecard-counters", &counters.public_record());
        let blocker_root = blocker_root(production_blockers);
        let release_candidate_root = domain_hash(
            "monero-l2-pq-bridge-exit-release-scorecard-root",
            &[
                HashPart::Str(report_id),
                HashPart::Str(&evidence_root),
                HashPart::Str(&gate_root),
                HashPart::Str(&counter_root),
                HashPart::Str(&blocker_root),
            ],
            32,
        );

        Self {
            evidence_root,
            gate_root,
            counter_root,
            blocker_root,
            release_candidate_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "evidence_root": self.evidence_root,
            "gate_root": self.gate_root,
            "counter_root": self.counter_root,
            "blocker_root": self.blocker_root,
            "release_candidate_root": self.release_candidate_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseCandidateScorecard {
    pub report_id: String,
    pub status: ReleaseCandidateStatus,
    pub dry_run_allowed: bool,
    pub production_release_allowed: bool,
    pub cargo_checks_deferred: bool,
    pub human_signoff_required: bool,
    pub counters: ScorecardCounters,
    pub production_blockers: Vec<ProductionBlockerKind>,
    pub gates: Vec<GateAssessment>,
    pub roots: ScorecardRoots,
    pub operator_summary: String,
}

impl ReleaseCandidateScorecard {
    pub fn from_evidence(config: &Config, evidence: &[ScorecardEvidence]) -> Self {
        let gates = evidence
            .iter()
            .map(|item| GateAssessment::from_evidence(config, item))
            .collect::<Vec<_>>();
        let counters = ScorecardCounters::from_gates(evidence, &gates);
        let production_blockers = production_blockers(config, evidence, &gates);
        let dry_run_allowed = counters.total_gates >= config.min_required_gates
            && counters.passing_gates >= config.min_passing_gates
            && counters.watch_gates <= config.max_watch_gates
            && counters.blocked_gates == 0
            && counters.user_exit_blockers == 0;
        let production_release_allowed = dry_run_allowed
            && production_blockers.is_empty()
            && !config.cargo_checks_deferred
            && config.production_release_allowed;
        let status = if dry_run_allowed {
            ReleaseCandidateStatus::ReadyForDryRun
        } else if counters.blocked_gates == 0 && counters.user_exit_blockers == 0 {
            ReleaseCandidateStatus::WatchOnly
        } else {
            ReleaseCandidateStatus::Blocked
        };
        let report_id = scorecard_report_id(&config.chain_id, counters.total_gates, &status);
        let roots = ScorecardRoots::new(
            evidence,
            &gates,
            &counters,
            &production_blockers,
            &report_id,
        );
        let operator_summary = operator_summary(status, &counters, &production_blockers);

        Self {
            report_id,
            status,
            dry_run_allowed,
            production_release_allowed,
            cargo_checks_deferred: config.cargo_checks_deferred,
            human_signoff_required: true,
            counters,
            production_blockers,
            gates,
            roots,
            operator_summary,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "status": self.status.as_str(),
            "dry_run_allowed": self.dry_run_allowed,
            "production_release_allowed": self.production_release_allowed,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "human_signoff_required": self.human_signoff_required,
            "counters": self.counters.public_record(),
            "production_blockers": self.production_blockers.iter().map(|item| item.as_str()).collect::<Vec<_>>(),
            "gates": self.gates.iter().map(GateAssessment::public_record).collect::<Vec<_>>(),
            "roots": self.roots.public_record(),
            "operator_summary": self.operator_summary,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub evidence: Vec<ScorecardEvidence>,
    pub latest_scorecard: ReleaseCandidateScorecard,
    pub scorecard_history: Vec<ReleaseCandidateScorecard>,
}

impl State {
    pub fn new(config: Config, evidence: Vec<ScorecardEvidence>) -> Self {
        let latest_scorecard = ReleaseCandidateScorecard::from_evidence(&config, &evidence);
        Self {
            config,
            evidence,
            latest_scorecard: latest_scorecard.clone(),
            scorecard_history: vec![latest_scorecard],
        }
    }

    pub fn ingest_evidence(&mut self, evidence: ScorecardEvidence) -> Result<String> {
        self.evidence.retain(|item| item.domain != evidence.domain);
        self.evidence.push(evidence);
        self.evidence.sort_by_key(|item| item.domain);
        let scorecard = ReleaseCandidateScorecard::from_evidence(&self.config, &self.evidence);
        let report_id = scorecard.report_id.clone();
        self.latest_scorecard = scorecard.clone();
        self.scorecard_history.push(scorecard);
        if self.scorecard_history.len() > self.config.max_scorecards {
            let overflow = self.scorecard_history.len() - self.config.max_scorecards;
            self.scorecard_history.drain(0..overflow);
        }
        Ok(report_id)
    }

    pub fn gate_map(&self) -> BTreeMap<String, Value> {
        self.latest_scorecard
            .gates
            .iter()
            .map(|gate| (gate.domain.as_str().to_string(), gate.public_record()))
            .collect()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config": self.config.public_record(),
            "evidence": self.evidence.iter().map(ScorecardEvidence::public_record).collect::<Vec<_>>(),
            "latest_scorecard": self.latest_scorecard.public_record(),
            "scorecard_history_len": self.scorecard_history.len(),
            "gate_map": self.gate_map(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }
}

pub fn devnet() -> State {
    let config = Config::devnet();
    State::new(config, default_evidence())
}

pub fn default_evidence() -> Vec<ScorecardEvidence> {
    vec![
        ScorecardEvidence::new(
            ScorecardDomain::DepositAdmission,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_deposit_admission_contract_runtime",
            "deposit-admission-state-root",
            "deposit locks are finality checked before minting a private L2 note",
            "lock observation, watcher certificate, privacy set, and low-fee bound are present",
            18,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::PrivateNoteTransition,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_private_note_state_transition_contract_runtime",
            "private-note-transition-state-root",
            "private note state transition preserves encrypted receipt and nullifier continuity",
            "deposit note, private action receipt, wallet hint, and forced-exit continuity roots are present",
            20,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::PrivateContractAction,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_adversarial_vertical_slice_corridor_runtime",
            "adversarial-corridor-state-root",
            "one minimal private contract action is represented in the corridor receipt",
            "contract action is bound by receipt roots but still needs an executable runtime assertion",
            24,
            80,
            true,
            true,
            Some(ProductionBlockerKind::MissingCargoExecution),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::SettlementReceipt,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_live_settlement_execution_contract_runtime",
            "live-settlement-state-root",
            "settlement receipt links private action output to the withdrawal/exit claim lane",
            "settlement contract report roots and release claim roots are present",
            21,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::ForcedExitExecution,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_forced_exit_user_recovery_playbook_runtime",
            "forced-exit-recovery-state-root",
            "user can construct a forced-exit package if sequencer and watchers misbehave",
            "playbook exists and must still be executed under a runtime harness",
            23,
            80,
            true,
            true,
            Some(ProductionBlockerKind::UnprovenForcedExit),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::DisputeLiveness,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_dispute_liveness_arbitration_contract_runtime",
            "dispute-liveness-state-root",
            "challenge windows and watcher evidence produce a user escape outcome",
            "arbitration cases, liveness timers, evidence roots, and escape outcomes are present",
            18,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::SequencerShutdownEscape,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_sequencer_shutdown_escape_contract_runtime",
            "sequencer-shutdown-state-root",
            "fallback availability and forced-exit lanes remain available after sequencer shutdown",
            "shutdown evidence, fallback DA, emergency quorum, and handoff roots are present",
            19,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::LiquidityExhaustionRecovery,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_liquidity_exhaustion_recovery_contract_runtime",
            "liquidity-exhaustion-state-root",
            "partial settlement and reserve recovery preserve user exit continuity",
            "reserve/backstop/auction paths exist but live liquidity evidence remains simulated",
            25,
            80,
            true,
            true,
            Some(ProductionBlockerKind::WeakLiquidityEvidence),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::MoneroReorgHandling,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_reorg_collusion_threat_model_manifest_runtime",
            "reorg-collusion-threat-model-state-root",
            "Monero reorg risk is explicit and blocks production when base-layer verifier assumptions are missing",
            "threat model records the no-base-layer-verifier residual risk",
            18,
            96,
            false,
            true,
            Some(ProductionBlockerKind::MissingBaseLayerVerifier),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::WatcherCollusionHandling,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_dispute_liveness_arbitration_contract_runtime",
            "watcher-collusion-evidence-root",
            "watcher collusion evidence feeds arbitration and slashing surfaces",
            "collusion evidence kinds and emergency release outcomes are present",
            18,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::PqAuthorityRotation,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_pq_authority_verification_contract_runtime",
            "pq-authority-verification-state-root",
            "post-quantum bridge authority verification gates release and upgrade control",
            "verification contracts exist but key rotation rehearsal remains deferred",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::WeakPqControlPlane),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::WalletRecovery,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_wallet_receipt_privacy_fixture_runtime",
            "wallet-receipt-privacy-state-root",
            "wallet can recover encrypted receipt roots without exposing linkage metadata",
            "wallet receipt privacy fixture and scan hints are present",
            18,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::PrivacyLeakRegression,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_wallet_receipt_privacy_fixture_runtime",
            "privacy-regression-state-root",
            "deposit, transfer, settlement, and forced-exit disclosure modes remain unlinkable within budget",
            "fixture exists but the leak regression matrix is not yet executable",
            18,
            80,
            true,
            true,
            Some(ProductionBlockerKind::WeakPrivacyEvidence),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::LowFeeBound,
            EvidenceStatus::Passing,
            "monero_l2_pq_bridge_exit_adversarial_vertical_slice_corridor_runtime",
            "low-fee-bound-state-root",
            "user escape and settlement lanes preserve the low-fee cap",
            "corridor and liquidity surfaces keep fee bounds below the configured cap",
            24,
            96,
            false,
            true,
            None,
        ),
        ScorecardEvidence::new(
            ScorecardDomain::CargoRuntimeExecution,
            EvidenceStatus::Deferred,
            "monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime",
            "cargo-runtime-harness-state-root",
            "the vertical slice must execute under cargo test/check before production readiness can rise",
            "cargo checks are intentionally deferred by workflow policy for this wave",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::MissingCargoExecution),
        ),
        ScorecardEvidence::new(
            ScorecardDomain::SecurityAuditSignoff,
            EvidenceStatus::Watch,
            "monero_l2_pq_bridge_exit_security_audit_signoff_manifest_runtime",
            "security-audit-signoff-state-root",
            "bridge/exit release requires human security and privacy signoff",
            "audit manifest exists but signoff remains non-production",
            18,
            96,
            true,
            true,
            Some(ProductionBlockerKind::AuditSignoffMissing),
        ),
    ]
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn evidence_id(domain: ScorecardDomain, source_runtime: &str, claim: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-evidence-id",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(claim),
        ],
        16,
    )
}

pub fn gate_id(domain: ScorecardDomain, evidence_root: &str) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-gate-id",
        &[HashPart::Str(domain.as_str()), HashPart::Str(evidence_root)],
        16,
    )
}

pub fn scorecard_report_id(
    chain_id: &str,
    total_gates: u64,
    status: &ReleaseCandidateStatus,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-report-id",
        &[
            HashPart::Str(chain_id),
            HashPart::U64(total_gates),
            HashPart::Str(status.as_str()),
        ],
        16,
    )
}

pub fn public_commitment_root(
    domain: ScorecardDomain,
    status: EvidenceStatus,
    source_runtime: &str,
    source_root: &str,
    claim: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-public-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_root),
            HashPart::Str(claim),
        ],
        32,
    )
}

pub fn private_commitment_root(
    domain: ScorecardDomain,
    evidence_id: &str,
    observation: &str,
    privacy_set_size: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-private-commitment",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(evidence_id),
            HashPart::Str(observation),
            HashPart::U64(privacy_set_size),
        ],
        32,
    )
}

pub fn wallet_scan_root(
    domain: ScorecardDomain,
    evidence_id: &str,
    privacy_set_size: u64,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-wallet-scan",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(evidence_id),
            HashPart::U64(privacy_set_size),
        ],
        32,
    )
}

pub fn pq_attestation_root(
    domain: ScorecardDomain,
    source_runtime: &str,
    source_root: &str,
) -> String {
    domain_hash(
        "monero-l2-pq-bridge-exit-scorecard-pq-attestation",
        &[
            HashPart::Str(domain.as_str()),
            HashPart::Str(source_runtime),
            HashPart::Str(source_root),
            HashPart::Str("hybrid-ml-dsa-slh-dsa-control-plane"),
        ],
        32,
    )
}

pub fn blocker_root(blockers: &[ProductionBlockerKind]) -> String {
    let blocker_leaves = blockers
        .iter()
        .map(|item| item.as_str().to_string())
        .collect::<Vec<_>>();
    merkle_root(
        "monero-l2-pq-bridge-exit-scorecard-production-blockers",
        blocker_leaves.as_slice(),
    )
}

pub fn record_root(domain: &str, record: &Value) -> String {
    domain_hash(
        &format!("monero-l2-pq-bridge-exit-scorecard-{domain}"),
        &[HashPart::Json(record)],
        32,
    )
}

pub fn gate_requirement(domain: ScorecardDomain) -> String {
    match domain {
        ScorecardDomain::DepositAdmission => {
            "deposit lock observation, finality, watcher certificate, and note-mint preconditions"
        }
        ScorecardDomain::PrivateNoteTransition => {
            "private note transition, encrypted receipt, nullifier/key-image continuity"
        }
        ScorecardDomain::PrivateContractAction => {
            "one minimal private transfer or contract action bound to the corridor receipt"
        }
        ScorecardDomain::SettlementReceipt => {
            "settlement receipt links private action output to withdrawal or forced-exit claim"
        }
        ScorecardDomain::ForcedExitExecution => {
            "user can force an exit when sequencer, watcher, or liquidity lanes fail"
        }
        ScorecardDomain::DisputeLiveness => {
            "challenge window, liveness timer, watcher evidence, and escape outcome"
        }
        ScorecardDomain::SequencerShutdownEscape => {
            "fallback data availability and emergency forced-exit lane after sequencer shutdown"
        }
        ScorecardDomain::LiquidityExhaustionRecovery => {
            "reserve, backstop, auction, partial settlement ordering, and low-fee cap"
        }
        ScorecardDomain::MoneroReorgHandling => {
            "Monero reorg and no-base-layer-verifier assumptions explicitly block production"
        }
        ScorecardDomain::WatcherCollusionHandling => {
            "watcher collusion evidence feeds dispute, slashing, and emergency release controls"
        }
        ScorecardDomain::PqAuthorityRotation => {
            "PQ sequencer, watcher, bridge release, upgrade, and withdrawal authorities rotate safely"
        }
        ScorecardDomain::WalletRecovery => {
            "wallet reconstructs scan hints, receipt roots, and forced-exit claim data"
        }
        ScorecardDomain::PrivacyLeakRegression => {
            "timing, amount, scan-hint, nullifier, and disclosure-mode leakage remain budgeted"
        }
        ScorecardDomain::LowFeeBound => {
            "deposit, transfer, settlement, and forced-exit lanes stay under the user fee cap"
        }
        ScorecardDomain::CargoRuntimeExecution => {
            "the vertical slice executes under deferred cargo/runtime harness gates"
        }
        ScorecardDomain::SecurityAuditSignoff => {
            "human security and privacy review explicitly signs or blocks release"
        }
    }
    .to_string()
}

pub fn remediation_hint(
    domain: ScorecardDomain,
    status: GateStatus,
    blocker: Option<ProductionBlockerKind>,
) -> String {
    if status == GateStatus::Pass {
        return format!(
            "{} evidence is sufficient for the next dry-run gate",
            domain.as_str()
        );
    }

    match blocker {
        Some(ProductionBlockerKind::MissingCargoExecution) => {
            "resume cargo/runtime harness execution and bind the result root into this scorecard"
        }
        Some(ProductionBlockerKind::MissingBaseLayerVerifier) => {
            "keep production blocked until Monero verification assumptions are explicitly replaced by a trust-minimized evidence policy"
        }
        Some(ProductionBlockerKind::IncompleteThreatModel) => {
            "expand threat-model coverage and require a residual-risk owner before dry-run"
        }
        Some(ProductionBlockerKind::WeakPqControlPlane) => {
            "run a PQ authority rotation drill with rollback and quarantine evidence"
        }
        Some(ProductionBlockerKind::WeakPrivacyEvidence) => {
            "execute the privacy leak regression matrix and bind its redaction-budget root"
        }
        Some(ProductionBlockerKind::WeakLiquidityEvidence) => {
            "bind live reserve, backstop, and auction fallback evidence before production"
        }
        Some(ProductionBlockerKind::UnprovenForcedExit) => {
            "execute a forced-exit recovery drill from wallet-local data only"
        }
        Some(ProductionBlockerKind::AuditSignoffMissing) => {
            "collect security and privacy signoff after runtime execution evidence is present"
        }
        None => "replace watch or missing evidence with a passing source runtime root",
    }
    .to_string()
}

pub fn production_blockers(
    config: &Config,
    evidence: &[ScorecardEvidence],
    gates: &[GateAssessment],
) -> Vec<ProductionBlockerKind> {
    let mut blockers = BTreeMap::<String, ProductionBlockerKind>::new();

    if config.cargo_checks_deferred {
        blockers.insert(
            ProductionBlockerKind::MissingCargoExecution
                .as_str()
                .to_string(),
            ProductionBlockerKind::MissingCargoExecution,
        );
    }
    if !config.production_release_allowed {
        blockers.insert(
            ProductionBlockerKind::AuditSignoffMissing
                .as_str()
                .to_string(),
            ProductionBlockerKind::AuditSignoffMissing,
        );
    }

    for item in evidence {
        if let Some(blocker) = item.production_blocker {
            blockers.insert(blocker.as_str().to_string(), blocker);
        }
        if item.domain == ScorecardDomain::MoneroReorgHandling
            && item.status != EvidenceStatus::Passing
        {
            blockers.insert(
                ProductionBlockerKind::MissingBaseLayerVerifier
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::MissingBaseLayerVerifier,
            );
        }
        if item.domain == ScorecardDomain::PrivacyLeakRegression
            && item.status != EvidenceStatus::Passing
        {
            blockers.insert(
                ProductionBlockerKind::WeakPrivacyEvidence
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::WeakPrivacyEvidence,
            );
        }
        if item.domain == ScorecardDomain::PqAuthorityRotation
            && item.status != EvidenceStatus::Passing
        {
            blockers.insert(
                ProductionBlockerKind::WeakPqControlPlane
                    .as_str()
                    .to_string(),
                ProductionBlockerKind::WeakPqControlPlane,
            );
        }
    }

    if gates.iter().any(|gate| gate.blocks_user_exit) {
        blockers.insert(
            ProductionBlockerKind::UnprovenForcedExit
                .as_str()
                .to_string(),
            ProductionBlockerKind::UnprovenForcedExit,
        );
    }

    blockers.into_values().collect()
}

pub fn operator_summary(
    status: ReleaseCandidateStatus,
    counters: &ScorecardCounters,
    blockers: &[ProductionBlockerKind],
) -> String {
    let blocker_labels = blockers
        .iter()
        .map(|item| item.as_str())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "status={} gates={} passing={} watch={} blocked={} deferred={} production_blockers=[{}]",
        status.as_str(),
        counters.total_gates,
        counters.passing_gates,
        counters.watch_gates,
        counters.blocked_gates,
        counters.deferred_gates,
        blocker_labels
    )
}
