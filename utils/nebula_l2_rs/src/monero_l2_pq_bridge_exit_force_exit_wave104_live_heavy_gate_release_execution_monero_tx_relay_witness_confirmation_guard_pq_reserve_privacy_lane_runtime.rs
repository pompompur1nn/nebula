use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-pq-reserve-privacy-lane-runtime-v1";
const WAVE: u64 = 104;
const BROADCAST_QUARANTINE_WAVE: u64 = 103;
const MIN_WITNESS_CONFIRMATIONS: u64 = 720;
const MIN_CONFIRMATION_LADDER_RUNG: u64 = 6;
const MIN_REORG_MONITOR_DEPTH: u64 = 720;
const LANE_ID: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-pq-reserve-privacy";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, RelayWitnessConfirmationError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayWitnessConfirmationError {
    LaneMissing,
    ConfirmationCheckpointMissing,
    Wave103BroadcastQuarantineRootMissing,
    ReserveAuthorizationRootMissing,
    PrivacyBudgetRootMissing,
    RelayWitnessRootMissing,
    MempoolAcceptanceRootMissing,
    TxidCommitmentRootMissing,
    BlockInclusionCandidateRootMissing,
    ConfirmationLadderRootMissing,
    ReorgMonitorRootMissing,
    HybridPqAuthorizationRootMissing,
    CircuitBreakerRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    WitnessConfirmationsTooLow,
    ConfirmationLadderRungTooLow,
    ReorgMonitorDepthTooLow,
    ConfirmationStillBlocked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKind {
    PqReservePrivacy,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqReservePrivacy => "pq_reserve_privacy",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::PqReservePrivacy => "PQ reserve privacy relay witness confirmation guard",
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::PqReservePrivacy => "pq-reserve-privacy-relay-witness-confirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationStatus {
    Empty,
    Blocked,
    QuarantineRooted,
    WitnessObserved,
    InclusionCandidate,
    Confirmable,
}

impl ConfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::QuarantineRooted => "quarantine_rooted",
            Self::WitnessObserved => "witness_observed",
            Self::InclusionCandidate => "inclusion_candidate",
            Self::Confirmable => "confirmable",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationBlockerKind {
    MissingWave103BroadcastQuarantineRoot,
    MissingReserveAuthorizationRoot,
    MissingPrivacyBudgetRoot,
    MissingRelayWitnessRoot,
    MissingMempoolAcceptanceRoot,
    MissingTxidCommitmentRoot,
    MissingBlockInclusionCandidateRoot,
    MissingConfirmationLadderRoot,
    MissingReorgMonitorRoot,
    MissingHybridPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingLiveHeavyGateEvidenceRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    WitnessConfirmationsTooLow,
    ConfirmationLadderRungTooLow,
    ReorgMonitorDepthTooLow,
    CircuitBreakerArmed,
    ConfirmationDisabled,
    ReleaseCreditDisabled,
    HeavyGatesNotRun,
    RootsOnlyBoundary,
}

impl ConfirmationBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave103BroadcastQuarantineRoot => {
                "missing_wave103_broadcast_quarantine_root"
            }
            Self::MissingReserveAuthorizationRoot => "missing_reserve_authorization_root",
            Self::MissingPrivacyBudgetRoot => "missing_privacy_budget_root",
            Self::MissingRelayWitnessRoot => "missing_relay_witness_root",
            Self::MissingMempoolAcceptanceRoot => "missing_mempool_acceptance_root",
            Self::MissingTxidCommitmentRoot => "missing_txid_commitment_root",
            Self::MissingBlockInclusionCandidateRoot => "missing_block_inclusion_candidate_root",
            Self::MissingConfirmationLadderRoot => "missing_confirmation_ladder_root",
            Self::MissingReorgMonitorRoot => "missing_reorg_monitor_root",
            Self::MissingHybridPqAuthorizationRoot => {
                "missing_hybrid_ml_dsa_slh_dsa_pq_authorization_root"
            }
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::WitnessConfirmationsTooLow => "witness_confirmations_too_low",
            Self::ConfirmationLadderRungTooLow => "confirmation_ladder_rung_too_low",
            Self::ReorgMonitorDepthTooLow => "reorg_monitor_depth_too_low",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ConfirmationDisabled => "confirmation_disabled",
            Self::ReleaseCreditDisabled => "release_credit_disabled",
            Self::HeavyGatesNotRun => "heavy_gates_not_run",
            Self::RootsOnlyBoundary => "roots_only_boundary",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub broadcast_quarantine_wave: u64,
    pub lane_id: String,
    pub active_lane: String,
    pub min_witness_confirmations: u64,
    pub min_confirmation_ladder_rung: u64,
    pub min_reorg_monitor_depth: u64,
    pub require_wave103_broadcast_quarantine_root: bool,
    pub require_reserve_authorization_root: bool,
    pub require_privacy_budget_root: bool,
    pub require_relay_witness_root: bool,
    pub require_mempool_acceptance_root: bool,
    pub require_txid_commitment_root: bool,
    pub require_block_inclusion_candidate_root: bool,
    pub require_confirmation_ladder_root: bool,
    pub require_reorg_monitor_root: bool,
    pub require_hybrid_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_live_heavy_gate_evidence: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
    pub roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            broadcast_quarantine_wave: BROADCAST_QUARANTINE_WAVE,
            lane_id: LANE_ID.to_string(),
            active_lane: LaneKind::PqReservePrivacy.as_str().to_string(),
            min_witness_confirmations: MIN_WITNESS_CONFIRMATIONS,
            min_confirmation_ladder_rung: MIN_CONFIRMATION_LADDER_RUNG,
            min_reorg_monitor_depth: MIN_REORG_MONITOR_DEPTH,
            require_wave103_broadcast_quarantine_root: true,
            require_reserve_authorization_root: true,
            require_privacy_budget_root: true,
            require_relay_witness_root: true,
            require_mempool_acceptance_root: true,
            require_txid_commitment_root: true,
            require_block_inclusion_candidate_root: true,
            require_confirmation_ladder_root: true,
            require_reorg_monitor_root: true,
            require_hybrid_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_live_heavy_gate_evidence: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            arm_circuit_breaker_by_default: true,
            confirmation_allowed: false,
            release_credit_allowed: false,
            heavy_gates_ran: false,
            roots_only_public_records: true,
        }
    }
}

impl Config {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "wave": self.wave,
            "broadcast_quarantine_wave": self.broadcast_quarantine_wave,
            "lane_id": self.lane_id,
            "active_lane": self.active_lane,
            "min_witness_confirmations": self.min_witness_confirmations,
            "min_confirmation_ladder_rung": self.min_confirmation_ladder_rung,
            "min_reorg_monitor_depth": self.min_reorg_monitor_depth,
            "require_wave103_broadcast_quarantine_root": self.require_wave103_broadcast_quarantine_root,
            "require_reserve_authorization_root": self.require_reserve_authorization_root,
            "require_privacy_budget_root": self.require_privacy_budget_root,
            "require_relay_witness_root": self.require_relay_witness_root,
            "require_mempool_acceptance_root": self.require_mempool_acceptance_root,
            "require_txid_commitment_root": self.require_txid_commitment_root,
            "require_block_inclusion_candidate_root": self.require_block_inclusion_candidate_root,
            "require_confirmation_ladder_root": self.require_confirmation_ladder_root,
            "require_reorg_monitor_root": self.require_reorg_monitor_root,
            "require_hybrid_pq_authorization_root": self.require_hybrid_pq_authorization_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_live_heavy_gate_evidence": self.require_live_heavy_gate_evidence,
            "require_operator_signoff_root": self.require_operator_signoff_root,
            "require_reviewer_signoff_root": self.require_reviewer_signoff_root,
            "arm_circuit_breaker_by_default": self.arm_circuit_breaker_by_default,
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "heavy_gates_ran": self.heavy_gates_ran,
            "roots_only_public_records": self.roots_only_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfirmationRoots {
    pub wave103_broadcast_quarantine_root: Option<String>,
    pub reserve_authorization_root: Option<String>,
    pub privacy_budget_root: Option<String>,
    pub relay_witness_root: Option<String>,
    pub mempool_acceptance_root: Option<String>,
    pub txid_commitment_root: Option<String>,
    pub block_inclusion_candidate_root: Option<String>,
    pub confirmation_ladder_root: Option<String>,
    pub reorg_monitor_root: Option<String>,
    pub hybrid_pq_authorization_root: Option<String>,
    pub circuit_breaker_root: Option<String>,
    pub live_heavy_gate_evidence_root: Option<String>,
    pub operator_signoff_root: Option<String>,
    pub reviewer_signoff_root: Option<String>,
}

impl ConfirmationRoots {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "wave103_broadcast_quarantine_root": self.wave103_broadcast_quarantine_root,
            "reserve_authorization_root": self.reserve_authorization_root,
            "privacy_budget_root": self.privacy_budget_root,
            "relay_witness_root": self.relay_witness_root,
            "mempool_acceptance_root": self.mempool_acceptance_root,
            "txid_commitment_root": self.txid_commitment_root,
            "block_inclusion_candidate_root": self.block_inclusion_candidate_root,
            "confirmation_ladder_root": self.confirmation_ladder_root,
            "reorg_monitor_root": self.reorg_monitor_root,
            "hybrid_ml_dsa_slh_dsa_pq_authorization_root": self.hybrid_pq_authorization_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "live_heavy_gate_evidence_root": self.live_heavy_gate_evidence_root,
            "operator_signoff_root": self.operator_signoff_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("confirmation_roots", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ConfirmationMeasurements {
    pub witness_confirmations: u64,
    pub confirmation_ladder_rung: u64,
    pub reorg_monitor_depth: u64,
}

impl ConfirmationMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            witness_confirmations: config.min_witness_confirmations.saturating_sub(1),
            confirmation_ladder_rung: config.min_confirmation_ladder_rung.saturating_sub(1),
            reorg_monitor_depth: config.min_reorg_monitor_depth.saturating_sub(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "witness_confirmations": self.witness_confirmations,
            "confirmation_ladder_rung": self.confirmation_ladder_rung,
            "reorg_monitor_depth": self.reorg_monitor_depth,
        })
    }

    pub fn state_root(self) -> String {
        record_root("confirmation_measurements", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationPolicy {
    pub lane: LaneKind,
    pub witness_label: String,
    pub ordinal: u64,
    pub command_scope: String,
    pub command_hint: String,
    pub witness_policy_root: String,
    pub reserve_policy_root: String,
    pub privacy_policy_root: String,
    pub confirmation_policy_root: String,
    pub reorg_policy_root: String,
}

impl ConfirmationPolicy {
    pub fn new(lane: LaneKind, witness_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave104 relay-witness-confirmation --lane {} --witness {} --fail-closed",
            lane.as_str(),
            witness_label
        );
        Self {
            lane,
            witness_label: witness_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            witness_policy_root: label_root(
                "witness_policy",
                lane.as_str(),
                witness_label,
                ordinal,
            ),
            reserve_policy_root: label_root(
                "reserve_policy",
                lane.as_str(),
                witness_label,
                ordinal,
            ),
            privacy_policy_root: label_root(
                "privacy_policy",
                lane.as_str(),
                witness_label,
                ordinal,
            ),
            confirmation_policy_root: label_root(
                "confirmation_policy",
                lane.as_str(),
                witness_label,
                ordinal,
            ),
            reorg_policy_root: label_root("reorg_policy", lane.as_str(), witness_label, ordinal),
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "witness_label": self.witness_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "witness_policy_root": self.witness_policy_root,
            "reserve_policy_root": self.reserve_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
            "confirmation_policy_root": self.confirmation_policy_root,
            "reorg_policy_root": self.reorg_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("confirmation_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmationCheckpoint {
    pub lane: LaneKind,
    pub witness_label: String,
    pub ordinal: u64,
    pub roots: ConfirmationRoots,
    pub measurements: ConfirmationMeasurements,
    pub policy: ConfirmationPolicy,
    pub status: ConfirmationStatus,
    pub blockers: Vec<ConfirmationBlockerKind>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
}

impl ConfirmationCheckpoint {
    pub fn empty(lane: LaneKind, witness_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = ConfirmationPolicy::new(lane, witness_label, ordinal);
        Self {
            lane,
            witness_label: witness_label.to_string(),
            ordinal,
            roots: ConfirmationRoots::default(),
            measurements: ConfirmationMeasurements::blocked(config),
            policy,
            status: ConfirmationStatus::Blocked,
            blockers: initial_blockers(config),
            confirmation_allowed: false,
            release_credit_allowed: false,
        }
    }

    pub fn stage_confirmation(
        mut self,
        roots: ConfirmationRoots,
        measurements: ConfirmationMeasurements,
        config: &Config,
    ) -> Self {
        self.roots = roots;
        self.measurements = measurements;
        self.blockers = self.active_blockers(config);
        self.status = if self.blockers.is_empty() {
            ConfirmationStatus::Confirmable
        } else if self.roots.block_inclusion_candidate_root.is_some() {
            ConfirmationStatus::InclusionCandidate
        } else if self.roots.relay_witness_root.is_some() {
            ConfirmationStatus::WitnessObserved
        } else if self.roots.wave103_broadcast_quarantine_root.is_some() {
            ConfirmationStatus::QuarantineRooted
        } else {
            ConfirmationStatus::Blocked
        };
        self.confirmation_allowed = false;
        self.release_credit_allowed = false;
        self
    }

    pub fn release_confirmation_credit(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty() {
            self.status = ConfirmationStatus::Confirmable;
            self.confirmation_allowed = true;
            self.release_credit_allowed = true;
            Ok(self)
        } else {
            Err(RelayWitnessConfirmationError::ConfirmationStillBlocked)
        }
    }

    pub fn active_blockers(&self, config: &Config) -> Vec<ConfirmationBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_wave103_broadcast_quarantine_root
            && self.roots.wave103_broadcast_quarantine_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingWave103BroadcastQuarantineRoot);
        }
        if config.require_reserve_authorization_root
            && self.roots.reserve_authorization_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingReserveAuthorizationRoot);
        }
        if config.require_privacy_budget_root && self.roots.privacy_budget_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingPrivacyBudgetRoot);
        }
        if config.require_relay_witness_root && self.roots.relay_witness_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingRelayWitnessRoot);
        }
        if config.require_mempool_acceptance_root && self.roots.mempool_acceptance_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingMempoolAcceptanceRoot);
        }
        if config.require_txid_commitment_root && self.roots.txid_commitment_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingTxidCommitmentRoot);
        }
        if config.require_block_inclusion_candidate_root
            && self.roots.block_inclusion_candidate_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingBlockInclusionCandidateRoot);
        }
        if config.require_confirmation_ladder_root && self.roots.confirmation_ladder_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingConfirmationLadderRoot);
        }
        if config.require_reorg_monitor_root && self.roots.reorg_monitor_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingReorgMonitorRoot);
        }
        if config.require_hybrid_pq_authorization_root
            && self.roots.hybrid_pq_authorization_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingHybridPqAuthorizationRoot);
        }
        if config.require_circuit_breaker_root && self.roots.circuit_breaker_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingCircuitBreakerRoot);
        }
        if config.require_live_heavy_gate_evidence
            && self.roots.live_heavy_gate_evidence_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
        }
        if config.require_operator_signoff_root && self.roots.operator_signoff_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingOperatorSignoffRoot);
        }
        if config.require_reviewer_signoff_root && self.roots.reviewer_signoff_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingReviewerSignoffRoot);
        }
        if self.measurements.witness_confirmations < config.min_witness_confirmations {
            blockers.push(ConfirmationBlockerKind::WitnessConfirmationsTooLow);
        }
        if self.measurements.confirmation_ladder_rung < config.min_confirmation_ladder_rung {
            blockers.push(ConfirmationBlockerKind::ConfirmationLadderRungTooLow);
        }
        if self.measurements.reorg_monitor_depth < config.min_reorg_monitor_depth {
            blockers.push(ConfirmationBlockerKind::ReorgMonitorDepthTooLow);
        }
        if config.arm_circuit_breaker_by_default {
            blockers.push(ConfirmationBlockerKind::CircuitBreakerArmed);
        }
        if !config.confirmation_allowed {
            blockers.push(ConfirmationBlockerKind::ConfirmationDisabled);
        }
        if !config.release_credit_allowed {
            blockers.push(ConfirmationBlockerKind::ReleaseCreditDisabled);
        }
        if !config.heavy_gates_ran {
            blockers.push(ConfirmationBlockerKind::HeavyGatesNotRun);
        }
        if config.roots_only_public_records {
            blockers.push(ConfirmationBlockerKind::RootsOnlyBoundary);
        }
        blockers
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "lane_title": self.lane.title(),
            "witness_label": self.witness_label,
            "ordinal": self.ordinal,
            "roots_root": self.roots.state_root(),
            "measurements_root": self.measurements.state_root(),
            "policy_root": self.policy.state_root(),
            "status": self.status.as_str(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("confirmation_checkpoint", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub lane_title: String,
    pub checkpoints: Vec<ConfirmationCheckpoint>,
    pub command_hints: Vec<String>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl State {
    pub fn new(config: Config, lane: LaneKind, checkpoints: Vec<ConfirmationCheckpoint>) -> Self {
        let command_hints = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.policy.command_hint.clone())
            .collect::<Vec<_>>();
        Self {
            confirmation_allowed: config.confirmation_allowed,
            release_credit_allowed: config.release_credit_allowed,
            heavy_gates_ran: config.heavy_gates_ran,
            config,
            lane,
            lane_title: lane.title().to_string(),
            checkpoints,
            command_hints,
        }
    }

    pub fn active_blockers(&self) -> Vec<ConfirmationBlockerKind> {
        self.checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn confirmable_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == ConfirmationStatus::Confirmable)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| !checkpoint.blockers.is_empty())
            .count()
    }

    pub fn quarantine_rooted_root(&self) -> String {
        status_root(
            "wave104_relay_witness_confirmation_quarantine_rooted",
            &self.checkpoints,
            ConfirmationStatus::QuarantineRooted,
        )
    }

    pub fn witness_observed_root(&self) -> String {
        status_root(
            "wave104_relay_witness_observed",
            &self.checkpoints,
            ConfirmationStatus::WitnessObserved,
        )
    }

    pub fn inclusion_candidate_root(&self) -> String {
        status_root(
            "wave104_block_inclusion_candidates",
            &self.checkpoints,
            ConfirmationStatus::InclusionCandidate,
        )
    }

    pub fn confirmable_root(&self) -> String {
        status_root(
            "wave104_confirmable_relay_witness_candidates",
            &self.checkpoints,
            ConfirmationStatus::Confirmable,
        )
    }

    pub fn blocked_root(&self) -> String {
        blocked_root(&self.checkpoints)
    }

    pub fn command_root(&self) -> String {
        root_from_strings(
            "wave104_relay_witness_confirmation_command_hints",
            self.command_hints.clone(),
        )
    }

    pub fn lane_summary_root(&self) -> String {
        domain_hash(
            "wave104-relay-witness-confirmation-lane-summary",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(LANE_ID),
                HashPart::Str(self.lane.as_str()),
                HashPart::U64(WAVE),
                HashPart::U64(self.checkpoints.len() as u64),
                HashPart::U64(self.blocked_count() as u64),
                HashPart::U64(self.confirmable_count() as u64),
            ],
            32,
        )
    }

    pub fn confirmation_denial_root(&self) -> String {
        let blocker_labels = self
            .active_blockers()
            .into_iter()
            .map(|blocker| blocker.as_str().to_string())
            .collect::<Vec<_>>();
        root_from_strings(
            "wave104_monero_tx_relay_witness_confirmation_denial_blockers",
            blocker_labels,
        )
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "config_root": self.config.state_root(),
            "lane": self.lane.as_str(),
            "lane_title": self.lane_title,
            "checkpoint_count": self.checkpoints.len(),
            "blocked_count": self.blocked_count(),
            "confirmable_count": self.confirmable_count(),
            "quarantine_rooted_root": self.quarantine_rooted_root(),
            "witness_observed_root": self.witness_observed_root(),
            "inclusion_candidate_root": self.inclusion_candidate_root(),
            "confirmable_root": self.confirmable_root(),
            "blocked_root": self.blocked_root(),
            "command_root": self.command_root(),
            "lane_summary_root": self.lane_summary_root(),
            "confirmation_denial_root": self.confirmation_denial_root(),
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "heavy_gates_ran": self.heavy_gates_ran,
            "checkpoints": self.checkpoints.iter().map(|checkpoint| checkpoint.public_record()).collect::<Vec<_>>(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record())
    }
}

pub fn devnet() -> State {
    let config = Config::default();
    let lane = LaneKind::PqReservePrivacy;
    let witness_labels = [
        "wave103_broadcast_quarantine_handoff",
        "reserve_authorization_hold",
        "privacy_budget_hold",
        "relay_witness_hold",
        "mempool_acceptance_hold",
        "txid_commitment_hold",
        "block_inclusion_candidate_hold",
        "confirmation_ladder_hold",
        "reorg_monitor_hold",
        "hybrid_pq_authorization_hold",
    ];
    let checkpoints = witness_labels
        .iter()
        .enumerate()
        .map(|(index, witness_label)| {
            ConfirmationCheckpoint::empty(lane, witness_label, (index + 1) as u64, &config)
        })
        .collect::<Vec<_>>();
    State::new(config, lane, checkpoints)
}

pub fn public_record() -> PublicRecord {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

fn initial_blockers(config: &Config) -> Vec<ConfirmationBlockerKind> {
    let mut blockers = Vec::new();
    if config.require_wave103_broadcast_quarantine_root {
        blockers.push(ConfirmationBlockerKind::MissingWave103BroadcastQuarantineRoot);
    }
    if config.require_reserve_authorization_root {
        blockers.push(ConfirmationBlockerKind::MissingReserveAuthorizationRoot);
    }
    if config.require_privacy_budget_root {
        blockers.push(ConfirmationBlockerKind::MissingPrivacyBudgetRoot);
    }
    if config.require_relay_witness_root {
        blockers.push(ConfirmationBlockerKind::MissingRelayWitnessRoot);
    }
    if config.require_mempool_acceptance_root {
        blockers.push(ConfirmationBlockerKind::MissingMempoolAcceptanceRoot);
    }
    if config.require_txid_commitment_root {
        blockers.push(ConfirmationBlockerKind::MissingTxidCommitmentRoot);
    }
    if config.require_block_inclusion_candidate_root {
        blockers.push(ConfirmationBlockerKind::MissingBlockInclusionCandidateRoot);
    }
    if config.require_confirmation_ladder_root {
        blockers.push(ConfirmationBlockerKind::MissingConfirmationLadderRoot);
    }
    if config.require_reorg_monitor_root {
        blockers.push(ConfirmationBlockerKind::MissingReorgMonitorRoot);
    }
    if config.require_hybrid_pq_authorization_root {
        blockers.push(ConfirmationBlockerKind::MissingHybridPqAuthorizationRoot);
    }
    if config.require_circuit_breaker_root {
        blockers.push(ConfirmationBlockerKind::MissingCircuitBreakerRoot);
    }
    if config.require_live_heavy_gate_evidence {
        blockers.push(ConfirmationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
    }
    if config.require_operator_signoff_root {
        blockers.push(ConfirmationBlockerKind::MissingOperatorSignoffRoot);
    }
    if config.require_reviewer_signoff_root {
        blockers.push(ConfirmationBlockerKind::MissingReviewerSignoffRoot);
    }
    blockers.push(ConfirmationBlockerKind::WitnessConfirmationsTooLow);
    blockers.push(ConfirmationBlockerKind::ConfirmationLadderRungTooLow);
    blockers.push(ConfirmationBlockerKind::ReorgMonitorDepthTooLow);
    if config.arm_circuit_breaker_by_default {
        blockers.push(ConfirmationBlockerKind::CircuitBreakerArmed);
    }
    if !config.confirmation_allowed {
        blockers.push(ConfirmationBlockerKind::ConfirmationDisabled);
    }
    if !config.release_credit_allowed {
        blockers.push(ConfirmationBlockerKind::ReleaseCreditDisabled);
    }
    if !config.heavy_gates_ran {
        blockers.push(ConfirmationBlockerKind::HeavyGatesNotRun);
    }
    if config.roots_only_public_records {
        blockers.push(ConfirmationBlockerKind::RootsOnlyBoundary);
    }
    blockers
}

fn blocked_root(checkpoints: &[ConfirmationCheckpoint]) -> String {
    let leaves = checkpoints
        .iter()
        .flat_map(|checkpoint| {
            checkpoint.blockers.iter().map(move |blocker| {
                json!({
                    "lane": checkpoint.lane.as_str(),
                    "witness_label": checkpoint.witness_label,
                    "blocker": blocker.as_str(),
                    "checkpoint_root": checkpoint.state_root(),
                })
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "wave104_blocked_monero_tx_relay_witness_confirmation_guards",
        &leaves,
    )
}

fn status_root(
    domain: &str,
    checkpoints: &[ConfirmationCheckpoint],
    status: ConfirmationStatus,
) -> String {
    root_from_strings(
        domain,
        checkpoints.iter().filter_map(|checkpoint| {
            if checkpoint.status == status {
                Some(checkpoint.state_root())
            } else {
                None
            }
        }),
    )
}

fn root_from_strings<I>(domain: &str, values: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let leaves = values.into_iter().map(Value::String).collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-record",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Json(record),
        ],
        32,
    )
}

fn label_root(kind: &str, lane: &str, label: &str, ordinal: u64) -> String {
    domain_hash(
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-label",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(kind),
            HashPart::Str(lane),
            HashPart::Str(label),
            HashPart::U64(ordinal),
        ],
        32,
    )
}
