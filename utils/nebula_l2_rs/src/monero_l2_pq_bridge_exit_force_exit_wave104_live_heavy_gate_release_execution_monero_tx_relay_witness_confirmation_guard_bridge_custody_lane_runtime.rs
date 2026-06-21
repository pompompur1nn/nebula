use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-bridge-custody-lane-runtime-v1";
const WAVE: u64 = 104;
const PREVIOUS_WAVE: u64 = 103;
const MIN_CONFIRMATION_LADDER_STEPS: u64 = 10;
const MIN_REORG_MONITOR_DEPTH: u64 = 720;
const LANE_ID: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-bridge-custody";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, ConfirmationGuardError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationGuardError {
    LaneMissing,
    CheckpointMissing,
    Wave103BroadcastQuarantineRootMissing,
    CustodySignedTransactionEnvelopeRootMissing,
    CustodySpendWitnessRootMissing,
    RelayWitnessRootMissing,
    MempoolAcceptanceRootMissing,
    TxidCommitmentRootMissing,
    BlockInclusionCandidateRootMissing,
    ConfirmationLadderRootMissing,
    ReorgMonitorRootMissing,
    PqAuthorizationRootMissing,
    CircuitBreakerRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    ConfirmationLadderTooShort,
    ReorgMonitorDepthTooLow,
    ConfirmationStillBlocked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKind {
    BridgeCustody,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BridgeCustody => "bridge_custody",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::BridgeCustody => "Bridge custody Monero tx relay witness confirmation guard",
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::BridgeCustody => "bridge-custody-relay-witness-confirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationStatus {
    Empty,
    Blocked,
    RelayWitnessed,
    MempoolAccepted,
    InclusionCandidate,
    LadderObserved,
    ConfirmationReady,
}

impl ConfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::RelayWitnessed => "relay_witnessed",
            Self::MempoolAccepted => "mempool_accepted",
            Self::InclusionCandidate => "inclusion_candidate",
            Self::LadderObserved => "ladder_observed",
            Self::ConfirmationReady => "confirmation_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationBlockerKind {
    MissingWave103BroadcastQuarantineRoot,
    MissingCustodySignedTransactionEnvelopeRoot,
    MissingCustodySpendWitnessRoot,
    MissingRelayWitnessRoot,
    MissingMempoolAcceptanceRoot,
    MissingTxidCommitmentRoot,
    MissingBlockInclusionCandidateRoot,
    MissingConfirmationLadderRoot,
    MissingReorgMonitorRoot,
    MissingPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingLiveHeavyGateEvidenceRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    ConfirmationLadderTooShort,
    ReorgMonitorDepthTooLow,
    CircuitBreakerArmed,
    ConfirmationDisabled,
    ReleaseCreditDisabled,
    RootsOnlyBoundary,
}

impl ConfirmationBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave103BroadcastQuarantineRoot => {
                "missing_wave103_broadcast_quarantine_root"
            }
            Self::MissingCustodySignedTransactionEnvelopeRoot => {
                "missing_custody_signed_transaction_envelope_root"
            }
            Self::MissingCustodySpendWitnessRoot => "missing_custody_spend_witness_root",
            Self::MissingRelayWitnessRoot => "missing_relay_witness_root",
            Self::MissingMempoolAcceptanceRoot => "missing_mempool_acceptance_root",
            Self::MissingTxidCommitmentRoot => "missing_txid_commitment_root",
            Self::MissingBlockInclusionCandidateRoot => "missing_block_inclusion_candidate_root",
            Self::MissingConfirmationLadderRoot => "missing_confirmation_ladder_root",
            Self::MissingReorgMonitorRoot => "missing_reorg_monitor_root",
            Self::MissingPqAuthorizationRoot => "missing_pq_authorization_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::ConfirmationLadderTooShort => "confirmation_ladder_too_short",
            Self::ReorgMonitorDepthTooLow => "reorg_monitor_depth_too_low",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ConfirmationDisabled => "confirmation_disabled",
            Self::ReleaseCreditDisabled => "release_credit_disabled",
            Self::RootsOnlyBoundary => "roots_only_boundary",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub previous_wave: u64,
    pub lane_id: String,
    pub active_lane: String,
    pub min_confirmation_ladder_steps: u64,
    pub min_reorg_monitor_depth: u64,
    pub require_wave103_broadcast_quarantine_root: bool,
    pub require_custody_signed_transaction_envelope_root: bool,
    pub require_custody_spend_witness_root: bool,
    pub require_relay_witness_root: bool,
    pub require_mempool_acceptance_root: bool,
    pub require_txid_commitment_root: bool,
    pub require_block_inclusion_candidate_root: bool,
    pub require_confirmation_ladder_root: bool,
    pub require_reorg_monitor_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_live_heavy_gate_evidence_root: bool,
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
            previous_wave: PREVIOUS_WAVE,
            lane_id: LANE_ID.to_string(),
            active_lane: LaneKind::BridgeCustody.as_str().to_string(),
            min_confirmation_ladder_steps: MIN_CONFIRMATION_LADDER_STEPS,
            min_reorg_monitor_depth: MIN_REORG_MONITOR_DEPTH,
            require_wave103_broadcast_quarantine_root: true,
            require_custody_signed_transaction_envelope_root: true,
            require_custody_spend_witness_root: true,
            require_relay_witness_root: true,
            require_mempool_acceptance_root: true,
            require_txid_commitment_root: true,
            require_block_inclusion_candidate_root: true,
            require_confirmation_ladder_root: true,
            require_reorg_monitor_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_live_heavy_gate_evidence_root: true,
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
            "previous_wave": self.previous_wave,
            "lane_id": self.lane_id,
            "active_lane": self.active_lane,
            "min_confirmation_ladder_steps": self.min_confirmation_ladder_steps,
            "min_reorg_monitor_depth": self.min_reorg_monitor_depth,
            "require_wave103_broadcast_quarantine_root": self.require_wave103_broadcast_quarantine_root,
            "require_custody_signed_transaction_envelope_root": self.require_custody_signed_transaction_envelope_root,
            "require_custody_spend_witness_root": self.require_custody_spend_witness_root,
            "require_relay_witness_root": self.require_relay_witness_root,
            "require_mempool_acceptance_root": self.require_mempool_acceptance_root,
            "require_txid_commitment_root": self.require_txid_commitment_root,
            "require_block_inclusion_candidate_root": self.require_block_inclusion_candidate_root,
            "require_confirmation_ladder_root": self.require_confirmation_ladder_root,
            "require_reorg_monitor_root": self.require_reorg_monitor_root,
            "require_pq_authorization_root": self.require_pq_authorization_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_live_heavy_gate_evidence_root": self.require_live_heavy_gate_evidence_root,
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
    pub custody_signed_transaction_envelope_root: Option<String>,
    pub custody_spend_witness_root: Option<String>,
    pub relay_witness_root: Option<String>,
    pub mempool_acceptance_root: Option<String>,
    pub txid_commitment_root: Option<String>,
    pub block_inclusion_candidate_root: Option<String>,
    pub confirmation_ladder_root: Option<String>,
    pub reorg_monitor_root: Option<String>,
    pub pq_authorization_root: Option<String>,
    pub circuit_breaker_root: Option<String>,
    pub live_heavy_gate_evidence_root: Option<String>,
    pub operator_signoff_root: Option<String>,
    pub reviewer_signoff_root: Option<String>,
}

impl ConfirmationRoots {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "wave103_broadcast_quarantine_root": self.wave103_broadcast_quarantine_root,
            "custody_signed_transaction_envelope_root": self.custody_signed_transaction_envelope_root,
            "custody_spend_witness_root": self.custody_spend_witness_root,
            "relay_witness_root": self.relay_witness_root,
            "mempool_acceptance_root": self.mempool_acceptance_root,
            "txid_commitment_root": self.txid_commitment_root,
            "block_inclusion_candidate_root": self.block_inclusion_candidate_root,
            "confirmation_ladder_root": self.confirmation_ladder_root,
            "reorg_monitor_root": self.reorg_monitor_root,
            "pq_authorization_root": self.pq_authorization_root,
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
    pub confirmation_ladder_steps: u64,
    pub reorg_monitor_depth: u64,
}

impl ConfirmationMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            confirmation_ladder_steps: config.min_confirmation_ladder_steps.saturating_sub(1),
            reorg_monitor_depth: config.min_reorg_monitor_depth.saturating_sub(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "confirmation_ladder_steps": self.confirmation_ladder_steps,
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
    pub claim_label: String,
    pub ordinal: u64,
    pub command_scope: String,
    pub command_hint: String,
    pub relay_witness_policy_root: String,
    pub mempool_acceptance_policy_root: String,
    pub inclusion_policy_root: String,
    pub confirmation_ladder_policy_root: String,
    pub custody_credit_policy_root: String,
}

impl ConfirmationPolicy {
    pub fn new(lane: LaneKind, claim_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave104 confirm-relay-witness --lane {} --claim {} --hold-release-credit",
            lane.as_str(),
            claim_label
        );
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            relay_witness_policy_root: label_root(
                "relay_witness_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            mempool_acceptance_policy_root: label_root(
                "mempool_acceptance_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            inclusion_policy_root: label_root(
                "inclusion_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            confirmation_ladder_policy_root: label_root(
                "confirmation_ladder_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            custody_credit_policy_root: label_root(
                "custody_credit_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "relay_witness_policy_root": self.relay_witness_policy_root,
            "mempool_acceptance_policy_root": self.mempool_acceptance_policy_root,
            "inclusion_policy_root": self.inclusion_policy_root,
            "confirmation_ladder_policy_root": self.confirmation_ladder_policy_root,
            "custody_credit_policy_root": self.custody_credit_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("confirmation_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayWitnessConfirmation {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub roots: ConfirmationRoots,
    pub measurements: ConfirmationMeasurements,
    pub policy: ConfirmationPolicy,
    pub status: ConfirmationStatus,
    pub blockers: Vec<ConfirmationBlockerKind>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
}

impl RelayWitnessConfirmation {
    pub fn empty(lane: LaneKind, claim_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = ConfirmationPolicy::new(lane, claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
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
            ConfirmationStatus::LadderObserved
        } else if self.roots.block_inclusion_candidate_root.is_some() {
            ConfirmationStatus::InclusionCandidate
        } else if self.roots.mempool_acceptance_root.is_some() {
            ConfirmationStatus::MempoolAccepted
        } else if self.roots.relay_witness_root.is_some() {
            ConfirmationStatus::RelayWitnessed
        } else {
            ConfirmationStatus::Blocked
        };
        self.confirmation_allowed = false;
        self.release_credit_allowed = false;
        self
    }

    pub fn release_credit_after_confirmation(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty() {
            self.status = ConfirmationStatus::ConfirmationReady;
            self.confirmation_allowed = true;
            self.release_credit_allowed = true;
            Ok(self)
        } else {
            Err(ConfirmationGuardError::ConfirmationStillBlocked)
        }
    }

    pub fn active_blockers(&self, config: &Config) -> Vec<ConfirmationBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_wave103_broadcast_quarantine_root
            && self.roots.wave103_broadcast_quarantine_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingWave103BroadcastQuarantineRoot);
        }
        if config.require_custody_signed_transaction_envelope_root
            && self
                .roots
                .custody_signed_transaction_envelope_root
                .is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingCustodySignedTransactionEnvelopeRoot);
        }
        if config.require_custody_spend_witness_root
            && self.roots.custody_spend_witness_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingCustodySpendWitnessRoot);
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
        if config.require_pq_authorization_root && self.roots.pq_authorization_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingPqAuthorizationRoot);
        }
        if config.require_circuit_breaker_root && self.roots.circuit_breaker_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingCircuitBreakerRoot);
        }
        if config.require_live_heavy_gate_evidence_root
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
        if self.measurements.confirmation_ladder_steps < config.min_confirmation_ladder_steps {
            blockers.push(ConfirmationBlockerKind::ConfirmationLadderTooShort);
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
        if config.roots_only_public_records {
            blockers.push(ConfirmationBlockerKind::RootsOnlyBoundary);
        }
        blockers
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "lane_title": self.lane.title(),
            "claim_label": self.claim_label,
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
        record_root("relay_witness_confirmation", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub lane_title: String,
    pub checkpoints: Vec<RelayWitnessConfirmation>,
    pub command_hints: Vec<String>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl State {
    pub fn new(config: Config, lane: LaneKind, checkpoints: Vec<RelayWitnessConfirmation>) -> Self {
        let command_hints = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.policy.command_hint.clone())
            .collect::<Vec<_>>();
        Self {
            config,
            lane,
            lane_title: lane.title().to_string(),
            checkpoints,
            command_hints,
            confirmation_allowed: false,
            release_credit_allowed: false,
            heavy_gates_ran: false,
        }
    }

    pub fn active_blockers(&self) -> Vec<ConfirmationBlockerKind> {
        self.checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn ready_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == ConfirmationStatus::ConfirmationReady)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| !checkpoint.blockers.is_empty())
            .count()
    }

    pub fn relay_witnessed_root(&self) -> String {
        status_root(
            "wave104_monero_tx_relay_witnessed",
            &self.checkpoints,
            ConfirmationStatus::RelayWitnessed,
        )
    }

    pub fn mempool_accepted_root(&self) -> String {
        status_root(
            "wave104_monero_tx_mempool_accepted",
            &self.checkpoints,
            ConfirmationStatus::MempoolAccepted,
        )
    }

    pub fn inclusion_candidate_root(&self) -> String {
        status_root(
            "wave104_monero_tx_block_inclusion_candidates",
            &self.checkpoints,
            ConfirmationStatus::InclusionCandidate,
        )
    }

    pub fn ladder_observed_root(&self) -> String {
        status_root(
            "wave104_monero_tx_confirmation_ladder_observed",
            &self.checkpoints,
            ConfirmationStatus::LadderObserved,
        )
    }

    pub fn confirmation_ready_root(&self) -> String {
        status_root(
            "wave104_monero_tx_confirmation_ready",
            &self.checkpoints,
            ConfirmationStatus::ConfirmationReady,
        )
    }

    pub fn blocked_root(&self) -> String {
        blocked_root(&self.checkpoints)
    }

    pub fn command_root(&self) -> String {
        root_from_strings(
            "wave104_monero_tx_relay_witness_confirmation_command_hints",
            self.command_hints.clone(),
        )
    }

    pub fn lane_summary_root(&self) -> String {
        domain_hash(
            "wave104-monero-tx-relay-witness-confirmation-lane-summary",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(LANE_ID),
                HashPart::Str(self.lane.as_str()),
                HashPart::U64(WAVE),
                HashPart::U64(self.checkpoints.len() as u64),
                HashPart::U64(self.blocked_count() as u64),
                HashPart::U64(self.ready_count() as u64),
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
            "ready_count": self.ready_count(),
            "relay_witnessed_root": self.relay_witnessed_root(),
            "mempool_accepted_root": self.mempool_accepted_root(),
            "inclusion_candidate_root": self.inclusion_candidate_root(),
            "ladder_observed_root": self.ladder_observed_root(),
            "confirmation_ready_root": self.confirmation_ready_root(),
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
    let lane = LaneKind::BridgeCustody;
    let claim_labels = [
        "wave103_broadcast_quarantine_hold",
        "custody_signed_transaction_envelope",
        "custody_spend_witness",
        "relay_witness_observation",
        "mempool_acceptance_observation",
        "txid_commitment_binding",
        "block_inclusion_candidate",
        "confirmation_ladder",
        "reorg_monitor",
        "pq_authorized_confirmation",
        "operator_reviewer_signoff",
    ];
    let checkpoints = claim_labels
        .iter()
        .enumerate()
        .map(|(index, claim_label)| {
            RelayWitnessConfirmation::empty(lane, claim_label, (index + 1) as u64, &config)
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
    if config.require_custody_signed_transaction_envelope_root {
        blockers.push(ConfirmationBlockerKind::MissingCustodySignedTransactionEnvelopeRoot);
    }
    if config.require_custody_spend_witness_root {
        blockers.push(ConfirmationBlockerKind::MissingCustodySpendWitnessRoot);
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
    if config.require_pq_authorization_root {
        blockers.push(ConfirmationBlockerKind::MissingPqAuthorizationRoot);
    }
    if config.require_circuit_breaker_root {
        blockers.push(ConfirmationBlockerKind::MissingCircuitBreakerRoot);
    }
    if config.require_live_heavy_gate_evidence_root {
        blockers.push(ConfirmationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
    }
    if config.require_operator_signoff_root {
        blockers.push(ConfirmationBlockerKind::MissingOperatorSignoffRoot);
    }
    if config.require_reviewer_signoff_root {
        blockers.push(ConfirmationBlockerKind::MissingReviewerSignoffRoot);
    }
    blockers.push(ConfirmationBlockerKind::ConfirmationLadderTooShort);
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
    if config.roots_only_public_records {
        blockers.push(ConfirmationBlockerKind::RootsOnlyBoundary);
    }
    blockers
}

fn blocked_root(checkpoints: &[RelayWitnessConfirmation]) -> String {
    let leaves = checkpoints
        .iter()
        .flat_map(|checkpoint| {
            checkpoint.blockers.iter().map(move |blocker| {
                json!({
                    "lane": checkpoint.lane.as_str(),
                    "claim_label": checkpoint.claim_label,
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
    checkpoints: &[RelayWitnessConfirmation],
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

pub fn devnet_relay_witness_confirmation_guard_root() -> String {
    let state = devnet();
    domain_hash(
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(LANE_ID),
            HashPart::Str(&state.blocked_root()),
            HashPart::Str(&state.confirmation_denial_root()),
        ],
        32,
    )
}
