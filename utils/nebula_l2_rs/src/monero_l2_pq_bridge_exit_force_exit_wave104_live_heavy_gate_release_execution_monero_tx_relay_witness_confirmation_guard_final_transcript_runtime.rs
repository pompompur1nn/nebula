use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-final-transcript-runtime-v1";
const WAVE: u64 = 104;
const BROADCAST_QUARANTINE_WAVE: u64 = 103;
const MIN_RELAY_WITNESS_HEIGHT: u64 = 1_040_000;
const MIN_CONFIRMATION_LADDER_DEPTH: u64 = 28;
const MIN_REORG_MONITOR_DEPTH: u64 = 36;
const MAX_RELAY_FEE_BPS: u64 = 12;
const LANE_ID: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-final-transcript";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, RelayConfirmationError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayConfirmationError {
    LaneMissing,
    ClaimMissing,
    Wave103BroadcastQuarantineRootMissing,
    SignedTransactionEnvelopeRootMissing,
    RelayWitnessRootMissing,
    MempoolAcceptanceRootMissing,
    TxidCommitmentRootMissing,
    BlockInclusionCandidateRootMissing,
    ConfirmationLadderRootMissing,
    ReorgMonitorRootMissing,
    PqAuthorizationRootMissing,
    CircuitBreakerRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    RelayWitnessHeightTooLow,
    ConfirmationLadderTooShallow,
    ReorgMonitorTooShallow,
    RelayFeeTooHigh,
    ReleaseCreditStillDenied,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKind {
    Compile,
    RuntimeReplay,
    AuditSecurity,
    BridgeCustody,
    WalletWatchtower,
    PqReservePrivacy,
    FinalTranscript,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::RuntimeReplay => "runtime_replay",
            Self::AuditSecurity => "audit_security",
            Self::BridgeCustody => "bridge_custody",
            Self::WalletWatchtower => "wallet_watchtower",
            Self::PqReservePrivacy => "pq_reserve_privacy",
            Self::FinalTranscript => "final_transcript",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Compile => "Compile Monero tx relay witness confirmation guard",
            Self::RuntimeReplay => "Runtime replay Monero tx relay witness confirmation guard",
            Self::AuditSecurity => "Audit security Monero tx relay witness confirmation guard",
            Self::BridgeCustody => "Bridge custody Monero tx relay witness confirmation guard",
            Self::WalletWatchtower => {
                "Wallet watchtower Monero tx relay witness confirmation guard"
            }
            Self::PqReservePrivacy => {
                "PQ reserve privacy Monero tx relay witness confirmation guard"
            }
            Self::FinalTranscript => "Final transcript Monero tx relay witness confirmation guard",
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::Compile => "compile-monero-relay-confirmation",
            Self::RuntimeReplay => "runtime-replay-monero-relay-confirmation",
            Self::AuditSecurity => "audit-security-monero-relay-confirmation",
            Self::BridgeCustody => "bridge-custody-monero-relay-confirmation",
            Self::WalletWatchtower => "wallet-watchtower-monero-relay-confirmation",
            Self::PqReservePrivacy => "pq-reserve-privacy-monero-relay-confirmation",
            Self::FinalTranscript => "final-transcript-monero-relay-confirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayConfirmationStatus {
    Empty,
    Blocked,
    RelayWitnessCandidate,
    MempoolAccepted,
    InclusionCandidate,
    ConfirmationReady,
}

impl RelayConfirmationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::RelayWitnessCandidate => "relay_witness_candidate",
            Self::MempoolAccepted => "mempool_accepted",
            Self::InclusionCandidate => "inclusion_candidate",
            Self::ConfirmationReady => "confirmation_ready",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelayConfirmationBlockerKind {
    MissingWave103BroadcastQuarantineRoot,
    MissingSignedTransactionEnvelopeRoot,
    MissingRelayWitnessRoot,
    MissingMempoolAcceptanceRoot,
    MissingTxidCommitmentRoot,
    MissingBlockInclusionCandidateRoot,
    MissingConfirmationLadderRoot,
    MissingReorgMonitorRoot,
    MissingPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    MissingLiveHeavyGateEvidenceRoot,
    RelayWitnessHeightTooLow,
    ConfirmationLadderTooShallow,
    ReorgMonitorTooShallow,
    RelayFeeTooHigh,
    CircuitBreakerArmed,
    ReleaseCreditDenied,
    RootsOnlyBoundary,
}

impl RelayConfirmationBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave103BroadcastQuarantineRoot => {
                "missing_wave103_broadcast_quarantine_root"
            }
            Self::MissingSignedTransactionEnvelopeRoot => {
                "missing_signed_transaction_envelope_root"
            }
            Self::MissingRelayWitnessRoot => "missing_relay_witness_root",
            Self::MissingMempoolAcceptanceRoot => "missing_mempool_acceptance_root",
            Self::MissingTxidCommitmentRoot => "missing_txid_commitment_root",
            Self::MissingBlockInclusionCandidateRoot => "missing_block_inclusion_candidate_root",
            Self::MissingConfirmationLadderRoot => "missing_confirmation_ladder_root",
            Self::MissingReorgMonitorRoot => "missing_reorg_monitor_root",
            Self::MissingPqAuthorizationRoot => "missing_pq_authorization_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::RelayWitnessHeightTooLow => "relay_witness_height_too_low",
            Self::ConfirmationLadderTooShallow => "confirmation_ladder_too_shallow",
            Self::ReorgMonitorTooShallow => "reorg_monitor_too_shallow",
            Self::RelayFeeTooHigh => "relay_fee_too_high",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ReleaseCreditDenied => "release_credit_denied",
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
    pub min_relay_witness_height: u64,
    pub min_confirmation_ladder_depth: u64,
    pub min_reorg_monitor_depth: u64,
    pub max_relay_fee_bps: u64,
    pub require_wave103_broadcast_quarantine_root: bool,
    pub require_signed_transaction_envelope_root: bool,
    pub require_relay_witness_root: bool,
    pub require_mempool_acceptance_root: bool,
    pub require_txid_commitment_root: bool,
    pub require_block_inclusion_candidate_root: bool,
    pub require_confirmation_ladder_root: bool,
    pub require_reorg_monitor_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub require_live_heavy_gate_evidence: bool,
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
            min_relay_witness_height: MIN_RELAY_WITNESS_HEIGHT,
            min_confirmation_ladder_depth: MIN_CONFIRMATION_LADDER_DEPTH,
            min_reorg_monitor_depth: MIN_REORG_MONITOR_DEPTH,
            max_relay_fee_bps: MAX_RELAY_FEE_BPS,
            require_wave103_broadcast_quarantine_root: true,
            require_signed_transaction_envelope_root: true,
            require_relay_witness_root: true,
            require_mempool_acceptance_root: true,
            require_txid_commitment_root: true,
            require_block_inclusion_candidate_root: true,
            require_confirmation_ladder_root: true,
            require_reorg_monitor_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            require_live_heavy_gate_evidence: true,
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
            "min_relay_witness_height": self.min_relay_witness_height,
            "min_confirmation_ladder_depth": self.min_confirmation_ladder_depth,
            "min_reorg_monitor_depth": self.min_reorg_monitor_depth,
            "max_relay_fee_bps": self.max_relay_fee_bps,
            "require_wave103_broadcast_quarantine_root": self.require_wave103_broadcast_quarantine_root,
            "require_signed_transaction_envelope_root": self.require_signed_transaction_envelope_root,
            "require_relay_witness_root": self.require_relay_witness_root,
            "require_mempool_acceptance_root": self.require_mempool_acceptance_root,
            "require_txid_commitment_root": self.require_txid_commitment_root,
            "require_block_inclusion_candidate_root": self.require_block_inclusion_candidate_root,
            "require_confirmation_ladder_root": self.require_confirmation_ladder_root,
            "require_reorg_monitor_root": self.require_reorg_monitor_root,
            "require_pq_authorization_root": self.require_pq_authorization_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_operator_signoff_root": self.require_operator_signoff_root,
            "require_reviewer_signoff_root": self.require_reviewer_signoff_root,
            "require_live_heavy_gate_evidence": self.require_live_heavy_gate_evidence,
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
pub struct RelayConfirmationRoots {
    pub wave103_broadcast_quarantine_root: Option<String>,
    pub signed_transaction_envelope_root: Option<String>,
    pub relay_witness_root: Option<String>,
    pub mempool_acceptance_root: Option<String>,
    pub txid_commitment_root: Option<String>,
    pub block_inclusion_candidate_root: Option<String>,
    pub confirmation_ladder_root: Option<String>,
    pub reorg_monitor_root: Option<String>,
    pub pq_authorization_root: Option<String>,
    pub circuit_breaker_root: Option<String>,
    pub operator_signoff_root: Option<String>,
    pub reviewer_signoff_root: Option<String>,
    pub live_heavy_gate_evidence_root: Option<String>,
}

impl RelayConfirmationRoots {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "wave103_broadcast_quarantine_root": self.wave103_broadcast_quarantine_root,
            "signed_transaction_envelope_root": self.signed_transaction_envelope_root,
            "relay_witness_root": self.relay_witness_root,
            "mempool_acceptance_root": self.mempool_acceptance_root,
            "txid_commitment_root": self.txid_commitment_root,
            "block_inclusion_candidate_root": self.block_inclusion_candidate_root,
            "confirmation_ladder_root": self.confirmation_ladder_root,
            "reorg_monitor_root": self.reorg_monitor_root,
            "pq_authorization_root": self.pq_authorization_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "operator_signoff_root": self.operator_signoff_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "live_heavy_gate_evidence_root": self.live_heavy_gate_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("relay_confirmation_roots", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RelayConfirmationMeasurements {
    pub relay_witness_height: u64,
    pub confirmation_ladder_depth: u64,
    pub reorg_monitor_depth: u64,
    pub relay_fee_bps: u64,
}

impl RelayConfirmationMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            relay_witness_height: config.min_relay_witness_height.saturating_sub(1),
            confirmation_ladder_depth: config.min_confirmation_ladder_depth.saturating_sub(1),
            reorg_monitor_depth: config.min_reorg_monitor_depth.saturating_sub(1),
            relay_fee_bps: config.max_relay_fee_bps.saturating_add(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "relay_witness_height": self.relay_witness_height,
            "confirmation_ladder_depth": self.confirmation_ladder_depth,
            "reorg_monitor_depth": self.reorg_monitor_depth,
            "relay_fee_bps": self.relay_fee_bps,
        })
    }

    pub fn state_root(self) -> String {
        record_root("relay_confirmation_measurements", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfirmationPolicy {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub command_scope: String,
    pub command_hint: String,
    pub relay_policy_root: String,
    pub mempool_policy_root: String,
    pub confirmation_policy_root: String,
    pub reorg_policy_root: String,
    pub credit_policy_root: String,
}

impl RelayConfirmationPolicy {
    pub fn new(lane: LaneKind, claim_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave104 confirm-relay --lane {} --claim {} --hold-credit",
            lane.as_str(),
            claim_label
        );
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            relay_policy_root: label_root("relay_policy", lane.as_str(), claim_label, ordinal),
            mempool_policy_root: label_root("mempool_policy", lane.as_str(), claim_label, ordinal),
            confirmation_policy_root: label_root(
                "confirmation_policy",
                lane.as_str(),
                claim_label,
                ordinal,
            ),
            reorg_policy_root: label_root("reorg_policy", lane.as_str(), claim_label, ordinal),
            credit_policy_root: label_root("credit_policy", lane.as_str(), claim_label, ordinal),
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "relay_policy_root": self.relay_policy_root,
            "mempool_policy_root": self.mempool_policy_root,
            "confirmation_policy_root": self.confirmation_policy_root,
            "reorg_policy_root": self.reorg_policy_root,
            "credit_policy_root": self.credit_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("relay_confirmation_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayConfirmationCheckpoint {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub roots: RelayConfirmationRoots,
    pub measurements: RelayConfirmationMeasurements,
    pub policy: RelayConfirmationPolicy,
    pub status: RelayConfirmationStatus,
    pub blockers: Vec<RelayConfirmationBlockerKind>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
}

impl RelayConfirmationCheckpoint {
    pub fn empty(lane: LaneKind, claim_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = RelayConfirmationPolicy::new(lane, claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            roots: RelayConfirmationRoots::default(),
            measurements: RelayConfirmationMeasurements::blocked(config),
            policy,
            status: RelayConfirmationStatus::Blocked,
            blockers: initial_blockers(config),
            confirmation_allowed: false,
            release_credit_allowed: false,
        }
    }

    pub fn stage_confirmation(
        mut self,
        roots: RelayConfirmationRoots,
        measurements: RelayConfirmationMeasurements,
        config: &Config,
    ) -> Self {
        self.roots = roots;
        self.measurements = measurements;
        self.blockers = self.active_blockers(config);
        self.status = if self.blockers.is_empty() {
            RelayConfirmationStatus::InclusionCandidate
        } else if self.roots.block_inclusion_candidate_root.is_some() {
            RelayConfirmationStatus::InclusionCandidate
        } else if self.roots.mempool_acceptance_root.is_some() {
            RelayConfirmationStatus::MempoolAccepted
        } else if self.roots.relay_witness_root.is_some() {
            RelayConfirmationStatus::RelayWitnessCandidate
        } else {
            RelayConfirmationStatus::Blocked
        };
        self.confirmation_allowed = false;
        self.release_credit_allowed = false;
        self
    }

    pub fn release_credit(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty() {
            self.status = RelayConfirmationStatus::ConfirmationReady;
            self.confirmation_allowed = true;
            self.release_credit_allowed = true;
            Ok(self)
        } else {
            Err(RelayConfirmationError::ReleaseCreditStillDenied)
        }
    }

    pub fn active_blockers(&self, config: &Config) -> Vec<RelayConfirmationBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_wave103_broadcast_quarantine_root
            && self.roots.wave103_broadcast_quarantine_root.is_none()
        {
            blockers.push(RelayConfirmationBlockerKind::MissingWave103BroadcastQuarantineRoot);
        }
        if config.require_signed_transaction_envelope_root
            && self.roots.signed_transaction_envelope_root.is_none()
        {
            blockers.push(RelayConfirmationBlockerKind::MissingSignedTransactionEnvelopeRoot);
        }
        if config.require_relay_witness_root && self.roots.relay_witness_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingRelayWitnessRoot);
        }
        if config.require_mempool_acceptance_root && self.roots.mempool_acceptance_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingMempoolAcceptanceRoot);
        }
        if config.require_txid_commitment_root && self.roots.txid_commitment_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingTxidCommitmentRoot);
        }
        if config.require_block_inclusion_candidate_root
            && self.roots.block_inclusion_candidate_root.is_none()
        {
            blockers.push(RelayConfirmationBlockerKind::MissingBlockInclusionCandidateRoot);
        }
        if config.require_confirmation_ladder_root && self.roots.confirmation_ladder_root.is_none()
        {
            blockers.push(RelayConfirmationBlockerKind::MissingConfirmationLadderRoot);
        }
        if config.require_reorg_monitor_root && self.roots.reorg_monitor_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingReorgMonitorRoot);
        }
        if config.require_pq_authorization_root && self.roots.pq_authorization_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingPqAuthorizationRoot);
        }
        if config.require_circuit_breaker_root && self.roots.circuit_breaker_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingCircuitBreakerRoot);
        }
        if config.require_operator_signoff_root && self.roots.operator_signoff_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingOperatorSignoffRoot);
        }
        if config.require_reviewer_signoff_root && self.roots.reviewer_signoff_root.is_none() {
            blockers.push(RelayConfirmationBlockerKind::MissingReviewerSignoffRoot);
        }
        if config.require_live_heavy_gate_evidence
            && self.roots.live_heavy_gate_evidence_root.is_none()
        {
            blockers.push(RelayConfirmationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
        }
        if self.measurements.relay_witness_height < config.min_relay_witness_height {
            blockers.push(RelayConfirmationBlockerKind::RelayWitnessHeightTooLow);
        }
        if self.measurements.confirmation_ladder_depth < config.min_confirmation_ladder_depth {
            blockers.push(RelayConfirmationBlockerKind::ConfirmationLadderTooShallow);
        }
        if self.measurements.reorg_monitor_depth < config.min_reorg_monitor_depth {
            blockers.push(RelayConfirmationBlockerKind::ReorgMonitorTooShallow);
        }
        if self.measurements.relay_fee_bps > config.max_relay_fee_bps {
            blockers.push(RelayConfirmationBlockerKind::RelayFeeTooHigh);
        }
        if config.arm_circuit_breaker_by_default {
            blockers.push(RelayConfirmationBlockerKind::CircuitBreakerArmed);
        }
        if !config.confirmation_allowed || !config.release_credit_allowed {
            blockers.push(RelayConfirmationBlockerKind::ReleaseCreditDenied);
        }
        if config.roots_only_public_records {
            blockers.push(RelayConfirmationBlockerKind::RootsOnlyBoundary);
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
        record_root("relay_confirmation_checkpoint", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub lane_title: String,
    pub checkpoints: Vec<RelayConfirmationCheckpoint>,
    pub command_hints: Vec<String>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub heavy_gates_ran: bool,
}

impl State {
    pub fn new(
        config: Config,
        lane: LaneKind,
        checkpoints: Vec<RelayConfirmationCheckpoint>,
    ) -> Self {
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

    pub fn active_blockers(&self) -> Vec<RelayConfirmationBlockerKind> {
        self.checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn ready_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == RelayConfirmationStatus::ConfirmationReady)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| !checkpoint.blockers.is_empty())
            .count()
    }

    pub fn relay_witness_root(&self) -> String {
        status_root(
            "wave104_monero_tx_relay_witness_candidates",
            &self.checkpoints,
            RelayConfirmationStatus::RelayWitnessCandidate,
        )
    }

    pub fn mempool_acceptance_root(&self) -> String {
        status_root(
            "wave104_monero_tx_mempool_acceptance_candidates",
            &self.checkpoints,
            RelayConfirmationStatus::MempoolAccepted,
        )
    }

    pub fn inclusion_candidate_root(&self) -> String {
        status_root(
            "wave104_monero_tx_inclusion_candidates",
            &self.checkpoints,
            RelayConfirmationStatus::InclusionCandidate,
        )
    }

    pub fn confirmation_ready_root(&self) -> String {
        status_root(
            "wave104_monero_tx_confirmation_ready",
            &self.checkpoints,
            RelayConfirmationStatus::ConfirmationReady,
        )
    }

    pub fn blocked_root(&self) -> String {
        blocked_root(&self.checkpoints)
    }

    pub fn command_root(&self) -> String {
        root_from_strings(
            "wave104_monero_tx_relay_confirmation_command_hints",
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

    pub fn release_credit_denial_root(&self) -> String {
        let blocker_labels = self
            .active_blockers()
            .into_iter()
            .map(|blocker| blocker.as_str().to_string())
            .collect::<Vec<_>>();
        root_from_strings(
            "wave104_monero_tx_release_credit_denial_blockers",
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
            "relay_witness_root": self.relay_witness_root(),
            "mempool_acceptance_root": self.mempool_acceptance_root(),
            "inclusion_candidate_root": self.inclusion_candidate_root(),
            "confirmation_ready_root": self.confirmation_ready_root(),
            "blocked_root": self.blocked_root(),
            "command_root": self.command_root(),
            "lane_summary_root": self.lane_summary_root(),
            "release_credit_denial_root": self.release_credit_denial_root(),
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
    let lane = LaneKind::FinalTranscript;
    let claim_labels = [
        "compile_lane_relay_confirmation",
        "runtime_lane_relay_confirmation",
        "audit_lane_relay_confirmation",
        "custody_lane_relay_confirmation",
        "wallet_lane_relay_confirmation",
        "pq_privacy_lane_relay_confirmation",
        "global_release_credit_hold",
    ];
    let checkpoints = claim_labels
        .iter()
        .enumerate()
        .map(|(index, claim_label)| {
            RelayConfirmationCheckpoint::empty(lane, claim_label, (index + 1) as u64, &config)
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

fn initial_blockers(config: &Config) -> Vec<RelayConfirmationBlockerKind> {
    let mut blockers = Vec::new();
    if config.require_wave103_broadcast_quarantine_root {
        blockers.push(RelayConfirmationBlockerKind::MissingWave103BroadcastQuarantineRoot);
    }
    if config.require_signed_transaction_envelope_root {
        blockers.push(RelayConfirmationBlockerKind::MissingSignedTransactionEnvelopeRoot);
    }
    if config.require_relay_witness_root {
        blockers.push(RelayConfirmationBlockerKind::MissingRelayWitnessRoot);
    }
    if config.require_mempool_acceptance_root {
        blockers.push(RelayConfirmationBlockerKind::MissingMempoolAcceptanceRoot);
    }
    if config.require_txid_commitment_root {
        blockers.push(RelayConfirmationBlockerKind::MissingTxidCommitmentRoot);
    }
    if config.require_block_inclusion_candidate_root {
        blockers.push(RelayConfirmationBlockerKind::MissingBlockInclusionCandidateRoot);
    }
    if config.require_confirmation_ladder_root {
        blockers.push(RelayConfirmationBlockerKind::MissingConfirmationLadderRoot);
    }
    if config.require_reorg_monitor_root {
        blockers.push(RelayConfirmationBlockerKind::MissingReorgMonitorRoot);
    }
    if config.require_pq_authorization_root {
        blockers.push(RelayConfirmationBlockerKind::MissingPqAuthorizationRoot);
    }
    if config.require_circuit_breaker_root {
        blockers.push(RelayConfirmationBlockerKind::MissingCircuitBreakerRoot);
    }
    if config.require_operator_signoff_root {
        blockers.push(RelayConfirmationBlockerKind::MissingOperatorSignoffRoot);
    }
    if config.require_reviewer_signoff_root {
        blockers.push(RelayConfirmationBlockerKind::MissingReviewerSignoffRoot);
    }
    if config.require_live_heavy_gate_evidence {
        blockers.push(RelayConfirmationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
    }
    blockers.push(RelayConfirmationBlockerKind::RelayWitnessHeightTooLow);
    blockers.push(RelayConfirmationBlockerKind::ConfirmationLadderTooShallow);
    blockers.push(RelayConfirmationBlockerKind::ReorgMonitorTooShallow);
    blockers.push(RelayConfirmationBlockerKind::RelayFeeTooHigh);
    if config.arm_circuit_breaker_by_default {
        blockers.push(RelayConfirmationBlockerKind::CircuitBreakerArmed);
    }
    if !config.confirmation_allowed || !config.release_credit_allowed {
        blockers.push(RelayConfirmationBlockerKind::ReleaseCreditDenied);
    }
    if config.roots_only_public_records {
        blockers.push(RelayConfirmationBlockerKind::RootsOnlyBoundary);
    }
    blockers
}

fn blocked_root(checkpoints: &[RelayConfirmationCheckpoint]) -> String {
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
        "wave104_blocked_monero_tx_relay_confirmation_guards",
        &leaves,
    )
}

fn status_root(
    domain: &str,
    checkpoints: &[RelayConfirmationCheckpoint],
    status: RelayConfirmationStatus,
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
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-confirmation-record",
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
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-confirmation-label",
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

pub fn devnet_relay_confirmation_root() -> String {
    let state = devnet();
    domain_hash(
        "wave104-live-heavy-gate-release-execution-monero-tx-relay-confirmation-root",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(LANE_ID),
            HashPart::Str(&state.blocked_root()),
            HashPart::Str(&state.release_credit_denial_root()),
        ],
        32,
    )
}
