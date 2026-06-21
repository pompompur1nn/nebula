use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-wallet-watchtower-lane-runtime-v1";
const WAVE: u64 = 104;
const PRIOR_WAVE: u64 = 103;
const MIN_WALLET_SCAN_HEIGHT: u64 = 1_040_000;
const MIN_WATCHTOWER_WITNESSES: u64 = 3;
const MIN_CONFIRMATION_LADDER_DEPTH: u64 = 10;
const LANE_ID: &str =
    "wave104-live-heavy-gate-release-execution-monero-tx-relay-witness-confirmation-guard-wallet-watchtower";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, ConfirmationGuardError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationGuardError {
    LaneMissing,
    ClaimMissing,
    Wave103BroadcastQuarantineRootMissing,
    WalletScanRootMissing,
    WatchtowerRelayWitnessRootMissing,
    MempoolAcceptanceRootMissing,
    TxidCommitmentRootMissing,
    BlockInclusionCandidateRootMissing,
    ConfirmationLadderRootMissing,
    ReorgMonitorRootMissing,
    WalletNoticeRootMissing,
    PqAuthorizationRootMissing,
    CircuitBreakerRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    WalletScanHeightTooLow,
    WatchtowerWitnessQuorumTooLow,
    ConfirmationLadderDepthTooLow,
    CircuitBreakerArmed,
    ConfirmationStillBlocked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LaneKind {
    WalletWatchtower,
}

impl LaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletWatchtower => "wallet_watchtower",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::WalletWatchtower => {
                "Wallet watchtower Monero tx relay witness confirmation guard"
            }
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::WalletWatchtower => "wallet-watchtower-relay-witness-confirmation",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationGuardStatus {
    Empty,
    Blocked,
    WalletObserved,
    WitnessObserved,
    MempoolAccepted,
    InclusionCandidate,
    Confirmed,
}

impl ConfirmationGuardStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::WalletObserved => "wallet_observed",
            Self::WitnessObserved => "witness_observed",
            Self::MempoolAccepted => "mempool_accepted",
            Self::InclusionCandidate => "inclusion_candidate",
            Self::Confirmed => "confirmed",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ConfirmationBlockerKind {
    MissingWave103BroadcastQuarantineRoot,
    MissingWalletScanRoot,
    MissingWatchtowerRelayWitnessRoot,
    MissingMempoolAcceptanceRoot,
    MissingTxidCommitmentRoot,
    MissingBlockInclusionCandidateRoot,
    MissingConfirmationLadderRoot,
    MissingReorgMonitorRoot,
    MissingWalletNoticeRoot,
    MissingPqAuthorizationRoot,
    MissingCircuitBreakerRoot,
    MissingLiveHeavyGateEvidenceRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    WalletScanHeightTooLow,
    WatchtowerWitnessQuorumTooLow,
    ConfirmationLadderDepthTooLow,
    CircuitBreakerArmed,
    ConfirmationDenied,
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
            Self::MissingWalletScanRoot => "missing_wallet_scan_root",
            Self::MissingWatchtowerRelayWitnessRoot => "missing_watchtower_relay_witness_root",
            Self::MissingMempoolAcceptanceRoot => "missing_mempool_acceptance_root",
            Self::MissingTxidCommitmentRoot => "missing_txid_commitment_root",
            Self::MissingBlockInclusionCandidateRoot => "missing_block_inclusion_candidate_root",
            Self::MissingConfirmationLadderRoot => "missing_confirmation_ladder_root",
            Self::MissingReorgMonitorRoot => "missing_reorg_monitor_root",
            Self::MissingWalletNoticeRoot => "missing_wallet_notice_root",
            Self::MissingPqAuthorizationRoot => "missing_pq_authorization_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::WalletScanHeightTooLow => "wallet_scan_height_too_low",
            Self::WatchtowerWitnessQuorumTooLow => "watchtower_witness_quorum_too_low",
            Self::ConfirmationLadderDepthTooLow => "confirmation_ladder_depth_too_low",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ConfirmationDenied => "confirmation_denied",
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
    pub prior_wave: u64,
    pub lane_id: String,
    pub active_lane: String,
    pub min_wallet_scan_height: u64,
    pub min_watchtower_witnesses: u64,
    pub min_confirmation_ladder_depth: u64,
    pub require_wave103_broadcast_quarantine_root: bool,
    pub require_wallet_scan_root: bool,
    pub require_watchtower_relay_witness_root: bool,
    pub require_mempool_acceptance_root: bool,
    pub require_txid_commitment_root: bool,
    pub require_block_inclusion_candidate_root: bool,
    pub require_confirmation_ladder_root: bool,
    pub require_reorg_monitor_root: bool,
    pub require_wallet_notice_root: bool,
    pub require_pq_authorization_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_live_heavy_gate_evidence: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub deny_confirmation_when_any_blocker_active: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub confirmation_disabled: bool,
    pub heavy_gates_ran: bool,
    pub roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            prior_wave: PRIOR_WAVE,
            lane_id: LANE_ID.to_string(),
            active_lane: LaneKind::WalletWatchtower.as_str().to_string(),
            min_wallet_scan_height: MIN_WALLET_SCAN_HEIGHT,
            min_watchtower_witnesses: MIN_WATCHTOWER_WITNESSES,
            min_confirmation_ladder_depth: MIN_CONFIRMATION_LADDER_DEPTH,
            require_wave103_broadcast_quarantine_root: true,
            require_wallet_scan_root: true,
            require_watchtower_relay_witness_root: true,
            require_mempool_acceptance_root: true,
            require_txid_commitment_root: true,
            require_block_inclusion_candidate_root: true,
            require_confirmation_ladder_root: true,
            require_reorg_monitor_root: true,
            require_wallet_notice_root: true,
            require_pq_authorization_root: true,
            require_circuit_breaker_root: true,
            require_live_heavy_gate_evidence: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            deny_confirmation_when_any_blocker_active: true,
            arm_circuit_breaker_by_default: true,
            confirmation_allowed: false,
            release_credit_allowed: false,
            confirmation_disabled: true,
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
            "prior_wave": self.prior_wave,
            "lane_id": self.lane_id,
            "active_lane": self.active_lane,
            "min_wallet_scan_height": self.min_wallet_scan_height,
            "min_watchtower_witnesses": self.min_watchtower_witnesses,
            "min_confirmation_ladder_depth": self.min_confirmation_ladder_depth,
            "require_wave103_broadcast_quarantine_root": self.require_wave103_broadcast_quarantine_root,
            "require_wallet_scan_root": self.require_wallet_scan_root,
            "require_watchtower_relay_witness_root": self.require_watchtower_relay_witness_root,
            "require_mempool_acceptance_root": self.require_mempool_acceptance_root,
            "require_txid_commitment_root": self.require_txid_commitment_root,
            "require_block_inclusion_candidate_root": self.require_block_inclusion_candidate_root,
            "require_confirmation_ladder_root": self.require_confirmation_ladder_root,
            "require_reorg_monitor_root": self.require_reorg_monitor_root,
            "require_wallet_notice_root": self.require_wallet_notice_root,
            "require_pq_authorization_root": self.require_pq_authorization_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_live_heavy_gate_evidence": self.require_live_heavy_gate_evidence,
            "require_operator_signoff_root": self.require_operator_signoff_root,
            "require_reviewer_signoff_root": self.require_reviewer_signoff_root,
            "deny_confirmation_when_any_blocker_active": self.deny_confirmation_when_any_blocker_active,
            "arm_circuit_breaker_by_default": self.arm_circuit_breaker_by_default,
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "confirmation_disabled": self.confirmation_disabled,
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
    pub wallet_scan_root: Option<String>,
    pub watchtower_relay_witness_root: Option<String>,
    pub mempool_acceptance_root: Option<String>,
    pub txid_commitment_root: Option<String>,
    pub block_inclusion_candidate_root: Option<String>,
    pub confirmation_ladder_root: Option<String>,
    pub reorg_monitor_root: Option<String>,
    pub wallet_notice_root: Option<String>,
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
            "wallet_scan_root": self.wallet_scan_root,
            "watchtower_relay_witness_root": self.watchtower_relay_witness_root,
            "mempool_acceptance_root": self.mempool_acceptance_root,
            "txid_commitment_root": self.txid_commitment_root,
            "block_inclusion_candidate_root": self.block_inclusion_candidate_root,
            "confirmation_ladder_root": self.confirmation_ladder_root,
            "reorg_monitor_root": self.reorg_monitor_root,
            "wallet_notice_root": self.wallet_notice_root,
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
    pub wallet_scan_height: u64,
    pub watchtower_witnesses: u64,
    pub confirmation_ladder_depth: u64,
}

impl ConfirmationMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            wallet_scan_height: config.min_wallet_scan_height.saturating_sub(1),
            watchtower_witnesses: config.min_watchtower_witnesses.saturating_sub(1),
            confirmation_ladder_depth: config.min_confirmation_ladder_depth.saturating_sub(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "wallet_scan_height": self.wallet_scan_height,
            "watchtower_witnesses": self.watchtower_witnesses,
            "confirmation_ladder_depth": self.confirmation_ladder_depth,
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
    pub confirmation_hold_root: String,
    pub relay_witness_policy_root: String,
    pub mempool_acceptance_policy_root: String,
    pub reorg_monitor_policy_root: String,
    pub release_credit_policy_root: String,
}

impl ConfirmationPolicy {
    pub fn new(lane: LaneKind, claim_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave104 confirm-relay-witness --lane {} --claim {} --hold-confirmation",
            lane.as_str(),
            claim_label
        );
        let confirmation_hold_root =
            label_root("confirmation_hold", lane.as_str(), claim_label, ordinal);
        let relay_witness_policy_root =
            label_root("relay_witness_policy", lane.as_str(), claim_label, ordinal);
        let mempool_acceptance_policy_root = label_root(
            "mempool_acceptance_policy",
            lane.as_str(),
            claim_label,
            ordinal,
        );
        let reorg_monitor_policy_root =
            label_root("reorg_monitor_policy", lane.as_str(), claim_label, ordinal);
        let release_credit_policy_root =
            label_root("release_credit_policy", lane.as_str(), claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            confirmation_hold_root,
            relay_witness_policy_root,
            mempool_acceptance_policy_root,
            reorg_monitor_policy_root,
            release_credit_policy_root,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "confirmation_hold_root": self.confirmation_hold_root,
            "relay_witness_policy_root": self.relay_witness_policy_root,
            "mempool_acceptance_policy_root": self.mempool_acceptance_policy_root,
            "reorg_monitor_policy_root": self.reorg_monitor_policy_root,
            "release_credit_policy_root": self.release_credit_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("confirmation_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MoneroTxRelayWitnessConfirmation {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub roots: ConfirmationRoots,
    pub measurements: ConfirmationMeasurements,
    pub policy: ConfirmationPolicy,
    pub status: ConfirmationGuardStatus,
    pub blockers: Vec<ConfirmationBlockerKind>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub confirmation_disabled: bool,
}

impl MoneroTxRelayWitnessConfirmation {
    pub fn empty(lane: LaneKind, claim_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = ConfirmationPolicy::new(lane, claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            roots: ConfirmationRoots::default(),
            measurements: ConfirmationMeasurements::blocked(config),
            policy,
            status: ConfirmationGuardStatus::Blocked,
            blockers: initial_blockers(config),
            confirmation_allowed: false,
            release_credit_allowed: false,
            confirmation_disabled: true,
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
            ConfirmationGuardStatus::Confirmed
        } else if self.roots.block_inclusion_candidate_root.is_some() {
            ConfirmationGuardStatus::InclusionCandidate
        } else if self.roots.mempool_acceptance_root.is_some() {
            ConfirmationGuardStatus::MempoolAccepted
        } else if self.roots.watchtower_relay_witness_root.is_some() {
            ConfirmationGuardStatus::WitnessObserved
        } else if self.roots.wallet_scan_root.is_some() {
            ConfirmationGuardStatus::WalletObserved
        } else {
            ConfirmationGuardStatus::Blocked
        };
        self.confirmation_allowed = false;
        self.release_credit_allowed = false;
        self.confirmation_disabled = true;
        self
    }

    pub fn release_credit(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty()
            && config.confirmation_allowed
            && config.release_credit_allowed
            && !config.confirmation_disabled
        {
            self.status = ConfirmationGuardStatus::Confirmed;
            self.confirmation_allowed = true;
            self.release_credit_allowed = true;
            self.confirmation_disabled = false;
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
        if config.require_wallet_scan_root && self.roots.wallet_scan_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingWalletScanRoot);
        }
        if config.require_watchtower_relay_witness_root
            && self.roots.watchtower_relay_witness_root.is_none()
        {
            blockers.push(ConfirmationBlockerKind::MissingWatchtowerRelayWitnessRoot);
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
        if config.require_wallet_notice_root && self.roots.wallet_notice_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingWalletNoticeRoot);
        }
        if config.require_pq_authorization_root && self.roots.pq_authorization_root.is_none() {
            blockers.push(ConfirmationBlockerKind::MissingPqAuthorizationRoot);
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
        if self.measurements.wallet_scan_height < config.min_wallet_scan_height {
            blockers.push(ConfirmationBlockerKind::WalletScanHeightTooLow);
        }
        if self.measurements.watchtower_witnesses < config.min_watchtower_witnesses {
            blockers.push(ConfirmationBlockerKind::WatchtowerWitnessQuorumTooLow);
        }
        if self.measurements.confirmation_ladder_depth < config.min_confirmation_ladder_depth {
            blockers.push(ConfirmationBlockerKind::ConfirmationLadderDepthTooLow);
        }
        if config.arm_circuit_breaker_by_default {
            blockers.push(ConfirmationBlockerKind::CircuitBreakerArmed);
        }
        if config.deny_confirmation_when_any_blocker_active {
            blockers.push(ConfirmationBlockerKind::ConfirmationDenied);
        }
        if config.confirmation_disabled || !config.confirmation_allowed {
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
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "roots_root": self.roots.state_root(),
            "measurements_root": self.measurements.state_root(),
            "policy_root": self.policy.state_root(),
            "status": self.status.as_str(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "confirmation_disabled": self.confirmation_disabled,
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
    pub checkpoints: Vec<MoneroTxRelayWitnessConfirmation>,
    pub confirmation_allowed: bool,
    pub release_credit_allowed: bool,
    pub confirmation_disabled: bool,
    pub heavy_gates_ran: bool,
    pub command_hints: Vec<String>,
}

impl State {
    pub fn new(
        config: Config,
        lane: LaneKind,
        checkpoints: Vec<MoneroTxRelayWitnessConfirmation>,
    ) -> Self {
        let command_hints = checkpoints
            .iter()
            .map(|checkpoint| checkpoint.policy.command_hint.clone())
            .collect::<Vec<_>>();
        Self {
            confirmation_allowed: config.confirmation_allowed,
            release_credit_allowed: config.release_credit_allowed,
            confirmation_disabled: config.confirmation_disabled,
            heavy_gates_ran: config.heavy_gates_ran,
            lane_title: lane.title().to_string(),
            config,
            lane,
            checkpoints,
            command_hints,
        }
    }

    pub fn active_blockers(&self) -> Vec<ConfirmationBlockerKind> {
        let mut blockers = self
            .checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>();
        blockers.sort_by_key(|blocker| blocker.as_str());
        blockers.dedup_by_key(|blocker| blocker.as_str());
        blockers
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status != ConfirmationGuardStatus::Confirmed)
            .count()
    }

    pub fn confirmed_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == ConfirmationGuardStatus::Confirmed)
            .count()
    }

    pub fn wallet_observed_root(&self) -> String {
        status_root(
            "wave104_wallet_observed_monero_tx_relay_witness_confirmations",
            &self.checkpoints,
            ConfirmationGuardStatus::WalletObserved,
        )
    }

    pub fn witness_observed_root(&self) -> String {
        status_root(
            "wave104_watchtower_witness_observed_monero_tx_confirmations",
            &self.checkpoints,
            ConfirmationGuardStatus::WitnessObserved,
        )
    }

    pub fn mempool_accepted_root(&self) -> String {
        status_root(
            "wave104_mempool_accepted_monero_tx_confirmations",
            &self.checkpoints,
            ConfirmationGuardStatus::MempoolAccepted,
        )
    }

    pub fn inclusion_candidate_root(&self) -> String {
        status_root(
            "wave104_block_inclusion_candidate_monero_tx_confirmations",
            &self.checkpoints,
            ConfirmationGuardStatus::InclusionCandidate,
        )
    }

    pub fn confirmed_root(&self) -> String {
        status_root(
            "wave104_confirmed_monero_tx_relay_witness_confirmations",
            &self.checkpoints,
            ConfirmationGuardStatus::Confirmed,
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
                HashPart::U64(self.confirmed_count() as u64),
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
            "confirmed_count": self.confirmed_count(),
            "wallet_observed_root": self.wallet_observed_root(),
            "witness_observed_root": self.witness_observed_root(),
            "mempool_accepted_root": self.mempool_accepted_root(),
            "inclusion_candidate_root": self.inclusion_candidate_root(),
            "confirmed_root": self.confirmed_root(),
            "blocked_root": self.blocked_root(),
            "command_root": self.command_root(),
            "lane_summary_root": self.lane_summary_root(),
            "confirmation_denial_root": self.confirmation_denial_root(),
            "confirmation_allowed": self.confirmation_allowed,
            "release_credit_allowed": self.release_credit_allowed,
            "confirmation_disabled": self.confirmation_disabled,
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
    let lane = LaneKind::WalletWatchtower;
    let claim_labels = [
        "wave103_broadcast_quarantine_anchor",
        "wallet_scan_snapshot",
        "watchtower_relay_witness_quorum",
        "mempool_acceptance_observation",
        "txid_commitment_record",
        "block_inclusion_candidate",
        "confirmation_ladder_snapshot",
        "reorg_monitor_hold",
        "wallet_notice_hold",
        "operator_reviewer_confirmation_hold",
    ];
    let checkpoints = claim_labels
        .iter()
        .enumerate()
        .map(|(index, claim_label)| {
            MoneroTxRelayWitnessConfirmation::empty(lane, claim_label, (index + 1) as u64, &config)
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
    if config.require_wallet_scan_root {
        blockers.push(ConfirmationBlockerKind::MissingWalletScanRoot);
    }
    if config.require_watchtower_relay_witness_root {
        blockers.push(ConfirmationBlockerKind::MissingWatchtowerRelayWitnessRoot);
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
    if config.require_wallet_notice_root {
        blockers.push(ConfirmationBlockerKind::MissingWalletNoticeRoot);
    }
    if config.require_pq_authorization_root {
        blockers.push(ConfirmationBlockerKind::MissingPqAuthorizationRoot);
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
    blockers.push(ConfirmationBlockerKind::WalletScanHeightTooLow);
    blockers.push(ConfirmationBlockerKind::WatchtowerWitnessQuorumTooLow);
    blockers.push(ConfirmationBlockerKind::ConfirmationLadderDepthTooLow);
    if config.arm_circuit_breaker_by_default {
        blockers.push(ConfirmationBlockerKind::CircuitBreakerArmed);
    }
    if config.deny_confirmation_when_any_blocker_active {
        blockers.push(ConfirmationBlockerKind::ConfirmationDenied);
    }
    if config.confirmation_disabled || !config.confirmation_allowed {
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

fn blocked_root(checkpoints: &[MoneroTxRelayWitnessConfirmation]) -> String {
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
    checkpoints: &[MoneroTxRelayWitnessConfirmation],
    status: ConfirmationGuardStatus,
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
