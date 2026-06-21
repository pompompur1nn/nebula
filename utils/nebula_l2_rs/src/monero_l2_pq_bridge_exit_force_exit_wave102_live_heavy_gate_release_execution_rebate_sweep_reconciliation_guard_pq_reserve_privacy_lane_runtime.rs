use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::hash::{domain_hash, merkle_root, HashPart};

const CHAIN_ID: &str = "nebula-monero-private-l2-devnet";
const PROTOCOL_VERSION: &str = "wave102-live-heavy-gate-release-execution-rebate-sweep-reconciliation-guard-pq-reserve-privacy-lane-runtime-v1";
const WAVE: u64 = 102;
const DISBURSEMENT_WAVE: u64 = 101;
const MIN_RECONCILIATION_HEIGHT: u64 = 1_020_000;
const MAX_RESIDUAL_BPS: u64 = 5;
const MIN_SWEEP_CONFIRMATIONS: u64 = 720;
const LANE_ID: &str = "wave102-live-heavy-gate-release-execution-rebate-sweep-reconciliation-guard-pq-reserve-privacy";

pub type PublicRecord = Value;
pub type Runtime = State;
pub type Result<T> = core::result::Result<T, ReconciliationError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconciliationError {
    LaneMissing,
    ClaimMissing,
    Wave101LiquidityThrottleRootMissing,
    RebateAccountingRootMissing,
    FeeRefundRootMissing,
    LiquiditySweepRootMissing,
    ResidualSettlementRootMissing,
    PrivacyReconciliationRootMissing,
    CircuitBreakerRootMissing,
    OperatorSignoffRootMissing,
    ReviewerSignoffRootMissing,
    LiveHeavyGateEvidenceRootMissing,
    ReconciliationHeightTooLow,
    ResidualBpsTooHigh,
    SweepConfirmationsTooLow,
    CircuitBreakerArmed,
    ReleaseExecutionStillBlocked,
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
            Self::Compile => "Compile rebate sweep reconciliation guard",
            Self::RuntimeReplay => "Runtime replay rebate sweep reconciliation guard",
            Self::AuditSecurity => "Audit security rebate sweep reconciliation guard",
            Self::BridgeCustody => "Bridge custody rebate sweep reconciliation guard",
            Self::WalletWatchtower => "Wallet watchtower rebate sweep reconciliation guard",
            Self::PqReservePrivacy => "PQ reserve privacy rebate sweep reconciliation guard",
            Self::FinalTranscript => "Final transcript rebate sweep reconciliation guard",
        }
    }

    pub fn command_scope(self) -> &'static str {
        match self {
            Self::Compile => "compile-rebate-sweep",
            Self::RuntimeReplay => "runtime-replay-rebate-sweep",
            Self::AuditSecurity => "audit-security-rebate-sweep",
            Self::BridgeCustody => "bridge-custody-rebate-sweep",
            Self::WalletWatchtower => "wallet-watchtower-rebate-sweep",
            Self::PqReservePrivacy => "pq-reserve-privacy-rebate-sweep",
            Self::FinalTranscript => "final-transcript-rebate-sweep",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconciliationStatus {
    Empty,
    Blocked,
    RebateCandidate,
    SweepCandidate,
    PrivacyChecked,
    Reconciled,
}

impl ReconciliationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Blocked => "blocked",
            Self::RebateCandidate => "rebate_candidate",
            Self::SweepCandidate => "sweep_candidate",
            Self::PrivacyChecked => "privacy_checked",
            Self::Reconciled => "reconciled",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReconciliationBlockerKind {
    MissingWave101LiquidityThrottleRoot,
    MissingRebateAccountingRoot,
    MissingFeeRefundRoot,
    MissingLiquiditySweepRoot,
    MissingResidualSettlementRoot,
    MissingPrivacyReconciliationRoot,
    MissingCircuitBreakerRoot,
    MissingOperatorSignoffRoot,
    MissingReviewerSignoffRoot,
    MissingLiveHeavyGateEvidenceRoot,
    ReconciliationHeightTooLow,
    ResidualBpsTooHigh,
    SweepConfirmationsTooLow,
    CircuitBreakerArmed,
    ReleaseExecutionDenied,
    RootsOnlyBoundary,
}

impl ReconciliationBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingWave101LiquidityThrottleRoot => "missing_wave101_liquidity_throttle_root",
            Self::MissingRebateAccountingRoot => "missing_rebate_accounting_root",
            Self::MissingFeeRefundRoot => "missing_fee_refund_root",
            Self::MissingLiquiditySweepRoot => "missing_liquidity_sweep_root",
            Self::MissingResidualSettlementRoot => "missing_residual_settlement_root",
            Self::MissingPrivacyReconciliationRoot => "missing_privacy_reconciliation_root",
            Self::MissingCircuitBreakerRoot => "missing_circuit_breaker_root",
            Self::MissingOperatorSignoffRoot => "missing_operator_signoff_root",
            Self::MissingReviewerSignoffRoot => "missing_reviewer_signoff_root",
            Self::MissingLiveHeavyGateEvidenceRoot => "missing_live_heavy_gate_evidence_root",
            Self::ReconciliationHeightTooLow => "reconciliation_height_too_low",
            Self::ResidualBpsTooHigh => "residual_bps_too_high",
            Self::SweepConfirmationsTooLow => "sweep_confirmations_too_low",
            Self::CircuitBreakerArmed => "circuit_breaker_armed",
            Self::ReleaseExecutionDenied => "release_execution_denied",
            Self::RootsOnlyBoundary => "roots_only_boundary",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub wave: u64,
    pub disbursement_wave: u64,
    pub lane_id: String,
    pub active_lane: String,
    pub min_reconciliation_height: u64,
    pub max_residual_bps: u64,
    pub min_sweep_confirmations: u64,
    pub require_wave101_liquidity_throttle_root: bool,
    pub require_rebate_accounting_root: bool,
    pub require_fee_refund_root: bool,
    pub require_liquidity_sweep_root: bool,
    pub require_residual_settlement_root: bool,
    pub require_privacy_reconciliation_root: bool,
    pub require_circuit_breaker_root: bool,
    pub require_operator_signoff_root: bool,
    pub require_reviewer_signoff_root: bool,
    pub require_live_heavy_gate_evidence: bool,
    pub deny_release_execution_when_any_blocker_active: bool,
    pub arm_circuit_breaker_by_default: bool,
    pub heavy_gates_ran: bool,
    pub roots_only_public_records: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            wave: WAVE,
            disbursement_wave: DISBURSEMENT_WAVE,
            lane_id: LANE_ID.to_string(),
            active_lane: LaneKind::PqReservePrivacy.as_str().to_string(),
            min_reconciliation_height: MIN_RECONCILIATION_HEIGHT,
            max_residual_bps: MAX_RESIDUAL_BPS,
            min_sweep_confirmations: MIN_SWEEP_CONFIRMATIONS,
            require_wave101_liquidity_throttle_root: true,
            require_rebate_accounting_root: true,
            require_fee_refund_root: true,
            require_liquidity_sweep_root: true,
            require_residual_settlement_root: true,
            require_privacy_reconciliation_root: true,
            require_circuit_breaker_root: true,
            require_operator_signoff_root: true,
            require_reviewer_signoff_root: true,
            require_live_heavy_gate_evidence: true,
            deny_release_execution_when_any_blocker_active: true,
            arm_circuit_breaker_by_default: true,
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
            "disbursement_wave": self.disbursement_wave,
            "lane_id": self.lane_id,
            "active_lane": self.active_lane,
            "min_reconciliation_height": self.min_reconciliation_height,
            "max_residual_bps": self.max_residual_bps,
            "min_sweep_confirmations": self.min_sweep_confirmations,
            "require_wave101_liquidity_throttle_root": self.require_wave101_liquidity_throttle_root,
            "require_rebate_accounting_root": self.require_rebate_accounting_root,
            "require_fee_refund_root": self.require_fee_refund_root,
            "require_liquidity_sweep_root": self.require_liquidity_sweep_root,
            "require_residual_settlement_root": self.require_residual_settlement_root,
            "require_privacy_reconciliation_root": self.require_privacy_reconciliation_root,
            "require_circuit_breaker_root": self.require_circuit_breaker_root,
            "require_operator_signoff_root": self.require_operator_signoff_root,
            "require_reviewer_signoff_root": self.require_reviewer_signoff_root,
            "require_live_heavy_gate_evidence": self.require_live_heavy_gate_evidence,
            "deny_release_execution_when_any_blocker_active": self.deny_release_execution_when_any_blocker_active,
            "arm_circuit_breaker_by_default": self.arm_circuit_breaker_by_default,
            "heavy_gates_ran": self.heavy_gates_ran,
            "roots_only_public_records": self.roots_only_public_records,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReconciliationRoots {
    pub rebate_accounting_root: Option<String>,
    pub fee_refund_root: Option<String>,
    pub liquidity_sweep_root: Option<String>,
    pub residual_settlement_root: Option<String>,
    pub privacy_reconciliation_root: Option<String>,
    pub circuit_breaker_root: Option<String>,
    pub operator_signoff_root: Option<String>,
    pub reviewer_signoff_root: Option<String>,
    pub live_heavy_gate_evidence_root: Option<String>,
}

impl ReconciliationRoots {
    pub fn public_record(&self) -> PublicRecord {
        json!({
            "rebate_accounting_root": self.rebate_accounting_root,
            "fee_refund_root": self.fee_refund_root,
            "liquidity_sweep_root": self.liquidity_sweep_root,
            "residual_settlement_root": self.residual_settlement_root,
            "privacy_reconciliation_root": self.privacy_reconciliation_root,
            "circuit_breaker_root": self.circuit_breaker_root,
            "operator_signoff_root": self.operator_signoff_root,
            "reviewer_signoff_root": self.reviewer_signoff_root,
            "live_heavy_gate_evidence_root": self.live_heavy_gate_evidence_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reconciliation_roots", &self.public_record())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ReconciliationMeasurements {
    pub reconciliation_height: u64,
    pub residual_bps: u64,
    pub sweep_confirmations: u64,
}

impl ReconciliationMeasurements {
    pub fn blocked(config: &Config) -> Self {
        Self {
            reconciliation_height: config.min_reconciliation_height.saturating_sub(1),
            residual_bps: config.max_residual_bps.saturating_add(1),
            sweep_confirmations: config.min_sweep_confirmations.saturating_sub(1),
        }
    }

    pub fn public_record(self) -> PublicRecord {
        json!({
            "reconciliation_height": self.reconciliation_height,
            "residual_bps": self.residual_bps,
            "sweep_confirmations": self.sweep_confirmations,
        })
    }

    pub fn state_root(self) -> String {
        record_root("reconciliation_measurements", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReconciliationPolicy {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub command_scope: String,
    pub command_hint: String,
    pub release_hold_root: String,
    pub rebate_policy_root: String,
    pub refund_policy_root: String,
    pub sweep_policy_root: String,
    pub privacy_policy_root: String,
}

impl ReconciliationPolicy {
    pub fn new(lane: LaneKind, claim_label: &str, ordinal: u64) -> Self {
        let command_scope = lane.command_scope().to_string();
        let command_hint = format!(
            "nebula wave102 reconcile --lane {} --claim {} --hold-release",
            lane.as_str(),
            claim_label
        );
        let release_hold_root = label_root("release_hold", lane.as_str(), claim_label, ordinal);
        let rebate_policy_root = label_root("rebate_policy", lane.as_str(), claim_label, ordinal);
        let refund_policy_root = label_root("refund_policy", lane.as_str(), claim_label, ordinal);
        let sweep_policy_root = label_root("sweep_policy", lane.as_str(), claim_label, ordinal);
        let privacy_policy_root = label_root("privacy_policy", lane.as_str(), claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            command_scope,
            command_hint,
            release_hold_root,
            rebate_policy_root,
            refund_policy_root,
            sweep_policy_root,
            privacy_policy_root,
        }
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "command_scope": self.command_scope,
            "command_hint": self.command_hint,
            "release_hold_root": self.release_hold_root,
            "rebate_policy_root": self.rebate_policy_root,
            "refund_policy_root": self.refund_policy_root,
            "sweep_policy_root": self.sweep_policy_root,
            "privacy_policy_root": self.privacy_policy_root,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("reconciliation_policy", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseExecutionReconciliation {
    pub lane: LaneKind,
    pub claim_label: String,
    pub ordinal: u64,
    pub wave101_liquidity_throttle_root: Option<String>,
    pub roots: ReconciliationRoots,
    pub measurements: ReconciliationMeasurements,
    pub policy: ReconciliationPolicy,
    pub status: ReconciliationStatus,
    pub blockers: Vec<ReconciliationBlockerKind>,
    pub release_execution_allowed: bool,
}

impl ReleaseExecutionReconciliation {
    pub fn empty(lane: LaneKind, claim_label: &str, ordinal: u64, config: &Config) -> Self {
        let policy = ReconciliationPolicy::new(lane, claim_label, ordinal);
        Self {
            lane,
            claim_label: claim_label.to_string(),
            ordinal,
            wave101_liquidity_throttle_root: None,
            roots: ReconciliationRoots::default(),
            measurements: ReconciliationMeasurements::blocked(config),
            policy,
            status: ReconciliationStatus::Blocked,
            blockers: initial_blockers(config),
            release_execution_allowed: false,
        }
    }

    pub fn stage_reconciliation(
        mut self,
        wave101_liquidity_throttle_root: String,
        roots: ReconciliationRoots,
        measurements: ReconciliationMeasurements,
        config: &Config,
    ) -> Self {
        self.wave101_liquidity_throttle_root = Some(wave101_liquidity_throttle_root);
        self.roots = roots;
        self.measurements = measurements;
        self.blockers = self.active_blockers(config);
        self.status = if self.blockers.is_empty() {
            ReconciliationStatus::PrivacyChecked
        } else if self.roots.liquidity_sweep_root.is_some() {
            ReconciliationStatus::SweepCandidate
        } else if self.roots.rebate_accounting_root.is_some() {
            ReconciliationStatus::RebateCandidate
        } else {
            ReconciliationStatus::Blocked
        };
        self.release_execution_allowed = false;
        self
    }

    pub fn mark_reconciled(mut self, config: &Config) -> Result<Self> {
        self.blockers = self.active_blockers(config);
        if self.blockers.is_empty() {
            self.status = ReconciliationStatus::Reconciled;
            self.release_execution_allowed = true;
            Ok(self)
        } else {
            Err(ReconciliationError::ReleaseExecutionStillBlocked)
        }
    }

    pub fn active_blockers(&self, config: &Config) -> Vec<ReconciliationBlockerKind> {
        let mut blockers = Vec::new();
        if config.require_wave101_liquidity_throttle_root
            && self.wave101_liquidity_throttle_root.is_none()
        {
            blockers.push(ReconciliationBlockerKind::MissingWave101LiquidityThrottleRoot);
        }
        if config.require_rebate_accounting_root && self.roots.rebate_accounting_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingRebateAccountingRoot);
        }
        if config.require_fee_refund_root && self.roots.fee_refund_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingFeeRefundRoot);
        }
        if config.require_liquidity_sweep_root && self.roots.liquidity_sweep_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingLiquiditySweepRoot);
        }
        if config.require_residual_settlement_root && self.roots.residual_settlement_root.is_none()
        {
            blockers.push(ReconciliationBlockerKind::MissingResidualSettlementRoot);
        }
        if config.require_privacy_reconciliation_root
            && self.roots.privacy_reconciliation_root.is_none()
        {
            blockers.push(ReconciliationBlockerKind::MissingPrivacyReconciliationRoot);
        }
        if config.require_circuit_breaker_root && self.roots.circuit_breaker_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingCircuitBreakerRoot);
        }
        if config.require_operator_signoff_root && self.roots.operator_signoff_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingOperatorSignoffRoot);
        }
        if config.require_reviewer_signoff_root && self.roots.reviewer_signoff_root.is_none() {
            blockers.push(ReconciliationBlockerKind::MissingReviewerSignoffRoot);
        }
        if config.require_live_heavy_gate_evidence
            && self.roots.live_heavy_gate_evidence_root.is_none()
        {
            blockers.push(ReconciliationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
        }
        if self.measurements.reconciliation_height < config.min_reconciliation_height {
            blockers.push(ReconciliationBlockerKind::ReconciliationHeightTooLow);
        }
        if self.measurements.residual_bps > config.max_residual_bps {
            blockers.push(ReconciliationBlockerKind::ResidualBpsTooHigh);
        }
        if self.measurements.sweep_confirmations < config.min_sweep_confirmations {
            blockers.push(ReconciliationBlockerKind::SweepConfirmationsTooLow);
        }
        if config.arm_circuit_breaker_by_default {
            blockers.push(ReconciliationBlockerKind::CircuitBreakerArmed);
        }
        if config.deny_release_execution_when_any_blocker_active {
            blockers.push(ReconciliationBlockerKind::ReleaseExecutionDenied);
        }
        if config.roots_only_public_records {
            blockers.push(ReconciliationBlockerKind::RootsOnlyBoundary);
        }
        blockers
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "lane": self.lane.as_str(),
            "lane_title": self.lane.title(),
            "claim_label": self.claim_label,
            "ordinal": self.ordinal,
            "wave101_liquidity_throttle_root": self.wave101_liquidity_throttle_root,
            "roots_root": self.roots.state_root(),
            "measurements_root": self.measurements.state_root(),
            "policy_root": self.policy.state_root(),
            "status": self.status.as_str(),
            "blockers": self.blockers.iter().map(|blocker| blocker.as_str()).collect::<Vec<_>>(),
            "release_execution_allowed": self.release_execution_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_execution_reconciliation", &self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    pub config: Config,
    pub lane: LaneKind,
    pub lane_title: String,
    pub checkpoints: Vec<ReleaseExecutionReconciliation>,
    pub command_hints: Vec<String>,
    pub release_execution_denied: bool,
    pub heavy_gates_ran: bool,
}

impl State {
    pub fn new(
        config: Config,
        lane: LaneKind,
        checkpoints: Vec<ReleaseExecutionReconciliation>,
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
            release_execution_denied: true,
            heavy_gates_ran: false,
        }
    }

    pub fn active_blockers(&self) -> Vec<ReconciliationBlockerKind> {
        self.checkpoints
            .iter()
            .flat_map(|checkpoint| checkpoint.blockers.iter().copied())
            .collect::<Vec<_>>()
    }

    pub fn reconciled_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| checkpoint.status == ReconciliationStatus::Reconciled)
            .count()
    }

    pub fn blocked_count(&self) -> usize {
        self.checkpoints
            .iter()
            .filter(|checkpoint| !checkpoint.blockers.is_empty())
            .count()
    }

    pub fn rebate_accounting_root(&self) -> String {
        status_root(
            "wave102_rebate_accounting_candidates",
            &self.checkpoints,
            ReconciliationStatus::RebateCandidate,
        )
    }

    pub fn liquidity_sweep_root(&self) -> String {
        status_root(
            "wave102_liquidity_sweep_candidates",
            &self.checkpoints,
            ReconciliationStatus::SweepCandidate,
        )
    }

    pub fn privacy_reconciliation_root(&self) -> String {
        status_root(
            "wave102_privacy_reconciliation_candidates",
            &self.checkpoints,
            ReconciliationStatus::PrivacyChecked,
        )
    }

    pub fn reconciled_root(&self) -> String {
        status_root(
            "wave102_reconciled_release_execution_claims",
            &self.checkpoints,
            ReconciliationStatus::Reconciled,
        )
    }

    pub fn blocked_root(&self) -> String {
        blocked_root(&self.checkpoints)
    }

    pub fn command_root(&self) -> String {
        root_from_strings(
            "wave102_reconciliation_command_hints",
            self.command_hints.clone(),
        )
    }

    pub fn lane_summary_root(&self) -> String {
        domain_hash(
            "wave102-release-execution-rebate-sweep-reconciliation-lane-summary",
            &[
                HashPart::Str(CHAIN_ID),
                HashPart::Str(PROTOCOL_VERSION),
                HashPart::Str(LANE_ID),
                HashPart::Str(self.lane.as_str()),
                HashPart::U64(WAVE),
                HashPart::U64(self.checkpoints.len() as u64),
                HashPart::U64(self.blocked_count() as u64),
                HashPart::U64(self.reconciled_count() as u64),
            ],
            32,
        )
    }

    pub fn release_execution_denial_root(&self) -> String {
        let blocker_labels = self
            .active_blockers()
            .into_iter()
            .map(|blocker| blocker.as_str().to_string())
            .collect::<Vec<_>>();
        root_from_strings("wave102_release_execution_denial_blockers", blocker_labels)
    }

    pub fn public_record(&self) -> PublicRecord {
        json!({
            "config_root": self.config.state_root(),
            "lane": self.lane.as_str(),
            "lane_title": self.lane_title,
            "checkpoint_count": self.checkpoints.len(),
            "blocked_count": self.blocked_count(),
            "reconciled_count": self.reconciled_count(),
            "rebate_accounting_root": self.rebate_accounting_root(),
            "liquidity_sweep_root": self.liquidity_sweep_root(),
            "privacy_reconciliation_root": self.privacy_reconciliation_root(),
            "reconciled_root": self.reconciled_root(),
            "blocked_root": self.blocked_root(),
            "command_root": self.command_root(),
            "lane_summary_root": self.lane_summary_root(),
            "release_execution_denial_root": self.release_execution_denial_root(),
            "release_execution_denied": self.release_execution_denied,
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
    let claim_labels = [
        "pq_authority_rebate",
        "reserve_fee_refund",
        "privacy_liquidity_sweep",
        "metadata_residual_settlement",
        "privacy_budget_packet",
        "pq_release_hold",
    ];
    let checkpoints = claim_labels
        .iter()
        .enumerate()
        .map(|(index, claim_label)| {
            ReleaseExecutionReconciliation::empty(lane, claim_label, (index + 1) as u64, &config)
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

fn initial_blockers(config: &Config) -> Vec<ReconciliationBlockerKind> {
    let mut blockers = Vec::new();
    if config.require_wave101_liquidity_throttle_root {
        blockers.push(ReconciliationBlockerKind::MissingWave101LiquidityThrottleRoot);
    }
    if config.require_rebate_accounting_root {
        blockers.push(ReconciliationBlockerKind::MissingRebateAccountingRoot);
    }
    if config.require_fee_refund_root {
        blockers.push(ReconciliationBlockerKind::MissingFeeRefundRoot);
    }
    if config.require_liquidity_sweep_root {
        blockers.push(ReconciliationBlockerKind::MissingLiquiditySweepRoot);
    }
    if config.require_residual_settlement_root {
        blockers.push(ReconciliationBlockerKind::MissingResidualSettlementRoot);
    }
    if config.require_privacy_reconciliation_root {
        blockers.push(ReconciliationBlockerKind::MissingPrivacyReconciliationRoot);
    }
    if config.require_circuit_breaker_root {
        blockers.push(ReconciliationBlockerKind::MissingCircuitBreakerRoot);
    }
    if config.require_operator_signoff_root {
        blockers.push(ReconciliationBlockerKind::MissingOperatorSignoffRoot);
    }
    if config.require_reviewer_signoff_root {
        blockers.push(ReconciliationBlockerKind::MissingReviewerSignoffRoot);
    }
    if config.require_live_heavy_gate_evidence {
        blockers.push(ReconciliationBlockerKind::MissingLiveHeavyGateEvidenceRoot);
    }
    blockers.push(ReconciliationBlockerKind::ReconciliationHeightTooLow);
    blockers.push(ReconciliationBlockerKind::ResidualBpsTooHigh);
    blockers.push(ReconciliationBlockerKind::SweepConfirmationsTooLow);
    if config.arm_circuit_breaker_by_default {
        blockers.push(ReconciliationBlockerKind::CircuitBreakerArmed);
    }
    if config.deny_release_execution_when_any_blocker_active {
        blockers.push(ReconciliationBlockerKind::ReleaseExecutionDenied);
    }
    if config.roots_only_public_records {
        blockers.push(ReconciliationBlockerKind::RootsOnlyBoundary);
    }
    blockers
}

fn blocked_root(checkpoints: &[ReleaseExecutionReconciliation]) -> String {
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
        "wave102_blocked_release_execution_reconciliation_guards",
        &leaves,
    )
}

fn status_root(
    domain: &str,
    checkpoints: &[ReleaseExecutionReconciliation],
    status: ReconciliationStatus,
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

fn reconciliation_guard_root(
    guard_kind: &str,
    lane: LaneKind,
    claim_label: &str,
    ordinal: u64,
    first_guard_root: &str,
    second_guard_root: &str,
) -> String {
    domain_hash(
        "wave102-live-heavy-gate-release-execution-rebate-sweep-reconciliation-guard",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(PROTOCOL_VERSION),
            HashPart::Str(guard_kind),
            HashPart::Str(lane.as_str()),
            HashPart::Str(claim_label),
            HashPart::U64(ordinal),
            HashPart::Str(first_guard_root),
            HashPart::Str(second_guard_root),
        ],
        32,
    )
}

fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "wave102-live-heavy-gate-release-execution-rebate-sweep-reconciliation-record",
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
        "wave102-live-heavy-gate-release-execution-rebate-sweep-reconciliation-label",
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

pub fn devnet_reconciliation_guard_root() -> String {
    let state = devnet();
    reconciliation_guard_root(
        "devnet_release_hold",
        state.lane,
        LANE_ID,
        WAVE,
        &state.blocked_root(),
        &state.release_execution_denial_root(),
    )
}
