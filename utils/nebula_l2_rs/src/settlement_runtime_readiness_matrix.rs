use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type SettlementRuntimeReadinessMatrixResult<T> = Result<T, String>;

pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION: &str =
    "nebula-settlement-runtime-readiness-matrix-v1";
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEVNET_HEIGHT: u64 = 1_440;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS: u64 = 10_000;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_RELEASE_SCORE_BPS: u64 = 9_400;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_CRITICAL_SCORE_BPS: u64 = 10_000;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS: u64 = 12_500;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_OPEN_BLOCKERS: u64 = 0;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_CRITICAL_INCIDENTS: u64 = 0;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_ROOT_DRIFT_EVENTS: u64 = 0;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_FRAUD_WINDOW_BLOCKS: u64 = 720;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_REMEDIATION_TTL_BLOCKS: u64 = 2_880;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_GATE_TTL_BLOCKS: u64 = 1_440;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_LANES: usize = 96;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_CHECKS: usize = 512;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_PROOF_QUEUES: usize = 128;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_FINALITY_SIGNALS: usize = 256;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_FRAUD_WINDOWS: usize = 128;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_RESERVES: usize = 128;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_STATE_ROOTS: usize = 256;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_INCIDENTS: usize = 256;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_RELEASE_GATES: usize = 256;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_TICKETS: usize = 512;
pub const SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_REPORTS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementLaneKind {
    MoneroFastExit,
    MoneroPrivateExit,
    MoneroBatchExit,
    MoneroAtomicSwap,
    RecursiveProofSettlement,
    PqFinalityBridge,
    FraudProofChallenge,
    LiquidityRebalance,
    StateRootAnchor,
    OperatorRecovery,
}

impl SettlementLaneKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroFastExit => "monero_fast_exit",
            Self::MoneroPrivateExit => "monero_private_exit",
            Self::MoneroBatchExit => "monero_batch_exit",
            Self::MoneroAtomicSwap => "monero_atomic_swap",
            Self::RecursiveProofSettlement => "recursive_proof_settlement",
            Self::PqFinalityBridge => "pq_finality_bridge",
            Self::FraudProofChallenge => "fraud_proof_challenge",
            Self::LiquidityRebalance => "liquidity_rebalance",
            Self::StateRootAnchor => "state_root_anchor",
            Self::OperatorRecovery => "operator_recovery",
        }
    }

    pub fn monero_bound(self) -> bool {
        matches!(
            self,
            Self::MoneroFastExit
                | Self::MoneroPrivateExit
                | Self::MoneroBatchExit
                | Self::MoneroAtomicSwap
        )
    }

    pub fn critical(self) -> bool {
        matches!(
            self,
            Self::MoneroFastExit
                | Self::RecursiveProofSettlement
                | Self::PqFinalityBridge
                | Self::StateRootAnchor
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessCheckKind {
    MoneroHeaderDepth,
    MoneroExitNullifier,
    MoneroReserveProof,
    RecursiveProofQueue,
    RecursiveProofVerifier,
    PqCommitteeQuorum,
    PqSignatureFreshness,
    FraudWindowOpen,
    FraudBondCoverage,
    LiquidityCoverage,
    StateRootContinuity,
    StateRootDaAvailability,
    OperatorIncidentBudget,
    OperatorRunbookDrill,
    ReleaseGateSignoff,
    ReleaseGateTimelock,
}

impl ReadinessCheckKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroHeaderDepth => "monero_header_depth",
            Self::MoneroExitNullifier => "monero_exit_nullifier",
            Self::MoneroReserveProof => "monero_reserve_proof",
            Self::RecursiveProofQueue => "recursive_proof_queue",
            Self::RecursiveProofVerifier => "recursive_proof_verifier",
            Self::PqCommitteeQuorum => "pq_committee_quorum",
            Self::PqSignatureFreshness => "pq_signature_freshness",
            Self::FraudWindowOpen => "fraud_window_open",
            Self::FraudBondCoverage => "fraud_bond_coverage",
            Self::LiquidityCoverage => "liquidity_coverage",
            Self::StateRootContinuity => "state_root_continuity",
            Self::StateRootDaAvailability => "state_root_da_availability",
            Self::OperatorIncidentBudget => "operator_incident_budget",
            Self::OperatorRunbookDrill => "operator_runbook_drill",
            Self::ReleaseGateSignoff => "release_gate_signoff",
            Self::ReleaseGateTimelock => "release_gate_timelock",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessSeverity {
    Advisory,
    Required,
    Critical,
    Blocker,
}

impl ReadinessSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Required => "required",
            Self::Critical => "critical",
            Self::Blocker => "blocker",
        }
    }

    pub fn weight_bps(self) -> u64 {
        match self {
            Self::Advisory => 1_000,
            Self::Required => 5_000,
            Self::Critical => 8_500,
            Self::Blocker => 10_000,
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(self, Self::Critical | Self::Blocker)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadinessStatus {
    Draft,
    Observing,
    Passing,
    Degraded,
    Blocked,
    Waived,
    Retired,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Observing => "observing",
            Self::Passing => "passing",
            Self::Degraded => "degraded",
            Self::Blocked => "blocked",
            Self::Waived => "waived",
            Self::Retired => "retired",
        }
    }

    pub fn passing(self) -> bool {
        matches!(self, Self::Passing | Self::Waived | Self::Retired)
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Draft | Self::Observing | Self::Degraded | Self::Blocked
        )
    }

    pub fn blocked(self) -> bool {
        matches!(self, Self::Blocked)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofQueueStatus {
    Empty,
    Filling,
    Proving,
    Verifying,
    Settled,
    Delayed,
    Blocked,
}

impl ProofQueueStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Filling => "filling",
            Self::Proving => "proving",
            Self::Verifying => "verifying",
            Self::Settled => "settled",
            Self::Delayed => "delayed",
            Self::Blocked => "blocked",
        }
    }

    pub fn healthy(self) -> bool {
        matches!(
            self,
            Self::Empty | Self::Filling | Self::Proving | Self::Verifying | Self::Settled
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalitySignalKind {
    PqCommitteeSignature,
    RecursiveProofAccepted,
    MoneroDepthReached,
    DaRootAvailable,
    GovernanceDelayElapsed,
    WatchtowerAck,
}

impl FinalitySignalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PqCommitteeSignature => "pq_committee_signature",
            Self::RecursiveProofAccepted => "recursive_proof_accepted",
            Self::MoneroDepthReached => "monero_depth_reached",
            Self::DaRootAvailable => "da_root_available",
            Self::GovernanceDelayElapsed => "governance_delay_elapsed",
            Self::WatchtowerAck => "watchtower_ack",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FraudWindowStatus {
    Scheduled,
    Open,
    Challenged,
    ExpiredClean,
    ResolvedFraud,
    EmergencyExtended,
}

impl FraudWindowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Open => "open",
            Self::Challenged => "challenged",
            Self::ExpiredClean => "expired_clean",
            Self::ResolvedFraud => "resolved_fraud",
            Self::EmergencyExtended => "emergency_extended",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::Challenged | Self::ResolvedFraud | Self::EmergencyExtended
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReserveStatus {
    Healthy,
    Rebalancing,
    LowCoverage,
    Frozen,
    AttestationMissing,
}

impl ReserveStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Rebalancing => "rebalancing",
            Self::LowCoverage => "low_coverage",
            Self::Frozen => "frozen",
            Self::AttestationMissing => "attestation_missing",
        }
    }

    pub fn blocks_release(self) -> bool {
        matches!(
            self,
            Self::LowCoverage | Self::Frozen | Self::AttestationMissing
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateRootStatus {
    Matched,
    Pending,
    Drift,
    ReorgGuarded,
    MissingDa,
}

impl StateRootStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matched => "matched",
            Self::Pending => "pending",
            Self::Drift => "drift",
            Self::ReorgGuarded => "reorg_guarded",
            Self::MissingDa => "missing_da",
        }
    }

    pub fn drift(self) -> bool {
        matches!(self, Self::Drift | Self::MissingDa)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Info,
    Warning,
    Critical,
    Sev1,
}

impl IncidentSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Sev1 => "sev1",
        }
    }

    pub fn release_blocking(self) -> bool {
        matches!(self, Self::Critical | Self::Sev1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Mitigating,
    Resolved,
    PostmortemComplete,
    Waived,
}

impl IncidentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::PostmortemComplete => "postmortem_complete",
            Self::Waived => "waived",
        }
    }

    pub fn open(self) -> bool {
        matches!(self, Self::Open | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseGateKind {
    MoneroExitSafety,
    RecursiveProofSafety,
    PqFinalitySafety,
    FraudWindowSafety,
    LiquidityReserveSafety,
    StateRootSafety,
    OperatorSafety,
    GovernanceSafety,
}

impl ReleaseGateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroExitSafety => "monero_exit_safety",
            Self::RecursiveProofSafety => "recursive_proof_safety",
            Self::PqFinalitySafety => "pq_finality_safety",
            Self::FraudWindowSafety => "fraud_window_safety",
            Self::LiquidityReserveSafety => "liquidity_reserve_safety",
            Self::StateRootSafety => "state_root_safety",
            Self::OperatorSafety => "operator_safety",
            Self::GovernanceSafety => "governance_safety",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    Open,
    Assigned,
    InProgress,
    Blocked,
    Verified,
    Closed,
    Waived,
}

impl TicketStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::InProgress => "in_progress",
            Self::Blocked => "blocked",
            Self::Verified => "verified",
            Self::Closed => "closed",
            Self::Waived => "waived",
        }
    }

    pub fn open(self) -> bool {
        matches!(
            self,
            Self::Open | Self::Assigned | Self::InProgress | Self::Blocked
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub min_release_score_bps: u64,
    pub min_critical_score_bps: u64,
    pub min_liquidity_coverage_bps: u64,
    pub max_open_blockers: u64,
    pub max_critical_incidents: u64,
    pub max_root_drift_events: u64,
    pub fraud_window_blocks: u64,
    pub remediation_ttl_blocks: u64,
    pub gate_ttl_blocks: u64,
    pub require_monero_exit_lane: bool,
    pub require_recursive_proofs: bool,
    pub require_pq_finality: bool,
    pub require_release_gate_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            min_release_score_bps:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_RELEASE_SCORE_BPS,
            min_critical_score_bps:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_CRITICAL_SCORE_BPS,
            min_liquidity_coverage_bps:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MIN_LIQUIDITY_COVERAGE_BPS,
            max_open_blockers: SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_OPEN_BLOCKERS,
            max_critical_incidents:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_CRITICAL_INCIDENTS,
            max_root_drift_events:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_MAX_ROOT_DRIFT_EVENTS,
            fraud_window_blocks: SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_FRAUD_WINDOW_BLOCKS,
            remediation_ttl_blocks:
                SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_REMEDIATION_TTL_BLOCKS,
            gate_ttl_blocks: SETTLEMENT_RUNTIME_READINESS_MATRIX_DEFAULT_GATE_TTL_BLOCKS,
            require_monero_exit_lane: true,
            require_recursive_proofs: true,
            require_pq_finality: true,
            require_release_gate_quorum: true,
        }
    }
}

impl Config {
    pub fn validate(&self) -> SettlementRuntimeReadinessMatrixResult<()> {
        if self.protocol_version != SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION {
            return Err(
                "settlement runtime readiness matrix protocol version mismatch".to_string(),
            );
        }
        if self.chain_id != CHAIN_ID {
            return Err("settlement runtime readiness matrix chain id mismatch".to_string());
        }
        if self.min_release_score_bps > SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS {
            return Err("minimum release score exceeds bps scale".to_string());
        }
        if self.min_critical_score_bps > SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS {
            return Err("minimum critical score exceeds bps scale".to_string());
        }
        if self.min_liquidity_coverage_bps < SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS {
            return Err(
                "minimum liquidity coverage must cover at least requested exits".to_string(),
            );
        }
        if self.fraud_window_blocks == 0 {
            return Err("fraud window blocks must be non-zero".to_string());
        }
        if self.remediation_ttl_blocks == 0 {
            return Err("remediation ttl blocks must be non-zero".to_string());
        }
        if self.gate_ttl_blocks == 0 {
            return Err("gate ttl blocks must be non-zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "min_release_score_bps": self.min_release_score_bps.to_string(),
            "min_critical_score_bps": self.min_critical_score_bps.to_string(),
            "min_liquidity_coverage_bps": self.min_liquidity_coverage_bps.to_string(),
            "max_open_blockers": self.max_open_blockers.to_string(),
            "max_critical_incidents": self.max_critical_incidents.to_string(),
            "max_root_drift_events": self.max_root_drift_events.to_string(),
            "fraud_window_blocks": self.fraud_window_blocks.to_string(),
            "remediation_ttl_blocks": self.remediation_ttl_blocks.to_string(),
            "gate_ttl_blocks": self.gate_ttl_blocks.to_string(),
            "require_monero_exit_lane": self.require_monero_exit_lane,
            "require_recursive_proofs": self.require_recursive_proofs,
            "require_pq_finality": self.require_pq_finality,
            "require_release_gate_quorum": self.require_release_gate_quorum,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementLane {
    pub lane_id: String,
    pub label: String,
    pub kind: SettlementLaneKind,
    pub status: ReadinessStatus,
    pub exit_asset: String,
    pub operator_set_id: String,
    pub monero_anchor_root: String,
    pub recursive_proof_queue_id: String,
    pub finality_signal_id: String,
    pub reserve_bucket_id: String,
    pub fraud_window_id: String,
    pub latest_state_root_id: String,
    pub release_gate_id: String,
    pub priority: u64,
    pub max_exit_amount_piconero: u64,
    pub pending_exit_amount_piconero: u64,
    pub opened_at_height: u64,
    pub last_checked_height: u64,
}

impl SettlementLane {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_id": self.lane_id,
            "label": self.label,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "exit_asset": self.exit_asset,
            "operator_set_id": self.operator_set_id,
            "monero_anchor_root": self.monero_anchor_root,
            "recursive_proof_queue_id": self.recursive_proof_queue_id,
            "finality_signal_id": self.finality_signal_id,
            "reserve_bucket_id": self.reserve_bucket_id,
            "fraud_window_id": self.fraud_window_id,
            "latest_state_root_id": self.latest_state_root_id,
            "release_gate_id": self.release_gate_id,
            "priority": self.priority.to_string(),
            "max_exit_amount_piconero": self.max_exit_amount_piconero.to_string(),
            "pending_exit_amount_piconero": self.pending_exit_amount_piconero.to_string(),
            "opened_at_height": self.opened_at_height.to_string(),
            "last_checked_height": self.last_checked_height.to_string(),
        })
    }

    pub fn root(&self) -> String {
        root_from_record(&self.public_record())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessCheck {
    pub check_id: String,
    pub lane_id: String,
    pub kind: ReadinessCheckKind,
    pub severity: ReadinessSeverity,
    pub status: ReadinessStatus,
    pub observed_value: String,
    pub required_value: String,
    pub evidence_root: String,
    pub ticket_id: String,
    pub created_at_height: u64,
    pub updated_at_height: u64,
}

impl ReadinessCheck {
    pub fn public_record(&self) -> Value {
        json!({
            "check_id": self.check_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "observed_value": self.observed_value,
            "required_value": self.required_value,
            "evidence_root": self.evidence_root,
            "ticket_id": self.ticket_id,
            "created_at_height": self.created_at_height.to_string(),
            "updated_at_height": self.updated_at_height.to_string(),
        })
    }

    pub fn score_bps(&self) -> u64 {
        if self.status.passing() {
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS
        } else if matches!(self.status, ReadinessStatus::Degraded) {
            self.severity
                .weight_bps()
                .saturating_sub(SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS / 10)
        } else {
            0
        }
    }

    pub fn release_blocking(&self) -> bool {
        self.status.open() && self.severity.blocks_release()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveProofQueue {
    pub queue_id: String,
    pub lane_id: String,
    pub status: ProofQueueStatus,
    pub circuit_family: String,
    pub aggregate_proof_root: String,
    pub verifier_key_root: String,
    pub pending_batches: u64,
    pub proved_batches: u64,
    pub failed_batches: u64,
    pub max_latency_blocks: u64,
    pub observed_latency_blocks: u64,
    pub updated_at_height: u64,
}

impl RecursiveProofQueue {
    pub fn public_record(&self) -> Value {
        json!({
            "queue_id": self.queue_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "circuit_family": self.circuit_family,
            "aggregate_proof_root": self.aggregate_proof_root,
            "verifier_key_root": self.verifier_key_root,
            "pending_batches": self.pending_batches.to_string(),
            "proved_batches": self.proved_batches.to_string(),
            "failed_batches": self.failed_batches.to_string(),
            "max_latency_blocks": self.max_latency_blocks.to_string(),
            "observed_latency_blocks": self.observed_latency_blocks.to_string(),
            "updated_at_height": self.updated_at_height.to_string(),
        })
    }

    pub fn blocked(&self) -> bool {
        !self.status.healthy()
            || self.failed_batches > 0
            || self.observed_latency_blocks > self.max_latency_blocks
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqFinalitySignal {
    pub signal_id: String,
    pub lane_id: String,
    pub kind: FinalitySignalKind,
    pub status: ReadinessStatus,
    pub committee_id: String,
    pub attestation_root: String,
    pub quorum_bps: u64,
    pub required_quorum_bps: u64,
    pub observed_at_height: u64,
    pub expires_at_height: u64,
}

impl PqFinalitySignal {
    pub fn public_record(&self) -> Value {
        json!({
            "signal_id": self.signal_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "committee_id": self.committee_id,
            "attestation_root": self.attestation_root,
            "quorum_bps": self.quorum_bps.to_string(),
            "required_quorum_bps": self.required_quorum_bps.to_string(),
            "observed_at_height": self.observed_at_height.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }

    pub fn passing_at(&self, height: u64) -> bool {
        self.status.passing()
            && self.quorum_bps >= self.required_quorum_bps
            && self.expires_at_height >= height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FraudWindow {
    pub window_id: String,
    pub lane_id: String,
    pub status: FraudWindowStatus,
    pub batch_root: String,
    pub challenger_set_root: String,
    pub bond_root: String,
    pub opened_at_height: u64,
    pub closes_at_height: u64,
    pub challenge_count: u64,
}

impl FraudWindow {
    pub fn public_record(&self) -> Value {
        json!({
            "window_id": self.window_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "batch_root": self.batch_root,
            "challenger_set_root": self.challenger_set_root,
            "bond_root": self.bond_root,
            "opened_at_height": self.opened_at_height.to_string(),
            "closes_at_height": self.closes_at_height.to_string(),
            "challenge_count": self.challenge_count.to_string(),
        })
    }

    pub fn release_blocking(&self) -> bool {
        self.status.blocks_release() || self.challenge_count > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityReserve {
    pub reserve_id: String,
    pub lane_id: String,
    pub status: ReserveStatus,
    pub asset_id: String,
    pub custodian_committee_id: String,
    pub attestation_root: String,
    pub available_piconero: u64,
    pub pending_exit_piconero: u64,
    pub coverage_bps: u64,
    pub rebalance_due_height: u64,
}

impl LiquidityReserve {
    pub fn public_record(&self) -> Value {
        json!({
            "reserve_id": self.reserve_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "asset_id": self.asset_id,
            "custodian_committee_id": self.custodian_committee_id,
            "attestation_root": self.attestation_root,
            "available_piconero": self.available_piconero.to_string(),
            "pending_exit_piconero": self.pending_exit_piconero.to_string(),
            "coverage_bps": self.coverage_bps.to_string(),
            "rebalance_due_height": self.rebalance_due_height.to_string(),
        })
    }

    pub fn release_blocking(&self, min_coverage_bps: u64) -> bool {
        self.status.blocks_release() || self.coverage_bps < min_coverage_bps
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStateRoot {
    pub root_id: String,
    pub lane_id: String,
    pub status: StateRootStatus,
    pub l2_state_root: String,
    pub monero_anchor_root: String,
    pub da_root: String,
    pub operator_observation_root: String,
    pub height: u64,
    pub observed_at_height: u64,
}

impl RuntimeStateRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "root_id": self.root_id,
            "lane_id": self.lane_id,
            "status": self.status.as_str(),
            "l2_state_root": self.l2_state_root,
            "monero_anchor_root": self.monero_anchor_root,
            "da_root": self.da_root,
            "operator_observation_root": self.operator_observation_root,
            "height": self.height.to_string(),
            "observed_at_height": self.observed_at_height.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperatorIncident {
    pub incident_id: String,
    pub lane_id: String,
    pub severity: IncidentSeverity,
    pub status: IncidentStatus,
    pub component: String,
    pub evidence_root: String,
    pub mitigation_root: String,
    pub opened_at_height: u64,
    pub resolved_at_height: u64,
}

impl OperatorIncident {
    pub fn public_record(&self) -> Value {
        json!({
            "incident_id": self.incident_id,
            "lane_id": self.lane_id,
            "severity": self.severity.as_str(),
            "status": self.status.as_str(),
            "component": self.component,
            "evidence_root": self.evidence_root,
            "mitigation_root": self.mitigation_root,
            "opened_at_height": self.opened_at_height.to_string(),
            "resolved_at_height": self.resolved_at_height.to_string(),
        })
    }

    pub fn release_blocking(&self) -> bool {
        self.status.open() && self.severity.release_blocking()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseGate {
    pub gate_id: String,
    pub lane_id: String,
    pub kind: ReleaseGateKind,
    pub status: ReadinessStatus,
    pub signoff_root: String,
    pub evidence_root: String,
    pub required_approvals: u64,
    pub observed_approvals: u64,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
}

impl ReleaseGate {
    pub fn public_record(&self) -> Value {
        json!({
            "gate_id": self.gate_id,
            "lane_id": self.lane_id,
            "kind": self.kind.as_str(),
            "status": self.status.as_str(),
            "signoff_root": self.signoff_root,
            "evidence_root": self.evidence_root,
            "required_approvals": self.required_approvals.to_string(),
            "observed_approvals": self.observed_approvals.to_string(),
            "opened_at_height": self.opened_at_height.to_string(),
            "expires_at_height": self.expires_at_height.to_string(),
        })
    }

    pub fn passing_at(&self, height: u64) -> bool {
        self.status.passing()
            && self.observed_approvals >= self.required_approvals
            && self.expires_at_height >= height
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationTicket {
    pub ticket_id: String,
    pub lane_id: String,
    pub check_id: String,
    pub status: TicketStatus,
    pub severity: ReadinessSeverity,
    pub owner: String,
    pub action_root: String,
    pub opened_at_height: u64,
    pub due_height: u64,
    pub verified_at_height: u64,
}

impl RemediationTicket {
    pub fn public_record(&self) -> Value {
        json!({
            "ticket_id": self.ticket_id,
            "lane_id": self.lane_id,
            "check_id": self.check_id,
            "status": self.status.as_str(),
            "severity": self.severity.as_str(),
            "owner": self.owner,
            "action_root": self.action_root,
            "opened_at_height": self.opened_at_height.to_string(),
            "due_height": self.due_height.to_string(),
            "verified_at_height": self.verified_at_height.to_string(),
        })
    }

    pub fn release_blocking(&self, height: u64) -> bool {
        self.status.open() && (self.severity.blocks_release() || self.due_height < height)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadinessReport {
    pub report_id: String,
    pub height: u64,
    pub release_score_bps: u64,
    pub critical_score_bps: u64,
    pub lane_root: String,
    pub blocked_lane_root: String,
    pub remediation_root: String,
    pub release_blocked: bool,
}

impl ReadinessReport {
    pub fn public_record(&self) -> Value {
        json!({
            "report_id": self.report_id,
            "height": self.height.to_string(),
            "release_score_bps": self.release_score_bps.to_string(),
            "critical_score_bps": self.critical_score_bps.to_string(),
            "lane_root": self.lane_root,
            "blocked_lane_root": self.blocked_lane_root,
            "remediation_root": self.remediation_root,
            "release_blocked": self.release_blocked,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roots {
    pub config_root: String,
    pub lane_root: String,
    pub check_root: String,
    pub proof_queue_root: String,
    pub finality_signal_root: String,
    pub fraud_window_root: String,
    pub liquidity_reserve_root: String,
    pub runtime_state_root_root: String,
    pub operator_incident_root: String,
    pub release_gate_root: String,
    pub remediation_ticket_root: String,
    pub readiness_report_root: String,
    pub blocked_lane_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "lane_root": self.lane_root,
            "check_root": self.check_root,
            "proof_queue_root": self.proof_queue_root,
            "finality_signal_root": self.finality_signal_root,
            "fraud_window_root": self.fraud_window_root,
            "liquidity_reserve_root": self.liquidity_reserve_root,
            "runtime_state_root_root": self.runtime_state_root_root,
            "operator_incident_root": self.operator_incident_root,
            "release_gate_root": self.release_gate_root,
            "remediation_ticket_root": self.remediation_ticket_root,
            "readiness_report_root": self.readiness_report_root,
            "blocked_lane_root": self.blocked_lane_root,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counters {
    pub lane_count: u64,
    pub monero_lane_count: u64,
    pub blocked_lane_count: u64,
    pub check_count: u64,
    pub passing_check_count: u64,
    pub blocking_check_count: u64,
    pub proof_queue_count: u64,
    pub blocked_proof_queue_count: u64,
    pub finality_signal_count: u64,
    pub passing_finality_signal_count: u64,
    pub fraud_window_count: u64,
    pub challenged_fraud_window_count: u64,
    pub liquidity_reserve_count: u64,
    pub low_liquidity_reserve_count: u64,
    pub runtime_state_root_count: u64,
    pub root_drift_count: u64,
    pub operator_incident_count: u64,
    pub critical_incident_count: u64,
    pub release_gate_count: u64,
    pub passing_release_gate_count: u64,
    pub remediation_ticket_count: u64,
    pub open_remediation_ticket_count: u64,
    pub readiness_report_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "lane_count": self.lane_count.to_string(),
            "monero_lane_count": self.monero_lane_count.to_string(),
            "blocked_lane_count": self.blocked_lane_count.to_string(),
            "check_count": self.check_count.to_string(),
            "passing_check_count": self.passing_check_count.to_string(),
            "blocking_check_count": self.blocking_check_count.to_string(),
            "proof_queue_count": self.proof_queue_count.to_string(),
            "blocked_proof_queue_count": self.blocked_proof_queue_count.to_string(),
            "finality_signal_count": self.finality_signal_count.to_string(),
            "passing_finality_signal_count": self.passing_finality_signal_count.to_string(),
            "fraud_window_count": self.fraud_window_count.to_string(),
            "challenged_fraud_window_count": self.challenged_fraud_window_count.to_string(),
            "liquidity_reserve_count": self.liquidity_reserve_count.to_string(),
            "low_liquidity_reserve_count": self.low_liquidity_reserve_count.to_string(),
            "runtime_state_root_count": self.runtime_state_root_count.to_string(),
            "root_drift_count": self.root_drift_count.to_string(),
            "operator_incident_count": self.operator_incident_count.to_string(),
            "critical_incident_count": self.critical_incident_count.to_string(),
            "release_gate_count": self.release_gate_count.to_string(),
            "passing_release_gate_count": self.passing_release_gate_count.to_string(),
            "remediation_ticket_count": self.remediation_ticket_count.to_string(),
            "open_remediation_ticket_count": self.open_remediation_ticket_count.to_string(),
            "readiness_report_count": self.readiness_report_count.to_string(),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub lanes: BTreeMap<String, SettlementLane>,
    pub checks: BTreeMap<String, ReadinessCheck>,
    pub proof_queues: BTreeMap<String, RecursiveProofQueue>,
    pub finality_signals: BTreeMap<String, PqFinalitySignal>,
    pub fraud_windows: BTreeMap<String, FraudWindow>,
    pub liquidity_reserves: BTreeMap<String, LiquidityReserve>,
    pub runtime_state_roots: BTreeMap<String, RuntimeStateRoot>,
    pub operator_incidents: BTreeMap<String, OperatorIncident>,
    pub release_gates: BTreeMap<String, ReleaseGate>,
    pub remediation_tickets: BTreeMap<String, RemediationTicket>,
    pub readiness_reports: BTreeMap<String, ReadinessReport>,
}

impl State {
    pub fn new(config: Config) -> SettlementRuntimeReadinessMatrixResult<Self> {
        config.validate()?;
        Ok(Self {
            height: 0,
            config,
            lanes: BTreeMap::new(),
            checks: BTreeMap::new(),
            proof_queues: BTreeMap::new(),
            finality_signals: BTreeMap::new(),
            fraud_windows: BTreeMap::new(),
            liquidity_reserves: BTreeMap::new(),
            runtime_state_roots: BTreeMap::new(),
            operator_incidents: BTreeMap::new(),
            release_gates: BTreeMap::new(),
            remediation_tickets: BTreeMap::new(),
            readiness_reports: BTreeMap::new(),
        })
    }

    pub fn devnet() -> SettlementRuntimeReadinessMatrixResult<State> {
        let mut state = State::new(Config::default())?;
        state.set_height(SETTLEMENT_RUNTIME_READINESS_MATRIX_DEVNET_HEIGHT)?;

        for spec in devnet_lane_specs() {
            state.add_lane(build_devnet_lane(spec, state.height))?;
        }
        for lane in state.lanes.values().cloned().collect::<Vec<_>>() {
            state.add_proof_queue(build_devnet_proof_queue(&lane, state.height))?;
            state.add_finality_signal(build_devnet_finality_signal(&lane, state.height))?;
            state.add_fraud_window(build_devnet_fraud_window(&lane, state.height))?;
            state.add_liquidity_reserve(build_devnet_liquidity_reserve(&lane, state.height))?;
            state.add_runtime_state_root(build_devnet_runtime_state_root(&lane, state.height))?;
            state.add_release_gate(build_devnet_release_gate(&lane, state.height))?;
            for check in build_devnet_checks(&lane, state.height) {
                state.add_check(check)?;
            }
        }

        state.add_operator_incident(OperatorIncident {
            incident_id: stable_id("incident", "resolved-monero-rpc-lag"),
            lane_id: stable_id("lane", "monero-fast-exit"),
            severity: IncidentSeverity::Warning,
            status: IncidentStatus::PostmortemComplete,
            component: "monero_rpc_bridge".to_string(),
            evidence_root: stable_hash("INCIDENT-EVIDENCE", &["monero-rpc-lag", "resolved"]),
            mitigation_root: stable_hash("INCIDENT-MITIGATION", &["dual-rpc-quorum", "enabled"]),
            opened_at_height: state.height.saturating_sub(180),
            resolved_at_height: state.height.saturating_sub(120),
        })?;
        state.add_operator_incident(OperatorIncident {
            incident_id: stable_id("incident", "proof-market-backpressure"),
            lane_id: stable_id("lane", "recursive-proof-settlement"),
            severity: IncidentSeverity::Info,
            status: IncidentStatus::Resolved,
            component: "recursive_proof_scheduler".to_string(),
            evidence_root: stable_hash("INCIDENT-EVIDENCE", &["proof-market", "backpressure"]),
            mitigation_root: stable_hash("INCIDENT-MITIGATION", &["extra-prover", "bonded"]),
            opened_at_height: state.height.saturating_sub(96),
            resolved_at_height: state.height.saturating_sub(72),
        })?;

        for ticket in build_devnet_tickets(&state) {
            state.add_remediation_ticket(ticket)?;
        }
        let report = state.build_report("devnet-runtime-readiness")?;
        state.add_readiness_report(report)?;
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> SettlementRuntimeReadinessMatrixResult<()> {
        self.config.validate()?;
        validate_len(
            "lanes",
            self.lanes.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_LANES,
        )?;
        validate_len(
            "checks",
            self.checks.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_CHECKS,
        )?;
        validate_len(
            "proof queues",
            self.proof_queues.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_PROOF_QUEUES,
        )?;
        validate_len(
            "finality signals",
            self.finality_signals.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_FINALITY_SIGNALS,
        )?;
        validate_len(
            "fraud windows",
            self.fraud_windows.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_FRAUD_WINDOWS,
        )?;
        validate_len(
            "liquidity reserves",
            self.liquidity_reserves.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_RESERVES,
        )?;
        validate_len(
            "runtime state roots",
            self.runtime_state_roots.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_STATE_ROOTS,
        )?;
        validate_len(
            "operator incidents",
            self.operator_incidents.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_INCIDENTS,
        )?;
        validate_len(
            "release gates",
            self.release_gates.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_RELEASE_GATES,
        )?;
        validate_len(
            "remediation tickets",
            self.remediation_tickets.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_TICKETS,
        )?;
        validate_len(
            "readiness reports",
            self.readiness_reports.len(),
            SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_REPORTS,
        )?;

        for lane in self.lanes.values() {
            self.validate_lane_links(lane)?;
        }
        for check in self.checks.values() {
            require_lane(&self.lanes, &check.lane_id, "check")?;
            if !check.ticket_id.is_empty()
                && !self.remediation_tickets.contains_key(&check.ticket_id)
                && check.release_blocking()
            {
                return Err(format!("blocking check {} has no ticket", check.check_id));
            }
        }
        for queue in self.proof_queues.values() {
            require_lane(&self.lanes, &queue.lane_id, "proof queue")?;
        }
        for signal in self.finality_signals.values() {
            require_lane(&self.lanes, &signal.lane_id, "finality signal")?;
        }
        for window in self.fraud_windows.values() {
            require_lane(&self.lanes, &window.lane_id, "fraud window")?;
            if window.closes_at_height < window.opened_at_height {
                return Err(format!(
                    "fraud window {} closes before it opens",
                    window.window_id
                ));
            }
        }
        for reserve in self.liquidity_reserves.values() {
            require_lane(&self.lanes, &reserve.lane_id, "liquidity reserve")?;
        }
        for root in self.runtime_state_roots.values() {
            require_lane(&self.lanes, &root.lane_id, "runtime state root")?;
        }
        for incident in self.operator_incidents.values() {
            require_lane(&self.lanes, &incident.lane_id, "operator incident")?;
        }
        for gate in self.release_gates.values() {
            require_lane(&self.lanes, &gate.lane_id, "release gate")?;
            if gate.expires_at_height < gate.opened_at_height {
                return Err(format!(
                    "release gate {} expires before it opens",
                    gate.gate_id
                ));
            }
        }
        for ticket in self.remediation_tickets.values() {
            require_lane(&self.lanes, &ticket.lane_id, "remediation ticket")?;
            if !ticket.check_id.is_empty() && !self.checks.contains_key(&ticket.check_id) {
                return Err(format!(
                    "remediation ticket {} references missing check",
                    ticket.ticket_id
                ));
            }
        }

        if self.config.require_monero_exit_lane
            && !self.lanes.values().any(|lane| lane.kind.monero_bound())
        {
            return Err("configuration requires at least one Monero exit lane".to_string());
        }
        if self.config.require_recursive_proofs && self.proof_queues.is_empty() {
            return Err("configuration requires recursive proof queues".to_string());
        }
        if self.config.require_pq_finality && self.finality_signals.is_empty() {
            return Err("configuration requires pq finality signals".to_string());
        }
        Ok(())
    }

    pub fn set_height(&mut self, height: u64) -> SettlementRuntimeReadinessMatrixResult<()> {
        self.height = height;
        self.validate()
    }

    pub fn update_height(&mut self, height: u64) -> SettlementRuntimeReadinessMatrixResult<()> {
        self.set_height(height)
    }

    pub fn add_lane(&mut self, lane: SettlementLane) -> SettlementRuntimeReadinessMatrixResult<()> {
        if self.lanes.contains_key(&lane.lane_id) {
            return Err(format!("duplicate settlement lane {}", lane.lane_id));
        }
        self.lanes.insert(lane.lane_id.clone(), lane);
        Ok(())
    }

    pub fn add_check(
        &mut self,
        check: ReadinessCheck,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &check.lane_id, "check")?;
        if self.checks.contains_key(&check.check_id) {
            return Err(format!("duplicate readiness check {}", check.check_id));
        }
        self.checks.insert(check.check_id.clone(), check);
        Ok(())
    }

    pub fn add_proof_queue(
        &mut self,
        queue: RecursiveProofQueue,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &queue.lane_id, "proof queue")?;
        if self.proof_queues.contains_key(&queue.queue_id) {
            return Err(format!("duplicate proof queue {}", queue.queue_id));
        }
        self.proof_queues.insert(queue.queue_id.clone(), queue);
        Ok(())
    }

    pub fn add_finality_signal(
        &mut self,
        signal: PqFinalitySignal,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &signal.lane_id, "finality signal")?;
        if self.finality_signals.contains_key(&signal.signal_id) {
            return Err(format!("duplicate finality signal {}", signal.signal_id));
        }
        self.finality_signals
            .insert(signal.signal_id.clone(), signal);
        Ok(())
    }

    pub fn add_fraud_window(
        &mut self,
        window: FraudWindow,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &window.lane_id, "fraud window")?;
        if self.fraud_windows.contains_key(&window.window_id) {
            return Err(format!("duplicate fraud window {}", window.window_id));
        }
        self.fraud_windows.insert(window.window_id.clone(), window);
        Ok(())
    }

    pub fn add_liquidity_reserve(
        &mut self,
        reserve: LiquidityReserve,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &reserve.lane_id, "liquidity reserve")?;
        if self.liquidity_reserves.contains_key(&reserve.reserve_id) {
            return Err(format!(
                "duplicate liquidity reserve {}",
                reserve.reserve_id
            ));
        }
        self.liquidity_reserves
            .insert(reserve.reserve_id.clone(), reserve);
        Ok(())
    }

    pub fn add_runtime_state_root(
        &mut self,
        root: RuntimeStateRoot,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &root.lane_id, "runtime state root")?;
        if self.runtime_state_roots.contains_key(&root.root_id) {
            return Err(format!("duplicate runtime state root {}", root.root_id));
        }
        self.runtime_state_roots.insert(root.root_id.clone(), root);
        Ok(())
    }

    pub fn add_operator_incident(
        &mut self,
        incident: OperatorIncident,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &incident.lane_id, "operator incident")?;
        if self.operator_incidents.contains_key(&incident.incident_id) {
            return Err(format!(
                "duplicate operator incident {}",
                incident.incident_id
            ));
        }
        self.operator_incidents
            .insert(incident.incident_id.clone(), incident);
        Ok(())
    }

    pub fn add_release_gate(
        &mut self,
        gate: ReleaseGate,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &gate.lane_id, "release gate")?;
        if self.release_gates.contains_key(&gate.gate_id) {
            return Err(format!("duplicate release gate {}", gate.gate_id));
        }
        self.release_gates.insert(gate.gate_id.clone(), gate);
        Ok(())
    }

    pub fn add_remediation_ticket(
        &mut self,
        ticket: RemediationTicket,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        require_lane(&self.lanes, &ticket.lane_id, "remediation ticket")?;
        if self.remediation_tickets.contains_key(&ticket.ticket_id) {
            return Err(format!("duplicate remediation ticket {}", ticket.ticket_id));
        }
        self.remediation_tickets
            .insert(ticket.ticket_id.clone(), ticket);
        Ok(())
    }

    pub fn add_readiness_report(
        &mut self,
        report: ReadinessReport,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        if self.readiness_reports.contains_key(&report.report_id) {
            return Err(format!("duplicate readiness report {}", report.report_id));
        }
        self.readiness_reports
            .insert(report.report_id.clone(), report);
        Ok(())
    }

    pub fn blocked_lanes(&self) -> Vec<SettlementLane> {
        self.lanes
            .values()
            .filter(|lane| self.lane_blocked(lane))
            .cloned()
            .collect()
    }

    pub fn lane_blocked(&self, lane: &SettlementLane) -> bool {
        if lane.status.blocked() {
            return true;
        }
        let lane_id = lane.lane_id.as_str();
        self.checks
            .values()
            .any(|check| check.lane_id == lane_id && check.release_blocking())
            || self
                .proof_queues
                .values()
                .any(|queue| queue.lane_id == lane_id && queue.blocked())
            || self
                .finality_signals
                .values()
                .any(|signal| signal.lane_id == lane_id && !signal.passing_at(self.height))
            || self
                .fraud_windows
                .values()
                .any(|window| window.lane_id == lane_id && window.release_blocking())
            || self.liquidity_reserves.values().any(|reserve| {
                reserve.lane_id == lane_id
                    && reserve.release_blocking(self.config.min_liquidity_coverage_bps)
            })
            || self
                .runtime_state_roots
                .values()
                .any(|root| root.lane_id == lane_id && root.status.drift())
            || self
                .operator_incidents
                .values()
                .any(|incident| incident.lane_id == lane_id && incident.release_blocking())
            || self
                .release_gates
                .values()
                .any(|gate| gate.lane_id == lane_id && !gate.passing_at(self.height))
            || self
                .remediation_tickets
                .values()
                .any(|ticket| ticket.lane_id == lane_id && ticket.release_blocking(self.height))
    }

    pub fn release_score_bps(&self) -> u64 {
        average_bps(self.checks.values().map(ReadinessCheck::score_bps))
    }

    pub fn critical_score_bps(&self) -> u64 {
        average_bps(
            self.checks
                .values()
                .filter(|check| check.severity.blocks_release())
                .map(ReadinessCheck::score_bps),
        )
    }

    pub fn release_blocked(&self) -> bool {
        let counters = self.counters();
        self.release_score_bps() < self.config.min_release_score_bps
            || self.critical_score_bps() < self.config.min_critical_score_bps
            || counters.blocked_lane_count > self.config.max_open_blockers
            || counters.critical_incident_count > self.config.max_critical_incidents
            || counters.root_drift_count > self.config.max_root_drift_events
    }

    pub fn build_report(
        &self,
        label: &str,
    ) -> SettlementRuntimeReadinessMatrixResult<ReadinessReport> {
        self.validate()?;
        let roots = self.roots();
        Ok(ReadinessReport {
            report_id: stable_id("readiness-report", label),
            height: self.height,
            release_score_bps: self.release_score_bps(),
            critical_score_bps: self.critical_score_bps(),
            lane_root: roots.lane_root,
            blocked_lane_root: roots.blocked_lane_root,
            remediation_root: roots.remediation_ticket_root,
            release_blocked: self.release_blocked(),
        })
    }

    pub fn roots(&self) -> Roots {
        let blocked_records = self
            .blocked_lanes()
            .iter()
            .map(SettlementLane::public_record)
            .collect::<Vec<_>>();
        Roots {
            config_root: root_from_record(&self.config.public_record()),
            lane_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-LANES",
                self.lanes
                    .values()
                    .map(SettlementLane::public_record)
                    .collect(),
            ),
            check_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-CHECKS",
                self.checks
                    .values()
                    .map(ReadinessCheck::public_record)
                    .collect(),
            ),
            proof_queue_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-PROOF-QUEUES",
                self.proof_queues
                    .values()
                    .map(RecursiveProofQueue::public_record)
                    .collect(),
            ),
            finality_signal_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-FINALITY-SIGNALS",
                self.finality_signals
                    .values()
                    .map(PqFinalitySignal::public_record)
                    .collect(),
            ),
            fraud_window_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-FRAUD-WINDOWS",
                self.fraud_windows
                    .values()
                    .map(FraudWindow::public_record)
                    .collect(),
            ),
            liquidity_reserve_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-LIQUIDITY-RESERVES",
                self.liquidity_reserves
                    .values()
                    .map(LiquidityReserve::public_record)
                    .collect(),
            ),
            runtime_state_root_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-STATE-ROOTS",
                self.runtime_state_roots
                    .values()
                    .map(RuntimeStateRoot::public_record)
                    .collect(),
            ),
            operator_incident_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-INCIDENTS",
                self.operator_incidents
                    .values()
                    .map(OperatorIncident::public_record)
                    .collect(),
            ),
            release_gate_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-RELEASE-GATES",
                self.release_gates
                    .values()
                    .map(ReleaseGate::public_record)
                    .collect(),
            ),
            remediation_ticket_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-TICKETS",
                self.remediation_tickets
                    .values()
                    .map(RemediationTicket::public_record)
                    .collect(),
            ),
            readiness_report_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-REPORTS",
                self.readiness_reports
                    .values()
                    .map(ReadinessReport::public_record)
                    .collect(),
            ),
            blocked_lane_root: collection_root(
                "SETTLEMENT-RUNTIME-READINESS-BLOCKED-LANES",
                blocked_records,
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        let blocked_lanes = self.blocked_lanes();
        Counters {
            lane_count: self.lanes.len() as u64,
            monero_lane_count: self
                .lanes
                .values()
                .filter(|lane| lane.kind.monero_bound())
                .count() as u64,
            blocked_lane_count: blocked_lanes.len() as u64,
            check_count: self.checks.len() as u64,
            passing_check_count: self
                .checks
                .values()
                .filter(|check| check.status.passing())
                .count() as u64,
            blocking_check_count: self
                .checks
                .values()
                .filter(|check| check.release_blocking())
                .count() as u64,
            proof_queue_count: self.proof_queues.len() as u64,
            blocked_proof_queue_count: self
                .proof_queues
                .values()
                .filter(|queue| queue.blocked())
                .count() as u64,
            finality_signal_count: self.finality_signals.len() as u64,
            passing_finality_signal_count: self
                .finality_signals
                .values()
                .filter(|signal| signal.passing_at(self.height))
                .count() as u64,
            fraud_window_count: self.fraud_windows.len() as u64,
            challenged_fraud_window_count: self
                .fraud_windows
                .values()
                .filter(|window| window.release_blocking())
                .count() as u64,
            liquidity_reserve_count: self.liquidity_reserves.len() as u64,
            low_liquidity_reserve_count: self
                .liquidity_reserves
                .values()
                .filter(|reserve| reserve.release_blocking(self.config.min_liquidity_coverage_bps))
                .count() as u64,
            runtime_state_root_count: self.runtime_state_roots.len() as u64,
            root_drift_count: self
                .runtime_state_roots
                .values()
                .filter(|root| root.status.drift())
                .count() as u64,
            operator_incident_count: self.operator_incidents.len() as u64,
            critical_incident_count: self
                .operator_incidents
                .values()
                .filter(|incident| incident.release_blocking())
                .count() as u64,
            release_gate_count: self.release_gates.len() as u64,
            passing_release_gate_count: self
                .release_gates
                .values()
                .filter(|gate| gate.passing_at(self.height))
                .count() as u64,
            remediation_ticket_count: self.remediation_tickets.len() as u64,
            open_remediation_ticket_count: self
                .remediation_tickets
                .values()
                .filter(|ticket| ticket.status.open())
                .count() as u64,
            readiness_report_count: self.readiness_reports.len() as u64,
        }
    }

    pub fn state_root(&self) -> String {
        domain_hash(
            "SETTLEMENT-RUNTIME-READINESS-STATE",
            &[
                HashPart::Str(SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION),
                HashPart::Str(CHAIN_ID),
                HashPart::Str(&self.height.to_string()),
                HashPart::Json(&self.roots().public_record()),
                HashPart::Json(&self.counters().public_record()),
            ],
            32,
        )
    }

    pub fn public_record(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "protocol_version": SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height.to_string(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "release_score_bps": self.release_score_bps().to_string(),
            "critical_score_bps": self.critical_score_bps().to_string(),
            "release_blocked": self.release_blocked(),
            "state_root": self.state_root(),
        })
    }

    fn validate_lane_links(
        &self,
        lane: &SettlementLane,
    ) -> SettlementRuntimeReadinessMatrixResult<()> {
        if !lane.recursive_proof_queue_id.is_empty()
            && !self
                .proof_queues
                .contains_key(&lane.recursive_proof_queue_id)
        {
            return Err(format!(
                "lane {} references missing proof queue",
                lane.lane_id
            ));
        }
        if !lane.finality_signal_id.is_empty()
            && !self.finality_signals.contains_key(&lane.finality_signal_id)
        {
            return Err(format!(
                "lane {} references missing finality signal",
                lane.lane_id
            ));
        }
        if !lane.reserve_bucket_id.is_empty()
            && !self
                .liquidity_reserves
                .contains_key(&lane.reserve_bucket_id)
        {
            return Err(format!("lane {} references missing reserve", lane.lane_id));
        }
        if !lane.fraud_window_id.is_empty()
            && !self.fraud_windows.contains_key(&lane.fraud_window_id)
        {
            return Err(format!(
                "lane {} references missing fraud window",
                lane.lane_id
            ));
        }
        if !lane.latest_state_root_id.is_empty()
            && !self
                .runtime_state_roots
                .contains_key(&lane.latest_state_root_id)
        {
            return Err(format!(
                "lane {} references missing state root",
                lane.lane_id
            ));
        }
        if !lane.release_gate_id.is_empty()
            && !self.release_gates.contains_key(&lane.release_gate_id)
        {
            return Err(format!(
                "lane {} references missing release gate",
                lane.lane_id
            ));
        }
        Ok(())
    }
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "SETTLEMENT-RUNTIME-READINESS-RECORD",
        &[
            HashPart::Str(SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(record),
        ],
        32,
    )
}

pub fn devnet() -> SettlementRuntimeReadinessMatrixResult<State> {
    State::devnet()
}

fn collection_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by_key(root_from_record);
    merkle_root(domain, &records)
}

fn stable_hash(domain: &str, values: &[&str]) -> String {
    let mut parts = Vec::with_capacity(values.len() + 2);
    parts.push(HashPart::Str(
        SETTLEMENT_RUNTIME_READINESS_MATRIX_PROTOCOL_VERSION,
    ));
    parts.push(HashPart::Str(CHAIN_ID));
    for value in values {
        parts.push(HashPart::Str(value));
    }
    domain_hash(domain, &parts, 32)
}

fn stable_id(kind: &str, label: &str) -> String {
    stable_hash("SETTLEMENT-RUNTIME-READINESS-ID", &[kind, label])
}

fn validate_len(
    name: &str,
    observed: usize,
    max: usize,
) -> SettlementRuntimeReadinessMatrixResult<()> {
    if observed > max {
        return Err(format!(
            "{name} exceeds settlement runtime readiness matrix limit"
        ));
    }
    Ok(())
}

fn require_lane(
    lanes: &BTreeMap<String, SettlementLane>,
    lane_id: &str,
    context: &str,
) -> SettlementRuntimeReadinessMatrixResult<()> {
    if lanes.contains_key(lane_id) {
        Ok(())
    } else {
        Err(format!("{context} references missing lane {lane_id}"))
    }
}

fn average_bps(values: impl Iterator<Item = u64>) -> u64 {
    let mut total = 0_u64;
    let mut count = 0_u64;
    for value in values {
        total = total.saturating_add(value);
        count = count.saturating_add(1);
    }
    if count == 0 {
        SETTLEMENT_RUNTIME_READINESS_MATRIX_MAX_BPS
    } else {
        total / count
    }
}

#[derive(Clone, Copy)]
struct DevnetLaneSpec {
    label: &'static str,
    kind: SettlementLaneKind,
    status: ReadinessStatus,
    exit_asset: &'static str,
    operator_set: &'static str,
    priority: u64,
    max_exit: u64,
    pending_exit: u64,
}

fn devnet_lane_specs() -> Vec<DevnetLaneSpec> {
    vec![
        DevnetLaneSpec {
            label: "monero-fast-exit",
            kind: SettlementLaneKind::MoneroFastExit,
            status: ReadinessStatus::Passing,
            exit_asset: "xmr",
            operator_set: "ops-monero-a",
            priority: 10,
            max_exit: 8_000_000_000_000,
            pending_exit: 2_400_000_000_000,
        },
        DevnetLaneSpec {
            label: "monero-private-exit",
            kind: SettlementLaneKind::MoneroPrivateExit,
            status: ReadinessStatus::Passing,
            exit_asset: "xmr",
            operator_set: "ops-monero-b",
            priority: 9,
            max_exit: 5_000_000_000_000,
            pending_exit: 1_500_000_000_000,
        },
        DevnetLaneSpec {
            label: "monero-batch-exit",
            kind: SettlementLaneKind::MoneroBatchExit,
            status: ReadinessStatus::Passing,
            exit_asset: "xmr",
            operator_set: "ops-batch-a",
            priority: 8,
            max_exit: 12_000_000_000_000,
            pending_exit: 3_000_000_000_000,
        },
        DevnetLaneSpec {
            label: "monero-atomic-swap",
            kind: SettlementLaneKind::MoneroAtomicSwap,
            status: ReadinessStatus::Passing,
            exit_asset: "xmr",
            operator_set: "ops-swap-a",
            priority: 7,
            max_exit: 3_000_000_000_000,
            pending_exit: 800_000_000_000,
        },
        DevnetLaneSpec {
            label: "recursive-proof-settlement",
            kind: SettlementLaneKind::RecursiveProofSettlement,
            status: ReadinessStatus::Passing,
            exit_asset: "proof-credit",
            operator_set: "ops-proof-a",
            priority: 10,
            max_exit: 1_000_000,
            pending_exit: 100_000,
        },
        DevnetLaneSpec {
            label: "pq-finality-bridge",
            kind: SettlementLaneKind::PqFinalityBridge,
            status: ReadinessStatus::Passing,
            exit_asset: "finality-vote",
            operator_set: "ops-pq-a",
            priority: 10,
            max_exit: 1_000_000,
            pending_exit: 40_000,
        },
        DevnetLaneSpec {
            label: "fraud-window-watch",
            kind: SettlementLaneKind::FraudProofChallenge,
            status: ReadinessStatus::Passing,
            exit_asset: "challenge-bond",
            operator_set: "ops-watchtower-a",
            priority: 8,
            max_exit: 1_000_000,
            pending_exit: 50_000,
        },
        DevnetLaneSpec {
            label: "liquidity-rebalance",
            kind: SettlementLaneKind::LiquidityRebalance,
            status: ReadinessStatus::Passing,
            exit_asset: "xmr",
            operator_set: "ops-liquidity-a",
            priority: 6,
            max_exit: 15_000_000_000_000,
            pending_exit: 2_000_000_000_000,
        },
        DevnetLaneSpec {
            label: "state-root-anchor",
            kind: SettlementLaneKind::StateRootAnchor,
            status: ReadinessStatus::Passing,
            exit_asset: "state-anchor",
            operator_set: "ops-state-a",
            priority: 10,
            max_exit: 1_000_000,
            pending_exit: 10_000,
        },
        DevnetLaneSpec {
            label: "operator-recovery",
            kind: SettlementLaneKind::OperatorRecovery,
            status: ReadinessStatus::Passing,
            exit_asset: "recovery-bond",
            operator_set: "ops-recovery-a",
            priority: 7,
            max_exit: 1_000_000,
            pending_exit: 15_000,
        },
    ]
}

fn build_devnet_lane(spec: DevnetLaneSpec, height: u64) -> SettlementLane {
    let lane_id = stable_id("lane", spec.label);
    SettlementLane {
        lane_id: lane_id.clone(),
        label: spec.label.to_string(),
        kind: spec.kind,
        status: spec.status,
        exit_asset: spec.exit_asset.to_string(),
        operator_set_id: stable_id("operator-set", spec.operator_set),
        monero_anchor_root: stable_hash("MONERO-ANCHOR", &[spec.label, spec.exit_asset]),
        recursive_proof_queue_id: stable_id("proof-queue", spec.label),
        finality_signal_id: stable_id("finality-signal", spec.label),
        reserve_bucket_id: stable_id("reserve", spec.label),
        fraud_window_id: stable_id("fraud-window", spec.label),
        latest_state_root_id: stable_id("state-root", spec.label),
        release_gate_id: stable_id("release-gate", spec.label),
        priority: spec.priority,
        max_exit_amount_piconero: spec.max_exit,
        pending_exit_amount_piconero: spec.pending_exit,
        opened_at_height: height.saturating_sub(1_000 + spec.priority),
        last_checked_height: height,
    }
}

fn build_devnet_proof_queue(lane: &SettlementLane, height: u64) -> RecursiveProofQueue {
    RecursiveProofQueue {
        queue_id: lane.recursive_proof_queue_id.clone(),
        lane_id: lane.lane_id.clone(),
        status: ProofQueueStatus::Settled,
        circuit_family: format!("{}-recursive-settlement", lane.kind.as_str()),
        aggregate_proof_root: stable_hash("AGGREGATE-PROOF", &[&lane.lane_id, lane.kind.as_str()]),
        verifier_key_root: stable_hash("VERIFIER-KEY", &[&lane.lane_id, "devnet-vk"]),
        pending_batches: if lane.kind.critical() { 0 } else { 1 },
        proved_batches: lane.priority.saturating_add(2),
        failed_batches: 0,
        max_latency_blocks: 36,
        observed_latency_blocks: 12,
        updated_at_height: height,
    }
}

fn build_devnet_finality_signal(lane: &SettlementLane, height: u64) -> PqFinalitySignal {
    PqFinalitySignal {
        signal_id: lane.finality_signal_id.clone(),
        lane_id: lane.lane_id.clone(),
        kind: if lane.kind.monero_bound() {
            FinalitySignalKind::MoneroDepthReached
        } else {
            FinalitySignalKind::PqCommitteeSignature
        },
        status: ReadinessStatus::Passing,
        committee_id: stable_id("pq-committee", lane.kind.as_str()),
        attestation_root: stable_hash("PQ-FINALITY-ATTESTATION", &[&lane.lane_id, "quorum"]),
        quorum_bps: 9_700,
        required_quorum_bps: 9_000,
        observed_at_height: height.saturating_sub(4),
        expires_at_height: height.saturating_add(512),
    }
}

fn build_devnet_fraud_window(lane: &SettlementLane, height: u64) -> FraudWindow {
    FraudWindow {
        window_id: lane.fraud_window_id.clone(),
        lane_id: lane.lane_id.clone(),
        status: FraudWindowStatus::Open,
        batch_root: stable_hash("FRAUD-WINDOW-BATCH", &[&lane.lane_id, "batch"]),
        challenger_set_root: stable_hash("FRAUD-WINDOW-CHALLENGERS", &[&lane.lane_id, "watchers"]),
        bond_root: stable_hash("FRAUD-WINDOW-BONDS", &[&lane.lane_id, "bonded"]),
        opened_at_height: height.saturating_sub(120),
        closes_at_height: height.saturating_add(600),
        challenge_count: 0,
    }
}

fn build_devnet_liquidity_reserve(lane: &SettlementLane, height: u64) -> LiquidityReserve {
    LiquidityReserve {
        reserve_id: lane.reserve_bucket_id.clone(),
        lane_id: lane.lane_id.clone(),
        status: ReserveStatus::Healthy,
        asset_id: lane.exit_asset.clone(),
        custodian_committee_id: stable_id("reserve-committee", lane.kind.as_str()),
        attestation_root: stable_hash("RESERVE-ATTESTATION", &[&lane.lane_id, &lane.exit_asset]),
        available_piconero: lane.max_exit_amount_piconero.saturating_mul(2),
        pending_exit_piconero: lane.pending_exit_amount_piconero,
        coverage_bps: 20_000,
        rebalance_due_height: height.saturating_add(720),
    }
}

fn build_devnet_runtime_state_root(lane: &SettlementLane, height: u64) -> RuntimeStateRoot {
    RuntimeStateRoot {
        root_id: lane.latest_state_root_id.clone(),
        lane_id: lane.lane_id.clone(),
        status: StateRootStatus::Matched,
        l2_state_root: stable_hash("L2-STATE-ROOT", &[&lane.lane_id, &height.to_string()]),
        monero_anchor_root: lane.monero_anchor_root.clone(),
        da_root: stable_hash("DA-ROOT", &[&lane.lane_id, "available"]),
        operator_observation_root: stable_hash("OPERATOR-OBSERVATION", &[&lane.lane_id, "matched"]),
        height,
        observed_at_height: height,
    }
}

fn build_devnet_release_gate(lane: &SettlementLane, height: u64) -> ReleaseGate {
    ReleaseGate {
        gate_id: lane.release_gate_id.clone(),
        lane_id: lane.lane_id.clone(),
        kind: match lane.kind {
            SettlementLaneKind::MoneroFastExit
            | SettlementLaneKind::MoneroPrivateExit
            | SettlementLaneKind::MoneroBatchExit
            | SettlementLaneKind::MoneroAtomicSwap => ReleaseGateKind::MoneroExitSafety,
            SettlementLaneKind::RecursiveProofSettlement => ReleaseGateKind::RecursiveProofSafety,
            SettlementLaneKind::PqFinalityBridge => ReleaseGateKind::PqFinalitySafety,
            SettlementLaneKind::FraudProofChallenge => ReleaseGateKind::FraudWindowSafety,
            SettlementLaneKind::LiquidityRebalance => ReleaseGateKind::LiquidityReserveSafety,
            SettlementLaneKind::StateRootAnchor => ReleaseGateKind::StateRootSafety,
            SettlementLaneKind::OperatorRecovery => ReleaseGateKind::OperatorSafety,
        },
        status: ReadinessStatus::Passing,
        signoff_root: stable_hash("RELEASE-GATE-SIGNOFF", &[&lane.lane_id, "approved"]),
        evidence_root: stable_hash("RELEASE-GATE-EVIDENCE", &[&lane.lane_id, "complete"]),
        required_approvals: 3,
        observed_approvals: 4,
        opened_at_height: height.saturating_sub(90),
        expires_at_height: height.saturating_add(1_000),
    }
}

fn build_devnet_checks(lane: &SettlementLane, height: u64) -> Vec<ReadinessCheck> {
    let mut checks = Vec::new();
    let base = [
        (
            ReadinessCheckKind::MoneroHeaderDepth,
            "header-depth",
            "64",
            "48",
        ),
        (
            ReadinessCheckKind::MoneroExitNullifier,
            "nullifier",
            "unique",
            "unique",
        ),
        (
            ReadinessCheckKind::MoneroReserveProof,
            "reserve-proof",
            "fresh",
            "fresh",
        ),
        (
            ReadinessCheckKind::RecursiveProofQueue,
            "proof-queue",
            "healthy",
            "healthy",
        ),
        (
            ReadinessCheckKind::RecursiveProofVerifier,
            "verifier",
            "accepted",
            "accepted",
        ),
        (
            ReadinessCheckKind::PqCommitteeQuorum,
            "pq-quorum",
            "9700",
            "9000",
        ),
        (
            ReadinessCheckKind::PqSignatureFreshness,
            "pq-freshness",
            "4",
            "64",
        ),
        (
            ReadinessCheckKind::FraudWindowOpen,
            "fraud-window",
            "open",
            "open",
        ),
        (
            ReadinessCheckKind::FraudBondCoverage,
            "fraud-bond",
            "covered",
            "covered",
        ),
        (
            ReadinessCheckKind::LiquidityCoverage,
            "liquidity",
            "20000",
            "12500",
        ),
        (
            ReadinessCheckKind::StateRootContinuity,
            "state-root",
            "matched",
            "matched",
        ),
        (
            ReadinessCheckKind::StateRootDaAvailability,
            "da-root",
            "available",
            "available",
        ),
        (
            ReadinessCheckKind::OperatorIncidentBudget,
            "incident-budget",
            "0",
            "0",
        ),
        (
            ReadinessCheckKind::OperatorRunbookDrill,
            "runbook",
            "passed",
            "passed",
        ),
        (ReadinessCheckKind::ReleaseGateSignoff, "signoff", "4", "3"),
        (
            ReadinessCheckKind::ReleaseGateTimelock,
            "timelock",
            "elapsed",
            "elapsed",
        ),
    ];
    for (kind, suffix, observed, required) in base {
        let severity = if matches!(
            kind,
            ReadinessCheckKind::MoneroHeaderDepth
                | ReadinessCheckKind::RecursiveProofVerifier
                | ReadinessCheckKind::PqCommitteeQuorum
                | ReadinessCheckKind::LiquidityCoverage
                | ReadinessCheckKind::StateRootContinuity
                | ReadinessCheckKind::ReleaseGateSignoff
        ) {
            ReadinessSeverity::Critical
        } else {
            ReadinessSeverity::Required
        };
        checks.push(ReadinessCheck {
            check_id: stable_id("check", &format!("{}-{suffix}", lane.label)),
            lane_id: lane.lane_id.clone(),
            kind,
            severity,
            status: ReadinessStatus::Passing,
            observed_value: observed.to_string(),
            required_value: required.to_string(),
            evidence_root: stable_hash("READINESS-CHECK-EVIDENCE", &[&lane.lane_id, suffix]),
            ticket_id: String::new(),
            created_at_height: height.saturating_sub(240),
            updated_at_height: height,
        });
    }
    checks
}

fn build_devnet_tickets(state: &State) -> Vec<RemediationTicket> {
    let mut tickets = Vec::new();
    let mut seen_lanes = BTreeSet::new();
    for check in state
        .checks
        .values()
        .filter(|check| check.severity.blocks_release())
    {
        if seen_lanes.insert(check.lane_id.clone()) {
            tickets.push(RemediationTicket {
                ticket_id: stable_id("ticket", &format!("{}-standing-remediation", check.lane_id)),
                lane_id: check.lane_id.clone(),
                check_id: check.check_id.clone(),
                status: TicketStatus::Verified,
                severity: check.severity,
                owner: "settlement-runtime".to_string(),
                action_root: stable_hash("REMEDIATION-ACTION", &[&check.lane_id, "verified"]),
                opened_at_height: state.height.saturating_sub(360),
                due_height: state
                    .height
                    .saturating_add(state.config.remediation_ttl_blocks),
                verified_at_height: state.height.saturating_sub(24),
            });
        }
    }
    tickets
}
