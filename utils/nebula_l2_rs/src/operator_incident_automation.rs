use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION: &str =
    "nebula-operator-incident-automation-v1";
pub const DEFAULT_TRIGGER_TTL_BLOCKS: u64 = 180;
pub const DEFAULT_RUNBOOK_ACK_BLOCKS: u64 = 12;
pub const DEFAULT_FREEZE_TTL_BLOCKS: u64 = 144;
pub const DEFAULT_QUARANTINE_TTL_BLOCKS: u64 = 720;
pub const DEFAULT_BRIDGE_PAUSE_TTL_BLOCKS: u64 = 288;
pub const DEFAULT_POSTMORTEM_DUE_BLOCKS: u64 = 2_880;
pub const DEFAULT_LATENCY_TRIGGER_MS: u64 = 2_500;
pub const DEFAULT_FEE_SPIKE_BPS: u64 = 1_500;
pub const DEFAULT_PRIVACY_RISK_BPS: u64 = 6_500;
pub const DEFAULT_MONERO_REORG_DEPTH: u64 = 8;
pub const DEFAULT_PROVER_BACKLOG: u64 = 64;
pub const DEFAULT_DA_FAILURE_BPS: u64 = 2_000;
pub const DEFAULT_LOW_FEE_MIN_BUDGET_UNITS: u64 = 250_000;
pub const DEFAULT_PQ_MIN_SECURITY_BITS: u16 = 192;
pub const MAX_BPS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentDomain {
    Latency,
    Fees,
    Privacy,
    Monero,
    Prover,
    DataAvailability,
    PostQuantum,
    PrivateState,
    BridgeSettlement,
    LowFeeLane,
    Global,
}

impl IncidentDomain {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Latency => "latency",
            Self::Fees => "fees",
            Self::Privacy => "privacy",
            Self::Monero => "monero",
            Self::Prover => "prover",
            Self::DataAvailability => "data_availability",
            Self::PostQuantum => "post_quantum",
            Self::PrivateState => "private_state",
            Self::BridgeSettlement => "bridge_settlement",
            Self::LowFeeLane => "low_fee_lane",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Watch,
    Warning,
    Severe,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Warning => "warning",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }

    pub fn floor_bps(self) -> u64 {
        match self {
            Self::Watch => 1_000,
            Self::Warning => 3_000,
            Self::Severe => 6_000,
            Self::Critical => 8_500,
        }
    }

    pub fn freezes(self) -> bool {
        matches!(self, Self::Severe | Self::Critical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Acknowledged,
    Mitigating,
    Resolved,
    Expired,
    Superseded,
}

impl IncidentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Mitigating => "mitigating",
            Self::Resolved => "resolved",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Open | Self::Acknowledged | Self::Mitigating)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    LatencySloBreach,
    FeeSpike,
    LowFeeBudgetDepleted,
    PrivacyLeakSignal,
    MoneroReorg,
    MoneroDaemonDivergence,
    ProverBacklog,
    ProverProofInvalid,
    DataAvailabilitySamplingFailure,
    DataAvailabilityQuorumLoss,
    PqKeyCompromise,
    PrivateStateInconsistency,
    BridgeSettlementStalled,
}

impl TriggerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencySloBreach => "latency_slo_breach",
            Self::FeeSpike => "fee_spike",
            Self::LowFeeBudgetDepleted => "low_fee_budget_depleted",
            Self::PrivacyLeakSignal => "privacy_leak_signal",
            Self::MoneroReorg => "monero_reorg",
            Self::MoneroDaemonDivergence => "monero_daemon_divergence",
            Self::ProverBacklog => "prover_backlog",
            Self::ProverProofInvalid => "prover_proof_invalid",
            Self::DataAvailabilitySamplingFailure => "data_availability_sampling_failure",
            Self::DataAvailabilityQuorumLoss => "data_availability_quorum_loss",
            Self::PqKeyCompromise => "pq_key_compromise",
            Self::PrivateStateInconsistency => "private_state_inconsistency",
            Self::BridgeSettlementStalled => "bridge_settlement_stalled",
        }
    }

    pub fn domain(self) -> IncidentDomain {
        match self {
            Self::LatencySloBreach => IncidentDomain::Latency,
            Self::FeeSpike => IncidentDomain::Fees,
            Self::LowFeeBudgetDepleted => IncidentDomain::LowFeeLane,
            Self::PrivacyLeakSignal => IncidentDomain::Privacy,
            Self::MoneroReorg | Self::MoneroDaemonDivergence => IncidentDomain::Monero,
            Self::ProverBacklog | Self::ProverProofInvalid => IncidentDomain::Prover,
            Self::DataAvailabilitySamplingFailure | Self::DataAvailabilityQuorumLoss => {
                IncidentDomain::DataAvailability
            }
            Self::PqKeyCompromise => IncidentDomain::PostQuantum,
            Self::PrivateStateInconsistency => IncidentDomain::PrivateState,
            Self::BridgeSettlementStalled => IncidentDomain::BridgeSettlement,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookKind {
    LatencyRecovery,
    FeeStabilization,
    PrivacyContainment,
    MoneroBridgeSafety,
    ProverCapacityFailover,
    DataAvailabilityRecovery,
    PostQuantumKeyCompromise,
    PrivateStateQuarantine,
    BridgeSettlementPause,
    LowFeeSubsidyProtection,
}

impl RunbookKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LatencyRecovery => "latency_recovery",
            Self::FeeStabilization => "fee_stabilization",
            Self::PrivacyContainment => "privacy_containment",
            Self::MoneroBridgeSafety => "monero_bridge_safety",
            Self::ProverCapacityFailover => "prover_capacity_failover",
            Self::DataAvailabilityRecovery => "data_availability_recovery",
            Self::PostQuantumKeyCompromise => "post_quantum_key_compromise",
            Self::PrivateStateQuarantine => "private_state_quarantine",
            Self::BridgeSettlementPause => "bridge_settlement_pause",
            Self::LowFeeSubsidyProtection => "low_fee_subsidy_protection",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    DispatchRunbook,
    PageOncall,
    RaiseGovernanceIncident,
    FreezeSequencerAdmission,
    FreezeBridgeWithdrawals,
    FreezeContractUpgrades,
    PauseBridgeSettlement,
    UnpauseBridgeSettlement,
    ActivateLowFeeSubsidy,
    CapLowFeeExposure,
    RotatePqKeys,
    RevokePqSession,
    QuarantinePrivateState,
    QuarantineDaBatch,
    IncreaseProverCapacity,
    RequireRecursiveProofReview,
}

impl ActionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DispatchRunbook => "dispatch_runbook",
            Self::PageOncall => "page_oncall",
            Self::RaiseGovernanceIncident => "raise_governance_incident",
            Self::FreezeSequencerAdmission => "freeze_sequencer_admission",
            Self::FreezeBridgeWithdrawals => "freeze_bridge_withdrawals",
            Self::FreezeContractUpgrades => "freeze_contract_upgrades",
            Self::PauseBridgeSettlement => "pause_bridge_settlement",
            Self::UnpauseBridgeSettlement => "unpause_bridge_settlement",
            Self::ActivateLowFeeSubsidy => "activate_low_fee_subsidy",
            Self::CapLowFeeExposure => "cap_low_fee_exposure",
            Self::RotatePqKeys => "rotate_pq_keys",
            Self::RevokePqSession => "revoke_pq_session",
            Self::QuarantinePrivateState => "quarantine_private_state",
            Self::QuarantineDaBatch => "quarantine_da_batch",
            Self::IncreaseProverCapacity => "increase_prover_capacity",
            Self::RequireRecursiveProofReview => "require_recursive_proof_review",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Planned,
    Active,
    Completed,
    Failed,
    Expired,
    Cancelled,
}

impl ActionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Active => "active",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Planned | Self::Active)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreezeScope {
    SequencerAdmission,
    BridgeWithdrawals,
    ContractUpgrades,
    ProverSettlements,
    PrivateStateWrites,
    Global,
}

impl FreezeScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SequencerAdmission => "sequencer_admission",
            Self::BridgeWithdrawals => "bridge_withdrawals",
            Self::ContractUpgrades => "contract_upgrades",
            Self::ProverSettlements => "prover_settlements",
            Self::PrivateStateWrites => "private_state_writes",
            Self::Global => "global",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSettlementMode {
    Normal,
    Paused,
    ProofOnly,
    EmergencyExitOnly,
}

impl BridgeSettlementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Paused => "paused",
            Self::ProofOnly => "proof_only",
            Self::EmergencyExitOnly => "emergency_exit_only",
        }
    }

    pub fn paused(self) -> bool {
        matches!(
            self,
            Self::Paused | Self::ProofOnly | Self::EmergencyExitOnly
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineStatus {
    Active,
    Review,
    Released,
    Escalated,
    Expired,
}

impl QuarantineStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Review => "review",
            Self::Released => "released",
            Self::Escalated => "escalated",
            Self::Expired => "expired",
        }
    }

    pub fn active(self) -> bool {
        matches!(self, Self::Active | Self::Review)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    MetricSnapshot,
    MerkleWitness,
    MoneroDaemonObservation,
    ProverTrace,
    DataAvailabilitySample,
    PrivacyAnalysis,
    PqSignatureAudit,
    RunbookTranscript,
    GovernanceTicket,
    OperatorNote,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MetricSnapshot => "metric_snapshot",
            Self::MerkleWitness => "merkle_witness",
            Self::MoneroDaemonObservation => "monero_daemon_observation",
            Self::ProverTrace => "prover_trace",
            Self::DataAvailabilitySample => "data_availability_sample",
            Self::PrivacyAnalysis => "privacy_analysis",
            Self::PqSignatureAudit => "pq_signature_audit",
            Self::RunbookTranscript => "runbook_transcript",
            Self::GovernanceTicket => "governance_ticket",
            Self::OperatorNote => "operator_note",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationTarget {
    Oncall,
    BridgeCouncil,
    SecurityCouncil,
    PrivacyReviewers,
    ProverOperators,
    DataAvailabilityCommittee,
    Governance,
}

impl EscalationTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Oncall => "oncall",
            Self::BridgeCouncil => "bridge_council",
            Self::SecurityCouncil => "security_council",
            Self::PrivacyReviewers => "privacy_reviewers",
            Self::ProverOperators => "prover_operators",
            Self::DataAvailabilityCommittee => "data_availability_committee",
            Self::Governance => "governance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub operator_label: String,
    pub trigger_ttl_blocks: u64,
    pub runbook_ack_blocks: u64,
    pub freeze_ttl_blocks: u64,
    pub quarantine_ttl_blocks: u64,
    pub bridge_pause_ttl_blocks: u64,
    pub postmortem_due_blocks: u64,
    pub latency_trigger_ms: u64,
    pub fee_spike_bps: u64,
    pub privacy_risk_bps: u64,
    pub monero_reorg_depth: u64,
    pub prover_backlog_jobs: u64,
    pub da_failure_bps: u64,
    pub low_fee_min_budget_units: u64,
    pub pq_min_security_bits: u16,
    pub auto_freeze_enabled: bool,
    pub auto_bridge_pause_enabled: bool,
    pub auto_low_fee_protection_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_version: OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            operator_label: "devnet-operator".to_string(),
            trigger_ttl_blocks: DEFAULT_TRIGGER_TTL_BLOCKS,
            runbook_ack_blocks: DEFAULT_RUNBOOK_ACK_BLOCKS,
            freeze_ttl_blocks: DEFAULT_FREEZE_TTL_BLOCKS,
            quarantine_ttl_blocks: DEFAULT_QUARANTINE_TTL_BLOCKS,
            bridge_pause_ttl_blocks: DEFAULT_BRIDGE_PAUSE_TTL_BLOCKS,
            postmortem_due_blocks: DEFAULT_POSTMORTEM_DUE_BLOCKS,
            latency_trigger_ms: DEFAULT_LATENCY_TRIGGER_MS,
            fee_spike_bps: DEFAULT_FEE_SPIKE_BPS,
            privacy_risk_bps: DEFAULT_PRIVACY_RISK_BPS,
            monero_reorg_depth: DEFAULT_MONERO_REORG_DEPTH,
            prover_backlog_jobs: DEFAULT_PROVER_BACKLOG,
            da_failure_bps: DEFAULT_DA_FAILURE_BPS,
            low_fee_min_budget_units: DEFAULT_LOW_FEE_MIN_BUDGET_UNITS,
            pq_min_security_bits: DEFAULT_PQ_MIN_SECURITY_BITS,
            auto_freeze_enabled: true,
            auto_bridge_pause_enabled: true,
            auto_low_fee_protection_enabled: true,
        }
    }
}

impl Config {
    pub fn devnet(operator_label: impl Into<String>) -> Self {
        Self {
            operator_label: operator_label.into(),
            ..Self::default()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_automation_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "trigger_ttl_blocks": self.trigger_ttl_blocks,
            "runbook_ack_blocks": self.runbook_ack_blocks,
            "freeze_ttl_blocks": self.freeze_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "bridge_pause_ttl_blocks": self.bridge_pause_ttl_blocks,
            "postmortem_due_blocks": self.postmortem_due_blocks,
            "latency_trigger_ms": self.latency_trigger_ms,
            "fee_spike_bps": self.fee_spike_bps,
            "privacy_risk_bps": self.privacy_risk_bps,
            "monero_reorg_depth": self.monero_reorg_depth,
            "prover_backlog_jobs": self.prover_backlog_jobs,
            "da_failure_bps": self.da_failure_bps,
            "low_fee_min_budget_units": self.low_fee_min_budget_units,
            "pq_min_security_bits": self.pq_min_security_bits,
            "auto_freeze_enabled": self.auto_freeze_enabled,
            "auto_bridge_pause_enabled": self.auto_bridge_pause_enabled,
            "auto_low_fee_protection_enabled": self.auto_low_fee_protection_enabled,
            "config_root": self.config_root(),
        })
    }

    pub fn config_root(&self) -> String {
        operator_incident_payload_root("OPERATOR-INCIDENT-CONFIG", &self.identity_record())
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("operator incident protocol version", &self.protocol_version)?;
        if self.protocol_version != OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION {
            return Err("operator incident protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("operator incident chain id mismatch".to_string());
        }
        require_non_empty("operator incident operator label", &self.operator_label)?;
        require_positive("operator incident trigger ttl", self.trigger_ttl_blocks)?;
        require_positive(
            "operator incident runbook ack blocks",
            self.runbook_ack_blocks,
        )?;
        require_positive("operator incident freeze ttl", self.freeze_ttl_blocks)?;
        require_positive(
            "operator incident quarantine ttl",
            self.quarantine_ttl_blocks,
        )?;
        require_positive(
            "operator incident bridge pause ttl",
            self.bridge_pause_ttl_blocks,
        )?;
        require_positive(
            "operator incident postmortem due blocks",
            self.postmortem_due_blocks,
        )?;
        require_positive("operator incident latency trigger", self.latency_trigger_ms)?;
        require_bps("operator incident fee spike bps", self.fee_spike_bps)?;
        require_bps("operator incident privacy risk bps", self.privacy_risk_bps)?;
        require_positive(
            "operator incident monero reorg depth",
            self.monero_reorg_depth,
        )?;
        require_positive("operator incident prover backlog", self.prover_backlog_jobs)?;
        require_bps("operator incident da failure bps", self.da_failure_bps)?;
        require_positive(
            "operator incident low fee min budget",
            self.low_fee_min_budget_units,
        )?;
        if self.pq_min_security_bits == 0 {
            return Err("operator incident pq min security bits must be positive".to_string());
        }
        Ok(self.config_root())
    }

    fn identity_record(&self) -> Value {
        json!({
            "kind": "operator_incident_automation_config",
            "protocol_version": self.protocol_version,
            "chain_id": self.chain_id,
            "operator_label": self.operator_label,
            "trigger_ttl_blocks": self.trigger_ttl_blocks,
            "runbook_ack_blocks": self.runbook_ack_blocks,
            "freeze_ttl_blocks": self.freeze_ttl_blocks,
            "quarantine_ttl_blocks": self.quarantine_ttl_blocks,
            "bridge_pause_ttl_blocks": self.bridge_pause_ttl_blocks,
            "postmortem_due_blocks": self.postmortem_due_blocks,
            "latency_trigger_ms": self.latency_trigger_ms,
            "fee_spike_bps": self.fee_spike_bps,
            "privacy_risk_bps": self.privacy_risk_bps,
            "monero_reorg_depth": self.monero_reorg_depth,
            "prover_backlog_jobs": self.prover_backlog_jobs,
            "da_failure_bps": self.da_failure_bps,
            "low_fee_min_budget_units": self.low_fee_min_budget_units,
            "pq_min_security_bits": self.pq_min_security_bits,
            "auto_freeze_enabled": self.auto_freeze_enabled,
            "auto_bridge_pause_enabled": self.auto_bridge_pause_enabled,
            "auto_low_fee_protection_enabled": self.auto_low_fee_protection_enabled,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentObservation {
    pub observation_id: String,
    pub height: u64,
    pub source_label: String,
    pub latency_ms: u64,
    pub fee_spike_bps: u64,
    pub privacy_risk_bps: u64,
    pub monero_reorg_depth: u64,
    pub monero_daemon_divergence: bool,
    pub prover_backlog_jobs: u64,
    pub invalid_proof_seen: bool,
    pub da_failure_bps: u64,
    pub da_quorum_loss: bool,
    pub low_fee_budget_units: u64,
    pub pq_security_bits: u16,
    pub pq_compromise_signal: bool,
    pub private_state_inconsistency: bool,
    pub bridge_settlement_lag_blocks: u64,
    pub metadata_root: String,
}

impl IncidentObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        source_label: &str,
        latency_ms: u64,
        fee_spike_bps: u64,
        privacy_risk_bps: u64,
        monero_reorg_depth: u64,
        monero_daemon_divergence: bool,
        prover_backlog_jobs: u64,
        invalid_proof_seen: bool,
        da_failure_bps: u64,
        da_quorum_loss: bool,
        low_fee_budget_units: u64,
        pq_security_bits: u16,
        pq_compromise_signal: bool,
        private_state_inconsistency: bool,
        bridge_settlement_lag_blocks: u64,
        metadata: &Value,
    ) -> Result<Self> {
        require_non_empty("incident observation source label", source_label)?;
        require_bps("incident observation fee spike bps", fee_spike_bps)?;
        require_bps("incident observation privacy risk bps", privacy_risk_bps)?;
        require_bps("incident observation da failure bps", da_failure_bps)?;
        let metadata_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-OBSERVATION-METADATA", metadata);
        let observation_id = operator_incident_observation_id(
            height,
            source_label,
            latency_ms,
            fee_spike_bps,
            privacy_risk_bps,
            monero_reorg_depth,
            prover_backlog_jobs,
            da_failure_bps,
            low_fee_budget_units,
            &metadata_root,
        );
        Ok(Self {
            observation_id,
            height,
            source_label: source_label.to_string(),
            latency_ms,
            fee_spike_bps,
            privacy_risk_bps,
            monero_reorg_depth,
            monero_daemon_divergence,
            prover_backlog_jobs,
            invalid_proof_seen,
            da_failure_bps,
            da_quorum_loss,
            low_fee_budget_units,
            pq_security_bits,
            pq_compromise_signal,
            private_state_inconsistency,
            bridge_settlement_lag_blocks,
            metadata_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_observation",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "observation_id": self.observation_id,
            "height": self.height,
            "source_label": self.source_label,
            "latency_ms": self.latency_ms,
            "fee_spike_bps": self.fee_spike_bps,
            "privacy_risk_bps": self.privacy_risk_bps,
            "monero_reorg_depth": self.monero_reorg_depth,
            "monero_daemon_divergence": self.monero_daemon_divergence,
            "prover_backlog_jobs": self.prover_backlog_jobs,
            "invalid_proof_seen": self.invalid_proof_seen,
            "da_failure_bps": self.da_failure_bps,
            "da_quorum_loss": self.da_quorum_loss,
            "low_fee_budget_units": self.low_fee_budget_units,
            "pq_security_bits": self.pq_security_bits,
            "pq_compromise_signal": self.pq_compromise_signal,
            "private_state_inconsistency": self.private_state_inconsistency,
            "bridge_settlement_lag_blocks": self.bridge_settlement_lag_blocks,
            "metadata_root": self.metadata_root,
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("incident observation id", &self.observation_id)?;
        require_non_empty("incident observation source label", &self.source_label)?;
        require_non_empty("incident observation metadata root", &self.metadata_root)?;
        require_bps("incident observation fee spike bps", self.fee_spike_bps)?;
        require_bps(
            "incident observation privacy risk bps",
            self.privacy_risk_bps,
        )?;
        require_bps("incident observation da failure bps", self.da_failure_bps)?;
        let expected = operator_incident_observation_id(
            self.height,
            &self.source_label,
            self.latency_ms,
            self.fee_spike_bps,
            self.privacy_risk_bps,
            self.monero_reorg_depth,
            self.prover_backlog_jobs,
            self.da_failure_bps,
            self.low_fee_budget_units,
            &self.metadata_root,
        );
        if self.observation_id != expected {
            return Err("incident observation id mismatch".to_string());
        }
        Ok(self.observation_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTrigger {
    pub trigger_id: String,
    pub trigger_kind: TriggerKind,
    pub domain: IncidentDomain,
    pub severity: Severity,
    pub severity_bps: u64,
    pub observed_value: u64,
    pub threshold_value: u64,
    pub evidence_root: String,
    pub source_label: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: IncidentStatus,
}

impl IncidentTrigger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_kind: TriggerKind,
        severity: Severity,
        severity_bps: u64,
        observed_value: u64,
        threshold_value: u64,
        evidence: &Value,
        source_label: &str,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("incident trigger source label", source_label)?;
        require_bps("incident trigger severity bps", severity_bps)?;
        if severity_bps < severity.floor_bps() {
            return Err("incident trigger severity bps below severity floor".to_string());
        }
        if expires_at_height <= opened_at_height {
            return Err("incident trigger expiry must be after open height".to_string());
        }
        let domain = trigger_kind.domain();
        let evidence_root = operator_incident_payload_root("OPERATOR-INCIDENT-EVIDENCE", evidence);
        let trigger_id = operator_incident_trigger_id(
            trigger_kind,
            severity,
            observed_value,
            threshold_value,
            &evidence_root,
            source_label,
            opened_at_height,
        );
        Ok(Self {
            trigger_id,
            trigger_kind,
            domain,
            severity,
            severity_bps,
            observed_value,
            threshold_value,
            evidence_root,
            source_label: source_label.to_string(),
            opened_at_height,
            expires_at_height,
            status: IncidentStatus::Open,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_trigger",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "trigger_id": self.trigger_id,
            "trigger_kind": self.trigger_kind.as_str(),
            "domain": self.domain.as_str(),
            "severity": self.severity.as_str(),
            "severity_bps": self.severity_bps,
            "observed_value": self.observed_value,
            "threshold_value": self.threshold_value,
            "evidence_root": self.evidence_root,
            "source_label": self.source_label,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("incident trigger id", &self.trigger_id)?;
        require_non_empty("incident trigger evidence root", &self.evidence_root)?;
        require_non_empty("incident trigger source label", &self.source_label)?;
        require_bps("incident trigger severity bps", self.severity_bps)?;
        if self.domain != self.trigger_kind.domain() {
            return Err("incident trigger domain mismatch".to_string());
        }
        if self.severity_bps < self.severity.floor_bps() {
            return Err("incident trigger severity bps below severity floor".to_string());
        }
        if self.expires_at_height <= self.opened_at_height {
            return Err("incident trigger expiry must be after open height".to_string());
        }
        let expected = operator_incident_trigger_id(
            self.trigger_kind,
            self.severity,
            self.observed_value,
            self.threshold_value,
            &self.evidence_root,
            &self.source_label,
            self.opened_at_height,
        );
        if self.trigger_id != expected {
            return Err("incident trigger id mismatch".to_string());
        }
        Ok(self.trigger_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectionAction {
    pub action_id: String,
    pub trigger_id: String,
    pub action_kind: ActionKind,
    pub domain: IncidentDomain,
    pub target_root: String,
    pub parameter_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: ActionStatus,
}

impl ProtectionAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        action_kind: ActionKind,
        domain: IncidentDomain,
        target: &Value,
        parameters: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        status: ActionStatus,
    ) -> Result<Self> {
        require_non_empty("protection action trigger id", trigger_id)?;
        if expires_at_height <= starts_at_height {
            return Err("protection action expiry must be after start height".to_string());
        }
        let target_root = operator_incident_payload_root("OPERATOR-INCIDENT-ACTION-TARGET", target);
        let parameter_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-ACTION-PARAMETERS", parameters);
        let action_id = operator_incident_action_id(
            trigger_id,
            action_kind,
            domain,
            &target_root,
            &parameter_root,
            starts_at_height,
        );
        Ok(Self {
            action_id,
            trigger_id: trigger_id.to_string(),
            action_kind,
            domain,
            target_root,
            parameter_root,
            starts_at_height,
            expires_at_height,
            status,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_protection_action",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "action_id": self.action_id,
            "trigger_id": self.trigger_id,
            "action_kind": self.action_kind.as_str(),
            "domain": self.domain.as_str(),
            "target_root": self.target_root,
            "parameter_root": self.parameter_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("protection action id", &self.action_id)?;
        require_non_empty("protection action trigger id", &self.trigger_id)?;
        require_non_empty("protection action target root", &self.target_root)?;
        require_non_empty("protection action parameter root", &self.parameter_root)?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("protection action expiry must be after start height".to_string());
        }
        let expected = operator_incident_action_id(
            &self.trigger_id,
            self.action_kind,
            self.domain,
            &self.target_root,
            &self.parameter_root,
            self.starts_at_height,
        );
        if self.action_id != expected {
            return Err("protection action id mismatch".to_string());
        }
        Ok(self.action_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookDispatch {
    pub dispatch_id: String,
    pub trigger_id: String,
    pub runbook_kind: RunbookKind,
    pub runbook_root: String,
    pub action_root: String,
    pub operator_commitment: String,
    pub dispatched_at_height: u64,
    pub ack_deadline_height: u64,
    pub status: ActionStatus,
}

impl RunbookDispatch {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        runbook_kind: RunbookKind,
        runbook: &Value,
        action_ids: &[String],
        operator_label: &str,
        dispatched_at_height: u64,
        ack_deadline_height: u64,
    ) -> Result<Self> {
        require_non_empty("runbook dispatch trigger id", trigger_id)?;
        require_non_empty("runbook dispatch operator label", operator_label)?;
        if ack_deadline_height <= dispatched_at_height {
            return Err("runbook dispatch ack deadline must be after dispatch height".to_string());
        }
        let runbook_root = operator_incident_payload_root("OPERATOR-INCIDENT-RUNBOOK", runbook);
        let action_root = string_collection_root("OPERATOR-INCIDENT-RUNBOOK-ACTIONS", action_ids);
        let operator_commitment = operator_incident_string_root(operator_label);
        let dispatch_id = operator_incident_runbook_dispatch_id(
            trigger_id,
            runbook_kind,
            &runbook_root,
            &action_root,
            &operator_commitment,
            dispatched_at_height,
        );
        Ok(Self {
            dispatch_id,
            trigger_id: trigger_id.to_string(),
            runbook_kind,
            runbook_root,
            action_root,
            operator_commitment,
            dispatched_at_height,
            ack_deadline_height,
            status: ActionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_runbook_dispatch",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "dispatch_id": self.dispatch_id,
            "trigger_id": self.trigger_id,
            "runbook_kind": self.runbook_kind.as_str(),
            "runbook_root": self.runbook_root,
            "action_root": self.action_root,
            "operator_commitment": self.operator_commitment,
            "dispatched_at_height": self.dispatched_at_height,
            "ack_deadline_height": self.ack_deadline_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("runbook dispatch id", &self.dispatch_id)?;
        require_non_empty("runbook dispatch trigger id", &self.trigger_id)?;
        require_non_empty("runbook dispatch root", &self.runbook_root)?;
        require_non_empty("runbook dispatch action root", &self.action_root)?;
        require_non_empty(
            "runbook dispatch operator commitment",
            &self.operator_commitment,
        )?;
        if self.ack_deadline_height <= self.dispatched_at_height {
            return Err("runbook dispatch ack deadline must be after dispatch height".to_string());
        }
        let expected = operator_incident_runbook_dispatch_id(
            &self.trigger_id,
            self.runbook_kind,
            &self.runbook_root,
            &self.action_root,
            &self.operator_commitment,
            self.dispatched_at_height,
        );
        if self.dispatch_id != expected {
            return Err("runbook dispatch id mismatch".to_string());
        }
        Ok(self.dispatch_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyFreeze {
    pub freeze_id: String,
    pub trigger_id: String,
    pub scope: FreezeScope,
    pub reason_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub allow_emergency_exits: bool,
    pub status: ActionStatus,
}

impl EmergencyFreeze {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        scope: FreezeScope,
        reason: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        allow_emergency_exits: bool,
    ) -> Result<Self> {
        require_non_empty("emergency freeze trigger id", trigger_id)?;
        if expires_at_height <= starts_at_height {
            return Err("emergency freeze expiry must be after start height".to_string());
        }
        let reason_root = operator_incident_payload_root("OPERATOR-INCIDENT-FREEZE-REASON", reason);
        let freeze_id = operator_incident_freeze_id(
            trigger_id,
            scope,
            &reason_root,
            starts_at_height,
            allow_emergency_exits,
        );
        Ok(Self {
            freeze_id,
            trigger_id: trigger_id.to_string(),
            scope,
            reason_root,
            starts_at_height,
            expires_at_height,
            allow_emergency_exits,
            status: ActionStatus::Active,
        })
    }

    pub fn active(&self) -> bool {
        self.status.active()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_emergency_freeze",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "freeze_id": self.freeze_id,
            "trigger_id": self.trigger_id,
            "scope": self.scope.as_str(),
            "reason_root": self.reason_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "allow_emergency_exits": self.allow_emergency_exits,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("emergency freeze id", &self.freeze_id)?;
        require_non_empty("emergency freeze trigger id", &self.trigger_id)?;
        require_non_empty("emergency freeze reason root", &self.reason_root)?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("emergency freeze expiry must be after start height".to_string());
        }
        let expected = operator_incident_freeze_id(
            &self.trigger_id,
            self.scope,
            &self.reason_root,
            self.starts_at_height,
            self.allow_emergency_exits,
        );
        if self.freeze_id != expected {
            return Err("emergency freeze id mismatch".to_string());
        }
        Ok(self.freeze_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LowFeeSubsidyProtection {
    pub protection_id: String,
    pub trigger_id: String,
    pub lane_root: String,
    pub sponsor_root: String,
    pub budget_floor_units: u64,
    pub subsidy_units: u64,
    pub exposure_cap_bps: u64,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub status: ActionStatus,
}

impl LowFeeSubsidyProtection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        lane: &Value,
        sponsor: &Value,
        budget_floor_units: u64,
        subsidy_units: u64,
        exposure_cap_bps: u64,
        starts_at_height: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("low fee protection trigger id", trigger_id)?;
        require_positive("low fee protection budget floor", budget_floor_units)?;
        require_positive("low fee protection subsidy units", subsidy_units)?;
        require_bps("low fee protection exposure cap", exposure_cap_bps)?;
        if expires_at_height <= starts_at_height {
            return Err("low fee protection expiry must be after start height".to_string());
        }
        let lane_root = operator_incident_payload_root("OPERATOR-INCIDENT-LOW-FEE-LANE", lane);
        let sponsor_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-LOW-FEE-SPONSOR", sponsor);
        let protection_id = operator_incident_low_fee_protection_id(
            trigger_id,
            &lane_root,
            &sponsor_root,
            budget_floor_units,
            subsidy_units,
            exposure_cap_bps,
            starts_at_height,
        );
        Ok(Self {
            protection_id,
            trigger_id: trigger_id.to_string(),
            lane_root,
            sponsor_root,
            budget_floor_units,
            subsidy_units,
            exposure_cap_bps,
            starts_at_height,
            expires_at_height,
            status: ActionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_low_fee_subsidy_protection",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "protection_id": self.protection_id,
            "trigger_id": self.trigger_id,
            "lane_root": self.lane_root,
            "sponsor_root": self.sponsor_root,
            "budget_floor_units": self.budget_floor_units,
            "subsidy_units": self.subsidy_units,
            "exposure_cap_bps": self.exposure_cap_bps,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("low fee protection id", &self.protection_id)?;
        require_non_empty("low fee protection trigger id", &self.trigger_id)?;
        require_non_empty("low fee protection lane root", &self.lane_root)?;
        require_non_empty("low fee protection sponsor root", &self.sponsor_root)?;
        require_positive("low fee protection budget floor", self.budget_floor_units)?;
        require_positive("low fee protection subsidy units", self.subsidy_units)?;
        require_bps("low fee protection exposure cap", self.exposure_cap_bps)?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("low fee protection expiry must be after start height".to_string());
        }
        let expected = operator_incident_low_fee_protection_id(
            &self.trigger_id,
            &self.lane_root,
            &self.sponsor_root,
            self.budget_floor_units,
            self.subsidy_units,
            self.exposure_cap_bps,
            self.starts_at_height,
        );
        if self.protection_id != expected {
            return Err("low fee protection id mismatch".to_string());
        }
        Ok(self.protection_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PqKeyCompromiseAction {
    pub compromise_id: String,
    pub trigger_id: String,
    pub compromised_key_root: String,
    pub replacement_key_root: String,
    pub revoked_session_root: String,
    pub security_bits_before: u16,
    pub security_bits_after: u16,
    pub rotation_height: u64,
    pub governance_ticket_root: String,
    pub status: ActionStatus,
}

impl PqKeyCompromiseAction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        compromised_key: &Value,
        replacement_key: &Value,
        revoked_sessions: &[String],
        security_bits_before: u16,
        security_bits_after: u16,
        rotation_height: u64,
        governance_ticket: &Value,
    ) -> Result<Self> {
        require_non_empty("pq compromise trigger id", trigger_id)?;
        if security_bits_after <= security_bits_before {
            return Err("pq compromise replacement security must improve".to_string());
        }
        let compromised_key_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-PQ-COMPROMISED-KEY", compromised_key);
        let replacement_key_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-PQ-REPLACEMENT-KEY", replacement_key);
        let revoked_session_root =
            string_collection_root("OPERATOR-INCIDENT-PQ-REVOKED-SESSIONS", revoked_sessions);
        let governance_ticket_root = operator_incident_payload_root(
            "OPERATOR-INCIDENT-PQ-GOVERNANCE-TICKET",
            governance_ticket,
        );
        let compromise_id = operator_incident_pq_compromise_id(
            trigger_id,
            &compromised_key_root,
            &replacement_key_root,
            &revoked_session_root,
            rotation_height,
        );
        Ok(Self {
            compromise_id,
            trigger_id: trigger_id.to_string(),
            compromised_key_root,
            replacement_key_root,
            revoked_session_root,
            security_bits_before,
            security_bits_after,
            rotation_height,
            governance_ticket_root,
            status: ActionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_pq_key_compromise_action",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "compromise_id": self.compromise_id,
            "trigger_id": self.trigger_id,
            "compromised_key_root": self.compromised_key_root,
            "replacement_key_root": self.replacement_key_root,
            "revoked_session_root": self.revoked_session_root,
            "security_bits_before": self.security_bits_before,
            "security_bits_after": self.security_bits_after,
            "rotation_height": self.rotation_height,
            "governance_ticket_root": self.governance_ticket_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("pq compromise id", &self.compromise_id)?;
        require_non_empty("pq compromise trigger id", &self.trigger_id)?;
        require_non_empty("pq compromised key root", &self.compromised_key_root)?;
        require_non_empty("pq replacement key root", &self.replacement_key_root)?;
        require_non_empty("pq revoked session root", &self.revoked_session_root)?;
        require_non_empty("pq governance ticket root", &self.governance_ticket_root)?;
        if self.security_bits_after <= self.security_bits_before {
            return Err("pq compromise replacement security must improve".to_string());
        }
        let expected = operator_incident_pq_compromise_id(
            &self.trigger_id,
            &self.compromised_key_root,
            &self.replacement_key_root,
            &self.revoked_session_root,
            self.rotation_height,
        );
        if self.compromise_id != expected {
            return Err("pq compromise id mismatch".to_string());
        }
        Ok(self.compromise_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivateStateQuarantine {
    pub quarantine_id: String,
    pub trigger_id: String,
    pub state_root: String,
    pub nullifier_root: String,
    pub disclosure_ticket_root: String,
    pub opened_at_height: u64,
    pub expires_at_height: u64,
    pub status: QuarantineStatus,
}

impl PrivateStateQuarantine {
    pub fn new(
        trigger_id: &str,
        state_root: &str,
        nullifier_root: &str,
        disclosure_ticket: &Value,
        opened_at_height: u64,
        expires_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("private state quarantine trigger id", trigger_id)?;
        require_non_empty("private state quarantine state root", state_root)?;
        require_non_empty("private state quarantine nullifier root", nullifier_root)?;
        if expires_at_height <= opened_at_height {
            return Err("private state quarantine expiry must be after open height".to_string());
        }
        let disclosure_ticket_root = operator_incident_payload_root(
            "OPERATOR-INCIDENT-DISCLOSURE-TICKET",
            disclosure_ticket,
        );
        let quarantine_id = operator_incident_private_quarantine_id(
            trigger_id,
            state_root,
            nullifier_root,
            &disclosure_ticket_root,
            opened_at_height,
        );
        Ok(Self {
            quarantine_id,
            trigger_id: trigger_id.to_string(),
            state_root: state_root.to_string(),
            nullifier_root: nullifier_root.to_string(),
            disclosure_ticket_root,
            opened_at_height,
            expires_at_height,
            status: QuarantineStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_private_state_quarantine",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "quarantine_id": self.quarantine_id,
            "trigger_id": self.trigger_id,
            "state_root": self.state_root,
            "nullifier_root": self.nullifier_root,
            "disclosure_ticket_root": self.disclosure_ticket_root,
            "opened_at_height": self.opened_at_height,
            "expires_at_height": self.expires_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("private state quarantine id", &self.quarantine_id)?;
        require_non_empty("private state quarantine trigger id", &self.trigger_id)?;
        require_non_empty("private state quarantine state root", &self.state_root)?;
        require_non_empty(
            "private state quarantine nullifier root",
            &self.nullifier_root,
        )?;
        require_non_empty(
            "private state quarantine disclosure ticket root",
            &self.disclosure_ticket_root,
        )?;
        if self.expires_at_height <= self.opened_at_height {
            return Err("private state quarantine expiry must be after open height".to_string());
        }
        let expected = operator_incident_private_quarantine_id(
            &self.trigger_id,
            &self.state_root,
            &self.nullifier_root,
            &self.disclosure_ticket_root,
            self.opened_at_height,
        );
        if self.quarantine_id != expected {
            return Err("private state quarantine id mismatch".to_string());
        }
        Ok(self.quarantine_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSettlementControl {
    pub control_id: String,
    pub trigger_id: String,
    pub mode: BridgeSettlementMode,
    pub previous_mode: BridgeSettlementMode,
    pub pause_reason_root: String,
    pub proof_gate_root: String,
    pub starts_at_height: u64,
    pub expires_at_height: u64,
    pub unpause_condition_root: String,
    pub status: ActionStatus,
}

impl BridgeSettlementControl {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        mode: BridgeSettlementMode,
        previous_mode: BridgeSettlementMode,
        pause_reason: &Value,
        proof_gate: &Value,
        starts_at_height: u64,
        expires_at_height: u64,
        unpause_condition: &Value,
    ) -> Result<Self> {
        require_non_empty("bridge settlement control trigger id", trigger_id)?;
        if expires_at_height <= starts_at_height {
            return Err("bridge settlement control expiry must be after start height".to_string());
        }
        let pause_reason_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-BRIDGE-PAUSE-REASON", pause_reason);
        let proof_gate_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-BRIDGE-PROOF-GATE", proof_gate);
        let unpause_condition_root = operator_incident_payload_root(
            "OPERATOR-INCIDENT-BRIDGE-UNPAUSE-CONDITION",
            unpause_condition,
        );
        let control_id = operator_incident_bridge_control_id(
            trigger_id,
            mode,
            previous_mode,
            &pause_reason_root,
            &proof_gate_root,
            starts_at_height,
        );
        Ok(Self {
            control_id,
            trigger_id: trigger_id.to_string(),
            mode,
            previous_mode,
            pause_reason_root,
            proof_gate_root,
            starts_at_height,
            expires_at_height,
            unpause_condition_root,
            status: ActionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_bridge_settlement_control",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "control_id": self.control_id,
            "trigger_id": self.trigger_id,
            "mode": self.mode.as_str(),
            "previous_mode": self.previous_mode.as_str(),
            "pause_reason_root": self.pause_reason_root,
            "proof_gate_root": self.proof_gate_root,
            "starts_at_height": self.starts_at_height,
            "expires_at_height": self.expires_at_height,
            "unpause_condition_root": self.unpause_condition_root,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("bridge settlement control id", &self.control_id)?;
        require_non_empty("bridge settlement control trigger id", &self.trigger_id)?;
        require_non_empty(
            "bridge settlement pause reason root",
            &self.pause_reason_root,
        )?;
        require_non_empty("bridge settlement proof gate root", &self.proof_gate_root)?;
        require_non_empty(
            "bridge settlement unpause condition root",
            &self.unpause_condition_root,
        )?;
        if self.expires_at_height <= self.starts_at_height {
            return Err("bridge settlement control expiry must be after start height".to_string());
        }
        let expected = operator_incident_bridge_control_id(
            &self.trigger_id,
            self.mode,
            self.previous_mode,
            &self.pause_reason_root,
            &self.proof_gate_root,
            self.starts_at_height,
        );
        if self.control_id != expected {
            return Err("bridge settlement control id mismatch".to_string());
        }
        Ok(self.control_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationReceipt {
    pub receipt_id: String,
    pub trigger_id: String,
    pub target: EscalationTarget,
    pub severity: Severity,
    pub message_root: String,
    pub channel_root: String,
    pub sent_at_height: u64,
    pub acknowledged_at_height: Option<u64>,
    pub status: ActionStatus,
}

impl EscalationReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        target: EscalationTarget,
        severity: Severity,
        message: &Value,
        channel: &Value,
        sent_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("escalation receipt trigger id", trigger_id)?;
        let message_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-ESCALATION-MESSAGE", message);
        let channel_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-ESCALATION-CHANNEL", channel);
        let receipt_id = operator_incident_escalation_receipt_id(
            trigger_id,
            target,
            severity,
            &message_root,
            &channel_root,
            sent_at_height,
        );
        Ok(Self {
            receipt_id,
            trigger_id: trigger_id.to_string(),
            target,
            severity,
            message_root,
            channel_root,
            sent_at_height,
            acknowledged_at_height: None,
            status: ActionStatus::Active,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_escalation_receipt",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "receipt_id": self.receipt_id,
            "trigger_id": self.trigger_id,
            "target": self.target.as_str(),
            "severity": self.severity.as_str(),
            "message_root": self.message_root,
            "channel_root": self.channel_root,
            "sent_at_height": self.sent_at_height,
            "acknowledged_at_height": self.acknowledged_at_height,
            "status": self.status.as_str(),
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("escalation receipt id", &self.receipt_id)?;
        require_non_empty("escalation receipt trigger id", &self.trigger_id)?;
        require_non_empty("escalation receipt message root", &self.message_root)?;
        require_non_empty("escalation receipt channel root", &self.channel_root)?;
        if let Some(ack_height) = self.acknowledged_at_height {
            if ack_height < self.sent_at_height {
                return Err("escalation receipt ack before sent height".to_string());
            }
        }
        let expected = operator_incident_escalation_receipt_id(
            &self.trigger_id,
            self.target,
            self.severity,
            &self.message_root,
            &self.channel_root,
            self.sent_at_height,
        );
        if self.receipt_id != expected {
            return Err("escalation receipt id mismatch".to_string());
        }
        Ok(self.receipt_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub trigger_id: String,
    pub evidence_kind: EvidenceKind,
    pub payload_root: String,
    pub collected_by_commitment: String,
    pub collected_at_height: u64,
    pub retention_until_height: u64,
}

impl EvidenceRecord {
    pub fn new(
        trigger_id: &str,
        evidence_kind: EvidenceKind,
        payload: &Value,
        collected_by: &str,
        collected_at_height: u64,
        retention_until_height: u64,
    ) -> Result<Self> {
        require_non_empty("evidence trigger id", trigger_id)?;
        require_non_empty("evidence collected by", collected_by)?;
        if retention_until_height <= collected_at_height {
            return Err("evidence retention must be after collection height".to_string());
        }
        let payload_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-EVIDENCE-PAYLOAD", payload);
        let collected_by_commitment = operator_incident_string_root(collected_by);
        let evidence_id = operator_incident_evidence_id(
            trigger_id,
            evidence_kind,
            &payload_root,
            &collected_by_commitment,
            collected_at_height,
        );
        Ok(Self {
            evidence_id,
            trigger_id: trigger_id.to_string(),
            evidence_kind,
            payload_root,
            collected_by_commitment,
            collected_at_height,
            retention_until_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_evidence_record",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "evidence_id": self.evidence_id,
            "trigger_id": self.trigger_id,
            "evidence_kind": self.evidence_kind.as_str(),
            "payload_root": self.payload_root,
            "collected_by_commitment": self.collected_by_commitment,
            "collected_at_height": self.collected_at_height,
            "retention_until_height": self.retention_until_height,
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("evidence id", &self.evidence_id)?;
        require_non_empty("evidence trigger id", &self.trigger_id)?;
        require_non_empty("evidence payload root", &self.payload_root)?;
        require_non_empty(
            "evidence collected by commitment",
            &self.collected_by_commitment,
        )?;
        if self.retention_until_height <= self.collected_at_height {
            return Err("evidence retention must be after collection height".to_string());
        }
        let expected = operator_incident_evidence_id(
            &self.trigger_id,
            self.evidence_kind,
            &self.payload_root,
            &self.collected_by_commitment,
            self.collected_at_height,
        );
        if self.evidence_id != expected {
            return Err("evidence id mismatch".to_string());
        }
        Ok(self.evidence_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostmortemEvidence {
    pub postmortem_id: String,
    pub trigger_id: String,
    pub incident_root: String,
    pub timeline_root: String,
    pub corrective_action_root: String,
    pub owner_commitment: String,
    pub due_height: u64,
    pub published_height: Option<u64>,
    pub evidence_root: String,
}

impl PostmortemEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        trigger_id: &str,
        incident: &Value,
        timeline: &Value,
        corrective_actions: &[String],
        owner_label: &str,
        due_height: u64,
        evidence_ids: &[String],
    ) -> Result<Self> {
        require_non_empty("postmortem trigger id", trigger_id)?;
        require_non_empty("postmortem owner label", owner_label)?;
        require_positive("postmortem due height", due_height)?;
        let incident_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-POSTMORTEM-INCIDENT", incident);
        let timeline_root =
            operator_incident_payload_root("OPERATOR-INCIDENT-POSTMORTEM-TIMELINE", timeline);
        let corrective_action_root = string_collection_root(
            "OPERATOR-INCIDENT-POSTMORTEM-CORRECTIVE-ACTIONS",
            corrective_actions,
        );
        let owner_commitment = operator_incident_string_root(owner_label);
        let evidence_root =
            string_collection_root("OPERATOR-INCIDENT-POSTMORTEM-EVIDENCE", evidence_ids);
        let postmortem_id = operator_incident_postmortem_id(
            trigger_id,
            &incident_root,
            &timeline_root,
            &corrective_action_root,
            &owner_commitment,
            due_height,
        );
        Ok(Self {
            postmortem_id,
            trigger_id: trigger_id.to_string(),
            incident_root,
            timeline_root,
            corrective_action_root,
            owner_commitment,
            due_height,
            published_height: None,
            evidence_root,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_postmortem_evidence",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "postmortem_id": self.postmortem_id,
            "trigger_id": self.trigger_id,
            "incident_root": self.incident_root,
            "timeline_root": self.timeline_root,
            "corrective_action_root": self.corrective_action_root,
            "owner_commitment": self.owner_commitment,
            "due_height": self.due_height,
            "published_height": self.published_height,
            "evidence_root": self.evidence_root,
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("postmortem id", &self.postmortem_id)?;
        require_non_empty("postmortem trigger id", &self.trigger_id)?;
        require_non_empty("postmortem incident root", &self.incident_root)?;
        require_non_empty("postmortem timeline root", &self.timeline_root)?;
        require_non_empty(
            "postmortem corrective action root",
            &self.corrective_action_root,
        )?;
        require_non_empty("postmortem owner commitment", &self.owner_commitment)?;
        require_non_empty("postmortem evidence root", &self.evidence_root)?;
        require_positive("postmortem due height", self.due_height)?;
        if let Some(published_height) = self.published_height {
            if published_height == 0 {
                return Err("postmortem published height must be positive".to_string());
            }
        }
        let expected = operator_incident_postmortem_id(
            &self.trigger_id,
            &self.incident_root,
            &self.timeline_root,
            &self.corrective_action_root,
            &self.owner_commitment,
            self.due_height,
        );
        if self.postmortem_id != expected {
            return Err("postmortem id mismatch".to_string());
        }
        Ok(self.postmortem_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIncidentRecord {
    pub record_id: String,
    pub trigger_id: String,
    pub domain: IncidentDomain,
    pub severity: Severity,
    pub record_root: String,
    pub state_root: String,
    pub published_at_height: u64,
}

impl PublicIncidentRecord {
    pub fn new(
        trigger_id: &str,
        domain: IncidentDomain,
        severity: Severity,
        record: &Value,
        state_root: &str,
        published_at_height: u64,
    ) -> Result<Self> {
        require_non_empty("public incident trigger id", trigger_id)?;
        require_non_empty("public incident state root", state_root)?;
        let record_root = operator_incident_payload_root("OPERATOR-INCIDENT-PUBLIC-RECORD", record);
        let record_id = operator_incident_public_record_id(
            trigger_id,
            domain,
            severity,
            &record_root,
            state_root,
            published_at_height,
        );
        Ok(Self {
            record_id,
            trigger_id: trigger_id.to_string(),
            domain,
            severity,
            record_root,
            state_root: state_root.to_string(),
            published_at_height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_public_record",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "record_id": self.record_id,
            "trigger_id": self.trigger_id,
            "domain": self.domain.as_str(),
            "severity": self.severity.as_str(),
            "record_root": self.record_root,
            "state_root": self.state_root,
            "published_at_height": self.published_at_height,
        })
    }

    pub fn validate(&self) -> Result<String> {
        require_non_empty("public incident record id", &self.record_id)?;
        require_non_empty("public incident trigger id", &self.trigger_id)?;
        require_non_empty("public incident record root", &self.record_root)?;
        require_non_empty("public incident state root", &self.state_root)?;
        let expected = operator_incident_public_record_id(
            &self.trigger_id,
            self.domain,
            self.severity,
            &self.record_root,
            &self.state_root,
            self.published_at_height,
        );
        if self.record_id != expected {
            return Err("public incident record id mismatch".to_string());
        }
        Ok(self.record_id.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub observation_root: String,
    pub trigger_root: String,
    pub runbook_root: String,
    pub action_root: String,
    pub freeze_root: String,
    pub low_fee_protection_root: String,
    pub pq_compromise_root: String,
    pub private_quarantine_root: String,
    pub bridge_control_root: String,
    pub escalation_root: String,
    pub evidence_root: String,
    pub postmortem_root: String,
    pub public_record_root: String,
    pub active_domain_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_roots",
            "config_root": self.config_root,
            "observation_root": self.observation_root,
            "trigger_root": self.trigger_root,
            "runbook_root": self.runbook_root,
            "action_root": self.action_root,
            "freeze_root": self.freeze_root,
            "low_fee_protection_root": self.low_fee_protection_root,
            "pq_compromise_root": self.pq_compromise_root,
            "private_quarantine_root": self.private_quarantine_root,
            "bridge_control_root": self.bridge_control_root,
            "escalation_root": self.escalation_root,
            "evidence_root": self.evidence_root,
            "postmortem_root": self.postmortem_root,
            "public_record_root": self.public_record_root,
            "active_domain_root": self.active_domain_root,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub observation_count: u64,
    pub trigger_count: u64,
    pub active_trigger_count: u64,
    pub critical_trigger_count: u64,
    pub runbook_dispatch_count: u64,
    pub active_action_count: u64,
    pub active_freeze_count: u64,
    pub low_fee_protection_count: u64,
    pub pq_compromise_count: u64,
    pub active_private_quarantine_count: u64,
    pub bridge_pause_count: u64,
    pub escalation_count: u64,
    pub evidence_count: u64,
    pub postmortem_count: u64,
    pub public_record_count: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_incident_counters",
            "observation_count": self.observation_count,
            "trigger_count": self.trigger_count,
            "active_trigger_count": self.active_trigger_count,
            "critical_trigger_count": self.critical_trigger_count,
            "runbook_dispatch_count": self.runbook_dispatch_count,
            "active_action_count": self.active_action_count,
            "active_freeze_count": self.active_freeze_count,
            "low_fee_protection_count": self.low_fee_protection_count,
            "pq_compromise_count": self.pq_compromise_count,
            "active_private_quarantine_count": self.active_private_quarantine_count,
            "bridge_pause_count": self.bridge_pause_count,
            "escalation_count": self.escalation_count,
            "evidence_count": self.evidence_count,
            "postmortem_count": self.postmortem_count,
            "public_record_count": self.public_record_count,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub bridge_mode: BridgeSettlementMode,
    pub config: Config,
    pub observations: Vec<IncidentObservation>,
    pub triggers: Vec<IncidentTrigger>,
    pub runbook_dispatches: Vec<RunbookDispatch>,
    pub protection_actions: Vec<ProtectionAction>,
    pub emergency_freezes: Vec<EmergencyFreeze>,
    pub low_fee_protections: Vec<LowFeeSubsidyProtection>,
    pub pq_compromise_actions: Vec<PqKeyCompromiseAction>,
    pub private_quarantines: Vec<PrivateStateQuarantine>,
    pub bridge_controls: Vec<BridgeSettlementControl>,
    pub escalation_receipts: Vec<EscalationReceipt>,
    pub evidence_records: Vec<EvidenceRecord>,
    pub postmortems: Vec<PostmortemEvidence>,
    pub public_records: Vec<PublicIncidentRecord>,
}

impl State {
    pub fn devnet() -> Result<Self> {
        let mut state = Self {
            height: 1,
            bridge_mode: BridgeSettlementMode::Normal,
            config: Config::devnet("devnet-operator"),
            observations: Vec::new(),
            triggers: Vec::new(),
            runbook_dispatches: Vec::new(),
            protection_actions: Vec::new(),
            emergency_freezes: Vec::new(),
            low_fee_protections: Vec::new(),
            pq_compromise_actions: Vec::new(),
            private_quarantines: Vec::new(),
            bridge_controls: Vec::new(),
            escalation_receipts: Vec::new(),
            evidence_records: Vec::new(),
            postmortems: Vec::new(),
            public_records: Vec::new(),
        };
        let observation = IncidentObservation::new(
            1,
            "devnet-observer",
            320,
            25,
            100,
            0,
            false,
            2,
            false,
            0,
            false,
            DEFAULT_LOW_FEE_MIN_BUDGET_UNITS * 2,
            DEFAULT_PQ_MIN_SECURITY_BITS,
            false,
            false,
            0,
            &json!({"fixture": "healthy_devnet"}),
        )?;
        state.observations.push(observation);
        state.validate()?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) -> Result<String> {
        if height < self.height {
            return Err("operator incident height cannot move backwards".to_string());
        }
        self.height = height;
        self.expire_stale_records();
        Ok(self.state_root())
    }

    pub fn ingest_observation(&mut self, observation: IncidentObservation) -> Result<Vec<String>> {
        observation.validate()?;
        if observation.height > self.height {
            self.height = observation.height;
        }
        self.observations.push(observation.clone());
        let trigger_ids = self.triggers_from_observation(&observation)?;
        self.validate()?;
        Ok(trigger_ids)
    }

    pub fn open_trigger(&mut self, mut trigger: IncidentTrigger) -> Result<String> {
        trigger.validate()?;
        if trigger.status == IncidentStatus::Expired {
            return Err("operator incident cannot open expired trigger".to_string());
        }
        let trigger_id = trigger.trigger_id.clone();
        if self
            .triggers
            .iter()
            .any(|existing| existing.trigger_id == trigger_id)
        {
            return Ok(trigger_id);
        }
        trigger.status = IncidentStatus::Open;
        self.dispatch_automation_for_trigger(&trigger)?;
        self.triggers.push(trigger);
        Ok(trigger_id)
    }

    pub fn acknowledge_trigger(&mut self, trigger_id: &str) -> Result<String> {
        let trigger = self
            .triggers
            .iter_mut()
            .find(|candidate| candidate.trigger_id == trigger_id)
            .ok_or_else(|| format!("unknown trigger {trigger_id}"))?;
        if !trigger.status.active() {
            return Err("only active triggers can be acknowledged".to_string());
        }
        trigger.status = IncidentStatus::Acknowledged;
        Ok(self.state_root())
    }

    pub fn resolve_trigger(
        &mut self,
        trigger_id: &str,
        postmortem: PostmortemEvidence,
    ) -> Result<String> {
        postmortem.validate()?;
        if postmortem.trigger_id != trigger_id {
            return Err("postmortem trigger mismatch".to_string());
        }
        let trigger = self
            .triggers
            .iter_mut()
            .find(|candidate| candidate.trigger_id == trigger_id)
            .ok_or_else(|| format!("unknown trigger {trigger_id}"))?;
        trigger.status = IncidentStatus::Resolved;
        for action in &mut self.protection_actions {
            if action.trigger_id == trigger_id && action.status.active() {
                action.status = ActionStatus::Completed;
            }
        }
        for freeze in &mut self.emergency_freezes {
            if freeze.trigger_id == trigger_id && freeze.status.active() {
                freeze.status = ActionStatus::Completed;
            }
        }
        for control in &mut self.bridge_controls {
            if control.trigger_id == trigger_id && control.status.active() {
                control.status = ActionStatus::Completed;
            }
        }
        self.bridge_mode = self.current_bridge_mode();
        self.postmortems.push(postmortem);
        self.validate()
    }

    pub fn unpause_bridge_settlement(
        &mut self,
        trigger_id: &str,
        unpause_evidence: &Value,
    ) -> Result<String> {
        require_non_empty("bridge unpause trigger id", trigger_id)?;
        let latest_mode = self.current_bridge_mode();
        let control = BridgeSettlementControl::new(
            trigger_id,
            BridgeSettlementMode::Normal,
            latest_mode,
            &json!({"operator_action": "unpause_bridge_settlement"}),
            unpause_evidence,
            self.height,
            self.height + self.config.bridge_pause_ttl_blocks,
            &json!({"mode": "normal", "evidence_root": operator_incident_payload_root("OPERATOR-INCIDENT-BRIDGE-UNPAUSE-EVIDENCE", unpause_evidence)}),
        )?;
        self.bridge_controls.push(control);
        self.bridge_mode = BridgeSettlementMode::Normal;
        let action = ProtectionAction::new(
            trigger_id,
            ActionKind::UnpauseBridgeSettlement,
            IncidentDomain::BridgeSettlement,
            &json!({"bridge_mode": "normal"}),
            unpause_evidence,
            self.height,
            self.height + self.config.bridge_pause_ttl_blocks,
            ActionStatus::Completed,
        )?;
        self.protection_actions.push(action);
        self.validate()
    }

    pub fn add_evidence(&mut self, evidence: EvidenceRecord) -> Result<String> {
        evidence.validate()?;
        if !self.trigger_ids().contains(&evidence.trigger_id) {
            return Err(format!(
                "evidence references unknown trigger {}",
                evidence.trigger_id
            ));
        }
        self.evidence_records.push(evidence);
        self.validate()
    }

    pub fn publish_public_record(&mut self, trigger_id: &str, record: &Value) -> Result<String> {
        let trigger = self
            .triggers
            .iter()
            .find(|candidate| candidate.trigger_id == trigger_id)
            .ok_or_else(|| format!("unknown trigger {trigger_id}"))?;
        let public_record = PublicIncidentRecord::new(
            trigger_id,
            trigger.domain,
            trigger.severity,
            record,
            &self.state_root(),
            self.height,
        )?;
        let record_id = public_record.record_id.clone();
        self.public_records.push(public_record);
        self.validate()?;
        Ok(record_id)
    }

    pub fn roots(&self) -> Roots {
        Roots {
            config_root: self.config.config_root(),
            observation_root: observation_collection_root(&self.observations),
            trigger_root: trigger_collection_root(&self.triggers),
            runbook_root: runbook_collection_root(&self.runbook_dispatches),
            action_root: action_collection_root(&self.protection_actions),
            freeze_root: freeze_collection_root(&self.emergency_freezes),
            low_fee_protection_root: low_fee_collection_root(&self.low_fee_protections),
            pq_compromise_root: pq_compromise_collection_root(&self.pq_compromise_actions),
            private_quarantine_root: private_quarantine_collection_root(&self.private_quarantines),
            bridge_control_root: bridge_control_collection_root(&self.bridge_controls),
            escalation_root: escalation_collection_root(&self.escalation_receipts),
            evidence_root: evidence_collection_root(&self.evidence_records),
            postmortem_root: postmortem_collection_root(&self.postmortems),
            public_record_root: public_record_collection_root(&self.public_records),
            active_domain_root: operator_incident_payload_root(
                "OPERATOR-INCIDENT-ACTIVE-DOMAINS",
                &json!(self.active_domain_map()),
            ),
        }
    }

    pub fn counters(&self) -> Counters {
        Counters {
            observation_count: self.observations.len() as u64,
            trigger_count: self.triggers.len() as u64,
            active_trigger_count: self.active_triggers().len() as u64,
            critical_trigger_count: self
                .triggers
                .iter()
                .filter(|trigger| trigger.severity == Severity::Critical)
                .count() as u64,
            runbook_dispatch_count: self.runbook_dispatches.len() as u64,
            active_action_count: self
                .protection_actions
                .iter()
                .filter(|action| action.status.active())
                .count() as u64,
            active_freeze_count: self
                .emergency_freezes
                .iter()
                .filter(|freeze| freeze.active())
                .count() as u64,
            low_fee_protection_count: self.low_fee_protections.len() as u64,
            pq_compromise_count: self.pq_compromise_actions.len() as u64,
            active_private_quarantine_count: self
                .private_quarantines
                .iter()
                .filter(|quarantine| quarantine.status.active())
                .count() as u64,
            bridge_pause_count: self
                .bridge_controls
                .iter()
                .filter(|control| control.mode.paused())
                .count() as u64,
            escalation_count: self.escalation_receipts.len() as u64,
            evidence_count: self.evidence_records.len() as u64,
            postmortem_count: self.postmortems.len() as u64,
            public_record_count: self.public_records.len() as u64,
        }
    }

    pub fn active_triggers(&self) -> Vec<&IncidentTrigger> {
        self.triggers
            .iter()
            .filter(|trigger| trigger.status.active())
            .collect()
    }

    pub fn active_domain_map(&self) -> BTreeMap<String, u64> {
        let mut domains = BTreeMap::new();
        for trigger in self.active_triggers() {
            let key = trigger.domain.as_str().to_string();
            let count = domains.get(&key).copied().unwrap_or(0) + 1;
            domains.insert(key, count);
        }
        domains
    }

    pub fn public_record_without_root(&self) -> Value {
        let roots = self.roots();
        let counters = self.counters();
        json!({
            "kind": "operator_incident_automation_state",
            "protocol_version": OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION,
            "chain_id": CHAIN_ID,
            "height": self.height,
            "bridge_mode": self.bridge_mode.as_str(),
            "config": self.config.public_record(),
            "roots": roots.public_record(),
            "counters": counters.public_record(),
            "active_domains": self.active_domain_map(),
        })
    }

    pub fn state_root(&self) -> String {
        operator_incident_automation_state_root_from_record(&self.public_record_without_root())
    }

    pub fn public_record(&self) -> Value {
        with_root_field(
            self.public_record_without_root(),
            "operator_incident_automation_state_root",
            self.state_root(),
        )
    }

    pub fn validate(&self) -> Result<String> {
        self.config.validate()?;
        let observation_ids = self
            .observations
            .iter()
            .map(IncidentObservation::validate)
            .collect::<Result<Vec<_>>>()?;
        ensure_unique_strings(&observation_ids, "observation id")?;

        let trigger_ids = self
            .triggers
            .iter()
            .map(IncidentTrigger::validate)
            .collect::<Result<Vec<_>>>()?;
        ensure_unique_strings(&trigger_ids, "trigger id")?;
        let trigger_set = trigger_ids.iter().cloned().collect::<BTreeSet<_>>();

        self.validate_records(&trigger_set)?;
        Ok(self.state_root())
    }

    fn triggers_from_observation(
        &mut self,
        observation: &IncidentObservation,
    ) -> Result<Vec<String>> {
        let mut trigger_ids = Vec::new();
        for trigger in self.derive_triggers(observation)? {
            let trigger_id = trigger.trigger_id.clone();
            self.open_trigger(trigger)?;
            trigger_ids.push(trigger_id);
        }
        Ok(trigger_ids)
    }

    fn derive_triggers(&self, observation: &IncidentObservation) -> Result<Vec<IncidentTrigger>> {
        let mut triggers = Vec::new();
        let expires_at_height = observation.height + self.config.trigger_ttl_blocks;
        if observation.latency_ms >= self.config.latency_trigger_ms {
            triggers.push(self.derived_trigger(
                TriggerKind::LatencySloBreach,
                observation.latency_ms,
                self.config.latency_trigger_ms,
                observation,
                expires_at_height,
            )?);
        }
        if observation.fee_spike_bps >= self.config.fee_spike_bps {
            triggers.push(self.derived_trigger(
                TriggerKind::FeeSpike,
                observation.fee_spike_bps,
                self.config.fee_spike_bps,
                observation,
                expires_at_height,
            )?);
        }
        if observation.low_fee_budget_units < self.config.low_fee_min_budget_units {
            triggers.push(self.derived_trigger(
                TriggerKind::LowFeeBudgetDepleted,
                observation.low_fee_budget_units,
                self.config.low_fee_min_budget_units,
                observation,
                expires_at_height,
            )?);
        }
        if observation.privacy_risk_bps >= self.config.privacy_risk_bps {
            triggers.push(self.derived_trigger(
                TriggerKind::PrivacyLeakSignal,
                observation.privacy_risk_bps,
                self.config.privacy_risk_bps,
                observation,
                expires_at_height,
            )?);
        }
        if observation.monero_reorg_depth >= self.config.monero_reorg_depth {
            triggers.push(self.derived_trigger(
                TriggerKind::MoneroReorg,
                observation.monero_reorg_depth,
                self.config.monero_reorg_depth,
                observation,
                expires_at_height,
            )?);
        }
        if observation.monero_daemon_divergence {
            triggers.push(self.derived_trigger(
                TriggerKind::MoneroDaemonDivergence,
                1,
                1,
                observation,
                expires_at_height,
            )?);
        }
        if observation.prover_backlog_jobs >= self.config.prover_backlog_jobs {
            triggers.push(self.derived_trigger(
                TriggerKind::ProverBacklog,
                observation.prover_backlog_jobs,
                self.config.prover_backlog_jobs,
                observation,
                expires_at_height,
            )?);
        }
        if observation.invalid_proof_seen {
            triggers.push(self.derived_trigger(
                TriggerKind::ProverProofInvalid,
                1,
                1,
                observation,
                expires_at_height,
            )?);
        }
        if observation.da_failure_bps >= self.config.da_failure_bps {
            triggers.push(self.derived_trigger(
                TriggerKind::DataAvailabilitySamplingFailure,
                observation.da_failure_bps,
                self.config.da_failure_bps,
                observation,
                expires_at_height,
            )?);
        }
        if observation.da_quorum_loss {
            triggers.push(self.derived_trigger(
                TriggerKind::DataAvailabilityQuorumLoss,
                1,
                1,
                observation,
                expires_at_height,
            )?);
        }
        if observation.pq_compromise_signal
            || observation.pq_security_bits < self.config.pq_min_security_bits
        {
            triggers.push(self.derived_trigger(
                TriggerKind::PqKeyCompromise,
                observation.pq_security_bits as u64,
                self.config.pq_min_security_bits as u64,
                observation,
                expires_at_height,
            )?);
        }
        if observation.private_state_inconsistency {
            triggers.push(self.derived_trigger(
                TriggerKind::PrivateStateInconsistency,
                1,
                1,
                observation,
                expires_at_height,
            )?);
        }
        if observation.bridge_settlement_lag_blocks >= self.config.bridge_pause_ttl_blocks {
            triggers.push(self.derived_trigger(
                TriggerKind::BridgeSettlementStalled,
                observation.bridge_settlement_lag_blocks,
                self.config.bridge_pause_ttl_blocks,
                observation,
                expires_at_height,
            )?);
        }
        Ok(triggers)
    }

    fn derived_trigger(
        &self,
        trigger_kind: TriggerKind,
        observed_value: u64,
        threshold_value: u64,
        observation: &IncidentObservation,
        expires_at_height: u64,
    ) -> Result<IncidentTrigger> {
        let severity = severity_for_trigger(trigger_kind, observed_value, threshold_value);
        IncidentTrigger::new(
            trigger_kind,
            severity,
            severity.floor_bps(),
            observed_value,
            threshold_value,
            &observation.public_record(),
            &observation.source_label,
            observation.height,
            expires_at_height,
        )
    }

    fn dispatch_automation_for_trigger(&mut self, trigger: &IncidentTrigger) -> Result<()> {
        let runbook_kind = runbook_for_trigger(trigger.trigger_kind);
        let mut action_ids = Vec::new();
        let expires_at = self.height + self.config.freeze_ttl_blocks;
        let target = json!({"trigger_id": trigger.trigger_id, "domain": trigger.domain.as_str()});
        let base_parameters = json!({
            "severity": trigger.severity.as_str(),
            "severity_bps": trigger.severity_bps,
            "observed_value": trigger.observed_value,
            "threshold_value": trigger.threshold_value,
        });

        let page_action = ProtectionAction::new(
            &trigger.trigger_id,
            ActionKind::PageOncall,
            trigger.domain,
            &target,
            &base_parameters,
            self.height,
            expires_at,
            ActionStatus::Active,
        )?;
        action_ids.push(page_action.action_id.clone());
        self.protection_actions.push(page_action);

        if trigger.severity.freezes() && self.config.auto_freeze_enabled {
            let scope = freeze_scope_for_trigger(trigger.trigger_kind);
            let freeze = EmergencyFreeze::new(
                &trigger.trigger_id,
                scope,
                &base_parameters,
                self.height,
                self.height + self.config.freeze_ttl_blocks,
                true,
            )?;
            self.emergency_freezes.push(freeze);
        }

        match trigger.trigger_kind {
            TriggerKind::LowFeeBudgetDepleted | TriggerKind::FeeSpike => {
                if self.config.auto_low_fee_protection_enabled {
                    self.activate_low_fee_protection(trigger, &mut action_ids)?;
                }
            }
            TriggerKind::PqKeyCompromise => {
                self.activate_pq_compromise(trigger, &mut action_ids)?;
            }
            TriggerKind::PrivateStateInconsistency | TriggerKind::PrivacyLeakSignal => {
                self.activate_private_quarantine(trigger, &mut action_ids)?;
            }
            TriggerKind::BridgeSettlementStalled
            | TriggerKind::MoneroReorg
            | TriggerKind::MoneroDaemonDivergence => {
                if self.config.auto_bridge_pause_enabled {
                    self.pause_bridge_settlement(trigger, &mut action_ids)?;
                }
            }
            TriggerKind::DataAvailabilitySamplingFailure
            | TriggerKind::DataAvailabilityQuorumLoss => {
                let action = ProtectionAction::new(
                    &trigger.trigger_id,
                    ActionKind::QuarantineDaBatch,
                    IncidentDomain::DataAvailability,
                    &target,
                    &base_parameters,
                    self.height,
                    self.height + self.config.quarantine_ttl_blocks,
                    ActionStatus::Active,
                )?;
                action_ids.push(action.action_id.clone());
                self.protection_actions.push(action);
            }
            TriggerKind::ProverBacklog | TriggerKind::ProverProofInvalid => {
                let kind = if trigger.trigger_kind == TriggerKind::ProverProofInvalid {
                    ActionKind::RequireRecursiveProofReview
                } else {
                    ActionKind::IncreaseProverCapacity
                };
                let action = ProtectionAction::new(
                    &trigger.trigger_id,
                    kind,
                    IncidentDomain::Prover,
                    &target,
                    &base_parameters,
                    self.height,
                    self.height + self.config.freeze_ttl_blocks,
                    ActionStatus::Active,
                )?;
                action_ids.push(action.action_id.clone());
                self.protection_actions.push(action);
            }
            TriggerKind::LatencySloBreach => {}
        }

        let dispatch = RunbookDispatch::new(
            &trigger.trigger_id,
            runbook_kind,
            &json!({"runbook": runbook_kind.as_str(), "trigger_kind": trigger.trigger_kind.as_str()}),
            &action_ids,
            &self.config.operator_label,
            self.height,
            self.height + self.config.runbook_ack_blocks,
        )?;
        self.runbook_dispatches.push(dispatch);

        let escalation = EscalationReceipt::new(
            &trigger.trigger_id,
            escalation_target_for_trigger(trigger.trigger_kind),
            trigger.severity,
            &json!({"trigger_id": trigger.trigger_id, "runbook": runbook_kind.as_str()}),
            &json!({"channel": "operator_incident_automation"}),
            self.height,
        )?;
        self.escalation_receipts.push(escalation);
        Ok(())
    }

    fn activate_low_fee_protection(
        &mut self,
        trigger: &IncidentTrigger,
        action_ids: &mut Vec<String>,
    ) -> Result<()> {
        let protection = LowFeeSubsidyProtection::new(
            &trigger.trigger_id,
            &json!({"lane": "low_fee_emergency_lane"}),
            &json!({"sponsor": self.config.operator_label}),
            self.config.low_fee_min_budget_units,
            self.config.low_fee_min_budget_units.saturating_mul(2),
            5_000,
            self.height,
            self.height + self.config.freeze_ttl_blocks,
        )?;
        self.low_fee_protections.push(protection);
        let action = ProtectionAction::new(
            &trigger.trigger_id,
            ActionKind::ActivateLowFeeSubsidy,
            IncidentDomain::LowFeeLane,
            &json!({"lane": "low_fee_emergency_lane"}),
            &json!({"budget_floor_units": self.config.low_fee_min_budget_units}),
            self.height,
            self.height + self.config.freeze_ttl_blocks,
            ActionStatus::Active,
        )?;
        action_ids.push(action.action_id.clone());
        self.protection_actions.push(action);
        Ok(())
    }

    fn activate_pq_compromise(
        &mut self,
        trigger: &IncidentTrigger,
        action_ids: &mut Vec<String>,
    ) -> Result<()> {
        let compromise = PqKeyCompromiseAction::new(
            &trigger.trigger_id,
            &json!({"compromised_key": "redacted"}),
            &json!({"replacement_key": "pending_ceremony"}),
            &[trigger.trigger_id.clone()],
            self.config.pq_min_security_bits.saturating_sub(64),
            self.config.pq_min_security_bits,
            self.height,
            &json!({"governance_ticket": "pq_key_compromise"}),
        )?;
        self.pq_compromise_actions.push(compromise);
        let action = ProtectionAction::new(
            &trigger.trigger_id,
            ActionKind::RotatePqKeys,
            IncidentDomain::PostQuantum,
            &json!({"key_scope": "operator_and_bridge"}),
            &json!({"min_security_bits": self.config.pq_min_security_bits}),
            self.height,
            self.height + self.config.quarantine_ttl_blocks,
            ActionStatus::Active,
        )?;
        action_ids.push(action.action_id.clone());
        self.protection_actions.push(action);
        Ok(())
    }

    fn activate_private_quarantine(
        &mut self,
        trigger: &IncidentTrigger,
        action_ids: &mut Vec<String>,
    ) -> Result<()> {
        let state_root = operator_incident_payload_root(
            "OPERATOR-INCIDENT-PRIVATE-STATE",
            &trigger.public_record(),
        );
        let nullifier_root = operator_incident_payload_root(
            "OPERATOR-INCIDENT-PRIVATE-NULLIFIERS",
            &trigger.public_record(),
        );
        let quarantine = PrivateStateQuarantine::new(
            &trigger.trigger_id,
            &state_root,
            &nullifier_root,
            &json!({"scope": "private_state_review"}),
            self.height,
            self.height + self.config.quarantine_ttl_blocks,
        )?;
        self.private_quarantines.push(quarantine);
        let action = ProtectionAction::new(
            &trigger.trigger_id,
            ActionKind::QuarantinePrivateState,
            IncidentDomain::PrivateState,
            &json!({"state_root": state_root, "nullifier_root": nullifier_root}),
            &json!({"ttl_blocks": self.config.quarantine_ttl_blocks}),
            self.height,
            self.height + self.config.quarantine_ttl_blocks,
            ActionStatus::Active,
        )?;
        action_ids.push(action.action_id.clone());
        self.protection_actions.push(action);
        Ok(())
    }

    fn pause_bridge_settlement(
        &mut self,
        trigger: &IncidentTrigger,
        action_ids: &mut Vec<String>,
    ) -> Result<()> {
        let previous_mode = self.bridge_mode;
        let next_mode = if trigger.severity == Severity::Critical {
            BridgeSettlementMode::EmergencyExitOnly
        } else {
            BridgeSettlementMode::Paused
        };
        let control = BridgeSettlementControl::new(
            &trigger.trigger_id,
            next_mode,
            previous_mode,
            &trigger.public_record(),
            &json!({"required": "monero_finality_and_recursive_validity"}),
            self.height,
            self.height + self.config.bridge_pause_ttl_blocks,
            &json!({"condition": "fresh_finality_and_reserve_evidence"}),
        )?;
        self.bridge_controls.push(control);
        self.bridge_mode = next_mode;
        let action = ProtectionAction::new(
            &trigger.trigger_id,
            ActionKind::PauseBridgeSettlement,
            IncidentDomain::BridgeSettlement,
            &json!({"previous_mode": previous_mode.as_str(), "next_mode": next_mode.as_str()}),
            &json!({"ttl_blocks": self.config.bridge_pause_ttl_blocks}),
            self.height,
            self.height + self.config.bridge_pause_ttl_blocks,
            ActionStatus::Active,
        )?;
        action_ids.push(action.action_id.clone());
        self.protection_actions.push(action);
        Ok(())
    }

    fn expire_stale_records(&mut self) {
        for trigger in &mut self.triggers {
            if trigger.status.active() && trigger.expires_at_height <= self.height {
                trigger.status = IncidentStatus::Expired;
            }
        }
        for action in &mut self.protection_actions {
            if action.status.active() && action.expires_at_height <= self.height {
                action.status = ActionStatus::Expired;
            }
        }
        for freeze in &mut self.emergency_freezes {
            if freeze.status.active() && freeze.expires_at_height <= self.height {
                freeze.status = ActionStatus::Expired;
            }
        }
        for quarantine in &mut self.private_quarantines {
            if quarantine.status.active() && quarantine.expires_at_height <= self.height {
                quarantine.status = QuarantineStatus::Expired;
            }
        }
        for control in &mut self.bridge_controls {
            if control.status.active() && control.expires_at_height <= self.height {
                control.status = ActionStatus::Expired;
            }
        }
        self.bridge_mode = self.current_bridge_mode();
    }

    fn current_bridge_mode(&self) -> BridgeSettlementMode {
        self.bridge_controls
            .iter()
            .filter(|control| control.status.active())
            .max_by_key(|control| control.starts_at_height)
            .map(|control| control.mode)
            .unwrap_or(BridgeSettlementMode::Normal)
    }

    fn trigger_ids(&self) -> BTreeSet<String> {
        self.triggers
            .iter()
            .map(|trigger| trigger.trigger_id.clone())
            .collect()
    }

    fn validate_records(&self, trigger_set: &BTreeSet<String>) -> Result<()> {
        validate_child_records(
            &self.runbook_dispatches,
            trigger_set,
            "runbook dispatch",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.protection_actions,
            trigger_set,
            "protection action",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.emergency_freezes,
            trigger_set,
            "emergency freeze",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.low_fee_protections,
            trigger_set,
            "low fee protection",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.pq_compromise_actions,
            trigger_set,
            "pq compromise",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.private_quarantines,
            trigger_set,
            "private quarantine",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.bridge_controls,
            trigger_set,
            "bridge control",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.escalation_receipts,
            trigger_set,
            "escalation receipt",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.evidence_records,
            trigger_set,
            "evidence record",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.postmortems,
            trigger_set,
            "postmortem",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        validate_child_records(
            &self.public_records,
            trigger_set,
            "public record",
            |record| record.validate(),
            |record| &record.trigger_id,
        )?;
        Ok(())
    }
}

pub fn operator_incident_automation_state_root_from_record(record: &Value) -> String {
    operator_incident_payload_root("OPERATOR-INCIDENT-STATE", record)
}

pub fn operator_incident_payload_root(domain: &str, value: &Value) -> String {
    domain_hash(
        domain,
        &[
            HashPart::Str(OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Json(value),
        ],
        32,
    )
}

pub fn operator_incident_string_root(value: &str) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-STRING",
        &[
            HashPart::Str(OPERATOR_INCIDENT_AUTOMATION_PROTOCOL_VERSION),
            HashPart::Str(CHAIN_ID),
            HashPart::Str(value),
        ],
        32,
    )
}

pub fn operator_incident_observation_id(
    height: u64,
    source_label: &str,
    latency_ms: u64,
    fee_spike_bps: u64,
    privacy_risk_bps: u64,
    monero_reorg_depth: u64,
    prover_backlog_jobs: u64,
    da_failure_bps: u64,
    low_fee_budget_units: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-OBSERVATION-ID",
        &[
            HashPart::Int(height as i128),
            HashPart::Str(source_label),
            HashPart::Int(latency_ms as i128),
            HashPart::Int(fee_spike_bps as i128),
            HashPart::Int(privacy_risk_bps as i128),
            HashPart::Int(monero_reorg_depth as i128),
            HashPart::Int(prover_backlog_jobs as i128),
            HashPart::Int(da_failure_bps as i128),
            HashPart::Int(low_fee_budget_units as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

pub fn operator_incident_trigger_id(
    trigger_kind: TriggerKind,
    severity: Severity,
    observed_value: u64,
    threshold_value: u64,
    evidence_root: &str,
    source_label: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-TRIGGER-ID",
        &[
            HashPart::Str(trigger_kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Int(observed_value as i128),
            HashPart::Int(threshold_value as i128),
            HashPart::Str(evidence_root),
            HashPart::Str(source_label),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_action_id(
    trigger_id: &str,
    action_kind: ActionKind,
    domain: IncidentDomain,
    target_root: &str,
    parameter_root: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-ACTION-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(domain.as_str()),
            HashPart::Str(target_root),
            HashPart::Str(parameter_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_runbook_dispatch_id(
    trigger_id: &str,
    runbook_kind: RunbookKind,
    runbook_root: &str,
    action_root: &str,
    operator_commitment: &str,
    dispatched_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-RUNBOOK-DISPATCH-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(runbook_kind.as_str()),
            HashPart::Str(runbook_root),
            HashPart::Str(action_root),
            HashPart::Str(operator_commitment),
            HashPart::Int(dispatched_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_freeze_id(
    trigger_id: &str,
    scope: FreezeScope,
    reason_root: &str,
    starts_at_height: u64,
    allow_emergency_exits: bool,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-FREEZE-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(scope.as_str()),
            HashPart::Str(reason_root),
            HashPart::Int(starts_at_height as i128),
            HashPart::Str(if allow_emergency_exits {
                "true"
            } else {
                "false"
            }),
        ],
        32,
    )
}

pub fn operator_incident_low_fee_protection_id(
    trigger_id: &str,
    lane_root: &str,
    sponsor_root: &str,
    budget_floor_units: u64,
    subsidy_units: u64,
    exposure_cap_bps: u64,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-LOW-FEE-PROTECTION-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(lane_root),
            HashPart::Str(sponsor_root),
            HashPart::Int(budget_floor_units as i128),
            HashPart::Int(subsidy_units as i128),
            HashPart::Int(exposure_cap_bps as i128),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_pq_compromise_id(
    trigger_id: &str,
    compromised_key_root: &str,
    replacement_key_root: &str,
    revoked_session_root: &str,
    rotation_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-PQ-COMPROMISE-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(compromised_key_root),
            HashPart::Str(replacement_key_root),
            HashPart::Str(revoked_session_root),
            HashPart::Int(rotation_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_private_quarantine_id(
    trigger_id: &str,
    state_root: &str,
    nullifier_root: &str,
    disclosure_ticket_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-PRIVATE-QUARANTINE-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(state_root),
            HashPart::Str(nullifier_root),
            HashPart::Str(disclosure_ticket_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_bridge_control_id(
    trigger_id: &str,
    mode: BridgeSettlementMode,
    previous_mode: BridgeSettlementMode,
    pause_reason_root: &str,
    proof_gate_root: &str,
    starts_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-BRIDGE-CONTROL-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(mode.as_str()),
            HashPart::Str(previous_mode.as_str()),
            HashPart::Str(pause_reason_root),
            HashPart::Str(proof_gate_root),
            HashPart::Int(starts_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_escalation_receipt_id(
    trigger_id: &str,
    target: EscalationTarget,
    severity: Severity,
    message_root: &str,
    channel_root: &str,
    sent_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-ESCALATION-RECEIPT-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(target.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(message_root),
            HashPart::Str(channel_root),
            HashPart::Int(sent_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_evidence_id(
    trigger_id: &str,
    evidence_kind: EvidenceKind,
    payload_root: &str,
    collected_by_commitment: &str,
    collected_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-EVIDENCE-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(evidence_kind.as_str()),
            HashPart::Str(payload_root),
            HashPart::Str(collected_by_commitment),
            HashPart::Int(collected_at_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_postmortem_id(
    trigger_id: &str,
    incident_root: &str,
    timeline_root: &str,
    corrective_action_root: &str,
    owner_commitment: &str,
    due_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-POSTMORTEM-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(incident_root),
            HashPart::Str(timeline_root),
            HashPart::Str(corrective_action_root),
            HashPart::Str(owner_commitment),
            HashPart::Int(due_height as i128),
        ],
        32,
    )
}

pub fn operator_incident_public_record_id(
    trigger_id: &str,
    domain: IncidentDomain,
    severity: Severity,
    record_root: &str,
    state_root: &str,
    published_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-INCIDENT-PUBLIC-RECORD-ID",
        &[
            HashPart::Str(trigger_id),
            HashPart::Str(domain.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(record_root),
            HashPart::Str(state_root),
            HashPart::Int(published_at_height as i128),
        ],
        32,
    )
}

pub fn observation_collection_root(records: &[IncidentObservation]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-OBSERVATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.observation_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn trigger_collection_root(records: &[IncidentTrigger]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-TRIGGER-COLLECTION",
        records
            .iter()
            .map(|record| (record.trigger_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn runbook_collection_root(records: &[RunbookDispatch]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-RUNBOOK-COLLECTION",
        records
            .iter()
            .map(|record| (record.dispatch_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn action_collection_root(records: &[ProtectionAction]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-ACTION-COLLECTION",
        records
            .iter()
            .map(|record| (record.action_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn freeze_collection_root(records: &[EmergencyFreeze]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-FREEZE-COLLECTION",
        records
            .iter()
            .map(|record| (record.freeze_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn low_fee_collection_root(records: &[LowFeeSubsidyProtection]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-LOW-FEE-COLLECTION",
        records
            .iter()
            .map(|record| (record.protection_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn pq_compromise_collection_root(records: &[PqKeyCompromiseAction]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-PQ-COMPROMISE-COLLECTION",
        records
            .iter()
            .map(|record| (record.compromise_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn private_quarantine_collection_root(records: &[PrivateStateQuarantine]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-PRIVATE-QUARANTINE-COLLECTION",
        records
            .iter()
            .map(|record| (record.quarantine_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn bridge_control_collection_root(records: &[BridgeSettlementControl]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-BRIDGE-CONTROL-COLLECTION",
        records
            .iter()
            .map(|record| (record.control_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn escalation_collection_root(records: &[EscalationReceipt]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-ESCALATION-COLLECTION",
        records
            .iter()
            .map(|record| (record.receipt_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn evidence_collection_root(records: &[EvidenceRecord]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-EVIDENCE-COLLECTION",
        records
            .iter()
            .map(|record| (record.evidence_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn postmortem_collection_root(records: &[PostmortemEvidence]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-POSTMORTEM-COLLECTION",
        records
            .iter()
            .map(|record| (record.postmortem_id.clone(), record.public_record()))
            .collect(),
    )
}

pub fn public_record_collection_root(records: &[PublicIncidentRecord]) -> String {
    keyed_value_root(
        "OPERATOR-INCIDENT-PUBLIC-RECORD-COLLECTION",
        records
            .iter()
            .map(|record| (record.record_id.clone(), record.public_record()))
            .collect(),
    )
}

fn runbook_for_trigger(trigger_kind: TriggerKind) -> RunbookKind {
    match trigger_kind {
        TriggerKind::LatencySloBreach => RunbookKind::LatencyRecovery,
        TriggerKind::FeeSpike => RunbookKind::FeeStabilization,
        TriggerKind::LowFeeBudgetDepleted => RunbookKind::LowFeeSubsidyProtection,
        TriggerKind::PrivacyLeakSignal => RunbookKind::PrivacyContainment,
        TriggerKind::MoneroReorg | TriggerKind::MoneroDaemonDivergence => {
            RunbookKind::MoneroBridgeSafety
        }
        TriggerKind::ProverBacklog | TriggerKind::ProverProofInvalid => {
            RunbookKind::ProverCapacityFailover
        }
        TriggerKind::DataAvailabilitySamplingFailure | TriggerKind::DataAvailabilityQuorumLoss => {
            RunbookKind::DataAvailabilityRecovery
        }
        TriggerKind::PqKeyCompromise => RunbookKind::PostQuantumKeyCompromise,
        TriggerKind::PrivateStateInconsistency => RunbookKind::PrivateStateQuarantine,
        TriggerKind::BridgeSettlementStalled => RunbookKind::BridgeSettlementPause,
    }
}

fn freeze_scope_for_trigger(trigger_kind: TriggerKind) -> FreezeScope {
    match trigger_kind {
        TriggerKind::LatencySloBreach => FreezeScope::SequencerAdmission,
        TriggerKind::FeeSpike | TriggerKind::LowFeeBudgetDepleted => {
            FreezeScope::SequencerAdmission
        }
        TriggerKind::PrivacyLeakSignal | TriggerKind::PrivateStateInconsistency => {
            FreezeScope::PrivateStateWrites
        }
        TriggerKind::MoneroReorg
        | TriggerKind::MoneroDaemonDivergence
        | TriggerKind::BridgeSettlementStalled => FreezeScope::BridgeWithdrawals,
        TriggerKind::ProverBacklog | TriggerKind::ProverProofInvalid => {
            FreezeScope::ProverSettlements
        }
        TriggerKind::DataAvailabilitySamplingFailure | TriggerKind::DataAvailabilityQuorumLoss => {
            FreezeScope::SequencerAdmission
        }
        TriggerKind::PqKeyCompromise => FreezeScope::Global,
    }
}

fn escalation_target_for_trigger(trigger_kind: TriggerKind) -> EscalationTarget {
    match trigger_kind {
        TriggerKind::LatencySloBreach
        | TriggerKind::FeeSpike
        | TriggerKind::LowFeeBudgetDepleted => EscalationTarget::Oncall,
        TriggerKind::PrivacyLeakSignal | TriggerKind::PrivateStateInconsistency => {
            EscalationTarget::PrivacyReviewers
        }
        TriggerKind::MoneroReorg
        | TriggerKind::MoneroDaemonDivergence
        | TriggerKind::BridgeSettlementStalled => EscalationTarget::BridgeCouncil,
        TriggerKind::ProverBacklog | TriggerKind::ProverProofInvalid => {
            EscalationTarget::ProverOperators
        }
        TriggerKind::DataAvailabilitySamplingFailure | TriggerKind::DataAvailabilityQuorumLoss => {
            EscalationTarget::DataAvailabilityCommittee
        }
        TriggerKind::PqKeyCompromise => EscalationTarget::SecurityCouncil,
    }
}

fn severity_for_trigger(
    trigger_kind: TriggerKind,
    observed_value: u64,
    threshold_value: u64,
) -> Severity {
    if matches!(
        trigger_kind,
        TriggerKind::PqKeyCompromise
            | TriggerKind::ProverProofInvalid
            | TriggerKind::PrivateStateInconsistency
            | TriggerKind::DataAvailabilityQuorumLoss
    ) {
        return Severity::Critical;
    }
    if threshold_value == 0 {
        return Severity::Warning;
    }
    let doubled = threshold_value.saturating_mul(2);
    let tripled = threshold_value.saturating_mul(3);
    if observed_value >= tripled {
        Severity::Critical
    } else if observed_value >= doubled {
        Severity::Severe
    } else if observed_value >= threshold_value {
        Severity::Warning
    } else {
        Severity::Watch
    }
}

fn keyed_value_root(domain: &str, mut records: Vec<(String, Value)>) -> String {
    records.sort_by(|left, right| left.0.cmp(&right.0));
    let leaves = records
        .into_iter()
        .map(|(key, value)| json!({"key": key, "value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn string_collection_root(domain: &str, values: &[String]) -> String {
    let mut sorted = values.to_vec();
    sorted.sort();
    let leaves = sorted
        .into_iter()
        .map(|value| json!({"value": value}))
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

fn with_root_field(mut record: Value, field: &str, root: String) -> Value {
    if let Value::Object(values) = &mut record {
        values.insert(field.to_string(), Value::String(root));
    }
    record
}

fn validate_child_records<T, F, G>(
    records: &[T],
    trigger_set: &BTreeSet<String>,
    label: &str,
    validate: F,
    trigger_id: G,
) -> Result<()>
where
    F: Fn(&T) -> Result<String>,
    G: Fn(&T) -> &String,
{
    let ids = records
        .iter()
        .map(|record| {
            let id = validate(record)?;
            let referenced_trigger = trigger_id(record);
            if !trigger_set.contains(referenced_trigger) {
                return Err(format!(
                    "{label} references unknown trigger {referenced_trigger}"
                ));
            }
            Ok(id)
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_unique_strings(&ids, label)
}

fn require_non_empty(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(format!("{label} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_positive(label: &str, value: u64) -> Result<()> {
    if value == 0 {
        Err(format!("{label} must be positive"))
    } else {
        Ok(())
    }
}

fn require_bps(label: &str, value: u64) -> Result<()> {
    if value > MAX_BPS {
        Err(format!("{label} exceeds 10000 bps"))
    } else {
        Ok(())
    }
}

fn ensure_unique_strings(values: &[String], label: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(label, value)?;
        if !seen.insert(value.clone()) {
            return Err(format!("{label} contains duplicate value"));
        }
    }
    Ok(())
}
