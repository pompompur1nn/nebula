use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub const RISK_PROTOCOL_VERSION: &str = "nebula-risk-v1";
pub const RISK_DEFAULT_MAX_BRIDGE_EXPOSURE_UNITS: u64 = 10_000_000_000_000;
pub const RISK_DEFAULT_MAX_PENDING_WITHDRAWALS: u64 = 1_000;
pub const RISK_DEFAULT_MAX_MEMPOOL_CONGESTION_BPS: u64 = 8_500;
pub const RISK_DEFAULT_MAX_LOW_FEE_PRESSURE_BPS: u64 = 9_000;
pub const RISK_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS: u64 = 12;
pub const RISK_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS: u64 = 20;
pub const RISK_DEFAULT_ASSESSMENT_TTL_BLOCKS: u64 = 40;
pub const RISK_SCORE_WARN_BPS: u64 = 5_000;
pub const RISK_SCORE_CRITICAL_BPS: u64 = 8_000;
pub const RISK_MAX_SIGNALS_PER_ASSESSMENT: usize = 64;

pub type RiskResult<T> = Result<T, String>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskDomain {
    Bridge,
    Sequencer,
    Mempool,
    Oracle,
    LowFeeMarket,
    Privacy,
    DataAvailability,
    Governance,
    Runtime,
    Custom(String),
}

impl RiskDomain {
    pub fn as_str(&self) -> String {
        match self {
            RiskDomain::Bridge => "bridge".to_string(),
            RiskDomain::Sequencer => "sequencer".to_string(),
            RiskDomain::Mempool => "mempool".to_string(),
            RiskDomain::Oracle => "oracle".to_string(),
            RiskDomain::LowFeeMarket => "low_fee_market".to_string(),
            RiskDomain::Privacy => "privacy".to_string(),
            RiskDomain::DataAvailability => "data_availability".to_string(),
            RiskDomain::Governance => "governance".to_string(),
            RiskDomain::Runtime => "runtime".to_string(),
            RiskDomain::Custom(label) => label.clone(),
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_domain",
            "chain_id": CHAIN_ID,
            "domain": self.as_str(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskSeverity {
    Info,
    Watch,
    Warn,
    Critical,
}

impl RiskSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskSeverity::Info => "info",
            RiskSeverity::Watch => "watch",
            RiskSeverity::Warn => "warn",
            RiskSeverity::Critical => "critical",
        }
    }

    pub fn score_bps(&self) -> u64 {
        match self {
            RiskSeverity::Info => 1_000,
            RiskSeverity::Watch => 3_000,
            RiskSeverity::Warn => 6_000,
            RiskSeverity::Critical => 10_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskSignalKind {
    BridgeExposure,
    PendingWithdrawals,
    MempoolCongestion,
    LowFeeBudgetPressure,
    OracleStaleness,
    DaSamplingFailure,
    PrivacyNullifierSpike,
    RuntimeErrorSpike,
    GovernanceEmergency,
    Custom(String),
}

impl RiskSignalKind {
    pub fn as_str(&self) -> String {
        match self {
            RiskSignalKind::BridgeExposure => "bridge_exposure".to_string(),
            RiskSignalKind::PendingWithdrawals => "pending_withdrawals".to_string(),
            RiskSignalKind::MempoolCongestion => "mempool_congestion".to_string(),
            RiskSignalKind::LowFeeBudgetPressure => "low_fee_budget_pressure".to_string(),
            RiskSignalKind::OracleStaleness => "oracle_staleness".to_string(),
            RiskSignalKind::DaSamplingFailure => "da_sampling_failure".to_string(),
            RiskSignalKind::PrivacyNullifierSpike => "privacy_nullifier_spike".to_string(),
            RiskSignalKind::RuntimeErrorSpike => "runtime_error_spike".to_string(),
            RiskSignalKind::GovernanceEmergency => "governance_emergency".to_string(),
            RiskSignalKind::Custom(label) => label.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskCircuitStatus {
    Closed,
    Watching,
    Open,
    CoolingDown,
}

impl RiskCircuitStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskCircuitStatus::Closed => "closed",
            RiskCircuitStatus::Watching => "watching",
            RiskCircuitStatus::Open => "open",
            RiskCircuitStatus::CoolingDown => "cooling_down",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskActionKind {
    Noop,
    Watch,
    ThrottleLowFeeLane,
    PauseBridgeWithdrawals,
    RequireAdditionalProofs,
    SlowSequencerAdmission,
    PauseContractUpgrades,
    EscalateGovernance,
}

impl RiskActionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskActionKind::Noop => "noop",
            RiskActionKind::Watch => "watch",
            RiskActionKind::ThrottleLowFeeLane => "throttle_low_fee_lane",
            RiskActionKind::PauseBridgeWithdrawals => "pause_bridge_withdrawals",
            RiskActionKind::RequireAdditionalProofs => "require_additional_proofs",
            RiskActionKind::SlowSequencerAdmission => "slow_sequencer_admission",
            RiskActionKind::PauseContractUpgrades => "pause_contract_upgrades",
            RiskActionKind::EscalateGovernance => "escalate_governance",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskLimitPolicy {
    pub policy_id: String,
    pub policy_label: String,
    pub max_bridge_exposure_units: u64,
    pub max_pending_withdrawals: u64,
    pub max_mempool_congestion_bps: u64,
    pub max_low_fee_pressure_bps: u64,
    pub max_oracle_staleness_blocks: u64,
    pub circuit_cooldown_blocks: u64,
    pub assessment_ttl_blocks: u64,
    pub created_at_height: u64,
    pub metadata_root: String,
}

impl RiskLimitPolicy {
    pub fn devnet_default(created_at_height: u64) -> Self {
        Self::new(
            "devnet-risk-policy",
            RISK_DEFAULT_MAX_BRIDGE_EXPOSURE_UNITS,
            RISK_DEFAULT_MAX_PENDING_WITHDRAWALS,
            RISK_DEFAULT_MAX_MEMPOOL_CONGESTION_BPS,
            RISK_DEFAULT_MAX_LOW_FEE_PRESSURE_BPS,
            RISK_DEFAULT_MAX_ORACLE_STALENESS_BLOCKS,
            RISK_DEFAULT_CIRCUIT_COOLDOWN_BLOCKS,
            RISK_DEFAULT_ASSESSMENT_TTL_BLOCKS,
            created_at_height,
            &json!({
                "mode": "devnet",
                "priority": ["privacy", "low_fees", "speed", "monero_settlement"],
            }),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_label: &str,
        max_bridge_exposure_units: u64,
        max_pending_withdrawals: u64,
        max_mempool_congestion_bps: u64,
        max_low_fee_pressure_bps: u64,
        max_oracle_staleness_blocks: u64,
        circuit_cooldown_blocks: u64,
        assessment_ttl_blocks: u64,
        created_at_height: u64,
        metadata: &Value,
    ) -> Self {
        let metadata_root = risk_payload_root("RISK-POLICY-METADATA", metadata);
        let policy_id = risk_policy_id(
            policy_label,
            max_bridge_exposure_units,
            max_pending_withdrawals,
            max_mempool_congestion_bps,
            max_low_fee_pressure_bps,
            max_oracle_staleness_blocks,
            circuit_cooldown_blocks,
            assessment_ttl_blocks,
            created_at_height,
            &metadata_root,
        );
        Self {
            policy_id,
            policy_label: policy_label.to_string(),
            max_bridge_exposure_units,
            max_pending_withdrawals,
            max_mempool_congestion_bps,
            max_low_fee_pressure_bps,
            max_oracle_staleness_blocks,
            circuit_cooldown_blocks,
            assessment_ttl_blocks,
            created_at_height,
            metadata_root,
        }
    }

    pub fn validate(&self) -> RiskResult<()> {
        if self.policy_label.is_empty() {
            return Err("risk policy label cannot be empty".to_string());
        }
        if self.max_mempool_congestion_bps > 10_000 || self.max_low_fee_pressure_bps > 10_000 {
            return Err("risk policy bps thresholds cannot exceed 10000".to_string());
        }
        if self.circuit_cooldown_blocks == 0 || self.assessment_ttl_blocks == 0 {
            return Err("risk policy block windows must be positive".to_string());
        }
        if self.policy_id
            != risk_policy_id(
                &self.policy_label,
                self.max_bridge_exposure_units,
                self.max_pending_withdrawals,
                self.max_mempool_congestion_bps,
                self.max_low_fee_pressure_bps,
                self.max_oracle_staleness_blocks,
                self.circuit_cooldown_blocks,
                self.assessment_ttl_blocks,
                self.created_at_height,
                &self.metadata_root,
            )
        {
            return Err("risk policy id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_limit_policy",
            "chain_id": CHAIN_ID,
            "protocol_version": RISK_PROTOCOL_VERSION,
            "policy_id": self.policy_id,
            "policy_label": self.policy_label,
            "max_bridge_exposure_units": self.max_bridge_exposure_units,
            "max_pending_withdrawals": self.max_pending_withdrawals,
            "max_mempool_congestion_bps": self.max_mempool_congestion_bps,
            "max_low_fee_pressure_bps": self.max_low_fee_pressure_bps,
            "max_oracle_staleness_blocks": self.max_oracle_staleness_blocks,
            "circuit_cooldown_blocks": self.circuit_cooldown_blocks,
            "assessment_ttl_blocks": self.assessment_ttl_blocks,
            "created_at_height": self.created_at_height,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    pub signal_id: String,
    pub domain: RiskDomain,
    pub signal_kind: RiskSignalKind,
    pub severity: RiskSeverity,
    pub height: u64,
    pub metric_value: u64,
    pub threshold_value: u64,
    pub subject_root: String,
    pub evidence_root: String,
    pub message: String,
}

impl RiskSignal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: RiskDomain,
        signal_kind: RiskSignalKind,
        severity: RiskSeverity,
        height: u64,
        metric_value: u64,
        threshold_value: u64,
        subject_root: &str,
        evidence: &Value,
        message: &str,
    ) -> Self {
        let evidence_root = risk_payload_root("RISK-SIGNAL-EVIDENCE", evidence);
        let signal_id = risk_signal_id(
            &domain,
            &signal_kind,
            &severity,
            height,
            metric_value,
            threshold_value,
            subject_root,
            &evidence_root,
        );
        Self {
            signal_id,
            domain,
            signal_kind,
            severity,
            height,
            metric_value,
            threshold_value,
            subject_root: subject_root.to_string(),
            evidence_root,
            message: message.to_string(),
        }
    }

    pub fn validate(&self) -> RiskResult<()> {
        if self.subject_root.is_empty() || self.evidence_root.is_empty() {
            return Err("risk signal roots cannot be empty".to_string());
        }
        if self.signal_id
            != risk_signal_id(
                &self.domain,
                &self.signal_kind,
                &self.severity,
                self.height,
                self.metric_value,
                self.threshold_value,
                &self.subject_root,
                &self.evidence_root,
            )
        {
            return Err("risk signal id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_signal",
            "chain_id": CHAIN_ID,
            "signal_id": self.signal_id,
            "domain": self.domain.as_str(),
            "signal_kind": self.signal_kind.as_str(),
            "severity": self.severity.as_str(),
            "height": self.height,
            "metric_value": self.metric_value,
            "threshold_value": self.threshold_value,
            "subject_root": self.subject_root,
            "evidence_root": self.evidence_root,
            "message": self.message,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskCircuitBreaker {
    pub circuit_id: String,
    pub domain: RiskDomain,
    pub status: RiskCircuitStatus,
    pub opened_at_height: u64,
    pub closed_at_height: u64,
    pub cooldown_blocks: u64,
    pub signal_root: String,
    pub reason_root: String,
    pub operator_commitment: String,
}

impl RiskCircuitBreaker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain: RiskDomain,
        status: RiskCircuitStatus,
        opened_at_height: u64,
        closed_at_height: u64,
        cooldown_blocks: u64,
        signal_root: &str,
        reason: &Value,
        operator_label: &str,
    ) -> Self {
        let reason_root = risk_payload_root("RISK-CIRCUIT-REASON", reason);
        let operator_commitment = risk_string_root("RISK-CIRCUIT-OPERATOR", operator_label);
        let circuit_id = risk_circuit_id(
            &domain,
            &status,
            opened_at_height,
            closed_at_height,
            cooldown_blocks,
            signal_root,
            &reason_root,
            &operator_commitment,
        );
        Self {
            circuit_id,
            domain,
            status,
            opened_at_height,
            closed_at_height,
            cooldown_blocks,
            signal_root: signal_root.to_string(),
            reason_root,
            operator_commitment,
        }
    }

    pub fn is_active(&self, height: u64) -> bool {
        matches!(&self.status, RiskCircuitStatus::Open)
            || (matches!(&self.status, RiskCircuitStatus::CoolingDown)
                && height < self.opened_at_height.saturating_add(self.cooldown_blocks))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_circuit_breaker",
            "chain_id": CHAIN_ID,
            "circuit_id": self.circuit_id,
            "domain": self.domain.as_str(),
            "status": self.status.as_str(),
            "opened_at_height": self.opened_at_height,
            "closed_at_height": self.closed_at_height,
            "cooldown_blocks": self.cooldown_blocks,
            "signal_root": self.signal_root,
            "reason_root": self.reason_root,
            "operator_commitment": self.operator_commitment,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAction {
    pub action_id: String,
    pub action_kind: RiskActionKind,
    pub domain: RiskDomain,
    pub height: u64,
    pub expires_at_height: u64,
    pub circuit_id: String,
    pub signal_root: String,
    pub metadata_root: String,
}

impl RiskAction {
    pub fn new(
        action_kind: RiskActionKind,
        domain: RiskDomain,
        height: u64,
        expires_at_height: u64,
        circuit_id: &str,
        signal_root: &str,
        metadata: &Value,
    ) -> Self {
        let metadata_root = risk_payload_root("RISK-ACTION-METADATA", metadata);
        let action_id = risk_action_id(
            &action_kind,
            &domain,
            height,
            expires_at_height,
            circuit_id,
            signal_root,
            &metadata_root,
        );
        Self {
            action_id,
            action_kind,
            domain,
            height,
            expires_at_height,
            circuit_id: circuit_id.to_string(),
            signal_root: signal_root.to_string(),
            metadata_root,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_action",
            "chain_id": CHAIN_ID,
            "action_id": self.action_id,
            "action_kind": self.action_kind.as_str(),
            "domain": self.domain.as_str(),
            "height": self.height,
            "expires_at_height": self.expires_at_height,
            "circuit_id": self.circuit_id,
            "signal_root": self.signal_root,
            "metadata_root": self.metadata_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub assessment_id: String,
    pub height: u64,
    pub policy_root: String,
    pub signal_root: String,
    pub circuit_root: String,
    pub action_root: String,
    pub bridge_exposure_units: u64,
    pub pending_withdrawals: u64,
    pub mempool_congestion_bps: u64,
    pub low_fee_pressure_bps: u64,
    pub stale_oracle_feed_count: u64,
    pub risk_score_bps: u64,
    pub status: String,
    pub expires_at_height: u64,
}

impl RiskAssessment {
    pub fn expected_assessment_id(&self) -> String {
        risk_assessment_id(
            self.height,
            &self.policy_root,
            &self.signal_root,
            &self.circuit_root,
            &self.action_root,
            self.bridge_exposure_units,
            self.pending_withdrawals,
            self.mempool_congestion_bps,
            self.low_fee_pressure_bps,
            self.stale_oracle_feed_count,
            self.risk_score_bps,
            self.expires_at_height,
        )
    }

    pub fn validate(&self) -> RiskResult<()> {
        if self.policy_root.is_empty() || self.signal_root.is_empty() {
            return Err("risk assessment roots cannot be empty".to_string());
        }
        if self.risk_score_bps > 10_000 {
            return Err("risk score cannot exceed 10000 bps".to_string());
        }
        if self.assessment_id != self.expected_assessment_id() {
            return Err("risk assessment id mismatch".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_assessment",
            "chain_id": CHAIN_ID,
            "assessment_id": self.assessment_id,
            "height": self.height,
            "policy_root": self.policy_root,
            "signal_root": self.signal_root,
            "circuit_root": self.circuit_root,
            "action_root": self.action_root,
            "bridge_exposure_units": self.bridge_exposure_units,
            "pending_withdrawals": self.pending_withdrawals,
            "mempool_congestion_bps": self.mempool_congestion_bps,
            "low_fee_pressure_bps": self.low_fee_pressure_bps,
            "stale_oracle_feed_count": self.stale_oracle_feed_count,
            "risk_score_bps": self.risk_score_bps,
            "status": self.status,
            "expires_at_height": self.expires_at_height,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskState {
    pub policies: BTreeMap<String, RiskLimitPolicy>,
    pub signals: BTreeMap<String, RiskSignal>,
    pub circuits: BTreeMap<String, RiskCircuitBreaker>,
    pub actions: BTreeMap<String, RiskAction>,
    pub assessments: BTreeMap<String, RiskAssessment>,
    pub height: u64,
}

impl RiskState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_devnet_policy() -> RiskResult<Self> {
        let mut state = Self::new();
        state.insert_policy(RiskLimitPolicy::devnet_default(0))?;
        Ok(state)
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn insert_policy(&mut self, policy: RiskLimitPolicy) -> RiskResult<RiskLimitPolicy> {
        policy.validate()?;
        self.policies
            .insert(policy.policy_id.clone(), policy.clone());
        Ok(policy)
    }

    pub fn active_policy(&self) -> RiskResult<RiskLimitPolicy> {
        self.policies
            .values()
            .max_by_key(|policy| policy.created_at_height)
            .cloned()
            .ok_or_else(|| "risk state has no policy".to_string())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assess_system(
        &mut self,
        height: u64,
        bridge_exposure_units: u64,
        pending_withdrawals: u64,
        mempool_admissions: u64,
        mempool_capacity: u64,
        low_fee_spent_units: u64,
        low_fee_budget_units: u64,
        stale_oracle_feed_count: u64,
        subject_record: &Value,
        operator_label: &str,
    ) -> RiskResult<RiskAssessment> {
        self.height = height;
        let policy = self.active_policy()?;
        let mempool_congestion_bps = ratio_bps(mempool_admissions, mempool_capacity.max(1));
        let low_fee_pressure_bps = ratio_bps(low_fee_spent_units, low_fee_budget_units.max(1));
        let subject_root = risk_payload_root("RISK-ASSESSMENT-SUBJECT", subject_record);
        let mut new_signals = Vec::new();
        if bridge_exposure_units > policy.max_bridge_exposure_units {
            new_signals.push(RiskSignal::new(
                RiskDomain::Bridge,
                RiskSignalKind::BridgeExposure,
                RiskSeverity::Critical,
                height,
                bridge_exposure_units,
                policy.max_bridge_exposure_units,
                &subject_root,
                subject_record,
                "bridge exposure exceeds policy",
            ));
        }
        if pending_withdrawals > policy.max_pending_withdrawals {
            new_signals.push(RiskSignal::new(
                RiskDomain::Bridge,
                RiskSignalKind::PendingWithdrawals,
                RiskSeverity::Warn,
                height,
                pending_withdrawals,
                policy.max_pending_withdrawals,
                &subject_root,
                subject_record,
                "pending withdrawals exceed policy",
            ));
        }
        if mempool_congestion_bps > policy.max_mempool_congestion_bps {
            new_signals.push(RiskSignal::new(
                RiskDomain::Mempool,
                RiskSignalKind::MempoolCongestion,
                RiskSeverity::Warn,
                height,
                mempool_congestion_bps,
                policy.max_mempool_congestion_bps,
                &subject_root,
                subject_record,
                "mempool congestion exceeds policy",
            ));
        }
        if low_fee_pressure_bps > policy.max_low_fee_pressure_bps {
            new_signals.push(RiskSignal::new(
                RiskDomain::LowFeeMarket,
                RiskSignalKind::LowFeeBudgetPressure,
                RiskSeverity::Warn,
                height,
                low_fee_pressure_bps,
                policy.max_low_fee_pressure_bps,
                &subject_root,
                subject_record,
                "low fee budget pressure exceeds policy",
            ));
        }
        if stale_oracle_feed_count > 0 {
            new_signals.push(RiskSignal::new(
                RiskDomain::Oracle,
                RiskSignalKind::OracleStaleness,
                RiskSeverity::Watch,
                height,
                stale_oracle_feed_count,
                0,
                &subject_root,
                subject_record,
                "one or more oracle feeds are stale",
            ));
        }
        new_signals.truncate(RISK_MAX_SIGNALS_PER_ASSESSMENT);
        for signal in &new_signals {
            signal.validate()?;
            self.signals
                .insert(signal.signal_id.clone(), signal.clone());
        }
        let signal_root = risk_signal_root(&new_signals);
        let circuits = self.reconcile_circuits(&policy, &new_signals, &signal_root, operator_label);
        let actions = self.actions_for_signals(&policy, &new_signals, &circuits, &signal_root);
        for circuit in &circuits {
            self.circuits
                .insert(circuit.circuit_id.clone(), circuit.clone());
        }
        for action in &actions {
            self.actions
                .insert(action.action_id.clone(), action.clone());
        }
        let circuit_root = risk_circuit_root(&circuits);
        let action_root = risk_action_root(&actions);
        let risk_score_bps = risk_score_from_signals(&new_signals);
        let status = if risk_score_bps >= RISK_SCORE_CRITICAL_BPS {
            "critical"
        } else if risk_score_bps >= RISK_SCORE_WARN_BPS {
            "warn"
        } else if !new_signals.is_empty() {
            "watch"
        } else {
            "ok"
        }
        .to_string();
        let mut assessment = RiskAssessment {
            assessment_id: String::new(),
            height,
            policy_root: risk_policy_root(&[policy.clone()]),
            signal_root,
            circuit_root,
            action_root,
            bridge_exposure_units,
            pending_withdrawals,
            mempool_congestion_bps,
            low_fee_pressure_bps,
            stale_oracle_feed_count,
            risk_score_bps,
            status,
            expires_at_height: height.saturating_add(policy.assessment_ttl_blocks),
        };
        assessment.assessment_id = assessment.expected_assessment_id();
        assessment.validate()?;
        self.assessments
            .insert(assessment.assessment_id.clone(), assessment.clone());
        Ok(assessment)
    }

    pub fn active_action_kinds(&self, height: u64) -> Vec<String> {
        self.actions
            .values()
            .filter(|action| action.expires_at_height >= height)
            .map(|action| action.action_kind.as_str().to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn state_root(&self) -> String {
        risk_state_root_from_record(&self.public_record())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "risk_state",
            "chain_id": CHAIN_ID,
            "protocol_version": RISK_PROTOCOL_VERSION,
            "height": self.height,
            "policy_root": risk_policy_root(&self.policies.values().cloned().collect::<Vec<_>>()),
            "signal_root": risk_signal_root(&self.signals.values().cloned().collect::<Vec<_>>()),
            "circuit_root": risk_circuit_root(&self.circuits.values().cloned().collect::<Vec<_>>()),
            "action_root": risk_action_root(&self.actions.values().cloned().collect::<Vec<_>>()),
            "assessment_root": risk_assessment_root(&self.assessments.values().cloned().collect::<Vec<_>>()),
            "active_actions": self.active_action_kinds(self.height),
        })
    }

    fn reconcile_circuits(
        &self,
        policy: &RiskLimitPolicy,
        signals: &[RiskSignal],
        signal_root: &str,
        operator_label: &str,
    ) -> Vec<RiskCircuitBreaker> {
        signals
            .iter()
            .filter(|signal| {
                matches!(
                    &signal.severity,
                    RiskSeverity::Warn | RiskSeverity::Critical
                )
            })
            .map(|signal| {
                let status = if matches!(&signal.severity, RiskSeverity::Critical) {
                    RiskCircuitStatus::Open
                } else {
                    RiskCircuitStatus::Watching
                };
                RiskCircuitBreaker::new(
                    signal.domain.clone(),
                    status,
                    signal.height,
                    0,
                    policy.circuit_cooldown_blocks,
                    signal_root,
                    &signal.public_record(),
                    operator_label,
                )
            })
            .collect()
    }

    fn actions_for_signals(
        &self,
        policy: &RiskLimitPolicy,
        signals: &[RiskSignal],
        circuits: &[RiskCircuitBreaker],
        signal_root: &str,
    ) -> Vec<RiskAction> {
        signals
            .iter()
            .map(|signal| {
                let action_kind = match &signal.signal_kind {
                    RiskSignalKind::BridgeExposure | RiskSignalKind::PendingWithdrawals => {
                        RiskActionKind::PauseBridgeWithdrawals
                    }
                    RiskSignalKind::MempoolCongestion => RiskActionKind::SlowSequencerAdmission,
                    RiskSignalKind::LowFeeBudgetPressure => RiskActionKind::ThrottleLowFeeLane,
                    RiskSignalKind::OracleStaleness => RiskActionKind::RequireAdditionalProofs,
                    RiskSignalKind::DaSamplingFailure => RiskActionKind::RequireAdditionalProofs,
                    RiskSignalKind::RuntimeErrorSpike => RiskActionKind::SlowSequencerAdmission,
                    RiskSignalKind::PrivacyNullifierSpike => {
                        RiskActionKind::RequireAdditionalProofs
                    }
                    RiskSignalKind::GovernanceEmergency => RiskActionKind::EscalateGovernance,
                    RiskSignalKind::Custom(_) => RiskActionKind::Watch,
                };
                let circuit_id = circuits
                    .iter()
                    .find(|circuit| circuit.domain == signal.domain)
                    .map(|circuit| circuit.circuit_id.as_str())
                    .unwrap_or("");
                RiskAction::new(
                    action_kind,
                    signal.domain.clone(),
                    signal.height,
                    signal.height.saturating_add(policy.circuit_cooldown_blocks),
                    circuit_id,
                    signal_root,
                    &signal.public_record(),
                )
            })
            .collect()
    }
}

pub fn risk_policy_id(
    policy_label: &str,
    max_bridge_exposure_units: u64,
    max_pending_withdrawals: u64,
    max_mempool_congestion_bps: u64,
    max_low_fee_pressure_bps: u64,
    max_oracle_staleness_blocks: u64,
    circuit_cooldown_blocks: u64,
    assessment_ttl_blocks: u64,
    created_at_height: u64,
    metadata_root: &str,
) -> String {
    domain_hash(
        "RISK-POLICY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(policy_label),
            HashPart::Int(max_bridge_exposure_units as i128),
            HashPart::Int(max_pending_withdrawals as i128),
            HashPart::Int(max_mempool_congestion_bps as i128),
            HashPart::Int(max_low_fee_pressure_bps as i128),
            HashPart::Int(max_oracle_staleness_blocks as i128),
            HashPart::Int(circuit_cooldown_blocks as i128),
            HashPart::Int(assessment_ttl_blocks as i128),
            HashPart::Int(created_at_height as i128),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn risk_signal_id(
    domain: &RiskDomain,
    signal_kind: &RiskSignalKind,
    severity: &RiskSeverity,
    height: u64,
    metric_value: u64,
    threshold_value: u64,
    subject_root: &str,
    evidence_root: &str,
) -> String {
    domain_hash(
        "RISK-SIGNAL-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&domain.as_str()),
            HashPart::Str(&signal_kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Int(height as i128),
            HashPart::Int(metric_value as i128),
            HashPart::Int(threshold_value as i128),
            HashPart::Str(subject_root),
            HashPart::Str(evidence_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn risk_circuit_id(
    domain: &RiskDomain,
    status: &RiskCircuitStatus,
    opened_at_height: u64,
    closed_at_height: u64,
    cooldown_blocks: u64,
    signal_root: &str,
    reason_root: &str,
    operator_commitment: &str,
) -> String {
    domain_hash(
        "RISK-CIRCUIT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(&domain.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Int(opened_at_height as i128),
            HashPart::Int(closed_at_height as i128),
            HashPart::Int(cooldown_blocks as i128),
            HashPart::Str(signal_root),
            HashPart::Str(reason_root),
            HashPart::Str(operator_commitment),
        ],
        32,
    )
}

pub fn risk_action_id(
    action_kind: &RiskActionKind,
    domain: &RiskDomain,
    height: u64,
    expires_at_height: u64,
    circuit_id: &str,
    signal_root: &str,
    metadata_root: &str,
) -> String {
    domain_hash(
        "RISK-ACTION-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(action_kind.as_str()),
            HashPart::Str(&domain.as_str()),
            HashPart::Int(height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Str(circuit_id),
            HashPart::Str(signal_root),
            HashPart::Str(metadata_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn risk_assessment_id(
    height: u64,
    policy_root: &str,
    signal_root: &str,
    circuit_root: &str,
    action_root: &str,
    bridge_exposure_units: u64,
    pending_withdrawals: u64,
    mempool_congestion_bps: u64,
    low_fee_pressure_bps: u64,
    stale_oracle_feed_count: u64,
    risk_score_bps: u64,
    expires_at_height: u64,
) -> String {
    domain_hash(
        "RISK-ASSESSMENT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Int(height as i128),
            HashPart::Str(policy_root),
            HashPart::Str(signal_root),
            HashPart::Str(circuit_root),
            HashPart::Str(action_root),
            HashPart::Int(bridge_exposure_units as i128),
            HashPart::Int(pending_withdrawals as i128),
            HashPart::Int(mempool_congestion_bps as i128),
            HashPart::Int(low_fee_pressure_bps as i128),
            HashPart::Int(stale_oracle_feed_count as i128),
            HashPart::Int(risk_score_bps as i128),
            HashPart::Int(expires_at_height as i128),
        ],
        32,
    )
}

pub fn risk_policy_root(policies: &[RiskLimitPolicy]) -> String {
    merkle_root(
        "RISK-POLICY",
        &policies
            .iter()
            .map(RiskLimitPolicy::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_signal_root(signals: &[RiskSignal]) -> String {
    merkle_root(
        "RISK-SIGNAL",
        &signals
            .iter()
            .map(RiskSignal::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_circuit_root(circuits: &[RiskCircuitBreaker]) -> String {
    merkle_root(
        "RISK-CIRCUIT",
        &circuits
            .iter()
            .map(RiskCircuitBreaker::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_action_root(actions: &[RiskAction]) -> String {
    merkle_root(
        "RISK-ACTION",
        &actions
            .iter()
            .map(RiskAction::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_assessment_root(assessments: &[RiskAssessment]) -> String {
    merkle_root(
        "RISK-ASSESSMENT",
        &assessments
            .iter()
            .map(RiskAssessment::public_record)
            .collect::<Vec<_>>(),
    )
}

pub fn risk_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn risk_string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn risk_state_root_from_record(record: &Value) -> String {
    domain_hash("RISK-STATE", &[HashPart::Json(record)], 32)
}

pub fn risk_score_from_signals(signals: &[RiskSignal]) -> u64 {
    signals
        .iter()
        .map(|signal| signal.severity.score_bps())
        .max()
        .unwrap_or(0)
        .min(10_000)
}

pub fn ratio_bps(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 10_000;
    }
    let value = (numerator as u128).saturating_mul(10_000) / denominator as u128;
    value.min(10_000) as u64
}
