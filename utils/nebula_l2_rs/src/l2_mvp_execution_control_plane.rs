use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type L2MvpExecutionControlPlaneResult<T> = Result<T, String>;

pub const L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION: &str =
    "nebula-l2-mvp-execution-control-plane-v1";
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_GLOBAL_SCORE_BPS: u64 = 9_200;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_CRITICAL_SCORE_BPS: u64 = 9_600;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_OPEN_BLOCKERS: u64 = 0;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_FEE_BPS: u64 = 45;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_PRIVACY_SET: u64 = 128;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_PQ_SECURITY_BITS: u64 = 256;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_LATENCY_BLOCKS: u64 = 4;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS: u64 = 10_000;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_MAX_COMPONENTS: usize = 256;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_MAX_WINDOWS: usize = 512;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BLOCKERS: usize = 1_024;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_MAX_RECEIPTS: usize = 1_024;
pub const L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT: u64 = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneComponentKind {
    MoneroSettlement,
    PqRuntime,
    PrivateContractExecution,
    DefiLiquidity,
    LowFeeProofs,
    PrivacyFirewall,
    OperatorReadiness,
    DataAvailability,
    SequencerFastPath,
}

impl ControlPlaneComponentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MoneroSettlement => "monero_settlement",
            Self::PqRuntime => "pq_runtime",
            Self::PrivateContractExecution => "private_contract_execution",
            Self::DefiLiquidity => "defi_liquidity",
            Self::LowFeeProofs => "low_fee_proofs",
            Self::PrivacyFirewall => "privacy_firewall",
            Self::OperatorReadiness => "operator_readiness",
            Self::DataAvailability => "data_availability",
            Self::SequencerFastPath => "sequencer_fast_path",
        }
    }

    pub fn critical(self) -> bool {
        matches!(
            self,
            Self::MoneroSettlement
                | Self::PqRuntime
                | Self::PrivateContractExecution
                | Self::PrivacyFirewall
                | Self::OperatorReadiness
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionWindowKind {
    PrivateTransfer,
    PrivateContractCall,
    TokenMigration,
    DefiSwap,
    BridgeExit,
    EmergencyExit,
}

impl ExecutionWindowKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PrivateTransfer => "private_transfer",
            Self::PrivateContractCall => "private_contract_call",
            Self::TokenMigration => "token_migration",
            Self::DefiSwap => "defi_swap",
            Self::BridgeExit => "bridge_exit",
            Self::EmergencyExit => "emergency_exit",
        }
    }

    pub fn required_components(self) -> BTreeSet<ControlPlaneComponentKind> {
        let mut components = BTreeSet::new();
        components.insert(ControlPlaneComponentKind::PqRuntime);
        components.insert(ControlPlaneComponentKind::PrivacyFirewall);
        components.insert(ControlPlaneComponentKind::OperatorReadiness);
        components.insert(ControlPlaneComponentKind::SequencerFastPath);
        match self {
            Self::PrivateTransfer => {
                components.insert(ControlPlaneComponentKind::LowFeeProofs);
            }
            Self::PrivateContractCall => {
                components.insert(ControlPlaneComponentKind::PrivateContractExecution);
                components.insert(ControlPlaneComponentKind::LowFeeProofs);
                components.insert(ControlPlaneComponentKind::DataAvailability);
            }
            Self::TokenMigration => {
                components.insert(ControlPlaneComponentKind::PrivateContractExecution);
                components.insert(ControlPlaneComponentKind::DefiLiquidity);
                components.insert(ControlPlaneComponentKind::LowFeeProofs);
            }
            Self::DefiSwap => {
                components.insert(ControlPlaneComponentKind::PrivateContractExecution);
                components.insert(ControlPlaneComponentKind::DefiLiquidity);
                components.insert(ControlPlaneComponentKind::LowFeeProofs);
            }
            Self::BridgeExit | Self::EmergencyExit => {
                components.insert(ControlPlaneComponentKind::MoneroSettlement);
                components.insert(ControlPlaneComponentKind::LowFeeProofs);
            }
        }
        components
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    Notice,
    Warning,
    Critical,
}

impl BlockerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Notice => "notice",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }

    pub fn penalty_bps(self) -> u64 {
        match self {
            Self::Notice => 100,
            Self::Warning => 500,
            Self::Critical => 2_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Open,
    OpenWithWarnings,
    Hold,
    EmergencyOnly,
}

impl GateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::OpenWithWarnings => "open_with_warnings",
            Self::Hold => "hold",
            Self::EmergencyOnly => "emergency_only",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub min_global_score_bps: u64,
    pub min_critical_score_bps: u64,
    pub max_open_blockers: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set: u64,
    pub min_pq_security_bits: u64,
    pub max_latency_blocks: u64,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            min_global_score_bps: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_GLOBAL_SCORE_BPS,
            min_critical_score_bps: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_CRITICAL_SCORE_BPS,
            max_open_blockers: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_OPEN_BLOCKERS,
            max_fee_bps: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_FEE_BPS,
            min_privacy_set: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_PRIVACY_SET,
            min_pq_security_bits: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MIN_PQ_SECURITY_BITS,
            max_latency_blocks: L2_MVP_EXECUTION_CONTROL_PLANE_DEFAULT_MAX_LATENCY_BLOCKS,
        }
    }

    pub fn validate(&self) -> L2MvpExecutionControlPlaneResult<()> {
        if self.min_global_score_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS
            || self.min_critical_score_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS
            || self.max_fee_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS
        {
            return Err("control plane bps values cannot exceed score scale".to_string());
        }
        if self.min_global_score_bps == 0
            || self.min_critical_score_bps == 0
            || self.min_privacy_set == 0
            || self.min_pq_security_bits == 0
            || self.max_latency_blocks == 0
        {
            return Err("control plane thresholds must be positive".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_mvp_execution_control_plane_config",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "min_global_score_bps": self.min_global_score_bps,
            "min_critical_score_bps": self.min_critical_score_bps,
            "max_open_blockers": self.max_open_blockers,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
            "min_pq_security_bits": self.min_pq_security_bits,
            "max_latency_blocks": self.max_latency_blocks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentReadiness {
    pub component_id: String,
    pub component_kind: ControlPlaneComponentKind,
    pub label: String,
    pub state_root: String,
    pub score_bps: u64,
    pub latency_blocks: u64,
    pub fee_bps: u64,
    pub privacy_set: u64,
    pub pq_security_bits: u64,
    pub last_updated_height: u64,
}

impl ComponentReadiness {
    pub fn new(
        component_kind: ControlPlaneComponentKind,
        label: &str,
        state_root: &str,
        score_bps: u64,
        latency_blocks: u64,
        fee_bps: u64,
        privacy_set: u64,
        pq_security_bits: u64,
        last_updated_height: u64,
    ) -> L2MvpExecutionControlPlaneResult<Self> {
        if label.is_empty() || state_root.is_empty() {
            return Err("component readiness identifiers cannot be empty".to_string());
        }
        if score_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS
            || fee_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS
        {
            return Err("component readiness bps values cannot exceed score scale".to_string());
        }
        let component_id = component_readiness_id(
            component_kind,
            label,
            state_root,
            score_bps,
            latency_blocks,
            fee_bps,
            last_updated_height,
        );
        Ok(Self {
            component_id,
            component_kind,
            label: label.to_string(),
            state_root: state_root.to_string(),
            score_bps,
            latency_blocks,
            fee_bps,
            privacy_set,
            pq_security_bits,
            last_updated_height,
        })
    }

    pub fn threshold_penalty(&self, config: &Config) -> u64 {
        let mut penalty = 0_u64;
        if self.latency_blocks > config.max_latency_blocks {
            penalty = penalty.saturating_add(300);
        }
        if self.fee_bps > config.max_fee_bps {
            penalty = penalty.saturating_add(400);
        }
        if self.privacy_set < config.min_privacy_set {
            penalty = penalty.saturating_add(800);
        }
        if self.pq_security_bits < config.min_pq_security_bits {
            penalty = penalty.saturating_add(1_500);
        }
        penalty
    }

    pub fn effective_score(&self, config: &Config) -> u64 {
        self.score_bps
            .saturating_sub(self.threshold_penalty(config))
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_mvp_component_readiness",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "component_id": self.component_id,
            "component_kind": self.component_kind.as_str(),
            "label": self.label,
            "state_root": self.state_root,
            "score_bps": self.score_bps,
            "latency_blocks": self.latency_blocks,
            "fee_bps": self.fee_bps,
            "privacy_set": self.privacy_set,
            "pq_security_bits": self.pq_security_bits,
            "last_updated_height": self.last_updated_height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWindow {
    pub window_id: String,
    pub window_kind: ExecutionWindowKind,
    pub label: String,
    pub required_components: BTreeSet<ControlPlaneComponentKind>,
    pub demand_root: String,
    pub opens_at_height: u64,
    pub expires_at_height: u64,
    pub max_fee_bps: u64,
    pub min_privacy_set: u64,
}

impl ExecutionWindow {
    pub fn new(
        window_kind: ExecutionWindowKind,
        label: &str,
        demand: &Value,
        opens_at_height: u64,
        expires_at_height: u64,
        max_fee_bps: u64,
        min_privacy_set: u64,
    ) -> L2MvpExecutionControlPlaneResult<Self> {
        if label.is_empty() {
            return Err("execution window label cannot be empty".to_string());
        }
        if expires_at_height <= opens_at_height {
            return Err("execution window must expire after opening".to_string());
        }
        if max_fee_bps > L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BPS {
            return Err("execution window fee cap cannot exceed score scale".to_string());
        }
        let demand_root =
            l2_mvp_execution_control_plane_payload_root("L2-MVP-EXECUTION-WINDOW-DEMAND", demand);
        let required_components = window_kind.required_components();
        let window_id = execution_window_id(
            window_kind,
            label,
            &demand_root,
            opens_at_height,
            expires_at_height,
            max_fee_bps,
            min_privacy_set,
        );
        Ok(Self {
            window_id,
            window_kind,
            label: label.to_string(),
            required_components,
            demand_root,
            opens_at_height,
            expires_at_height,
            max_fee_bps,
            min_privacy_set,
        })
    }

    pub fn active_at(&self, height: u64) -> bool {
        self.opens_at_height <= height && height <= self.expires_at_height
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_mvp_execution_window",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "window_id": self.window_id,
            "window_kind": self.window_kind.as_str(),
            "label": self.label,
            "required_components": self.required_components.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "demand_root": self.demand_root,
            "opens_at_height": self.opens_at_height,
            "expires_at_height": self.expires_at_height,
            "max_fee_bps": self.max_fee_bps,
            "min_privacy_set": self.min_privacy_set,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneBlocker {
    pub blocker_id: String,
    pub component_kind: ControlPlaneComponentKind,
    pub severity: BlockerSeverity,
    pub label: String,
    pub evidence_root: String,
    pub opened_at_height: u64,
    pub resolved: bool,
}

impl ControlPlaneBlocker {
    pub fn new(
        component_kind: ControlPlaneComponentKind,
        severity: BlockerSeverity,
        label: &str,
        evidence: &Value,
        opened_at_height: u64,
        resolved: bool,
    ) -> L2MvpExecutionControlPlaneResult<Self> {
        if label.is_empty() {
            return Err("control plane blocker label cannot be empty".to_string());
        }
        let evidence_root =
            l2_mvp_execution_control_plane_payload_root("L2-MVP-BLOCKER-EVIDENCE", evidence);
        let blocker_id = control_plane_blocker_id(
            component_kind,
            severity,
            label,
            &evidence_root,
            opened_at_height,
        );
        Ok(Self {
            blocker_id,
            component_kind,
            severity,
            label: label.to_string(),
            evidence_root,
            opened_at_height,
            resolved,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_mvp_control_plane_blocker",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "blocker_id": self.blocker_id,
            "component_kind": self.component_kind.as_str(),
            "severity": self.severity.as_str(),
            "label": self.label,
            "evidence_root": self.evidence_root,
            "opened_at_height": self.opened_at_height,
            "resolved": self.resolved,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReceipt {
    pub receipt_id: String,
    pub window_id: String,
    pub decision: GateDecision,
    pub score_bps: u64,
    pub critical_score_bps: u64,
    pub open_blockers: u64,
    pub missing_component_root: String,
    pub reason_root: String,
    pub height: u64,
}

impl GateReceipt {
    pub fn new(
        window_id: &str,
        decision: GateDecision,
        score_bps: u64,
        critical_score_bps: u64,
        open_blockers: u64,
        missing_components: &[String],
        reason: &Value,
        height: u64,
    ) -> L2MvpExecutionControlPlaneResult<Self> {
        if window_id.is_empty() {
            return Err("gate receipt window id cannot be empty".to_string());
        }
        let missing_component_root = merkle_root(
            "L2-MVP-GATE-MISSING-COMPONENTS",
            &missing_components
                .iter()
                .map(|component| Value::String(component.clone()))
                .collect::<Vec<_>>(),
        );
        let reason_root = l2_mvp_execution_control_plane_payload_root("L2-MVP-GATE-REASON", reason);
        let receipt_id = gate_receipt_id(
            window_id,
            decision,
            score_bps,
            critical_score_bps,
            open_blockers,
            &missing_component_root,
            &reason_root,
            height,
        );
        Ok(Self {
            receipt_id,
            window_id: window_id.to_string(),
            decision,
            score_bps,
            critical_score_bps,
            open_blockers,
            missing_component_root,
            reason_root,
            height,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "l2_mvp_gate_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "receipt_id": self.receipt_id,
            "window_id": self.window_id,
            "decision": self.decision.as_str(),
            "score_bps": self.score_bps,
            "critical_score_bps": self.critical_score_bps,
            "open_blockers": self.open_blockers,
            "missing_component_root": self.missing_component_root,
            "reason_root": self.reason_root,
            "height": self.height,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roots {
    pub config_root: String,
    pub component_root: String,
    pub window_root: String,
    pub blocker_root: String,
    pub receipt_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "component_root": self.component_root,
            "window_root": self.window_root,
            "blocker_root": self.blocker_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub component_count: u64,
    pub window_count: u64,
    pub blocker_count: u64,
    pub open_blocker_count: u64,
    pub receipt_count: u64,
    pub open_receipt_count: u64,
    pub hold_receipt_count: u64,
    pub global_score_bps: u64,
    pub critical_score_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "component_count": self.component_count,
            "window_count": self.window_count,
            "blocker_count": self.blocker_count,
            "open_blocker_count": self.open_blocker_count,
            "receipt_count": self.receipt_count,
            "open_receipt_count": self.open_receipt_count,
            "hold_receipt_count": self.hold_receipt_count,
            "global_score_bps": self.global_score_bps,
            "critical_score_bps": self.critical_score_bps,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub height: u64,
    pub config: Config,
    pub components: BTreeMap<String, ComponentReadiness>,
    pub windows: BTreeMap<String, ExecutionWindow>,
    pub blockers: BTreeMap<String, ControlPlaneBlocker>,
    pub receipts: BTreeMap<String, GateReceipt>,
    pub roots: Roots,
    pub counters: Counters,
    pub state_root: String,
}

impl State {
    pub fn new(height: u64, config: Config) -> L2MvpExecutionControlPlaneResult<Self> {
        config.validate()?;
        let mut state = Self {
            height,
            config,
            components: BTreeMap::new(),
            windows: BTreeMap::new(),
            blockers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            roots: Roots {
                config_root: String::new(),
                component_root: String::new(),
                window_root: String::new(),
                blocker_root: String::new(),
                receipt_root: String::new(),
            },
            counters: Counters {
                component_count: 0,
                window_count: 0,
                blocker_count: 0,
                open_blocker_count: 0,
                receipt_count: 0,
                open_receipt_count: 0,
                hold_receipt_count: 0,
                global_score_bps: 0,
                critical_score_bps: 0,
            },
            state_root: String::new(),
        };
        state.refresh();
        Ok(state)
    }

    pub fn insert_component(
        &mut self,
        component: ComponentReadiness,
    ) -> L2MvpExecutionControlPlaneResult<()> {
        if self.components.len() >= L2_MVP_EXECUTION_CONTROL_PLANE_MAX_COMPONENTS {
            return Err("control plane component limit exceeded".to_string());
        }
        self.components
            .insert(component.component_id.clone(), component);
        self.refresh();
        Ok(())
    }

    pub fn insert_window(
        &mut self,
        window: ExecutionWindow,
    ) -> L2MvpExecutionControlPlaneResult<()> {
        if self.windows.len() >= L2_MVP_EXECUTION_CONTROL_PLANE_MAX_WINDOWS {
            return Err("control plane window limit exceeded".to_string());
        }
        self.windows.insert(window.window_id.clone(), window);
        self.refresh();
        Ok(())
    }

    pub fn insert_blocker(
        &mut self,
        blocker: ControlPlaneBlocker,
    ) -> L2MvpExecutionControlPlaneResult<()> {
        if self.blockers.len() >= L2_MVP_EXECUTION_CONTROL_PLANE_MAX_BLOCKERS {
            return Err("control plane blocker limit exceeded".to_string());
        }
        self.blockers.insert(blocker.blocker_id.clone(), blocker);
        self.refresh();
        Ok(())
    }

    pub fn insert_receipt(&mut self, receipt: GateReceipt) -> L2MvpExecutionControlPlaneResult<()> {
        if self.receipts.len() >= L2_MVP_EXECUTION_CONTROL_PLANE_MAX_RECEIPTS {
            return Err("control plane receipt limit exceeded".to_string());
        }
        self.receipts.insert(receipt.receipt_id.clone(), receipt);
        self.refresh();
        Ok(())
    }

    pub fn component_by_kind(
        &self,
        kind: ControlPlaneComponentKind,
    ) -> Option<&ComponentReadiness> {
        self.components
            .values()
            .filter(|component| component.component_kind == kind)
            .max_by_key(|component| component.last_updated_height)
    }

    pub fn open_blockers(&self) -> Vec<&ControlPlaneBlocker> {
        self.blockers
            .values()
            .filter(|blocker| !blocker.resolved)
            .collect()
    }

    pub fn global_score_bps(&self) -> u64 {
        if self.components.is_empty() {
            return 0;
        }
        let component_score = self
            .components
            .values()
            .map(|component| component.effective_score(&self.config))
            .fold(0_u64, u64::saturating_add)
            / self.components.len() as u64;
        let blocker_penalty = self
            .open_blockers()
            .iter()
            .map(|blocker| blocker.severity.penalty_bps())
            .fold(0_u64, u64::saturating_add);
        component_score.saturating_sub(blocker_penalty)
    }

    pub fn critical_score_bps(&self) -> u64 {
        let critical = self
            .components
            .values()
            .filter(|component| component.component_kind.critical())
            .collect::<Vec<_>>();
        if critical.is_empty() {
            return 0;
        }
        critical
            .iter()
            .map(|component| component.effective_score(&self.config))
            .fold(0_u64, u64::saturating_add)
            / critical.len() as u64
    }

    pub fn evaluate_window(
        &self,
        window: &ExecutionWindow,
    ) -> L2MvpExecutionControlPlaneResult<GateReceipt> {
        let mut missing = Vec::new();
        let mut required_scores = Vec::new();
        for kind in &window.required_components {
            match self.component_by_kind(*kind) {
                Some(component) => {
                    required_scores.push(component.effective_score(&self.config));
                    if component.fee_bps > window.max_fee_bps {
                        missing.push(format!("{}:fee_cap", kind.as_str()));
                    }
                    if component.privacy_set < window.min_privacy_set {
                        missing.push(format!("{}:privacy_set", kind.as_str()));
                    }
                }
                None => missing.push(format!("{}:missing", kind.as_str())),
            }
        }
        let score_bps = if required_scores.is_empty() {
            0
        } else {
            required_scores
                .iter()
                .fold(0_u64, |acc, value| acc.saturating_add(*value))
                / required_scores.len() as u64
        };
        let critical_score_bps = self.critical_score_bps();
        let open_blockers = self.open_blockers().len() as u64;
        let decision = if !window.active_at(self.height) {
            GateDecision::Hold
        } else if !missing.is_empty()
            || open_blockers > self.config.max_open_blockers
            || critical_score_bps < self.config.min_critical_score_bps
        {
            if window.window_kind == ExecutionWindowKind::EmergencyExit
                && critical_score_bps >= self.config.min_global_score_bps
            {
                GateDecision::EmergencyOnly
            } else {
                GateDecision::Hold
            }
        } else if score_bps >= self.config.min_global_score_bps {
            GateDecision::Open
        } else {
            GateDecision::OpenWithWarnings
        };
        GateReceipt::new(
            &window.window_id,
            decision,
            score_bps,
            critical_score_bps,
            open_blockers,
            &missing,
            &json!({
                "window_kind": window.window_kind.as_str(),
                "active": window.active_at(self.height),
                "required_components": window.required_components.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
                "missing": missing,
            }),
            self.height,
        )
    }

    pub fn evaluate_active_windows(&mut self) -> L2MvpExecutionControlPlaneResult<Vec<String>> {
        let mut created = Vec::new();
        let windows = self.windows.values().cloned().collect::<Vec<_>>();
        for window in windows {
            if self.receipts.values().any(|receipt| {
                receipt.window_id == window.window_id && receipt.height == self.height
            }) {
                continue;
            }
            let receipt = self.evaluate_window(&window)?;
            created.push(receipt.receipt_id.clone());
            self.insert_receipt(receipt)?;
        }
        Ok(created)
    }

    pub fn refresh(&mut self) {
        self.roots = Roots {
            config_root: l2_mvp_execution_control_plane_payload_root(
                "L2-MVP-CONTROL-PLANE-CONFIG",
                &self.config.public_record(),
            ),
            component_root: component_readiness_root(
                &self.components.values().cloned().collect::<Vec<_>>(),
            ),
            window_root: execution_window_root(&self.windows.values().cloned().collect::<Vec<_>>()),
            blocker_root: control_plane_blocker_root(
                &self.blockers.values().cloned().collect::<Vec<_>>(),
            ),
            receipt_root: gate_receipt_root(&self.receipts.values().cloned().collect::<Vec<_>>()),
        };
        self.counters = Counters {
            component_count: self.components.len() as u64,
            window_count: self.windows.len() as u64,
            blocker_count: self.blockers.len() as u64,
            open_blocker_count: self.open_blockers().len() as u64,
            receipt_count: self.receipts.len() as u64,
            open_receipt_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == GateDecision::Open)
                .count() as u64,
            hold_receipt_count: self
                .receipts
                .values()
                .filter(|receipt| receipt.decision == GateDecision::Hold)
                .count() as u64,
            global_score_bps: self.global_score_bps(),
            critical_score_bps: self.critical_score_bps(),
        };
        self.state_root = root_from_record(&self.public_record_without_state_root());
    }

    fn public_record_without_state_root(&self) -> Value {
        json!({
            "kind": "l2_mvp_execution_control_plane_state",
            "chain_id": CHAIN_ID,
            "protocol_version": L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION,
            "height": self.height,
            "roots": self.roots.public_record(),
            "counters": self.counters.public_record(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_state_root();
        if let Value::Object(ref mut values) = record {
            values.insert("state_root".to_string(), json!(self.state_root));
        }
        record
    }

    pub fn devnet() -> L2MvpExecutionControlPlaneResult<Self> {
        let mut state = Self::new(
            L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT,
            Config::devnet(),
        )?;
        for (kind, label, score, latency, fee, privacy, pq) in [
            (
                ControlPlaneComponentKind::MoneroSettlement,
                "monero-pq-fast-exit",
                9_700,
                3,
                30,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::PqRuntime,
                "pq-contract-runtime-ledger",
                9_850,
                1,
                8,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::PrivateContractExecution,
                "private-contract-execution",
                9_400,
                2,
                24,
                384,
                256,
            ),
            (
                ControlPlaneComponentKind::DefiLiquidity,
                "private-defi-liquidity",
                9_250,
                2,
                22,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::LowFeeProofs,
                "low-fee-proof-sponsor",
                9_500,
                2,
                18,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::PrivacyFirewall,
                "zk-privacy-budget-firewall",
                9_900,
                1,
                5,
                512,
                256,
            ),
            (
                ControlPlaneComponentKind::OperatorReadiness,
                "operator-supervision",
                9_700,
                1,
                0,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::DataAvailability,
                "private-da-market",
                9_200,
                3,
                20,
                256,
                256,
            ),
            (
                ControlPlaneComponentKind::SequencerFastPath,
                "fast-private-sequencer",
                9_600,
                1,
                12,
                256,
                256,
            ),
        ] {
            state.insert_component(ComponentReadiness::new(
                kind,
                label,
                &format!("state-root-{label}"),
                score,
                latency,
                fee,
                privacy,
                pq,
                L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT,
            )?)?;
        }
        state.insert_window(ExecutionWindow::new(
            ExecutionWindowKind::PrivateContractCall,
            "devnet-private-contract-call-window",
            &json!({"contract_bundle": "private-amm-call", "proof_class": "contract_call"}),
            L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT.saturating_sub(1),
            L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT.saturating_add(16),
            35,
            256,
        )?)?;
        state.insert_window(ExecutionWindow::new(
            ExecutionWindowKind::BridgeExit,
            "devnet-monero-fast-exit-window",
            &json!({"exit_lane": "fast", "asset": "wxmr"}),
            L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT.saturating_sub(1),
            L2_MVP_EXECUTION_CONTROL_PLANE_DEVNET_HEIGHT.saturating_add(12),
            40,
            256,
        )?)?;
        state.evaluate_active_windows()?;
        Ok(state)
    }
}

pub fn component_readiness_id(
    component_kind: ControlPlaneComponentKind,
    label: &str,
    state_root: &str,
    score_bps: u64,
    latency_blocks: u64,
    fee_bps: u64,
    last_updated_height: u64,
) -> String {
    domain_hash(
        "L2-MVP-COMPONENT-READINESS-ID",
        &[
            HashPart::Str(L2_MVP_EXECUTION_CONTROL_PLANE_PROTOCOL_VERSION),
            HashPart::Str(component_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(state_root),
            HashPart::Int(score_bps as i128),
            HashPart::Int(latency_blocks as i128),
            HashPart::Int(fee_bps as i128),
            HashPart::Int(last_updated_height as i128),
        ],
        32,
    )
}

pub fn execution_window_id(
    window_kind: ExecutionWindowKind,
    label: &str,
    demand_root: &str,
    opens_at_height: u64,
    expires_at_height: u64,
    max_fee_bps: u64,
    min_privacy_set: u64,
) -> String {
    domain_hash(
        "L2-MVP-EXECUTION-WINDOW-ID",
        &[
            HashPart::Str(window_kind.as_str()),
            HashPart::Str(label),
            HashPart::Str(demand_root),
            HashPart::Int(opens_at_height as i128),
            HashPart::Int(expires_at_height as i128),
            HashPart::Int(max_fee_bps as i128),
            HashPart::Int(min_privacy_set as i128),
        ],
        32,
    )
}

pub fn control_plane_blocker_id(
    component_kind: ControlPlaneComponentKind,
    severity: BlockerSeverity,
    label: &str,
    evidence_root: &str,
    opened_at_height: u64,
) -> String {
    domain_hash(
        "L2-MVP-CONTROL-PLANE-BLOCKER-ID",
        &[
            HashPart::Str(component_kind.as_str()),
            HashPart::Str(severity.as_str()),
            HashPart::Str(label),
            HashPart::Str(evidence_root),
            HashPart::Int(opened_at_height as i128),
        ],
        32,
    )
}

pub fn gate_receipt_id(
    window_id: &str,
    decision: GateDecision,
    score_bps: u64,
    critical_score_bps: u64,
    open_blockers: u64,
    missing_component_root: &str,
    reason_root: &str,
    height: u64,
) -> String {
    domain_hash(
        "L2-MVP-GATE-RECEIPT-ID",
        &[
            HashPart::Str(window_id),
            HashPart::Str(decision.as_str()),
            HashPart::Int(score_bps as i128),
            HashPart::Int(critical_score_bps as i128),
            HashPart::Int(open_blockers as i128),
            HashPart::Str(missing_component_root),
            HashPart::Str(reason_root),
            HashPart::Int(height as i128),
        ],
        32,
    )
}

pub fn component_readiness_root(components: &[ComponentReadiness]) -> String {
    let leaves = components
        .iter()
        .map(ComponentReadiness::public_record)
        .collect::<Vec<_>>();
    merkle_root("L2-MVP-COMPONENT-READINESS", &leaves)
}

pub fn execution_window_root(windows: &[ExecutionWindow]) -> String {
    let leaves = windows
        .iter()
        .map(ExecutionWindow::public_record)
        .collect::<Vec<_>>();
    merkle_root("L2-MVP-EXECUTION-WINDOWS", &leaves)
}

pub fn control_plane_blocker_root(blockers: &[ControlPlaneBlocker]) -> String {
    let leaves = blockers
        .iter()
        .map(ControlPlaneBlocker::public_record)
        .collect::<Vec<_>>();
    merkle_root("L2-MVP-CONTROL-PLANE-BLOCKERS", &leaves)
}

pub fn gate_receipt_root(receipts: &[GateReceipt]) -> String {
    let leaves = receipts
        .iter()
        .map(GateReceipt::public_record)
        .collect::<Vec<_>>();
    merkle_root("L2-MVP-GATE-RECEIPTS", &leaves)
}

pub fn l2_mvp_execution_control_plane_payload_root(domain: &str, payload: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(payload)], 32)
}

pub fn root_from_record(record: &Value) -> String {
    domain_hash(
        "L2-MVP-EXECUTION-CONTROL-PLANE-STATE-ROOT",
        &[HashPart::Json(record)],
        32,
    )
}

pub fn devnet() -> L2MvpExecutionControlPlaneResult<State> {
    State::devnet()
}
