use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;

pub const PROTOCOL_VERSION: &str =
    "nebula-private-l2-pq-confidential-operator-progress-feed-runtime-v1";
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const PANEL_FEED_SCHEMA: &str = "nebula-l2-progress-panel-json-v1";
pub const WORKER_COORDINATION_SCHEME: &str = "bounded-gpt-5-5-worker-progress-root-v1";
pub const FEATURE_SCORE_SCHEME: &str = "pq-private-l2-feature-scorecard-bps-v1";
pub const MODULE_RECEIPT_SCHEME: &str = "deterministic-runtime-module-receipt-root-v1";
pub const DEFAULT_DEVNET_HEIGHT: u64 = 1_180_000;
pub const MAX_BPS: u64 = 10_000;
pub const DEFAULT_MAX_FEATURES: usize = 128;
pub const DEFAULT_MAX_WORKERS: usize = 64;
pub const DEFAULT_MAX_MODULE_RECEIPTS: usize = 4_096;
pub const DEFAULT_MAX_ACTIVITIES: usize = 8_192;
pub const DEFAULT_MAX_QUEUE_ITEMS: usize = 2_048;
pub const DEFAULT_MAX_PANEL_SNAPSHOTS: usize = 2_048;
pub const DEFAULT_MIN_READY_FEATURE_BPS: u64 = 7_500;
pub const DEFAULT_MIN_READY_OVERALL_BPS: u64 = 7_000;
pub const DEFAULT_MAX_STALE_WORKER_BLOCKS: u64 = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKind {
    QuantumResistance,
    Speed,
    DefiSmartContracts,
    LowFees,
    Privacy,
    MoneroBridge,
    OperatorVisibility,
    WalletDeveloperApi,
    DevnetScenarioRunner,
    RuntimeReadiness,
}

impl FeatureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QuantumResistance => "quantum_resistance",
            Self::Speed => "speed",
            Self::DefiSmartContracts => "defi_smart_contracts",
            Self::LowFees => "low_fees",
            Self::Privacy => "privacy",
            Self::MoneroBridge => "monero_bridge",
            Self::OperatorVisibility => "operator_visibility",
            Self::WalletDeveloperApi => "wallet_developer_api",
            Self::DevnetScenarioRunner => "devnet_scenario_runner",
            Self::RuntimeReadiness => "runtime_readiness",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::QuantumResistance => "Quantum Resistance",
            Self::Speed => "Speed",
            Self::DefiSmartContracts => "DeFi And Smart Contracts",
            Self::LowFees => "Low Fees",
            Self::Privacy => "Privacy",
            Self::MoneroBridge => "Monero Bridge",
            Self::OperatorVisibility => "Operator Visibility",
            Self::WalletDeveloperApi => "Wallet Developer API",
            Self::DevnetScenarioRunner => "Devnet Scenario Runner",
            Self::RuntimeReadiness => "Runtime Readiness",
        }
    }

    pub fn priority_weight_bps(self) -> u64 {
        match self {
            Self::QuantumResistance => 1_600,
            Self::Privacy => 1_400,
            Self::Speed => 1_250,
            Self::DefiSmartContracts => 1_250,
            Self::LowFees => 1_150,
            Self::MoneroBridge => 1_100,
            Self::RuntimeReadiness => 850,
            Self::WalletDeveloperApi => 600,
            Self::DevnetScenarioRunner => 500,
            Self::OperatorVisibility => 300,
        }
    }

    pub fn privacy_sensitive(self) -> bool {
        matches!(
            self,
            Self::Privacy
                | Self::MoneroBridge
                | Self::DefiSmartContracts
                | Self::WalletDeveloperApi
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkStatus {
    Queued,
    Drafting,
    Integrating,
    Formatted,
    Scanned,
    CompileDeferred,
    Compiled,
    Blocked,
    Complete,
}

impl WorkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Drafting => "drafting",
            Self::Integrating => "integrating",
            Self::Formatted => "formatted",
            Self::Scanned => "scanned",
            Self::CompileDeferred => "compile_deferred",
            Self::Compiled => "compiled",
            Self::Blocked => "blocked",
            Self::Complete => "complete",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(self, Self::Compiled | Self::Blocked | Self::Complete)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerKind {
    LocalCodex,
    Gpt55Worker,
    Gpt54Worker,
    Explorer,
    Verifier,
}

impl WorkerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalCodex => "local_codex",
            Self::Gpt55Worker => "gpt_5_5_worker",
            Self::Gpt54Worker => "gpt_5_4_worker",
            Self::Explorer => "explorer",
            Self::Verifier => "verifier",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityKind {
    FeatureWaveStarted,
    WorkerSpawned,
    ModuleDrafted,
    ModuleIntegrated,
    PanelUpdated,
    LightweightGate,
    CompileGate,
    RiskRaised,
    RiskCleared,
}

impl ActivityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FeatureWaveStarted => "feature_wave_started",
            Self::WorkerSpawned => "worker_spawned",
            Self::ModuleDrafted => "module_drafted",
            Self::ModuleIntegrated => "module_integrated",
            Self::PanelUpdated => "panel_updated",
            Self::LightweightGate => "lightweight_gate",
            Self::CompileGate => "compile_gate",
            Self::RiskRaised => "risk_raised",
            Self::RiskCleared => "risk_cleared",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Config {
    pub protocol_version: String,
    pub chain_id: String,
    pub panel_feed_schema: String,
    pub worker_coordination_scheme: String,
    pub feature_score_scheme: String,
    pub module_receipt_scheme: String,
    pub min_ready_feature_bps: u64,
    pub min_ready_overall_bps: u64,
    pub max_stale_worker_blocks: u64,
    pub max_features: usize,
    pub max_workers: usize,
    pub max_module_receipts: usize,
    pub max_activities: usize,
    pub max_queue_items: usize,
    pub max_panel_snapshots: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.to_string(),
            chain_id: CHAIN_ID.to_string(),
            panel_feed_schema: PANEL_FEED_SCHEMA.to_string(),
            worker_coordination_scheme: WORKER_COORDINATION_SCHEME.to_string(),
            feature_score_scheme: FEATURE_SCORE_SCHEME.to_string(),
            module_receipt_scheme: MODULE_RECEIPT_SCHEME.to_string(),
            min_ready_feature_bps: DEFAULT_MIN_READY_FEATURE_BPS,
            min_ready_overall_bps: DEFAULT_MIN_READY_OVERALL_BPS,
            max_stale_worker_blocks: DEFAULT_MAX_STALE_WORKER_BLOCKS,
            max_features: DEFAULT_MAX_FEATURES,
            max_workers: DEFAULT_MAX_WORKERS,
            max_module_receipts: DEFAULT_MAX_MODULE_RECEIPTS,
            max_activities: DEFAULT_MAX_ACTIVITIES,
            max_queue_items: DEFAULT_MAX_QUEUE_ITEMS,
            max_panel_snapshots: DEFAULT_MAX_PANEL_SNAPSHOTS,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err("operator progress feed protocol version mismatch".to_string());
        }
        if self.chain_id != CHAIN_ID {
            return Err("operator progress feed chain id mismatch".to_string());
        }
        if self.panel_feed_schema != PANEL_FEED_SCHEMA {
            return Err("operator progress feed panel schema mismatch".to_string());
        }
        if self.worker_coordination_scheme != WORKER_COORDINATION_SCHEME {
            return Err("operator progress feed worker scheme mismatch".to_string());
        }
        if self.feature_score_scheme != FEATURE_SCORE_SCHEME
            || self.module_receipt_scheme != MODULE_RECEIPT_SCHEME
        {
            return Err("operator progress feed commitment scheme mismatch".to_string());
        }
        if self.min_ready_feature_bps > MAX_BPS || self.min_ready_overall_bps > MAX_BPS {
            return Err("operator progress feed ready score above max".to_string());
        }
        if self.max_features == 0
            || self.max_workers == 0
            || self.max_module_receipts == 0
            || self.max_activities == 0
            || self.max_queue_items == 0
            || self.max_panel_snapshots == 0
        {
            return Err("operator progress feed capacity cannot be zero".to_string());
        }
        Ok(())
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_feed_config",
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": SCHEMA_VERSION,
            "hash_suite": HASH_SUITE,
            "panel_feed_schema": self.panel_feed_schema,
            "worker_coordination_scheme": self.worker_coordination_scheme,
            "feature_score_scheme": self.feature_score_scheme,
            "module_receipt_scheme": self.module_receipt_scheme,
            "min_ready_feature_bps": self.min_ready_feature_bps,
            "min_ready_overall_bps": self.min_ready_overall_bps,
            "max_stale_worker_blocks": self.max_stale_worker_blocks,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FeatureProgress {
    pub feature_id: String,
    pub feature_kind: FeatureKind,
    pub label: String,
    pub percent_bps: u64,
    pub priority_weight_bps: u64,
    pub evidence_root: String,
    pub note_root: String,
    pub blocker_root: String,
    pub updated_at_height: u64,
    pub privacy_sensitive: bool,
}

impl FeatureProgress {
    pub fn new(
        feature_kind: FeatureKind,
        percent_bps: u64,
        evidence: &Value,
        note: &str,
        blockers: &[String],
        updated_at_height: u64,
    ) -> Result<Self> {
        if percent_bps > MAX_BPS {
            return Err("feature progress percent above max".to_string());
        }
        let evidence_root = value_root("OPERATOR-PROGRESS-FEATURE-EVIDENCE", evidence);
        let note_root = string_root("OPERATOR-PROGRESS-FEATURE-NOTE", note);
        let blocker_root = string_set_root("OPERATOR-PROGRESS-FEATURE-BLOCKERS", blockers);
        let priority_weight_bps = feature_kind.priority_weight_bps();
        let feature_id = feature_id(
            feature_kind,
            percent_bps,
            priority_weight_bps,
            &evidence_root,
            &note_root,
            &blocker_root,
            updated_at_height,
        );
        Ok(Self {
            feature_id,
            feature_kind,
            label: feature_kind.label().to_string(),
            percent_bps,
            priority_weight_bps,
            evidence_root,
            note_root,
            blocker_root,
            updated_at_height,
            privacy_sensitive: feature_kind.privacy_sensitive(),
        })
    }

    pub fn ready(&self, config: &Config) -> bool {
        self.percent_bps >= config.min_ready_feature_bps
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_feature",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "feature_id": self.feature_id,
            "feature_kind": self.feature_kind.as_str(),
            "label": self.label,
            "percent_bps": self.percent_bps,
            "priority_weight_bps": self.priority_weight_bps,
            "evidence_root": self.evidence_root,
            "note_root": self.note_root,
            "blocker_root": self.blocker_root,
            "updated_at_height": self.updated_at_height,
            "privacy_sensitive": self.privacy_sensitive,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkerHeartbeat {
    pub worker_id: String,
    pub worker_kind: WorkerKind,
    pub label_commitment: String,
    pub owned_path_root: String,
    pub current_task_root: String,
    pub reasoning_mode: String,
    pub status: WorkStatus,
    pub last_height: u64,
    pub produced_loc: u64,
    pub confidence_bps: u64,
    pub privacy_risk_bps: u64,
}

impl WorkerHeartbeat {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        worker_kind: WorkerKind,
        label: &str,
        owned_paths: &[String],
        current_task: &str,
        reasoning_mode: &str,
        status: WorkStatus,
        last_height: u64,
        produced_loc: u64,
        confidence_bps: u64,
        privacy_risk_bps: u64,
    ) -> Result<Self> {
        if label.is_empty() || current_task.is_empty() || reasoning_mode.is_empty() {
            return Err("worker heartbeat labels cannot be empty".to_string());
        }
        if confidence_bps > MAX_BPS || privacy_risk_bps > MAX_BPS {
            return Err("worker heartbeat bps above max".to_string());
        }
        let label_commitment = string_root("OPERATOR-PROGRESS-WORKER-LABEL", label);
        let owned_path_root = string_set_root("OPERATOR-PROGRESS-WORKER-PATHS", owned_paths);
        let current_task_root = string_root("OPERATOR-PROGRESS-WORKER-TASK", current_task);
        let worker_id = worker_id(
            worker_kind,
            &label_commitment,
            &owned_path_root,
            &current_task_root,
            reasoning_mode,
            last_height,
        );
        Ok(Self {
            worker_id,
            worker_kind,
            label_commitment,
            owned_path_root,
            current_task_root,
            reasoning_mode: reasoning_mode.to_string(),
            status,
            last_height,
            produced_loc,
            confidence_bps,
            privacy_risk_bps,
        })
    }

    pub fn stale_at(&self, height: u64, config: &Config) -> bool {
        height.saturating_sub(self.last_height) > config.max_stale_worker_blocks
            && !self.status.terminal()
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_worker_heartbeat",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "worker_id": self.worker_id,
            "worker_kind": self.worker_kind.as_str(),
            "label_commitment": self.label_commitment,
            "owned_path_root": self.owned_path_root,
            "current_task_root": self.current_task_root,
            "reasoning_mode": self.reasoning_mode,
            "status": self.status.as_str(),
            "last_height": self.last_height,
            "produced_loc": self.produced_loc,
            "confidence_bps": self.confidence_bps,
            "privacy_risk_bps": self.privacy_risk_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeModuleReceipt {
    pub module_id: String,
    pub module_name: String,
    pub file_path_root: String,
    pub loc: u64,
    pub priority_feature: FeatureKind,
    pub state_root: String,
    pub public_api_root: String,
    pub integrated_lib: bool,
    pub integrated_devnet: bool,
    pub integrated_operator: bool,
    pub fmt_clean: bool,
    pub scan_clean: bool,
    pub compiled: bool,
    pub recorded_at_height: u64,
}

impl RuntimeModuleReceipt {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        module_name: &str,
        file_path: &str,
        loc: u64,
        priority_feature: FeatureKind,
        state: &Value,
        public_api: &[String],
        integrated_lib: bool,
        integrated_devnet: bool,
        integrated_operator: bool,
        fmt_clean: bool,
        scan_clean: bool,
        compiled: bool,
        recorded_at_height: u64,
    ) -> Result<Self> {
        if module_name.is_empty() || file_path.is_empty() {
            return Err("runtime module receipt identifiers cannot be empty".to_string());
        }
        let file_path_root = string_root("OPERATOR-PROGRESS-MODULE-PATH", file_path);
        let state_root = value_root("OPERATOR-PROGRESS-MODULE-STATE", state);
        let public_api_root = string_set_root("OPERATOR-PROGRESS-MODULE-API", public_api);
        let module_id = module_id(
            module_name,
            &file_path_root,
            loc,
            priority_feature,
            &state_root,
            &public_api_root,
            recorded_at_height,
        );
        Ok(Self {
            module_id,
            module_name: module_name.to_string(),
            file_path_root,
            loc,
            priority_feature,
            state_root,
            public_api_root,
            integrated_lib,
            integrated_devnet,
            integrated_operator,
            fmt_clean,
            scan_clean,
            compiled,
            recorded_at_height,
        })
    }

    pub fn fully_integrated(&self) -> bool {
        self.integrated_lib && self.integrated_devnet && self.integrated_operator
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_runtime_module_receipt",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "module_id": self.module_id,
            "module_name": self.module_name,
            "file_path_root": self.file_path_root,
            "loc": self.loc,
            "priority_feature": self.priority_feature.as_str(),
            "state_root": self.state_root,
            "public_api_root": self.public_api_root,
            "integrated_lib": self.integrated_lib,
            "integrated_devnet": self.integrated_devnet,
            "integrated_operator": self.integrated_operator,
            "fmt_clean": self.fmt_clean,
            "scan_clean": self.scan_clean,
            "compiled": self.compiled,
            "recorded_at_height": self.recorded_at_height,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProgressActivity {
    pub activity_id: String,
    pub activity_kind: ActivityKind,
    pub height: u64,
    pub summary_root: String,
    pub detail_root: String,
    pub related_root: String,
    pub visible_to_panel: bool,
}

impl ProgressActivity {
    pub fn new(
        activity_kind: ActivityKind,
        height: u64,
        summary: &str,
        detail: &Value,
        related_ids: &[String],
        visible_to_panel: bool,
    ) -> Result<Self> {
        if summary.is_empty() {
            return Err("progress activity summary cannot be empty".to_string());
        }
        let summary_root = string_root("OPERATOR-PROGRESS-ACTIVITY-SUMMARY", summary);
        let detail_root = value_root("OPERATOR-PROGRESS-ACTIVITY-DETAIL", detail);
        let related_root = string_set_root("OPERATOR-PROGRESS-ACTIVITY-RELATED", related_ids);
        let activity_id = activity_id(
            activity_kind,
            height,
            &summary_root,
            &detail_root,
            &related_root,
            visible_to_panel,
        );
        Ok(Self {
            activity_id,
            activity_kind,
            height,
            summary_root,
            detail_root,
            related_root,
            visible_to_panel,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_activity",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "activity_id": self.activity_id,
            "activity_kind": self.activity_kind.as_str(),
            "height": self.height,
            "summary_root": self.summary_root,
            "detail_root": self.detail_root,
            "related_root": self.related_root,
            "visible_to_panel": self.visible_to_panel,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkQueueItem {
    pub item_id: String,
    pub feature_kind: FeatureKind,
    pub title_root: String,
    pub scope_root: String,
    pub target_loc: u64,
    pub status: WorkStatus,
    pub assigned_worker_root: String,
    pub due_height: u64,
    pub risk_bps: u64,
}

impl WorkQueueItem {
    pub fn new(
        feature_kind: FeatureKind,
        title: &str,
        scope: &Value,
        target_loc: u64,
        status: WorkStatus,
        assigned_workers: &[String],
        due_height: u64,
        risk_bps: u64,
    ) -> Result<Self> {
        if title.is_empty() {
            return Err("work queue title cannot be empty".to_string());
        }
        if risk_bps > MAX_BPS {
            return Err("work queue risk above max".to_string());
        }
        let title_root = string_root("OPERATOR-PROGRESS-QUEUE-TITLE", title);
        let scope_root = value_root("OPERATOR-PROGRESS-QUEUE-SCOPE", scope);
        let assigned_worker_root =
            string_set_root("OPERATOR-PROGRESS-QUEUE-WORKERS", assigned_workers);
        let item_id = queue_item_id(
            feature_kind,
            &title_root,
            &scope_root,
            target_loc,
            status,
            &assigned_worker_root,
            due_height,
            risk_bps,
        );
        Ok(Self {
            item_id,
            feature_kind,
            title_root,
            scope_root,
            target_loc,
            status,
            assigned_worker_root,
            due_height,
            risk_bps,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_queue_item",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "item_id": self.item_id,
            "feature_kind": self.feature_kind.as_str(),
            "title_root": self.title_root,
            "scope_root": self.scope_root,
            "target_loc": self.target_loc,
            "status": self.status.as_str(),
            "assigned_worker_root": self.assigned_worker_root,
            "due_height": self.due_height,
            "risk_bps": self.risk_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PanelSnapshot {
    pub snapshot_id: String,
    pub height: u64,
    pub overall_percent_bps: u64,
    pub feature_root: String,
    pub worker_root: String,
    pub module_root: String,
    pub activity_root: String,
    pub queue_root: String,
    pub summary_root: String,
    pub stale_worker_root: String,
    pub ready: bool,
}

impl PanelSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        overall_percent_bps: u64,
        feature_root: &str,
        worker_root: &str,
        module_root: &str,
        activity_root: &str,
        queue_root: &str,
        summary: &str,
        stale_worker_ids: &[String],
        ready: bool,
    ) -> Result<Self> {
        if overall_percent_bps > MAX_BPS {
            return Err("panel snapshot percent above max".to_string());
        }
        let summary_root = string_root("OPERATOR-PROGRESS-PANEL-SUMMARY", summary);
        let stale_worker_root =
            string_set_root("OPERATOR-PROGRESS-PANEL-STALE-WORKERS", stale_worker_ids);
        let snapshot_id = panel_snapshot_id(
            height,
            overall_percent_bps,
            feature_root,
            worker_root,
            module_root,
            activity_root,
            queue_root,
            &summary_root,
            &stale_worker_root,
            ready,
        );
        Ok(Self {
            snapshot_id,
            height,
            overall_percent_bps,
            feature_root: feature_root.to_string(),
            worker_root: worker_root.to_string(),
            module_root: module_root.to_string(),
            activity_root: activity_root.to_string(),
            queue_root: queue_root.to_string(),
            summary_root,
            stale_worker_root,
            ready,
        })
    }

    pub fn public_record(&self) -> Value {
        json!({
            "kind": "operator_progress_panel_snapshot",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "snapshot_id": self.snapshot_id,
            "height": self.height,
            "overall_percent_bps": self.overall_percent_bps,
            "feature_root": self.feature_root,
            "worker_root": self.worker_root,
            "module_root": self.module_root,
            "activity_root": self.activity_root,
            "queue_root": self.queue_root,
            "summary_root": self.summary_root,
            "stale_worker_root": self.stale_worker_root,
            "ready": self.ready,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Counters {
    pub features: u64,
    pub ready_features: u64,
    pub workers: u64,
    pub stale_workers: u64,
    pub module_receipts: u64,
    pub integrated_modules: u64,
    pub formatted_modules: u64,
    pub scanned_modules: u64,
    pub compiled_modules: u64,
    pub activities: u64,
    pub panel_visible_activities: u64,
    pub queued_items: u64,
    pub open_queue_items: u64,
    pub panel_snapshots: u64,
    pub total_recorded_loc: u64,
    pub overall_percent_bps: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "features": self.features,
            "ready_features": self.ready_features,
            "workers": self.workers,
            "stale_workers": self.stale_workers,
            "module_receipts": self.module_receipts,
            "integrated_modules": self.integrated_modules,
            "formatted_modules": self.formatted_modules,
            "scanned_modules": self.scanned_modules,
            "compiled_modules": self.compiled_modules,
            "activities": self.activities,
            "panel_visible_activities": self.panel_visible_activities,
            "queued_items": self.queued_items,
            "open_queue_items": self.open_queue_items,
            "panel_snapshots": self.panel_snapshots,
            "total_recorded_loc": self.total_recorded_loc,
            "overall_percent_bps": self.overall_percent_bps,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub feature_root: String,
    pub worker_root: String,
    pub module_root: String,
    pub activity_root: String,
    pub queue_root: String,
    pub panel_snapshot_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "feature_root": self.feature_root,
            "worker_root": self.worker_root,
            "module_root": self.module_root,
            "activity_root": self.activity_root,
            "queue_root": self.queue_root,
            "panel_snapshot_root": self.panel_snapshot_root,
            "state_root": self.state_root,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct State {
    pub config: Config,
    pub height: u64,
    pub features: BTreeMap<String, FeatureProgress>,
    pub workers: BTreeMap<String, WorkerHeartbeat>,
    pub module_receipts: BTreeMap<String, RuntimeModuleReceipt>,
    pub activities: BTreeMap<String, ProgressActivity>,
    pub queue_items: BTreeMap<String, WorkQueueItem>,
    pub panel_snapshots: BTreeMap<String, PanelSnapshot>,
}

impl State {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            height,
            features: BTreeMap::new(),
            workers: BTreeMap::new(),
            module_receipts: BTreeMap::new(),
            activities: BTreeMap::new(),
            queue_items: BTreeMap::new(),
            panel_snapshots: BTreeMap::new(),
        })
    }

    pub fn devnet() -> Self {
        let mut state = match Self::new(Config::devnet(), DEFAULT_DEVNET_HEIGHT) {
            Ok(state) => state,
            Err(_) => Self::empty_devnet_fallback(),
        };
        state.seed_devnet_progress();
        state
    }

    fn empty_devnet_fallback() -> Self {
        Self {
            config: Config::devnet(),
            height: DEFAULT_DEVNET_HEIGHT,
            features: BTreeMap::new(),
            workers: BTreeMap::new(),
            module_receipts: BTreeMap::new(),
            activities: BTreeMap::new(),
            queue_items: BTreeMap::new(),
            panel_snapshots: BTreeMap::new(),
        }
    }

    pub fn set_height(&mut self, height: u64) {
        self.height = height;
    }

    pub fn upsert_feature(&mut self, feature: FeatureProgress) -> Result<()> {
        if self.features.len() >= self.config.max_features
            && !self.features.contains_key(&feature.feature_id)
        {
            return Err("operator progress feed feature limit exceeded".to_string());
        }
        self.features
            .retain(|_, existing| existing.feature_kind != feature.feature_kind);
        self.features.insert(feature.feature_id.clone(), feature);
        Ok(())
    }

    pub fn upsert_worker(&mut self, worker: WorkerHeartbeat) -> Result<()> {
        if self.workers.len() >= self.config.max_workers
            && !self.workers.contains_key(&worker.worker_id)
        {
            return Err("operator progress feed worker limit exceeded".to_string());
        }
        self.workers
            .retain(|_, existing| existing.label_commitment != worker.label_commitment);
        self.workers.insert(worker.worker_id.clone(), worker);
        Ok(())
    }

    pub fn record_module(&mut self, receipt: RuntimeModuleReceipt) -> Result<()> {
        if self.module_receipts.len() >= self.config.max_module_receipts
            && !self.module_receipts.contains_key(&receipt.module_id)
        {
            return Err("operator progress feed module receipt limit exceeded".to_string());
        }
        self.module_receipts
            .retain(|_, existing| existing.module_name != receipt.module_name);
        self.module_receipts
            .insert(receipt.module_id.clone(), receipt);
        Ok(())
    }

    pub fn log_activity(&mut self, activity: ProgressActivity) -> Result<()> {
        if self.activities.len() >= self.config.max_activities
            && !self.activities.contains_key(&activity.activity_id)
        {
            let first_key = self.activities.keys().next().cloned();
            if let Some(first_key) = first_key {
                self.activities.remove(&first_key);
            }
        }
        self.activities
            .insert(activity.activity_id.clone(), activity);
        Ok(())
    }

    pub fn queue_work(&mut self, item: WorkQueueItem) -> Result<()> {
        if self.queue_items.len() >= self.config.max_queue_items
            && !self.queue_items.contains_key(&item.item_id)
        {
            return Err("operator progress feed queue limit exceeded".to_string());
        }
        self.queue_items.insert(item.item_id.clone(), item);
        Ok(())
    }

    pub fn snapshot_panel(&mut self, summary: &str) -> Result<PanelSnapshot> {
        let roots = self.roots();
        let stale_workers = self
            .workers
            .values()
            .filter(|worker| worker.stale_at(self.height, &self.config))
            .map(|worker| worker.worker_id.clone())
            .collect::<Vec<_>>();
        let overall_percent_bps = self.overall_percent_bps();
        let snapshot = PanelSnapshot::new(
            self.height,
            overall_percent_bps,
            &roots.feature_root,
            &roots.worker_root,
            &roots.module_root,
            &roots.activity_root,
            &roots.queue_root,
            summary,
            &stale_workers,
            overall_percent_bps >= self.config.min_ready_overall_bps && stale_workers.is_empty(),
        )?;
        if self.panel_snapshots.len() >= self.config.max_panel_snapshots
            && !self.panel_snapshots.contains_key(&snapshot.snapshot_id)
        {
            let first_key = self.panel_snapshots.keys().next().cloned();
            if let Some(first_key) = first_key {
                self.panel_snapshots.remove(&first_key);
            }
        }
        self.panel_snapshots
            .insert(snapshot.snapshot_id.clone(), snapshot.clone());
        Ok(snapshot)
    }

    pub fn overall_percent_bps(&self) -> u64 {
        let mut weighted_total = 0_u128;
        let mut weight_total = 0_u128;
        for feature in self.features.values() {
            weighted_total = weighted_total.saturating_add(
                (feature.percent_bps as u128).saturating_mul(feature.priority_weight_bps as u128),
            );
            weight_total = weight_total.saturating_add(feature.priority_weight_bps as u128);
        }
        if weight_total == 0 {
            0
        } else {
            (weighted_total / weight_total).min(MAX_BPS as u128) as u64
        }
    }

    pub fn stale_worker_ids(&self) -> Vec<String> {
        self.workers
            .values()
            .filter(|worker| worker.stale_at(self.height, &self.config))
            .map(|worker| worker.worker_id.clone())
            .collect()
    }

    pub fn feature_score_table(&self) -> BTreeMap<String, u64> {
        self.features
            .values()
            .map(|feature| {
                (
                    feature.feature_kind.as_str().to_string(),
                    feature.percent_bps,
                )
            })
            .collect()
    }

    pub fn counters(&self) -> Counters {
        let stale_workers = self.stale_worker_ids().len() as u64;
        Counters {
            features: self.features.len() as u64,
            ready_features: self
                .features
                .values()
                .filter(|feature| feature.ready(&self.config))
                .count() as u64,
            workers: self.workers.len() as u64,
            stale_workers,
            module_receipts: self.module_receipts.len() as u64,
            integrated_modules: self
                .module_receipts
                .values()
                .filter(|receipt| receipt.fully_integrated())
                .count() as u64,
            formatted_modules: self
                .module_receipts
                .values()
                .filter(|receipt| receipt.fmt_clean)
                .count() as u64,
            scanned_modules: self
                .module_receipts
                .values()
                .filter(|receipt| receipt.scan_clean)
                .count() as u64,
            compiled_modules: self
                .module_receipts
                .values()
                .filter(|receipt| receipt.compiled)
                .count() as u64,
            activities: self.activities.len() as u64,
            panel_visible_activities: self
                .activities
                .values()
                .filter(|activity| activity.visible_to_panel)
                .count() as u64,
            queued_items: self.queue_items.len() as u64,
            open_queue_items: self
                .queue_items
                .values()
                .filter(|item| !item.status.terminal())
                .count() as u64,
            panel_snapshots: self.panel_snapshots.len() as u64,
            total_recorded_loc: self
                .module_receipts
                .values()
                .map(|receipt| receipt.loc)
                .sum::<u64>(),
            overall_percent_bps: self.overall_percent_bps(),
        }
    }

    pub fn roots(&self) -> Roots {
        let config_root = value_root("OPERATOR-PROGRESS-CONFIG", &self.config.public_record());
        let feature_root = record_root(
            "OPERATOR-PROGRESS-FEATURES",
            self.features
                .values()
                .map(FeatureProgress::public_record)
                .collect(),
        );
        let worker_root = record_root(
            "OPERATOR-PROGRESS-WORKERS",
            self.workers
                .values()
                .map(WorkerHeartbeat::public_record)
                .collect(),
        );
        let module_root = record_root(
            "OPERATOR-PROGRESS-MODULES",
            self.module_receipts
                .values()
                .map(RuntimeModuleReceipt::public_record)
                .collect(),
        );
        let activity_root = record_root(
            "OPERATOR-PROGRESS-ACTIVITIES",
            self.activities
                .values()
                .map(ProgressActivity::public_record)
                .collect(),
        );
        let queue_root = record_root(
            "OPERATOR-PROGRESS-QUEUE",
            self.queue_items
                .values()
                .map(WorkQueueItem::public_record)
                .collect(),
        );
        let panel_snapshot_root = record_root(
            "OPERATOR-PROGRESS-PANEL-SNAPSHOTS",
            self.panel_snapshots
                .values()
                .map(PanelSnapshot::public_record)
                .collect(),
        );
        let state_root = domain_hash(
            "OPERATOR-PROGRESS-STATE",
            &[
                HashPart::Str(&config_root),
                HashPart::Str(&feature_root),
                HashPart::Str(&worker_root),
                HashPart::Str(&module_root),
                HashPart::Str(&activity_root),
                HashPart::Str(&queue_root),
                HashPart::Str(&panel_snapshot_root),
                HashPart::U64(self.height),
            ],
            32,
        );
        Roots {
            config_root,
            feature_root,
            worker_root,
            module_root,
            activity_root,
            queue_root,
            panel_snapshot_root,
            state_root,
        }
    }

    pub fn state_root(&self) -> String {
        self.roots().state_root
    }

    pub fn public_record(&self) -> Value {
        let counters = self.counters();
        let roots = self.roots();
        json!({
            "kind": "operator_progress_feed_state",
            "chain_id": CHAIN_ID,
            "protocol_version": PROTOCOL_VERSION,
            "schema_version": SCHEMA_VERSION,
            "height": self.height,
            "overall_percent_bps": counters.overall_percent_bps,
            "feature_scores": self.feature_score_table(),
            "stale_worker_root": string_set_root("OPERATOR-PROGRESS-STALE-WORKERS", &self.stale_worker_ids()),
            "counters": counters.public_record(),
            "roots": roots.public_record(),
            "state_root": roots.state_root,
        })
    }

    fn seed_devnet_progress(&mut self) {
        let features = [
            (
                FeatureKind::QuantumResistance,
                7_400,
                "PQ signatures, committees, governance, bridge, account, and proof runtimes are broadly covered.",
            ),
            (
                FeatureKind::Speed,
                6_900,
                "Fast lanes, preconfirmation receipts, microbatching, state witness prefetch, and relay paths are wired.",
            ),
            (
                FeatureKind::DefiSmartContracts,
                7_000,
                "Private tokens, AMMs, vaults, perps, lending, cross-contract settlement, and composability guards are present.",
            ),
            (
                FeatureKind::LowFees,
                6_800,
                "Fee sponsors, DA rebates, batch auctions, compression markets, and low-fee reservations are integrated.",
            ),
            (
                FeatureKind::Privacy,
                7_300,
                "Roots-only public state, selective disclosure, view-key audit paths, and privacy budgets are common.",
            ),
            (
                FeatureKind::MoneroBridge,
                7_100,
                "Bridge settlement, watchtower disputes, finality, liquidity backstops, and reorg rescue are covered.",
            ),
            (
                FeatureKind::OperatorVisibility,
                6_600,
                "Panel feed, operator catalogs, and public records are becoming first-class progress surfaces.",
            ),
            (
                FeatureKind::WalletDeveloperApi,
                6_200,
                "Wallet/API surfaces are queued for private tokens, contracts, fee sponsorship, and bridge flows.",
            ),
            (
                FeatureKind::DevnetScenarioRunner,
                5_900,
                "End-to-end devnet scenario runner is queued after the current code wave.",
            ),
            (
                FeatureKind::RuntimeReadiness,
                6_500,
                "Readiness aggregation is being promoted from notes into committed runtime state.",
            ),
        ];
        for (kind, bps, note) in features {
            if let Ok(feature) = FeatureProgress::new(
                kind,
                bps,
                &json!({"source": "devnet_seed", "panel": PANEL_FEED_SCHEMA}),
                note,
                &[],
                self.height,
            ) {
                let _ = self.upsert_feature(feature);
            }
        }

        let worker_paths = vec![
            "utils/nebula_l2_rs/src/private_l2_pq_confidential_operator_progress_feed_runtime.rs"
                .to_string(),
        ];
        if let Ok(worker) = WorkerHeartbeat::new(
            WorkerKind::LocalCodex,
            "local-progress-runtime-integrator",
            &worker_paths,
            "add operator progress feed runtime and wire panel-backed feature visibility",
            "medium",
            WorkStatus::Integrating,
            self.height,
            0,
            8_500,
            500,
        ) {
            let _ = self.upsert_worker(worker);
        }

        let gpt_paths = vec![
            "private_l2_pq_confidential_runtime_readiness_scoreboard.rs".to_string(),
            "private_l2_pq_confidential_wallet_developer_api_runtime.rs".to_string(),
            "private_l2_pq_confidential_devnet_scenario_runner.rs".to_string(),
        ];
        if let Ok(worker) = WorkerHeartbeat::new(
            WorkerKind::Gpt55Worker,
            "gpt-5-5-runtime-wave",
            &gpt_paths,
            "draft readiness scoreboard, wallet developer API, and scenario runner modules",
            "low",
            WorkStatus::Drafting,
            self.height,
            0,
            7_800,
            900,
        ) {
            let _ = self.upsert_worker(worker);
        }

        let module_names = [
            (
                "monero_l2_pq_private_bridge_watchtower_execution_dispute_runtime",
                FeatureKind::MoneroBridge,
                2_803,
            ),
            (
                "private_l2_pq_confidential_cross_runtime_state_commitment_bus_runtime",
                FeatureKind::RuntimeReadiness,
                2_051,
            ),
            (
                "private_l2_fast_pq_confidential_receipt_preconfirmation_market_runtime",
                FeatureKind::Speed,
                2_210,
            ),
            (
                "private_l2_low_fee_pq_confidential_bridge_da_fee_rebate_market_runtime",
                FeatureKind::LowFees,
                2_405,
            ),
            (
                "private_l2_pq_confidential_token_bridge_settlement_router_runtime",
                FeatureKind::DefiSmartContracts,
                2_608,
            ),
            (
                "private_l2_pq_confidential_governance_upgrade_timelock_mesh_runtime",
                FeatureKind::QuantumResistance,
                2_799,
            ),
        ];
        for (name, feature, loc) in module_names {
            if let Ok(receipt) = RuntimeModuleReceipt::new(
                name,
                &format!("utils/nebula_l2_rs/src/{name}.rs"),
                loc,
                feature,
                &json!({"seeded_from": "latest_wave"}),
                &[
                    "Config".to_string(),
                    "State".to_string(),
                    "Runtime".to_string(),
                    "Counters".to_string(),
                    "Roots".to_string(),
                ],
                true,
                true,
                true,
                true,
                true,
                false,
                self.height,
            ) {
                let _ = self.record_module(receipt);
            }
        }

        let queue_specs = [
            (
                FeatureKind::RuntimeReadiness,
                "Add readiness scoreboard",
                json!({"runtime": "private_l2_pq_confidential_runtime_readiness_scoreboard"}),
                2_000,
            ),
            (
                FeatureKind::WalletDeveloperApi,
                "Add wallet/developer API runtime",
                json!({"runtime": "private_l2_pq_confidential_wallet_developer_api_runtime"}),
                2_200,
            ),
            (
                FeatureKind::DevnetScenarioRunner,
                "Add deterministic devnet scenario runner",
                json!({"runtime": "private_l2_pq_confidential_devnet_scenario_runner"}),
                2_200,
            ),
            (
                FeatureKind::OperatorVisibility,
                "Promote progress panel into runtime feed",
                json!({"runtime": "private_l2_pq_confidential_operator_progress_feed_runtime"}),
                1_500,
            ),
        ];
        for (feature, title, scope, target_loc) in queue_specs {
            if let Ok(item) = WorkQueueItem::new(
                feature,
                title,
                &scope,
                target_loc,
                WorkStatus::Drafting,
                &["local".to_string(), "gpt-5.5".to_string()],
                self.height.saturating_add(512),
                1_500,
            ) {
                let _ = self.queue_work(item);
            }
        }

        if let Ok(activity) = ProgressActivity::new(
            ActivityKind::FeatureWaveStarted,
            self.height,
            "Operator progress feed opened for the next large Rust feature wave.",
            &json!({
                "workers": ["local", "gpt-5.5"],
                "panel_feed": PANEL_FEED_SCHEMA,
                "compile_policy": "deferred_until_major_wave"
            }),
            &[],
            true,
        ) {
            let _ = self.log_activity(activity);
        }
        let _ = self.snapshot_panel("Progress feed seeded for live feature tracking.");
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Runtime {
    pub state: State,
}

impl Runtime {
    pub fn new(config: Config, height: u64) -> Result<Self> {
        Ok(Self {
            state: State::new(config, height)?,
        })
    }

    pub fn devnet() -> Self {
        Self {
            state: State::devnet(),
        }
    }

    pub fn state_root(&self) -> String {
        self.state.state_root()
    }

    pub fn public_record(&self) -> Value {
        self.state.public_record()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn feature_id(
    feature_kind: FeatureKind,
    percent_bps: u64,
    priority_weight_bps: u64,
    evidence_root: &str,
    note_root: &str,
    blocker_root: &str,
    updated_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-FEATURE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feature_kind.as_str()),
            HashPart::U64(percent_bps),
            HashPart::U64(priority_weight_bps),
            HashPart::Str(evidence_root),
            HashPart::Str(note_root),
            HashPart::Str(blocker_root),
            HashPart::U64(updated_at_height),
        ],
        32,
    )
}

pub fn worker_id(
    worker_kind: WorkerKind,
    label_commitment: &str,
    owned_path_root: &str,
    current_task_root: &str,
    reasoning_mode: &str,
    last_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-WORKER-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(worker_kind.as_str()),
            HashPart::Str(label_commitment),
            HashPart::Str(owned_path_root),
            HashPart::Str(current_task_root),
            HashPart::Str(reasoning_mode),
            HashPart::U64(last_height),
        ],
        32,
    )
}

pub fn module_id(
    module_name: &str,
    file_path_root: &str,
    loc: u64,
    priority_feature: FeatureKind,
    state_root: &str,
    public_api_root: &str,
    recorded_at_height: u64,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-MODULE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(module_name),
            HashPart::Str(file_path_root),
            HashPart::U64(loc),
            HashPart::Str(priority_feature.as_str()),
            HashPart::Str(state_root),
            HashPart::Str(public_api_root),
            HashPart::U64(recorded_at_height),
        ],
        32,
    )
}

pub fn activity_id(
    activity_kind: ActivityKind,
    height: u64,
    summary_root: &str,
    detail_root: &str,
    related_root: &str,
    visible_to_panel: bool,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-ACTIVITY-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(activity_kind.as_str()),
            HashPart::U64(height),
            HashPart::Str(summary_root),
            HashPart::Str(detail_root),
            HashPart::Str(related_root),
            HashPart::U64(if visible_to_panel { 1 } else { 0 }),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn queue_item_id(
    feature_kind: FeatureKind,
    title_root: &str,
    scope_root: &str,
    target_loc: u64,
    status: WorkStatus,
    assigned_worker_root: &str,
    due_height: u64,
    risk_bps: u64,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-QUEUE-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::Str(feature_kind.as_str()),
            HashPart::Str(title_root),
            HashPart::Str(scope_root),
            HashPart::U64(target_loc),
            HashPart::Str(status.as_str()),
            HashPart::Str(assigned_worker_root),
            HashPart::U64(due_height),
            HashPart::U64(risk_bps),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn panel_snapshot_id(
    height: u64,
    overall_percent_bps: u64,
    feature_root: &str,
    worker_root: &str,
    module_root: &str,
    activity_root: &str,
    queue_root: &str,
    summary_root: &str,
    stale_worker_root: &str,
    ready: bool,
) -> String {
    domain_hash(
        "OPERATOR-PROGRESS-PANEL-SNAPSHOT-ID",
        &[
            HashPart::Str(CHAIN_ID),
            HashPart::U64(height),
            HashPart::U64(overall_percent_bps),
            HashPart::Str(feature_root),
            HashPart::Str(worker_root),
            HashPart::Str(module_root),
            HashPart::Str(activity_root),
            HashPart::Str(queue_root),
            HashPart::Str(summary_root),
            HashPart::Str(stale_worker_root),
            HashPart::U64(if ready { 1 } else { 0 }),
        ],
        32,
    )
}

pub fn value_root(domain: &str, value: &Value) -> String {
    domain_hash(domain, &[HashPart::Json(value)], 32)
}

pub fn string_root(domain: &str, value: &str) -> String {
    domain_hash(domain, &[HashPart::Str(value)], 32)
}

pub fn string_set_root(domain: &str, values: &[String]) -> String {
    let leaves = values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(Value::String)
        .collect::<Vec<_>>();
    merkle_root(domain, &leaves)
}

pub fn record_root(domain: &str, mut records: Vec<Value>) -> String {
    records.sort_by_key(|value| value_root("OPERATOR-PROGRESS-SORT", value));
    merkle_root(domain, &records)
}
