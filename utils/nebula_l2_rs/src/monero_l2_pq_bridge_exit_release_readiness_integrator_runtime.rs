use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::{
        CargoRuntimeHarnessReport, CargoRuntimeHarnessReportStatus,
        State as CargoRuntimeHarnessState,
    },
    monero_l2_pq_bridge_exit_claim_queue_handler_runtime::{
        ExitClaimQueueHandlerReport, ExitClaimQueueHandlerReportStatus,
        State as ExitClaimQueueHandlerState,
    },
    monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::{
        PqAuthorityKeyManagerReport, PqAuthorityKeyManagerReportStatus, State as PqAuthorityState,
    },
    monero_l2_pq_bridge_exit_security_audit_harness_adapter_runtime::{
        SecurityAuditHarnessReport, SecurityAuditHarnessReportStatus,
        State as SecurityAuditHarnessState,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitReleaseReadinessIntegratorRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_READINESS_INTEGRATOR_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-release-readiness-integrator-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_RELEASE_READINESS_INTEGRATOR_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const RELEASE_READINESS_INTEGRATOR_SUITE: &str =
    "monero-l2-pq-bridge-exit-release-readiness-integrator-v1";
pub const DEFAULT_MIN_READINESS_ITEMS: u64 = 6;
pub const DEFAULT_MAX_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReadinessStatus {
    Ready,
    Watch,
    Blocked,
}

impl ReleaseReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReadinessDimension {
    SettlementExecution,
    PqAuthority,
    CargoRuntime,
    SecurityAudit,
    ForcedExitUserAnswer,
    ProductionRelease,
}

impl ReleaseReadinessDimension {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettlementExecution => "settlement_execution",
            Self::PqAuthority => "pq_authority",
            Self::CargoRuntime => "cargo_runtime",
            Self::SecurityAudit => "security_audit",
            Self::ForcedExitUserAnswer => "forced_exit_user_answer",
            Self::ProductionRelease => "production_release",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub integrator_suite: String,
    pub min_readiness_items: u64,
    pub cargo_checks_deferred: bool,
    pub runtime_tests_deferred: bool,
    pub security_audit_deferred: bool,
    pub production_release_allowed: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            integrator_suite: RELEASE_READINESS_INTEGRATOR_SUITE.to_string(),
            min_readiness_items: DEFAULT_MIN_READINESS_ITEMS,
            cargo_checks_deferred: true,
            runtime_tests_deferred: true,
            security_audit_deferred: true,
            production_release_allowed: false,
            max_reports: DEFAULT_MAX_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "integrator_suite": self.integrator_suite,
            "min_readiness_items": self.min_readiness_items,
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "runtime_tests_deferred": self.runtime_tests_deferred,
            "security_audit_deferred": self.security_audit_deferred,
            "production_release_allowed": self.production_release_allowed,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseReadinessItem {
    pub item_id: String,
    pub dimension: ReleaseReadinessDimension,
    pub status: ReleaseReadinessStatus,
    pub source_status: String,
    pub requirement: String,
    pub observed: String,
    pub source_root: String,
    pub readiness_root: String,
    pub blocks_user_release: bool,
    pub blocks_production: bool,
    pub remediation: String,
}

impl ReleaseReadinessItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        dimension: ReleaseReadinessDimension,
        status: ReleaseReadinessStatus,
        source_status: impl Into<String>,
        requirement: impl Into<String>,
        observed: impl Into<String>,
        source_root: impl Into<String>,
        blocks_user_release: bool,
        blocks_production: bool,
        remediation: impl Into<String>,
    ) -> Self {
        let source_status = source_status.into();
        let requirement = requirement.into();
        let observed = observed.into();
        let source_root = source_root.into();
        let remediation = remediation.into();
        let readiness_root = release_readiness_item_root(
            dimension,
            status,
            &source_status,
            &requirement,
            &observed,
            &source_root,
            blocks_user_release,
            blocks_production,
        );
        let item_id = release_readiness_item_id(dimension, &readiness_root);
        Self {
            item_id,
            dimension,
            status,
            source_status,
            requirement,
            observed,
            source_root,
            readiness_root,
            blocks_user_release,
            blocks_production,
            remediation,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "item_id": self.item_id,
            "dimension": self.dimension.as_str(),
            "status": self.status.as_str(),
            "source_status": self.source_status,
            "requirement": self.requirement,
            "observed": self.observed,
            "source_root": self.source_root,
            "readiness_root": self.readiness_root,
            "blocks_user_release": self.blocks_user_release,
            "blocks_production": self.blocks_production,
            "remediation": self.remediation,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("release_readiness_item", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitReleaseReadinessReceipt {
    pub receipt_id: String,
    pub status: ReleaseReadinessStatus,
    pub readiness_label: String,
    pub user_question_answer: String,
    pub release_claim_id: String,
    pub settlement_state_root: String,
    pub settlement_report_root: String,
    pub pq_authority_state_root: String,
    pub pq_authority_report_root: String,
    pub cargo_harness_state_root: String,
    pub cargo_harness_report_root: String,
    pub security_audit_state_root: String,
    pub security_audit_report_root: String,
    pub items_total: u64,
    pub items_ready: u64,
    pub items_watch: u64,
    pub items_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
    pub settlement_calls_ready: u64,
    pub pq_signatures_valid: u64,
    pub cargo_tests_executed: u64,
    pub audits_passed: u64,
    pub findings_total: u64,
    pub items: BTreeMap<String, ReleaseReadinessItem>,
    pub roots: BridgeExitReleaseReadinessRoots,
}

impl BridgeExitReleaseReadinessReceipt {
    pub fn public_record(&self) -> Value {
        let items = self
            .items
            .values()
            .map(ReleaseReadinessItem::public_record)
            .collect::<Vec<_>>();
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "readiness_label": self.readiness_label,
            "user_question_answer": self.user_question_answer,
            "release_claim_id": self.release_claim_id,
            "settlement_state_root": self.settlement_state_root,
            "settlement_report_root": self.settlement_report_root,
            "pq_authority_state_root": self.pq_authority_state_root,
            "pq_authority_report_root": self.pq_authority_report_root,
            "cargo_harness_state_root": self.cargo_harness_state_root,
            "cargo_harness_report_root": self.cargo_harness_report_root,
            "security_audit_state_root": self.security_audit_state_root,
            "security_audit_report_root": self.security_audit_report_root,
            "items_total": self.items_total,
            "items_ready": self.items_ready,
            "items_watch": self.items_watch,
            "items_blocked": self.items_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
            "settlement_calls_ready": self.settlement_calls_ready,
            "pq_signatures_valid": self.pq_signatures_valid,
            "cargo_tests_executed": self.cargo_tests_executed,
            "audits_passed": self.audits_passed,
            "findings_total": self.findings_total,
            "items": items,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.receipt_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BridgeExitReleaseReadinessRoots {
    pub item_root: String,
    pub source_root: String,
    pub blocker_root: String,
    pub receipt_root: String,
}

impl BridgeExitReleaseReadinessRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "item_root": self.item_root,
            "source_root": self.source_root,
            "blocker_root": self.blocker_root,
            "receipt_root": self.receipt_root,
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Counters {
    pub receipts_run: u64,
    pub receipts_ready: u64,
    pub receipts_watch: u64,
    pub receipts_blocked: u64,
    pub items_total: u64,
    pub items_ready: u64,
    pub items_watch: u64,
    pub items_blocked: u64,
    pub user_release_blockers: u64,
    pub production_blockers: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "receipts_run": self.receipts_run,
            "receipts_ready": self.receipts_ready,
            "receipts_watch": self.receipts_watch,
            "receipts_blocked": self.receipts_blocked,
            "items_total": self.items_total,
            "items_ready": self.items_ready,
            "items_watch": self.items_watch,
            "items_blocked": self.items_blocked,
            "user_release_blockers": self.user_release_blockers,
            "production_blockers": self.production_blockers,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("counters", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Roots {
    pub config_root: String,
    pub receipt_root: String,
    pub counters_root: String,
    pub state_root: String,
}

impl Roots {
    pub fn empty(config: &Config, counters: &Counters) -> Self {
        let mut roots = Self {
            config_root: config.state_root(),
            receipt_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-EMPTY-RECEIPTS",
                &[],
            ),
            counters_root: counters.state_root(),
            state_root: String::new(),
        };
        roots.state_root = roots.compute_state_root();
        roots
    }

    pub fn public_record(&self) -> Value {
        json!({
            "config_root": self.config_root,
            "receipt_root": self.receipt_root,
            "counters_root": self.counters_root,
            "state_root": self.state_root,
        })
    }

    pub fn compute_state_root(&self) -> String {
        domain_hash(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-STATE",
            &[
                HashPart::Str(&self.config_root),
                HashPart::Str(&self.receipt_root),
                HashPart::Str(&self.counters_root),
            ],
            32,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub latest_receipt: Option<BridgeExitReleaseReadinessReceipt>,
    pub receipt_history: Vec<BridgeExitReleaseReadinessReceipt>,
    pub counters: Counters,
    pub roots: Roots,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let counters = Counters::default();
        let roots = Roots::empty(&config, &counters);
        let mut state = Self {
            config,
            latest_receipt: None,
            receipt_history: Vec::new(),
            counters,
            roots,
        };
        let settlement = crate::monero_l2_pq_bridge_exit_claim_queue_handler_runtime::devnet();
        let pq_authority =
            crate::monero_l2_pq_bridge_exit_pq_authority_key_manager_adapter_runtime::devnet();
        let cargo_harness =
            crate::monero_l2_pq_bridge_exit_cargo_runtime_harness_adapter_runtime::devnet();
        let security_audit =
            crate::monero_l2_pq_bridge_exit_security_audit_harness_adapter_runtime::devnet();
        state
            .integrate_release_readiness(
                &settlement,
                &pq_authority,
                &cargo_harness,
                &security_audit,
            )
            .expect("devnet bridge exit release readiness integrator");
        state
    }

    pub fn integrate_release_readiness(
        &mut self,
        settlement: &ExitClaimQueueHandlerState,
        pq_authority: &PqAuthorityState,
        cargo_harness: &CargoRuntimeHarnessState,
        security_audit: &SecurityAuditHarnessState,
    ) -> Result<String> {
        let settlement_report = settlement
            .latest_report
            .as_ref()
            .ok_or_else(|| "exit claim queue handler has no latest report".to_string())?;
        let pq_report = pq_authority
            .latest_report
            .as_ref()
            .ok_or_else(|| "PQ authority adapter has no latest report".to_string())?;
        let cargo_report = cargo_harness
            .latest_report
            .as_ref()
            .ok_or_else(|| "cargo runtime harness adapter has no latest report".to_string())?;
        let audit_report = security_audit
            .latest_report
            .as_ref()
            .ok_or_else(|| "security audit harness adapter has no latest report".to_string())?;
        let items = build_readiness_items(
            &self.config,
            settlement_report,
            pq_report,
            cargo_report,
            audit_report,
        );
        ensure(
            items.len() as u64 >= self.config.min_readiness_items,
            "release readiness integrator omitted required readiness dimensions",
        )?;
        let items_total = items.len() as u64;
        let items_ready = items
            .values()
            .filter(|item| item.status == ReleaseReadinessStatus::Ready)
            .count() as u64;
        let items_watch = items
            .values()
            .filter(|item| item.status == ReleaseReadinessStatus::Watch)
            .count() as u64;
        let items_blocked = items
            .values()
            .filter(|item| item.status == ReleaseReadinessStatus::Blocked)
            .count() as u64;
        let user_release_blockers = items
            .values()
            .filter(|item| item.blocks_user_release)
            .count() as u64;
        let production_blockers =
            items.values().filter(|item| item.blocks_production).count() as u64;
        let status = receipt_status(items_watch, items_blocked, user_release_blockers);
        let readiness_label = readiness_label(status, production_blockers).to_string();
        let user_question_answer = user_question_answer(status, user_release_blockers).to_string();
        let item_records = items
            .values()
            .map(ReleaseReadinessItem::public_record)
            .collect::<Vec<_>>();
        let item_root = merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-ITEMS",
            &item_records,
        );
        let source_root = source_root(
            &settlement.state_root(),
            &settlement_report.state_root(),
            &pq_authority.state_root(),
            &pq_report.state_root(),
            &cargo_harness.state_root(),
            &cargo_report.state_root(),
            &security_audit.state_root(),
            &audit_report.state_root(),
        );
        let blocker_root = blocker_root(&items);
        let receipt_root = receipt_root(
            status,
            &readiness_label,
            &source_root,
            &item_root,
            &blocker_root,
            &settlement_report.release_claim_id,
            user_release_blockers,
            production_blockers,
        );
        let receipt_id = bridge_exit_release_readiness_receipt_id(
            &settlement_report.release_claim_id,
            &receipt_root,
        );
        let receipt = BridgeExitReleaseReadinessReceipt {
            receipt_id: receipt_id.clone(),
            status,
            readiness_label,
            user_question_answer,
            release_claim_id: settlement_report.release_claim_id.clone(),
            settlement_state_root: settlement.state_root(),
            settlement_report_root: settlement_report.state_root(),
            pq_authority_state_root: pq_authority.state_root(),
            pq_authority_report_root: pq_report.state_root(),
            cargo_harness_state_root: cargo_harness.state_root(),
            cargo_harness_report_root: cargo_report.state_root(),
            security_audit_state_root: security_audit.state_root(),
            security_audit_report_root: audit_report.state_root(),
            items_total,
            items_ready,
            items_watch,
            items_blocked,
            user_release_blockers,
            production_blockers,
            settlement_calls_ready: settlement_report.settlement_calls_ready,
            pq_signatures_valid: pq_report.signatures_valid,
            cargo_tests_executed: cargo_report.tests_executed,
            audits_passed: audit_report.audits_passed,
            findings_total: audit_report.findings_total,
            items,
            roots: BridgeExitReleaseReadinessRoots {
                item_root,
                source_root,
                blocker_root,
                receipt_root,
            },
        };
        self.record_receipt(receipt);
        Ok(receipt_id)
    }

    pub fn public_record(&self) -> Value {
        json!({
            "protocol_version": self.config.protocol_version,
            "schema_version": self.config.schema_version,
            "integrator_suite": self.config.integrator_suite,
            "latest_receipt": self.latest_receipt.as_ref().map(BridgeExitReleaseReadinessReceipt::public_record),
            "receipt_history_len": self.receipt_history.len(),
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn record_receipt(&mut self, receipt: BridgeExitReleaseReadinessReceipt) {
        self.counters.receipts_run += 1;
        self.counters.items_total += receipt.items_total;
        self.counters.items_ready += receipt.items_ready;
        self.counters.items_watch += receipt.items_watch;
        self.counters.items_blocked += receipt.items_blocked;
        self.counters.user_release_blockers += receipt.user_release_blockers;
        self.counters.production_blockers += receipt.production_blockers;
        match receipt.status {
            ReleaseReadinessStatus::Ready => self.counters.receipts_ready += 1,
            ReleaseReadinessStatus::Watch => self.counters.receipts_watch += 1,
            ReleaseReadinessStatus::Blocked => self.counters.receipts_blocked += 1,
        }
        self.latest_receipt = Some(receipt.clone());
        self.receipt_history.push(receipt);
        if self.receipt_history.len() > self.config.max_reports {
            self.receipt_history.remove(0);
        }
        self.refresh_roots();
    }

    fn refresh_roots(&mut self) {
        let receipt_records = self
            .receipt_history
            .iter()
            .map(BridgeExitReleaseReadinessReceipt::public_record)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            receipt_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-RECEIPTS",
                &receipt_records,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
    }
}

fn build_readiness_items(
    config: &Config,
    settlement: &ExitClaimQueueHandlerReport,
    pq: &PqAuthorityKeyManagerReport,
    cargo: &CargoRuntimeHarnessReport,
    audit: &SecurityAuditHarnessReport,
) -> BTreeMap<String, ReleaseReadinessItem> {
    let mut items = BTreeMap::new();
    for item in [
        settlement_item(settlement),
        pq_authority_item(pq),
        cargo_runtime_item(cargo),
        security_audit_item(audit),
        forced_exit_user_answer_item(settlement, pq, cargo, audit),
        production_release_item(config, settlement, pq, cargo, audit),
    ] {
        items.insert(item.dimension.as_str().to_string(), item);
    }
    items
}

fn settlement_item(report: &ExitClaimQueueHandlerReport) -> ReleaseReadinessItem {
    let status = if report.status == ExitClaimQueueHandlerReportStatus::Failed
        || report.envelopes_rejected > 0
        || report.quarantine_required > 0
    {
        ReleaseReadinessStatus::Blocked
    } else if report.status == ExitClaimQueueHandlerReportStatus::Watch
        || report.challenge_window_holds > 0
        || report.live_settlement_holds > 0
        || report.settlement_calls_ready == 0
    {
        ReleaseReadinessStatus::Watch
    } else {
        ReleaseReadinessStatus::Ready
    };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::SettlementExecution,
        status,
        report.status.as_str(),
        "forced-exit settlement calls must be prepared, non-rejected, and live-executable",
        format!(
            "settlement_calls_ready={} rejected={} challenge_holds={} live_settlement_holds={} quarantine_required={}",
            report.settlement_calls_ready,
            report.envelopes_rejected,
            report.challenge_window_holds,
            report.live_settlement_holds,
            report.quarantine_required
        ),
        report.roots.report_root.clone(),
        status == ReleaseReadinessStatus::Blocked,
        status != ReleaseReadinessStatus::Ready,
        "enable live settlement execution and clear challenge-window or quarantine holds",
    )
}

fn pq_authority_item(report: &PqAuthorityKeyManagerReport) -> ReleaseReadinessItem {
    let status = if report.status == PqAuthorityKeyManagerReportStatus::Failed
        || report.stale_rotations > 0
        || report.observations_rejected > 0
    {
        ReleaseReadinessStatus::Blocked
    } else if report.status == PqAuthorityKeyManagerReportStatus::Watch
        || report.signatures_valid == 0
        || report.release_holds_required > 0
    {
        ReleaseReadinessStatus::Watch
    } else {
        ReleaseReadinessStatus::Ready
    };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::PqAuthority,
        status,
        report.status.as_str(),
        "release authority must be bound to fresh post-quantum signer, rotation, and epoch roots",
        format!(
            "signatures_valid={} release_holds={} stale_rotations={} rejected={}",
            report.signatures_valid,
            report.release_holds_required,
            report.stale_rotations,
            report.observations_rejected
        ),
        report.roots.report_root.clone(),
        status == ReleaseReadinessStatus::Blocked,
        status != ReleaseReadinessStatus::Ready,
        "enable live PQ authority verification and clear signer rotation holds",
    )
}

fn cargo_runtime_item(report: &CargoRuntimeHarnessReport) -> ReleaseReadinessItem {
    let status =
        if report.status == CargoRuntimeHarnessReportStatus::Failed || report.cases_rejected > 0 {
            ReleaseReadinessStatus::Blocked
        } else if report.status == CargoRuntimeHarnessReportStatus::Watch
            || report.tests_executed == 0
            || report.release_holds_required > 0
        {
            ReleaseReadinessStatus::Watch
        } else {
            ReleaseReadinessStatus::Ready
        };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::CargoRuntime,
        status,
        report.status.as_str(),
        "final-release fixtures must be executable cargo/runtime tests with assertion roots",
        format!(
            "tests_executed={} assertion_roots_bound={} cases_total={} release_holds={}",
            report.tests_executed,
            report.assertion_roots_bound,
            report.cases_total,
            report.release_holds_required
        ),
        report.roots.report_root.clone(),
        false,
        status != ReleaseReadinessStatus::Ready,
        "materialize and run bridge_exit_final_release cargo/runtime tests",
    )
}

fn security_audit_item(report: &SecurityAuditHarnessReport) -> ReleaseReadinessItem {
    let status = if report.status == SecurityAuditHarnessReportStatus::Failed
        || report.high_or_critical_findings > 0
        || report.cases_rejected > 0
    {
        ReleaseReadinessStatus::Blocked
    } else if report.status == SecurityAuditHarnessReportStatus::Watch
        || report.audits_passed == 0
        || report.findings_total > 0
        || report.release_holds_required > 0
    {
        ReleaseReadinessStatus::Watch
    } else {
        ReleaseReadinessStatus::Ready
    };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::SecurityAudit,
        status,
        report.status.as_str(),
        "security and privacy audit signoff must cover safety-case, cargo, and PQ authority roots",
        format!(
            "audits_passed={} findings_total={} high_or_critical={} release_holds={}",
            report.audits_passed,
            report.findings_total,
            report.high_or_critical_findings,
            report.release_holds_required
        ),
        report.roots.report_root.clone(),
        status == ReleaseReadinessStatus::Blocked,
        status != ReleaseReadinessStatus::Ready,
        "complete crypto/privacy audit execution and resolve residual-risk findings",
    )
}

fn forced_exit_user_answer_item(
    settlement: &ExitClaimQueueHandlerReport,
    pq: &PqAuthorityKeyManagerReport,
    cargo: &CargoRuntimeHarnessReport,
    audit: &SecurityAuditHarnessReport,
) -> ReleaseReadinessItem {
    let settlement_blocked =
        settlement.envelopes_rejected > 0 || settlement.quarantine_required > 0;
    let pq_blocked = pq.stale_rotations > 0 || pq.observations_rejected > 0;
    let audit_blocked = audit.high_or_critical_findings > 0 || audit.cases_rejected > 0;
    let status = if settlement_blocked || pq_blocked || audit_blocked {
        ReleaseReadinessStatus::Blocked
    } else if settlement.settlement_calls_ready == 0
        || settlement.live_settlement_holds > 0
        || pq.signatures_valid == 0
        || cargo.tests_executed == 0
        || audit.audits_passed == 0
    {
        ReleaseReadinessStatus::Watch
    } else {
        ReleaseReadinessStatus::Ready
    };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::ForcedExitUserAnswer,
        status,
        status.as_str(),
        "a user must have a believable path to force exit when sequencers or watchers misbehave",
        format!(
            "settlement_ready={} pq_signatures_valid={} cargo_tests_executed={} audits_passed={}",
            settlement.settlement_calls_ready, pq.signatures_valid, cargo.tests_executed, audit.audits_passed
        ),
        forced_exit_answer_root(
            &settlement.roots.report_root,
            &pq.roots.report_root,
            &cargo.roots.report_root,
            &audit.roots.report_root,
        ),
        status == ReleaseReadinessStatus::Blocked,
        status != ReleaseReadinessStatus::Ready,
        "connect live settlement, PQ authority, executable tests, and audit signoff before claiming forced-exit readiness",
    )
}

fn production_release_item(
    config: &Config,
    settlement: &ExitClaimQueueHandlerReport,
    pq: &PqAuthorityKeyManagerReport,
    cargo: &CargoRuntimeHarnessReport,
    audit: &SecurityAuditHarnessReport,
) -> ReleaseReadinessItem {
    let all_reports_ready = settlement.status == ExitClaimQueueHandlerReportStatus::Passed
        && pq.status == PqAuthorityKeyManagerReportStatus::Passed
        && cargo.status == CargoRuntimeHarnessReportStatus::Passed
        && audit.status == SecurityAuditHarnessReportStatus::Passed;
    let status = if config.production_release_allowed && all_reports_ready {
        ReleaseReadinessStatus::Ready
    } else if audit.high_or_critical_findings > 0 || settlement.envelopes_rejected > 0 {
        ReleaseReadinessStatus::Blocked
    } else {
        ReleaseReadinessStatus::Watch
    };
    ReleaseReadinessItem::new(
        ReleaseReadinessDimension::ProductionRelease,
        status,
        status.as_str(),
        "production release must remain blocked until live handlers, cargo/runtime tests, and audits are green",
        format!(
            "production_release_allowed={} all_reports_ready={} cargo_deferred={} runtime_deferred={} audit_deferred={}",
            config.production_release_allowed,
            all_reports_ready,
            config.cargo_checks_deferred,
            config.runtime_tests_deferred,
            config.security_audit_deferred
        ),
        production_release_root(
            config.production_release_allowed,
            all_reports_ready,
            &settlement.roots.report_root,
            &pq.roots.report_root,
            &cargo.roots.report_root,
            &audit.roots.report_root,
        ),
        false,
        status != ReleaseReadinessStatus::Ready,
        "keep production blocked until every release readiness source reports passed",
    )
}

fn receipt_status(
    items_watch: u64,
    items_blocked: u64,
    user_release_blockers: u64,
) -> ReleaseReadinessStatus {
    if items_blocked > 0 || user_release_blockers > 0 {
        ReleaseReadinessStatus::Blocked
    } else if items_watch > 0 {
        ReleaseReadinessStatus::Watch
    } else {
        ReleaseReadinessStatus::Ready
    }
}

fn readiness_label(status: ReleaseReadinessStatus, production_blockers: u64) -> &'static str {
    match status {
        ReleaseReadinessStatus::Blocked => "bridge_exit_release_readiness_blocked",
        ReleaseReadinessStatus::Watch if production_blockers > 0 => {
            "bridge_exit_release_readiness_watch_production_blocked"
        }
        ReleaseReadinessStatus::Watch => "bridge_exit_release_readiness_watch",
        ReleaseReadinessStatus::Ready => "bridge_exit_release_ready",
    }
}

fn user_question_answer(
    status: ReleaseReadinessStatus,
    user_release_blockers: u64,
) -> &'static str {
    match status {
        ReleaseReadinessStatus::Ready => {
            "yes: the current evidence says a user can get in, transact privately, and force exit"
        }
        ReleaseReadinessStatus::Watch if user_release_blockers == 0 => {
            "not yet for production: user-exit blockers are absent, but deferred live execution, tests, or audits remain"
        }
        ReleaseReadinessStatus::Watch => {
            "not yet: user-exit readiness still depends on unresolved watch gates"
        }
        ReleaseReadinessStatus::Blocked => {
            "no: at least one release-critical bridge/exit readiness dimension is blocked"
        }
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record(state: &State) -> Value {
    state.public_record()
}

pub fn state_root(state: &State) -> String {
    state.state_root()
}

#[allow(clippy::too_many_arguments)]
pub fn release_readiness_item_root(
    dimension: ReleaseReadinessDimension,
    status: ReleaseReadinessStatus,
    source_status: &str,
    requirement: &str,
    observed: &str,
    source_root: &str,
    blocks_user_release: bool,
    blocks_production: bool,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-ITEM",
        &[
            HashPart::Str(dimension.as_str()),
            HashPart::Str(status.as_str()),
            HashPart::Str(source_status),
            HashPart::Str(requirement),
            HashPart::Str(observed),
            HashPart::Str(source_root),
            HashPart::Str(bool_str(blocks_user_release)),
            HashPart::Str(bool_str(blocks_production)),
        ],
        32,
    )
}

pub fn release_readiness_item_id(
    dimension: ReleaseReadinessDimension,
    readiness_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-ITEM-ID",
        &[
            HashPart::Str(dimension.as_str()),
            HashPart::Str(readiness_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn source_root(
    settlement_state_root: &str,
    settlement_report_root: &str,
    pq_authority_state_root: &str,
    pq_authority_report_root: &str,
    cargo_harness_state_root: &str,
    cargo_harness_report_root: &str,
    security_audit_state_root: &str,
    security_audit_report_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-SOURCE",
        &[
            HashPart::Str(settlement_state_root),
            HashPart::Str(settlement_report_root),
            HashPart::Str(pq_authority_state_root),
            HashPart::Str(pq_authority_report_root),
            HashPart::Str(cargo_harness_state_root),
            HashPart::Str(cargo_harness_report_root),
            HashPart::Str(security_audit_state_root),
            HashPart::Str(security_audit_report_root),
        ],
        32,
    )
}

pub fn blocker_root(items: &BTreeMap<String, ReleaseReadinessItem>) -> String {
    let records = items
        .values()
        .filter(|item| item.blocks_user_release || item.blocks_production)
        .map(|item| {
            json!({
                "dimension": item.dimension.as_str(),
                "status": item.status.as_str(),
                "readiness_root": item.readiness_root,
                "blocks_user_release": item.blocks_user_release,
                "blocks_production": item.blocks_production,
                "remediation": item.remediation,
            })
        })
        .collect::<Vec<_>>();
    merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-BLOCKERS",
        &records,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn receipt_root(
    status: ReleaseReadinessStatus,
    readiness_label: &str,
    source_root: &str,
    item_root: &str,
    blocker_root: &str,
    release_claim_id: &str,
    user_release_blockers: u64,
    production_blockers: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-RECEIPT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(readiness_label),
            HashPart::Str(source_root),
            HashPart::Str(item_root),
            HashPart::Str(blocker_root),
            HashPart::Str(release_claim_id),
            HashPart::U64(user_release_blockers),
            HashPart::U64(production_blockers),
        ],
        32,
    )
}

pub fn bridge_exit_release_readiness_receipt_id(
    release_claim_id: &str,
    receipt_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-RECEIPT-ID",
        &[HashPart::Str(release_claim_id), HashPart::Str(receipt_root)],
        32,
    )
}

pub fn forced_exit_answer_root(
    settlement_report_root: &str,
    pq_authority_report_root: &str,
    cargo_harness_report_root: &str,
    security_audit_report_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-FORCED-EXIT-ANSWER",
        &[
            HashPart::Str(settlement_report_root),
            HashPart::Str(pq_authority_report_root),
            HashPart::Str(cargo_harness_report_root),
            HashPart::Str(security_audit_report_root),
        ],
        32,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn production_release_root(
    production_release_allowed: bool,
    all_reports_ready: bool,
    settlement_report_root: &str,
    pq_authority_report_root: &str,
    cargo_harness_report_root: &str,
    security_audit_report_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-PRODUCTION",
        &[
            HashPart::Str(bool_str(production_release_allowed)),
            HashPart::Str(bool_str(all_reports_ready)),
            HashPart::Str(settlement_report_root),
            HashPart::Str(pq_authority_report_root),
            HashPart::Str(cargo_harness_report_root),
            HashPart::Str(security_audit_report_root),
        ],
        32,
    )
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-RELEASE-READINESS-RECORD",
        &[HashPart::Str(kind), HashPart::Json(record)],
        32,
    )
}

pub fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn bool_str(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
