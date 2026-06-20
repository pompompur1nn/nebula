use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    monero_l2_pq_bridge_exit_private_receipt_scanner_adapter_runtime::{
        PrivateReceiptScannerReport, PrivateReceiptScannerReportStatus, ReceiptScanObservation,
        ReceiptScanStatus,
    },
    monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::{
        BridgeExitReleaseReadinessReceipt, ReleaseReadinessStatus,
    },
    monero_l2_pq_bridge_exit_release_remediation_planner_runtime::{
        ReleaseRemediationPlan, RemediationPlanStatus,
    },
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitWalletReceiptPrivacyFixtureRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_WALLET_RECEIPT_PRIVACY_FIXTURE_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-wallet-receipt-privacy-fixture-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_WALLET_RECEIPT_PRIVACY_FIXTURE_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const WALLET_RECEIPT_PRIVACY_FIXTURE_SUITE: &str =
    "monero-l2-pq-bridge-exit-wallet-receipt-privacy-fixture-v1";
pub const DEFAULT_MIN_WALLET_FIXTURES: u64 = 3;
pub const DEFAULT_MAX_COMMITTED_HINTS: u64 = 3;
pub const DEFAULT_MAX_METADATA_FIELDS: u64 = 6;
pub const DEFAULT_FORCED_EXIT_ROOTS_REQUIRED: u64 = 4;
pub const DEFAULT_MAX_FIXTURE_REPORTS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletScanKind {
    ViewTag,
    SubaddressHint,
    ReceiptCommitment,
    ForcedExitGuard,
}

impl WalletScanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ViewTag => "view_tag",
            Self::SubaddressHint => "subaddress_hint",
            Self::ReceiptCommitment => "receipt_commitment",
            Self::ForcedExitGuard => "forced_exit_guard",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletFixtureStatus {
    Ready,
    Watch,
    Blocked,
}

impl WalletFixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Watch => "watch",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_suite: String,
    pub min_wallet_fixtures: u64,
    pub max_committed_hints: u64,
    pub max_metadata_fields: u64,
    pub forced_exit_roots_required: u64,
    pub include_wallet_payloads: bool,
    pub release_gate_deferred: bool,
    pub remediation_gate_deferred: bool,
    pub max_reports: usize,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_suite: WALLET_RECEIPT_PRIVACY_FIXTURE_SUITE.to_string(),
            min_wallet_fixtures: DEFAULT_MIN_WALLET_FIXTURES,
            max_committed_hints: DEFAULT_MAX_COMMITTED_HINTS,
            max_metadata_fields: DEFAULT_MAX_METADATA_FIELDS,
            forced_exit_roots_required: DEFAULT_FORCED_EXIT_ROOTS_REQUIRED,
            include_wallet_payloads: false,
            release_gate_deferred: true,
            remediation_gate_deferred: true,
            max_reports: DEFAULT_MAX_FIXTURE_REPORTS,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_suite": self.fixture_suite,
            "min_wallet_fixtures": self.min_wallet_fixtures,
            "max_committed_hints": self.max_committed_hints,
            "max_metadata_fields": self.max_metadata_fields,
            "forced_exit_roots_required": self.forced_exit_roots_required,
            "include_wallet_payloads": self.include_wallet_payloads,
            "release_gate_deferred": self.release_gate_deferred,
            "remediation_gate_deferred": self.remediation_gate_deferred,
            "max_reports": self.max_reports,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReceiptPrivacyFixture {
    pub fixture_id: String,
    pub status: WalletFixtureStatus,
    pub wallet_label: String,
    pub scan_kind: WalletScanKind,
    pub scanner_observation_id: String,
    pub scanner_observation_status: ReceiptScanStatus,
    pub release_claim_id: String,
    pub transfer_id: String,
    pub scenario_id: String,
    pub committed_hint_count: u64,
    pub metadata_field_count: u64,
    pub metadata_leakage_units: u64,
    pub scan_window_start: u64,
    pub scan_window_end: u64,
    pub privacy_set_size: u64,
    pub wallet_scan_root: String,
    pub committed_hint_root: String,
    pub bounded_metadata_root: String,
    pub forced_exit_root: String,
    pub receipt_guard_root: String,
    pub readiness_root: String,
    pub remediation_root: String,
    pub fixture_root: String,
    pub wallet_payload: Option<Value>,
}

impl WalletReceiptPrivacyFixture {
    pub fn from_observation(
        config: &Config,
        observation: &ReceiptScanObservation,
        readiness: &BridgeExitReleaseReadinessReceipt,
        remediation: &ReleaseRemediationPlan,
        ordinal: u64,
    ) -> Self {
        let scan_kind = scan_kind(ordinal);
        let wallet_label = wallet_label(scan_kind, ordinal);
        let committed_hint_count = committed_hint_count(config, scan_kind);
        let metadata_field_count = metadata_field_count(config, observation);
        let wallet_scan_root = wallet_scan_root(&wallet_label, scan_kind, observation);
        let committed_hint_root =
            committed_hint_root(config, scan_kind, observation, committed_hint_count);
        let bounded_metadata_root =
            bounded_metadata_root(config, observation, metadata_field_count);
        let forced_exit_root = forced_exit_root(
            &observation.exit_receipt_guard_root,
            &readiness.roots.blocker_root,
            &remediation.roots.priority_root,
            config.forced_exit_roots_required,
        );
        let receipt_guard_root = receipt_guard_root(
            &observation.receipt_root,
            &bounded_metadata_root,
            &forced_exit_root,
        );
        let readiness_root = readiness.state_root();
        let remediation_root = remediation.state_root();
        let status = fixture_status(config, observation, readiness, remediation);
        let fixture_root = fixture_root(
            status,
            &wallet_scan_root,
            &committed_hint_root,
            &bounded_metadata_root,
            &forced_exit_root,
            &readiness_root,
            &remediation_root,
        );
        let wallet_payload = config.include_wallet_payloads.then(|| {
            json!({
                "wallet_label": wallet_label,
                "scan_kind": scan_kind.as_str(),
                "committed_hint_root": committed_hint_root,
                "bounded_metadata_root": bounded_metadata_root,
                "forced_exit_root": forced_exit_root,
            })
        });
        let fixture_id = fixture_id(&wallet_label, &fixture_root);
        Self {
            fixture_id,
            status,
            wallet_label,
            scan_kind,
            scanner_observation_id: observation.observation_id.clone(),
            scanner_observation_status: observation.status,
            release_claim_id: observation.release_claim_id.clone(),
            transfer_id: observation.transfer_id.clone(),
            scenario_id: observation.scenario_id.clone(),
            committed_hint_count,
            metadata_field_count,
            metadata_leakage_units: observation.metadata_leakage_units,
            scan_window_start: observation.scan_window_start,
            scan_window_end: observation.scan_window_end,
            privacy_set_size: observation.privacy_set_size,
            wallet_scan_root,
            committed_hint_root,
            bounded_metadata_root,
            forced_exit_root,
            receipt_guard_root,
            readiness_root,
            remediation_root,
            fixture_root,
            wallet_payload,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "status": self.status.as_str(),
            "wallet_label": self.wallet_label,
            "scan_kind": self.scan_kind.as_str(),
            "scanner_observation_id": self.scanner_observation_id,
            "scanner_observation_status": self.scanner_observation_status.as_str(),
            "release_claim_id": self.release_claim_id,
            "transfer_id": self.transfer_id,
            "scenario_id": self.scenario_id,
            "committed_hint_count": self.committed_hint_count,
            "metadata_field_count": self.metadata_field_count,
            "metadata_leakage_units": self.metadata_leakage_units,
            "scan_window_start": self.scan_window_start,
            "scan_window_end": self.scan_window_end,
            "privacy_set_size": self.privacy_set_size,
            "wallet_scan_root": self.wallet_scan_root,
            "committed_hint_root": self.committed_hint_root,
            "bounded_metadata_root": self.bounded_metadata_root,
            "forced_exit_root": self.forced_exit_root,
            "receipt_guard_root": self.receipt_guard_root,
            "readiness_root": self.readiness_root,
            "remediation_root": self.remediation_root,
            "fixture_root": self.fixture_root,
            "wallet_payload": self.wallet_payload,
        })
    }

    pub fn state_root(&self) -> String {
        self.fixture_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReceiptPrivacyFixtureReceipt {
    pub receipt_id: String,
    pub status: WalletFixtureStatus,
    pub release_claim_id: String,
    pub scanner_report_id: String,
    pub scanner_report_status: PrivateReceiptScannerReportStatus,
    pub readiness_receipt_id: String,
    pub readiness_receipt_status: ReleaseReadinessStatus,
    pub remediation_plan_id: String,
    pub remediation_plan_status: RemediationPlanStatus,
    pub fixtures_total: u64,
    pub fixtures_ready: u64,
    pub fixtures_watch: u64,
    pub fixtures_blocked: u64,
    pub committed_hints_total: u64,
    pub metadata_fields_total: u64,
    pub forced_exit_roots_total: u64,
    pub fixtures: BTreeMap<String, WalletReceiptPrivacyFixture>,
    pub roots: WalletReceiptPrivacyFixtureReceiptRoots,
}

impl WalletReceiptPrivacyFixtureReceipt {
    pub fn public_record(&self) -> Value {
        let fixtures = self
            .fixtures
            .values()
            .map(WalletReceiptPrivacyFixture::public_record)
            .collect::<Vec<_>>();
        json!({
            "receipt_id": self.receipt_id,
            "status": self.status.as_str(),
            "release_claim_id": self.release_claim_id,
            "scanner_report_id": self.scanner_report_id,
            "scanner_report_status": self.scanner_report_status.as_str(),
            "readiness_receipt_id": self.readiness_receipt_id,
            "readiness_receipt_status": self.readiness_receipt_status.as_str(),
            "remediation_plan_id": self.remediation_plan_id,
            "remediation_plan_status": self.remediation_plan_status.as_str(),
            "fixtures_total": self.fixtures_total,
            "fixtures_ready": self.fixtures_ready,
            "fixtures_watch": self.fixtures_watch,
            "fixtures_blocked": self.fixtures_blocked,
            "committed_hints_total": self.committed_hints_total,
            "metadata_fields_total": self.metadata_fields_total,
            "forced_exit_roots_total": self.forced_exit_roots_total,
            "fixtures": fixtures,
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.receipt_root.clone()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WalletReceiptPrivacyFixtureReceiptRoots {
    pub fixture_root: String,
    pub source_root: String,
    pub wallet_scan_root: String,
    pub committed_hint_root: String,
    pub bounded_metadata_root: String,
    pub forced_exit_root: String,
    pub receipt_root: String,
}

impl WalletReceiptPrivacyFixtureReceiptRoots {
    pub fn public_record(&self) -> Value {
        json!({
            "fixture_root": self.fixture_root,
            "source_root": self.source_root,
            "wallet_scan_root": self.wallet_scan_root,
            "committed_hint_root": self.committed_hint_root,
            "bounded_metadata_root": self.bounded_metadata_root,
            "forced_exit_root": self.forced_exit_root,
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
    pub fixtures_total: u64,
    pub fixtures_ready: u64,
    pub fixtures_watch: u64,
    pub fixtures_blocked: u64,
    pub committed_hints_total: u64,
    pub metadata_fields_total: u64,
    pub forced_exit_roots_total: u64,
}

impl Counters {
    pub fn public_record(&self) -> Value {
        json!({
            "receipts_run": self.receipts_run,
            "receipts_ready": self.receipts_ready,
            "receipts_watch": self.receipts_watch,
            "receipts_blocked": self.receipts_blocked,
            "fixtures_total": self.fixtures_total,
            "fixtures_ready": self.fixtures_ready,
            "fixtures_watch": self.fixtures_watch,
            "fixtures_blocked": self.fixtures_blocked,
            "committed_hints_total": self.committed_hints_total,
            "metadata_fields_total": self.metadata_fields_total,
            "forced_exit_roots_total": self.forced_exit_roots_total,
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
                "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURE-EMPTY-RECEIPTS",
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
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURE-STATE",
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
    pub latest_receipt: Option<WalletReceiptPrivacyFixtureReceipt>,
    pub receipt_history: Vec<WalletReceiptPrivacyFixtureReceipt>,
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
        let scanner =
            crate::monero_l2_pq_bridge_exit_private_receipt_scanner_adapter_runtime::devnet();
        let readiness =
            crate::monero_l2_pq_bridge_exit_release_readiness_integrator_runtime::devnet();
        let remediation =
            crate::monero_l2_pq_bridge_exit_release_remediation_planner_runtime::devnet();
        let _ = state.process_wallet_receipt_privacy_fixtures(
            scanner.latest_report.as_ref(),
            readiness.latest_receipt.as_ref(),
            remediation.latest_plan.as_ref(),
        );
        state
    }

    pub fn process_wallet_receipt_privacy_fixtures(
        &mut self,
        scanner_report: Option<&PrivateReceiptScannerReport>,
        readiness_receipt: Option<&BridgeExitReleaseReadinessReceipt>,
        remediation_plan: Option<&ReleaseRemediationPlan>,
    ) -> Result<WalletReceiptPrivacyFixtureReceipt> {
        let scanner_report = scanner_report
            .ok_or_else(|| "wallet receipt privacy fixtures require scanner report".to_string())?;
        let readiness_receipt = readiness_receipt.ok_or_else(|| {
            "wallet receipt privacy fixtures require readiness receipt".to_string()
        })?;
        let remediation_plan = remediation_plan.ok_or_else(|| {
            "wallet receipt privacy fixtures require remediation plan".to_string()
        })?;
        let mut fixtures = BTreeMap::new();
        for (ordinal, observation) in scanner_report.observations.values().enumerate() {
            let fixture = WalletReceiptPrivacyFixture::from_observation(
                &self.config,
                observation,
                readiness_receipt,
                remediation_plan,
                ordinal as u64,
            );
            fixtures.insert(fixture.fixture_id.clone(), fixture);
        }
        let receipt = build_receipt(
            &self.config,
            scanner_report,
            readiness_receipt,
            remediation_plan,
            fixtures,
        );
        self.apply_receipt(receipt.clone());
        Ok(receipt)
    }

    pub fn public_record(&self) -> Value {
        let receipt_history = self
            .receipt_history
            .iter()
            .map(WalletReceiptPrivacyFixtureReceipt::public_record)
            .collect::<Vec<_>>();
        json!({
            "config": self.config.public_record(),
            "latest_receipt": self.latest_receipt.as_ref().map(WalletReceiptPrivacyFixtureReceipt::public_record),
            "receipt_history": receipt_history,
            "counters": self.counters.public_record(),
            "roots": self.roots.public_record(),
        })
    }

    pub fn state_root(&self) -> String {
        self.roots.state_root.clone()
    }

    fn apply_receipt(&mut self, receipt: WalletReceiptPrivacyFixtureReceipt) {
        self.counters.receipts_run += 1;
        self.counters.fixtures_total += receipt.fixtures_total;
        self.counters.fixtures_ready += receipt.fixtures_ready;
        self.counters.fixtures_watch += receipt.fixtures_watch;
        self.counters.fixtures_blocked += receipt.fixtures_blocked;
        self.counters.committed_hints_total += receipt.committed_hints_total;
        self.counters.metadata_fields_total += receipt.metadata_fields_total;
        self.counters.forced_exit_roots_total += receipt.forced_exit_roots_total;
        match receipt.status {
            WalletFixtureStatus::Ready => self.counters.receipts_ready += 1,
            WalletFixtureStatus::Watch => self.counters.receipts_watch += 1,
            WalletFixtureStatus::Blocked => self.counters.receipts_blocked += 1,
        }
        self.latest_receipt = Some(receipt.clone());
        self.receipt_history.push(receipt);
        if self.receipt_history.len() > self.config.max_reports {
            let trim = self.receipt_history.len() - self.config.max_reports;
            self.receipt_history.drain(0..trim);
        }
        let receipt_roots = self
            .receipt_history
            .iter()
            .map(WalletReceiptPrivacyFixtureReceipt::state_root)
            .collect::<Vec<_>>();
        self.roots = Roots {
            config_root: self.config.state_root(),
            receipt_root: merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURE-RECEIPTS",
                &receipt_roots,
            ),
            counters_root: self.counters.state_root(),
            state_root: String::new(),
        };
        self.roots.state_root = self.roots.compute_state_root();
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

fn build_receipt(
    config: &Config,
    scanner_report: &PrivateReceiptScannerReport,
    readiness_receipt: &BridgeExitReleaseReadinessReceipt,
    remediation_plan: &ReleaseRemediationPlan,
    fixtures: BTreeMap<String, WalletReceiptPrivacyFixture>,
) -> WalletReceiptPrivacyFixtureReceipt {
    let fixtures_total = fixtures.len() as u64;
    let fixtures_ready = fixtures
        .values()
        .filter(|fixture| fixture.status == WalletFixtureStatus::Ready)
        .count() as u64;
    let fixtures_watch = fixtures
        .values()
        .filter(|fixture| fixture.status == WalletFixtureStatus::Watch)
        .count() as u64;
    let fixtures_blocked = fixtures
        .values()
        .filter(|fixture| fixture.status == WalletFixtureStatus::Blocked)
        .count() as u64;
    let committed_hints_total = fixtures
        .values()
        .map(|fixture| fixture.committed_hint_count)
        .sum();
    let metadata_fields_total = fixtures
        .values()
        .map(|fixture| fixture.metadata_field_count)
        .sum();
    let forced_exit_roots_total = fixtures_total * config.forced_exit_roots_required;
    let status = receipt_status(config, fixtures_total, fixtures_watch, fixtures_blocked);
    let fixture_roots = fixtures
        .values()
        .map(WalletReceiptPrivacyFixture::state_root)
        .collect::<Vec<_>>();
    let wallet_scan_roots = fixtures
        .values()
        .map(|fixture| fixture.wallet_scan_root.clone())
        .collect::<Vec<_>>();
    let committed_hint_roots = fixtures
        .values()
        .map(|fixture| fixture.committed_hint_root.clone())
        .collect::<Vec<_>>();
    let bounded_metadata_roots = fixtures
        .values()
        .map(|fixture| fixture.bounded_metadata_root.clone())
        .collect::<Vec<_>>();
    let forced_exit_roots = fixtures
        .values()
        .map(|fixture| fixture.forced_exit_root.clone())
        .collect::<Vec<_>>();
    let fixture_root = merkle_root(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURES",
        &fixture_roots,
    );
    let source_root = source_root(
        scanner_report,
        readiness_receipt,
        remediation_plan,
        &fixture_root,
    );
    let roots = WalletReceiptPrivacyFixtureReceiptRoots {
        fixture_root,
        source_root,
        wallet_scan_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-WALLET-SCANS",
            &wallet_scan_roots,
        ),
        committed_hint_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-COMMITTED-HINTS",
            &committed_hint_roots,
        ),
        bounded_metadata_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-BOUNDED-METADATA",
            &bounded_metadata_roots,
        ),
        forced_exit_root: merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FORCED-EXIT-ROOTS",
            &forced_exit_roots,
        ),
        receipt_root: String::new(),
    };
    let mut roots = roots;
    roots.receipt_root = receipt_root(
        status,
        &scanner_report.report_id,
        &readiness_receipt.receipt_id,
        &remediation_plan.plan_id,
        &roots,
        fixtures_total,
    );
    let receipt_id = receipt_id(&scanner_report.release_claim_id, &roots.receipt_root);
    WalletReceiptPrivacyFixtureReceipt {
        receipt_id,
        status,
        release_claim_id: scanner_report.release_claim_id.clone(),
        scanner_report_id: scanner_report.report_id.clone(),
        scanner_report_status: scanner_report.status,
        readiness_receipt_id: readiness_receipt.receipt_id.clone(),
        readiness_receipt_status: readiness_receipt.status,
        remediation_plan_id: remediation_plan.plan_id.clone(),
        remediation_plan_status: remediation_plan.status,
        fixtures_total,
        fixtures_ready,
        fixtures_watch,
        fixtures_blocked,
        committed_hints_total,
        metadata_fields_total,
        forced_exit_roots_total,
        fixtures,
        roots,
    }
}

fn scan_kind(ordinal: u64) -> WalletScanKind {
    match ordinal % 4 {
        0 => WalletScanKind::ViewTag,
        1 => WalletScanKind::SubaddressHint,
        2 => WalletScanKind::ReceiptCommitment,
        _ => WalletScanKind::ForcedExitGuard,
    }
}

fn wallet_label(scan_kind: WalletScanKind, ordinal: u64) -> String {
    format!("devnet-wallet-{}-{:02}", scan_kind.as_str(), ordinal + 1)
}

fn committed_hint_count(config: &Config, scan_kind: WalletScanKind) -> u64 {
    match scan_kind {
        WalletScanKind::ViewTag => 1,
        WalletScanKind::SubaddressHint => 2.min(config.max_committed_hints),
        WalletScanKind::ReceiptCommitment | WalletScanKind::ForcedExitGuard => {
            config.max_committed_hints
        }
    }
}

fn metadata_field_count(config: &Config, observation: &ReceiptScanObservation) -> u64 {
    let base = 4 + observation.metadata_leakage_units.min(2);
    base.min(config.max_metadata_fields)
}

fn fixture_status(
    config: &Config,
    observation: &ReceiptScanObservation,
    readiness: &BridgeExitReleaseReadinessReceipt,
    remediation: &ReleaseRemediationPlan,
) -> WalletFixtureStatus {
    if observation.status == ReceiptScanStatus::Rejected
        || observation.metadata_leakage_units > config.max_metadata_fields
        || readiness.status == ReleaseReadinessStatus::Blocked
        || remediation.status == RemediationPlanStatus::Blocked
    {
        WalletFixtureStatus::Blocked
    } else if observation.status == ReceiptScanStatus::Deferred
        || readiness.status == ReleaseReadinessStatus::Watch
        || remediation.status == RemediationPlanStatus::Active
    {
        WalletFixtureStatus::Watch
    } else {
        WalletFixtureStatus::Ready
    }
}

fn receipt_status(
    config: &Config,
    fixtures_total: u64,
    fixtures_watch: u64,
    fixtures_blocked: u64,
) -> WalletFixtureStatus {
    if fixtures_blocked > 0 || fixtures_total < config.min_wallet_fixtures {
        WalletFixtureStatus::Blocked
    } else if fixtures_watch > 0 {
        WalletFixtureStatus::Watch
    } else {
        WalletFixtureStatus::Ready
    }
}

fn wallet_scan_root(
    wallet_label: &str,
    scan_kind: WalletScanKind,
    observation: &ReceiptScanObservation,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-WALLET-SCAN",
        &[
            HashPart::Str(wallet_label),
            HashPart::Str(scan_kind.as_str()),
            HashPart::Str(&observation.view_tag_root),
            HashPart::Str(&observation.subaddress_hint_root),
            HashPart::Str(&observation.receipt_commitment_root),
            HashPart::U64(observation.scan_window_start),
            HashPart::U64(observation.scan_window_end),
        ],
        32,
    )
}

fn committed_hint_root(
    config: &Config,
    scan_kind: WalletScanKind,
    observation: &ReceiptScanObservation,
    committed_hint_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-COMMITTED-HINT",
        &[
            HashPart::Str(scan_kind.as_str()),
            HashPart::Str(&observation.view_tag_root),
            HashPart::Str(&observation.subaddress_hint_root),
            HashPart::Str(&observation.receipt_commitment_root),
            HashPart::U64(committed_hint_count),
            HashPart::U64(config.max_committed_hints),
        ],
        32,
    )
}

fn bounded_metadata_root(
    config: &Config,
    observation: &ReceiptScanObservation,
    metadata_field_count: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-BOUNDED-METADATA",
        &[
            HashPart::Str(&observation.metadata_budget_root),
            HashPart::U64(metadata_field_count),
            HashPart::U64(config.max_metadata_fields),
            HashPart::U64(observation.metadata_leakage_units),
            HashPart::U64(observation.privacy_set_size),
        ],
        32,
    )
}

fn forced_exit_root(
    exit_receipt_guard_root: &str,
    readiness_blocker_root: &str,
    remediation_priority_root: &str,
    required_roots: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FORCED-EXIT",
        &[
            HashPart::Str(exit_receipt_guard_root),
            HashPart::Str(readiness_blocker_root),
            HashPart::Str(remediation_priority_root),
            HashPart::U64(required_roots),
        ],
        32,
    )
}

fn receipt_guard_root(
    receipt_root: &str,
    bounded_metadata_root: &str,
    forced_exit_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-RECEIPT-GUARD",
        &[
            HashPart::Str(receipt_root),
            HashPart::Str(bounded_metadata_root),
            HashPart::Str(forced_exit_root),
        ],
        32,
    )
}

fn fixture_root(
    status: WalletFixtureStatus,
    wallet_scan_root: &str,
    committed_hint_root: &str,
    bounded_metadata_root: &str,
    forced_exit_root: &str,
    readiness_root: &str,
    remediation_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURE",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(wallet_scan_root),
            HashPart::Str(committed_hint_root),
            HashPart::Str(bounded_metadata_root),
            HashPart::Str(forced_exit_root),
            HashPart::Str(readiness_root),
            HashPart::Str(remediation_root),
        ],
        32,
    )
}

fn source_root(
    scanner_report: &PrivateReceiptScannerReport,
    readiness_receipt: &BridgeExitReleaseReadinessReceipt,
    remediation_plan: &ReleaseRemediationPlan,
    fixture_root: &str,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-SOURCE",
        &[
            HashPart::Str(&scanner_report.roots.report_root),
            HashPart::Str(&readiness_receipt.roots.receipt_root),
            HashPart::Str(&remediation_plan.roots.plan_root),
            HashPart::Str(fixture_root),
        ],
        32,
    )
}

fn receipt_root(
    status: WalletFixtureStatus,
    scanner_report_id: &str,
    readiness_receipt_id: &str,
    remediation_plan_id: &str,
    roots: &WalletReceiptPrivacyFixtureReceiptRoots,
    fixtures_total: u64,
) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-RECEIPT",
        &[
            HashPart::Str(status.as_str()),
            HashPart::Str(scanner_report_id),
            HashPart::Str(readiness_receipt_id),
            HashPart::Str(remediation_plan_id),
            HashPart::Str(&roots.fixture_root),
            HashPart::Str(&roots.source_root),
            HashPart::Str(&roots.wallet_scan_root),
            HashPart::Str(&roots.committed_hint_root),
            HashPart::Str(&roots.bounded_metadata_root),
            HashPart::Str(&roots.forced_exit_root),
            HashPart::U64(fixtures_total),
        ],
        32,
    )
}

fn fixture_id(wallet_label: &str, fixture_root: &str) -> String {
    format!("wallet-receipt-privacy-fixture-{wallet_label}-{fixture_root}")
}

fn receipt_id(release_claim_id: &str, receipt_root: &str) -> String {
    format!("wallet-receipt-privacy-fixture-receipt-{release_claim_id}-{receipt_root}")
}

pub fn record_root(kind: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-WALLET-RECEIPT-PRIVACY-FIXTURE-RECORD",
        &[
            HashPart::Str(kind),
            HashPart::Json(record),
            HashPart::Str(PROTOCOL_VERSION),
        ],
        32,
    )
}
