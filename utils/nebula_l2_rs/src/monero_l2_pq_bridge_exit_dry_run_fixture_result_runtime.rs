use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    hash::{domain_hash, merkle_root, HashPart},
    CHAIN_ID,
};

pub type Result<T> = std::result::Result<T, String>;
pub type MoneroL2PqBridgeExitDryRunFixtureResultRuntimeResult<T> = Result<T>;
pub type Runtime = State;

pub const MONERO_L2_PQ_BRIDGE_EXIT_DRY_RUN_FIXTURE_RESULT_RUNTIME_PROTOCOL_VERSION: &str =
    "nebula-monero-l2-pq-bridge-exit-dry-run-fixture-result-runtime-v1";
pub const PROTOCOL_VERSION: &str =
    MONERO_L2_PQ_BRIDGE_EXIT_DRY_RUN_FIXTURE_RESULT_RUNTIME_PROTOCOL_VERSION;
pub const SCHEMA_VERSION: u64 = 1;
pub const HASH_SUITE: &str = "SHAKE256-domain-separated-canonical-json";
pub const FIXTURE_RESULT_SUITE: &str = "monero-private-l2-bridge-exit-dry-run-fixture-results-v1";
pub const DEFAULT_MAX_FIXTURES: usize = 128;
pub const DEFAULT_MIN_PASS_STAGES: u64 = 5;
pub const DEFAULT_MAX_WATCH_STAGES: u64 = 2;
pub const DEFAULT_MAX_USER_FEE_BPS: u64 = 30;
pub const DEFAULT_MIN_PRIVACY_SET_SIZE: u64 = 96;
pub const DEFAULT_MIN_PQ_EVIDENCE_COUNT: u64 = 4;
pub const DEFAULT_DEPOSIT_AMOUNT_PICONERO: u128 = 800_000_000_000;
pub const DEFAULT_MAX_USER_FEE_PICONERO: u128 = 24_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStage {
    DepositAdmission,
    PrivateNote,
    MinimalPrivateTransfer,
    SettlementReceipt,
    ForcedWithdrawalExit,
}

impl FixtureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DepositAdmission => "deposit_admission",
            Self::PrivateNote => "private_note",
            Self::MinimalPrivateTransfer => "minimal_private_transfer",
            Self::SettlementReceipt => "settlement_receipt",
            Self::ForcedWithdrawalExit => "forced_withdrawal_exit",
        }
    }

    pub fn is_exit_critical(self) -> bool {
        matches!(
            self,
            Self::DepositAdmission | Self::SettlementReceipt | Self::ForcedWithdrawalExit
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixtureStatus {
    Pass,
    Watch,
    Block,
}

impl FixtureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Watch => "watch",
            Self::Block => "block",
        }
    }

    pub fn blocks_dry_run(self) -> bool {
        matches!(self, Self::Block)
    }

    pub fn blocks_production(self) -> bool {
        matches!(self, Self::Watch | Self::Block)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Present,
    Simulated,
    Deferred,
    Missing,
    Rejected,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Simulated => "simulated",
            Self::Deferred => "deferred",
            Self::Missing => "missing",
            Self::Rejected => "rejected",
        }
    }

    pub fn fixture_status(self) -> FixtureStatus {
        match self {
            Self::Present => FixtureStatus::Pass,
            Self::Simulated | Self::Deferred => FixtureStatus::Watch,
            Self::Missing | Self::Rejected => FixtureStatus::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProductionBlockerKind {
    CargoChecksDeferred,
    ProductionReleaseDisabled,
    SimulatedMoneroWatcher,
    SimulatedPqAuthority,
    SimulatedSettlementAdapter,
    PrivacyFloorNotMet,
    UserFeeAboveLowFeeBound,
    MissingExitAuthorization,
    MissingFixtureRoot,
}

impl ProductionBlockerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CargoChecksDeferred => "cargo_checks_deferred",
            Self::ProductionReleaseDisabled => "production_release_disabled",
            Self::SimulatedMoneroWatcher => "simulated_monero_watcher",
            Self::SimulatedPqAuthority => "simulated_pq_authority",
            Self::SimulatedSettlementAdapter => "simulated_settlement_adapter",
            Self::PrivacyFloorNotMet => "privacy_floor_not_met",
            Self::UserFeeAboveLowFeeBound => "user_fee_above_low_fee_bound",
            Self::MissingExitAuthorization => "missing_exit_authorization",
            Self::MissingFixtureRoot => "missing_fixture_root",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub chain_id: String,
    pub protocol_version: String,
    pub schema_version: u64,
    pub hash_suite: String,
    pub fixture_result_suite: String,
    pub max_fixtures: usize,
    pub min_pass_stages: u64,
    pub max_watch_stages: u64,
    pub max_user_fee_bps: u64,
    pub min_privacy_set_size: u64,
    pub min_pq_evidence_count: u64,
    pub deposit_amount_piconero: u128,
    pub max_user_fee_piconero: u128,
    pub cargo_checks_deferred: bool,
    pub production_release_allowed: bool,
}

impl Config {
    pub fn devnet() -> Self {
        Self {
            chain_id: CHAIN_ID.to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            schema_version: SCHEMA_VERSION,
            hash_suite: HASH_SUITE.to_string(),
            fixture_result_suite: FIXTURE_RESULT_SUITE.to_string(),
            max_fixtures: DEFAULT_MAX_FIXTURES,
            min_pass_stages: DEFAULT_MIN_PASS_STAGES,
            max_watch_stages: DEFAULT_MAX_WATCH_STAGES,
            max_user_fee_bps: DEFAULT_MAX_USER_FEE_BPS,
            min_privacy_set_size: DEFAULT_MIN_PRIVACY_SET_SIZE,
            min_pq_evidence_count: DEFAULT_MIN_PQ_EVIDENCE_COUNT,
            deposit_amount_piconero: DEFAULT_DEPOSIT_AMOUNT_PICONERO,
            max_user_fee_piconero: DEFAULT_MAX_USER_FEE_PICONERO,
            cargo_checks_deferred: true,
            production_release_allowed: false,
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "chain_id": self.chain_id,
            "protocol_version": self.protocol_version,
            "schema_version": self.schema_version,
            "hash_suite": self.hash_suite,
            "fixture_result_suite": self.fixture_result_suite,
            "max_fixtures": self.max_fixtures,
            "min_pass_stages": self.min_pass_stages,
            "max_watch_stages": self.max_watch_stages,
            "max_user_fee_bps": self.max_user_fee_bps,
            "min_privacy_set_size": self.min_privacy_set_size,
            "min_pq_evidence_count": self.min_pq_evidence_count,
            "deposit_amount_piconero": self.deposit_amount_piconero.to_string(),
            "max_user_fee_piconero": self.max_user_fee_piconero.to_string(),
            "cargo_checks_deferred": self.cargo_checks_deferred,
            "production_release_allowed": self.production_release_allowed,
        })
    }

    pub fn state_root(&self) -> String {
        record_root("config", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SimulatedExecutionRoot {
    pub stage: FixtureStage,
    pub execution_root: String,
    pub transcript_root: String,
    pub adapter_root: String,
    pub evidence_status: EvidenceStatus,
    pub simulated: bool,
}

impl SimulatedExecutionRoot {
    pub fn public_record(&self) -> Value {
        json!({
            "stage": self.stage.as_str(),
            "execution_root": self.execution_root,
            "transcript_root": self.transcript_root,
            "adapter_root": self.adapter_root,
            "evidence_status": self.evidence_status.as_str(),
            "simulated": self.simulated,
            "stage_exit_critical": self.stage.is_exit_critical(),
        })
    }

    pub fn fixture_result_root(&self) -> String {
        record_root("simulated_execution_root", &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LowFeeCheck {
    pub fee_piconero: u128,
    pub fee_bps: u64,
    pub max_fee_piconero: u128,
    pub max_fee_bps: u64,
    pub sponsored: bool,
}

impl LowFeeCheck {
    pub fn status(&self) -> FixtureStatus {
        if self.fee_piconero <= self.max_fee_piconero && self.fee_bps <= self.max_fee_bps {
            FixtureStatus::Pass
        } else if self.sponsored && self.fee_bps <= self.max_fee_bps {
            FixtureStatus::Watch
        } else {
            FixtureStatus::Block
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "fee_piconero": self.fee_piconero.to_string(),
            "fee_bps": self.fee_bps,
            "max_fee_piconero": self.max_fee_piconero.to_string(),
            "max_fee_bps": self.max_fee_bps,
            "sponsored": self.sponsored,
            "status": self.status().as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivacyCheck {
    pub note_commitment_hidden: bool,
    pub sender_receiver_unlinked: bool,
    pub amount_hidden: bool,
    pub view_tag_leak_regression_clean: bool,
    pub anonymity_set_size: u64,
    pub min_anonymity_set_size: u64,
}

impl PrivacyCheck {
    pub fn status(&self) -> FixtureStatus {
        let hard_pass = self.note_commitment_hidden
            && self.sender_receiver_unlinked
            && self.amount_hidden
            && self.view_tag_leak_regression_clean
            && self.anonymity_set_size >= self.min_anonymity_set_size;
        let watch = self.note_commitment_hidden
            && self.amount_hidden
            && self.anonymity_set_size >= self.min_anonymity_set_size / 2;
        if hard_pass {
            FixtureStatus::Pass
        } else if watch {
            FixtureStatus::Watch
        } else {
            FixtureStatus::Block
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "note_commitment_hidden": self.note_commitment_hidden,
            "sender_receiver_unlinked": self.sender_receiver_unlinked,
            "amount_hidden": self.amount_hidden,
            "view_tag_leak_regression_clean": self.view_tag_leak_regression_clean,
            "anonymity_set_size": self.anonymity_set_size,
            "min_anonymity_set_size": self.min_anonymity_set_size,
            "status": self.status().as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PqControlPlaneEvidence {
    pub authority_epoch: u64,
    pub keyset_root: String,
    pub signature_scheme: String,
    pub rotation_root: String,
    pub transcript_binding_root: String,
    pub threshold_signatures: u64,
    pub required_signatures: u64,
    pub evidence_status: EvidenceStatus,
}

impl PqControlPlaneEvidence {
    pub fn status(&self) -> FixtureStatus {
        if self.threshold_signatures < self.required_signatures {
            FixtureStatus::Block
        } else {
            self.evidence_status.fixture_status()
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "authority_epoch": self.authority_epoch,
            "keyset_root": self.keyset_root,
            "signature_scheme": self.signature_scheme,
            "rotation_root": self.rotation_root,
            "transcript_binding_root": self.transcript_binding_root,
            "threshold_signatures": self.threshold_signatures,
            "required_signatures": self.required_signatures,
            "evidence_status": self.evidence_status.as_str(),
            "status": self.status().as_str(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StageFixtureResult {
    pub stage: FixtureStage,
    pub execution_root: SimulatedExecutionRoot,
    pub low_fee_check: LowFeeCheck,
    pub privacy_check: PrivacyCheck,
    pub pq_evidence: PqControlPlaneEvidence,
    pub receipt_root: String,
    pub production_blockers: Vec<ProductionBlockerKind>,
}

impl StageFixtureResult {
    pub fn status(&self) -> FixtureStatus {
        if self
            .execution_root
            .evidence_status
            .fixture_status()
            .blocks_dry_run()
            || self.low_fee_check.status().blocks_dry_run()
            || self.privacy_check.status().blocks_dry_run()
            || self.pq_evidence.status().blocks_dry_run()
        {
            FixtureStatus::Block
        } else if self.execution_root.simulated
            || self
                .execution_root
                .evidence_status
                .fixture_status()
                .blocks_production()
            || self.low_fee_check.status().blocks_production()
            || self.privacy_check.status().blocks_production()
            || self.pq_evidence.status().blocks_production()
            || !self.production_blockers.is_empty()
        {
            FixtureStatus::Watch
        } else {
            FixtureStatus::Pass
        }
    }

    pub fn public_record(&self) -> Value {
        json!({
            "stage": self.stage.as_str(),
            "execution_root": self.execution_root.public_record(),
            "fixture_result_root": self.execution_root.fixture_result_root(),
            "low_fee_check": self.low_fee_check.public_record(),
            "privacy_check": self.privacy_check.public_record(),
            "pq_evidence": self.pq_evidence.public_record(),
            "receipt_root": self.receipt_root,
            "production_blockers": self.production_blockers
                .iter()
                .map(|blocker| blocker.as_str())
                .collect::<Vec<_>>(),
            "status": self.status().as_str(),
        })
    }

    pub fn state_root(&self) -> String {
        record_root(self.stage.as_str(), &self.public_record())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FixtureResult {
    pub fixture_id: String,
    pub scenario_label: String,
    pub deposit_note_root: String,
    pub private_transfer_root: String,
    pub settlement_receipt_root: String,
    pub forced_exit_root: String,
    pub stage_results: Vec<StageFixtureResult>,
}

impl FixtureResult {
    pub fn status_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::from([
            ("pass".to_string(), 0_u64),
            ("watch".to_string(), 0_u64),
            ("block".to_string(), 0_u64),
        ]);
        for result in &self.stage_results {
            let key = result.status().as_str().to_string();
            let current = counts.get(&key).copied().unwrap_or(0);
            counts.insert(key, current + 1);
        }
        counts
    }

    pub fn status(&self) -> FixtureStatus {
        let counts = self.status_counts();
        if counts.get("block").copied().unwrap_or(0) > 0 {
            FixtureStatus::Block
        } else if counts.get("watch").copied().unwrap_or(0) > 0 {
            FixtureStatus::Watch
        } else {
            FixtureStatus::Pass
        }
    }

    pub fn fixture_result_root(&self) -> String {
        record_root("fixture_result", &self.public_record_without_root())
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "fixture_id": self.fixture_id,
            "scenario_label": self.scenario_label,
            "deposit_note_root": self.deposit_note_root,
            "private_transfer_root": self.private_transfer_root,
            "settlement_receipt_root": self.settlement_receipt_root,
            "forced_exit_root": self.forced_exit_root,
            "stage_results": self.stage_results
                .iter()
                .map(StageFixtureResult::public_record)
                .collect::<Vec<_>>(),
            "stage_result_root": merkle_root(
                "MONERO-L2-PQ-BRIDGE-EXIT-FIXTURE-STAGE-RESULTS",
                &self.stage_results
                    .iter()
                    .map(StageFixtureResult::public_record)
                    .collect::<Vec<_>>()
            ),
            "status_counts": self.status_counts(),
            "status": self.status().as_str(),
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert(
                "fixture_result_root".to_string(),
                Value::String(self.fixture_result_root()),
            );
        }
        record
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProductionBlocker {
    pub blocker_id: String,
    pub kind: ProductionBlockerKind,
    pub source_stage: Option<FixtureStage>,
    pub evidence_root: String,
    pub remediation: String,
}

impl ProductionBlocker {
    pub fn public_record(&self) -> Value {
        json!({
            "blocker_id": self.blocker_id,
            "kind": self.kind.as_str(),
            "source_stage": self.source_stage.map(FixtureStage::as_str),
            "evidence_root": self.evidence_root,
            "remediation": self.remediation,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct State {
    pub config: Config,
    pub fixtures: Vec<FixtureResult>,
    pub production_blockers: Vec<ProductionBlocker>,
    pub fixture_notes: BTreeMap<String, String>,
}

impl State {
    pub fn devnet() -> Self {
        let config = Config::devnet();
        let fixtures = vec![devnet_fixture_result(&config)];
        let production_blockers = devnet_production_blockers(&config, &fixtures);
        let fixture_notes = BTreeMap::from([
            (
                "deposit_admission".to_string(),
                "deposit lock watcher evidence remains simulated until adapter receipts are live"
                    .to_string(),
            ),
            (
                "private_note".to_string(),
                "private note root binds deposit note mint without exposing amount or recipient"
                    .to_string(),
            ),
            (
                "forced_withdrawal_exit".to_string(),
                "forced exit path is dry-run complete but production release remains disabled"
                    .to_string(),
            ),
        ]);
        Self {
            config,
            fixtures,
            production_blockers,
            fixture_notes,
        }
    }

    pub fn fixture_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-FIXTURE-RESULTS",
            &self
                .fixtures
                .iter()
                .map(FixtureResult::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn blocker_root(&self) -> String {
        merkle_root(
            "MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-PRODUCTION-BLOCKERS",
            &self
                .production_blockers
                .iter()
                .map(ProductionBlocker::public_record)
                .collect::<Vec<_>>(),
        )
    }

    pub fn status_counts(&self) -> BTreeMap<String, u64> {
        let mut counts = BTreeMap::from([
            ("pass".to_string(), 0_u64),
            ("watch".to_string(), 0_u64),
            ("block".to_string(), 0_u64),
        ]);
        for fixture in &self.fixtures {
            for (key, value) in fixture.status_counts() {
                let current = counts.get(&key).copied().unwrap_or(0);
                counts.insert(key, current + value);
            }
        }
        counts
    }

    pub fn release_status(&self) -> FixtureStatus {
        if !self.config.production_release_allowed || !self.production_blockers.is_empty() {
            FixtureStatus::Block
        } else if self
            .fixtures
            .iter()
            .any(|fixture| fixture.status().blocks_production())
        {
            FixtureStatus::Watch
        } else {
            FixtureStatus::Pass
        }
    }

    pub fn public_record_without_root(&self) -> Value {
        json!({
            "kind": "monero_l2_pq_bridge_exit_dry_run_fixture_result_runtime",
            "config": self.config.public_record(),
            "config_root": self.config.state_root(),
            "fixtures": self.fixtures
                .iter()
                .map(FixtureResult::public_record)
                .collect::<Vec<_>>(),
            "fixture_root": self.fixture_root(),
            "production_blockers": self.production_blockers
                .iter()
                .map(ProductionBlocker::public_record)
                .collect::<Vec<_>>(),
            "production_blocker_root": self.blocker_root(),
            "fixture_notes": self.fixture_notes,
            "status_counts": self.status_counts(),
            "release_status": self.release_status().as_str(),
            "cargo_checks_deferred": self.config.cargo_checks_deferred,
            "production_release_allowed": self.config.production_release_allowed,
        })
    }

    pub fn public_record(&self) -> Value {
        let mut record = self.public_record_without_root();
        if let Value::Object(values) = &mut record {
            values.insert("state_root".to_string(), Value::String(self.state_root()));
        }
        record
    }

    pub fn state_root(&self) -> String {
        record_root("state", &self.public_record_without_root())
    }
}

pub fn devnet() -> State {
    State::devnet()
}

pub fn public_record() -> Value {
    devnet().public_record()
}

pub fn state_root() -> String {
    devnet().state_root()
}

pub fn fixture_result_root(fixture: &FixtureResult) -> String {
    fixture.fixture_result_root()
}

pub fn stage_result_root(stage: &StageFixtureResult) -> String {
    stage.state_root()
}

fn devnet_fixture_result(config: &Config) -> FixtureResult {
    let deposit_note_root = root_from_label("deposit-note", "devnet-admission-note");
    let private_transfer_root = root_from_label("private-transfer", "minimal-transfer");
    let settlement_receipt_root = root_from_label("settlement-receipt", "receipt-bound-to-note");
    let forced_exit_root = root_from_label("forced-exit", "dual-path-withdrawal-package");
    let stage_results = vec![
        devnet_stage(
            config,
            FixtureStage::DepositAdmission,
            EvidenceStatus::Simulated,
            true,
            12_000,
            2,
            config.min_privacy_set_size,
            vec![ProductionBlockerKind::SimulatedMoneroWatcher],
        ),
        devnet_stage(
            config,
            FixtureStage::PrivateNote,
            EvidenceStatus::Present,
            false,
            8_000,
            1,
            config.min_privacy_set_size + 32,
            Vec::new(),
        ),
        devnet_stage(
            config,
            FixtureStage::MinimalPrivateTransfer,
            EvidenceStatus::Present,
            false,
            10_000,
            2,
            config.min_privacy_set_size + 16,
            Vec::new(),
        ),
        devnet_stage(
            config,
            FixtureStage::SettlementReceipt,
            EvidenceStatus::Simulated,
            true,
            18_000,
            3,
            config.min_privacy_set_size,
            vec![ProductionBlockerKind::SimulatedSettlementAdapter],
        ),
        devnet_stage(
            config,
            FixtureStage::ForcedWithdrawalExit,
            EvidenceStatus::Simulated,
            true,
            20_000,
            3,
            config.min_privacy_set_size,
            vec![
                ProductionBlockerKind::SimulatedPqAuthority,
                ProductionBlockerKind::MissingExitAuthorization,
            ],
        ),
    ];
    FixtureResult {
        fixture_id: "devnet-fixture-result-001".to_string(),
        scenario_label: "deposit-to-private-note-transfer-receipt-forced-exit".to_string(),
        deposit_note_root,
        private_transfer_root,
        settlement_receipt_root,
        forced_exit_root,
        stage_results,
    }
}

fn devnet_stage(
    config: &Config,
    stage: FixtureStage,
    evidence_status: EvidenceStatus,
    simulated: bool,
    fee_piconero: u128,
    fee_bps: u64,
    anonymity_set_size: u64,
    production_blockers: Vec<ProductionBlockerKind>,
) -> StageFixtureResult {
    let stage_label = stage.as_str();
    let execution_root = SimulatedExecutionRoot {
        stage,
        execution_root: root_from_label(stage_label, "execution"),
        transcript_root: root_from_label(stage_label, "transcript"),
        adapter_root: root_from_label(stage_label, "adapter"),
        evidence_status,
        simulated,
    };
    let low_fee_check = LowFeeCheck {
        fee_piconero,
        fee_bps,
        max_fee_piconero: config.max_user_fee_piconero,
        max_fee_bps: config.max_user_fee_bps,
        sponsored: fee_piconero <= config.max_user_fee_piconero,
    };
    let privacy_check = PrivacyCheck {
        note_commitment_hidden: true,
        sender_receiver_unlinked: true,
        amount_hidden: true,
        view_tag_leak_regression_clean: true,
        anonymity_set_size,
        min_anonymity_set_size: config.min_privacy_set_size,
    };
    let pq_evidence = PqControlPlaneEvidence {
        authority_epoch: 7,
        keyset_root: root_from_label(stage_label, "pq-keyset"),
        signature_scheme: "ML-DSA-87+ML-KEM-1024-control-plane".to_string(),
        rotation_root: root_from_label(stage_label, "pq-rotation"),
        transcript_binding_root: root_from_label(stage_label, "pq-transcript-binding"),
        threshold_signatures: config.min_pq_evidence_count,
        required_signatures: config.min_pq_evidence_count,
        evidence_status,
    };
    StageFixtureResult {
        stage,
        execution_root,
        low_fee_check,
        privacy_check,
        pq_evidence,
        receipt_root: root_from_label(stage_label, "receipt"),
        production_blockers,
    }
}

fn devnet_production_blockers(
    config: &Config,
    fixtures: &[FixtureResult],
) -> Vec<ProductionBlocker> {
    let mut blockers = Vec::new();
    if config.cargo_checks_deferred {
        blockers.push(ProductionBlocker {
            blocker_id: "blocker-cargo-checks-deferred".to_string(),
            kind: ProductionBlockerKind::CargoChecksDeferred,
            source_stage: None,
            evidence_root: config.state_root(),
            remediation: "run cargo check, tests, clippy, and release harness outside this fixture"
                .to_string(),
        });
    }
    if !config.production_release_allowed {
        blockers.push(ProductionBlocker {
            blocker_id: "blocker-production-release-disabled".to_string(),
            kind: ProductionBlockerKind::ProductionReleaseDisabled,
            source_stage: None,
            evidence_root: config.state_root(),
            remediation: "flip only after live adapters, audit signoff, and cargo gates pass"
                .to_string(),
        });
    }
    for fixture in fixtures {
        for stage in &fixture.stage_results {
            for blocker in &stage.production_blockers {
                blockers.push(ProductionBlocker {
                    blocker_id: format!("blocker-{}-{}", stage.stage.as_str(), blocker.as_str()),
                    kind: *blocker,
                    source_stage: Some(stage.stage),
                    evidence_root: stage.state_root(),
                    remediation: remediation_for(*blocker).to_string(),
                });
            }
        }
    }
    blockers
}

fn remediation_for(blocker: ProductionBlockerKind) -> &'static str {
    match blocker {
        ProductionBlockerKind::CargoChecksDeferred => {
            "complete cargo verification and attach signed check evidence"
        }
        ProductionBlockerKind::ProductionReleaseDisabled => {
            "enable release only from audited production configuration"
        }
        ProductionBlockerKind::SimulatedMoneroWatcher => {
            "replace simulated lock watcher with indexed Monero custody evidence"
        }
        ProductionBlockerKind::SimulatedPqAuthority => {
            "attach live PQ authority threshold signatures and rotation transcript"
        }
        ProductionBlockerKind::SimulatedSettlementAdapter => {
            "replace simulated settlement adapter receipt with live verifier output"
        }
        ProductionBlockerKind::PrivacyFloorNotMet => {
            "increase anonymity set and rerun privacy leak regression"
        }
        ProductionBlockerKind::UserFeeAboveLowFeeBound => {
            "lower user fee or route through fee sponsorship"
        }
        ProductionBlockerKind::MissingExitAuthorization => {
            "bind forced withdrawal package to user recovery and authority authorization"
        }
        ProductionBlockerKind::MissingFixtureRoot => {
            "rerun dry-run executor and publish fixture result root"
        }
    }
}

fn root_from_label(domain: &str, label: &str) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-FIXTURE-ROOT",
        &[HashPart::Str(domain), HashPart::Str(label)],
        32,
    )
}

fn record_root(label: &str, record: &Value) -> String {
    domain_hash(
        "MONERO-L2-PQ-BRIDGE-EXIT-DRY-RUN-FIXTURE-RESULT",
        &[HashPart::Str(label), HashPart::Json(record)],
        32,
    )
}
